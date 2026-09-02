//! Parses and formats the conditional branches inside `cfg_if!` invocations.
//!
//! Predicates and Rust bodies are formatted independently before the macro shell is
//! rebuilt. When reconstruction could move structural trivia, the original shell is
//! retained. Nested supported macros are still formatted when exact body splice
//! boundaries remain available.

use super::{Error, Options, nested};
use crate::{
    fragment::{self, Disposition, ProtectedFragment},
    source::SourceMap,
    writer::Writer,
};
use proc_macro2::TokenStream;
use std::ops::Range;
use syn::{
    Block, Ident, Item, Meta, Stmt, Token, braced, bracketed, parenthesized,
    parse::{Parse, ParseStream, Result as ParseResult, discouraged::Speculative},
    spanned::Spanned,
    token,
};

/// Predicate column after the shell indentation and `if #[cfg(` prefix.
const FIRST_PREDICATE_OFFSET: usize = 13;
/// Conservative shell width preceding each predicate after the first.
const FOLLOWING_PREDICATE_OFFSET: usize = 20;

/// Parsed conditional chain with an optional terminal `else` branch.
struct CfgIfInput {
    branches: Vec<ConditionalBranch>,
    else_branch: Option<ElseBranch>,
}

/// Parsed `if` or `else if` branch with tokens retained for source mapping.
struct ConditionalBranch {
    else_token: Option<Token![else]>,
    if_token: Token![if],
    pound_token: Token![#],
    bracket_token: token::Bracket,
    cfg_ident: Ident,
    paren_token: token::Paren,
    predicate: TokenStream,
    brace_token: token::Brace,
    body: Body,
}

/// Parsed terminal `else` branch.
struct ElseBranch {
    else_token: Token![else],
    brace_token: token::Brace,
    body: Body,
}

/// Branch contents classified by the Rust grammar used to parse them.
enum Body {
    /// A complete sequence of Rust items.
    Items(Vec<Item>),
    /// Statements and an optional trailing expression.
    Statements(Vec<Stmt>),
}

/// Formatted predicate and body ready for shell rendering.
struct ConditionalLayout {
    predicate: String,
    body: String,
}

/// Formatted contents of an entire conditional chain.
struct Layout {
    branches: Vec<ConditionalLayout>,
    else_body: Option<String>,
}

/// Exact byte ranges for a brace pair and its enclosed source.
struct BodyRanges {
    open: Range<usize>,
    body: Range<usize>,
    close: Range<usize>,
}

impl Parse for CfgIfInput {
    fn parse(input: ParseStream<'_>) -> ParseResult<Self> {
        let mut branches = vec![ConditionalBranch::parse(input, None)?];
        let mut else_branch = None;

        while !input.is_empty() {
            let else_token = input.parse()?;
            if input.peek(Token![if]) {
                branches.push(ConditionalBranch::parse(input, Some(else_token))?);
            } else {
                let content;
                let brace_token = braced!(content in input);
                else_branch = Some(ElseBranch {
                    else_token,
                    brace_token,
                    body: parse_body(&content)?,
                });
                if !input.is_empty() {
                    return Err(input.error("unexpected tokens after cfg_if else branch"));
                }
            }
        }

        Ok(Self {
            branches,
            else_branch,
        })
    }
}

impl ConditionalBranch {
    /// Parses one branch, including the supplied `else` token for chained branches.
    fn parse(input: ParseStream<'_>, else_token: Option<Token![else]>) -> ParseResult<Self> {
        let if_token = input.parse()?;
        let pound_token = input.parse()?;
        let attribute;
        let bracket_token = bracketed!(attribute in input);
        let cfg_ident: Ident = attribute.parse()?;
        if cfg_ident != "cfg" {
            return Err(syn::Error::new(cfg_ident.span(), "expected cfg attribute"));
        }
        let predicate_content;
        let paren_token = parenthesized!(predicate_content in attribute);
        let predicate = predicate_content.parse()?;
        if !predicate_content.is_empty() {
            return Err(predicate_content.error("unexpected tokens in cfg predicate"));
        }
        if !attribute.is_empty() {
            return Err(attribute.error("unexpected tokens in cfg attribute"));
        }

        let content;
        let brace_token = braced!(content in input);
        let body = parse_body(&content)?;
        Ok(Self {
            else_token,
            if_token,
            pound_token,
            bracket_token,
            cfg_ident,
            paren_token,
            predicate,
            brace_token,
            body,
        })
    }
}

/// Parses a branch body as items when the entire body permits that interpretation.
fn parse_body(input: ParseStream<'_>) -> ParseResult<Body> {
    // Item and statement grammars overlap. Parse items on a fork so the real stream
    // advances only when every token belongs to a complete item sequence.
    let items = input.fork();
    let mut parsed = Vec::new();
    let items_result = (|| {
        while !items.is_empty() {
            parsed.push(items.parse::<Item>()?);
        }
        ParseResult::Ok(())
    })();
    if items_result.is_ok() {
        input.advance_to(&items);
        return Ok(Body::Items(parsed));
    }

    input.call(Block::parse_within).map(Body::Statements)
}

/// Formats the delimiter contents of a `cfg_if!` invocation.
#[cfg(test)]
pub(super) fn cfg_if(
    source: &str,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    cfg_if_with(
        &crate::rustfmt::Formatter::default(),
        source,
        options,
        depth,
    )
}

/// Formats a `cfg_if!` body using the configured Rust fragment formatter.
///
/// Structural trivia that cannot be safely moved causes the shell to be preserved.
pub(super) fn cfg_if_with(
    formatter: &crate::rustfmt::Formatter,
    source: &str,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let input = syn::parse_str::<CfgIfInput>(source).map_err(Error::Parse)?;
    let source_map = SourceMap::new(source);
    let Some(ranges) = source_ranges(&source_map, &input)? else {
        // Unreliable brace spans leave no safe boundary for body replacement.
        return Ok(ProtectedFragment::preserved(source));
    };
    if !has_only_whitespace_gaps(source, ranges) {
        // Non-whitespace between mapped fields is structural trivia that a canonical
        // shell would discard.
        return preserve_cfg_if(formatter, source, &source_map, &input, options, depth);
    }

    let mut branches = Vec::with_capacity(input.branches.len());
    let mut predicate_column = options.indentation + FIRST_PREDICATE_OFFSET;
    for branch in &input.branches {
        let Some(body) = format_body(
            &source_map,
            &branch.brace_token,
            &branch.body,
            depth,
            options.indentation + 8,
            formatter,
        )?
        else {
            return preserve_cfg_if(formatter, source, &source_map, &input, options, depth);
        };
        let Some(predicate) =
            format_predicate(formatter, &source_map, &branch.predicate, predicate_column)?
        else {
            return preserve_cfg_if(formatter, source, &source_map, &input, options, depth);
        };
        // Rustfmt needs the absolute column of each predicate. The following offset
        // covers `)] {} else if #[cfg(` after an empty body and conservatively
        // reserves the multiline `} else if #[cfg(` form after a non-empty body.
        predicate_column = if body.is_empty() {
            rendered_end_column(&predicate, predicate_column, options.indentation + 4)
                + FOLLOWING_PREDICATE_OFFSET
        } else {
            options.indentation + FOLLOWING_PREDICATE_OFFSET
        };
        branches.push(ConditionalLayout { predicate, body });
    }
    let else_body = match &input.else_branch {
        Some(branch) => {
            let Some(body) = format_body(
                &source_map,
                &branch.brace_token,
                &branch.body,
                depth,
                options.indentation + 8,
                formatter,
            )?
            else {
                return preserve_cfg_if(formatter, source, &source_map, &input, options, depth);
            };
            Some(body)
        }
        None => None,
    };

    let output = render(
        &Layout {
            branches,
            else_body,
        },
        options,
    );
    syn::parse_str::<CfgIfInput>(&output).map_err(Error::Output)?;
    Ok(ProtectedFragment::formatted(output))
}

/// Returns the absolute character column after the rendered source.
fn rendered_end_column(source: &str, first_column: usize, indentation: usize) -> usize {
    source.rsplit_once('\n').map_or_else(
        || first_column + source.chars().count(),
        |(_, line)| indentation + line.chars().count(),
    )
}

/// Preserves the conditional shell while applying safe nested formatting in bodies.
fn preserve_cfg_if(
    formatter: &crate::rustfmt::Formatter,
    source: &str,
    source_map: &SourceMap<'_>,
    input: &CfgIfInput,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let mut item_groups = Vec::new();
    let mut statement_groups = Vec::new();
    for body in input
        .branches
        .iter()
        .map(|branch| &branch.body)
        .chain(input.else_branch.iter().map(|branch| &branch.body))
    {
        match body {
            Body::Items(items) => item_groups.push(items.as_slice()),
            Body::Statements(statements) => statement_groups.push(statements.as_slice()),
        }
    }
    nested::preserve_bodies_with_nested(
        formatter,
        source,
        source_map,
        &item_groups,
        &statement_groups,
        options,
        depth,
    )
}

/// Collects ranges that own every reconstructable field in the conditional shell.
///
/// Returns `None` when a branch's brace spans do not identify exact source braces.
fn source_ranges(
    source_map: &SourceMap<'_>,
    input: &CfgIfInput,
) -> Result<Option<Vec<Range<usize>>>, Error> {
    let mut ranges = Vec::new();
    for branch in &input.branches {
        ranges.extend(
            branch
                .else_token
                .as_ref()
                .map(Spanned::span)
                .map(|span| source_map.span_range(span))
                .transpose()?,
        );
        ranges.extend([
            source_map.span_range(branch.if_token.span())?,
            source_map.span_range(branch.pound_token.span())?,
            source_map.span_range(branch.bracket_token.span.open())?,
            source_map.span_range(branch.cfg_ident.span())?,
            source_map.span_range(branch.paren_token.span.open())?,
            source_map.span_range(branch.predicate.span())?,
            source_map.span_range(branch.paren_token.span.close())?,
            source_map.span_range(branch.bracket_token.span.close())?,
        ]);
        let Some(body) = body_ranges(source_map, &branch.brace_token)? else {
            return Ok(None);
        };
        ranges.extend([body.open, body.body, body.close]);
    }
    if let Some(branch) = &input.else_branch {
        ranges.push(source_map.span_range(branch.else_token.span())?);
        let Some(body) = body_ranges(source_map, &branch.brace_token)? else {
            return Ok(None);
        };
        ranges.extend([body.open, body.body, body.close]);
    }
    Ok(Some(ranges))
}

/// Maps a parsed brace pair to its opening, body, and closing byte ranges.
fn body_ranges(
    source_map: &SourceMap<'_>,
    brace: &token::Brace,
) -> Result<Option<BodyRanges>, Error> {
    let open = source_map.span_range(brace.span.open())?;
    let close = source_map.span_range(brace.span.close())?;
    // Span conversion alone does not prove that the mapped bytes are an ordered
    // brace pair, so verify the delimiters before using them as splice boundaries.
    if source_map.slice(open.clone())? != "{"
        || source_map.slice(close.clone())? != "}"
        || open.end > close.start
    {
        return Ok(None);
    }
    let body = open.end..close.start;
    Ok(Some(BodyRanges { open, body, close }))
}

/// Formats a predicate when its syntax and trivia permit relocation.
///
/// Returns `None` for preserved multiline source because canonical rendering would
/// move its continuation lines.
fn format_predicate(
    formatter: &crate::rustfmt::Formatter,
    source_map: &SourceMap<'_>,
    predicate: &TokenStream,
    column: usize,
) -> Result<Option<String>, Error> {
    let range = source_map.span_range(predicate.span())?;
    let predicate_source = source_map.slice(range)?;
    let predicate = match syn::parse2::<Meta>(predicate.clone()) {
        Ok(_) if fragment::source_requires_preservation(predicate_source) => {
            ProtectedFragment::preserved(predicate_source)
        }
        Ok(_) => formatter
            .meta(predicate_source, column)
            .map_err(Error::from)?,
        Err(_) => ProtectedFragment::preserved(predicate_source),
    };
    Ok(movable(predicate))
}

/// Formats a branch body according to its parsed item or statement grammar.
///
/// Returns `None` when the body boundaries or preserved multiline layout cannot be
/// moved into the canonical shell.
fn format_body(
    source_map: &SourceMap<'_>,
    brace: &token::Brace,
    body: &Body,
    depth: usize,
    indentation: usize,
    formatter: &crate::rustfmt::Formatter,
) -> Result<Option<String>, Error> {
    let Some(ranges) = body_ranges(source_map, brace)? else {
        return Ok(None);
    };
    let body_start = ranges.body.start;
    let body_source = source_map.slice(ranges.body)?;
    let body = match body {
        Body::Items(items) => nested::items(
            formatter,
            items,
            body_source,
            body_start,
            source_map,
            depth,
            indentation,
        )?,
        Body::Statements(statements) => nested::statements(
            formatter,
            statements,
            body_source,
            body_start,
            source_map,
            depth,
            indentation,
        )?,
    };
    Ok(movable(body))
}

/// Extracts text only when moving the fragment cannot disturb preserved line layout.
fn movable(fragment: ProtectedFragment) -> Option<String> {
    if fragment.disposition() != Disposition::Formatted
        && (fragment.text().contains('\n') || fragment.text().contains('\r'))
    {
        return None;
    }
    Some(fragment.into_string())
}

/// Checks that mapped fields are ordered and all uncovered source is whitespace.
fn has_only_whitespace_gaps(source: &str, ranges: impl IntoIterator<Item = Range<usize>>) -> bool {
    let mut ranges = ranges.into_iter().collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut cursor = 0;
    for range in ranges {
        // Overlap and out-of-bounds ranges mean source mapping cannot establish
        // exclusive ownership of the intervening bytes.
        if range.start < cursor
            || range.end > source.len()
            || source[cursor..range.start]
                .chars()
                .any(|character| !character.is_whitespace())
        {
            return false;
        }
        cursor = range.end;
    }
    source[cursor..]
        .chars()
        .all(|character| character.is_whitespace())
}

/// Renders a canonical `cfg_if!` body from formatted branch contents.
fn render(layout: &Layout, options: Options) -> String {
    let mut writer = Writer::new(options.indentation, options.line_ending.as_str());
    writer.newline();
    writer.indented(|writer| {
        for (index, branch) in layout.branches.iter().enumerate() {
            if index != 0 {
                writer.push(" else ");
            }
            writer.push("if #[cfg(");
            writer.push(&branch.predicate);
            writer.push(")] ");
            write_body(writer, &branch.body);
        }
        if let Some(body) = &layout.else_body {
            writer.push(" else ");
            write_body(writer, body);
        }
    });
    writer.newline();
    writer.pad_to_indentation();
    writer.finish()
}

/// Writes one canonical braced body at the writer's current indentation.
fn write_body(writer: &mut Writer<'_>, body: &str) {
    writer.push("{");
    if body.is_empty() {
        writer.push("}");
        return;
    }
    writer.newline();
    writer.indented(|writer| writer.push(body));
    // The closing brace needs exactly one preceding line break regardless of
    // whether the fragment formatter supplied a trailing newline.
    if !body.ends_with('\n') {
        writer.newline();
    }
    writer.push("}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::LineEnding;

    const OPTIONS: Options = Options {
        indentation: 0,
        body_column: 0,
        line_ending: LineEnding::Lf,
    };

    fn fixed_point(source: &str) -> String {
        let once = cfg_if(source, OPTIONS, 0)
            .expect("cfg_if should format")
            .into_string();
        let twice = cfg_if(&once, OPTIONS, 0)
            .expect("cfg_if should format twice")
            .into_string();
        assert_eq!(once, twice);
        once
    }

    #[test]
    fn formats_item_bodies_and_prefers_items() {
        let source = "if #[cfg(test)] { const VALUE:usize=1; fn value()->usize{VALUE} } else { const VALUE:usize=2; }";
        let parsed = syn::parse_str::<CfgIfInput>(source).expect("cfg_if should parse");
        assert!(matches!(parsed.branches[0].body, Body::Items(_)));
        assert!(matches!(
            parsed.else_branch.expect("else branch should exist").body,
            Body::Items(_)
        ));

        let output = fixed_point(source);
        assert!(output.contains("const VALUE: usize = 1;"));
        assert!(output.contains("fn value() -> usize {"));
    }

    #[test]
    fn formats_statement_bodies_and_tail_expressions() {
        let source = "if #[cfg(feature=\"std\")] { let value=source(); value } else { fallback() }";
        let parsed = syn::parse_str::<CfgIfInput>(source).expect("cfg_if should parse");
        assert!(matches!(parsed.branches[0].body, Body::Statements(_)));
        assert!(matches!(
            parsed.else_branch.expect("else branch should exist").body,
            Body::Statements(_)
        ));

        let output = fixed_point(source);
        assert!(output.contains("let value = source();\n"));
        assert!(output.contains("value\n"));
        assert!(output.contains("fallback()\n"));
    }

    #[test]
    fn formats_else_if_chain_and_predicates() {
        let source = "if #[cfg(all(target_arch=\"aarch64\",feature=\"std\"))] { first() } else if #[cfg(any(test,miri))] { second() } else { third() }";
        let output = fixed_point(source);

        assert!(output.contains("if #[cfg(all(target_arch = \"aarch64\", feature = \"std\"))] {"));
        assert!(output.contains("} else if #[cfg(any(test, miri))] {"));
        assert!(output.contains("} else {"));
    }

    #[test]
    fn formats_else_if_predicate_at_its_wider_column() {
        let source = "if #[cfg(test)] { first() } else if #[cfg(all(feature=\"an_extremely_descriptive_first_feature\",feature=\"an_extremely_descriptive_second_feature\",feature=\"an_extremely_descriptive_third_feature\"))] { second() }";
        let output = fixed_point(source);

        assert!(
            output
                .lines()
                .all(|line| line.chars().count() <= crate::writer::MAX_OVERFLOW_WIDTH),
            "{output}"
        );
        assert!(output.contains("} else if #[cfg(all(\n"), "{output}");
    }

    #[test]
    fn formats_else_if_predicate_after_inline_empty_branch() {
        let source = "if #[cfg(test)] {} else if #[cfg(all(feature=\"an_extremely_descriptive_first_feature\",feature=\"an_extremely_descriptive_second_feature\",feature=\"an_extremely_descriptive_third_feature\"))] { second() }";
        let output = fixed_point(source);

        assert!(
            output
                .lines()
                .all(|line| line.chars().count() <= crate::writer::MAX_OVERFLOW_WIDTH),
            "{output}"
        );
        assert!(output.contains("{} else if #[cfg(all(\n"), "{output}");
    }

    #[test]
    fn accepts_boolean_cfg_predicates() {
        let source = "if #[cfg(true)] { first() } else if #[cfg(false)] { second() }";
        let output = fixed_point(source);

        assert!(output.contains("if #[cfg(true)] {"));
        assert!(output.contains("} else if #[cfg(false)] {"));
    }

    #[test]
    fn preserves_outer_predicate_while_formatting_nested_macro() {
        let source = "if #[cfg(all(\n    test,\n    /* keep */ feature = \"std\"\n))] { fn run() { select! {value=receive()=>value} } }";
        let formatted = cfg_if(source, OPTIONS, 0).expect("cfg_if should format nested macro");

        assert_eq!(
            formatted.disposition(),
            Disposition::PreservedWithNestedFormatting
        );
        assert!(formatted.text().contains("/* keep */ feature"));
        assert!(formatted.text().contains("value = receive() => value,"));
    }

    #[test]
    fn preserves_skipped_sibling_while_formatting_nested_macro() {
        let source = "if #[cfg(test)] { #[rustfmt::skip] fn skipped() { call( ) } fn run() { select! {value=receive()=>value} } }";
        let formatted = cfg_if(source, OPTIONS, 0).expect("cfg_if should format nested macro");

        assert!(
            formatted
                .text()
                .contains("#[rustfmt::skip] fn skipped() { call( ) }")
        );
        assert!(formatted.text().contains("value = receive() => value,"));
    }

    #[test]
    fn formats_body_line_comments() {
        let source = "if #[cfg(test)] {\n// keep ordinary\npub struct Example{pub value:usize}\n}";
        let output = fixed_point(source);

        assert_eq!(output.matches("// keep ordinary").count(), 1);
        assert!(output.contains("pub struct Example {"));
    }

    #[test]
    fn formats_source_docs() {
        let source = "if #[cfg(test)] {\n/// Exact docs.\npub struct Example{pub value:usize}\n}";
        let output = fixed_point(source);

        assert_eq!(output.matches("/// Exact docs.").count(), 1);
        assert!(output.contains("pub struct Example {"));
    }

    #[test]
    fn preserves_opaque_macro_tokens_and_source_docs() {
        let source = "if #[cfg(test)] {\n        loom::lazy_static! {\n            /// Exact model-local docs.\n            static ref VALUE: AtomicUsize = AtomicUsize::new(0);\n        }\n        const OTHER:usize=1;\n    }";
        let output = fixed_point(source);

        assert_eq!(output.matches("/// Exact model-local docs.").count(), 1);
        assert!(!output.contains("#[doc ="), "{output}");
        assert!(output.contains("static ref VALUE: AtomicUsize = AtomicUsize::new(0);"));
        assert!(output.contains("const OTHER: usize = 1;"));
    }

    #[test]
    fn preserves_opaque_macro_tokens_in_statement_body() {
        let source = "if #[cfg(test)] { let span=info_span!(parent: &span, \"name\"); span }";
        let output = fixed_point(source);

        assert!(output.contains("info_span!(parent: &span, \"name\")"));
        assert!(!output.contains("parent : & span"), "{output}");
    }

    #[test]
    fn preserves_structural_and_formats_body_comments() {
        let structural = "if // keep seam\n#[cfg(test)] { const VALUE:usize=1; }";
        let formatted = cfg_if(structural, OPTIONS, 0).expect("cfg_if should be preserved");
        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), structural);

        let block = "if #[cfg(test)] {\n    const VALUE: usize = /* keep */ 1;\n}";
        let formatted = cfg_if(block, OPTIONS, 0).expect("cfg_if should format");
        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(formatted.text().matches("/* keep */").count(), 1);
        assert!(
            formatted
                .text()
                .contains("const VALUE: usize = /* keep */ 1;")
        );
    }

    #[test]
    fn formats_internal_item_blank_lines() {
        let source = "if #[cfg(test)] {\n    pub struct First;\n\n    pub trait Example {\n        type Value;\n\n        fn value(&self) -> Self::Value;\n    }\n}";
        let formatted = cfg_if(source, OPTIONS, 0).expect("cfg_if should be protected");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(
            formatted
                .text()
                .contains("pub struct First;\n\n        pub trait Example")
        );
        assert!(
            formatted
                .text()
                .contains("type Value;\n\n            fn value")
        );
    }

    #[test]
    fn formats_nested_macro_without_collapsing_item_blank_lines() {
        let source = "if #[cfg(test)] {\n    pub struct First;\n\n    fn run() { select! { value=receive()=>value } }\n}";
        let formatted = cfg_if(source, OPTIONS, 0).expect("nested selection should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(
            formatted
                .text()
                .contains("pub struct First;\n\n        fn run()")
        );
        assert!(formatted.text().contains("value = receive() => value,"));
        let reparsed = syn::parse_str::<CfgIfInput>(formatted.text()).expect("cfg_if should parse");
        let twice = cfg_if(formatted.text(), OPTIONS, 0).expect("cfg_if should format twice");
        assert_eq!(reparsed.branches.len(), 1);
        assert_eq!(formatted.text(), twice.text());
    }

    #[test]
    fn formats_nested_macros_in_item_and_statement_bodies() {
        let cases = [
            (
                "if #[cfg(test)] { fn run() { select! { value=receive()=>value } } }",
                true,
            ),
            (
                "if #[cfg(test)] { let value=select! { item=receive()=>item }; value }",
                false,
            ),
        ];

        for (source, is_item_body) in cases {
            let parsed = syn::parse_str::<CfgIfInput>(source).expect("cfg_if should parse");
            assert_eq!(
                matches!(parsed.branches[0].body, Body::Items(_)),
                is_item_body
            );
            let output = fixed_point(source);
            assert!(
                output.contains("item = receive() => item,")
                    || output.contains("value = receive() => value,")
            );
        }
    }

    #[test]
    fn rejects_macro_template_body() {
        let source = "if #[cfg(test)] { Some(unsafe { arch::$kernel($($arg),+) }) } else { None }";
        assert!(matches!(cfg_if(source, OPTIONS, 0), Err(Error::Parse(_))));
    }

    #[test]
    fn matches_rustfmt_fallback_for_unbreakable_enum() {
        let source = r#"if #[cfg(feature = "aws")] {
/// Errors that can occur when deploying infrastructure on AWS
#[derive(Debug)]
pub enum Error {
#[error("AWS security group ingress error: {0}")]
AwsSecurityGroupIngress(#[from] aws_sdk_ec2::operation::authorize_security_group_ingress::AuthorizeSecurityGroupIngressError),
#[error("AWS describe instances error: {0}")]
AwsDescribeInstances(#[from] aws_sdk_ec2::operation::describe_instances::DescribeInstancesError),
#[error("S3 operation failed: {operation} on bucket '{bucket}'")]
AwsS3 { bucket:String, operation:S3Operation, #[source] source:Box<aws_sdk_s3::Error> },
}
}"#;
        let output = fixed_point(source);

        assert_eq!(
            output
                .matches("/// Errors that can occur when deploying infrastructure on AWS")
                .count(),
            1
        );
        assert!(output.contains("AwsDescribeInstances(#[from]"));
        assert!(output.contains("AwsS3 { bucket:String"));
        assert_eq!(output.matches("AWS describe instances error").count(), 1);
        assert!(output.contains("#[source] source:Box"));
        assert_ne!(output, source);
    }

    #[test]
    fn rejects_invalid_cfg_header() {
        for source in [
            "if #[allow(test)] { const VALUE: usize = 1; }",
            "if #[cfg(test) extra] { const VALUE: usize = 1; }",
            "if #[cfg(test)] { const VALUE: usize = 1; } trailing",
        ] {
            assert!(matches!(cfg_if(source, OPTIONS, 0), Err(Error::Parse(_))));
        }
    }
}
