//! Formatting adapters for ordinary Rust syntax fragments.

use crate::source::SourceMap;
use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use quote::quote;
use std::{collections::HashMap, ops::Range, panic::AssertUnwindSafe};
use syn::{
    Attribute, Expr, File, Item, ItemFn, Lit, Meta, Pat, Stmt, parse::Parse, spanned::Spanned,
};
use thiserror::Error;

/// An error produced while formatting a Rust syntax fragment.
#[derive(Debug, Error)]
pub enum Error {
    /// The synthetic wrapper could not be constructed.
    #[error("failed to construct formatter wrapper: {0}")]
    Construct(#[source] syn::Error),
    /// `prettyplease` panicked while unparsing the wrapper.
    #[error("prettyplease panicked while formatting a fragment")]
    Panic,
    /// Formatted wrapper output was not valid Rust.
    #[error("failed to parse formatted wrapper: {0}")]
    Reparse(#[source] syn::Error),
    /// The formatted wrapper did not have its required synthetic shape.
    #[error("formatted wrapper had an unexpected shape")]
    WrapperShape,
    /// A source span could not be mapped into the formatted wrapper.
    #[error("failed to locate formatted fragment: {0}")]
    Source(#[from] crate::source::Error),
    /// Pretty output did not contain the expected synthetic indentation.
    #[error("formatted wrapper had unexpected indentation")]
    Indentation,
}

/// How a protected fragment was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// The fragment was formatted with `prettyplease`.
    Formatted,
    /// Exact source was retained because formatting could lose trivia.
    PreservedForTrivia,
    /// The enclosing source was retained while supported nested macros changed.
    PreservedWithNestedFormatting,
}

/// A formatted fragment or an exact source-preserving fallback.
pub struct ProtectedFragment {
    text: String,
    disposition: Disposition,
}

struct ShieldedLiteral {
    range: Range<usize>,
    placeholder: String,
    source: String,
}

pub(crate) struct MultilineLiterals {
    shielded: String,
    marker_prefix: String,
    literals: Vec<ShieldedLiteral>,
}

struct BlankLines {
    comments: crate::trivia::LineComments,
    marker_prefix: String,
    count: usize,
}

impl BlankLines {
    fn prepare(source: &str) -> Option<Self> {
        if !source_has_internal_blank_line(source) {
            return None;
        }
        let lines = source.split_inclusive('\n').collect::<Vec<_>>();
        let first_content = lines.iter().position(|line| !line.trim().is_empty())?;
        let last_content = lines.iter().rposition(|line| !line.trim().is_empty())?;
        let marker_prefix = crate::marker::unique_prefix(source, "blank");
        let mut count = 0;
        let mut marked = String::with_capacity(source.len());
        for (index, line) in lines.into_iter().enumerate() {
            if first_content < index && index < last_content && line.trim().is_empty() {
                let line_ending = if line.ends_with("\r\n") {
                    "\r\n"
                } else if line.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                marked.push_str("// ");
                marked.push_str(&marker_prefix);
                marked.push_str(&count.to_string());
                marked.push_str(line_ending);
                count += 1;
            } else {
                marked.push_str(line);
            }
        }
        let comments = crate::trivia::LineComments::prepare(&marked)?;
        Some(Self {
            comments,
            marker_prefix,
            count,
        })
    }

    fn restore(self, formatted: &str) -> Option<String> {
        let restored = self.comments.restore(formatted)?;
        let marker_start = format!("// {}", self.marker_prefix);
        let mut seen = vec![false; self.count];
        let mut output = String::with_capacity(restored.len());
        for line in restored.split_inclusive('\n') {
            let line_ending = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            let content = line.strip_suffix(line_ending).unwrap_or(line);
            let trimmed = content.trim();
            if let Some(index) = trimmed
                .strip_prefix(&marker_start)
                .and_then(|index| index.parse::<usize>().ok())
            {
                if index >= seen.len() || std::mem::replace(&mut seen[index], true) {
                    return None;
                }
                output.push_str(line_ending);
            } else {
                if content.contains(&self.marker_prefix) {
                    return None;
                }
                output.push_str(line);
            }
        }
        if !seen.into_iter().all(|marker| marker)
            || output.contains(&self.marker_prefix)
            || output.parse::<TokenStream>().is_err()
        {
            return None;
        }
        Some(output)
    }
}

impl MultilineLiterals {
    pub(crate) fn prepare(source: &str) -> Option<Self> {
        let stream = source.parse::<TokenStream>().ok()?;
        let source_map = SourceMap::new(source);
        let mut ranges = Vec::new();
        collect_literal_ranges(stream, &source_map, &mut ranges)?;
        ranges.retain(|range| {
            source
                .get(range.clone())
                .is_some_and(|literal| literal.contains('\n') || literal.contains('\r'))
        });
        if ranges.is_empty() {
            return None;
        }

        let marker_prefix = crate::marker::unique_prefix(source, "literal");
        let mut literals = Vec::with_capacity(ranges.len());
        for (index, range) in ranges.into_iter().enumerate() {
            let literal = source.get(range.clone())?;
            let marker = format!("{marker_prefix}{index}");
            literals.push(ShieldedLiteral {
                range,
                placeholder: literal_placeholder(literal, &marker)?,
                source: literal.to_owned(),
            });
        }

        let mut shielded = source.to_owned();
        for literal in literals.iter().rev() {
            shielded.replace_range(literal.range.clone(), &literal.placeholder);
        }
        Some(Self {
            shielded,
            marker_prefix,
            literals,
        })
    }

    pub(crate) fn text(&self) -> &str {
        &self.shielded
    }

    pub(crate) fn restore(self, fragment: ProtectedFragment) -> Option<ProtectedFragment> {
        let ProtectedFragment { text, disposition } = fragment;
        let stream = text.parse::<TokenStream>().ok()?;
        let source_map = SourceMap::new(&text);
        let mut ranges = Vec::new();
        collect_literal_ranges(stream, &source_map, &mut ranges)?;

        let mut matched = vec![None; self.literals.len()];
        {
            let placeholders = self
                .literals
                .iter()
                .enumerate()
                .map(|(index, literal)| (literal.placeholder.as_str(), index))
                .collect::<HashMap<_, _>>();
            for range in ranges {
                let literal = text.get(range.clone())?;
                let Some(index) = placeholders.get(literal).copied() else {
                    continue;
                };
                if matched[index].replace(range).is_some() {
                    return None;
                }
            }
        }
        let mut replacements = self
            .literals
            .into_iter()
            .zip(matched)
            .map(|(literal, range)| Some((range?, literal.source)))
            .collect::<Option<Vec<_>>>()?;
        replacements.sort_unstable_by_key(|(range, _)| (range.start, range.end));
        if replacements
            .windows(2)
            .any(|pair| pair[0].0.end > pair[1].0.start)
        {
            return None;
        }

        let mut restored = text;
        for (range, source) in replacements.into_iter().rev() {
            restored.replace_range(range, &source);
        }
        if restored.contains(&self.marker_prefix) || restored.parse::<TokenStream>().is_err() {
            return None;
        }
        Some(ProtectedFragment {
            text: restored,
            disposition,
        })
    }
}

impl ProtectedFragment {
    pub(crate) const fn formatted(text: String) -> Self {
        Self {
            text,
            disposition: Disposition::Formatted,
        }
    }

    pub(crate) fn preserved(source: &str) -> Self {
        Self {
            text: source.to_owned(),
            disposition: Disposition::PreservedForTrivia,
        }
    }

    pub(crate) const fn preserved_with_nested_formatting(text: String) -> Self {
        Self {
            text,
            disposition: Disposition::PreservedWithNestedFormatting,
        }
    }

    /// Returns the protected fragment text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns how the fragment was produced.
    pub const fn disposition(&self) -> Disposition {
        self.disposition
    }

    /// Consumes the fragment and returns its text.
    pub fn into_string(self) -> String {
        self.text
    }
}

/// Formats an expression through a synthetic function body.
///
/// `source` must be the exact source text from which `expression` was parsed.
pub fn expression(expression: &Expr, source: &str) -> Result<ProtectedFragment, Error> {
    format_or_preserve(source, || format_expression(expression))
}

pub(crate) fn expression_preserving_blank_lines(
    expression: &Expr,
    source: &str,
) -> Result<ProtectedFragment, Error> {
    let Some(blank_lines) = BlankLines::prepare(source) else {
        return format_or_preserve(source, || format_expression(expression));
    };
    let formatted = format_expression(expression)?;
    let Some(restored) = blank_lines.restore(&formatted) else {
        return Ok(ProtectedFragment::preserved(source));
    };
    Ok(ProtectedFragment::formatted(restored))
}

/// Formats a block expression as a standalone function-body expression.
///
/// `source` must be the exact source text from which `expression` was parsed.
pub(crate) fn block_expression(
    expression: &Expr,
    source: &str,
) -> Result<ProtectedFragment, Error> {
    if !matches!(expression, Expr::Block(_)) {
        return Err(Error::WrapperShape);
    }
    format_or_preserve(source, || format_block_expression(expression))
}

pub(crate) fn block_expression_preserving_blank_lines(
    expression: &Expr,
    source: &str,
) -> Result<ProtectedFragment, Error> {
    if !matches!(expression, Expr::Block(_)) {
        return Err(Error::WrapperShape);
    }
    let Some(blank_lines) = BlankLines::prepare(source) else {
        return format_or_preserve(source, || format_block_expression(expression));
    };
    let formatted = format_block_expression(expression)?;
    let Some(restored) = blank_lines.restore(&formatted) else {
        return Ok(ProtectedFragment::preserved(source));
    };
    Ok(ProtectedFragment::formatted(restored))
}

/// Formats a pattern through a synthetic `for` loop.
///
/// `source` must be the exact source text from which `pattern` was parsed.
pub fn pattern(pattern: &Pat, source: &str) -> Result<ProtectedFragment, Error> {
    format_or_preserve(source, || {
        let wrapper = parse_wrapper(quote! {
            fn __commonware_fmt() {
                for #pattern in () {}
            }
        })?;
        let (formatted, reparsed) = unparse_and_reparse(&wrapper)?;
        let function = sole_function(&reparsed)?;
        let [Stmt::Expr(Expr::ForLoop(for_loop), None)] = function.block.stmts.as_slice() else {
            return Err(Error::WrapperShape);
        };
        extract_dedented(&formatted, for_loop.pat.span())
    })
}

/// Formats a complete list of items.
///
/// `source` must be the exact source text from which `items` were parsed.
pub fn items(items: &[Item], source: &str) -> Result<ProtectedFragment, Error> {
    format_or_preserve_with_docs(source, || {
        let wrapper = File {
            shebang: None,
            attrs: Vec::new(),
            items: items.to_vec(),
        };
        let formatted = unparse(&wrapper)?;
        let reparsed = syn::parse_file(&formatted).map_err(Error::Reparse)?;
        if reparsed.items.len() != items.len() {
            return Err(Error::WrapperShape);
        }
        Ok(formatted
            .strip_suffix('\n')
            .unwrap_or(&formatted)
            .to_owned())
    })
}

/// Formats a complete list of statements.
///
/// `source` must be the exact source text from which `statements` were parsed.
pub fn statements(statements: &[Stmt], source: &str) -> Result<ProtectedFragment, Error> {
    format_or_preserve(source, || {
        if statements.is_empty() {
            return Ok(String::new());
        }

        let wrapper = parse_wrapper(quote! {
            fn __commonware_fmt() {
                #(#statements)*
            }
        })?;
        let (formatted, reparsed) = unparse_and_reparse(&wrapper)?;
        let function = sole_function(&reparsed)?;
        if function.block.stmts.len() != statements.len() {
            return Err(Error::WrapperShape);
        }
        let first = function
            .block
            .stmts
            .first()
            .ok_or(Error::WrapperShape)?
            .span();
        let last = function
            .block
            .stmts
            .last()
            .ok_or(Error::WrapperShape)?
            .span();
        extract_dedented(&formatted, join_spans(first, last)?)
    })
}

/// Formats a cfg predicate or other meta item.
///
/// `source` must be the exact source text from which `meta` was parsed.
pub fn meta(meta: &Meta, source: &str) -> Result<ProtectedFragment, Error> {
    format_or_preserve(source, || {
        let wrapper = parse_wrapper(quote! {
            #[cfg(#meta)]
            struct __CommonwareFmt;
        })?;
        let (formatted, reparsed) = unparse_and_reparse(&wrapper)?;
        let [Item::Struct(item)] = reparsed.items.as_slice() else {
            return Err(Error::WrapperShape);
        };
        let [attribute] = item.attrs.as_slice() else {
            return Err(Error::WrapperShape);
        };
        let parsed = parse_cfg_argument(attribute)?;
        extract_dedented(&formatted, parsed.span())
    })
}

fn format_or_preserve(
    source: &str,
    format: impl FnOnce() -> Result<String, Error>,
) -> Result<ProtectedFragment, Error> {
    format_or_preserve_with_policy(source, false, format)
}

fn format_or_preserve_with_docs(
    source: &str,
    format: impl FnOnce() -> Result<String, Error>,
) -> Result<ProtectedFragment, Error> {
    format_or_preserve_with_policy(source, true, format)
}

fn format_or_preserve_with_policy(
    source: &str,
    recover_source_docs: bool,
    format: impl FnOnce() -> Result<String, Error>,
) -> Result<ProtectedFragment, Error> {
    if source_has_internal_blank_line(source) {
        return Ok(ProtectedFragment::preserved(source));
    }
    if source_requires_preservation(source) {
        let comments = if recover_source_docs {
            crate::trivia::LineComments::prepare_allowing_docs(source)
        } else {
            crate::trivia::LineComments::prepare(source)
        };
        if let Some(comments) = comments {
            let formatted = format()?;
            if let Some(restored) = comments.restore(&formatted) {
                return Ok(ProtectedFragment::formatted(restored));
            }
        }
        return Ok(ProtectedFragment::preserved(source));
    }

    Ok(ProtectedFragment::formatted(format()?))
}

fn parse_wrapper(tokens: TokenStream) -> Result<File, Error> {
    syn::parse2(tokens).map_err(Error::Construct)
}

fn format_expression(expression: &Expr) -> Result<String, Error> {
    let wrapper = parse_wrapper(quote! {
        fn __commonware_fmt() {
            let __commonware_fmt_value = #expression;
        }
    })?;
    let (formatted, reparsed) = unparse_and_reparse(&wrapper)?;
    let function = sole_function(&reparsed)?;
    let [Stmt::Local(local)] = function.block.stmts.as_slice() else {
        return Err(Error::WrapperShape);
    };
    let Some(initializer) = &local.init else {
        return Err(Error::WrapperShape);
    };
    if initializer.diverge.is_some() {
        return Err(Error::WrapperShape);
    }
    extract_dedented(&formatted, initializer.expr.span())
}

fn format_block_expression(expression: &Expr) -> Result<String, Error> {
    let wrapper = parse_wrapper(quote! {
        fn __commonware_fmt() {
            #expression
        }
    })?;
    let (formatted, reparsed) = unparse_and_reparse(&wrapper)?;
    let function = sole_function(&reparsed)?;
    let [Stmt::Expr(expression @ Expr::Block(_), None)] = function.block.stmts.as_slice() else {
        return Err(Error::WrapperShape);
    };
    extract_dedented(&formatted, expression.span())
}

fn unparse_and_reparse(wrapper: &File) -> Result<(String, File), Error> {
    let formatted = unparse(wrapper)?;
    let reparsed = syn::parse_file(&formatted).map_err(Error::Reparse)?;
    Ok((formatted, reparsed))
}

fn unparse(wrapper: &File) -> Result<String, Error> {
    std::panic::catch_unwind(AssertUnwindSafe(|| prettyplease::unparse(wrapper)))
        .map_err(|_| Error::Panic)
}

fn sole_function(file: &File) -> Result<&ItemFn, Error> {
    let [Item::Fn(function)] = file.items.as_slice() else {
        return Err(Error::WrapperShape);
    };
    if function.sig.ident != "__commonware_fmt" {
        return Err(Error::WrapperShape);
    }
    Ok(function)
}

fn parse_cfg_argument(attribute: &Attribute) -> Result<Meta, Error> {
    if !attribute.path().is_ident("cfg") {
        return Err(Error::WrapperShape);
    }
    attribute
        .parse_args_with(Meta::parse)
        .map_err(Error::Reparse)
}

fn join_spans(first: Span, last: Span) -> Result<Span, Error> {
    first.join(last).ok_or(Error::WrapperShape)
}

fn extract_dedented(formatted: &str, span: Span) -> Result<String, Error> {
    let source = SourceMap::new(formatted);
    let range = source.span_range(span)?;
    dedent_wrapper(source.slice(range)?)
}

fn dedent_wrapper(source: &str) -> Result<String, Error> {
    let mut output = String::with_capacity(source.len());
    let mut lines = source.split_inclusive('\n');
    let Some(first) = lines.next() else {
        return Ok(output);
    };
    output.push_str(first);

    for line in lines {
        if line == "\n" {
            output.push('\n');
            continue;
        }
        let line = line.strip_prefix("    ").ok_or(Error::Indentation)?;
        output.push_str(line);
    }

    Ok(output)
}

pub(crate) fn source_requires_preservation(source: &str) -> bool {
    let Ok(stream) = source.parse::<TokenStream>() else {
        return true;
    };
    let source_map = SourceMap::new(source);
    let mut ranges = Vec::new();
    let mut literal_ranges = Vec::new();
    let mut has_multiline_literal = false;
    if collect_token_ranges(
        stream,
        &source_map,
        &mut ranges,
        &mut literal_ranges,
        &mut has_multiline_literal,
    )
    .is_err()
    {
        return true;
    }
    if has_multiline_literal || has_source_spelled_doc_comment(source, &literal_ranges) {
        return true;
    }

    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut cursor = 0;
    for range in ranges {
        if range.start > cursor && !source[cursor..range.start].chars().all(char::is_whitespace) {
            return true;
        }
        cursor = cursor.max(range.end);
    }
    source[cursor..]
        .chars()
        .any(|character| !character.is_whitespace())
}

pub(crate) fn source_has_multiline_literal(source: &str) -> bool {
    let Ok(stream) = source.parse::<TokenStream>() else {
        return true;
    };
    let source_map = SourceMap::new(source);
    let mut ranges = Vec::new();
    let mut literal_ranges = Vec::new();
    let mut has_multiline_literal = false;
    collect_token_ranges(
        stream,
        &source_map,
        &mut ranges,
        &mut literal_ranges,
        &mut has_multiline_literal,
    )
    .is_err()
        || has_multiline_literal
}

pub(crate) fn source_has_internal_blank_line(source: &str) -> bool {
    let mut saw_content = false;
    let mut saw_blank_after_content = false;
    for line in source.lines() {
        if line.trim().is_empty() {
            saw_blank_after_content |= saw_content;
        } else {
            if saw_blank_after_content {
                return true;
            }
            saw_content = true;
        }
    }
    false
}

fn collect_token_ranges(
    stream: TokenStream,
    source: &SourceMap<'_>,
    ranges: &mut Vec<Range<usize>>,
    literal_ranges: &mut Vec<Range<usize>>,
    has_multiline_literal: &mut bool,
) -> Result<(), crate::source::Error> {
    for token in stream {
        match token {
            TokenTree::Group(group) => {
                if group.delimiter() != Delimiter::None {
                    ranges.push(source.span_range(group.span_open())?);
                    ranges.push(source.span_range(group.span_close())?);
                }
                collect_token_ranges(
                    group.stream(),
                    source,
                    ranges,
                    literal_ranges,
                    has_multiline_literal,
                )?;
            }
            TokenTree::Literal(literal) => {
                let range = source.span_range(literal.span())?;
                let literal = source.slice(range.clone())?;
                *has_multiline_literal |= literal.contains('\n') || literal.contains('\r');
                literal_ranges.push(range.clone());
                ranges.push(range);
            }
            TokenTree::Ident(ident) => ranges.push(source.span_range(ident.span())?),
            TokenTree::Punct(punct) => ranges.push(source.span_range(punct.span())?),
        }
    }
    Ok(())
}

fn collect_literal_ranges(
    stream: TokenStream,
    source: &SourceMap<'_>,
    ranges: &mut Vec<Range<usize>>,
) -> Option<()> {
    for token in stream {
        match token {
            TokenTree::Group(group) => {
                collect_literal_ranges(group.stream(), source, ranges)?;
            }
            TokenTree::Literal(literal) => ranges.push(source.span_range(literal.span()).ok()?),
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
    Some(())
}

fn literal_placeholder(source: &str, marker: &str) -> Option<String> {
    match syn::parse_str::<Lit>(source).ok()? {
        Lit::Str(literal) => Some(format!("\"{marker}\"{}", literal.suffix())),
        Lit::ByteStr(literal) => Some(format!("b\"{marker}\"{}", literal.suffix())),
        Lit::CStr(literal) => Some(format!("c\"{marker}\"{}", literal.suffix())),
        Lit::Byte(_)
        | Lit::Char(_)
        | Lit::Int(_)
        | Lit::Float(_)
        | Lit::Bool(_)
        | Lit::Verbatim(_) => None,
        _ => None,
    }
}

fn has_source_spelled_doc_comment(source: &str, literal_ranges: &[Range<usize>]) -> bool {
    let mut literal_ranges = literal_ranges.to_vec();
    literal_ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut literals = literal_ranges.iter().peekable();
    let mut offset = 0;
    while offset < source.len() {
        while literals.peek().is_some_and(|literal| literal.end <= offset) {
            literals.next();
        }

        let remaining = &source[offset..];
        if remaining.starts_with("///")
            || remaining.starts_with("//!")
            || remaining.starts_with("/**")
            || remaining.starts_with("/*!")
        {
            return true;
        }
        if let Some(literal) = literals.peek()
            && literal.start <= offset
        {
            offset = literal.end;
            literals.next();
            continue;
        }

        offset += source[offset..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse::Parser;

    #[test]
    fn formats_expression() {
        let source = "value.map(|item| { let doubled = item * 2; doubled + 1 })";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(
            formatted.text(),
            "value\n    .map(|item| {\n        let doubled = item * 2;\n        doubled + 1\n    })"
        );
        syn::parse_str::<Expr>(formatted.text()).expect("formatted expression should parse");
    }

    #[test]
    fn formats_block_expression_without_initializer_prefix() {
        let source = "{ // Keep this guard.\nif ready() && !start_sync::<E, A, S, V>(&context, &mut state).await { return; } }";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = block_expression(&input, source).expect("block should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(formatted.text().matches("// Keep this guard.").count(), 1);
        assert!(formatted.text().contains("start_sync::<E, A, S, V>("));
        syn::parse_str::<Expr>(formatted.text()).expect("formatted block should parse");
    }

    #[test]
    fn formats_pattern() {
        let source = "Example { first, second: Some(value) }";
        let input: Pat = Pat::parse_single
            .parse_str(source)
            .expect("pattern should parse");
        let formatted = pattern(&input, source).expect("pattern should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(formatted.text(), source);
        Pat::parse_single
            .parse_str(formatted.text())
            .expect("formatted pattern should parse");
    }

    #[test]
    fn formats_items_and_explicit_doc_attributes() {
        let source = "#[doc = \"An example.\"]\npub struct Example { pub value: usize }\nimpl Example { pub fn value(&self) -> usize { self.value } }";
        let file = syn::parse_file(source).expect("items should parse");
        let formatted = items(&file.items, source).expect("items should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_ne!(formatted.text(), source);
        assert_eq!(
            syn::parse_file(formatted.text())
                .expect("formatted items should parse")
                .items
                .len(),
            2
        );
    }

    #[test]
    fn formats_statements() {
        let source = "let value = source.map(|item| item + 1); value.unwrap_or_default()";
        let block: syn::Block =
            syn::parse_str(&format!("{{{source}}}")).expect("block should parse");
        let formatted = statements(&block.stmts, source).expect("statements should format");

        let reparsed: syn::Block =
            syn::parse_str(&format!("{{{}}}", formatted.text())).expect("statements should parse");
        assert_eq!(reparsed.stmts.len(), 2);
    }

    #[test]
    fn formats_meta() {
        let source = "all(test, any(feature = \"std\", unix))";
        let input: Meta = syn::parse_str(source).expect("meta should parse");
        let formatted = meta(&input, source).expect("meta should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(formatted.text(), source);
        syn::parse_str::<Meta>(formatted.text()).expect("formatted meta should parse");
    }

    #[test]
    fn preserves_multiline_literal() {
        let source = "r#\"first\n    second\"#";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should be protected");

        assert_eq!(
            formatted.disposition(),
            Disposition::PreservedForTrivia,
            "{}",
            formatted.text()
        );
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn shields_and_restores_multiline_literal_categories() {
        let source = "call(r#\"first\n    second\"#, br#\"third\n    fourth\"#, cr#\"fifth\n    sixth\"#, \"seventh\\\n    eighth\")";
        let literals = MultilineLiterals::prepare(source).expect("literals should be shielded");

        assert!(!literals.text().contains('\n'));
        let shielded = literals.text().to_owned();
        let restored = literals
            .restore(ProtectedFragment::formatted(shielded))
            .expect("literals should restore");

        assert_eq!(restored.disposition(), Disposition::Formatted);
        assert_eq!(restored.text(), source);
    }

    #[test]
    fn restores_multiline_literal_crlf_and_avoids_marker_collision() {
        let source = "call(\"__commonware_fmt_literal_0_\", r#\"first\r\n    second\"#)";
        let literals = MultilineLiterals::prepare(source).expect("literal should be shielded");
        assert_ne!(literals.marker_prefix, "__commonware_fmt_literal_0_");
        let shielded = literals.text().to_owned();

        let restored = literals
            .restore(ProtectedFragment::formatted(shielded))
            .expect("literal should restore");
        assert_eq!(restored.text(), source);
    }

    #[test]
    fn preserves_exact_source_doc_trailing_spaces() {
        let source = "/// Keep this Markdown break.  \npub struct Example { pub value: usize }";
        let file = syn::parse_file(source).expect("items should parse");
        let formatted = items(&file.items, source).expect("items should format");

        assert!(
            formatted
                .text()
                .contains("/// Keep this Markdown break.  \n")
        );
        assert!(formatted.text().contains("pub struct Example {"));
    }

    #[test]
    fn preserves_short_vertical_call_with_trailing_comment() {
        let source = "call(\n    first,\n    second, // keep argument context\n)";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should be protected");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn preserves_internal_blank_lines_in_items() {
        let source = "pub struct First;\n\npub trait Example {\n    type Value;\n\n    fn value(&self) -> Self::Value;\n}\n\npub struct Last;";
        let file = syn::parse_file(source).expect("items should parse");
        let formatted = items(&file.items, source).expect("items should be protected");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn preserves_internal_blank_lines_in_statements() {
        let source = "let first=source();\n\nlet second=source();\nfirst + second";
        let block: syn::Block =
            syn::parse_str(&format!("{{{source}}}")).expect("block should parse");
        let formatted = statements(&block.stmts, source).expect("statements should be protected");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn formats_expression_while_preserving_internal_blank_lines() {
        let source = "match value {\n    Some(value) => {\n        first(value);\n\n        // __commonware_fmt_blank_user_text\n        second(value);\n\n        finish(value)\n    }\n    None => fallback(),\n}";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression_preserving_blank_lines(&input, source)
            .expect("expression should format with blank lines");
        let reparsed: Expr =
            syn::parse_str(formatted.text()).expect("formatted expression should parse");
        let repeated = expression_preserving_blank_lines(&reparsed, formatted.text())
            .expect("formatted expression should remain stable");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(
            formatted
                .text()
                .lines()
                .filter(|line| line.trim().is_empty())
                .count(),
            2
        );
        assert_eq!(
            formatted
                .text()
                .matches("// __commonware_fmt_blank_user_text")
                .count(),
            1
        );
        assert_eq!(formatted.text(), repeated.text());
    }

    #[test]
    fn reattaches_trailing_line_comment() {
        let source = "value // keep exactly";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(formatted.text(), "value // keep exactly\n");
    }

    #[test]
    fn keeps_trailing_comment_before_closing_delimiter() {
        let source = "if !interesting(\n    self.activity_timeout,\n    finalized,\n    current.view,\n    view,\n    true // allow future\n) {\n    return;\n}";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(
            formatted.text().contains("true, // allow future\n)"),
            "{}",
            formatted.text()
        );
    }

    #[test]
    fn reattaches_line_comments_inside_block() {
        let source = "{\n// keep before\nlet value=source();\nvalue // keep trailing\n}";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let once = expression(&input, source)
            .expect("expression should format")
            .into_string();
        let reparsed = syn::parse_str(&once).expect("formatted expression should parse");
        let twice = expression(&reparsed, &once)
            .expect("expression should format twice")
            .into_string();

        assert!(once.contains("// keep before"));
        assert!(once.contains("value // keep trailing"));
        assert_eq!(once, twice);
    }

    #[test]
    fn restores_line_before_collapsed_closing_delimiter() {
        let source = "cell.with_mut(|ptr| {\n    // SAFETY: keep the boundary clear.\n    unsafe { (*ptr).assume_init_read() }\n})";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(
            formatted.text().contains(
                "        // SAFETY: keep the boundary clear.\n        unsafe { (*ptr).assume_init_read() }\n    })"
            ),
            "{}",
            formatted.text()
        );
    }

    #[test]
    fn formats_block_with_leading_comment_and_tail_expression() {
        let source = "{\n// keep field context\nvalue\n}";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should format");

        assert_eq!(
            formatted.disposition(),
            Disposition::Formatted,
            "{}",
            formatted.text()
        );
        assert!(formatted.text().contains("    // keep field context\n"));
    }

    #[test]
    fn collapses_unrelated_call_inside_commented_block() {
        let source = "{\n// keep before call\ncall(\n    value\n)\n}";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(
            formatted.text().contains("call(value)"),
            "{}",
            formatted.text()
        );
        assert!(
            !formatted.text().contains("call(value\n"),
            "{}",
            formatted.text()
        );
    }

    #[test]
    fn keeps_only_nearest_comment_enclosing_close_on_own_line() {
        let source = "call(\n    {\n        // keep inside argument\n        value\n    }\n)";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(
            formatted.text().contains("    value\n})"),
            "{}",
            formatted.text()
        );
        assert!(!formatted.text().contains("}\n)"), "{}", formatted.text());
    }

    #[test]
    fn reattaches_comments_across_prettyplease_token_normalization() {
        let source = "{\nlet value=match input {\nSome(value)=>match value {\n// keep nested\n0=>1,\n_=>2,\n},\nNone=>0,\n};\nif value>0 { call(); };\n// keep after optional semicolon\nvalue\n}";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let once = expression(&input, source)
            .expect("expression should format")
            .into_string();
        let reparsed = syn::parse_str(&once).expect("formatted expression should parse");
        let twice = expression(&reparsed, &once)
            .expect("expression should format twice")
            .into_string();

        assert_eq!(once.matches("// keep nested").count(), 1);
        assert_eq!(once.matches("// keep after optional semicolon").count(), 1);
        assert_eq!(once, twice);
    }

    #[test]
    fn places_trailing_comment_after_normalized_match_arm() {
        let source = "match value {\nSome(value)=>{value} // keep arm\nNone=>0,\n}";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let once = expression(&input, source)
            .expect("expression should format")
            .into_string();
        let reparsed = syn::parse_str(&once).expect("formatted expression should parse");
        let twice = expression(&reparsed, &once)
            .expect("expression should format twice")
            .into_string();

        assert!(once.contains("value, // keep arm\n"), "{once}");
        assert_eq!(once.matches("// keep arm").count(), 1);
        assert_eq!(once, twice);
    }

    #[test]
    fn preserves_block_comments() {
        let source = "call(/* keep */ value)";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should be protected");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn formats_source_spelled_doc_comments_in_item_lists() {
        for (source, expected) in [
            (
                "/// Exact doc text.  \npub struct Example;",
                "Exact doc text.",
            ),
            (
                "/** Exact block doc text.  */\npub struct Example;",
                "Exact block doc text.",
            ),
        ] {
            let file = syn::parse_file(source).expect("item should parse");
            let once = items(&file.items, source).expect("item should format");
            let reparsed = syn::parse_file(once.text()).expect("formatted item should parse");
            let twice = items(&reparsed.items, once.text()).expect("item should format twice");

            assert_eq!(once.disposition(), Disposition::Formatted);
            assert_eq!(once.text().matches(expected).count(), 1);
            assert_eq!(once.text(), twice.text());
        }
    }

    #[test]
    fn ignores_comment_markers_in_literals() {
        let source = "format!(\"http://example.test/*path*/\")";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let formatted = expression(&input, source).expect("expression should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(formatted.text().contains("http://example.test/*path*/"));
    }

    #[test]
    fn reaches_fixed_point() {
        let source = "match value {Some(value)=>value,None=>0}";
        let input: Expr = syn::parse_str(source).expect("expression should parse");
        let once = expression(&input, source)
            .expect("expression should format")
            .into_string();
        let reparsed = syn::parse_str(&once).expect("formatted expression should parse");
        let twice = expression(&reparsed, &once)
            .expect("expression should format twice")
            .into_string();

        assert_eq!(once, twice);
    }

    #[test]
    fn empty_statements_are_empty() {
        let formatted = statements(&[], "").expect("empty statements should format");
        assert_eq!(formatted.text(), "");
        assert_eq!(formatted.disposition(), Disposition::Formatted);
    }
}
