//! Complete-file collection and replacement of supported macro bodies.

use crate::{
    macros::{self, LineEnding, Options, delimiter_text, format_at_depth, macro_kind},
    pretty::Disposition,
    skip,
    source::SourceMap,
};
use proc_macro2::{TokenStream, TokenTree};
use std::ops::Range;
use syn::{
    Expr, ForeignItem, ImplItem, Item, Macro, Stmt, TraitItem, spanned::Spanned, visit::Visit,
};
use thiserror::Error;

const MAX_FORMAT_PASSES: usize = 4;

/// The result of formatting one Rust source file.
pub struct Output {
    text: String,
    formatted_macros: usize,
    preserved_macros: usize,
}

impl Output {
    /// Returns the complete formatted source.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Consumes the result and returns the complete formatted source.
    pub fn into_string(self) -> String {
        self.text
    }

    /// Returns the number of supported macro shells formatted on the first pass.
    pub const fn formatted_macros(&self) -> usize {
        self.formatted_macros
    }

    /// Returns the number of supported macro shells preserved on the first pass.
    pub const fn preserved_macros(&self) -> usize {
        self.preserved_macros
    }
}

/// An error produced while formatting a complete Rust source file.
#[derive(Debug, Error)]
pub enum Error {
    /// The input exceeded the nesting accepted by the syntax parser.
    #[error("Rust source exceeded the supported delimiter nesting limit")]
    NestingLimit,
    /// The input or candidate output was not valid Rust syntax.
    #[error("failed to parse Rust source: {0}")]
    Parse(#[source] syn::Error),
    /// A supported macro body could not be formatted.
    #[error("failed to format supported macro: {0}")]
    Macro(#[from] macros::Error),
    /// A source span could not be mapped to a byte range.
    #[error("failed to locate macro source: {0}")]
    Source(#[from] crate::source::Error),
    /// A selected macro did not retain exact brace delimiters.
    #[error("supported macro did not have valid brace delimiters")]
    Delimiter,
    /// Selected macro body replacements overlapped.
    #[error("supported macro replacements overlapped")]
    Overlap,
    /// The formatter did not converge within its bounded pass limit.
    #[error("formatter output did not reach a fixed point")]
    NotFixedPoint,
}

struct Collector<'ast> {
    macros: Vec<&'ast Macro>,
}

impl<'ast> Visit<'ast> for Collector<'ast> {
    fn visit_item(&mut self, node: &'ast Item) {
        if skip::item(node) {
            return;
        }
        syn::visit::visit_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast ImplItem) {
        if skip::impl_item(node) {
            return;
        }
        syn::visit::visit_impl_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast TraitItem) {
        if skip::trait_item(node) {
            return;
        }
        syn::visit::visit_trait_item(self, node);
    }

    fn visit_foreign_item(&mut self, node: &'ast ForeignItem) {
        if skip::foreign_item(node) {
            return;
        }
        syn::visit::visit_foreign_item(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast Stmt) {
        if skip::statement(node) {
            return;
        }
        syn::visit::visit_stmt(self, node);
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        if skip::expression(node) {
            return;
        }
        syn::visit::visit_expr(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if macro_kind(&node.path, &node.delimiter).is_some() {
            self.macros.push(node);
            return;
        }
        syn::visit::visit_macro(self, node);
    }
}

struct Replacement {
    range: Range<usize>,
    text: String,
}

struct Pass {
    text: String,
    formatted_macros: usize,
    preserved_macros: usize,
}

/// Formats every supported Commonware macro invocation in `source`.
pub fn format(source: &str) -> Result<Output, Error> {
    let first = format_once(source)?;
    let formatted_macros = first.formatted_macros;
    let preserved_macros = first.preserved_macros;
    let mut text = first.text;
    for _ in 1..MAX_FORMAT_PASSES {
        let next = format_once(&text)?;
        if next.text == text {
            return Ok(Output {
                text,
                formatted_macros,
                preserved_macros,
            });
        }
        text = next.text;
    }
    Err(Error::NotFixedPoint)
}

fn format_once(source: &str) -> Result<Pass, Error> {
    ensure_nesting_limit(source)?;
    let file = syn::parse_file(source).map_err(Error::Parse)?;
    let mut collector = Collector { macros: Vec::new() };
    collector.visit_file(&file);

    let source_map = SourceMap::new(source);
    let line_ending = dominant_line_ending(source);
    let mut replacements = Vec::new();
    let mut formatted_macros = 0;
    let mut preserved_macros = 0;
    for invocation in collector.macros {
        let kind = macro_kind(&invocation.path, &invocation.delimiter)
            .expect("collector only retains supported macros");
        let delimiter = invocation.delimiter.span();
        let open = source_map.span_range(delimiter.open())?;
        let close = source_map.span_range(delimiter.close())?;
        let (expected_open, expected_close) =
            delimiter_text(&invocation.delimiter).ok_or(Error::Delimiter)?;
        if source_map.slice(open.clone())? != expected_open
            || source_map.slice(close.clone())? != expected_close
            || open.end > close.start
        {
            return Err(Error::Delimiter);
        }
        let body_range = open.end..close.start;
        let body_source = source_map.slice(body_range.clone())?;
        let path_start = source_map.byte_offset(invocation.path.span().start())?;
        let options = Options {
            indentation: line_indentation(source, path_start),
            line_ending,
        };
        let body = format_at_depth(kind, body_source, options, 0)?;
        if body.disposition() == Disposition::Formatted {
            formatted_macros += 1;
        } else {
            preserved_macros += 1;
        }
        if body.text() != body_source {
            replacements.push(Replacement {
                range: body_range,
                text: body.into_string(),
            });
        }
    }

    replacements
        .sort_unstable_by_key(|replacement| (replacement.range.start, replacement.range.end));
    if replacements
        .windows(2)
        .any(|pair| pair[0].range.end > pair[1].range.start)
    {
        return Err(Error::Overlap);
    }
    let mut output = source.to_owned();
    for replacement in replacements.into_iter().rev() {
        output.replace_range(replacement.range, &replacement.text);
    }
    syn::parse_file(&output).map_err(Error::Parse)?;
    Ok(Pass {
        text: output,
        formatted_macros,
        preserved_macros,
    })
}

const MAX_DELIMITER_DEPTH: usize = 256;

fn ensure_nesting_limit(source: &str) -> Result<(), Error> {
    let Ok(stream) = source.parse::<TokenStream>() else {
        return Ok(());
    };
    let mut iterators = vec![stream.into_iter()];
    while let Some(iterator) = iterators.last_mut() {
        match iterator.next() {
            Some(TokenTree::Group(group)) => {
                if iterators.len() > MAX_DELIMITER_DEPTH {
                    return Err(Error::NestingLimit);
                }
                iterators.push(group.stream().into_iter());
            }
            Some(_) => {}
            None => {
                iterators.pop();
            }
        }
    }
    Ok(())
}

fn dominant_line_ending(source: &str) -> LineEnding {
    let crlf = source.match_indices("\r\n").count();
    let lf = source.bytes().filter(|byte| *byte == b'\n').count();
    if crlf > lf.saturating_sub(crlf) {
        LineEnding::Crlf
    } else {
        LineEnding::Lf
    }
}

fn line_indentation(source: &str, offset: usize) -> usize {
    let line_start = source[..offset]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    source[line_start..offset]
        .bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .fold(0, |column, byte| match byte {
            b' ' => column + 1,
            b'\t' => (column / 4 + 1) * 4,
            _ => unreachable!("indentation contains only spaces and tabs"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_supported_macros_and_preserves_surrounding_source() {
        let source = "fn example() {\n    let before = 1;\n    select! {value=receive()=>value}\n    commonware_macros::select_loop! {context,on_stopped=>shutdown(),}\n    let after = 2;\n}\n";
        let formatted = format(source).expect("file should format");

        assert_eq!(formatted.formatted_macros(), 2);
        assert_eq!(formatted.preserved_macros(), 0);
        assert!(formatted.text().contains("    let before = 1;\n"));
        assert!(formatted.text().contains("    let after = 2;\n"));
        assert!(
            formatted
                .text()
                .contains("select! {\n        value = receive() => value,\n    }")
        );
        assert!(formatted.text().contains(
            "commonware_macros::select_loop! {\n        context,\n        on_stopped => shutdown(),\n    }"
        ));
    }

    #[test]
    fn formats_a_first_line_macro_after_a_byte_order_mark() {
        let source = "\u{feff}select! {value=receive()=>value}\n";
        let formatted = format(source).expect("file with byte order mark should format");

        assert!(formatted.text().starts_with("\u{feff}select! {\n"));
        assert!(formatted.text().contains("value = receive() => value,"));
    }

    #[test]
    fn aligns_a_tab_indented_macro_shell() {
        let source = "fn run() {\n\tselect! {value=receive()=>value}\n}\n";
        let formatted = format(source).expect("tab-indented macro should format");

        assert!(
            formatted
                .text()
                .contains("\tselect! {\n        value = receive() => value,\n    }")
        );
    }

    #[test]
    fn rejects_excessive_delimiter_nesting_without_recursing() {
        let source = format!(
            "fn run() {{ let _ = {}0{}; }}",
            "(".repeat(10_000),
            ")".repeat(10_000)
        );

        assert!(matches!(format(&source), Err(Error::NestingLimit)));
    }

    #[test]
    fn formats_stability_macros_and_nested_select() {
        let source = "commonware_macros::stability_mod!(ALPHA,pub(crate) mod example);\nstability_scope!(BETA,cfg(test){\n// keep item comment\n/// Run one selection.\nfn run(){select! {value=receive()=>value}}\n});\n";
        let once = format(source).expect("stability macros should format");
        let twice = format(once.text()).expect("stability macros should format twice");

        assert_eq!(once.formatted_macros(), 2);
        assert_eq!(once.preserved_macros(), 0);
        assert!(
            once.text()
                .contains("commonware_macros::stability_mod!(ALPHA, pub(crate) mod example);")
        );
        assert!(once.text().contains("stability_scope!(BETA, cfg(test) {\n"));
        assert_eq!(once.text().matches("// keep item comment").count(), 1);
        assert_eq!(once.text().matches("/// Run one selection.").count(), 1);
        assert!(once.text().contains("value = receive() => value,"));
        assert_eq!(once.text(), twice.text());
    }

    #[test]
    fn formats_cfg_if_in_files_and_stability_scopes() {
        let source = "cfg_if::cfg_if! { if #[cfg(test)] { const VALUE:usize=1; } else { const VALUE:usize=2; } }\nfn run() { cfg_if! { if #[cfg(test)] { let value=source(); value } else { fallback() } } }\nstability_scope!(ALPHA { cfg_if! { if #[cfg(test)] { pub struct Example{pub value:usize} } } });\n";
        let once = format(source).expect("cfg_if macros should format");
        let twice = format(once.text()).expect("cfg_if macros should format twice");

        assert_eq!(once.formatted_macros(), 3);
        assert_eq!(once.preserved_macros(), 0);
        assert!(once.text().contains("const VALUE: usize = 1;"));
        assert!(once.text().contains("let value = source();"));
        assert!(once.text().contains("pub struct Example {"));
        assert_eq!(once.text(), twice.text());
    }

    #[test]
    fn honors_scoped_rustfmt_skip() {
        let source = "#[rustfmt::skip]\nfn skipped() {\n    select! {value=receive()=>value}\n}\n\nfn formatted() {\n    select! {value=receive()=>value}\n}\n\nfn skipped_statement() {\n    #[rustfmt::skip]\n    select! {value=receive()=>value};\n    #[rustfmt::skip]\n    consume(select! {value=receive()=>value});\n}\n";
        let formatted = format(source).expect("unskipped macro should format");

        assert_eq!(formatted.formatted_macros(), 1);
        assert!(
            formatted.text().contains(
                "#[rustfmt::skip]\nfn skipped() {\n    select! {value=receive()=>value}\n}"
            )
        );
        assert!(formatted.text().contains(
            "fn formatted() {\n    select! {\n        value = receive() => value,\n    }\n}"
        ));
        assert!(
            formatted
                .text()
                .contains("#[rustfmt::skip]\n    select! {value=receive()=>value};")
        );
        assert!(
            formatted
                .text()
                .contains("#[rustfmt::skip]\n    consume(select! {value=receive()=>value});")
        );
    }

    #[test]
    fn preserves_skipped_item_inside_stability_scope() {
        let source = "stability_scope!(ALPHA {\n    #[rustfmt::skip]\n    fn skipped() { select! {value=receive()=>value} }\n    fn formatted() { select! {value=receive()=>value} }\n});\n";
        let formatted = format(source).expect("unskipped nested macro should format");

        assert_eq!(formatted.formatted_macros(), 0);
        assert_eq!(formatted.preserved_macros(), 1);
        assert!(
            formatted.text().contains(
                "#[rustfmt::skip]\n    fn skipped() { select! {value=receive()=>value} }"
            )
        );
        assert!(formatted.text().contains("value = receive() => value,"));
        assert_eq!(
            formatted.text().matches("value=receive()=>value").count(),
            1
        );
    }

    #[test]
    fn preserves_crlf_while_restoring_nested_stability_items() {
        let source = "stability_scope!(ALPHA {\r\n    #[rustfmt::skip]\r\n    fn skipped() { select! {value=receive()=>value} }\r\n    fn formatted() { select! {value=receive()=>value} }\r\n});\r\n";
        let formatted = format(source).expect("nested macro should preserve CRLF");

        assert!(!formatted.text().replace("\r\n", "").contains('\n'));
        assert!(formatted.text().contains("value = receive() => value,"));
    }

    #[test]
    fn keeps_deep_formatting_through_preserved_stability_item() {
        let source = "stability_scope!(ALPHA {\n    fn run() {\n        select! {\n            outer=receive_outer()=>{\n                /* keep */\n                select! {inner=receive_inner()=>inner}\n            }\n        }\n    }\n});\n";
        let formatted = format(source).expect("deep nested macro should format safely");

        assert_eq!(formatted.text().matches("/* keep */").count(), 1);
        assert_eq!(
            formatted
                .text()
                .matches("inner = receive_inner() => inner,")
                .count(),
            1
        );
        assert!(!formatted.text().contains("__commonware_fmt_nested_"));
    }

    #[test]
    fn formats_nested_macro_inside_commented_outer_shell() {
        let source = "fn example() {\n    select! {\n        // Keep this seam.\n        outer = receive_outer() => select! {inner=receive_inner()=>inner},\n    }\n}\n";
        let formatted = format(source).expect("file should format safely");

        assert_eq!(formatted.formatted_macros(), 1);
        assert_eq!(formatted.preserved_macros(), 0);
        assert!(formatted.text().contains("// Keep this seam."));
        assert!(
            formatted
                .text()
                .contains("inner = receive_inner() => inner,")
        );
    }

    #[test]
    fn preserves_block_comment_around_formatted_nested_macro() {
        let source = "fn example() {\n    select! {\n        outer=receive_outer()=>{/* keep */select! {inner=receive_inner()=>inner}}\n    }\n}\n";
        let once = format(source).expect("file should preserve block comment safely");
        let twice = format(once.text()).expect("file should reach a fixed point");

        assert_eq!(once.text().matches("/* keep */").count(), 1);
        assert!(once.text().contains("select!"));
        assert!(!once.text().contains("__commonware_fmt_nested_"));
        assert!(once.text().contains("inner = receive_inner() => inner,"));
        assert_eq!(once.text(), twice.text());
    }

    #[test]
    fn ignores_unsupported_paths_and_delimiters() {
        let source = "fn example() {\n    other::select! {value=receive()=>value}\n    select!(value=receive()=>value);\n}\nother::cfg_if! { if #[cfg(test)] { const VALUE:usize=1; } }\ncfg_if!(if #[cfg(test)] { const VALUE:usize=1; });\n";
        let formatted = format(source).expect("file should remain valid");

        assert_eq!(formatted.text(), source);
        assert_eq!(formatted.formatted_macros(), 0);
    }

    #[test]
    fn preserves_crlf_line_endings() {
        let source = "fn example() {\r\n    select! {value=receive()=>value}\r\n}\r\n";
        let formatted = format(source).expect("file should format");

        assert!(!formatted.text().replace("\r\n", "").contains('\n'));
        assert!(
            formatted
                .text()
                .contains("select! {\r\n        value = receive() => value,\r\n    }")
        );
    }

    #[test]
    fn formats_escaped_newline_literal_without_changing_token() {
        let literal = "\"voter should recover after failure, \\\n+                             even when certification remains pending\"";
        let source = format!("fn run() {{\n    select! {{ _=wait()=>panic!({literal}) }}\n}}\n");
        let formatted = format(&source).expect("file should format");

        assert_eq!(formatted.formatted_macros(), 1);
        assert_eq!(formatted.preserved_macros(), 0);
        assert_eq!(formatted.text().matches(literal).count(), 1);
        assert!(formatted.text().contains("_ = wait() => panic!("));
    }

    #[test]
    fn formats_multiline_literal_inside_opaque_nested_macro() {
        let literal = "r#\"first\n    second\"#";
        let source =
            format!("fn run() {{\n    select! {{ value=receive()=>opaque!({literal}) }}\n}}\n");
        let formatted = format(&source).expect("file should format");

        assert_eq!(formatted.formatted_macros(), 1);
        assert_eq!(formatted.preserved_macros(), 0);
        assert_eq!(formatted.text().matches(literal).count(), 1);
        assert!(formatted.text().contains("value = receive() => opaque!("));
    }

    #[test]
    fn formats_multiline_byte_and_c_literals_without_changing_tokens() {
        let byte_literal = "br#\"first\n    second\"#";
        let c_literal = "cr#\"third\n    fourth\"#";
        let source = format!(
            "fn run() {{\n    select! {{ value=receive()=>consume({byte_literal},{c_literal}) }}\n}}\n"
        );
        let formatted = format(&source).expect("file should format");

        assert_eq!(formatted.formatted_macros(), 1);
        assert_eq!(formatted.preserved_macros(), 0);
        assert_eq!(formatted.text().matches(byte_literal).count(), 1);
        assert_eq!(formatted.text().matches(c_literal).count(), 1);
        assert!(formatted.text().contains("value = receive() => consume("));
    }

    #[test]
    fn reattaches_exact_line_comments_in_crlf_file() {
        let source = "fn example() {\r\n    select! {\r\n        // na\u{ef}ve leading  \r\n        value=receive()=>{\r\n            // duplicate  \r\n            value // duplicate  \r\n        },\r\n        // trailing body  \r\n    }\r\n}\r\n";
        let formatted = format(source).expect("comments should format safely");

        assert_eq!(formatted.formatted_macros(), 1);
        assert_eq!(formatted.preserved_macros(), 0);
        assert!(!formatted.text().replace("\r\n", "").contains('\n'));
        assert!(formatted.text().contains("// na\u{ef}ve leading  \r\n"));
        assert_eq!(formatted.text().matches("// duplicate  \r\n").count(), 2);
        assert!(formatted.text().contains("// trailing body  \r\n"));
    }

    #[test]
    fn rejects_invalid_supported_macro_body() {
        let source = "fn example() {\n    select! {value}\n}\n";
        assert!(matches!(format(source), Err(Error::Macro(_))));
    }

    #[test]
    fn converges_before_returning_destination_sensitive_output() {
        let source = "fn run() {\n    select! {\n        output = receive() => match output {\n            Some(Message::Verified { certificate: Certificate::Notarization(value), .. }) => consume(value),\n            Some(Message::Verified { certificate: Certificate::Finalization(value), .. }) => consume(value),\n            None => return,\n        },\n    }\n}\n";
        let formatted = format(source).expect("destination-sensitive source should converge");
        let repeated = format(formatted.text()).expect("formatted source should remain stable");

        assert_eq!(formatted.text(), repeated.text());
    }
}
