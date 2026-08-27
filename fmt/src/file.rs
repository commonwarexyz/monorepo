//! Complete-file collection and replacement of supported macro bodies.

use crate::{
    macros::{self, LineEnding, MacroKind, Options, macro_kind},
    pretty::Disposition,
    source::SourceMap,
};
use std::ops::Range;
use syn::{Macro, spanned::Spanned, visit::Visit};
use thiserror::Error;

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
    /// A second formatter pass changed the candidate output.
    #[error("formatter output did not reach a fixed point")]
    NotFixedPoint,
}

struct Collector<'ast> {
    macros: Vec<&'ast Macro>,
}

impl<'ast> Visit<'ast> for Collector<'ast> {
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
    let second = format_once(&first.text)?;
    if first.text != second.text {
        return Err(Error::NotFixedPoint);
    }
    Ok(Output {
        text: first.text,
        formatted_macros: first.formatted_macros,
        preserved_macros: first.preserved_macros,
    })
}

fn format_once(source: &str) -> Result<Pass, Error> {
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
        if source_map.slice(open.clone())? != "{"
            || source_map.slice(close.clone())? != "}"
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
        let body = match kind {
            MacroKind::Select => macros::select(body_source, options)?,
            MacroKind::SelectLoop => macros::select_loop(body_source, options)?,
        };
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
        .chars()
        .take_while(|character| *character == ' ')
        .count()
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
        let source = "fn example() {\n    other::select! {value=receive()=>value}\n    select!(value=receive()=>value);\n}\n";
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
}
