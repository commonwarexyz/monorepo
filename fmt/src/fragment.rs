//! Protected Rust fragments and source-fidelity helpers.

use crate::source::SourceMap;
use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::ops::Range;
use syn::Lit;

/// How a protected fragment was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// The fragment was formatted with rustfmt.
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
    marker: String,
    placeholder: String,
    source: String,
}

pub(crate) struct MultilineLiterals {
    shielded: String,
    marker_prefix: String,
    literals: Vec<ShieldedLiteral>,
}

impl MultilineLiterals {
    pub(crate) fn prepare(source: &str) -> Option<Self> {
        let stream = source.parse::<TokenStream>().ok()?;
        let source_map = SourceMap::new(source);
        let mut ranges = Vec::new();
        collect_literal_ranges_for_shielding(stream, &source_map, false, false, &mut ranges)?;
        ranges.retain(|(range, _)| {
            source
                .get(range.clone())
                .is_some_and(|literal| literal.contains('\n') || literal.contains('\r'))
        });
        if ranges.is_empty() {
            return None;
        }

        let marker_prefix = crate::marker::unique_prefix(source, "literal");
        let mut literals = Vec::with_capacity(ranges.len());
        for (index, (range, multiline_placeholder)) in ranges.into_iter().enumerate() {
            let literal = source.get(range.clone())?;
            let line_start = source[..range.start]
                .rfind('\n')
                .map_or(0, |newline| newline + 1);
            let indentation_length = source[line_start..range.start]
                .bytes()
                .take_while(|byte| matches!(byte, b' ' | b'\t'))
                .count();
            let indentation = &source[line_start..line_start + indentation_length];
            let marker = format!("{marker_prefix}{index}_");
            literals.push(ShieldedLiteral {
                range,
                placeholder: literal_placeholder(
                    literal,
                    &marker,
                    multiline_placeholder,
                    indentation,
                )?,
                marker,
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
        for range in ranges {
            let literal = text.get(range.clone())?;
            let mut indexes = self
                .literals
                .iter()
                .enumerate()
                .filter_map(|(index, shielded)| {
                    literal.contains(&shielded.marker).then_some(index)
                });
            let Some(index) = indexes.next() else {
                continue;
            };
            if indexes.next().is_some() {
                return None;
            }
            if matched[index].replace(range).is_some() {
                return None;
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

fn collect_literal_ranges_for_shielding(
    stream: TokenStream,
    source: &SourceMap<'_>,
    rustfmt_context: bool,
    opaque_context: bool,
    ranges: &mut Vec<(Range<usize>, bool)>,
) -> Option<()> {
    let tokens = stream.into_iter().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) => {
                let invocation = macro_invocation_before_group(&tokens, index, group.delimiter());
                let (rustfmt_context, opaque_context) = match invocation {
                    Some(invocation)
                        if !opaque_context && literal_macro_is_transparent(&invocation) =>
                    {
                        (true, false)
                    }
                    Some(_) => (false, true),
                    None => (rustfmt_context, opaque_context),
                };
                collect_literal_ranges_for_shielding(
                    group.stream(),
                    source,
                    rustfmt_context,
                    opaque_context,
                    ranges,
                )?;
            }
            TokenTree::Literal(literal) => ranges.push((
                source.span_range(literal.span()).ok()?,
                rustfmt_context && !opaque_context,
            )),
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
    Some(())
}

struct MacroInvocation {
    path: Vec<String>,
    leading_colon: bool,
    delimiter: Delimiter,
}

fn macro_invocation_before_group(
    tokens: &[TokenTree],
    group: usize,
    delimiter: Delimiter,
) -> Option<MacroInvocation> {
    if group < 2 || !matches!(&tokens[group - 1], TokenTree::Punct(punct) if punct.as_char() == '!')
    {
        return None;
    }
    let mut cursor = group - 2;
    let mut path = Vec::new();
    loop {
        let TokenTree::Ident(ident) = &tokens[cursor] else {
            return None;
        };
        let name = ident.to_string();
        path.push(name.strip_prefix("r#").unwrap_or(&name).to_owned());
        if cursor < 3
            || !matches!(&tokens[cursor - 1], TokenTree::Punct(punct) if punct.as_char() == ':')
            || !matches!(&tokens[cursor - 2], TokenTree::Punct(punct) if punct.as_char() == ':')
            || !matches!(&tokens[cursor - 3], TokenTree::Ident(_))
        {
            break;
        }
        cursor -= 3;
    }
    path.reverse();
    let leading_colon = cursor >= 2
        && matches!(&tokens[cursor - 1], TokenTree::Punct(punct) if punct.as_char() == ':')
        && matches!(&tokens[cursor - 2], TokenTree::Punct(punct) if punct.as_char() == ':');
    Some(MacroInvocation {
        path,
        leading_colon,
        delimiter,
    })
}

fn literal_macro_is_transparent(invocation: &MacroInvocation) -> bool {
    if invocation
        .path
        .last()
        .is_some_and(|name| rustfmt_formats_macro_name(name))
    {
        return true;
    }
    if invocation.leading_colon {
        return false;
    }
    match (invocation.path.as_slice(), invocation.delimiter) {
        ([name], Delimiter::Brace)
            if matches!(name.as_str(), "cfg_if" | "select" | "select_loop") =>
        {
            true
        }
        ([name], Delimiter::Parenthesis)
            if matches!(name.as_str(), "stability_mod" | "stability_scope") =>
        {
            true
        }
        ([prefix, name], Delimiter::Brace)
            if prefix == "cfg_if" && name == "cfg_if"
                || prefix == "commonware_macros"
                    && matches!(name.as_str(), "select" | "select_loop") =>
        {
            true
        }
        ([prefix, name], Delimiter::Parenthesis)
            if prefix == "commonware_macros"
                && matches!(name.as_str(), "stability_mod" | "stability_scope") =>
        {
            true
        }
        _ => false,
    }
}

pub(crate) fn rustfmt_formats_macro_name(name: &str) -> bool {
    matches!(
        name,
        "assert"
            | "assert_eq"
            | "assert_ne"
            | "debug"
            | "debug_assert"
            | "debug_assert_eq"
            | "debug_assert_ne"
            | "debug_span"
            | "eprint"
            | "eprintln"
            | "error"
            | "error_span"
            | "event"
            | "format"
            | "format_args"
            | "format_args_nl"
            | "info"
            | "info_span"
            | "matches"
            | "panic"
            | "print"
            | "println"
            | "todo"
            | "trace"
            | "trace_span"
            | "unimplemented"
            | "unreachable"
            | "vec"
            | "warn"
            | "warn_span"
            | "write"
            | "writeln"
    )
}

fn literal_placeholder(
    source: &str,
    marker: &str,
    multiline: bool,
    indentation: &str,
) -> Option<String> {
    let width = source.lines().next()?.chars().count();
    let (prefix, suffix) = match syn::parse_str::<Lit>(source).ok()? {
        Lit::Str(literal) => ("", literal.suffix().to_owned()),
        Lit::ByteStr(literal) => ("b", literal.suffix().to_owned()),
        Lit::CStr(literal) => ("c", literal.suffix().to_owned()),
        Lit::Byte(_)
        | Lit::Char(_)
        | Lit::Int(_)
        | Lit::Float(_)
        | Lit::Bool(_)
        | Lit::Verbatim(_) => return None,
        _ => return None,
    };
    let placeholder = padded_literal(prefix, marker, &suffix, width);
    if !multiline {
        return Some(placeholder);
    }
    let closing_quote = placeholder.len().checked_sub(suffix.len() + 1)?;
    let mut placeholder = placeholder;
    placeholder.insert_str(closing_quote, &format!("_\n{indentation}"));
    Some(placeholder)
}

fn padded_literal(prefix: &str, marker: &str, suffix: &str, width: usize) -> String {
    let base_width = prefix.chars().count() + marker.chars().count() + suffix.chars().count() + 2;
    format!(
        "{prefix}\"{marker}{}\"{suffix}",
        "_".repeat(width.saturating_sub(base_width))
    )
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
    fn retains_multiline_shape_only_in_rustfmt_macro_placeholders() {
        for rustfmt_source in [
            "panic!(\"first\n    second\")",
            "r#panic!(\"first\n    second\")",
            "tracing::error!(\"first\n    second\")",
            "commonware_macros::select! { value = receive() => \"first\n    second\" }",
        ] {
            let rustfmt_literals =
                MultilineLiterals::prepare(rustfmt_source).expect("literal should be shielded");
            assert!(rustfmt_literals.text().contains('\n'));
            let rustfmt_shielded = rustfmt_literals.text().to_owned();
            assert_eq!(
                rustfmt_literals
                    .restore(ProtectedFragment::formatted(rustfmt_shielded))
                    .expect("literal should restore")
                    .text(),
                rustfmt_source
            );
        }

        for opaque_source in [
            "opaque!(\"first\n    second\")",
            "opaque!(panic!(\"first\n    second\"))",
            "other::select!(\"first\n    second\")",
            "commonware_macros::select!(\"first\n    second\")",
            "::commonware_macros::select! { \"first\n    second\" }",
        ] {
            let opaque_literals =
                MultilineLiterals::prepare(opaque_source).expect("literal should be shielded");
            assert!(!opaque_literals.text().contains('\n'));
        }
    }

    #[test]
    fn detects_only_internal_blank_lines() {
        assert!(source_has_internal_blank_line("first\n\nsecond"));
        assert!(!source_has_internal_blank_line("\nfirst\n"));
    }

    #[test]
    fn distinguishes_comments_from_literal_contents() {
        assert!(source_requires_preservation("value // comment"));
        assert!(!source_requires_preservation(
            "format!(\"http://example.test/*path*/\")"
        ));
    }
}
