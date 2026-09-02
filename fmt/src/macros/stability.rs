//! Formats Commonware stability module declarations and item scopes.
//!
//! Stability levels and visibility are range-validated before canonical
//! reconstruction. Predicates and item bodies are recovered from exact source.
//! Structural comments or preserved multiline fragments keep the original shell
//! so their placement remains intact.

use super::{Error, Options, nested};
use crate::{
    fragment::{Disposition, ProtectedFragment},
    source::SourceMap,
    writer::Writer,
};
use commonware_macros_grammar::{
    StabilityLevel, StabilityLevelSyntax, StabilityModInput, StabilityScopeInput,
};
use quote::ToTokens;
use std::ops::Range;
use syn::{Visibility, spanned::Spanned};

/// Formats the delimiter contents of a `stability_mod!` invocation.
pub(super) fn stability_mod(source: &str) -> Result<ProtectedFragment, Error> {
    let input = syn::parse_str::<StabilityModInput>(source).map_err(Error::Parse)?;
    let source_map = SourceMap::new(source);
    let visibility_range = visibility_range(&source_map, &input.visibility)?;
    let mut ranges = vec![
        level_range(&source_map, &input.level)?,
        source_map.span_range(input.comma_token.span())?,
        source_map.span_range(input.mod_token.span())?,
        source_map.span_range(input.name.span())?,
    ];
    ranges.extend(visibility_range.clone());
    // Reconstruction owns only whitespace between mapped fields. Any other bytes
    // may be comments or opaque syntax whose placement must remain unchanged.
    if !has_only_whitespace_gaps(source, ranges) {
        return Ok(ProtectedFragment::preserved(source));
    }

    let level = level_text(&input.level);
    let visibility = if let Some(range) = visibility_range {
        if crate::fragment::source_requires_preservation(source_map.slice(range)?) {
            return Ok(ProtectedFragment::preserved(source));
        }
        visibility_text(&input.visibility)
    } else {
        String::new()
    };
    let output = format!("{level}, {visibility}mod {}", input.name);
    syn::parse_str::<StabilityModInput>(&output).map_err(Error::Output)?;
    Ok(ProtectedFragment::formatted(output))
}

/// Formats a `stability_scope!` body with the default Rust fragment formatter.
#[cfg(test)]
pub(super) fn stability_scope(
    source: &str,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    stability_scope_with(
        &crate::rustfmt::Formatter::default(),
        source,
        options,
        depth,
    )
}

/// Formats a `stability_scope!` body using the configured Rust fragment formatter.
pub(super) fn stability_scope_with(
    formatter: &crate::rustfmt::Formatter,
    source: &str,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let input = syn::parse_str::<StabilityScopeInput>(source).map_err(Error::Parse)?;
    let source_map = SourceMap::new(source);
    let open = source_map.span_range(input.brace_token.span.open())?;
    let close = source_map.span_range(input.brace_token.span.close())?;
    // The item range is later used as a splice boundary, so delimiter bytes and
    // ordering must be proven rather than inferred from spans alone.
    if source_map.slice(open.clone())? != "{"
        || source_map.slice(close.clone())? != "}"
        || open.end > close.start
    {
        return Err(Error::MarkerDelimiter);
    }

    let items_range = open.end..close.start;
    let mut structural = vec![level_range(&source_map, &input.level)?, open, close];
    if let Some(cfg) = &input.cfg {
        structural.extend([
            source_map.span_range(cfg.comma_token.span())?,
            source_map.span_range(cfg.cfg_ident.span())?,
            source_map.span_range(cfg.paren_token.span.open())?,
            source_map.span_range(cfg.predicate.span())?,
            source_map.span_range(cfg.paren_token.span.close())?,
        ]);
    }
    // The item body is an owned field. Only gaps around shell tokens must be free
    // of structural trivia before canonical rendering.
    structural.push(items_range.clone());
    if !has_only_whitespace_gaps(source, structural) {
        return Ok(ProtectedFragment::preserved(source));
    }

    let items_source = source_map.slice(items_range.clone())?;
    let items = nested::items(
        formatter,
        &input.items,
        items_source,
        items_range.start,
        &source_map,
        depth,
        options.indentation + 4,
    )?;
    if items.disposition() != Disposition::Formatted
        && (items.text().contains('\n') || items.text().contains('\r'))
    {
        // Preserved multiline items cannot be reindented safely. Keep the shell and
        // splice in only nested formatting that retained the original body layout.
        return preserve_scope_items(source, items_range, items_source, &items);
    }

    let level = level_text(&input.level);
    let predicate = if let Some(cfg) = &input.cfg {
        let predicate_source = source_map.slice(source_map.span_range(cfg.predicate.span())?)?;
        let predicate = if crate::fragment::source_requires_preservation(predicate_source) {
            ProtectedFragment::preserved(predicate_source)
        } else {
            // Rustfmt needs the absolute predicate column after `<level>, cfg(`.
            formatter
                .meta(
                    predicate_source,
                    options.body_column + level.chars().count() + 6,
                )
                .map_err(Error::from)?
        };
        if predicate.disposition() != Disposition::Formatted
            && (predicate.text().contains('\n') || predicate.text().contains('\r'))
        {
            // Moving preserved continuation lines would change their relationship
            // to the original shell.
            return preserve_scope_items(source, items_range, items_source, &items);
        }
        Some(predicate.into_string())
    } else {
        None
    };

    let output = render_scope(&level, predicate.as_deref(), items.text(), options);
    syn::parse_str::<StabilityScopeInput>(&output).map_err(Error::Output)?;
    Ok(ProtectedFragment::formatted(output))
}

/// Preserves a stability shell while retaining any nested formatting in its items.
fn preserve_scope_items(
    source: &str,
    items_range: Range<usize>,
    items_source: &str,
    items: &ProtectedFragment,
) -> Result<ProtectedFragment, Error> {
    if items.text() == items_source {
        return Ok(ProtectedFragment::preserved(source));
    }
    // The replacement range comes from the original source map. Reparse after the
    // splice to ensure nested formatting did not invalidate the preserved shell.
    let mut output = source.to_owned();
    output.replace_range(items_range, items.text());
    syn::parse_str::<StabilityScopeInput>(&output).map_err(Error::Output)?;
    Ok(ProtectedFragment::preserved_with_nested_formatting(output))
}

/// Renders a canonical stability scope from formatted component text.
fn render_scope(level: &str, predicate: Option<&str>, items: &str, options: Options) -> String {
    let mut writer = Writer::new_inline(options.indentation, options.line_ending.as_str());
    writer.push(level);
    if let Some(predicate) = predicate {
        writer.push(", cfg(");
        writer.push(predicate);
        writer.push(")");
    }
    if items.is_empty() {
        writer.push(" {}");
        return writer.finish();
    }

    writer.push(" {");
    writer.newline();
    writer.indented(|writer| writer.push(items));
    // Add a line break only when the formatted item fragment did not supply one.
    if !items.ends_with('\n') {
        writer.newline();
    }
    writer.push("}");
    writer.finish()
}

/// Maps the selected stability-level syntax to its exact source range.
fn level_range(source_map: &SourceMap<'_>, level: &StabilityLevel) -> Result<Range<usize>, Error> {
    let span = match level.syntax() {
        StabilityLevelSyntax::Literal(literal) => literal.span(),
        StabilityLevelSyntax::Named(ident) => ident.span(),
    };
    source_map.span_range(span).map_err(Error::from)
}

/// Returns token text for the parsed stability-level syntax.
fn level_text(level: &StabilityLevel) -> String {
    match level.syntax() {
        StabilityLevelSyntax::Literal(literal) => literal.to_string(),
        StabilityLevelSyntax::Named(ident) => ident.to_string(),
    }
}

/// Maps an explicit visibility to source, or returns `None` for inherited visibility.
fn visibility_range(
    source_map: &SourceMap<'_>,
    visibility: &Visibility,
) -> Result<Option<Range<usize>>, Error> {
    if matches!(visibility, Visibility::Inherited) {
        return Ok(None);
    }
    source_map
        .span_range(visibility.span())
        .map(Some)
        .map_err(Error::from)
}

/// Returns canonical source text for a parsed visibility.
fn visibility_text(visibility: &Visibility) -> String {
    match visibility {
        Visibility::Public(_) => "pub ".to_owned(),
        Visibility::Restricted(restricted) => {
            // Token rendering inserts spaces around path separators. Remove them so
            // the reconstructed visibility uses ordinary Rust path spelling.
            let path = restricted
                .path
                .to_token_stream()
                .to_string()
                .replace(" :: ", "::");
            if restricted.in_token.is_some() {
                format!("pub(in {path}) ")
            } else {
                format!("pub({path}) ")
            }
        }
        Visibility::Inherited => String::new(),
    }
}

/// Checks that mapped fields are ordered and all uncovered source is whitespace.
fn has_only_whitespace_gaps(source: &str, ranges: impl IntoIterator<Item = Range<usize>>) -> bool {
    let mut ranges = ranges.into_iter().collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut cursor = 0;
    for range in ranges {
        // Invalid or overlapping spans cannot prove that uncovered bytes are trivia
        // owned by the shell.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::LineEnding;

    const OPTIONS: Options = Options {
        indentation: 0,
        body_column: 0,
        line_ending: LineEnding::Lf,
    };

    #[test]
    fn formats_stability_mod() {
        for (source, expected) in [
            (
                "BETA,pub(crate) mod example",
                "BETA, pub(crate) mod example",
            ),
            (
                "ALPHA,pub(in crate::private) mod example",
                "ALPHA, pub(in crate::private) mod example",
            ),
        ] {
            let formatted = stability_mod(source).expect("stability module should format");
            assert_eq!(formatted.text(), expected);
        }
    }

    #[test]
    fn formats_stability_scope_items_and_cfg() {
        let source = "BETA,cfg(all(test,feature=\"std\")){pub struct Example;fn hidden(){}}";
        let once = stability_scope(source, OPTIONS, 0)
            .expect("stability scope should format")
            .into_string();
        let twice = stability_scope(&once, OPTIONS, 0)
            .expect("stability scope should format twice")
            .into_string();

        assert!(once.starts_with("BETA, cfg(all(test, feature = \"std\")) {\n"));
        assert!(once.contains("    pub struct Example;\n"));
        assert!(once.contains("    fn hidden() {}\n"));
        assert_eq!(once, twice);
    }

    #[test]
    fn preserves_structural_comment() {
        let source = "BETA, // keep\ncfg(test) { pub struct Example; }";
        let formatted =
            stability_scope(source, OPTIONS, 0).expect("commented scope should be preserved");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn formats_internal_item_blank_lines() {
        let source = "BETA {\n    pub struct First;\n\n    pub trait Example {\n        type Value;\n\n        fn value(&self) -> Self::Value;\n    }\n\n    pub struct Last;\n}";
        let formatted =
            stability_scope(source, OPTIONS, 0).expect("stability scope should be protected");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(
            formatted
                .text()
                .contains("pub struct First;\n\n    pub trait Example")
        );
        assert!(formatted.text().contains("type Value;\n\n        fn value"));
    }

    #[test]
    fn formats_nested_macro_without_collapsing_item_blank_lines() {
        let source = "BETA {\n    pub struct First;\n\n    fn run() { select! { value=receive()=>value } }\n}";
        let formatted = stability_scope(source, OPTIONS, 0)
            .expect("nested selection should format")
            .into_string();

        assert!(formatted.contains("pub struct First;\n\n    fn run()"));
        assert!(formatted.contains("value = receive() => value"));
    }

    #[test]
    fn preserves_multiline_predicate_while_formatting_nested_macro() {
        let source = "BETA, cfg(all(\n    test,\n    /* keep */ feature = \"std\"\n)) { fn run() { select! {value=receive()=>value} } }";
        let formatted = stability_scope(source, OPTIONS, 0)
            .expect("stability scope should format nested macro");

        assert_eq!(
            formatted.disposition(),
            Disposition::PreservedWithNestedFormatting
        );
        assert!(formatted.text().contains("/* keep */ feature"));
        assert!(formatted.text().contains("value = receive() => value,"));
    }
}
