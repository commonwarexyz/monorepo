//! Preserves nested macros while formatting surrounding Rust fragments.
//!
//! Macros that rustfmt does not format are replaced with unique, parseable markers.
//! After rustfmt runs, supported macro bodies are formatted recursively and opaque
//! macros are restored with indentation adjusted only when safe. Ambiguous marker
//! placement falls back to the original surrounding source.

use super::{Error, LineEnding, MacroKind, Options, delimiter_text, format_at_depth, macro_kind};
use crate::{
    fragment::{self, Disposition, ProtectedFragment},
    skip,
    source::SourceMap,
};
use proc_macro2::{Ident, Span};
use std::ops::Range;
use syn::{
    Block, Expr, ForeignItem, ImplItem, Item, Macro, Stmt, TraitItem,
    ext::IdentExt as _,
    parse::Parser,
    spanned::Spanned,
    visit::{self, Visit},
    visit_mut::{self, VisitMut},
};

/// Maximum supported-macro nesting depth formatted in one pass.
const RECURSION_LIMIT: usize = 32;

/// Selects the rustfmt wrapper used for an expression fragment.
#[derive(Clone, Copy)]
enum Style {
    /// Formats a standalone expression.
    Expression,
    /// Formats an expression in match-arm body context.
    MatchArmBody,
    /// Formats a source-spelled block expression without discarding its braces.
    BlockExpression,
}

/// Controls expression shielding and recursive nested-macro formatting.
#[derive(Clone, Copy)]
struct ExpressionOptions {
    /// Destination indentation passed to the selected rustfmt wrapper.
    indentation: usize,
    /// Current supported-macro nesting depth.
    depth: usize,
    /// Syntactic wrapper used to format the expression.
    style: Style,
    /// Whether supported nested macro bodies may be formatted recursively.
    format_supported: bool,
}

impl Style {
    /// Formats `source` with this style's syntactic wrapper.
    fn format(
        self,
        formatter: &crate::rustfmt::Formatter,
        source: &str,
        indentation: usize,
    ) -> Result<ProtectedFragment, Error> {
        match self {
            Self::Expression => formatter
                .expression(source, indentation)
                .map_err(Error::from),
            Self::BlockExpression => formatter
                .block_expression(source, indentation)
                .map_err(Error::from),
            Self::MatchArmBody => formatter
                .match_arm_body(source, indentation)
                .map_err(Error::from),
        }
    }
}

/// Selects the grammar used to parse and locate markers after formatting.
#[derive(Clone, Copy)]
enum RestoreStyle {
    /// Parses the fragment as one expression.
    Expression,
    /// Parses the fragment as a Rust file containing items.
    Items,
    /// Parses the fragment as a sequence of block statements.
    Statements,
}

/// State used to restore markers in an item or statement collection.
struct CollectionRestore<'a> {
    /// Formatter used when recursively formatting supported child macros.
    formatter: &'a crate::rustfmt::Formatter,
    /// Original collection source used by the conservative fallback.
    fragment_source: &'a str,
    /// Collection source with every recorded macro replaced by a marker.
    shielded_source: &'a str,
    /// Prefix that identifies only markers created for this collection.
    marker_prefix: &'a str,
    /// Original macro metadata in source traversal order.
    nested: &'a [NestedMacro],
    /// Current supported-macro nesting depth.
    depth: usize,
    /// Grammar used to find markers in formatted output.
    style: RestoreStyle,
    /// Whether a skip attribute prevents accepting a rewritten outer shell.
    had_skip: bool,
}

/// Original source and marker metadata for one shielded macro invocation.
struct NestedMacro {
    marker: String,
    kind: NestedKind,
    source_range: Range<usize>,
    prefix: String,
    body: String,
    suffix: String,
    original_column: usize,
    marker_open: &'static str,
    marker_close: &'static str,
}

/// Determines whether a shielded body is formatted recursively or kept opaque.
#[derive(Clone, Copy)]
enum NestedKind {
    /// A supported macro whose body can be formatted at the next depth.
    Supported(MacroKind),
    /// A macro whose invocation must be restored without formatting its body.
    Opaque,
}

/// Replaces macros in an AST clone with unique markers and records their source.
struct Shield<'a> {
    source_map: &'a SourceMap<'a>,
    marker_prefix: String,
    nested: Vec<NestedMacro>,
    had_skip: bool,
    format_supported: bool,
    error: Option<Error>,
}

/// Detects whether shielding is needed and whether skip attributes require preservation.
#[derive(Default)]
struct ShieldPreflight {
    has_macro: bool,
    had_skip: bool,
}

impl<'ast> Visit<'ast> for ShieldPreflight {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if skip::expression(node) {
            self.had_skip = true;
            return;
        }
        visit::visit_expr(self, node);
    }

    fn visit_item(&mut self, node: &'ast Item) {
        if skip::item(node) {
            self.had_skip = true;
            return;
        }
        visit::visit_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast ImplItem) {
        if skip::impl_item(node) {
            self.had_skip = true;
            return;
        }
        visit::visit_impl_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast TraitItem) {
        if skip::trait_item(node) {
            self.had_skip = true;
            return;
        }
        visit::visit_trait_item(self, node);
    }

    fn visit_foreign_item(&mut self, node: &'ast ForeignItem) {
        if skip::foreign_item(node) {
            self.had_skip = true;
            return;
        }
        visit::visit_foreign_item(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast Stmt) {
        if skip::statement(node) {
            self.had_skip = true;
            return;
        }
        visit::visit_stmt(self, node);
    }

    fn visit_macro(&mut self, _node: &'ast Macro) {
        self.has_macro = true;
    }
}

impl Shield<'_> {
    /// Validates and records `node`, then replaces it with a delimiter-matched marker.
    fn shield(&mut self, node: &mut Macro, kind: NestedKind) -> Result<(), Error> {
        let delimiter = node.delimiter.span();
        let open = self.source_map.span_range(delimiter.open())?;
        let close = self.source_map.span_range(delimiter.close())?;
        let (expected_open, expected_close) =
            delimiter_text(&node.delimiter).ok_or(Error::MarkerDelimiter)?;
        // Proc-macro spans are accepted only when they point at the expected
        // delimiter bytes in source order.
        if self.source_map.slice(open.clone())? != expected_open
            || self.source_map.slice(close.clone())? != expected_close
            || open.end > close.start
        {
            return Err(Error::MarkerDelimiter);
        }
        let start = self.source_map.byte_offset(node.path.span().start())?;
        if start > open.start {
            return Err(Error::MarkerDelimiter);
        }

        let marker = format!("{}{}", self.marker_prefix, self.nested.len());
        // Preserve the original delimiter shape so the placeholder remains valid
        // in the same expression, statement, or item context.
        self.nested.push(NestedMacro {
            marker: marker.clone(),
            kind,
            source_range: start..close.end,
            prefix: self.source_map.slice(start..open.end)?.to_owned(),
            body: self.source_map.slice(open.end..close.start)?.to_owned(),
            suffix: self.source_map.slice(close.start..close.end)?.to_owned(),
            original_column: node.path.span().start().column,
            marker_open: expected_open,
            marker_close: expected_close,
        });

        let ident = Ident::new(&marker, node.path.span());
        *node = match &node.delimiter {
            syn::MacroDelimiter::Paren(_) => syn::parse_quote_spanned!(node.span()=> #ident!()),
            syn::MacroDelimiter::Brace(_) => syn::parse_quote_spanned!(node.span()=> #ident! {}),
            syn::MacroDelimiter::Bracket(_) => syn::parse_quote_spanned!(node.span()=> #ident![]),
        };
        Ok(())
    }
}

impl VisitMut for Shield<'_> {
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        if skip::expression(node) {
            self.had_skip = true;
            return;
        }
        visit_mut::visit_expr_mut(self, node);
    }

    fn visit_item_mut(&mut self, node: &mut Item) {
        if skip::item(node) {
            self.had_skip = true;
            return;
        }
        visit_mut::visit_item_mut(self, node);
    }

    fn visit_impl_item_mut(&mut self, node: &mut ImplItem) {
        if skip::impl_item(node) {
            self.had_skip = true;
            return;
        }
        visit_mut::visit_impl_item_mut(self, node);
    }

    fn visit_trait_item_mut(&mut self, node: &mut TraitItem) {
        if skip::trait_item(node) {
            self.had_skip = true;
            return;
        }
        visit_mut::visit_trait_item_mut(self, node);
    }

    fn visit_foreign_item_mut(&mut self, node: &mut ForeignItem) {
        if skip::foreign_item(node) {
            self.had_skip = true;
            return;
        }
        visit_mut::visit_foreign_item_mut(self, node);
    }

    fn visit_stmt_mut(&mut self, node: &mut Stmt) {
        if skip::statement(node) {
            self.had_skip = true;
            return;
        }
        visit_mut::visit_stmt_mut(self, node);
    }

    fn visit_macro_mut(&mut self, node: &mut Macro) {
        if self.error.is_some() {
            return;
        }
        if rustfmt_formats_macro(node) {
            // Rustfmt can handle these macro bodies directly, so exposing them is
            // both safe and necessary for its native formatting rules.
            return;
        }
        let kind = if self.format_supported {
            macro_kind(&node.path, &node.delimiter)
                .map_or(NestedKind::Opaque, NestedKind::Supported)
        } else {
            NestedKind::Opaque
        };
        if let Err(error) = self.shield(node, kind) {
            self.error = Some(error);
        }
    }
}

/// Returns whether rustfmt natively formats the macro identified by `node`.
fn rustfmt_formats_macro(node: &Macro) -> bool {
    let Some(name) = node
        .path
        .segments
        .last()
        .map(|segment| segment.ident.unraw().to_string())
    else {
        return false;
    };
    fragment::rustfmt_formats_macro_name(&name)
}

/// One marker invocation found in rustfmt's output.
struct Marker {
    name: String,
    path_span: Span,
    open_span: Span,
    close_span: Span,
    open_text: &'static str,
    close_text: &'static str,
}

/// Collects generated marker invocations in source traversal order.
struct MarkerCollector<'a> {
    prefix: &'a str,
    markers: Vec<Marker>,
}

/// Source spans and format kind for one supported child macro.
struct ChildMacro {
    kind: MacroKind,
    path_span: Span,
    open_span: Span,
    close_span: Span,
    open_text: &'static str,
    close_text: &'static str,
}

/// Collects the outermost supported macros that own recursive formatting work.
#[derive(Default)]
struct ChildCollector {
    macros: Vec<ChildMacro>,
}

impl<'ast> Visit<'ast> for ChildCollector {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if skip::expression(node) {
            return;
        }
        visit::visit_expr(self, node);
    }

    fn visit_item(&mut self, node: &'ast Item) {
        if skip::item(node) {
            return;
        }
        visit::visit_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast ImplItem) {
        if skip::impl_item(node) {
            return;
        }
        visit::visit_impl_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast TraitItem) {
        if skip::trait_item(node) {
            return;
        }
        visit::visit_trait_item(self, node);
    }

    fn visit_foreign_item(&mut self, node: &'ast ForeignItem) {
        if skip::foreign_item(node) {
            return;
        }
        visit::visit_foreign_item(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast Stmt) {
        if skip::statement(node) {
            return;
        }
        visit::visit_stmt(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if let Some(kind) = macro_kind(&node.path, &node.delimiter) {
            let delimiter = node.delimiter.span();
            let Some((open_text, close_text)) = delimiter_text(&node.delimiter) else {
                return;
            };
            self.macros.push(ChildMacro {
                kind,
                path_span: node.path.span(),
                open_span: delimiter.open(),
                close_span: delimiter.close(),
                open_text,
                close_text,
            });
            // Descendants belong to this macro body's recursive formatting pass.
            return;
        }
        visit::visit_macro(self, node);
    }
}

impl<'ast> Visit<'ast> for MarkerCollector<'_> {
    fn visit_macro(&mut self, node: &'ast Macro) {
        if let Some(ident) = node.path.get_ident()
            && ident.to_string().starts_with(self.prefix)
        {
            let delimiter = node.delimiter.span();
            let Some((open_text, close_text)) = delimiter_text(&node.delimiter) else {
                return;
            };
            self.markers.push(Marker {
                name: ident.to_string(),
                path_span: node.path.span(),
                open_span: delimiter.open(),
                close_span: delimiter.close(),
                open_text,
                close_text,
            });
            return;
        }
        visit::visit_macro(self, node);
    }
}

/// Formats supported nested macro bodies while preserving the outer fragment source.
pub(super) fn preserve_with_nested(
    formatter: &crate::rustfmt::Formatter,
    source: &str,
    source_map: &SourceMap<'_>,
    expressions: &[&Expr],
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let mut collector = ChildCollector::default();
    for expression in expressions {
        collector.visit_expr(expression);
    }
    preserve_collected(formatter, source, source_map, collector, options, depth)
}

/// Formats supported nested macros inside item and statement bodies.
///
/// The surrounding body source remains unchanged. This is the conservative path
/// used when a parent macro cannot safely rewrite its own shell.
pub(super) fn preserve_bodies_with_nested(
    formatter: &crate::rustfmt::Formatter,
    source: &str,
    source_map: &SourceMap<'_>,
    item_groups: &[&[Item]],
    statement_groups: &[&[Stmt]],
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let mut collector = ChildCollector::default();
    for items in item_groups {
        for item in *items {
            collector.visit_item(item);
        }
    }
    for statements in statement_groups {
        for statement in *statements {
            collector.visit_stmt(statement);
        }
    }
    preserve_collected(formatter, source, source_map, collector, options, depth)
}

/// Applies recursive formatting to collected child bodies by validated source range.
fn preserve_collected(
    formatter: &crate::rustfmt::Formatter,
    fragment_source: &str,
    source_map: &SourceMap<'_>,
    collector: ChildCollector,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    if collector.macros.is_empty() {
        return Ok(ProtectedFragment::preserved(fragment_source));
    }
    // Every recursive entry increments the depth before formatting a child body.
    if depth >= RECURSION_LIMIT {
        return Err(Error::RecursionLimit);
    }

    let mut replacements = Vec::new();
    for child in collector.macros {
        let path_start = source_map.byte_offset(child.path_span.start())?;
        let open = source_map.span_range(child.open_span)?;
        let close = source_map.span_range(child.close_span)?;
        if source_map.slice(open.clone())? != child.open_text
            || source_map.slice(close.clone())? != child.close_text
            || open.end > close.start
        {
            return Err(Error::MarkerDelimiter);
        }
        let body_range = open.end..close.start;
        let body_source = source_map.slice(body_range.clone())?;
        // Child options are derived from the invocation's actual source location,
        // with the caller's values serving as the first-line origin.
        let child_options = Options {
            indentation: line_indentation(fragment_source, path_start, options.indentation),
            body_column: line_column(fragment_source, open.end, options.body_column),
            line_ending: options.line_ending,
        };
        let body = format_at_depth(formatter, child.kind, body_source, child_options, depth + 1)?;
        if body.text() != body_source {
            let start = body_range.start;
            let end = body_range.end;
            if start > end || end > fragment_source.len() {
                return Err(Error::MarkerMismatch);
            }
            replacements.push((start..end, body.into_string()));
        }
    }

    if replacements.is_empty() {
        return Ok(ProtectedFragment::preserved(fragment_source));
    }
    replacements.sort_unstable_by_key(|(range, _)| (range.start, range.end));
    if replacements
        .windows(2)
        .any(|pair| pair[0].0.end > pair[1].0.start)
    {
        return Err(Error::MarkerMismatch);
    }
    let mut output = fragment_source.to_owned();
    // Reverse order keeps earlier byte ranges valid while replacements change size.
    for (range, replacement) in replacements.into_iter().rev() {
        output.replace_range(range, &replacement);
    }
    Ok(ProtectedFragment::preserved_with_nested_formatting(output))
}

/// Formats an expression while shielding macros that rustfmt cannot inspect safely.
pub(super) fn expression(
    formatter: &crate::rustfmt::Formatter,
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    indentation: usize,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    format_expression(
        formatter,
        expression,
        fragment_source,
        source,
        source_map,
        ExpressionOptions {
            indentation,
            depth,
            style: Style::Expression,
            format_supported: true,
        },
    )
}

/// Formats an expression as a match-arm body while shielding nested macros.
pub(super) fn match_arm_body(
    formatter: &crate::rustfmt::Formatter,
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    indentation: usize,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    format_expression(
        formatter,
        expression,
        fragment_source,
        source,
        source_map,
        ExpressionOptions {
            indentation,
            depth,
            style: Style::MatchArmBody,
            format_supported: true,
        },
    )
}

/// Formats a block expression while preserving its source-spelled block context.
pub(super) fn block_expression(
    formatter: &crate::rustfmt::Formatter,
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    indentation: usize,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    format_expression(
        formatter,
        expression,
        fragment_source,
        source,
        source_map,
        ExpressionOptions {
            indentation,
            depth,
            style: Style::BlockExpression,
            format_supported: true,
        },
    )
}

/// Result of formatting an expression for a possible destination indentation.
pub(super) struct RelocatedExpression {
    /// Expression text formatted at the requested indentation.
    pub(super) fragment: ProtectedFragment,
    /// Whether a supported nested macro prevented arbitrary later relocation.
    pub(super) had_supported: bool,
}

/// Probes an expression at a destination indentation without formatting supported macros.
///
/// Opaque macros are shielded and restored. `had_supported` tells the caller that
/// the expression must be formatted again after its final placement is known.
pub(super) fn relocate_expression(
    formatter: &crate::rustfmt::Formatter,
    source: &str,
    indentation: usize,
) -> Result<RelocatedExpression, Error> {
    let expression = syn::parse_str::<Expr>(source).map_err(Error::Parse)?;
    let mut collector = ChildCollector::default();
    collector.visit_expr(&expression);
    let source_map = SourceMap::new(source);
    let fragment = format_expression(
        formatter,
        &expression,
        source,
        source,
        &source_map,
        ExpressionOptions {
            indentation,
            depth: 0,
            style: Style::Expression,
            format_supported: false,
        },
    )?;
    Ok(RelocatedExpression {
        fragment,
        had_supported: !collector.macros.is_empty(),
    })
}

/// Formats an item collection after shielding nested macros.
///
/// When structurally valid marker placement is unsafe to accept, restoration
/// retries against the original shell and retains supported child formatting when
/// possible. Missing, duplicated, or reordered markers remain an error.
pub(super) fn items(
    formatter: &crate::rustfmt::Formatter,
    items: &[Item],
    fragment_source: &str,
    fragment_start: usize,
    source_map: &SourceMap<'_>,
    depth: usize,
    indentation: usize,
) -> Result<ProtectedFragment, Error> {
    let marker_prefix = crate::marker::unique_prefix(fragment_source, "nested");
    let mut shield = Shield {
        source_map,
        marker_prefix: marker_prefix.clone(),
        nested: Vec::new(),
        had_skip: false,
        format_supported: true,
        error: None,
    };
    let mut shielded = items.to_vec();
    for item in &mut shielded {
        shield.visit_item_mut(item);
    }
    if let Some(error) = shield.error {
        return Err(error);
    }
    if shield.nested.is_empty() {
        if shield.had_skip {
            return Ok(ProtectedFragment::preserved(fragment_source));
        }
        return formatter
            .items(fragment_source, indentation)
            .map_err(Error::from);
    }
    // Opaque markers do not recurse and remain safe at the depth boundary.
    if depth >= RECURSION_LIMIT && has_supported(&shield.nested) {
        return Err(Error::RecursionLimit);
    }

    let shielded_source = shield_source(fragment_source, fragment_start, &shield.nested)?;
    finish_collection(
        CollectionRestore {
            formatter,
            fragment_source,
            shielded_source: &shielded_source,
            marker_prefix: &marker_prefix,
            nested: &shield.nested,
            depth,
            style: RestoreStyle::Items,
            had_skip: shield.had_skip,
        },
        || {
            formatter
                .items(&shielded_source, indentation)
                .map_err(Error::from)
        },
        |restored| syn::parse_file(restored).map(|_| ()),
    )
}

/// Formats a statement collection after shielding nested macros.
///
/// When structurally valid marker placement is unsafe to accept, restoration
/// retries against the original shell and retains supported child formatting when
/// possible. Missing, duplicated, or reordered markers remain an error.
pub(super) fn statements(
    formatter: &crate::rustfmt::Formatter,
    statements: &[Stmt],
    fragment_source: &str,
    fragment_start: usize,
    source_map: &SourceMap<'_>,
    depth: usize,
    indentation: usize,
) -> Result<ProtectedFragment, Error> {
    let marker_prefix = crate::marker::unique_prefix(fragment_source, "nested");
    let mut shield = Shield {
        source_map,
        marker_prefix: marker_prefix.clone(),
        nested: Vec::new(),
        had_skip: false,
        format_supported: true,
        error: None,
    };
    let mut shielded = statements.to_vec();
    for statement in &mut shielded {
        shield.visit_stmt_mut(statement);
    }
    if let Some(error) = shield.error {
        return Err(error);
    }
    if shield.nested.is_empty() {
        if shield.had_skip {
            return Ok(ProtectedFragment::preserved(fragment_source));
        }
        return formatter
            .statements(fragment_source, indentation)
            .map_err(Error::from);
    }
    // Opaque markers do not recurse and remain safe at the depth boundary.
    if depth >= RECURSION_LIMIT && has_supported(&shield.nested) {
        return Err(Error::RecursionLimit);
    }

    let shielded_source = shield_source(fragment_source, fragment_start, &shield.nested)?;
    finish_collection(
        CollectionRestore {
            formatter,
            fragment_source,
            shielded_source: &shielded_source,
            marker_prefix: &marker_prefix,
            nested: &shield.nested,
            depth,
            style: RestoreStyle::Statements,
            had_skip: shield.had_skip,
        },
        || {
            formatter
                .statements(&shielded_source, indentation)
                .map_err(Error::from)
        },
        |restored| parse_statements(restored).map(|_| ()),
    )
}

/// Restores a formatted collection, with a source-shell fallback when needed.
fn finish_collection(
    context: CollectionRestore<'_>,
    format: impl FnOnce() -> Result<ProtectedFragment, Error>,
    validate: impl Fn(&str) -> Result<(), syn::Error>,
) -> Result<ProtectedFragment, Error> {
    if !context.had_skip {
        let formatted = format()?;
        if formatted.disposition() != Disposition::PreservedForTrivia
            && let Some(restored) = restore(
                formatted.text(),
                context.marker_prefix,
                context.nested,
                context.depth,
                context.style,
                false,
                context.formatter,
            )?
        {
            validate(&restored).map_err(Error::Output)?;
            return Ok(ProtectedFragment::formatted(restored));
        }
    }

    // Skip attributes, trivia preservation, or unsafe marker placement prevent
    // accepting rustfmt's shell. Restore into the original shielded shell instead.
    let Some(restored) = restore(
        context.shielded_source,
        context.marker_prefix,
        context.nested,
        context.depth,
        context.style,
        true,
        context.formatter,
    )?
    else {
        return Ok(ProtectedFragment::preserved(context.fragment_source));
    };
    validate(&restored).map_err(Error::Output)?;
    Ok(ProtectedFragment::preserved_with_nested_formatting(
        restored,
    ))
}

/// Formats one expression through shielding, rustfmt, and validated restoration.
fn format_expression(
    formatter: &crate::rustfmt::Formatter,
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    options: ExpressionOptions,
) -> Result<ProtectedFragment, Error> {
    let ExpressionOptions {
        indentation,
        depth,
        style,
        format_supported,
    } = options;
    let mut preflight = ShieldPreflight::default();
    preflight.visit_expr(expression);
    // Avoid rebuilding and reparsing expressions that contain no macro nodes.
    if !preflight.has_macro {
        if preflight.had_skip {
            return Ok(ProtectedFragment::preserved(fragment_source));
        }
        return style.format(formatter, fragment_source, indentation);
    }

    let marker_prefix = crate::marker::unique_prefix(source, "nested");
    let mut shield = Shield {
        source_map,
        marker_prefix: marker_prefix.clone(),
        nested: Vec::new(),
        had_skip: false,
        format_supported,
        error: None,
    };
    let mut shielded = expression.clone();
    shield.visit_expr_mut(&mut shielded);
    if let Some(error) = shield.error {
        return Err(error);
    }
    if shield.nested.is_empty() {
        if shield.had_skip {
            return Ok(ProtectedFragment::preserved(fragment_source));
        }
        return style.format(formatter, fragment_source, indentation);
    }
    // Opaque markers do not recurse and remain safe at the depth boundary.
    if depth >= RECURSION_LIMIT && has_supported(&shield.nested) {
        return Err(Error::RecursionLimit);
    }

    let expression_range = source_map.span_range(expression.span())?;
    // The caller-provided fragment must exactly match the expression whose spans
    // were collected, otherwise marker-relative offsets would target other bytes.
    if source_map.slice(expression_range.clone())? != fragment_source {
        return Err(Error::MarkerMismatch);
    }
    let shielded_source = shield_source(fragment_source, expression_range.start, &shield.nested)?;

    if shield.had_skip {
        // A skip attribute freezes the outer expression, but supported macros
        // outside the skipped subtree may still be formatted recursively.
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Expression,
            true,
            formatter,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        syn::parse_str::<Expr>(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    }

    let formatted = style.format(formatter, &shielded_source, indentation)?;
    if formatted.disposition() == Disposition::PreservedForTrivia {
        // When trivia blocks shell formatting, restore against the unchanged
        // shielded source so nested formatting can still be retained.
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Expression,
            true,
            formatter,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        syn::parse_str::<Expr>(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    }
    let Some(restored) = restore(
        formatted.text(),
        &marker_prefix,
        &shield.nested,
        depth,
        RestoreStyle::Expression,
        false,
        formatter,
    )?
    else {
        // Marker placement in rustfmt output was unsafe. Retry against the
        // original shell before abandoning nested formatting entirely.
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Expression,
            true,
            formatter,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        syn::parse_str::<Expr>(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    };
    syn::parse_str::<Expr>(&restored).map_err(Error::Output)?;
    Ok(ProtectedFragment::formatted(restored))
}

/// Replaces recorded macro source ranges with empty, delimiter-matched markers.
fn shield_source(
    fragment_source: &str,
    fragment_start: usize,
    nested: &[NestedMacro],
) -> Result<String, Error> {
    let mut replacements = nested
        .iter()
        .map(|nested| {
            let start = nested
                .source_range
                .start
                .checked_sub(fragment_start)
                .ok_or(Error::MarkerMismatch)?;
            let end = nested
                .source_range
                .end
                .checked_sub(fragment_start)
                .ok_or(Error::MarkerMismatch)?;
            if start > end || end > fragment_source.len() {
                return Err(Error::MarkerMismatch);
            }
            Ok((
                start..end,
                format!(
                    "{}! {}{}",
                    nested.marker, nested.marker_open, nested.marker_close
                ),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    replacements.sort_unstable_by_key(|(range, _)| (range.start, range.end));
    if replacements
        .windows(2)
        .any(|pair| pair[0].0.end > pair[1].0.start)
    {
        return Err(Error::MarkerMismatch);
    }

    let mut output = fragment_source.to_owned();
    // Reverse order keeps every source-relative range stable as text sizes change.
    for (range, replacement) in replacements.into_iter().rev() {
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

/// Restores all markers and recursively formats supported macro bodies.
///
/// Returns `None` when restoration is structurally valid but unsafe for the
/// requested shell. When `allow_preserved` is false, every supported child must
/// produce formatted output before the shell can be accepted as formatted.
fn restore(
    formatted: &str,
    marker_prefix: &str,
    nested: &[NestedMacro],
    depth: usize,
    style: RestoreStyle,
    allow_preserved: bool,
    formatter: &crate::rustfmt::Formatter,
) -> Result<Option<String>, Error> {
    let mut collector = MarkerCollector {
        prefix: marker_prefix,
        markers: Vec::new(),
    };
    // Parse according to the wrapper grammar to locate actual macro nodes. Text
    // search could confuse marker-like content in comments or string literals.
    match style {
        RestoreStyle::Expression => {
            let expression = syn::parse_str::<Expr>(formatted).map_err(Error::Output)?;
            collector.visit_expr(&expression);
        }
        RestoreStyle::Items => {
            let file = syn::parse_file(formatted).map_err(Error::Output)?;
            collector.visit_file(&file);
        }
        RestoreStyle::Statements => {
            for statement in parse_statements(formatted).map_err(Error::Output)? {
                collector.visit_stmt(&statement);
            }
        }
    }
    // Exact count and traversal order bind each generated marker to the original
    // invocation it replaced.
    if collector.markers.len() != nested.len()
        || collector
            .markers
            .iter()
            .zip(nested)
            .any(|(marker, nested)| marker.name != nested.marker)
    {
        return Err(Error::MarkerMismatch);
    }

    let source_map = SourceMap::new(formatted);
    let line_ending = dominant_line_ending(formatted);
    let mut replacements = Vec::with_capacity(nested.len());
    for (marker, nested) in collector.markers.iter().zip(nested) {
        let range = marker_range(&source_map, marker)?;
        let indentation = line_indentation(formatted, range.start, 0);
        let replacement = match nested.kind {
            NestedKind::Supported(kind) => {
                // The restored prefix may end after the marker path, so compute
                // the body column from the real prefix rather than marker width.
                let options = Options {
                    indentation,
                    body_column: restored_body_column(
                        &nested.prefix,
                        marker.path_span.start().column,
                    ),
                    line_ending,
                };
                let body = format_at_depth(formatter, kind, &nested.body, options, depth + 1)?;
                if body.disposition() != Disposition::Formatted && !allow_preserved {
                    return Ok(None);
                }
                format!("{}{}{}", nested.prefix, body.text(), nested.suffix)
            }
            NestedKind::Opaque => {
                let source = format!("{}{}{}", nested.prefix, nested.body, nested.suffix);
                // A multiline opaque macro cannot replace a marker embedded
                // between tokens without changing the surrounding line structure.
                if source.contains('\n') && marker_is_embedded_on_line(formatted, &range) {
                    return Ok(None);
                }
                let Some(source) = reindent_opaque(
                    &source,
                    nested.original_column,
                    marker.path_span.start().column,
                ) else {
                    return Ok(None);
                };
                source
            }
        };
        replacements.push((range, replacement));
    }

    let mut output = formatted.to_owned();
    // Reverse replacement preserves the spans collected from the formatted text.
    for (range, replacement) in replacements.into_iter().rev() {
        output.replace_range(range, &replacement);
    }
    Ok(Some(output))
}

/// Returns whether non-whitespace tokens surround a marker on the same line.
fn marker_is_embedded_on_line(source: &str, range: &Range<usize>) -> bool {
    let line_start = source[..range.start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line_end = source[range.end..]
        .find('\n')
        .map_or(source.len(), |newline| range.end + newline);
    source[line_start..range.start]
        .chars()
        .any(|character| !character.is_whitespace())
        && source[range.end..line_end]
            .chars()
            .any(|character| !character.is_whitespace())
}

/// Returns whether any recorded macro body requires recursive formatting.
fn has_supported(nested: &[NestedMacro]) -> bool {
    nested
        .iter()
        .any(|nested| matches!(nested.kind, NestedKind::Supported(_)))
}

/// Parses a fragment using the grammar of statements inside a block.
fn parse_statements(source: &str) -> Result<Vec<Stmt>, syn::Error> {
    Block::parse_within.parse_str(source)
}

/// Moves an opaque multiline invocation when every continuation line has the expected indent.
///
/// Returns `None` when moving the source could alter literal bytes, block-comment
/// layout, or indentation that is not rooted at `original_column`.
fn reindent_opaque(source: &str, original_column: usize, target_column: usize) -> Option<String> {
    if !source.contains('\n') || original_column == target_column {
        return Some(source.to_owned());
    }
    // Indentation-like bytes inside multiline literals and block comments are
    // content, so they cannot be shifted as structural leading whitespace.
    if fragment::source_has_multiline_literal(source) || source.contains("/*") {
        return None;
    }

    let original_prefix = " ".repeat(original_column);
    let target_prefix = " ".repeat(target_column);
    let mut output = String::with_capacity(source.len());
    let mut lines = source.split_inclusive('\n');
    output.push_str(lines.next()?);
    for line in lines {
        let (content, ending) = split_line_ending(line);
        if content.is_empty() {
            output.push_str(ending);
            continue;
        }
        let content = content.strip_prefix(&original_prefix)?;
        output.push_str(&target_prefix);
        output.push_str(content);
        output.push_str(ending);
    }
    Some(output)
}

/// Splits one inclusive line into content and its exact line ending.
fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(content) = line.strip_suffix("\r\n") {
        return (content, "\r\n");
    }
    if let Some(content) = line.strip_suffix('\n') {
        return (content, "\n");
    }
    (line, "")
}

/// Chooses the line ending used by a majority of lines, defaulting ties to LF.
fn dominant_line_ending(source: &str) -> LineEnding {
    let crlf = source.match_indices("\r\n").count();
    let lf = source.bytes().filter(|byte| *byte == b'\n').count();
    if crlf > lf.saturating_sub(crlf) {
        LineEnding::Crlf
    } else {
        LineEnding::Lf
    }
}

/// Resolves and validates the complete source range of a marker invocation.
fn marker_range(source_map: &SourceMap<'_>, marker: &Marker) -> Result<Range<usize>, Error> {
    let start = source_map.byte_offset(marker.path_span.start())?;
    let open = source_map.span_range(marker.open_span)?;
    let close = source_map.span_range(marker.close_span)?;
    if source_map.slice(open)? != marker.open_text
        || source_map.slice(close.clone())? != marker.close_text
    {
        return Err(Error::MarkerDelimiter);
    }
    Ok(start..close.end)
}

/// Returns the leading-space indentation at `offset`.
///
/// `initial_indentation` is used when the fragment's first line begins outside
/// the provided source string.
fn line_indentation(source: &str, offset: usize, initial_indentation: usize) -> usize {
    let Some(line_start) = source[..offset].rfind('\n').map(|newline| newline + 1) else {
        return initial_indentation;
    };
    source[line_start..offset]
        .chars()
        .take_while(|character| *character == ' ')
        .count()
}

/// Returns the rendered column at `offset`, with tabs advancing to four-column stops.
///
/// `initial_column` supplies the column where a first-line fragment begins.
fn line_column(source: &str, offset: usize, initial_column: usize) -> usize {
    let (prefix, column) = source[..offset]
        .rsplit_once('\n')
        .map_or((&source[..offset], initial_column), |(_, prefix)| {
            (prefix, 0)
        });
    prefix
        .chars()
        .fold(column, |column, character| match character {
            '\t' => (column / 4 + 1) * 4,
            _ => column + 1,
        })
}

/// Computes the nested body column after restoring its original invocation prefix.
fn restored_body_column(prefix: &str, initial_column: usize) -> usize {
    line_column(prefix, prefix.len(), initial_column)
}
