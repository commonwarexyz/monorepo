//! Marker-based preservation of supported nested macros.

use super::{Error, LineEnding, MacroKind, Options, delimiter_text, format_at_depth, macro_kind};
use crate::{
    pretty::{self, Disposition, ProtectedFragment},
    skip,
    source::SourceMap,
};
use proc_macro2::{Ident, Span};
use std::ops::Range;
use syn::{
    Block, Expr, ForeignItem, ImplItem, Item, Macro, Stmt, TraitItem,
    parse::Parser,
    spanned::Spanned,
    visit::{self, Visit},
    visit_mut::{self, VisitMut},
};

const RECURSION_LIMIT: usize = 32;

#[derive(Clone, Copy)]
enum Style {
    Expression,
    ExpressionPreservingBlankLines,
    BlockExpression,
    BlockExpressionPreservingBlankLines,
}

#[derive(Clone, Copy)]
enum RestoreStyle {
    Expression,
    Items,
    Statements,
}

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

#[derive(Clone, Copy)]
enum NestedKind {
    Supported(MacroKind),
    Opaque,
}

struct Shield<'a> {
    source_map: &'a SourceMap<'a>,
    marker_prefix: String,
    nested: Vec<NestedMacro>,
    had_skip: bool,
    error: Option<Error>,
}

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
    fn shield(&mut self, node: &mut Macro, kind: NestedKind) -> Result<(), Error> {
        let delimiter = node.delimiter.span();
        let open = self.source_map.span_range(delimiter.open())?;
        let close = self.source_map.span_range(delimiter.close())?;
        let (expected_open, expected_close) =
            delimiter_text(&node.delimiter).ok_or(Error::MarkerDelimiter)?;
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
        let kind = macro_kind(&node.path, &node.delimiter)
            .map_or(NestedKind::Opaque, NestedKind::Supported);
        if let Err(error) = self.shield(node, kind) {
            self.error = Some(error);
        }
    }
}

struct Marker {
    name: String,
    path_span: Span,
    open_span: Span,
    close_span: Span,
    open_text: &'static str,
    close_text: &'static str,
}

struct MarkerCollector<'a> {
    prefix: &'a str,
    markers: Vec<Marker>,
}

struct ChildMacro {
    kind: MacroKind,
    path_span: Span,
    open_span: Span,
    close_span: Span,
    open_text: &'static str,
    close_text: &'static str,
}

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

pub(super) fn preserve_with_nested(
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
    preserve_collected(source, 0, source, source_map, collector, options, depth)
}

pub(super) fn preserve_bodies_with_nested(
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
    preserve_collected(source, 0, source, source_map, collector, options, depth)
}

fn preserve_collected(
    fragment_source: &str,
    fragment_start: usize,
    context_source: &str,
    source_map: &SourceMap<'_>,
    collector: ChildCollector,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    if collector.macros.is_empty() {
        return Ok(ProtectedFragment::preserved(fragment_source));
    }
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
        let child_options = Options {
            indentation: line_indentation(context_source, path_start, options.indentation),
            line_ending: options.line_ending,
        };
        let body = format_at_depth(child.kind, body_source, child_options, depth + 1)?;
        if body.text() != body_source {
            let start = body_range
                .start
                .checked_sub(fragment_start)
                .ok_or(Error::MarkerMismatch)?;
            let end = body_range
                .end
                .checked_sub(fragment_start)
                .ok_or(Error::MarkerMismatch)?;
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
    for (range, replacement) in replacements.into_iter().rev() {
        output.replace_range(range, &replacement);
    }
    Ok(ProtectedFragment::preserved_with_nested_formatting(output))
}

pub(super) fn preserve_expression(
    expression: &Expr,
    fragment_source: &str,
    fragment_start: usize,
    context_source: &str,
    source_map: &SourceMap<'_>,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let mut collector = ChildCollector::default();
    collector.visit_expr(expression);
    preserve_collected(
        fragment_source,
        fragment_start,
        context_source,
        source_map,
        collector,
        options,
        depth,
    )
}

pub(super) fn expression(
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    format_expression(
        expression,
        fragment_source,
        source,
        source_map,
        depth,
        Style::Expression,
    )
}

pub(super) fn expression_preserving_blank_lines(
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    format_expression(
        expression,
        fragment_source,
        source,
        source_map,
        depth,
        Style::ExpressionPreservingBlankLines,
    )
}

pub(super) fn block_expression(
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    format_expression(
        expression,
        fragment_source,
        source,
        source_map,
        depth,
        Style::BlockExpression,
    )
}

pub(super) fn block_expression_preserving_blank_lines(
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    format_expression(
        expression,
        fragment_source,
        source,
        source_map,
        depth,
        Style::BlockExpressionPreservingBlankLines,
    )
}

pub(super) fn items(
    items: &[Item],
    fragment_source: &str,
    fragment_start: usize,
    source_map: &SourceMap<'_>,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let marker_prefix = crate::marker::unique_prefix(fragment_source, "nested");
    let mut shield = Shield {
        source_map,
        marker_prefix: marker_prefix.clone(),
        nested: Vec::new(),
        had_skip: false,
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
        return pretty::items(items, fragment_source).map_err(Error::from);
    }
    if depth >= RECURSION_LIMIT && has_supported(&shield.nested) {
        return Err(Error::RecursionLimit);
    }

    let shielded_source = shield_source(fragment_source, fragment_start, &shield.nested)?;
    if shield.had_skip {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Items,
            true,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        syn::parse_file(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    }
    let formatted = pretty::items(&shielded, &shielded_source)?;
    if formatted.disposition() == Disposition::PreservedForTrivia {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Items,
            true,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        syn::parse_file(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    }
    let Some(restored) = restore(
        formatted.text(),
        &marker_prefix,
        &shield.nested,
        depth,
        RestoreStyle::Items,
        false,
    )?
    else {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Items,
            true,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        syn::parse_file(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    };
    syn::parse_file(&restored).map_err(Error::Output)?;
    Ok(ProtectedFragment::formatted(restored))
}

pub(super) fn statements(
    statements: &[Stmt],
    fragment_source: &str,
    fragment_start: usize,
    source_map: &SourceMap<'_>,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let marker_prefix = crate::marker::unique_prefix(fragment_source, "nested");
    let mut shield = Shield {
        source_map,
        marker_prefix: marker_prefix.clone(),
        nested: Vec::new(),
        had_skip: false,
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
        return pretty::statements(statements, fragment_source).map_err(Error::from);
    }
    if depth >= RECURSION_LIMIT && has_supported(&shield.nested) {
        return Err(Error::RecursionLimit);
    }

    let shielded_source = shield_source(fragment_source, fragment_start, &shield.nested)?;
    if shield.had_skip {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Statements,
            true,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        parse_statements(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    }
    let formatted = pretty::statements(&shielded, &shielded_source)?;
    if formatted.disposition() == Disposition::PreservedForTrivia {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Statements,
            true,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        parse_statements(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    }
    let Some(restored) = restore(
        formatted.text(),
        &marker_prefix,
        &shield.nested,
        depth,
        RestoreStyle::Statements,
        false,
    )?
    else {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Statements,
            true,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        parse_statements(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    };
    parse_statements(&restored).map_err(Error::Output)?;
    Ok(ProtectedFragment::formatted(restored))
}

fn format_expression(
    expression: &Expr,
    fragment_source: &str,
    source: &str,
    source_map: &SourceMap<'_>,
    depth: usize,
    style: Style,
) -> Result<ProtectedFragment, Error> {
    let mut preflight = ShieldPreflight::default();
    preflight.visit_expr(expression);
    if !preflight.has_macro {
        if preflight.had_skip {
            return Ok(ProtectedFragment::preserved(fragment_source));
        }
        return match style {
            Style::Expression => pretty::expression(expression, fragment_source),
            Style::ExpressionPreservingBlankLines => {
                pretty::expression_preserving_blank_lines(expression, fragment_source)
            }
            Style::BlockExpression => pretty::block_expression(expression, fragment_source),
            Style::BlockExpressionPreservingBlankLines => {
                pretty::block_expression_preserving_blank_lines(expression, fragment_source)
            }
        }
        .map_err(Error::from);
    }

    let marker_prefix = crate::marker::unique_prefix(source, "nested");
    let mut shield = Shield {
        source_map,
        marker_prefix: marker_prefix.clone(),
        nested: Vec::new(),
        had_skip: false,
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
        return match style {
            Style::Expression => pretty::expression(expression, fragment_source),
            Style::ExpressionPreservingBlankLines => {
                pretty::expression_preserving_blank_lines(expression, fragment_source)
            }
            Style::BlockExpression => pretty::block_expression(expression, fragment_source),
            Style::BlockExpressionPreservingBlankLines => {
                pretty::block_expression_preserving_blank_lines(expression, fragment_source)
            }
        }
        .map_err(Error::from);
    }
    if depth >= RECURSION_LIMIT && has_supported(&shield.nested) {
        return Err(Error::RecursionLimit);
    }

    let expression_range = source_map.span_range(expression.span())?;
    if source_map.slice(expression_range.clone())? != fragment_source {
        return Err(Error::MarkerMismatch);
    }
    let shielded_source = shield_source(fragment_source, expression_range.start, &shield.nested)?;

    if shield.had_skip {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Expression,
            true,
        )?
        else {
            return Ok(ProtectedFragment::preserved(fragment_source));
        };
        syn::parse_str::<Expr>(&restored).map_err(Error::Output)?;
        return Ok(ProtectedFragment::preserved_with_nested_formatting(
            restored,
        ));
    }

    let formatted = match style {
        Style::Expression => pretty::expression(&shielded, &shielded_source)?,
        Style::ExpressionPreservingBlankLines => {
            pretty::expression_preserving_blank_lines(&shielded, &shielded_source)?
        }
        Style::BlockExpression => pretty::block_expression(&shielded, &shielded_source)?,
        Style::BlockExpressionPreservingBlankLines => {
            pretty::block_expression_preserving_blank_lines(&shielded, &shielded_source)?
        }
    };
    if formatted.disposition() == Disposition::PreservedForTrivia {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Expression,
            true,
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
    )?
    else {
        let Some(restored) = restore(
            &shielded_source,
            &marker_prefix,
            &shield.nested,
            depth,
            RestoreStyle::Expression,
            true,
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
    for (range, replacement) in replacements.into_iter().rev() {
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

fn restore(
    formatted: &str,
    marker_prefix: &str,
    nested: &[NestedMacro],
    depth: usize,
    style: RestoreStyle,
    allow_preserved: bool,
) -> Result<Option<String>, Error> {
    let mut collector = MarkerCollector {
        prefix: marker_prefix,
        markers: Vec::new(),
    };
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
                let options = Options {
                    indentation,
                    line_ending,
                };
                let body = format_at_depth(kind, &nested.body, options, depth + 1)?;
                if body.disposition() != Disposition::Formatted && !allow_preserved {
                    return Ok(None);
                }
                format!("{}{}{}", nested.prefix, body.text(), nested.suffix)
            }
            NestedKind::Opaque => {
                let source = format!("{}{}{}", nested.prefix, nested.body, nested.suffix);
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
    for (range, replacement) in replacements.into_iter().rev() {
        output.replace_range(range, &replacement);
    }
    Ok(Some(output))
}

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

fn has_supported(nested: &[NestedMacro]) -> bool {
    nested
        .iter()
        .any(|nested| matches!(nested.kind, NestedKind::Supported(_)))
}

fn parse_statements(source: &str) -> Result<Vec<Stmt>, syn::Error> {
    Block::parse_within.parse_str(source)
}

fn reindent_opaque(source: &str, original_column: usize, target_column: usize) -> Option<String> {
    if !source.contains('\n') || original_column == target_column {
        return Some(source.to_owned());
    }
    if pretty::source_has_multiline_literal(source) || source.contains("/*") {
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

fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(content) = line.strip_suffix("\r\n") {
        return (content, "\r\n");
    }
    if let Some(content) = line.strip_suffix('\n') {
        return (content, "\n");
    }
    (line, "")
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

fn line_indentation(source: &str, offset: usize, initial_indentation: usize) -> usize {
    let Some(line_start) = source[..offset].rfind('\n').map(|newline| newline + 1) else {
        return initial_indentation;
    };
    source[line_start..offset]
        .chars()
        .take_while(|character| *character == ' ')
        .count()
}
