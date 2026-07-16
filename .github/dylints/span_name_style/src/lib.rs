#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_errors;
extern crate rustc_span;

use rustc_ast::{
    token::{Lit, LitKind, Token, TokenKind},
    tokenstream::{TokenStream, TokenTree},
    AttrArgs, AttrKind, Attribute, DelimArgs, MacCall,
};
use rustc_errors::DiagDecorator;
use rustc_lint::{EarlyContext, EarlyLintPass, LintContext};
use rustc_span::Span;

dylint_linting::declare_pre_expansion_lint! {
    /// ### What it does
    ///
    /// Checks that tracing span names (the string passed to `span!`,
    /// `info_span!`, and friends, or the `name = "..."` of
    /// `#[tracing::instrument]`) follow the repository style guide: lowercase,
    /// dot-separated paths with at least two segments, such as
    /// `component.module.operation`.
    ///
    /// ### Why is this bad?
    ///
    /// Spans are viewed stand-alone in trace search results and span lists, so
    /// names must be fully descriptive on their own. `::` separators and
    /// single-segment names make spans hard to find and attribute.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// #[tracing::instrument(name = "qmdb::any::Db::sync", skip_all)]
    /// async fn sync(&self) {}
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// #[tracing::instrument(name = "qmdb.any.db.sync", skip_all)]
    /// async fn sync(&self) {}
    /// ```
    pub SPAN_NAME_STYLE,
    Deny,
    "span names must be lowercase dot-separated paths with at least two segments"
}

const SPAN_MACROS: &[&str] = &[
    "span",
    "trace_span",
    "debug_span",
    "info_span",
    "warn_span",
    "error_span",
];

impl EarlyLintPass for SpanNameStyle {
    fn check_mac(&mut self, cx: &EarlyContext<'_>, mac: &MacCall) {
        let Some(segment) = mac.path.segments.last() else {
            return;
        };
        let macro_name = segment.ident.as_str().to_owned();
        if !SPAN_MACROS.contains(&macro_name.as_str()) {
            return;
        }

        if let Some((name, span)) = span_macro_name(&mac.args, macro_name == "span") {
            check_name(cx, &name, span);
        }
    }

    fn check_attribute(&mut self, cx: &EarlyContext<'_>, attr: &Attribute) {
        let AttrKind::Normal(normal) = &attr.kind else {
            return;
        };
        let Some(segment) = normal.item.path.segments.last() else {
            return;
        };
        if segment.ident.as_str() != "instrument" {
            return;
        }
        let Some(AttrArgs::Delimited(args)) = normal.item.args.unparsed_ref() else {
            return;
        };

        if let Some((name, span)) = instrument_name(args) {
            check_name(cx, &name, span);
        }
    }
}

/// Extracts the span name literal from a tracing span macro invocation.
///
/// The tracing grammar is `(target: "...",)? (parent: EXPR,)? (LEVEL,)? NAME
/// (, fields)*`. The name is the first top-level comma group that is a single
/// string literal, after skipping `target:`/`parent:` prefixes (and the level
/// argument for the `span!` form).
fn span_macro_name(args: &DelimArgs, has_level: bool) -> Option<(String, Span)> {
    let mut skip_level = has_level;
    for group in top_level_groups(&args.tokens) {
        if let [TokenTree::Token(Token { kind, .. }, _), TokenTree::Token(
            Token {
                kind: TokenKind::Colon,
                ..
            },
            _,
        ), ..] = group.as_slice()
        {
            if let TokenKind::Ident(ident, _) = kind {
                if ident.as_str() == "target" || ident.as_str() == "parent" {
                    continue;
                }
            }
        }

        if skip_level {
            skip_level = false;
            continue;
        }

        return string_literal(&group);
    }
    None
}

/// Extracts the `name = "..."` value from `#[instrument(...)]` arguments.
fn instrument_name(args: &DelimArgs) -> Option<(String, Span)> {
    for group in top_level_groups(&args.tokens) {
        if let [TokenTree::Token(
            Token {
                kind: TokenKind::Ident(ident, _),
                ..
            },
            _,
        ), TokenTree::Token(
            Token {
                kind: TokenKind::Eq,
                ..
            },
            _,
        ), rest @ ..] = group.as_slice()
        {
            if ident.as_str() == "name" {
                return string_literal(rest);
            }
        }
    }
    None
}

/// Splits a token stream into top-level comma-separated groups.
fn top_level_groups(tokens: &TokenStream) -> Vec<Vec<TokenTree>> {
    let mut groups = vec![Vec::new()];
    for tree in tokens.iter() {
        if let TokenTree::Token(
            Token {
                kind: TokenKind::Comma,
                ..
            },
            _,
        ) = tree
        {
            groups.push(Vec::new());
        } else {
            groups.last_mut().unwrap().push(tree.clone());
        }
    }
    groups
}

/// Returns the contents of a group consisting of a single string literal.
fn string_literal(group: &[TokenTree]) -> Option<(String, Span)> {
    let [TokenTree::Token(
        Token {
            kind:
                TokenKind::Literal(Lit {
                    kind: LitKind::Str,
                    symbol,
                    ..
                }),
            span,
        },
        _,
    )] = group
    else {
        return None;
    };
    Some((symbol.as_str().to_owned(), *span))
}

fn check_name(cx: &EarlyContext<'_>, name: &str, span: Span) {
    let reason = if name.contains("::") {
        "span names must use `.` separators, not `::`"
    } else if !name.contains('.') {
        "span names must be fully descriptive, with at least two dot-separated segments"
    } else if !name.split('.').all(|s| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }) {
        "span name segments must be non-empty and contain only `[a-z0-9_]`"
    } else {
        return;
    };

    cx.emit_span_lint(
        SPAN_NAME_STYLE,
        span,
        DiagDecorator(|diag| {
            diag.primary_message(reason);
            diag.help("use a lowercase dot-separated path such as `component.module.operation`");
        }),
    );
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
