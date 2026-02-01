//! Proc-macro implementation for `commonware-macros`.
//!
//! This is an internal crate. Use [`commonware-macros`](https://docs.rs/commonware-macros)
//! instead.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use crate::nextest::configured_test_groups;
use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote};
use syn::{
    braced,
    parse::{Parse, ParseStream, Result},
    parse_macro_input, Error, Expr, Ident, ItemFn, LitInt, LitStr, Pat, Token, Visibility,
};

mod nextest;

/// Stability level input that accepts either a literal integer (0-4) or a named constant
/// (ALPHA, BETA, GAMMA, DELTA, EPSILON).
struct StabilityLevel {
    value: u8,
}

impl Parse for StabilityLevel {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(LitInt) {
            let lit: LitInt = input.parse()?;
            let value: u8 = lit
                .base10_parse()
                .map_err(|_| Error::new(lit.span(), "stability level must be 0, 1, 2, 3, or 4"))?;
            if value > 4 {
                return Err(Error::new(
                    lit.span(),
                    "stability level must be 0, 1, 2, 3, or 4",
                ));
            }
            Ok(Self { value })
        } else if lookahead.peek(Ident) {
            let ident: Ident = input.parse()?;
            let value = match ident.to_string().as_str() {
                "ALPHA" => 0,
                "BETA" => 1,
                "GAMMA" => 2,
                "DELTA" => 3,
                "EPSILON" => 4,
                _ => {
                    return Err(Error::new(
                        ident.span(),
                        "expected stability level: ALPHA, BETA, GAMMA, DELTA, EPSILON, or 0-4",
                    ));
                }
            };
            Ok(Self { value })
        } else {
            Err(lookahead.error())
        }
    }
}

fn level_name(level: u8) -> &'static str {
    match level {
        0 => "ALPHA",
        1 => "BETA",
        2 => "GAMMA",
        3 => "DELTA",
        4 => "EPSILON",
        _ => unreachable!(),
    }
}

/// Generates cfg identifiers that should exclude an item at the given stability level.
///
/// The stability system works by excluding items when building at higher stability levels.
/// For example, an item marked `#[stability(BETA)]` (level 1) should be excluded when
/// building with `--cfg commonware_stability_GAMMA` (level 2) or higher.
///
/// This function returns identifiers for all levels above the given level, plus `RESERVED`.
/// The generated `#[cfg(not(any(...)))]` attribute ensures the item is included only when
/// none of the higher-level cfgs are set.
///
/// ```text
/// Level 0 (ALPHA)   -> excludes at: BETA, GAMMA, DELTA, EPSILON, RESERVED
/// Level 1 (BETA)    -> excludes at: GAMMA, DELTA, EPSILON, RESERVED
/// Level 2 (GAMMA)   -> excludes at: DELTA, EPSILON, RESERVED
/// Level 3 (DELTA)   -> excludes at: EPSILON, RESERVED
/// Level 4 (EPSILON) -> excludes at: RESERVED
/// ```
///
/// `RESERVED` is a special level used by `scripts/find_unstable_public.sh` to exclude ALL
/// stability-marked items, leaving only unmarked public items visible in rustdoc output.
fn exclusion_cfg_names(level: u8) -> Vec<proc_macro2::Ident> {
    let mut names: Vec<_> = ((level + 1)..=4)
        .map(|l| format_ident!("commonware_stability_{}", level_name(l)))
        .collect();

    names.push(format_ident!("commonware_stability_RESERVED"));
    names
}

#[proc_macro_attribute]
pub fn stability(attr: TokenStream, item: TokenStream) -> TokenStream {
    let level = parse_macro_input!(attr as StabilityLevel);
    let exclude_names = exclusion_cfg_names(level.value);

    let item2: proc_macro2::TokenStream = item.into();
    let expanded = quote! {
        #[cfg(not(any(#(#exclude_names),*)))]
        #item2
    };

    TokenStream::from(expanded)
}

/// Input for the `stability_mod!` macro: `level, visibility mod name`
struct StabilityModInput {
    level: StabilityLevel,
    visibility: Visibility,
    name: Ident,
}

impl Parse for StabilityModInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let level: StabilityLevel = input.parse()?;
        input.parse::<Token![,]>()?;
        let visibility: Visibility = input.parse()?;
        input.parse::<Token![mod]>()?;
        let name: Ident = input.parse()?;
        Ok(Self {
            level,
            visibility,
            name,
        })
    }
}

#[proc_macro]
pub fn stability_mod(input: TokenStream) -> TokenStream {
    let StabilityModInput {
        level,
        visibility,
        name,
    } = parse_macro_input!(input as StabilityModInput);

    let exclude_names = exclusion_cfg_names(level.value);

    let expanded = quote! {
        #[cfg(not(any(#(#exclude_names),*)))]
        #visibility mod #name;
    };

    TokenStream::from(expanded)
}

/// Input for the `stability_scope!` macro: `level [, cfg(predicate)] { items... }`
struct StabilityScopeInput {
    level: StabilityLevel,
    predicate: Option<syn::Meta>,
    items: Vec<syn::Item>,
}

impl Parse for StabilityScopeInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let level: StabilityLevel = input.parse()?;

        // Check for optional cfg predicate
        let predicate = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;

            // Parse `cfg(...)` - expect the literal identifier "cfg" followed by parenthesized content
            let cfg_ident: Ident = input.parse()?;
            if cfg_ident != "cfg" {
                return Err(Error::new(cfg_ident.span(), "expected `cfg`"));
            }
            let cfg_content;
            syn::parenthesized!(cfg_content in input);
            Some(cfg_content.parse()?)
        } else {
            None
        };

        let content;
        braced!(content in input);

        let mut items = Vec::new();
        while !content.is_empty() {
            items.push(content.parse()?);
        }

        Ok(Self {
            level,
            predicate,
            items,
        })
    }
}

#[proc_macro]
pub fn stability_scope(input: TokenStream) -> TokenStream {
    let StabilityScopeInput {
        level,
        predicate,
        items,
    } = parse_macro_input!(input as StabilityScopeInput);

    let exclude_names = exclusion_cfg_names(level.value);

    let cfg_attr = predicate.map_or_else(
        || quote! { #[cfg(not(any(#(#exclude_names),*)))] },
        |pred| quote! { #[cfg(all(#pred, not(any(#(#exclude_names),*))))] },
    );

    let expanded_items: Vec<_> = items
        .into_iter()
        .map(|item| {
            quote! {
                #cfg_attr
                #item
            }
        })
        .collect();

    let expanded = quote! {
        #(#expanded_items)*
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn test_async(_: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(item as ItemFn);

    // Extract function components
    let attrs = input.attrs;
    let vis = input.vis;
    let mut sig = input.sig;
    let block = input.block;

    // Remove 'async' from the function signature (#[test] only
    // accepts sync functions)
    sig.asyncness
        .take()
        .expect("test_async macro can only be used with async functions");

    // Generate output tokens
    let expanded = quote! {
        #[test]
        #(#attrs)*
        #vis #sig {
            futures::executor::block_on(async #block);
        }
    };
    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn test_traced(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(item as ItemFn);

    // Parse the attribute argument for log level
    let log_level = if attr.is_empty() {
        // Default log level is DEBUG
        quote! { tracing::Level::DEBUG }
    } else {
        // Parse the attribute as a string literal
        let level_str = parse_macro_input!(attr as LitStr);
        let level_ident = level_str.value().to_uppercase();
        match level_ident.as_str() {
            "TRACE" => quote! { tracing::Level::TRACE },
            "DEBUG" => quote! { tracing::Level::DEBUG },
            "INFO" => quote! { tracing::Level::INFO },
            "WARN" => quote! { tracing::Level::WARN },
            "ERROR" => quote! { tracing::Level::ERROR },
            _ => {
                // Return a compile error for invalid log levels
                return Error::new_spanned(
                    level_str,
                    "Invalid log level. Expected one of: TRACE, DEBUG, INFO, WARN, ERROR.",
                )
                .to_compile_error()
                .into();
            }
        }
    };

    // Extract function components
    let attrs = input.attrs;
    let vis = input.vis;
    let sig = input.sig;
    let block = input.block;

    // Generate output tokens
    let expanded = quote! {
        #[test]
        #(#attrs)*
        #vis #sig {
            // Create a subscriber and dispatcher with the specified log level
            let subscriber = tracing_subscriber::fmt()
                .with_test_writer()
                .with_max_level(#log_level)
                .with_line_number(true)
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                .finish();
            let dispatcher = tracing::Dispatch::new(subscriber);

            // Set the subscriber for the scope of the test
            tracing::dispatcher::with_default(&dispatcher, || {
                #block
            });
        }
    };
    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn test_group(attr: TokenStream, item: TokenStream) -> TokenStream {
    if attr.is_empty() {
        return Error::new(
            Span::call_site(),
            "test_group requires a string literal filter group name",
        )
        .to_compile_error()
        .into();
    }

    let mut input = parse_macro_input!(item as ItemFn);
    let group_literal = parse_macro_input!(attr as LitStr);

    let group = match nextest::sanitize_group_literal(&group_literal) {
        Ok(group) => group,
        Err(err) => return err.to_compile_error().into(),
    };
    let groups = match configured_test_groups() {
        Ok(groups) => groups,
        Err(_) => {
            // Don't fail the compilation if the file isn't found; just return the original input.
            return TokenStream::from(quote!(#input));
        }
    };

    if let Err(err) = nextest::ensure_group_known(groups, &group, group_literal.span()) {
        return err.to_compile_error().into();
    }

    let original_name = input.sig.ident.to_string();
    let new_ident = Ident::new(&format!("{original_name}_{group}_"), input.sig.ident.span());

    input.sig.ident = new_ident;

    TokenStream::from(quote!(#input))
}

#[proc_macro_attribute]
pub fn test_collect_traces(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    // Parse the attribute argument for log level
    let log_level = if attr.is_empty() {
        // Default log level is DEBUG
        quote! { ::tracing_subscriber::filter::LevelFilter::DEBUG }
    } else {
        // Parse the attribute as a string literal
        let level_str = parse_macro_input!(attr as LitStr);
        let level_ident = level_str.value().to_uppercase();
        match level_ident.as_str() {
            "TRACE" => quote! { ::tracing_subscriber::filter::LevelFilter::TRACE },
            "DEBUG" => quote! { ::tracing_subscriber::filter::LevelFilter::DEBUG },
            "INFO" => quote! { ::tracing_subscriber::filter::LevelFilter::INFO },
            "WARN" => quote! { ::tracing_subscriber::filter::LevelFilter::WARN },
            "ERROR" => quote! { ::tracing_subscriber::filter::LevelFilter::ERROR },
            _ => {
                // Return a compile error for invalid log levels
                return Error::new_spanned(
                    level_str,
                    "Invalid log level. Expected one of: TRACE, DEBUG, INFO, WARN, ERROR.",
                )
                .to_compile_error()
                .into();
            }
        }
    };

    let attrs = input.attrs;
    let vis = input.vis;
    let sig = input.sig;
    let block = input.block;

    // Create the signature of the inner function that takes the TraceStorage.
    let inner_ident = format_ident!("__{}_inner_traced", sig.ident);
    let mut inner_sig = sig.clone();
    inner_sig.ident = inner_ident.clone();

    // Create the signature of the outer test function.
    let mut outer_sig = sig;
    outer_sig.inputs.clear();

    // Detect the path of the `commonware-runtime` crate. If it has been renamed or
    // this macro is being used within the `commonware-runtime` crate itself, adjust
    // the path accordingly.
    let rt_path = match crate_name("commonware-runtime") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let ident = syn::Ident::new(&name, Span::call_site());
            quote!(#ident)
        }
        Err(_) => quote!(::commonware_runtime), // fallback
    };

    let expanded = quote! {
        // Inner test function runs the actual test logic, accepting the TraceStorage
        // created by the harness.
        #(#attrs)*
        #vis #inner_sig #block

        #[test]
        #vis #outer_sig {
            use ::tracing_subscriber::{Layer, fmt, Registry, layer::SubscriberExt, util::SubscriberInitExt};
            use ::tracing::{Dispatch, dispatcher};
            use #rt_path::telemetry::traces::collector::{CollectingLayer, TraceStorage};

            let trace_store = TraceStorage::default();
            let collecting_layer = CollectingLayer::new(trace_store.clone());

            let fmt_layer = fmt::layer()
                .with_test_writer()
                .with_line_number(true)
                .with_span_events(fmt::format::FmtSpan::CLOSE)
                .with_filter(#log_level);

            let subscriber = Registry::default().with(collecting_layer).with(fmt_layer);
            let dispatcher = Dispatch::new(subscriber);
            dispatcher::with_default(&dispatcher, || {
                #inner_ident(trace_store);
            });
        }
    };

    TokenStream::from(expanded)
}

struct SelectInput {
    branches: Vec<Branch>,
}

struct Branch {
    pattern: Pat,
    future: Expr,
    body: Expr,
}

/// Branch for [select_loop!] with optional `else` clause for `Some` patterns.
struct SelectLoopBranch {
    pattern: Pat,
    future: Expr,
    else_body: Option<Expr>,
    body: Expr,
}

impl Parse for SelectInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut branches = Vec::new();

        while !input.is_empty() {
            let pattern = Pat::parse_single(input)?;
            input.parse::<Token![=]>()?;
            let future: Expr = input.parse()?;
            input.parse::<Token![=>]>()?;
            let body: Expr = input.parse()?;

            branches.push(Branch {
                pattern,
                future,
                body,
            });

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }

        Ok(Self { branches })
    }
}

#[proc_macro]
pub fn select(input: TokenStream) -> TokenStream {
    // Parse the input tokens
    let SelectInput { branches } = parse_macro_input!(input as SelectInput);

    // Generate code from provided statements
    let mut select_branches = Vec::new();
    for Branch {
        pattern,
        future,
        body,
    } in branches.into_iter()
    {
        // Generate branch for `select!` macro
        let branch_code = quote! {
            #pattern = #future => #body,
        };
        select_branches.push(branch_code);
    }

    // Generate the final output code
    quote! {
        {
            ::commonware_macros::__reexport::tokio::select! {
                biased;
                #(#select_branches)*
            }
        }
    }
    .into()
}

/// Input for [select_loop!].
///
/// Parses: `context, [on_start => expr,] on_stopped => expr, branches... [, on_end => expr]`
struct SelectLoopInput {
    context: Expr,
    start_expr: Option<Expr>,
    shutdown_expr: Expr,
    branches: Vec<SelectLoopBranch>,
    end_expr: Option<Expr>,
}

impl Parse for SelectLoopInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        // Parse context expression
        let context: Expr = input.parse()?;
        input.parse::<Token![,]>()?;

        // Check for optional `on_start =>`
        let start_expr = if input.peek(Ident) {
            let ident: Ident = input.fork().parse()?;
            if ident == "on_start" {
                input.parse::<Ident>()?; // consume the ident
                input.parse::<Token![=>]>()?;
                let expr: Expr = input.parse()?;
                input.parse::<Token![,]>()?;
                Some(expr)
            } else {
                None
            }
        } else {
            None
        };

        // Parse `on_stopped =>`
        let on_stopped_ident: Ident = input.parse()?;
        if on_stopped_ident != "on_stopped" {
            return Err(Error::new(
                on_stopped_ident.span(),
                "expected `on_stopped` keyword",
            ));
        }
        input.parse::<Token![=>]>()?;

        // Parse shutdown expression
        let shutdown_expr: Expr = input.parse()?;

        // Parse comma after shutdown expression
        input.parse::<Token![,]>()?;

        // Parse branches directly (no surrounding braces)
        // Stop when we see `on_end` or reach end of input
        let mut branches = Vec::new();
        while !input.is_empty() {
            // Check if next token is `on_end`
            if input.peek(Ident) {
                let ident: Ident = input.fork().parse()?;
                if ident == "on_end" {
                    break;
                }
            }

            let pattern = Pat::parse_single(input)?;
            input.parse::<Token![=]>()?;
            let future: Expr = input.parse()?;

            // Parse optional else clause: `else expr`
            let else_body = if input.peek(Token![else]) {
                input.parse::<Token![else]>()?;
                Some(input.parse::<Expr>()?)
            } else {
                None
            };

            input.parse::<Token![=>]>()?;
            let body: Expr = input.parse()?;

            branches.push(SelectLoopBranch {
                pattern,
                future,
                else_body,
                body,
            });

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }

        // Check for optional `on_end =>`
        let end_expr = if !input.is_empty() && input.peek(Ident) {
            let ident: Ident = input.parse()?;
            if ident == "on_end" {
                input.parse::<Token![=>]>()?;
                let expr: Expr = input.parse()?;
                if input.peek(Token![,]) {
                    input.parse::<Token![,]>()?;
                }
                Some(expr)
            } else {
                return Err(Error::new(ident.span(), "expected `on_end` keyword"));
            }
        } else {
            None
        };

        Ok(Self {
            context,
            start_expr,
            shutdown_expr,
            branches,
            end_expr,
        })
    }
}

#[proc_macro]
pub fn select_loop(input: TokenStream) -> TokenStream {
    let SelectLoopInput {
        context,
        start_expr,
        shutdown_expr,
        branches,
        end_expr,
    } = parse_macro_input!(input as SelectLoopInput);

    fn is_irrefutable(pat: &Pat) -> bool {
        match pat {
            Pat::Wild(_) | Pat::Rest(_) => true,
            Pat::Ident(i) => i.subpat.as_ref().is_none_or(|(_, p)| is_irrefutable(p)),
            Pat::Type(t) => is_irrefutable(&t.pat),
            Pat::Tuple(t) => t.elems.iter().all(is_irrefutable),
            Pat::Reference(r) => is_irrefutable(&r.pat),
            Pat::Paren(p) => is_irrefutable(&p.pat),
            _ => false,
        }
    }

    for b in &branches {
        if b.else_body.is_none() && !is_irrefutable(&b.pattern) {
            return Error::new_spanned(
                &b.pattern,
                "refutable patterns require an else clause: \
                 `Some(msg) = future else break => { ... }`",
            )
            .to_compile_error()
            .into();
        }
    }

    // Convert branches to tokens for the inner select!
    let branch_tokens: Vec<_> = branches
        .iter()
        .map(|b| {
            let pattern = &b.pattern;
            let future = &b.future;
            let body = &b.body;

            // If else clause is present, use let-else to unwrap
            b.else_body.as_ref().map_or_else(
                // No else: normal pattern binding (already validated as irrefutable)
                || quote! { #pattern = #future => #body, },
                // With else: use let-else for refutable patterns
                |else_expr| {
                    quote! {
                        __select_result = #future => {
                            let #pattern = __select_result else { #else_expr };
                            #body
                        },
                    }
                },
            )
        })
        .collect();

    // Helper to convert an expression to tokens, inlining block contents
    // to preserve variable scope
    fn expr_to_tokens(expr: &Expr) -> proc_macro2::TokenStream {
        match expr {
            Expr::Block(block) => {
                let stmts = &block.block.stmts;
                quote! { #(#stmts)* }
            }
            other => quote! { #other; },
        }
    }

    // Generate on_start and on_end tokens if present
    let on_start_tokens = start_expr.as_ref().map(expr_to_tokens);
    let on_end_tokens = end_expr.as_ref().map(expr_to_tokens);
    let shutdown_tokens = expr_to_tokens(&shutdown_expr);

    quote! {
        {
            let mut shutdown = #context.stopped();
            loop {
                #on_start_tokens

                commonware_macros::select! {
                    _ = &mut shutdown => {
                        #shutdown_tokens

                        // Break the loop after handling shutdown. Some implementations
                        // may divert control flow themselves, so this may be unused.
                        #[allow(unreachable_code)]
                        break;
                    },
                    #(#branch_tokens)*
                }

                #on_end_tokens
            }
        }
    }
    .into()
}
