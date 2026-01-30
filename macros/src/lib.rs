//! Augment the development of primitives with procedural macros.

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

/// Generates cfg exclusion identifiers for levels above the given level.
/// Always includes `commonware_stability_RESERVED` to allow finding unmarked items.
fn exclusion_cfg_names(level: u8) -> Vec<proc_macro2::Ident> {
    let mut names: Vec<_> = ((level + 1)..=4)
        .map(|l| format_ident!("commonware_stability_{}", level_name(l)))
        .collect();

    // RESERVED excludes all stability-marked items, leaving only unmarked ones
    names.push(format_ident!("commonware_stability_RESERVED"));
    names
}

/// Marks an item with a stability level.
///
/// When building with `RUSTFLAGS="--cfg commonware_stability_X"`, items with stability
/// less than X are excluded. Unmarked items are always included.
///
/// See [commonware README](https://github.com/commonwarexyz/monorepo#stability) for stability level definitions.
///
/// # Example
/// ```rust,ignore
/// use commonware_macros::stability;
///
/// #[stability(BETA)]  // excluded at GAMMA, DELTA, EPSILON
/// pub struct StableApi { }
/// ```
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

/// Marks a module with a stability level.
///
/// When building with `RUSTFLAGS="--cfg commonware_stability_N"`, modules with stability
/// less than N are excluded.
///
/// # Example
/// ```rust,ignore
/// use commonware_macros::stability_mod;
///
/// stability_mod!(BETA, pub mod stable_module);
/// ```
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

/// Marks all items within a scope with a stability level and optional cfg predicate.
///
/// When building with `RUSTFLAGS="--cfg commonware_stability_N"`, items with stability
/// less than N are excluded.
///
/// # Example
/// ```rust,ignore
/// use commonware_macros::stability_scope;
///
/// // Without cfg predicate
/// stability_scope!(BETA {
///     pub mod stable_module;
///     pub use crate::stable_module::Item;
/// });
///
/// // With cfg predicate
/// stability_scope!(BETA, cfg(feature = "std") {
///     pub mod std_only_module;
/// });
/// ```
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

/// Run a test function asynchronously.
///
/// This macro is powered by the [futures](https://docs.rs/futures) crate
/// and is not bound to a particular executor or context.
///
/// # Example
/// ```rust
/// #[commonware_macros::test_async]
/// async fn test_async_fn() {
///    assert_eq!(2 + 2, 4);
/// }
/// ```
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

/// Capture logs (based on the provided log level) from a test run using
/// [libtest's output capture functionality](https://doc.rust-lang.org/book/ch11-02-running-tests.html#showing-function-output).
///
/// This macro defaults to a log level of `DEBUG` if no level is provided.
///
/// This macro is powered by the [tracing](https://docs.rs/tracing) and
/// [tracing-subscriber](https://docs.rs/tracing-subscriber) crates.
///
/// # Example
/// ```rust
/// use tracing::{debug, info};
///
/// #[commonware_macros::test_traced("INFO")]
/// fn test_info_level() {
///     info!("This is an info log");
///     debug!("This is a debug log (won't be shown)");
///     assert_eq!(2 + 2, 4);
/// }
/// ```
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

/// Prefix a test name with a nextest filter group.
///
/// This renames `test_some_behavior` into `test_some_behavior_<group>_`, making
/// it easy to filter tests by group postfixes in nextest.
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

/// Capture logs from a test run into an in-memory store.
///
/// This macro defaults to a log level of `DEBUG` on the [mod@tracing_subscriber::fmt] layer if no level is provided.
///
/// This macro is powered by the [tracing](https://docs.rs/tracing),
/// [tracing-subscriber](https://docs.rs/tracing-subscriber), and
/// [commonware-runtime](https://docs.rs/commonware-runtime) crates.
///
/// # Note
///
/// This macro requires the resolution of the `commonware-runtime`, `tracing`, and `tracing_subscriber` crates.
///
/// # Example
/// ```rust,ignore
/// use commonware_runtime::telemetry::traces::collector::TraceStorage;
/// use tracing::{debug, info};
///
/// #[commonware_macros::test_collect_traces("INFO")]
/// fn test_info_level(traces: TraceStorage) {
///     // Filter applies to console output (FmtLayer)
///     info!("This is an info log");
///     debug!("This is a debug log (won't be shown in console output)");
///
///     // All traces are collected, regardless of level, by the CollectingLayer.
///     assert_eq!(traces.get_all().len(), 2);
/// }
/// ```
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

/// Select the first future that completes (biased by order).
///
/// This macro is powered by the [futures](https://docs.rs/futures) crate
/// and is not bound to a particular executor or context.
///
/// # Fusing
///
/// This macro handles the [fusing](https://docs.rs/futures/latest/futures/future/trait.FutureExt.html#method.fuse)
/// futures in a `select`-specific scope.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use futures::executor::block_on;
/// use futures_timer::Delay;
///
/// async fn task() -> usize {
///     42
/// }
///
/// block_on(async move {
///     commonware_macros::select! {
///         _ = Delay::new(Duration::from_secs(1)) => {
///             println!("timeout fired");
///         },
///         v = task() => {
///             println!("task completed with value: {}", v);
///         },
///     };
/// });
/// ```
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
        // Generate branch for `select_biased!` macro
        let branch_code = quote! {
            #pattern = (#future).fuse() => #body,
        };
        select_branches.push(branch_code);
    }

    // Generate the final output code
    quote! {
        {
            use futures::FutureExt as _;

            futures::select_biased! {
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
    branches: Vec<Branch>,
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

/// Convenience macro to continuously [select!] over a set of futures in biased order,
/// with a required shutdown handler.
///
/// This macro automatically creates a shutdown future from the provided context and requires a
/// shutdown handler block. The shutdown future is created outside the loop, allowing it to
/// persist across iterations until shutdown is signaled. The shutdown branch is always checked
/// first (biased).
///
/// After the shutdown block is executed, the loop breaks by default. If different control flow
/// is desired (such as returning from the enclosing function), it must be handled explicitly.
///
/// # Syntax
///
/// ```rust,ignore
/// commonware_macros::select_loop! {
///     context,
///     on_start => { /* optional: runs at start of each iteration */ },
///     on_stopped => { cleanup },
///     pattern = future => block,
///     // ...
///     on_end => { /* optional: runs after non-shutdown arm completes */ },
/// }
/// ```
///
/// The order of blocks matches execution order:
/// 1. `on_start` (optional) - Runs at the start of each loop iteration, before the select.
///    Can use `continue` to skip the select or `break` to exit the loop.
/// 2. `on_stopped` (required) - The shutdown handler, executed when shutdown is signaled.
/// 3. Select arms - The futures to select over.
/// 4. `on_end` (optional) - Runs after a non-shutdown arm completes. Skipped when shutdown
///    is triggered. Useful for post-processing that should happen after each arm.
///
/// All blocks share the same lexical scope within the loop body. Variables declared in
/// `on_start` are visible in the select arms, `on_stopped`, and `on_end`. This allows
/// preparing state in `on_start` and using it throughout the iteration.
///
/// The `shutdown` variable (the future from `context.stopped()`) is accessible in the
/// shutdown block, allowing explicit cleanup such as `drop(shutdown)` before breaking or returning.
///
/// # Example
///
/// ```rust,ignore
/// async fn run(context: impl commonware_runtime::Spawner) {
///     let mut counter = 0;
///     commonware_macros::select_loop! {
///         context,
///         on_start => {
///             // Prepare state for this iteration (visible in arms and on_end)
///             let start_time = std::time::Instant::now();
///             counter += 1;
///         },
///         on_stopped => {
///             println!("shutting down after {} iterations", counter);
///             drop(shutdown);
///         },
///         msg = receiver.recv() => {
///             println!("received: {:?}", msg);
///         },
///         on_end => {
///             // Access variables from on_start
///             println!("iteration took {:?}", start_time.elapsed());
///         },
///     }
/// }
/// ```
#[proc_macro]
pub fn select_loop(input: TokenStream) -> TokenStream {
    let SelectLoopInput {
        context,
        start_expr,
        shutdown_expr,
        branches,
        end_expr,
    } = parse_macro_input!(input as SelectLoopInput);

    // Convert branches to tokens for the inner select!
    let branch_tokens: Vec<_> = branches
        .iter()
        .map(|b| {
            let pattern = &b.pattern;
            let future = &b.future;
            let body = &b.body;
            quote! { #pattern = #future => #body, }
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
