//! Augment the development of primitives with procedural macros.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use crate::nextest::configured_test_groups;
use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream, Result},
    parse_macro_input, Block, Error, Expr, Ident, ItemFn, LitStr, Pat, Token,
};

mod nextest;

/// Run a test function asynchronously.
///
/// This macro is powered by the [futures](https://docs.rs/futures) crate
/// and is not bound to a particular executor or context.
///
/// # Example
/// ```rust
/// use commonware_macros::test_async;
///
/// #[test_async]
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
/// use commonware_macros::test_traced;
/// use tracing::{debug, info};
///
/// #[test_traced("INFO")]
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
/// use commonware_macros::test_collect_traces;
/// use commonware_runtime::telemetry::traces::collector::TraceStorage;
/// use tracing::{debug, info};
///
/// #[test_collect_traces("INFO")]
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
    block: Block,
}

impl Parse for SelectInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut branches = Vec::new();

        while !input.is_empty() {
            let pattern = Pat::parse_single(input)?;
            input.parse::<Token![=]>()?;
            let future: Expr = input.parse()?;
            input.parse::<Token![=>]>()?;
            let block: Block = input.parse()?;

            branches.push(Branch {
                pattern,
                future,
                block,
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

impl ToTokens for SelectInput {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        for branch in &self.branches {
            let pattern = &branch.pattern;
            let future = &branch.future;
            let block = &branch.block;

            tokens.extend(quote! {
                #pattern = #future => #block,
            });
        }
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
/// use commonware_macros::select;
/// use futures::executor::block_on;
/// use futures_timer::Delay;
///
/// async fn task() -> usize {
///     42
/// }
//
/// block_on(async move {
///     select! {
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
        block,
    } in branches.into_iter()
    {
        // Generate branch for `select_biased!` macro
        let branch_code = quote! {
            #pattern = (#future).fuse() => #block,
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
/// Parses: `context, on_stopped => { block }, { branches... }`
struct SelectLoopInput {
    context: Expr,
    shutdown_block: Block,
    branches: Vec<Branch>,
}

impl Parse for SelectLoopInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        // Parse context expression
        let context: Expr = input.parse()?;
        input.parse::<Token![,]>()?;

        // Parse `on_stopped =>`
        let on_stopped_ident: Ident = input.parse()?;
        if on_stopped_ident != "on_stopped" {
            return Err(Error::new(
                on_stopped_ident.span(),
                "expected `on_stopped` keyword",
            ));
        }
        input.parse::<Token![=>]>()?;

        // Parse shutdown block
        let shutdown_block: Block = input.parse()?;

        // Parse comma after shutdown block
        input.parse::<Token![,]>()?;

        // Parse branches directly (no surrounding braces)
        let mut branches = Vec::new();
        while !input.is_empty() {
            let pattern = Pat::parse_single(input)?;
            input.parse::<Token![=]>()?;
            let future: Expr = input.parse()?;
            input.parse::<Token![=>]>()?;
            let block: Block = input.parse()?;

            branches.push(Branch {
                pattern,
                future,
                block,
            });

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }

        Ok(Self {
            context,
            shutdown_block,
            branches,
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
/// select_loop! {
///     context,
///     on_stopped => { cleanup },
///     pattern = future => block,
///     // ...
/// }
/// ```
///
/// The `shutdown` variable (the future from `context.stopped()`) is accessible in the
/// shutdown block, allowing explicit cleanup such as `drop(shutdown)` before breaking or returning.
///
/// # Example
///
/// ```rust,ignore
/// use commonware_macros::select_loop;
///
/// async fn run(context: impl commonware_runtime::Spawner) {
///     select_loop! {
///         context,
///         on_stopped => {
///             println!("shutting down");
///             drop(shutdown);
///         },
///         msg = receiver.recv() => {
///             println!("received: {:?}", msg);
///         },
///     }
/// }
/// ```
#[proc_macro]
pub fn select_loop(input: TokenStream) -> TokenStream {
    let SelectLoopInput {
        context,
        shutdown_block,
        branches,
    } = parse_macro_input!(input as SelectLoopInput);

    // Convert branches to tokens for the inner select!
    let branch_tokens: Vec<_> = branches
        .iter()
        .map(|b| {
            let pattern = &b.pattern;
            let future = &b.future;
            let block = &b.block;
            quote! { #pattern = #future => #block, }
        })
        .collect();

    quote! {
        {
            let mut shutdown = #context.stopped();
            loop {
                commonware_macros::select! {
                    _ = &mut shutdown => {
                        #shutdown_block

                        // Break the loop after handling shutdown. Some implementations
                        // may divert control flow themselves, so this may be unused.
                        #[allow(unreachable_code)]
                        break;
                    },
                    #(#branch_tokens)*
                }
            }
        }
    }
    .into()
}
