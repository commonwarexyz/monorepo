//! Augment the development of primitives with procedural macros.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream, Result},
    parse_macro_input,
    spanned::Spanned,
    Block, Error, Expr, Ident, ItemFn, LitStr, Pat, Token,
};

/// Capture logs (based on the provided log level) from a test run using
/// [libtest's output capture functionality](https://doc.rust-lang.org/book/ch11-02-running-tests.html#showing-function-output).
/// This macro defaults to a log level of `DEBUG` if no level is provided.
///
/// This macro is powered by the `tracing` and `tracing-subscriber` crates.
///
/// # Example
/// ```rust
/// use commonware_macros::test_with_logging;
/// use tracing::{debug, info};
///
/// #[test_with_logging("INFO")]
/// fn test_info_level() {
///     info!("This is an info log");
///     debug!("This is a debug log (won't be shown)");
///     assert_eq!(2 + 2, 4);
/// }
/// ```
#[proc_macro_attribute]
pub fn test_with_logging(attr: TokenStream, item: TokenStream) -> TokenStream {
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
                .finish();
            let dispatcher = tracing::Dispatch::new(subscriber);

            // Set the subcriber for the scope of the test
            tracing::dispatcher::with_default(&dispatcher, || {
                #block
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
    fn parse(input: ParseStream) -> Result<Self> {
        let mut branches = Vec::new();

        while !input.is_empty() {
            let pattern: Pat = input.parse()?;
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

        Ok(SelectInput { branches })
    }
}

/// Select the first future that completes (biased by order).
///
/// This macro is powered by the `futures::select_biased!` macro
/// and as such is not bound to a particular executor or runtime.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use commonware_macros::select;
/// use commonware_runtime::{Clock, Spawner, Runner, deterministic::{Executor, Config}};
///
/// async fn task() -> usize {
///     42
/// }
//
/// let (executor, runtime, auditor) = Executor::default();
/// executor.start(async move {
///     select! {
///         _ = runtime.sleep(Duration::from_secs(1)) => {
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
    let mut stmts = Vec::new();
    let mut select_branches = Vec::new();
    for (
        index,
        Branch {
            pattern,
            future,
            block,
        },
    ) in branches.into_iter().enumerate()
    {
        // Generate a unique identifier for each future
        let future_ident = Ident::new(&format!("__select_future_{}", index), pattern.span());

        // Fuse and pin each future
        let stmt = quote! {
            let #future_ident = (#future).fuse();
            futures::pin_mut!(#future_ident);
        };
        stmts.push(stmt);

        // Generate branch for `select_biased!` macro
        let branch_code = quote! {
            #pattern = #future_ident => #block,
        };
        select_branches.push(branch_code);
    }

    // Generate the final output code
    quote! {
        {
            use futures::{FutureExt, select_biased};

            #(#stmts)*

            select_biased! {
                #(#select_branches)*
            }
        }
    }
    .into()
}
