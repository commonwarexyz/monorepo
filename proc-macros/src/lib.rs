//! Augment the development of primitives with procedural macros.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream, Result},
    parse_macro_input,
    spanned::Spanned,
    Block, Error, Expr, Ident, ItemFn, LitStr, Pat, Token,
};

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
            ::commonware_macros::futures::executor::block_on(async #block);
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
        quote! { ::commonware_macros::tracing::Level::DEBUG }
    } else {
        // Parse the attribute as a string literal
        let level_str = parse_macro_input!(attr as LitStr);
        let level_ident = level_str.value().to_uppercase();
        match level_ident.as_str() {
            "TRACE" => quote! { ::commonware_macros::tracing::Level::TRACE },
            "DEBUG" => quote! { ::commonware_macros::tracing::Level::DEBUG },
            "INFO" => quote! { ::commonware_macros::tracing::Level::INFO },
            "WARN" => quote! { ::commonware_macros::tracing::Level::WARN },
            "ERROR" => quote! { ::commonware_macros::tracing::Level::ERROR },
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
            let subscriber = ::commonware_macros::tracing_subscriber::fmt()
                .with_test_writer()
                .with_max_level(#log_level)
                .with_line_number(true)
                .with_span_events(::commonware_macros::tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                .finish();
            let dispatcher = ::commonware_macros::tracing::Dispatch::new(subscriber);

            // Set the subscriber for the scope of the test
            ::commonware_macros::tracing::dispatcher::with_default(&dispatcher, || {
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
        let future_ident = Ident::new(&format!("__select_future_{index}"), pattern.span());

        // Fuse and pin each future
        let stmt = quote! {
            let #future_ident = (#future).fuse();
            ::commonware_macros::futures::pin_mut!(#future_ident);
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
            use ::commonware_macros::futures::FutureExt as _;
            #(#stmts)*

            ::commonware_macros::futures::select_biased! {
                #(#select_branches)*
            }
        }
    }
    .into()
}
