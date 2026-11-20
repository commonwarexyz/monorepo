// force-host
// no-prefer-dynamic
// edition:2021

// Stands in for `commonware_macros_impl` under its crate name, so definitions
// match.

#![crate_type = "proc-macro"]

extern crate proc_macro;

use proc_macro::{Delimiter, Group, TokenStream, TokenTree};

// Invokes tokio's `select!` through `commonware_macros`' re-export on
// `branches`, preserving their spans, the way the real macros do after they
// wrap each branch in the budget guard.
fn tokio_select(branches: TokenStream) -> TokenStream {
    let mut select: TokenStream = "::commonware_macros::__reexport::tokio::select!"
        .parse()
        .unwrap();
    select.extend([TokenTree::Group(Group::new(Delimiter::Brace, branches))]);
    TokenTree::Group(Group::new(Delimiter::Brace, select)).into()
}

#[proc_macro]
pub fn select(input: TokenStream) -> TokenStream {
    let mut branches: TokenStream = "biased;".parse().unwrap();
    branches.extend(input);
    tokio_select(branches)
}

// The real `select_loop!` expands to `commonware_macros::select!`. Invoking
// tokio's `select!` directly covers the `select_loop!` exemption on its own.
#[proc_macro]
pub fn select_loop(input: TokenStream) -> TokenStream {
    tokio_select(input)
}
