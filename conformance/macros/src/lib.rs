//! Augment the development of conformance tests with procedural macros.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, DeriveInput,
    punctuated::Punctuated,
    Ident, Token, Type,
};

/// A single conformance test entry: `Type` or `Type => n_cases`
struct ConformanceEntry {
    ty: Type,
    n_cases: Option<syn::Expr>,
}

impl Parse for ConformanceEntry {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let ty: Type = input.parse()?;

        let n_cases = if input.peek(Token![=>]) {
            input.parse::<Token![=>]>()?;
            Some(input.parse()?)
        } else {
            None
        };

        Ok(Self { ty, n_cases })
    }
}

/// The full input to conformance_tests!
struct ConformanceInput {
    entries: Punctuated<ConformanceEntry, Token![,]>,
}

impl Parse for ConformanceInput {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let entries = Punctuated::parse_terminated(input)?;
        Ok(Self { entries })
    }
}

/// Convert a type to a valid snake_case function name suffix.
///
/// Examples:
/// - `Vec<u8>` -> `vec_u8`
/// - `BTreeMap<u32, String>` -> `btreemap_u32_string`
/// - `Option<Vec<u8>>` -> `option_vec_u8`
fn type_to_ident(ty: &Type) -> String {
    let type_str = quote!(#ty).to_string();

    let mut result = String::with_capacity(type_str.len());
    let mut prev_was_separator = true;

    for c in type_str.chars() {
        match c {
            'A'..='Z' => {
                if !prev_was_separator && !result.is_empty() {
                    result.push('_');
                }
                result.push(c.to_ascii_lowercase());
                prev_was_separator = false;
            }
            'a'..='z' | '0'..='9' => {
                result.push(c);
                prev_was_separator = false;
            }
            '_' => {
                if !prev_was_separator && !result.is_empty() {
                    result.push('_');
                }
                prev_was_separator = true;
            }
            '<' | '>' | ',' | ' ' | ':' => {
                if !prev_was_separator && !result.is_empty() {
                    result.push('_');
                }
                prev_was_separator = true;
            }
            // Skip other characters
            _ => {}
        }
    }

    result.trim_end_matches("_").to_string()
}

/// Define conformance tests for types implementing the `Conformance` trait.
///
/// This macro generates test functions that verify implementations match expected
/// hash values stored in `conformance.toml`.
///
/// # Usage
///
/// ```ignore
/// conformance_tests! {
///     Vec<u8>,                       // Uses default (65536 cases)
///     Vec<u16> => 100,               // Explicit case count
///     BTreeMap<u32, String> => 100,
/// }
/// ```
///
/// This generates test functions named after the type:
/// - `test_vec_u8`
/// - `test_vec_u16`
/// - `test_btreemap_u32_string`
///
/// The type name is used as the key in the TOML file.
#[proc_macro]
pub fn conformance_tests(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ConformanceInput);

    let tests = input.entries.iter().map(|entry| {
        let ty = &entry.ty;
        let n_cases = entry
            .n_cases
            .as_ref()
            .map(|e| quote!(#e))
            .unwrap_or_else(|| quote!(::commonware_conformance::DEFAULT_CASES));

        let type_name_str = quote!(#ty).to_string().replace(' ', "");
        let fn_name_suffix = type_to_ident(ty);
        let fn_name = Ident::new(&format!("test_{fn_name_suffix}"), Span::call_site());

        quote! {
            #[::commonware_conformance::commonware_macros::test_group("conformance")]
            #[test]
            fn #fn_name() {
                ::commonware_conformance::futures::executor::block_on(
                    ::commonware_conformance::run_conformance_test::<#ty>(
                        concat!(module_path!(), "::", #type_name_str),
                        #n_cases,
                        ::std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance.toml")),
                    )
                );
            }
        }
    });

    let expanded = quote! {
        #(#tests)*
    };

    expanded.into()
}

/// Generate a conformance test for the type this derive is applied to.
///
/// This derive macro generates a test module containing a conformance test
/// for the annotated type.
///
/// # Attributes
///
/// Use the `#[conformance(...)]` attribute to configure the test:
///
/// - `bridge = SomeType`: Wrap the type with a bridge type, generating
///   `SomeType<MyType>` instead of just `MyType`. This is useful for types
///   that don't directly implement `Conformance` but have a wrapper that does.
///
/// - `n_cases = N`: Number of test cases to generate (default: 65536).
///
/// # Examples
///
/// Basic usage (type must implement `Conformance`):
///
/// ```ignore
/// #[derive(ConformanceTest)]
/// pub struct MyType { /* ... */ }
/// ```
///
/// With a bridge type (e.g., for codec conformance):
///
/// ```ignore
/// #[derive(ConformanceTest)]
/// #[conformance(bridge = CodecConformance)]
/// pub struct MyType { /* ... */ }
/// // Generates test for: CodecConformance<MyType>
/// ```
///
/// With custom case count:
///
/// ```ignore
/// #[derive(ConformanceTest)]
/// #[conformance(n_cases = 1024)]
/// pub struct MyType { /* ... */ }
/// ```
///
/// Combined:
///
/// ```ignore
/// #[derive(ConformanceTest)]
/// #[conformance(bridge = CodecConformance, n_cases = 1024)]
/// pub struct MyType { /* ... */ }
/// ```
#[proc_macro_derive(ConformanceTest, attributes(conformance))]
pub fn derive_conformance_test(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let type_name = &input.ident;

    // Parse the #[conformance(...)] attribute
    let mut bridge: Option<syn::Path> = None;
    let mut n_cases: Option<syn::Expr> = None;

    for attr in &input.attrs {
        if attr.path().is_ident("conformance") {
            let result = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("bridge") {
                    meta.input.parse::<Token![=]>()?;
                    bridge = Some(meta.input.parse()?);
                    Ok(())
                } else if meta.path.is_ident("n_cases") {
                    meta.input.parse::<Token![=]>()?;
                    n_cases = Some(meta.input.parse()?);
                    Ok(())
                } else {
                    Err(meta.error("expected `bridge` or `n_cases`"))
                }
            });

            if let Err(e) = result {
                return e.to_compile_error().into();
            }
        }
    }

    // Build the test type (either Bridge<Type> or just Type)
    let test_type: proc_macro2::TokenStream = if let Some(bridge_path) = &bridge {
        quote!(#bridge_path<#type_name>)
    } else {
        quote!(#type_name)
    };

    // Build the n_cases expression
    let n_cases_expr = n_cases
        .map(|e| quote!(#e))
        .unwrap_or_else(|| quote!(::commonware_conformance::DEFAULT_CASES));

    // Generate the test function name from the full test type
    let test_type_for_name: syn::Type = syn::parse2(test_type.clone()).unwrap();
    let fn_name_suffix = type_to_ident(&test_type_for_name);
    let fn_name = Ident::new(&format!("test_{fn_name_suffix}"), Span::call_site());

    // Generate the type name string for the TOML key
    let type_name_str = test_type.to_string().replace(' ', "");

    let expanded = quote! {
        #[cfg(test)]
        #[::commonware_conformance::commonware_macros::test_group("conformance")]
        #[test]
        fn #fn_name() {
            ::commonware_conformance::futures::executor::block_on(
                ::commonware_conformance::run_conformance_test::<#test_type>(
                    concat!(module_path!(), "::", #type_name_str),
                    #n_cases_expr,
                    ::std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance.toml")),
                )
            );
        }
    };

    expanded.into()
}
