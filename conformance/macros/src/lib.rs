//! Augment the development of [`commonware-conformance`](https://docs.rs/commonware-conformance) with procedural macros.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
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
/// Inserts underscores at PascalCase boundaries and replaces punctuation
/// with underscores. Consecutive separators are collapsed.
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

/// Define tests for types implementing the
/// [`Conformance`](https://docs.rs/commonware-conformance/latest/commonware_conformance/trait.Conformance.html) trait.
///
/// Generates test functions that verify implementations match expected digest
/// values stored in `conformance.toml`.
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
/// - `test_b_tree_map_u32_string`
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ident_for(type_str: &str) -> String {
        let ty: Type = syn::parse_str(type_str).unwrap();
        type_to_ident(&ty)
    }

    #[test]
    fn test_simple_types() {
        assert_eq!(ident_for("u8"), "u8");
        assert_eq!(ident_for("u32"), "u32");
        assert_eq!(ident_for("String"), "string");
    }

    #[test]
    fn test_generic_types() {
        assert_eq!(ident_for("Vec<u8>"), "vec_u8");
        assert_eq!(ident_for("Option<u32>"), "option_u32");
        assert_eq!(ident_for("Option<Vec<u8>>"), "option_vec_u8");
    }

    #[test]
    fn test_pascal_case_splitting() {
        assert_eq!(ident_for("BTreeMap<u32, String>"), "b_tree_map_u32_string");
        assert_eq!(ident_for("HashMap<u32, u32>"), "hash_map_u32_u32");
    }

    #[test]
    fn test_wrapper_types() {
        assert_eq!(
            ident_for("CodecConformance<Vec<u8>>"),
            "codec_conformance_vec_u8"
        );
        assert_eq!(
            ident_for("CodecConformance<BTreeMap<u32, u32>>"),
            "codec_conformance_b_tree_map_u32_u32"
        );
    }

    #[test]
    fn test_paths() {
        assert_eq!(ident_for("std::vec::Vec<u8>"), "std_vec_vec_u8");
        assert_eq!(ident_for("crate::Foo"), "crate_foo");
    }

    #[test]
    fn test_tuples() {
        assert_eq!(ident_for("(u32, u32)"), "u32_u32");
        assert_eq!(ident_for("(u32, u32, u32)"), "u32_u32_u32");
    }

    #[test]
    fn test_arrays() {
        assert_eq!(ident_for("[u8; 32]"), "u8_32");
    }

    #[test]
    fn test_underscores_in_names() {
        assert_eq!(ident_for("my_type"), "my_type");
        assert_eq!(ident_for("My_Type"), "my_type");
    }
}
