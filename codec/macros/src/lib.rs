//! Augment the development of [`commonware-codec`](https://docs.rs/commonware-codec) with procedural macros.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

mod expand;
mod input;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::Span;
use quote::quote;
use syn::{
    DeriveInput, Error, Generics, Ident, Type, WhereClause, WherePredicate, parenthesized,
    parse_macro_input, parse_quote,
};

/// Resolves the path to the `commonware-codec` crate, accounting for renames and use within
/// `commonware-codec` itself (which aliases itself via `extern crate self`, so its doctests
/// resolve the same path).
fn codec_path() -> proc_macro2::TokenStream {
    match crate_name("commonware-codec") {
        Ok(FoundCrate::Itself) | Err(_) => quote!(::commonware_codec),
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!(::#ident)
        }
    }
}

/// Returns a where clause that preserves user predicates and adds one generated bound.
fn where_clause_with(generics: &Generics, predicate: WherePredicate) -> WhereClause {
    let mut generics = generics.clone();
    generics.make_where_clause().predicates.push(predicate);
    generics
        .where_clause
        .expect("make_where_clause should create a where clause")
}

/// Derives `Write` by writing each field in declaration order.
///
/// Enum variants write their mandatory `#[codec(tag = N)]` byte before their fields, and
/// `write_bufs` forwards to each field's `write_bufs`. All four codec derives accept
/// `#[codec(bound = "...")]` to replace the auto-generated per-field bounds.
#[proc_macro_derive(Write, attributes(codec))]
pub fn derive_write(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand::write(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derives `EncodeSize` as the sum of field sizes, plus one tag byte for enums.
///
/// Never derive this alongside `FixedSize`, which provides `EncodeSize` automatically.
#[proc_macro_derive(EncodeSize, attributes(codec))]
pub fn derive_encode_size(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand::encode_size(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derives `FixedSize` with `SIZE` the sum of field sizes. Structs only.
#[proc_macro_derive(FixedSize, attributes(codec))]
pub fn derive_fixed_size(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand::fixed_size(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derives `Read` by reading each field in declaration order.
///
/// `Cfg` is `()` unless exactly one field (or at most one per enum variant) is marked
/// `#[codec(cfg)]`, in which case that field's `Read::Cfg` becomes the container's and receives
/// the caller's config; every other field must have a unit-like config. Unknown enum tags yield
/// `Error::InvalidEnum`.
#[proc_macro_derive(Read, attributes(codec))]
pub fn derive_read(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand::read(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derives byte-array conversion impls for a fixed-size type.
///
/// Generates:
/// - `TryFrom<[u8; SIZE]>` and `TryFrom<&[u8; SIZE]>`, or `From<[u8; SIZE]>` and
///   `From<&[u8; SIZE]>` when `infallible` (decoding via `DecodeFixed`).
/// - `TryFrom<&[u8]>`
/// - `From<T> for [u8; SIZE]`
/// - `From<&T> for [u8; SIZE]`
///
/// The type must implement `Read<Cfg = ()>` and `EncodeFixed`.
///
/// # Attributes
///
/// - `#[fixed_array(infallible)]`: emit `From<[u8; SIZE]>` instead of `TryFrom<[u8; SIZE]>`.
///   The type's decode must never fail (any `[u8; SIZE]` is a valid value), since the generated
///   `From` unwraps the `DecodeFixed` result.
/// - `#[fixed_array(bytes([u8; N]))]`: required for any generic type (lifetime, type, or
///   const). Stable Rust forbids a generic parameter inside the const expression
///   `[u8; <T as FixedSize>::SIZE]`, so the byte array type must be named.
#[proc_macro_derive(FixedArray, attributes(fixed_array))]
pub fn fixed_array(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let (impl_generics, ty_generics, _) = input.generics.split_for_impl();

    let mut infallible = false;
    let mut bytes_ty: Option<Type> = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("fixed_array") {
            continue;
        }
        let result = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("infallible") {
                infallible = true;
                Ok(())
            } else if meta.path.is_ident("bytes") {
                let content;
                parenthesized!(content in meta.input);
                bytes_ty = Some(content.parse()?);
                Ok(())
            } else {
                Err(meta.error("expected `infallible` or `bytes(...)`"))
            }
        });
        if let Err(e) = result {
            return e.to_compile_error().into();
        }
    }

    // Stable Rust forbids any generic parameter (lifetime, type, or const) inside the const
    // expression `<T as FixedSize>::SIZE`, so generic types must name the byte array type.
    if !input.generics.params.is_empty() && bytes_ty.is_none() {
        return Error::new_spanned(
            &input.generics,
            "generic types must name the byte array type: #[fixed_array(bytes([u8; N]))]",
        )
        .to_compile_error()
        .into();
    }

    let codec = codec_path();
    let bytes = bytes_ty.as_ref().map_or_else(
        || quote!([u8; <#name as #codec::FixedSize>::SIZE]),
        |ty| quote!(#ty),
    );
    let decode_fixed_where = where_clause_with(
        &input.generics,
        parse_quote!(#name #ty_generics: #codec::DecodeFixed),
    );
    let encode_fixed_where = where_clause_with(
        &input.generics,
        parse_quote!(#name #ty_generics: #codec::EncodeFixed),
    );

    let from_arrays = if infallible {
        quote! {
            impl #impl_generics core::convert::From<#bytes> for #name #ty_generics #decode_fixed_where {
                fn from(bytes: #bytes) -> Self {
                    <Self as #codec::DecodeFixed>::decode_fixed(bytes)
                        .expect("infallible decode of fixed-size array")
                }
            }

            impl #impl_generics core::convert::From<&#bytes> for #name #ty_generics #decode_fixed_where {
                fn from(bytes: &#bytes) -> Self {
                    <Self as core::convert::From<#bytes>>::from(*bytes)
                }
            }
        }
    } else {
        quote! {
            impl #impl_generics core::convert::TryFrom<#bytes> for #name #ty_generics #decode_fixed_where {
                type Error = #codec::Error;

                fn try_from(bytes: #bytes) -> core::result::Result<Self, Self::Error> {
                    <Self as #codec::DecodeFixed>::decode_fixed(bytes)
                }
            }

            impl #impl_generics core::convert::TryFrom<&#bytes> for #name #ty_generics #decode_fixed_where {
                type Error = #codec::Error;

                fn try_from(bytes: &#bytes) -> core::result::Result<Self, Self::Error> {
                    <Self as #codec::DecodeFixed>::decode_fixed(*bytes)
                }
            }
        }
    };

    let expanded = quote! {
        #from_arrays

        impl #impl_generics core::convert::TryFrom<&[u8]> for #name #ty_generics #decode_fixed_where {
            type Error = #codec::Error;

            fn try_from(bytes: &[u8]) -> core::result::Result<Self, Self::Error> {
                <Self as #codec::Decode>::decode_cfg(bytes, &())
            }
        }

        impl #impl_generics core::convert::From<#name #ty_generics> for #bytes #encode_fixed_where {
            fn from(value: #name #ty_generics) -> Self {
                #codec::EncodeFixed::encode_fixed(&value)
            }
        }

        impl #impl_generics core::convert::From<&#name #ty_generics> for #bytes #encode_fixed_where {
            fn from(value: &#name #ty_generics) -> Self {
                #codec::EncodeFixed::encode_fixed(value)
            }
        }
    };

    TokenStream::from(expanded)
}
