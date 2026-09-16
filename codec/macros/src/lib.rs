//! Procedural macro implementations for `commonware-codec`.
//!
//! Import these derives from `commonware_codec`, which documents their attributes
//! and provides compiling examples.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::Span;
use quote::quote;
use syn::{
    DeriveInput, Error, Generics, Ident, Type, WhereClause, WherePredicate, parenthesized,
    parse_macro_input, parse_quote,
};

/// Resolves the path to the `commonware-codec` crate, accounting for renames and use within
/// `commonware-codec` itself.
fn codec_path() -> proc_macro2::TokenStream {
    match crate_name("commonware-codec") {
        Ok(FoundCrate::Itself) => quote!(::commonware_codec),
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!(::#ident)
        }
        Err(_) => quote!(::commonware_codec),
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

/// Derives `commonware_codec::FixedArray`.
///
/// See the [codec documentation](https://docs.rs/commonware-codec/latest/commonware_codec/derive.FixedArray.html) for examples and attributes.
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
                <Self as #codec::Decode>::decode_cfg(#codec::Copying(bytes), &())
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

#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
mod derive;

/// Derives `commonware_codec::Write`.
///
/// See the [codec documentation](https://docs.rs/commonware-codec/latest/commonware_codec/derive.Write.html) for examples and attributes.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
#[proc_macro_derive(Write, attributes(codec, read_cfg, encode_size))]
pub fn write(input: TokenStream) -> TokenStream {
    derive_tokens(input, derive::Kind::Write)
}

/// Derives `commonware_codec::Read`.
///
/// See the [codec documentation](https://docs.rs/commonware-codec/latest/commonware_codec/derive.Read.html) for examples and attributes.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
#[proc_macro_derive(Read, attributes(codec, read_cfg, encode_size))]
pub fn read(input: TokenStream) -> TokenStream {
    derive_tokens(input, derive::Kind::Read)
}

/// Derives `commonware_codec::EncodeSize`.
///
/// See the [codec documentation](https://docs.rs/commonware-codec/latest/commonware_codec/derive.EncodeSize.html) for examples and attributes.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
#[proc_macro_derive(EncodeSize, attributes(codec, read_cfg, encode_size))]
pub fn encode_size(input: TokenStream) -> TokenStream {
    derive_tokens(input, derive::Kind::EncodeSize)
}

/// Derives `commonware_codec::FixedSize`.
///
/// See the [codec documentation](https://docs.rs/commonware-codec/latest/commonware_codec/derive.FixedSize.html) for examples and attributes.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
#[proc_macro_derive(FixedSize, attributes(codec, read_cfg, encode_size))]
pub fn fixed_size(input: TokenStream) -> TokenStream {
    derive_tokens(input, derive::Kind::FixedSize)
}

/// Derives `commonware_codec::Encode`.
///
/// See the [codec documentation](https://docs.rs/commonware-codec/latest/commonware_codec/derive.Encode.html) for examples and attributes.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
#[proc_macro_derive(Encode, attributes(codec, read_cfg, encode_size))]
pub fn encode(input: TokenStream) -> TokenStream {
    derive_tokens(input, derive::Kind::Encode)
}

#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
fn derive_tokens(input: TokenStream, kind: derive::Kind) -> TokenStream {
    derive::expand(parse_macro_input!(input as DeriveInput), kind)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
