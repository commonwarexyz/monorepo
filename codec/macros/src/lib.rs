//! Augment the development of [`commonware-codec`](https://docs.rs/commonware-codec) with procedural macros.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::quote;
use syn::{parenthesized, parse_macro_input, DeriveInput, Error, Ident, Type};

/// Resolves the path to the `commonware-codec` crate, accounting for renames and use within
/// `commonware-codec` itself.
fn codec_path() -> proc_macro2::TokenStream {
    match crate_name("commonware-codec") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!(::#ident)
        }
        Err(_) => quote!(::commonware_codec),
    }
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
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

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

    let from_arrays = if infallible {
        quote! {
            impl #impl_generics core::convert::From<#bytes> for #name #ty_generics #where_clause {
                fn from(bytes: #bytes) -> Self {
                    <Self as #codec::DecodeFixed>::decode_fixed(bytes)
                        .expect("infallible decode of fixed-size array")
                }
            }

            impl #impl_generics core::convert::From<&#bytes> for #name #ty_generics #where_clause {
                fn from(bytes: &#bytes) -> Self {
                    <Self as core::convert::From<#bytes>>::from(*bytes)
                }
            }
        }
    } else {
        quote! {
            impl #impl_generics core::convert::TryFrom<#bytes> for #name #ty_generics #where_clause {
                type Error = #codec::Error;

                fn try_from(bytes: #bytes) -> core::result::Result<Self, Self::Error> {
                    <Self as #codec::DecodeFixed>::decode_fixed(bytes)
                }
            }

            impl #impl_generics core::convert::TryFrom<&#bytes> for #name #ty_generics #where_clause {
                type Error = #codec::Error;

                fn try_from(bytes: &#bytes) -> core::result::Result<Self, Self::Error> {
                    <Self as #codec::DecodeFixed>::decode_fixed(*bytes)
                }
            }
        }
    };

    let expanded = quote! {
        #from_arrays

        impl #impl_generics core::convert::TryFrom<&[u8]> for #name #ty_generics #where_clause {
            type Error = #codec::Error;

            fn try_from(bytes: &[u8]) -> core::result::Result<Self, Self::Error> {
                <Self as #codec::Decode>::decode_cfg(bytes, &())
            }
        }

        impl #impl_generics core::convert::From<#name #ty_generics> for #bytes #where_clause {
            fn from(value: #name #ty_generics) -> Self {
                #codec::EncodeFixed::encode_fixed(&value)
            }
        }

        impl #impl_generics core::convert::From<&#name #ty_generics> for #bytes #where_clause {
            fn from(value: &#name #ty_generics) -> Self {
                #codec::EncodeFixed::encode_fixed(value)
            }
        }
    };

    TokenStream::from(expanded)
}
