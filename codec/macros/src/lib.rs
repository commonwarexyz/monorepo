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

/// Derives byte-array conversion traits for a fixed-size type.
///
/// Generates:
/// - `TryFrom<[u8; SIZE]>` (skipped when `infallible`, since the standard library's blanket
///   `TryFrom` impl already covers types with an infallible `From<[u8; SIZE]>`)
/// - `TryFrom<&[u8; SIZE]>`
/// - `TryFrom<&[u8]>`
/// - `From<T> for [u8; SIZE]`
/// - `From<&T> for [u8; SIZE]`
///
/// The type must implement `Read<Cfg = ()>` and `EncodeFixed`.
///
/// # Attributes
///
/// - `#[fixed_conversions(infallible)]`: skip the `TryFrom<[u8; SIZE]>` impl.
/// - `#[fixed_conversions(bytes([u8; N]))]`: required for generic types. Stable Rust forbids
///   `[u8; <T as FixedSize>::SIZE]` when `T` is generic, so the byte array type must be named.
#[proc_macro_derive(FixedConversions, attributes(fixed_conversions))]
pub fn fixed_conversions(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let mut infallible = false;
    let mut bytes_ty: Option<Type> = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("fixed_conversions") {
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

    if !input.generics.params.is_empty() && bytes_ty.is_none() {
        return Error::new_spanned(
            &input.generics,
            "generic types must name the byte array type: #[fixed_conversions(bytes([u8; N]))]",
        )
        .to_compile_error()
        .into();
    }

    let codec = codec_path();
    let bytes = bytes_ty.as_ref().map_or_else(
        || quote!([u8; <#name as #codec::FixedSize>::SIZE]),
        |ty| quote!(#ty),
    );

    let try_from_array = if infallible {
        quote!()
    } else {
        quote! {
            impl #impl_generics core::convert::TryFrom<#bytes> for #name #ty_generics #where_clause {
                type Error = #codec::Error;

                fn try_from(bytes: #bytes) -> core::result::Result<Self, Self::Error> {
                    <Self as #codec::DecodeFixed>::decode_fixed(bytes)
                }
            }
        }
    };

    let expanded = quote! {
        #try_from_array

        impl #impl_generics core::convert::TryFrom<&#bytes> for #name #ty_generics #where_clause {
            type Error = #codec::Error;

            fn try_from(bytes: &#bytes) -> core::result::Result<Self, Self::Error> {
                <Self as #codec::DecodeFixed>::decode_fixed(*bytes)
            }
        }

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
