//! Derive macros for commonware-codec traits.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Data, DeriveInput, Fields, FieldsNamed, FieldsUnnamed, Index};

/// Derive macro for the `Read` trait.
///
/// Automatically implements `Read` for structs where all fields implement `Read`.
/// The generated implementation will use `()` as the `Cfg` type for simplicity.
/// If any field requires a different `Cfg`, you'll need to implement `Read` manually.
///
/// # Example
///
/// ```
/// use commonware_codec::{Read, extensions::ReadExt};
/// use commonware_codec_derive::Read;
///
/// #[derive(Read)]
/// struct Point {
///     x: u32,
///     y: u32,
/// }
///
/// // Read is now implemented for Point
/// ```
#[proc_macro_derive(Read)]
pub fn derive_read(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_read(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive macro for the `Write` trait.
///
/// Automatically implements `Write` for structs where all fields implement `Write`.
///
/// # Example
///
/// ```
/// use commonware_codec::Write;
/// use commonware_codec_derive::Write;
///
/// #[derive(Write)]
/// struct Point {
///     x: u32,
///     y: u32,
/// }
///
/// // Write is now implemented for Point
/// ```
#[proc_macro_derive(Write)]
pub fn derive_write(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_write(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive macro for the `EncodeSize` trait.
///
/// Automatically implements `EncodeSize` for structs where all fields implement `EncodeSize`.
///
/// # Example
///
/// ```
/// use commonware_codec::EncodeSize;
/// use commonware_codec_derive::EncodeSize;
///
/// #[derive(EncodeSize)]
/// struct Point {
///     x: u32,
///     y: u32,
/// }
///
/// // EncodeSize is now implemented for Point
/// ```
#[proc_macro_derive(EncodeSize)]
pub fn derive_encode_size(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_encode_size(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_read(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let read_fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => expand_read_named_fields(fields)?,
            Fields::Unnamed(fields) => expand_read_unnamed_fields(fields)?,
            Fields::Unit => quote! { Ok(#name) },
        },
        Data::Enum(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "Read derive macro does not support enums",
            ));
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "Read derive macro does not support unions",
            ));
        }
    };

    Ok(quote! {
        impl #impl_generics ::commonware_codec::Read for #name #type_generics #where_clause {
            type Cfg = ();

            fn read_cfg(buf: &mut impl ::bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, ::commonware_codec::Error> {
                #read_fields
            }
        }
    })
}

fn expand_write(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let write_fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => expand_write_named_fields(fields)?,
            Fields::Unnamed(fields) => expand_write_unnamed_fields(fields)?,
            Fields::Unit => quote! {},
        },
        Data::Enum(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "Write derive macro does not support enums",
            ));
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "Write derive macro does not support unions",
            ));
        }
    };

    Ok(quote! {
        impl #impl_generics ::commonware_codec::Write for #name #type_generics #where_clause {
            fn write(&self, buf: &mut impl ::bytes::BufMut) {
                #write_fields
            }
        }
    })
}

fn expand_encode_size(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let size_calculation = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => expand_encode_size_named_fields(fields)?,
            Fields::Unnamed(fields) => expand_encode_size_unnamed_fields(fields)?,
            Fields::Unit => quote! { 0 },
        },
        Data::Enum(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "EncodeSize derive macro does not support enums",
            ));
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "EncodeSize derive macro does not support unions",
            ));
        }
    };

    Ok(quote! {
        impl #impl_generics ::commonware_codec::EncodeSize for #name #type_generics #where_clause {
            fn encode_size(&self) -> usize {
                #size_calculation
            }
        }
    })
}

fn expand_read_named_fields(fields: &FieldsNamed) -> syn::Result<TokenStream2> {
    if fields.named.is_empty() {
        return Ok(quote! { Ok(Self) });
    }

    let field_reads = fields.named.iter().map(|field| {
        let field_name = &field.ident;
        quote! {
            let #field_name = ::commonware_codec::Read::read_cfg(buf, &())?;
        }
    });

    let field_names = fields.named.iter().map(|field| &field.ident);

    Ok(quote! {
        #(#field_reads)*
        Ok(Self {
            #(#field_names,)*
        })
    })
}

fn expand_read_unnamed_fields(fields: &FieldsUnnamed) -> syn::Result<TokenStream2> {
    if fields.unnamed.is_empty() {
        return Ok(quote! { Ok(Self) });
    }

    let field_reads = fields.unnamed.iter().enumerate().map(|(i, _)| {
        let field_name = format_ident!("field_{}", i);
        quote! {
            let #field_name = ::commonware_codec::Read::read_cfg(buf, &())?;
        }
    });

    let field_names = (0..fields.unnamed.len()).map(|i| format_ident!("field_{}", i));

    Ok(quote! {
        #(#field_reads)*
        Ok(Self(#(#field_names,)*))
    })
}

fn expand_write_named_fields(fields: &FieldsNamed) -> syn::Result<TokenStream2> {
    let field_writes = fields.named.iter().map(|field| {
        let field_name = &field.ident;
        quote! {
            ::commonware_codec::Write::write(&self.#field_name, buf);
        }
    });

    Ok(quote! {
        #(#field_writes)*
    })
}

fn expand_write_unnamed_fields(fields: &FieldsUnnamed) -> syn::Result<TokenStream2> {
    let field_writes = fields.unnamed.iter().enumerate().map(|(i, _)| {
        let index = Index::from(i);
        quote! {
            ::commonware_codec::Write::write(&self.#index, buf);
        }
    });

    Ok(quote! {
        #(#field_writes)*
    })
}

fn expand_encode_size_named_fields(fields: &FieldsNamed) -> syn::Result<TokenStream2> {
    if fields.named.is_empty() {
        return Ok(quote! { 0 });
    }

    let field_sizes = fields.named.iter().map(|field| {
        let field_name = &field.ident;
        quote! {
            ::commonware_codec::EncodeSize::encode_size(&self.#field_name)
        }
    });

    Ok(quote! {
        0 #(+ #field_sizes)*
    })
}

fn expand_encode_size_unnamed_fields(fields: &FieldsUnnamed) -> syn::Result<TokenStream2> {
    if fields.unnamed.is_empty() {
        return Ok(quote! { 0 });
    }

    let field_sizes = fields.unnamed.iter().enumerate().map(|(i, _)| {
        let index = Index::from(i);
        quote! {
            ::commonware_codec::EncodeSize::encode_size(&self.#index)
        }
    });

    Ok(quote! {
        0 #(+ #field_sizes)*
    })
}
