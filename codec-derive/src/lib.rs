//! Derive macros for commonware-codec traits.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, Data, DeriveInput, Field, Fields, FieldsNamed, FieldsUnnamed, Index, Meta,
};

/// Derive macro for the `Read` trait.
///
/// Automatically implements `Read` for structs where all fields implement `Read`.
/// The generated implementation will use `()` as the `Cfg` type for simplicity.
/// If any field requires a different `Cfg`, you'll need to implement `Read` manually.
///
/// # Codec Helper Attributes
///
/// You can use the `#[codec(varint)]` helper attribute to enable variable-length encoding for integer fields.
/// The wrapper type (UInt for unsigned, SInt for signed) is automatically inferred from the field type.
///
/// Supported types: u16, u32, u64, u128, i16, i32, i64, i128
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
/// #[derive(Read)]
/// struct EfficientPoint {
///     #[codec(varint)]
///     x: u32,  // Encoded as UInt (varint)
///     #[codec(varint)]
///     y: i32,  // Encoded as SInt (signed varint)
/// }
///
/// // Read is now implemented for both structs
/// ```
#[proc_macro_derive(Read, attributes(codec))]
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
/// # Codec Helper Attributes
///
/// You can use the `#[codec(varint)]` helper attribute to enable variable-length encoding for integer fields.
/// The wrapper type (UInt for unsigned, SInt for signed) is automatically inferred from the field type.
///
/// Supported types: u16, u32, u64, u128, i16, i32, i64, i128
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
/// #[derive(Write)]
/// struct EfficientPoint {
///     #[codec(varint)]
///     x: u32,  // Encoded as UInt (varint)
///     #[codec(varint)]
///     y: i32,  // Encoded as SInt (signed varint)
/// }
///
/// // Write is now implemented for both structs
/// ```
#[proc_macro_derive(Write, attributes(codec))]
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
/// # Codec Helper Attributes
///
/// You can use the `#[codec(varint)]` helper attribute to enable variable-length encoding for integer fields.
/// The wrapper type (UInt for unsigned, SInt for signed) is automatically inferred from the field type.
///
/// Supported types: u16, u32, u64, u128, i16, i32, i64, i128
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
/// #[derive(EncodeSize)]
/// struct EfficientPoint {
///     #[codec(varint)]
///     x: u32,  // Encoded as UInt (varint)
///     #[codec(varint)]
///     y: i32,  // Encoded as SInt (signed varint)
/// }
///
/// // EncodeSize is now implemented for both structs
/// ```
#[proc_macro_derive(EncodeSize, attributes(codec))]
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

    let field_reads = fields
        .named
        .iter()
        .map(|field| {
            let field_name = &field.ident;
            let wrapper = parse_codec_attributes(field)?;
            Ok(generate_field_read(field_name.as_ref().unwrap(), &wrapper))
        })
        .collect::<syn::Result<Vec<_>>>()?;

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

    let field_reads = fields
        .unnamed
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let field_name = format_ident!("field_{}", i);
            let wrapper = parse_codec_attributes(field)?;
            Ok(generate_field_read(&field_name, &wrapper))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let field_names = (0..fields.unnamed.len()).map(|i| format_ident!("field_{}", i));

    Ok(quote! {
        #(#field_reads)*
        Ok(Self(#(#field_names,)*))
    })
}

fn expand_write_named_fields(fields: &FieldsNamed) -> syn::Result<TokenStream2> {
    let field_writes = fields
        .named
        .iter()
        .map(|field| {
            let field_name = &field.ident;
            let wrapper = parse_codec_attributes(field)?;
            let field_access = quote! { self.#field_name };
            Ok(generate_field_write(field_access, &wrapper))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        #(#field_writes)*
    })
}

fn expand_write_unnamed_fields(fields: &FieldsUnnamed) -> syn::Result<TokenStream2> {
    let field_writes = fields
        .unnamed
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let index = Index::from(i);
            let wrapper = parse_codec_attributes(field)?;
            let field_access = quote! { self.#index };
            Ok(generate_field_write(field_access, &wrapper))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        #(#field_writes)*
    })
}

fn expand_encode_size_named_fields(fields: &FieldsNamed) -> syn::Result<TokenStream2> {
    if fields.named.is_empty() {
        return Ok(quote! { 0 });
    }

    let field_sizes = fields
        .named
        .iter()
        .map(|field| {
            let field_name = &field.ident;
            let wrapper = parse_codec_attributes(field)?;
            let field_access = quote! { self.#field_name };
            Ok(generate_field_encode_size(field_access, &wrapper))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        0 #(+ #field_sizes)*
    })
}

fn expand_encode_size_unnamed_fields(fields: &FieldsUnnamed) -> syn::Result<TokenStream2> {
    if fields.unnamed.is_empty() {
        return Ok(quote! { 0 });
    }

    let field_sizes = fields
        .unnamed
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let index = Index::from(i);
            let wrapper = parse_codec_attributes(field)?;
            let field_access = quote! { self.#index };
            Ok(generate_field_encode_size(field_access, &wrapper))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        0 #(+ #field_sizes)*
    })
}

// ---------- Helper Functions for Codec Attributes ----------

#[derive(Debug, Clone, PartialEq)]
enum CodecWrapper {
    None,
    UInt,
    SInt,
}

/// Parse codec attributes on a field to determine if it should be wrapped.
fn parse_codec_attributes(field: &Field) -> syn::Result<CodecWrapper> {
    for attr in &field.attrs {
        if attr.path().is_ident("codec") {
            match &attr.meta {
                Meta::List(meta_list) => {
                    // Parse #[codec(varint)]
                    let nested = meta_list.parse_args::<syn::Ident>()?;
                    match nested.to_string().as_str() {
                        "varint" => return infer_wrapper_from_type(&field.ty),
                        other => {
                            return Err(syn::Error::new_spanned(
                                nested,
                                format!("Unknown codec attribute: {}. Use 'varint'", other),
                            ));
                        }
                    }
                }
                Meta::Path(_) | Meta::NameValue(_) => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "Use #[codec(varint)] - wrapper type is inferred from field type",
                    ));
                }
            }
        }
    }
    Ok(CodecWrapper::None)
}

/// Infer the appropriate wrapper type based on the field's type.
fn infer_wrapper_from_type(ty: &syn::Type) -> syn::Result<CodecWrapper> {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            match segment.ident.to_string().as_str() {
                // Unsigned types -> UInt
                "u16" | "u32" | "u64" | "u128" => return Ok(CodecWrapper::UInt),
                // Signed types -> SInt
                "i16" | "i32" | "i64" | "i128" => return Ok(CodecWrapper::SInt),
                _ => {}
            }
        }
    }

    Err(syn::Error::new_spanned(
        ty,
        "codec attribute can only be used with integer types: u16, u32, u64, u128, i16, i32, i64, i128",
    ))
}

/// Generate appropriate field access for reading, based on codec wrapper.
fn generate_field_read(field_name: &syn::Ident, wrapper: &CodecWrapper) -> TokenStream2 {
    match wrapper {
        CodecWrapper::None => quote! {
            let #field_name = ::commonware_codec::Read::read_cfg(buf, &())?;
        },
        CodecWrapper::UInt => quote! {
            let #field_name = ::commonware_codec::varint::UInt::read_cfg(buf, &())?.into();
        },
        CodecWrapper::SInt => quote! {
            let #field_name = ::commonware_codec::varint::SInt::read_cfg(buf, &())?.into();
        },
    }
}

/// Generate appropriate field access for writing, based on codec wrapper.
fn generate_field_write(field_access: TokenStream2, wrapper: &CodecWrapper) -> TokenStream2 {
    match wrapper {
        CodecWrapper::None => quote! {
            ::commonware_codec::Write::write(&#field_access, buf);
        },
        CodecWrapper::UInt => quote! {
            ::commonware_codec::Write::write(&::commonware_codec::varint::UInt(#field_access), buf);
        },
        CodecWrapper::SInt => quote! {
            ::commonware_codec::Write::write(&::commonware_codec::varint::SInt(#field_access), buf);
        },
    }
}

/// Generate appropriate field access for encoding size, based on codec wrapper.
fn generate_field_encode_size(field_access: TokenStream2, wrapper: &CodecWrapper) -> TokenStream2 {
    match wrapper {
        CodecWrapper::None => quote! {
            ::commonware_codec::EncodeSize::encode_size(&#field_access)
        },
        CodecWrapper::UInt => quote! {
            ::commonware_codec::EncodeSize::encode_size(&::commonware_codec::varint::UInt(#field_access))
        },
        CodecWrapper::SInt => quote! {
            ::commonware_codec::EncodeSize::encode_size(&::commonware_codec::varint::SInt(#field_access))
        },
    }
}
