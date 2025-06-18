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
/// The `Cfg` type is automatically inferred from field attributes and types.
///
/// # Helper Attributes
///
/// ## Codec Attributes
/// You can use the `#[codec(varint)]` helper attribute to enable variable-length encoding for integer fields.
/// The wrapper type (UInt for unsigned, SInt for signed) is automatically inferred from the field type.
///
/// Supported types: u16, u32, u64, u128, i16, i32, i64, i128
///
/// ## Config Attributes  
/// You can use the `#[config(ConfigType)]` helper attribute to specify custom configuration types for fields.
/// The overall `Cfg` type is built as an ordered tuple of field configs, with optimizations:
/// - Unit type `()` fields are ignored
/// - Single config field uses the type directly (not wrapped in tuple)
/// - Fields without explicit `#[config]` use inferred defaults (e.g., `RangeCfg` for `Vec`, `String`)
///
/// # Example
///
/// ```
/// use commonware_codec::{Read, extensions::ReadExt, RangeCfg};
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
/// #[derive(Read)]
/// struct ConfigurableStruct {
///     #[config(RangeCfg)]
///     data: Vec<u8>,  // Uses RangeCfg for length limits
///     count: u32,     // Uses () (no config needed)
/// }
/// // Cfg type is RangeCfg - single config type, not wrapped in tuple
///
/// // Read is now implemented for all structs
/// ```
#[proc_macro_derive(Read, attributes(codec, config))]
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
#[proc_macro_derive(Write, attributes(codec, config))]
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
#[proc_macro_derive(EncodeSize, attributes(codec, config))]
pub fn derive_encode_size(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_encode_size(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_read(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let (read_fields, cfg_type) = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => expand_read_named_fields_with_cfg(fields)?,
            Fields::Unnamed(fields) => expand_read_unnamed_fields_with_cfg(fields)?,
            Fields::Unit => (quote! { Ok(#name) }, syn::parse_quote!(())),
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
            type Cfg = #cfg_type;

            fn read_cfg(buf: &mut impl ::bytes::Buf, cfg: &Self::Cfg) -> Result<Self, ::commonware_codec::Error> {
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

fn expand_read_named_fields_with_cfg(
    fields: &FieldsNamed,
) -> syn::Result<(TokenStream2, syn::Type)> {
    if fields.named.is_empty() {
        return Ok((quote! { Ok(Self) }, syn::parse_quote!(())));
    }

    // Parse field configurations
    let field_configs = fields
        .named
        .iter()
        .map(parse_field_attributes)
        .collect::<syn::Result<Vec<_>>>()?;

    let field_types: Vec<_> = fields.named.iter().map(|f| &f.ty).collect();
    let cfg_type = build_cfg_type(&field_configs, &field_types);

    // Generate field reads with cfg handling
    let mut cfg_index = 0;
    let field_reads = fields
        .named
        .iter()
        .zip(&field_configs)
        .map(|(field, config)| {
            let field_name = field.ident.as_ref().unwrap();

            if is_unit_type(&field.ty) {
                // Unit types don't need config and are constructed directly
                return Ok(quote! {
                    let #field_name = ();
                });
            }

            let read_code = match &cfg_type {
                syn::Type::Tuple(_) => {
                    let index = syn::Index::from(cfg_index);
                    cfg_index += 1;
                    generate_field_read_with_cfg(
                        field_name,
                        &config.wrapper,
                        quote! { &cfg.#index },
                    )
                }
                _ if cfg_index == 0 => {
                    cfg_index += 1;
                    generate_field_read_with_cfg(field_name, &config.wrapper, quote! { cfg })
                }
                _ => {
                    cfg_index += 1;
                    generate_field_read_with_cfg(field_name, &config.wrapper, quote! { &() })
                }
            };
            Ok(read_code)
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let field_names = fields.named.iter().map(|field| &field.ident);

    let read_impl = quote! {
        #(#field_reads)*
        Ok(Self {
            #(#field_names,)*
        })
    };

    Ok((read_impl, cfg_type))
}

fn expand_read_named_fields(fields: &FieldsNamed) -> syn::Result<TokenStream2> {
    let (read_impl, _) = expand_read_named_fields_with_cfg(fields)?;
    Ok(read_impl)
}

fn expand_read_unnamed_fields_with_cfg(
    fields: &FieldsUnnamed,
) -> syn::Result<(TokenStream2, syn::Type)> {
    if fields.unnamed.is_empty() {
        return Ok((quote! { Ok(Self) }, syn::parse_quote!(())));
    }

    // Parse field configurations
    let field_configs = fields
        .unnamed
        .iter()
        .map(parse_field_attributes)
        .collect::<syn::Result<Vec<_>>>()?;

    let field_types: Vec<_> = fields.unnamed.iter().map(|f| &f.ty).collect();
    let cfg_type = build_cfg_type(&field_configs, &field_types);

    // Generate field reads with cfg handling
    let mut cfg_index = 0;
    let field_reads = fields
        .unnamed
        .iter()
        .enumerate()
        .zip(&field_configs)
        .map(|((i, field), config)| {
            let field_name = format_ident!("field_{}", i);

            if is_unit_type(&field.ty) {
                // Unit types don't need config and are constructed directly
                return Ok(quote! {
                    let #field_name = ();
                });
            }

            let read_code = match &cfg_type {
                syn::Type::Tuple(_) => {
                    let index = syn::Index::from(cfg_index);
                    cfg_index += 1;
                    generate_field_read_with_cfg(
                        &field_name,
                        &config.wrapper,
                        quote! { &cfg.#index },
                    )
                }
                _ if cfg_index == 0 => {
                    cfg_index += 1;
                    generate_field_read_with_cfg(&field_name, &config.wrapper, quote! { cfg })
                }
                _ => {
                    cfg_index += 1;
                    generate_field_read_with_cfg(&field_name, &config.wrapper, quote! { &() })
                }
            };
            Ok(read_code)
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let field_names = (0..fields.unnamed.len()).map(|i| format_ident!("field_{}", i));

    let read_impl = quote! {
        #(#field_reads)*
        Ok(Self(#(#field_names,)*))
    };

    Ok((read_impl, cfg_type))
}

fn expand_read_unnamed_fields(fields: &FieldsUnnamed) -> syn::Result<TokenStream2> {
    let (read_impl, _) = expand_read_unnamed_fields_with_cfg(fields)?;
    Ok(read_impl)
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

/// Configuration for a field - specifies both codec wrapper and config type.
#[derive(Clone)]
struct FieldConfig {
    wrapper: CodecWrapper,
    cfg_type: Option<syn::Type>,
}

/// Parse all relevant attributes on a field to determine configuration.
fn parse_field_attributes(field: &Field) -> syn::Result<FieldConfig> {
    let mut wrapper = CodecWrapper::None;
    let mut cfg_type = None;

    for attr in &field.attrs {
        if attr.path().is_ident("codec") {
            match &attr.meta {
                Meta::List(meta_list) => {
                    // Parse #[codec(varint)]
                    let nested = meta_list.parse_args::<syn::Ident>()?;
                    match nested.to_string().as_str() {
                        "varint" => wrapper = infer_wrapper_from_type(&field.ty)?,
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
        } else if attr.path().is_ident("config") {
            match &attr.meta {
                Meta::List(meta_list) => {
                    // Parse #[config(RangeCfg)] or #[config(CustomType)]
                    cfg_type = Some(meta_list.parse_args::<syn::Type>()?);
                }
                Meta::Path(_) | Meta::NameValue(_) => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "Use #[config(ConfigType)] to specify the config type for this field",
                    ));
                }
            }
        }
    }

    Ok(FieldConfig { wrapper, cfg_type })
}

/// Parse codec attributes on a field to determine if it should be wrapped.
/// This is kept for backward compatibility but delegates to parse_field_attributes.
fn parse_codec_attributes(field: &Field) -> syn::Result<CodecWrapper> {
    Ok(parse_field_attributes(field)?.wrapper)
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
    generate_field_read_with_cfg(field_name, wrapper, quote! { &() })
}

/// Generate appropriate field access for reading with custom cfg, based on codec wrapper.
fn generate_field_read_with_cfg(
    field_name: &syn::Ident,
    wrapper: &CodecWrapper,
    cfg_expr: TokenStream2,
) -> TokenStream2 {
    match wrapper {
        CodecWrapper::None => quote! {
            let #field_name = ::commonware_codec::Read::read_cfg(buf, #cfg_expr)?;
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

/// Check if a type is the unit type `()`.
fn is_unit_type(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Tuple(tuple) if tuple.elems.is_empty())
}

/// Determine the default config type for a field based on its type.
/// Returns None for types that don't need configuration.
fn infer_default_cfg_type(ty: &syn::Type) -> Option<syn::Type> {
    if is_unit_type(ty) {
        return None;
    }

    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            match segment.ident.to_string().as_str() {
                "Vec" | "String" | "Bytes" => {
                    // These types typically need RangeCfg for length limits
                    return Some(syn::parse_quote!(::commonware_codec::RangeCfg));
                }
                "HashMap" | "BTreeMap" | "HashSet" | "BTreeSet" => {
                    // Maps and sets need RangeCfg for their size, plus their element configs
                    return Some(syn::parse_quote!(::commonware_codec::RangeCfg));
                }
                "Option" => {
                    // Option<T> uses T::Cfg
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            return infer_default_cfg_type(inner_ty);
                        }
                    }
                }
                // Primitive types don't need config
                "u8" | "u16" | "u32" | "u64" | "u128" | "usize" |
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize" |
                "f32" | "f64" | "bool" => {
                    return None;
                }
                _ => {}
            }
        }
    }

    // Default to None for types that don't need special config
    None
}

/// Build the overall Cfg type from field configurations.
fn build_cfg_type(field_configs: &[FieldConfig], field_types: &[&syn::Type]) -> syn::Type {
    let mut cfg_types = Vec::new();

    for (config, field_type) in field_configs.iter().zip(field_types.iter()) {
        // Skip unit types
        if is_unit_type(field_type) {
            continue;
        }

        let cfg_type = config
            .cfg_type
            .clone()
            .or_else(|| infer_default_cfg_type(field_type));

        if let Some(cfg_type) = cfg_type {
            cfg_types.push(cfg_type);
        }
    }

    match cfg_types.len() {
        0 => syn::parse_quote!(()),
        1 => cfg_types.into_iter().next().unwrap(),
        _ => {
            let tuple_elems = cfg_types
                .into_iter()
                .collect::<syn::punctuated::Punctuated<_, syn::Token![,]>>();
            syn::Type::Tuple(syn::TypeTuple {
                paren_token: syn::token::Paren::default(),
                elems: tuple_elems,
            })
        }
    }
}
