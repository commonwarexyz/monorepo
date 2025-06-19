//! Derive macros for commonware-codec traits.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, Data, DeriveInput, Field, Fields, FieldsNamed, FieldsUnnamed, Index, Meta,
};

/// Derive macro for the `Read` trait.
///
/// Automatically implements `Read` for structs and enums where all fields implement `Read`.
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
/// You can also use `#[config(default)]` to use the `Default::default()` value for that field's config type.
/// The overall `Cfg` type is built as an ordered tuple of field configs, with optimizations:
/// - Unit type `()` fields are ignored
/// - Fields with `#[config(default)]` are ignored (they use `Default::default()` at runtime)
/// - Single config field uses the type directly (not wrapped in tuple)
/// - Fields without explicit `#[config]` use inferred defaults (e.g., `RangeCfg` for `Vec`, `String`)
///
/// # Enum Support
///
/// Enums are encoded with a u8 discriminant (0, 1, 2, ...) followed by the variant data.
/// - Maximum 256 variants supported
/// - Unit variants encode as just the discriminant
/// - Data variants encode discriminant + field data
/// - Enum `Cfg` type is currently always `()` for simplicity
///
/// # Example
///
/// ```
/// use commonware_codec::{extensions::ReadExt, RangeCfg};
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
/// enum Message {
///     Ping,
///     Pong(u32),
///     Data { id: u16, count: u32 },
/// }
///
/// #[derive(Read)]
/// struct SimpleStruct {
///     id: u32,
///     value: u16,
/// }
///
/// // Read is now implemented for all types
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
/// Automatically implements `Write` for structs and enums where all fields implement `Write`.
///
/// # Codec Helper Attributes
///
/// You can use the `#[codec(varint)]` helper attribute to enable variable-length encoding for integer fields.
/// The wrapper type (UInt for unsigned, SInt for signed) is automatically inferred from the field type.
///
/// Supported types: u16, u32, u64, u128, i16, i32, i64, i128
///
/// # Enum Support
///
/// Enums are encoded with a u8 discriminant (0, 1, 2, ...) followed by the variant data.
/// - Maximum 256 variants supported
/// - Unit variants encode as just the discriminant
/// - Data variants encode discriminant + field data
///
/// # Example
///
/// ```
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
/// #[derive(Write)]
/// enum Message {
///     Ping,
///     Pong(u32),
///     Data { id: u16, payload: Vec<u8> },
/// }
///
/// // Write is now implemented for all types
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
/// Automatically implements `EncodeSize` for structs and enums where all fields implement `EncodeSize`.
///
/// # Codec Helper Attributes
///
/// You can use the `#[codec(varint)]` helper attribute to enable variable-length encoding for integer fields.
/// The wrapper type (UInt for unsigned, SInt for signed) is automatically inferred from the field type.
///
/// Supported types: u16, u32, u64, u128, i16, i32, i64, i128
///
/// # Enum Support
///
/// Enums return size as 1 (discriminant) + size of variant data.
/// - Unit variants return size 1
/// - Data variants return 1 + sum of field sizes
///
/// # Example
///
/// ```
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
/// #[derive(EncodeSize)]
/// enum Message {
///     Ping,           // Size: 1
///     Pong(u32),      // Size: 1 + 4 = 5
///     Data { id: u16, payload: Vec<u8> },  // Size: 1 + 2 + payload.encode_size()
/// }
///
/// // EncodeSize is now implemented for all types
/// ```
#[proc_macro_derive(EncodeSize, attributes(codec, config))]
pub fn derive_encode_size(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_encode_size(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive macro for the `FixedSize` trait.
///
/// Automatically implements `FixedSize` for structs where all fields implement `FixedSize`.
/// The total `SIZE` is calculated as the sum of all field sizes.
///
/// # Requirements
///
/// - All fields must implement `FixedSize`
/// - Only works with structs (not enums or unions)
/// - Does not support generic types currently
///
/// # Codec Helper Attributes
///
/// The `#[codec(varint)]` attribute is not supported for `FixedSize` since varint encoding
/// produces variable-length output. Using this attribute will result in a compile error.
///
/// # Example
///
/// ```
/// use commonware_codec_derive::FixedSize;
///
/// #[derive(FixedSize)]
/// struct Point {
///     x: u32,
///     y: u32,
/// }
///
/// // SIZE = 4 + 4 = 8 bytes
///
/// #[derive(FixedSize)]
/// struct Header {
///     magic: [u8; 4],
///     version: u16,
///     flags: u8,
/// }
///
/// // SIZE = 4 + 2 + 1 = 7 bytes
///
/// #[derive(FixedSize)]
/// struct Tuple(u64, bool, u16);
///
/// // SIZE = 8 + 1 + 2 = 11 bytes
///
/// // FixedSize is now implemented for all types
/// ```
#[proc_macro_derive(FixedSize, attributes(codec))]
pub fn derive_fixed_size(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_fixed_size(&input)
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
        Data::Enum(data) => expand_read_enum_with_cfg(data)?,
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
        Data::Enum(data) => expand_write_enum(data)?,
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
        Data::Enum(data) => expand_encode_size_enum(data)?,
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

            // If this field uses default, read with Default::default() config
            if config.use_default {
                return Ok(generate_field_read_with_cfg(
                    field_name,
                    &config.wrapper,
                    quote! { &::std::default::Default::default() },
                ));
            }

            // Determine if this field has a config in the cfg tuple
            let has_cfg = config
                .cfg_type
                .clone()
                .or_else(|| infer_default_cfg_type(&field.ty))
                .is_some();

            let read_code = if has_cfg {
                match &cfg_type {
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
                        // This shouldn't happen in well-formed code, but fallback to unit config
                        generate_field_read_with_cfg(field_name, &config.wrapper, quote! { &() })
                    }
                }
            } else {
                // No config needed, use unit config
                generate_field_read_with_cfg(field_name, &config.wrapper, quote! { &() })
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

            // If this field uses default, read with Default::default() config
            if config.use_default {
                return Ok(generate_field_read_with_cfg(
                    &field_name,
                    &config.wrapper,
                    quote! { &::std::default::Default::default() },
                ));
            }

            // Determine if this field has a config in the cfg tuple
            let has_cfg = config
                .cfg_type
                .clone()
                .or_else(|| infer_default_cfg_type(&field.ty))
                .is_some();

            let read_code = if has_cfg {
                match &cfg_type {
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
                        // This shouldn't happen in well-formed code, but fallback to unit config
                        generate_field_read_with_cfg(&field_name, &config.wrapper, quote! { &() })
                    }
                }
            } else {
                // No config needed, use unit config
                generate_field_read_with_cfg(&field_name, &config.wrapper, quote! { &() })
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
    use_default: bool, // If true, use Default::default() for this field's config
}

/// Parse all relevant attributes on a field to determine configuration.
fn parse_field_attributes(field: &Field) -> syn::Result<FieldConfig> {
    let mut wrapper = CodecWrapper::None;
    let mut cfg_type = None;
    let mut use_default = false;

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
                    // Parse the content inside config(...)
                    // First try to parse as syn::Type, then check if it's the "default" identifier
                    let content = meta_list.tokens.clone();
                    if let Ok(ident) = syn::parse2::<syn::Ident>(content.clone()) {
                        if ident == "default" {
                            use_default = true;
                        } else {
                            // It's an identifier but not "default", treat as a path type
                            cfg_type = Some(syn::parse2::<syn::Type>(content)?);
                        }
                    } else {
                        // Parse as a general type (Path, Tuple, etc.)
                        cfg_type = Some(syn::parse2::<syn::Type>(content)?);
                    }
                }
                Meta::Path(_) | Meta::NameValue(_) => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "Use #[config(ConfigType)] or #[config(default)] to specify the config for this field",
                    ));
                }
            }
        }
    }

    Ok(FieldConfig {
        wrapper,
        cfg_type,
        use_default,
    })
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
            (#field_access).write(buf);
        },
        CodecWrapper::UInt => quote! {
            ::commonware_codec::varint::UInt(#field_access).write(buf);
        },
        CodecWrapper::SInt => quote! {
            ::commonware_codec::varint::SInt(#field_access).write(buf);
        },
    }
}

/// Generate appropriate field access for encoding size, based on codec wrapper.
fn generate_field_encode_size(field_access: TokenStream2, wrapper: &CodecWrapper) -> TokenStream2 {
    match wrapper {
        CodecWrapper::None => quote! {
            (#field_access).encode_size()
        },
        CodecWrapper::UInt => quote! {
            ::commonware_codec::varint::UInt(#field_access).encode_size()
        },
        CodecWrapper::SInt => quote! {
            ::commonware_codec::varint::SInt(#field_access).encode_size()
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
                "Vec" => {
                    // Vec<T> has Cfg = (RangeCfg, T::Cfg)
                    // For Vec<u8>, this becomes (RangeCfg, ())
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            let inner_cfg = infer_default_cfg_type(inner_ty)
                                .unwrap_or_else(|| syn::parse_quote!(()));
                            return Some(
                                syn::parse_quote!((::commonware_codec::RangeCfg, #inner_cfg)),
                            );
                        }
                    }
                    // Fallback for Vec without type args (shouldn't happen in valid code)
                    return Some(syn::parse_quote!((::commonware_codec::RangeCfg, ())));
                }
                "String" | "Bytes" => {
                    // These types use RangeCfg directly
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
                "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64"
                | "i128" | "isize" | "f32" | "f64" | "bool" => {
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

        // Skip fields that use default (they don't contribute to the cfg tuple)
        if config.use_default {
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

// ---------- Enum Support Functions ----------

fn expand_read_enum_with_cfg(data: &syn::DataEnum) -> syn::Result<(TokenStream2, syn::Type)> {
    if data.variants.len() > 256 {
        return Err(syn::Error::new_spanned(
            data.variants.first(),
            "Enum cannot have more than 256 variants (u8 discriminant limit)",
        ));
    }

    // For simplicity, enum configurations are always unit type () for now
    // This can be enhanced later if needed for complex enum variants
    let cfg_type = syn::parse_quote!(());

    let match_arms = data
        .variants
        .iter()
        .enumerate()
        .map(|(index, variant)| {
            let variant_name = &variant.ident;
            let discriminant = index as u8;

            match &variant.fields {
                Fields::Unit => Ok(quote! {
                    #discriminant => Ok(Self::#variant_name),
                }),
                Fields::Unnamed(fields) => {
                    let field_reads = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, field)| {
                            let field_name = format_ident!("field_{}", i);
                            let field_config = parse_field_attributes(field)?;

                            if is_unit_type(&field.ty) {
                                Ok(quote! { let #field_name = (); })
                            } else {
                                Ok(generate_field_read_with_cfg(
                                    &field_name,
                                    &field_config.wrapper,
                                    quote! { &() },
                                ))
                            }
                        })
                        .collect::<syn::Result<Vec<_>>>()?;

                    let field_names =
                        (0..fields.unnamed.len()).map(|i| format_ident!("field_{}", i));

                    Ok(quote! {
                        #discriminant => {
                            #(#field_reads)*
                            Ok(Self::#variant_name(#(#field_names,)*))
                        },
                    })
                }
                Fields::Named(fields) => {
                    let field_reads = fields
                        .named
                        .iter()
                        .map(|field| {
                            let field_name = field.ident.as_ref().unwrap();
                            let field_config = parse_field_attributes(field)?;

                            if is_unit_type(&field.ty) {
                                Ok(quote! { let #field_name = (); })
                            } else {
                                Ok(generate_field_read_with_cfg(
                                    field_name,
                                    &field_config.wrapper,
                                    quote! { &() },
                                ))
                            }
                        })
                        .collect::<syn::Result<Vec<_>>>()?;

                    let field_names = fields.named.iter().map(|field| &field.ident);

                    Ok(quote! {
                        #discriminant => {
                            #(#field_reads)*
                            Ok(Self::#variant_name { #(#field_names,)* })
                        },
                    })
                }
            }
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let read_impl = quote! {
        let discriminant = u8::read(buf)?;
        match discriminant {
            #(#match_arms)*
            invalid => Err(::commonware_codec::Error::InvalidEnum(invalid)),
        }
    };

    Ok((read_impl, cfg_type))
}

fn expand_write_enum(data: &syn::DataEnum) -> syn::Result<TokenStream2> {
    if data.variants.len() > 256 {
        return Err(syn::Error::new_spanned(
            data.variants.first(),
            "Enum cannot have more than 256 variants (u8 discriminant limit)",
        ));
    }

    let match_arms = data
        .variants
        .iter()
        .enumerate()
        .map(|(index, variant)| {
            let variant_name = &variant.ident;
            let discriminant = index as u8;

            match &variant.fields {
                Fields::Unit => Ok(quote! {
                    Self::#variant_name => {
                        ::bytes::BufMut::put_u8(buf, #discriminant);
                    }
                }),
                Fields::Unnamed(fields) => {
                    let field_patterns =
                        (0..fields.unnamed.len()).map(|i| format_ident!("field_{}", i));
                    let field_writes = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, field)| {
                            let field_name = format_ident!("field_{}", i);
                            let wrapper = parse_codec_attributes(field)?;
                            Ok(generate_field_write(quote! { *#field_name }, &wrapper))
                        })
                        .collect::<syn::Result<Vec<_>>>()?;

                    Ok(quote! {
                        Self::#variant_name(#(#field_patterns,)*) => {
                            ::bytes::BufMut::put_u8(buf, #discriminant);
                            #(#field_writes)*
                        }
                    })
                }
                Fields::Named(fields) => {
                    let field_names = fields.named.iter().map(|field| &field.ident);
                    let field_writes = fields
                        .named
                        .iter()
                        .map(|field| {
                            let field_name = &field.ident;
                            let wrapper = parse_codec_attributes(field)?;
                            Ok(generate_field_write(quote! { *#field_name }, &wrapper))
                        })
                        .collect::<syn::Result<Vec<_>>>()?;

                    Ok(quote! {
                        Self::#variant_name { #(#field_names,)* } => {
                            ::bytes::BufMut::put_u8(buf, #discriminant);
                            #(#field_writes)*
                        }
                    })
                }
            }
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        match self {
            #(#match_arms)*
        }
    })
}

fn expand_fixed_size(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;

    // Generate bounds for generic type parameters
    let mut generics = input.generics.clone();

    // Add FixedSize bound to each type parameter
    for param in &mut generics.params {
        if let syn::GenericParam::Type(type_param) = param {
            type_param
                .bounds
                .push(syn::parse_quote!(::commonware_codec::FixedSize));
        }
    }

    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    let size_calculation = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => expand_fixed_size_named_fields(fields)?,
            Fields::Unnamed(fields) => expand_fixed_size_unnamed_fields(fields)?,
            Fields::Unit => quote! { 0 },
        },
        Data::Enum(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "FixedSize derive macro does not support enums - enums have variable size due to discriminant",
            ));
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "FixedSize derive macro does not support unions",
            ));
        }
    };

    Ok(quote! {
        impl #impl_generics ::commonware_codec::FixedSize for #name #type_generics #where_clause {
            const SIZE: usize = #size_calculation;
        }
    })
}

fn expand_fixed_size_named_fields(fields: &FieldsNamed) -> syn::Result<TokenStream2> {
    if fields.named.is_empty() {
        return Ok(quote! { 0 });
    }

    let field_sizes = fields
        .named
        .iter()
        .map(|field| {
            // Check for varint attributes - not allowed for FixedSize
            if let Some(attr) = field.attrs.iter().find(|attr| attr.path().is_ident("codec")) {
                return Err(syn::Error::new_spanned(
                    attr,
                    "FixedSize derive macro does not support #[codec] attributes - varint encoding produces variable-length output",
                ));
            }

            let field_type = &field.ty;
            Ok(quote! { <#field_type as ::commonware_codec::FixedSize>::SIZE })
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        0 #(+ #field_sizes)*
    })
}

fn expand_fixed_size_unnamed_fields(fields: &FieldsUnnamed) -> syn::Result<TokenStream2> {
    if fields.unnamed.is_empty() {
        return Ok(quote! { 0 });
    }

    let field_sizes = fields
        .unnamed
        .iter()
        .map(|field| {
            // Check for varint attributes - not allowed for FixedSize
            if let Some(attr) = field.attrs.iter().find(|attr| attr.path().is_ident("codec")) {
                return Err(syn::Error::new_spanned(
                    attr,
                    "FixedSize derive macro does not support #[codec] attributes - varint encoding produces variable-length output",
                ));
            }

            let field_type = &field.ty;
            Ok(quote! { <#field_type as ::commonware_codec::FixedSize>::SIZE })
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        0 #(+ #field_sizes)*
    })
}

fn expand_encode_size_enum(data: &syn::DataEnum) -> syn::Result<TokenStream2> {
    if data.variants.len() > 256 {
        return Err(syn::Error::new_spanned(
            data.variants.first(),
            "Enum cannot have more than 256 variants (u8 discriminant limit)",
        ));
    }

    let match_arms = data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            match &variant.fields {
                Fields::Unit => Ok(quote! {
                    Self::#variant_name => 1,
                }),
                Fields::Unnamed(fields) => {
                    let field_patterns =
                        (0..fields.unnamed.len()).map(|i| format_ident!("field_{}", i));
                    let field_sizes = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, field)| {
                            let field_name = format_ident!("field_{}", i);
                            let wrapper = parse_codec_attributes(field)?;
                            Ok(generate_field_encode_size(
                                quote! { *#field_name },
                                &wrapper,
                            ))
                        })
                        .collect::<syn::Result<Vec<_>>>()?;

                    Ok(quote! {
                        Self::#variant_name(#(#field_patterns,)*) => {
                            1 #(+ #field_sizes)*
                        },
                    })
                }
                Fields::Named(fields) => {
                    let field_names = fields.named.iter().map(|field| &field.ident);
                    let field_sizes = fields
                        .named
                        .iter()
                        .map(|field| {
                            let field_name = &field.ident;
                            let wrapper = parse_codec_attributes(field)?;
                            Ok(generate_field_encode_size(
                                quote! { *#field_name },
                                &wrapper,
                            ))
                        })
                        .collect::<syn::Result<Vec<_>>>()?;

                    Ok(quote! {
                        Self::#variant_name { #(#field_names,)* } => {
                            1 #(+ #field_sizes)*
                        },
                    })
                }
            }
        })
        .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        match self {
            #(#match_arms)*
        }
    })
}
