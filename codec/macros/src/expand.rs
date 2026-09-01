//! Code generation for the codec derives.

use crate::{
    codec_path,
    input::{Container, Data, Field, Style, Variant},
};
use proc_macro2::TokenStream;
use quote::{ToTokens, format_ident, quote};
use std::collections::HashSet;
use syn::{DeriveInput, Error, Generics, Ident, Result, WherePredicate, parse_quote};

pub fn write(input: &DeriveInput) -> Result<TokenStream> {
    let container = Container::parse(input)?;
    let codec = codec_path();
    let preds = predicates(&container, |field| {
        let ty = &field.ty;
        vec![parse_quote!(#ty: #codec::Write)]
    });
    let generics = bounded(&container.generics, preds);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let ident = &container.ident;

    let write_method = format_ident!("write");
    let bufs_method = format_ident!("write_bufs");
    let (buf, write_body, bufs_body) = match &container.data {
        Data::Struct(_, fields) => (
            buf_ident(!fields.is_empty()),
            struct_write_body(&codec, fields, &write_method),
            struct_write_body(&codec, fields, &bufs_method),
        ),
        Data::Enum(variants) => (
            buf_ident(true),
            enum_write_body(&codec, variants, &write_method)?,
            enum_write_body(&codec, variants, &bufs_method)?,
        ),
    };

    Ok(quote! {
        impl #impl_generics #codec::Write for #ident #ty_generics #where_clause {
            fn write(&self, #buf: &mut impl #codec::bytes::BufMut) {
                #write_body
            }

            fn write_bufs(&self, #buf: &mut impl #codec::BufsMut) {
                #bufs_body
            }
        }
    })
}

pub fn encode_size(input: &DeriveInput) -> Result<TokenStream> {
    let container = Container::parse(input)?;
    let codec = codec_path();
    let preds = predicates(&container, |field| {
        let ty = &field.ty;
        vec![parse_quote!(#ty: #codec::EncodeSize)]
    });
    let generics = bounded(&container.generics, preds);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let ident = &container.ident;

    let size_method = format_ident!("encode_size");
    let inline_method = format_ident!("encode_inline_size");
    let (size_body, inline_body) = match &container.data {
        Data::Struct(_, fields) => (
            struct_size_body(&codec, fields, &size_method),
            struct_size_body(&codec, fields, &inline_method),
        ),
        Data::Enum(variants) => (
            enum_size_body(&codec, variants, &size_method)?,
            enum_size_body(&codec, variants, &inline_method)?,
        ),
    };

    Ok(quote! {
        impl #impl_generics #codec::EncodeSize for #ident #ty_generics #where_clause {
            fn encode_size(&self) -> usize {
                #size_body
            }

            fn encode_inline_size(&self) -> usize {
                #inline_body
            }
        }
    })
}

pub fn fixed_size(input: &DeriveInput) -> Result<TokenStream> {
    let container = Container::parse(input)?;
    let fields = match &container.data {
        Data::Struct(_, fields) => fields,
        Data::Enum(_) => {
            return Err(Error::new_spanned(
                &container.ident,
                "cannot derive FixedSize for enums; implement it manually if variants are padded \
                 to a common size",
            ));
        }
    };
    let codec = codec_path();
    let preds = predicates(&container, |field| {
        let ty = &field.ty;
        vec![parse_quote!(#ty: #codec::FixedSize)]
    });
    let generics = bounded(&container.generics, preds);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let ident = &container.ident;

    let size = sum(fields.iter().map(|field| {
        let ty = &field.ty;
        quote!(<#ty as #codec::FixedSize>::SIZE)
    }));

    Ok(quote! {
        impl #impl_generics #codec::FixedSize for #ident #ty_generics #where_clause {
            const SIZE: usize = #size;
        }
    })
}

pub fn read(input: &DeriveInput) -> Result<TokenStream> {
    let container = Container::parse(input)?;
    let codec = codec_path();
    // A cfg field gets no predicates: an assumed `Ty: Read` bound would shadow the type's
    // impl and stop `<Ty as Read>::Cfg` from normalizing, which must happen for the caller's
    // config to thread through (and for an enum's variant cfg types to unify). The field's
    // type has to implement Read via the container's inherited bounds instead.
    let preds = predicates(&container, |field| {
        if field.cfg {
            return Vec::new();
        }
        let ty = &field.ty;
        vec![
            parse_quote!(#ty: #codec::Read),
            parse_quote!(<#ty as #codec::Read>::Cfg: #codec::IsUnit),
        ]
    });
    let generics = bounded(&container.generics, preds);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let ident = &container.ident;

    let cfg_ty = container.fields().find(|field| field.cfg).map_or_else(
        || quote!(()),
        |field| {
            let ty = &field.ty;
            quote!(<#ty as #codec::Read>::Cfg)
        },
    );
    let cfg = if container.fields().any(|field| field.cfg) {
        format_ident!("cfg")
    } else {
        format_ident!("_cfg")
    };

    let (buf, body) = match &container.data {
        Data::Struct(style, fields) => (
            buf_ident(!fields.is_empty()),
            struct_read_body(&codec, *style, fields, &cfg),
        ),
        Data::Enum(variants) => (buf_ident(true), enum_read_body(&codec, variants, &cfg)?),
    };

    Ok(quote! {
        impl #impl_generics #codec::Read for #ident #ty_generics #where_clause {
            type Cfg = #cfg_ty;

            fn read_cfg(
                #buf: &mut impl #codec::bytes::Buf,
                #cfg: &Self::Cfg,
            ) -> ::core::result::Result<Self, #codec::Error> {
                #body
            }
        }
    })
}

/// Extends the container's generics with the given predicates.
fn bounded(generics: &Generics, preds: Vec<WherePredicate>) -> Generics {
    let mut generics = generics.clone();
    if !preds.is_empty() {
        generics.make_where_clause().predicates.extend(preds);
    }
    generics
}

/// Collects deduplicated per-field predicates for fields that mention a container generic
/// parameter, unless `#[codec(bound = "...")]` replaces them.
fn predicates(
    container: &Container,
    per_field: impl Fn(&Field) -> Vec<WherePredicate>,
) -> Vec<WherePredicate> {
    if let Some(bound) = &container.bound {
        return bound.clone();
    }
    let mut seen = HashSet::new();
    let mut preds = Vec::new();
    for field in container.fields().filter(|field| field.generic) {
        for pred in per_field(field) {
            if seen.insert(pred.to_token_stream().to_string()) {
                preds.push(pred);
            }
        }
    }
    preds
}

/// Names the buffer parameter, underscored when the body never touches it.
fn buf_ident(used: bool) -> Ident {
    if used {
        format_ident!("buf")
    } else {
        format_ident!("_buf")
    }
}

/// Joins expressions with `+`, or `0` when there are none.
fn sum(exprs: impl IntoIterator<Item = TokenStream>) -> TokenStream {
    let mut exprs = exprs.into_iter();
    let Some(first) = exprs.next() else {
        return quote!(0);
    };
    quote!(#first #(+ #exprs)*)
}

/// Match pattern for a variant, binding each field to its hygiene-safe ident.
fn variant_pattern(variant: &Variant) -> TokenStream {
    let ident = &variant.ident;
    if variant.style == Style::Unit {
        return quote!(Self::#ident);
    }
    let members = variant.fields.iter().map(|field| &field.member);
    let bindings = variant.fields.iter().map(|field| &field.binding);
    quote!(Self::#ident { #(#members: #bindings),* })
}

/// Requires the variant's tag, rejecting untagged variants.
fn tag(variant: &Variant) -> Result<&syn::LitInt> {
    variant.tag.as_ref().ok_or_else(|| {
        Error::new_spanned(&variant.ident, "enum variants require #[codec(tag = N)]")
    })
}

fn struct_write_body(codec: &TokenStream, fields: &[Field], method: &Ident) -> TokenStream {
    let writes = fields.iter().map(|field| {
        let member = &field.member;
        quote!(#codec::Write::#method(&self.#member, buf);)
    });
    quote!(#(#writes)*)
}

fn enum_write_body(
    codec: &TokenStream,
    variants: &[Variant],
    method: &Ident,
) -> Result<TokenStream> {
    let arms = variants
        .iter()
        .map(|variant| {
            let tag = tag(variant)?;
            let pattern = variant_pattern(variant);
            let writes = variant.fields.iter().map(|field| {
                let binding = &field.binding;
                quote!(#codec::Write::#method(#binding, buf);)
            });
            Ok(quote! {
                #pattern => {
                    <u8 as #codec::Write>::write(&#tag, buf);
                    #(#writes)*
                }
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(quote! {
        match self {
            #(#arms)*
        }
    })
}

fn struct_size_body(codec: &TokenStream, fields: &[Field], method: &Ident) -> TokenStream {
    sum(fields.iter().map(|field| {
        let member = &field.member;
        quote!(#codec::EncodeSize::#method(&self.#member))
    }))
}

fn enum_size_body(
    codec: &TokenStream,
    variants: &[Variant],
    method: &Ident,
) -> Result<TokenStream> {
    let arms = variants
        .iter()
        .map(|variant| {
            tag(variant)?;
            let pattern = variant_pattern(variant);
            let size = sum(variant.fields.iter().map(|field| {
                let binding = &field.binding;
                quote!(#codec::EncodeSize::#method(#binding))
            }));
            Ok(quote!(#pattern => #size,))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(quote! {
        1 + match self {
            #(#arms)*
        }
    })
}

/// Read expression for one field: the `#[codec(cfg)]` field receives the caller's config,
/// every other field a unit-like default.
fn field_read(codec: &TokenStream, field: &Field, cfg: &Ident) -> TokenStream {
    let binding = &field.binding;
    let ty = &field.ty;
    if field.cfg {
        quote!(let #binding = <#ty as #codec::Read>::read_cfg(buf, #cfg)?;)
    } else {
        quote! {
            let #binding = <#ty as #codec::Read>::read_cfg(
                buf,
                &#codec::unit_cfg::<<#ty as #codec::Read>::Cfg>(),
            )?;
        }
    }
}

/// Constructor expression from the hygiene-safe bindings.
fn construct(prefix: TokenStream, style: Style, fields: &[Field]) -> TokenStream {
    if style == Style::Unit {
        return prefix;
    }
    let members = fields.iter().map(|field| &field.member);
    let bindings = fields.iter().map(|field| &field.binding);
    quote!(#prefix { #(#members: #bindings),* })
}

fn struct_read_body(
    codec: &TokenStream,
    style: Style,
    fields: &[Field],
    cfg: &Ident,
) -> TokenStream {
    let reads = fields.iter().map(|field| field_read(codec, field, cfg));
    let value = construct(quote!(Self), style, fields);
    quote! {
        #(#reads)*
        ::core::result::Result::Ok(#value)
    }
}

fn enum_read_body(codec: &TokenStream, variants: &[Variant], cfg: &Ident) -> Result<TokenStream> {
    let arms = variants
        .iter()
        .map(|variant| {
            let tag = tag(variant)?;
            let ident = &variant.ident;
            let reads = variant
                .fields
                .iter()
                .map(|field| field_read(codec, field, cfg));
            let value = construct(quote!(Self::#ident), variant.style, &variant.fields);
            Ok(quote! {
                #tag => {
                    #(#reads)*
                    ::core::result::Result::Ok(#value)
                }
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(quote! {
        let tag = <u8 as #codec::Read>::read_cfg(buf, &())?;
        match tag {
            #(#arms)*
            _ => ::core::result::Result::Err(#codec::Error::InvalidEnum(tag)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(result: Result<TokenStream>) -> String {
        result.unwrap_err().to_string()
    }

    #[test]
    fn test_missing_tag() {
        let input: DeriveInput = parse_quote! {
            enum E {
                A(u8),
            }
        };
        assert!(err(write(&input)).contains("require #[codec(tag = N)]"));
        assert!(err(encode_size(&input)).contains("require #[codec(tag = N)]"));
        assert!(err(read(&input)).contains("require #[codec(tag = N)]"));
    }

    #[test]
    fn test_duplicate_tag() {
        let input: DeriveInput = parse_quote! {
            enum E {
                #[codec(tag = 1)]
                A(u8),
                #[codec(tag = 1)]
                B(u8),
            }
        };
        assert!(err(write(&input)).contains("duplicate tag value"));
    }

    #[test]
    fn test_tag_out_of_range() {
        let input: DeriveInput = parse_quote! {
            enum E {
                #[codec(tag = 300)]
                A(u8),
            }
        };
        assert!(err(write(&input)).contains("number too large"));
    }

    #[test]
    fn test_two_cfg_fields() {
        let input: DeriveInput = parse_quote! {
            struct S {
                #[codec(cfg)]
                a: u8,
                #[codec(cfg)]
                b: u8,
            }
        };
        assert!(err(read(&input)).contains("at most one field"));
    }

    #[test]
    fn test_fixed_size_enum() {
        let input: DeriveInput = parse_quote! {
            enum E {
                #[codec(tag = 0)]
                A(u8),
            }
        };
        assert!(err(fixed_size(&input)).contains("cannot derive FixedSize for enums"));
    }

    #[test]
    fn test_empty_enum() {
        let input: DeriveInput = parse_quote! {
            enum E {}
        };
        assert!(err(write(&input)).contains("empty enums"));
    }

    #[test]
    fn test_union() {
        let input: DeriveInput = parse_quote! {
            union U {
                a: u8,
            }
        };
        assert!(err(write(&input)).contains("unions"));
    }

    #[test]
    fn test_misplaced_attributes() {
        let tag_on_field: DeriveInput = parse_quote! {
            struct S {
                #[codec(tag = 0)]
                a: u8,
            }
        };
        assert!(err(write(&tag_on_field)).contains("not valid on a field"));

        let cfg_on_container: DeriveInput = parse_quote! {
            #[codec(cfg)]
            struct S {
                a: u8,
            }
        };
        assert!(err(write(&cfg_on_container)).contains("not valid on a container"));

        let bound_on_variant: DeriveInput = parse_quote! {
            enum E {
                #[codec(tag = 0, bound = "")]
                A(u8),
            }
        };
        assert!(err(write(&bound_on_variant)).contains("not valid on a variant"));
    }

    #[test]
    fn test_bound_override() {
        let input: DeriveInput = parse_quote! {
            #[codec(bound = "T: Clone")]
            struct S<T> {
                a: T,
            }
        };
        let expanded = write(&input).unwrap().to_string();
        assert!(expanded.contains("T : Clone"));
        assert!(!expanded.contains("T : :: commonware_codec :: Write"));
    }
}
