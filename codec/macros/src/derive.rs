use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Error, Expr, Fields, Ident, Member, Result, Type};

mod generics;
mod options;
#[cfg(test)]
mod tests;

use options::{Options, Place};

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Write,
    Read,
    EncodeSize,
    FixedSize,
    Encode,
}

struct Field<'a> {
    ty: &'a Type,
    member: Member,
    binding: Ident,
    options: Options,
}

struct Shape<'a> {
    path: TokenStream,
    fields: Vec<Field<'a>>,
    named: bool,
    unit: bool,
    tag: Option<u8>,
}

impl<'a> Shape<'a> {
    fn new(path: TokenStream, fields: &'a Fields, tag: Option<u8>) -> Result<Self> {
        let fields_parsed = fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                Ok(Field {
                    ty: &field.ty,
                    member: field
                        .ident
                        .clone()
                        .map(Member::Named)
                        .unwrap_or_else(|| Member::Unnamed(index.into())),
                    binding: format_ident!("__codec_field_{index}", span = Span::mixed_site()),
                    options: Options::parse(&field.attrs, Place::Field)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            path,
            fields: fields_parsed,
            named: matches!(fields, Fields::Named(_)),
            unit: matches!(fields, Fields::Unit),
            tag,
        })
    }

    fn pattern(&self) -> TokenStream {
        let path = &self.path;
        let bindings = self.fields.iter().map(|f| &f.binding);
        if self.unit {
            quote!(#path)
        } else if self.named {
            let members = self.fields.iter().map(|f| &f.member);
            quote!(#path { #(#members: #bindings),* })
        } else {
            quote!(#path (#(#bindings),*))
        }
    }
}

pub fn expand(mut input: DeriveInput, kind: Kind) -> Result<TokenStream> {
    if kind == Kind::Encode {
        let write = expand(input.clone(), Kind::Write)?;
        let size = expand(input, Kind::EncodeSize)?;
        return Ok(quote!(#write #size));
    }
    let mut options = Options::parse(&input.attrs, Place::Container)?;
    if let Some(invalid_tag) = &options.invalid_tag
        && !matches!(input.data, Data::Enum(_))
    {
        return Err(Error::new_spanned(
            invalid_tag,
            "invalid_tag requires an enum",
        ));
    }
    generics::rename_consts(&mut input, kind, &mut options);
    let shapes = match &input.data {
        Data::Struct(data) => vec![Shape::new(quote!(Self), &data.fields, None)?],
        Data::Enum(data) => {
            if data.variants.is_empty() || data.variants.len() > 256 {
                return Err(Error::new_spanned(
                    &input,
                    "codec enums require 1 through 256 variants",
                ));
            }
            let mut tags = [false; 256];
            data.variants
                .iter()
                .enumerate()
                .map(|(index, variant)| {
                    let attrs = Options::parse(&variant.attrs, Place::Variant)?;
                    let tag = attrs.tag.unwrap_or(index as u8);
                    if tags[tag as usize] {
                        return Err(Error::new_spanned(variant, "duplicate codec enum tag"));
                    }
                    tags[tag as usize] = true;
                    let name = &variant.ident;
                    Shape::new(quote!(Self::#name), &variant.fields, Some(tag))
                })
                .collect::<Result<Vec<_>>>()?
        }
        Data::Union(_) => {
            return Err(Error::new_spanned(
                &input,
                "codec derives do not support unions",
            ));
        }
    };
    if kind == Kind::FixedSize
        && (options.encode_size.is_some()
            || shapes
                .iter()
                .flat_map(|s| &s.fields)
                .any(|f| f.options.encode_with.is_some() || f.options.encode_size.is_some()))
    {
        return Err(Error::new_spanned(
            &input,
            "FixedSize does not support custom encoding or encode_size attributes",
        ));
    }
    if kind == Kind::EncodeSize && options.encode_size.is_none() {
        for field in shapes.iter().flat_map(|s| &s.fields) {
            if field.options.encode_with.is_some() && field.options.encode_size.is_none() {
                return Err(Error::new_spanned(
                    field.ty,
                    "custom encoding requires a field or container encode_size attribute",
                ));
            }
        }
    }
    let codec = crate::codec_path();
    Ok(implementation(&input, &options, &shapes, kind, &codec))
}

fn implementation(
    input: &DeriveInput,
    options: &Options,
    shapes: &[Shape<'_>],
    kind: Kind,
    codec: &TokenStream,
) -> TokenStream {
    let name = &input.ident;
    let (generics, cfg_ty) = generics::for_impl(input, options, shapes, kind, codec);
    let (impl_generics, _, where_clause) = generics.split_for_impl();
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let (trait_name, body) = match kind {
        Kind::Write => {
            let write = write_body(shapes, codec, false);
            let bufs = if options.encode_size.is_some() {
                quote!(<Self as #codec::Write>::write(self, buf);)
            } else {
                write_body(shapes, codec, true)
            };
            (
                quote!(Write),
                quote! {
                    #[inline]
                    fn write(&self, buf: &mut impl #codec::__BufMut) { #write }
                    #[inline]
                    fn write_bufs(&self, buf: &mut impl #codec::BufsMut) { #bufs }
                },
            )
        }
        Kind::Read => {
            let arms = shapes.iter().map(|shape| {
                let reads = shape.fields.iter().map(|field| {
                    let ty = field.ty;
                    let binding = &field.binding;
                    let cfg = field
                        .options
                        .cfg
                        .as_ref()
                        .map_or_else(|| quote!(cfg), |expr| quote!(#expr));
                    let read = match &field.options.read_with {
                        Some(Expr::Block(block)) => {
                            let attrs = &block.attrs;
                            let label = &block.label;
                            let statements = &block.block.stmts;
                            quote!(#(#attrs)* #label { let cfg = #cfg; let buf = &mut *buf; #(#statements)* })
                        }
                        Some(expr) => quote!((#expr)(&mut *buf, #cfg)),
                        None => quote!(<#ty as #codec::Read>::read_cfg(buf, #cfg)),
                    };
                    quote! {
                        let #binding: ::core::result::Result<#ty, #codec::Error> = #read;
                        let #binding: #ty = #binding?;
                    }
                });
                let constructor = shape.pattern();
                let body = quote!({ #(#reads)* ::core::result::Result::Ok(#constructor) });
                match shape.tag {
                    Some(tag) => quote!(#tag => #body),
                    None => body,
                }
            });
            let body = if shapes[0].tag.is_some() {
                let invalid_tag = match &options.invalid_tag {
                    Some(Expr::Block(block)) => quote!(#block),
                    Some(expr) => quote!((#expr)(tag)),
                    None => quote!(#codec::Error::InvalidEnum(tag)),
                };
                quote! { match <::core::primitive::u8 as #codec::Read>::read_cfg(buf, &())? { #(#arms,)* tag => { let _ = tag; let tag: #codec::Error = #invalid_tag; ::core::result::Result::Err(tag) } } }
            } else {
                quote!(#(#arms)*)
            };
            (
                quote!(Read),
                quote! {
                    type Cfg = #cfg_ty;
                    #[inline]
                    fn read_cfg(buf: &mut impl #codec::Buf, cfg: &Self::Cfg) -> ::core::result::Result<Self, #codec::Error> { #body }
                },
            )
        }
        Kind::EncodeSize => {
            let size = size_body(shapes, options, codec, false);
            let inline = size_body(shapes, options, codec, true);
            (
                quote!(EncodeSize),
                quote! {
                    #[inline]
                    fn encode_size(&self) -> ::core::primitive::usize { #size }
                    #[inline]
                    fn encode_inline_size(&self) -> ::core::primitive::usize { #inline }
                },
            )
        }
        Kind::FixedSize => {
            let sizes: Vec<_> = shapes
                .iter()
                .map(|shape| {
                    let prefix = usize::from(shape.tag.is_some());
                    let types = shape.fields.iter().map(|f| f.ty);
                    quote!(#prefix #(+ <#types as #codec::FixedSize>::SIZE)*)
                })
                .collect();
            let first = &sizes[0];
            let checks = sizes.iter().skip(1).map(|size| quote!(::core::assert!((#first) == (#size), "codec enum variants must have equal fixed sizes");));
            (
                quote!(FixedSize),
                quote!(const SIZE: ::core::primitive::usize = { #(#checks)* #first };),
            )
        }
        Kind::Encode => unreachable!(),
    };
    // Generic parameter names are linted on the original type declaration.
    quote!(#[allow(non_upper_case_globals)] impl #impl_generics #codec::#trait_name for #name #ty_generics #where_clause { #body })
}

fn write_body(shapes: &[Shape<'_>], codec: &TokenStream, bufs: bool) -> TokenStream {
    let method = if bufs {
        quote!(write_bufs)
    } else {
        quote!(write)
    };
    let arms = shapes.iter().map(|shape| {
        let pattern = shape.pattern();
        let tag = shape
            .tag
            .map(|tag| quote!(<::core::primitive::u8 as #codec::Write>::#method(&#tag, buf);));
        let fields = shape.fields.iter().map(|field| {
            let binding = &field.binding;
            let ty = field.ty;
            match &field.options.encode_with {
                Some(Expr::Block(block)) => {
                    quote!({ let value = #binding; let buf = &mut *buf; #block; })
                }
                Some(expr) => quote!({ (#expr)(#binding, &mut *buf); }),
                None if field.options.encode_size.is_some() => {
                    quote!(<#ty as #codec::Write>::write(#binding, buf);)
                }
                None => quote!(<#ty as #codec::Write>::#method(#binding, buf);),
            }
        });
        quote!(#pattern => { #tag #(#fields)* })
    });
    quote!(match self { #(#arms),* })
}

fn size_body(
    shapes: &[Shape<'_>],
    options: &Options,
    codec: &TokenStream,
    inline: bool,
) -> TokenStream {
    if let Some(expr) = &options.encode_size {
        return quote!(#expr);
    }
    let method = if inline {
        quote!(encode_inline_size)
    } else {
        quote!(encode_size)
    };
    let arms = shapes.iter().map(|shape| {
        let pattern = shape.pattern();
        let prefix = usize::from(shape.tag.is_some());
        let sizes = shape.fields.iter().map(|field| {
            let binding = &field.binding;
            let ty = field.ty;
            field.options.encode_size.as_ref().map_or_else(
                || quote!(<#ty as #codec::EncodeSize>::#method(#binding)),
                |expr| quote!({ let value = #binding; #expr }),
            )
        });
        quote!(#pattern => #prefix #(+ #sizes)*)
    });
    quote!(match self { #(#arms),* })
}
