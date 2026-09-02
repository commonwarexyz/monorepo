//! Parsed model and attribute-grammar validation for the codec derives.

use proc_macro2::{Span, TokenTree};
use quote::{ToTokens, format_ident};
use std::collections::HashSet;
use syn::{
    Data as SynData, DeriveInput, Error, Fields, Generics, Ident, LitInt, LitStr, Member, Result,
    Token, Type, WherePredicate, punctuated::Punctuated, spanned::Spanned,
};

/// A container (struct or enum) with validated `#[codec(...)]` attributes.
pub struct Container {
    pub ident: Ident,
    pub generics: Generics,
    /// Predicates from `#[codec(bound = "...")]`, replacing auto-generated ones when present.
    pub bound: Option<Vec<WherePredicate>>,
    pub data: Data,
}

pub enum Data {
    Struct(Style, Vec<Field>),
    Enum(Vec<Variant>),
}

/// Field arrangement of a struct or enum variant.
#[derive(Clone, Copy, PartialEq)]
pub enum Style {
    Named,
    Unnamed,
    Unit,
}

pub struct Variant {
    pub ident: Ident,
    /// Tag literal from `#[codec(tag = N)]`, validated as `u8`. Demanded lazily so that
    /// `derive(FixedSize)` on an enum reports the enum rejection instead of a missing tag.
    pub tag: Option<LitInt>,
    pub style: Style,
    pub fields: Vec<Field>,
}

pub struct Field {
    pub member: Member,
    /// Hygiene-safe binding used in enum match arms and read bodies.
    pub binding: Ident,
    pub ty: Type,
    /// Span of a `#[codec(cfg)]` marker: this field's `Read::Cfg` is the container's `Cfg`.
    pub cfg: Option<Span>,
    /// The type mentions a container type or const parameter, so it needs a predicate.
    pub generic: bool,
}

impl Container {
    pub fn parse(input: &DeriveInput) -> Result<Self> {
        let mut bound = None;
        for attr in &input.attrs {
            if !attr.path().is_ident("codec") {
                continue;
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("bound") {
                    let lit: LitStr = meta.value()?.parse()?;
                    if bound.is_some() {
                        return Err(Error::new_spanned(&lit, "duplicate `bound` attribute"));
                    }
                    let predicates =
                        lit.parse_with(Punctuated::<WherePredicate, Token![,]>::parse_terminated)?;
                    bound = Some(predicates.into_iter().collect());
                    Ok(())
                } else if meta.path.is_ident("tag") || meta.path.is_ident("cfg") {
                    Err(meta.error("attribute is not valid on a container"))
                } else {
                    Err(meta.error("expected `bound = \"...\"`"))
                }
            })?;
        }

        let params = param_idents(&input.generics);
        let data = match &input.data {
            SynData::Struct(data) => {
                let (style, fields) = parse_fields(&data.fields, &params)?;
                check_single_cfg(&fields)?;
                Data::Struct(style, fields)
            }
            SynData::Enum(data) => {
                if data.variants.is_empty() {
                    return Err(Error::new_spanned(
                        &input.ident,
                        "cannot derive codec traits for empty enums",
                    ));
                }
                let mut seen = HashSet::new();
                let mut variants = Vec::with_capacity(data.variants.len());
                for variant in &data.variants {
                    variants.push(parse_variant(variant, &params, &mut seen)?);
                }
                Data::Enum(variants)
            }
            SynData::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "cannot derive codec traits for unions",
                ));
            }
        };

        Ok(Self {
            ident: input.ident.clone(),
            generics: input.generics.clone(),
            bound,
            data,
        })
    }

    /// Returns every field of the container in declaration order.
    pub fn fields(&self) -> impl Iterator<Item = &Field> {
        let (struct_fields, variants) = match &self.data {
            Data::Struct(_, fields) => (Some(fields.iter()), None),
            Data::Enum(variants) => (None, Some(variants.iter().flat_map(|v| v.fields.iter()))),
        };
        struct_fields
            .into_iter()
            .flatten()
            .chain(variants.into_iter().flatten())
    }
}

fn parse_variant(
    variant: &syn::Variant,
    params: &HashSet<String>,
    seen: &mut HashSet<u8>,
) -> Result<Variant> {
    if let Some((_, discriminant)) = &variant.discriminant {
        return Err(Error::new_spanned(
            discriminant,
            "explicit discriminants play no role in encoding; the wire tag is #[codec(tag = N)]",
        ));
    }
    let mut tag = None;
    for attr in &variant.attrs {
        if !attr.path().is_ident("codec") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("tag") {
                let lit: LitInt = meta.value()?.parse()?;
                if !lit.suffix().is_empty() {
                    return Err(Error::new_spanned(&lit, "tag literals must be unsuffixed"));
                }
                let value: u8 = lit.base10_parse()?;
                if tag.is_some() {
                    return Err(Error::new_spanned(&lit, "duplicate `tag` attribute"));
                }
                if !seen.insert(value) {
                    return Err(Error::new_spanned(&lit, "duplicate tag value"));
                }
                tag = Some(lit);
                Ok(())
            } else if meta.path.is_ident("cfg") || meta.path.is_ident("bound") {
                Err(meta.error("attribute is not valid on a variant"))
            } else {
                Err(meta.error("expected `tag = N`"))
            }
        })?;
    }

    let (style, fields) = parse_fields(&variant.fields, params)?;
    check_single_cfg(&fields)?;
    Ok(Variant {
        ident: variant.ident.clone(),
        tag,
        style,
        fields,
    })
}

fn parse_fields(fields: &Fields, params: &HashSet<String>) -> Result<(Style, Vec<Field>)> {
    let style = match fields {
        Fields::Named(_) => Style::Named,
        Fields::Unnamed(_) => Style::Unnamed,
        Fields::Unit => Style::Unit,
    };
    let mut parsed = Vec::with_capacity(fields.len());
    for (index, field) in fields.iter().enumerate() {
        let mut cfg = None;
        for attr in &field.attrs {
            if !attr.path().is_ident("codec") {
                continue;
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("cfg") {
                    if cfg.is_some() {
                        return Err(meta.error("duplicate `cfg` attribute"));
                    }
                    cfg = Some(meta.path.span());
                    Ok(())
                } else if meta.path.is_ident("tag") || meta.path.is_ident("bound") {
                    Err(meta.error("attribute is not valid on a field"))
                } else {
                    Err(meta.error("expected `cfg`"))
                }
            })?;
        }
        let member = field.ident.as_ref().map_or_else(
            || Member::Unnamed(index.into()),
            |ident| Member::Named(ident.clone()),
        );
        parsed.push(Field {
            member,
            binding: format_ident!("__f{index}"),
            ty: field.ty.clone(),
            cfg,
            generic: mentions_param(&field.ty, params),
        });
    }
    Ok((style, parsed))
}

fn check_single_cfg(fields: &[Field]) -> Result<()> {
    let mut cfgs = fields.iter().filter_map(|f| f.cfg);
    if let (Some(_), Some(second)) = (cfgs.next(), cfgs.next()) {
        return Err(Error::new(
            second,
            "at most one field may be marked #[codec(cfg)]",
        ));
    }
    Ok(())
}

/// Collects the idents of the container's type and const parameters.
fn param_idents(generics: &Generics) -> HashSet<String> {
    generics
        .type_params()
        .map(|p| p.ident.to_string())
        .chain(generics.const_params().map(|p| p.ident.to_string()))
        .collect()
}

/// Returns whether the type's tokens mention any of the given parameter idents.
fn mentions_param(ty: &Type, params: &HashSet<String>) -> bool {
    fn scan(stream: proc_macro2::TokenStream, params: &HashSet<String>) -> bool {
        stream.into_iter().any(|tree| match tree {
            TokenTree::Ident(ident) => params.contains(&ident.to_string()),
            TokenTree::Group(group) => scan(group.stream(), params),
            _ => false,
        })
    }
    !params.is_empty() && scan(ty.to_token_stream(), params)
}
