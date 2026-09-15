use proc_macro2::Span;
use syn::{
    Attribute, Error, Expr, LitInt, Result, Token, Type, WherePredicate, parenthesized,
    punctuated::Punctuated,
};

#[derive(Default)]
pub(super) struct Options {
    pub(super) read_cfg: Option<Type>,
    pub(super) cfg: Option<Expr>,
    pub(super) read_with: Option<Expr>,
    pub(super) invalid_tag: Option<Expr>,
    pub(super) read_bounds: Option<Punctuated<WherePredicate, Token![,]>>,
    pub(super) write_bounds: Option<Punctuated<WherePredicate, Token![,]>>,
    pub(super) encode_size_bounds: Option<Punctuated<WherePredicate, Token![,]>>,
    pub(super) fixed_size_bounds: Option<Punctuated<WherePredicate, Token![,]>>,
    pub(super) encode_with: Option<Expr>,
    pub(super) encode_size: Option<Expr>,
    pub(super) tag: Option<u8>,
}

#[derive(Clone, Copy)]
pub(super) enum Place {
    Container,
    Variant,
    Field,
}

fn set<T>(slot: &mut Option<T>, value: T, span: Span, name: &str) -> Result<()> {
    if slot.is_some() {
        return Err(Error::new(span, format!("duplicate `{name}` attribute")));
    }
    *slot = Some(value);
    Ok(())
}

impl Options {
    pub(super) fn parse(attrs: &[Attribute], place: Place) -> Result<Self> {
        let mut options = Self::default();
        for attr in attrs {
            if attr.path().is_ident("read_cfg") || attr.path().is_ident("encode_size") {
                if !matches!(place, Place::Container) {
                    return Err(Error::new_spanned(
                        attr,
                        "this attribute belongs on the container; use `#[codec(...)]` on fields",
                    ));
                }
                if attr.path().is_ident("read_cfg") {
                    set(
                        &mut options.read_cfg,
                        attr.parse_args()?,
                        attr.pound_token.span,
                        "read_cfg",
                    )?;
                } else {
                    set(
                        &mut options.encode_size,
                        attr.parse_args()?,
                        attr.pound_token.span,
                        "encode_size",
                    )?;
                }
            } else if attr.path().is_ident("codec") {
                let mut any = false;
                attr.parse_nested_meta(|meta| {
                    any = true;
                    let span = meta.path.segments[0].ident.span();
                    if matches!(place, Place::Container)
                        && (meta.path.is_ident("read_bounds")
                            || meta.path.is_ident("write_bounds")
                            || meta.path.is_ident("encode_size_bounds")
                            || meta.path.is_ident("fixed_size_bounds"))
                    {
                        let content;
                        parenthesized!(content in meta.input);
                        let bounds = content.parse_terminated(|input| input.parse(), Token![,])?;
                        let name = meta.path.get_ident().unwrap().to_string();
                        let slot = match name.as_str() {
                            "read_bounds" => &mut options.read_bounds,
                            "write_bounds" => &mut options.write_bounds,
                            "encode_size_bounds" => &mut options.encode_size_bounds,
                            _ => &mut options.fixed_size_bounds,
                        };
                        set(slot, bounds, span, &name)
                    } else if meta.path.is_ident("read_with") && matches!(place, Place::Field) {
                        set(
                            &mut options.read_with,
                            meta.value()?.parse()?,
                            span,
                            "read_with",
                        )
                    } else if meta.path.is_ident("invalid_tag") && matches!(place, Place::Container)
                    {
                        set(
                            &mut options.invalid_tag,
                            meta.value()?.parse()?,
                            span,
                            "invalid_tag",
                        )
                    } else if meta.path.is_ident("read_cfg") && matches!(place, Place::Container) {
                        set(
                            &mut options.read_cfg,
                            meta.value()?.parse()?,
                            span,
                            "read_cfg",
                        )
                    } else if meta.path.is_ident("cfg") && matches!(place, Place::Field) {
                        set(&mut options.cfg, meta.value()?.parse()?, span, "cfg")
                    } else if meta.path.is_ident("encode_with") && matches!(place, Place::Field) {
                        set(
                            &mut options.encode_with,
                            meta.value()?.parse()?,
                            span,
                            "encode_with",
                        )
                    } else if meta.path.is_ident("encode_size") && !matches!(place, Place::Variant)
                    {
                        set(
                            &mut options.encode_size,
                            meta.value()?.parse()?,
                            span,
                            "encode_size",
                        )
                    } else if meta.path.is_ident("tag") && matches!(place, Place::Variant) {
                        let literal: LitInt = meta.value()?.parse()?;
                        let tag = literal.base10_parse::<u8>().map_err(|_| {
                            Error::new_spanned(
                                &literal,
                                "tag must be an integer from 0 through 255",
                            )
                        })?;
                        set(&mut options.tag, tag, span, "tag")
                    } else {
                        Err(meta
                            .error("unknown codec attribute or attribute in the wrong position"))
                    }
                })?;
                if !any {
                    return Err(Error::new_spanned(attr, "expected a codec attribute"));
                }
            }
        }
        Ok(options)
    }
}
