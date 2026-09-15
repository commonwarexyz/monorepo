use super::{Kind, Shape, options::Options};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    Attribute, DeriveInput, Ident, Type, parse_quote,
    visit_mut::{self, VisitMut},
};

// Const parameters share the value namespace with generated local bindings. Keep
// attribute expressions untouched so they can use the documented local names.
struct ConstNames(Vec<(Ident, Ident)>);

impl VisitMut for ConstNames {
    fn visit_attribute_mut(&mut self, _: &mut Attribute) {}

    fn visit_const_param_mut(&mut self, param: &mut syn::ConstParam) {
        if let Some((_, replacement)) = self.0.iter().find(|(name, _)| *name == param.ident) {
            param.ident = replacement.clone();
        }
        visit_mut::visit_const_param_mut(self, param);
    }

    fn visit_path_mut(&mut self, path: &mut syn::Path) {
        if path.leading_colon.is_none() && path.segments.len() == 1 {
            let ident = &mut path.segments[0].ident;
            if let Some((_, replacement)) = self.0.iter().find(|(name, _)| name == ident) {
                *ident = replacement.clone();
            }
        }
        visit_mut::visit_path_mut(self, path);
    }
}

pub(super) fn rename_consts(input: &mut DeriveInput, kind: Kind, options: &mut Options) {
    let source = quote!(#input).to_string();
    let mut names = ConstNames(Vec::new());
    for param in input.generics.const_params() {
        let name = param.ident.to_string();
        let reserved = match kind {
            Kind::Write => matches!(name.as_str(), "buf" | "value"),
            Kind::Read => matches!(name.as_str(), "buf" | "cfg" | "tag"),
            Kind::EncodeSize if options.encode_size.is_none() => name == "value",
            _ => false,
        };
        if reserved
            || (kind != Kind::FixedSize
                && !(kind == Kind::EncodeSize && options.encode_size.is_some())
                && name.starts_with("__codec_field_"))
        {
            let mut replacement = format!("__CODEC_CONST_{}", name.to_uppercase());
            while source.contains(&replacement) {
                replacement.push('_');
            }
            names.0.push((
                param.ident.clone(),
                Ident::new(&replacement, param.ident.span()),
            ));
        }
    }
    names.visit_derive_input_mut(input);
    for bounds in [
        &mut options.read_bounds,
        &mut options.write_bounds,
        &mut options.encode_size_bounds,
        &mut options.fixed_size_bounds,
    ]
    .into_iter()
    .flatten()
    {
        for bound in bounds {
            names.visit_where_predicate_mut(bound);
        }
    }
    if let Some(cfg) = &mut options.read_cfg {
        names.visit_type_mut(cfg);
    }
}

// A fresh parameter ties the source projection to the field configuration
// without a self-referential equality such as T: Read<Cfg = T::Cfg>.
fn cfg_projection(
    cfg: &Type,
    parameter: &Ident,
    codec: &TokenStream,
    generics: &syn::Generics,
) -> Option<syn::WherePredicate> {
    let Type::Path(path) = cfg else { return None };
    if !path.path.segments.last().is_some_and(|s| s.ident == "Cfg") {
        return None;
    }
    let (owner, mut trait_path): (Type, syn::Path) = if let Some(qself) = &path.qself {
        if qself.position == 0 || qself.position + 1 != path.path.segments.len() {
            return None;
        }
        let mut trait_path = path.path.clone();
        trait_path.segments.pop();
        trait_path.segments.pop_punct();
        ((*qself.ty).clone(), trait_path)
    } else {
        if path.path.leading_colon.is_some()
            || path.path.segments.len() != 2
            || !generics
                .type_params()
                .any(|param| param.ident == path.path.segments[0].ident)
        {
            return None;
        }
        let mut owner = path.path.clone();
        owner.segments.pop();
        owner.segments.pop_punct();
        (parse_quote!(#owner), parse_quote!(#codec::Read))
    };
    let segment = trait_path.segments.last_mut()?;
    match &mut segment.arguments {
        syn::PathArguments::None => {
            segment.arguments = syn::PathArguments::AngleBracketed(parse_quote!(<Cfg = #parameter>))
        }
        syn::PathArguments::AngleBracketed(arguments) => {
            arguments.args.push(parse_quote!(Cfg = #parameter))
        }
        syn::PathArguments::Parenthesized(_) => return None,
    }
    Some(parse_quote!(#owner: #trait_path))
}

// Recursive wrappers cannot appear in the impl's predicates: selecting that
// impl would require selecting itself. Their nonrecursive siblings still need
// bounds, including projections such as T::Item rather than the owner T.
// Explicit configurations also require leaf bounds: a wrapper predicate would
// hide the wrapper impl's concrete associated configuration type.
fn bound_types(ty: &Type, owner: &Ident, leaves: Option<&syn::Generics>) -> (bool, Vec<Type>) {
    if let Type::Path(path) = ty
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && path
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == *owner || s.ident == "Self")
    {
        return (true, Vec::new());
    }
    if let (Some(generics), Type::Path(path)) = (leaves, ty) {
        let generic = path.path.leading_colon.is_none()
            && path.path.segments.first().is_some_and(|segment| {
                generics
                    .type_params()
                    .any(|param| param.ident == segment.ident)
            });
        let projection = path
            .qself
            .as_ref()
            .is_some_and(|qself| !bound_types(&qself.ty, owner, leaves).1.is_empty());
        if generic || projection {
            return (false, vec![ty.clone()]);
        }
    }
    struct Children<'a> {
        owner: &'a Ident,
        leaves: Option<&'a syn::Generics>,
        recursive: bool,
        bounds: Vec<Type>,
    }
    impl VisitMut for Children<'_> {
        fn visit_type_mut(&mut self, ty: &mut Type) {
            let (recursive, bounds) = bound_types(ty, self.owner, self.leaves);
            self.recursive |= recursive;
            self.bounds.extend(bounds);
        }
    }
    let mut children = Children {
        owner,
        leaves,
        recursive: false,
        bounds: Vec::new(),
    };
    visit_mut::visit_type_mut(&mut children, &mut ty.clone());
    if children.recursive || leaves.is_some() {
        (children.recursive, children.bounds)
    } else {
        (false, vec![ty.clone()])
    }
}

pub(super) fn for_impl(
    input: &DeriveInput,
    options: &Options,
    shapes: &[Shape<'_>],
    kind: Kind,
    codec: &TokenStream,
) -> (syn::Generics, Type) {
    let name = &input.ident;
    let mut cfg_ty: Type = options.read_cfg.clone().unwrap_or_else(|| parse_quote!(()));
    let mut generics = input.generics.clone();
    if kind == Kind::Read {
        let source = quote!(#input).to_string();
        let mut parameter = "__CodecCfg".to_owned();
        while source.contains(&parameter) {
            parameter.push('_');
        }
        let parameter = Ident::new(&parameter, Span::mixed_site());
        if let Some(bound) = cfg_projection(&cfg_ty, &parameter, codec, &input.generics) {
            generics.params.push(parse_quote!(#parameter));
            generics.make_where_clause().predicates.push(bound);
            cfg_ty = parse_quote!(#parameter);
        }
        generics.make_where_clause().predicates.push(parse_quote!(
            #cfg_ty: ::core::clone::Clone + ::core::marker::Send + ::core::marker::Sync + 'static
        ));
    }
    let bounds = match kind {
        Kind::Read => &options.read_bounds,
        Kind::Write => &options.write_bounds,
        Kind::EncodeSize => &options.encode_size_bounds,
        Kind::FixedSize => &options.fixed_size_bounds,
        Kind::Encode => unreachable!(),
    };
    if let Some(bounds) = bounds {
        generics
            .make_where_clause()
            .predicates
            .extend(bounds.iter().cloned());
        return (generics, cfg_ty);
    }
    for field in shapes.iter().flat_map(|s| &s.fields) {
        if kind == Kind::Read && field.options.read_with.is_some() {
            continue;
        }
        let leaves = (kind == Kind::Read && field.options.cfg.is_some()).then_some(&input.generics);
        let (recursive, types) = bound_types(field.ty, name, leaves);
        for ty in types {
            let bound = match kind {
                Kind::Write if field.options.encode_with.is_none() => {
                    parse_quote!(#ty: #codec::Write)
                }
                Kind::Read if !recursive && field.options.cfg.is_none() => {
                    parse_quote!(#ty: #codec::Read<Cfg = #cfg_ty>)
                }
                Kind::Read => parse_quote!(#ty: #codec::Read),
                Kind::EncodeSize
                    if options.encode_size.is_none() && field.options.encode_size.is_none() =>
                {
                    parse_quote!(#ty: #codec::EncodeSize)
                }
                Kind::FixedSize => parse_quote!(#ty: #codec::FixedSize),
                _ => continue,
            };
            generics.make_where_clause().predicates.push(bound);
        }
    }
    (generics, cfg_ty)
}
