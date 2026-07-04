use super::input::{Field, Item, ItemKind};
use std::collections::BTreeSet;
use syn::{visit::Visit, GenericParam, Generics, Result, Type};

/// A set of generic parameter names, partitioned by kind.
///
/// Used both for the full set of mailbox parameters and for the subset a
/// branch's items actually reference.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct GenericSet {
    type_params: BTreeSet<String>,
    lifetime_params: BTreeSet<String>,
    const_params: BTreeSet<String>,
}

impl GenericSet {
    pub(crate) fn from_generics(generics: &Generics) -> Self {
        let mut set = Self::default();
        for param in &generics.params {
            match param {
                GenericParam::Type(param) => {
                    set.type_params.insert(param.ident.to_string());
                }
                GenericParam::Lifetime(param) => {
                    set.lifetime_params.insert(param.lifetime.ident.to_string());
                }
                GenericParam::Const(param) => {
                    set.const_params.insert(param.ident.to_string());
                }
            }
        }
        set
    }

    fn merge(&mut self, other: Self) {
        self.type_params.extend(other.type_params);
        self.lifetime_params.extend(other.lifetime_params);
        self.const_params.extend(other.const_params);
    }

    fn contains(&self, param: &GenericParam) -> bool {
        match param {
            GenericParam::Type(param) => self.type_params.contains(&param.ident.to_string()),
            GenericParam::Lifetime(param) => self
                .lifetime_params
                .contains(&param.lifetime.ident.to_string()),
            GenericParam::Const(param) => self.const_params.contains(&param.ident.to_string()),
        }
    }

    /// Names present in `self` but absent from `other`, formatted for display.
    fn missing_from(&self, other: &Self) -> Vec<String> {
        let mut missing = Vec::new();
        missing.extend(self.type_params.difference(&other.type_params).cloned());
        missing.extend(
            self.lifetime_params
                .difference(&other.lifetime_params)
                .map(|name| format!("'{name}")),
        );
        missing.extend(self.const_params.difference(&other.const_params).cloned());
        missing
    }
}

struct TypeGenericUseCollector<'a> {
    declared: &'a GenericSet,
    found: GenericSet,
}

impl<'a> TypeGenericUseCollector<'a> {
    fn new(declared: &'a GenericSet) -> Self {
        Self {
            declared,
            found: GenericSet::default(),
        }
    }
}

impl Visit<'_> for TypeGenericUseCollector<'_> {
    fn visit_type_path(&mut self, node: &syn::TypePath) {
        if node.qself.is_none() && !node.path.segments.is_empty() {
            let ident = node.path.segments[0].ident.to_string();
            if self.declared.type_params.contains(&ident) {
                self.found.type_params.insert(ident);
            }
        }

        syn::visit::visit_type_path(self, node);
    }

    fn visit_lifetime(&mut self, node: &syn::Lifetime) {
        let ident = node.ident.to_string();
        if self.declared.lifetime_params.contains(&ident) {
            self.found.lifetime_params.insert(ident);
        }

        syn::visit::visit_lifetime(self, node);
    }

    fn visit_expr_path(&mut self, node: &syn::ExprPath) {
        if node.qself.is_none() && node.path.segments.len() == 1 {
            let ident = node.path.segments[0].ident.to_string();
            if self.declared.const_params.contains(&ident) {
                self.found.const_params.insert(ident);
            }
        }

        syn::visit::visit_expr_path(self, node);
    }
}

fn collect_usage_from_type(ty: &Type, declared: &GenericSet) -> GenericSet {
    let mut visitor = TypeGenericUseCollector::new(declared);
    visitor.visit_type(ty);
    visitor.found
}

fn collect_usage_from_fields(fields: &[Field], declared: &GenericSet) -> GenericSet {
    let mut usage = GenericSet::default();
    for field in fields {
        usage.merge(collect_usage_from_type(&field.ty, declared));
    }
    usage
}

/// Mailbox parameters referenced by a generic parameter's own bounds.
fn collect_usage_from_param_bounds(param: &GenericParam, declared: &GenericSet) -> GenericSet {
    let mut visitor = TypeGenericUseCollector::new(declared);
    match param {
        GenericParam::Type(param) => {
            for bound in &param.bounds {
                visitor.visit_type_param_bound(bound);
            }
        }
        GenericParam::Lifetime(param) => {
            for bound in &param.bounds {
                visitor.visit_lifetime(bound);
            }
        }
        GenericParam::Const(param) => {
            visitor.visit_type(&param.ty);
        }
    }
    visitor.found
}

pub(crate) fn collect_readonly_ingress_usage(items: &[Item], declared: &GenericSet) -> GenericSet {
    let mut usage = GenericSet::default();
    for item in items {
        match &item.kind {
            ItemKind::Request {
                response,
                read_write: false,
                ..
            } => {
                usage.merge(collect_usage_from_fields(&item.fields, declared));
                usage.merge(collect_usage_from_type(response, declared));
            }
            ItemKind::Tell
            | ItemKind::Request {
                read_write: true, ..
            } => {}
        }
    }
    usage
}

pub(crate) fn collect_read_write_ingress_usage(
    items: &[Item],
    declared: &GenericSet,
) -> GenericSet {
    let mut usage = GenericSet::default();
    for item in items {
        match &item.kind {
            ItemKind::Tell => {
                usage.merge(collect_usage_from_fields(&item.fields, declared));
            }
            ItemKind::Request {
                response,
                read_write: true,
                ..
            } => {
                usage.merge(collect_usage_from_fields(&item.fields, declared));
                usage.merge(collect_usage_from_type(response, declared));
            }
            ItemKind::Request {
                read_write: false, ..
            } => {}
        }
    }
    usage
}

/// Retain only the parameters whose name is in `usage`, preserving order,
/// attributes, and bounds. Order preservation keeps lifetimes ahead of types
/// and consts, so the filtered list stays valid.
pub(crate) fn filter_generics(generics: &Generics, usage: &GenericSet) -> Generics {
    let mut filtered = generics.clone();
    filtered.params = filtered
        .params
        .into_iter()
        .filter(|param| usage.contains(param))
        .collect();
    if filtered.params.is_empty() {
        filtered.lt_token = None;
        filtered.gt_token = None;
    }
    filtered.where_clause = None;
    filtered
}

fn reject_generic_defaults(generics: &Generics) -> Result<()> {
    for param in &generics.params {
        let has_default = match param {
            GenericParam::Type(param) => param.default.is_some(),
            GenericParam::Const(param) => param.default.is_some(),
            GenericParam::Lifetime(_) => false,
        };
        if has_default {
            return Err(syn::Error::new_spanned(
                param,
                "defaults are not supported on ingress! generics",
            ));
        }
    }
    Ok(())
}

fn push_error(accumulator: &mut Option<syn::Error>, error: syn::Error) {
    match accumulator {
        Some(existing) => existing.combine(error),
        None => *accumulator = Some(error),
    }
}

fn param_name(param: &GenericParam) -> String {
    match param {
        GenericParam::Type(param) => param.ident.to_string(),
        GenericParam::Lifetime(param) => format!("'{}", param.lifetime.ident),
        GenericParam::Const(param) => param.ident.to_string(),
    }
}

fn unused_param_error(param: &GenericParam) -> syn::Error {
    let span = match param {
        GenericParam::Type(param) => param.ident.span(),
        GenericParam::Lifetime(param) => param.lifetime.ident.span(),
        GenericParam::Const(param) => param.ident.span(),
    };
    syn::Error::new(
        span,
        format!(
            "generic parameter `{}` is not used by any ingress item",
            param_name(param)
        ),
    )
}

/// Reject mailbox generics that filtering cannot satisfy.
///
/// Two conditions are fatal:
/// - A parameter used by no item. The top-level ingress enum and mailbox struct
///   keep the full mailbox generics, so an unused parameter would otherwise
///   surface as an opaque rustc error on generated code.
/// - A retained parameter whose bounds reference a parameter the same branch
///   drops. Filtering would then emit an enum that names a parameter it no
///   longer declares, so the reference must be an error instead.
pub(crate) fn validate_generics(
    generics: &Generics,
    declared: &GenericSet,
    readonly_usage: &GenericSet,
    read_write_usage: &GenericSet,
) -> Result<()> {
    reject_generic_defaults(generics)?;

    let mut error = None;

    let mut used = readonly_usage.clone();
    used.merge(read_write_usage.clone());
    for param in &generics.params {
        if !used.contains(param) {
            push_error(&mut error, unused_param_error(param));
        }
    }

    for (label, usage) in [
        ("read-only", readonly_usage),
        ("read-write", read_write_usage),
    ] {
        for param in &generics.params {
            if !usage.contains(param) {
                continue;
            }
            let referenced = collect_usage_from_param_bounds(param, declared);
            let name = param_name(param);
            for missing in referenced.missing_from(usage) {
                push_error(&mut error, syn::Error::new_spanned(param, format!(
                    "{label} items use `{name}`, whose bounds reference `{missing}`, but no {label} item uses `{missing}`; use `{missing}` in a {label} item or remove it from `{name}`'s bounds"
                )));
            }
        }
    }

    error.map_or(Ok(()), Err)
}
