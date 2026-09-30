//! Surface type checking and lowering to HIR (DESIGN.md §3.1–§3.6, §4).
//!
//! The [`Checker`] turns resolved `syn` items into [`hir`] items:
//!
//! 1. **Signatures** ([`Checker::lower_signatures`]): type aliases (expanded,
//!    cycle-checked), struct/enum definitions (fields, generics with bound
//!    `Copy` only, derives — `Clone, Copy` required), constant types, and
//!    function signatures normalized to [`FnSig`] (kind from
//!    `#[spec]/#[lemma]/#[law]/#[proof]`, receivers `self`/`&self`, target
//!    features and their implication closure, `#[inline]`, `#[must_use]`,
//!    `#[specialize]`, `#[implements]`, contract attributes). Attributes are
//!    validated here (§3.1 whitelist, `#[allow]` whitelist,
//!    `#[inline(always)]` + `#[target_feature]`).
//! 2. **Bodies** ([`Checker::check_bodies`]): constants and functions are
//!    type checked bidirectionally by [`expr`](self::expr) (expressions and
//!    statements), [`pat`](self::pat) (patterns, default binding modes,
//!    exhaustiveness via [`crate::exhaust`]) and [`script`](self::script)
//!    (ghost scripts and propositions).
//!
//! Subset rejections that are syntactic (closures, floats, `loop`, `&mut`,
//! signed types, ...) are reported where the construct is met, each with its
//! own [`DiagKind`]; global rules live in [`crate::validate`].
//!
//! The §15 annotations (DESIGN.md §15) are parsed, resolved, typed and
//! placed by [`spec15`] into the HIR records of [`crate::hir`].

pub mod exits;
pub mod expr;
pub mod pat;
pub mod script;
pub mod spec15;

use std::collections::{HashMap, HashSet};

use quote::ToTokens;
use syn::spanned::Spanned;

use crate::const_eval::ConstEval;
use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::hir::{self, Derives, FieldDef, FnKind, Inline, ItemId, ModId, Receiver, Shape, Ty, TyParam, UintTy, Vis};
use crate::resolve::{vis_of, Annot, Def, Ext, ItemSrc, ItemTag, Ns, Resolver};
use crate::span::{FileId, Span};
use crate::target::{feature_closure, is_known_feature};

/// Generic parameters in scope while lowering a type.
#[derive(Clone, Debug, Default)]
pub struct GenScope {
    pub params: Vec<String>,
    /// `Self` inside inherent impls.
    pub self_ty: Option<Ty>,
}

/// Parsed contract attributes of an exec or spec function.
#[derive(Clone, Default)]
pub struct Contracts {
    pub requires: Vec<syn::Expr>,
    /// `#[ensures(..)]` payload.
    pub ensures: Option<syn::Expr>,
    pub decreases: Option<(syn::Expr, Option<u64>)>,
    pub implements: Option<syn::Path>,
}

/// A lowered function signature.
#[derive(Clone)]
pub struct FnSig {
    pub kind: FnKind,
    pub ghost: bool,
    pub owner: Option<ItemId>,
    pub receiver: Option<Receiver>,
    pub generics: Vec<TyParam>,
    /// The function's own lifetime parameters.
    pub lifetimes: Vec<String>,
    /// Types of all parameters (receiver first).
    pub params: Vec<Ty>,
    pub param_lts: Vec<hir::Lifetimes>,
    pub ret: Ty,
    pub ret_lts: hir::Lifetimes,
    pub impl_block: Option<u32>,
    pub impl_lifetimes: Vec<String>,
    pub impl_self_lts: Vec<String>,
    pub target_features: Vec<String>,
    pub feature_set: Vec<String>,
    pub inline: Option<Inline>,
    pub must_use: bool,
    pub specialize: bool,
    pub contracts: Contracts,
    pub sig_span: Span,
    pub docs: Vec<String>,
    pub allow: Vec<String>,
    pub gen_scope: GenScope,
    /// The §15 annotations, parsed ([`spec15::FnSpecSyn`]).
    pub spec: spec15::FnSpecSyn,
    /// Per parameter (receiver first): `#[ghost]`.
    pub ghost_params: Vec<bool>,
}

/// The type checker.
pub struct Checker<'a> {
    pub res: &'a Resolver,
    pub ce: ConstEval<'a>,
    pub diags: Diagnostics,
    alias_tys: HashMap<ItemId, Ty>,
    alias_busy: HashSet<ItemId>,
    /// Lowered items (structs/enums/aliases after signatures; consts and fns
    /// after bodies).
    pub hir_items: Vec<Option<hir::ItemKind>>,
    pub sigs: HashMap<ItemId, FnSig>,
    pub const_tys: HashMap<ItemId, Ty>,
    pub const_lts: HashMap<ItemId, hir::Lifetimes>,
    /// Item docs and allows by item.
    pub item_docs: HashMap<ItemId, (Vec<String>, Vec<String>)>,
    /// Lifetime recorder for declaration types (see [`hir::Lifetimes`]).
    lt_rec: Option<Vec<String>>,
}

/// Docs from `#[doc = ".."]` attributes.
pub fn docs_of(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("doc"))
        .filter_map(|a| match &a.meta {
            syn::Meta::NameValue(nv) => match &nv.value {
                syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The annotation an attribute path names (`requires`, `sandblaster::requires`,
/// `sandblaster::prelude::requires`), if any.
pub fn annotation_of(path: &syn::Path) -> Option<(Annot, bool)> {
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    let (name, qualified) = match segs.as_slice() {
        [n] => (n.as_str(), false),
        [r, n] if r == "sandblaster" => (n.as_str(), true),
        [r, p, n] if r == "sandblaster" && (p == "prelude" || p == "ghost") => (n.as_str(), true),
        _ => return None,
    };
    Annot::from_name(name).map(|a| (a, qualified))
}

/// Whether a lint name may appear in `#[allow(..)]` (§3.1).
pub fn allow_whitelisted(lint: &str) -> bool {
    lint == "dead_code" || lint.starts_with("unused") || lint == "non_snake_case" || lint == "non_camel_case_types" || lint == "non_upper_case_globals" || lint.starts_with("clippy::") || lint == "clippy"
}

impl<'a> Checker<'a> {
    pub fn new(res: &'a Resolver) -> Checker<'a> {
        Checker {
            res,
            ce: ConstEval::new(res),
            diags: Diagnostics::new(),
            alias_tys: HashMap::new(),
            alias_busy: HashSet::new(),
            hir_items: vec![None; res.items.len()],
            sigs: HashMap::new(),
            const_tys: HashMap::new(),
            const_lts: HashMap::new(),
            item_docs: HashMap::new(),
            lt_rec: None,
        }
    }

    /// Lowers a declaration type, recording its lifetimes.
    pub fn lower_decl_ty(&mut self, m: ModId, t: &syn::Type, g: &GenScope, ghost: bool) -> (Ty, hir::Lifetimes) {
        let saved = self.lt_rec.replace(Vec::new());
        let ty = self.lower_ty(m, t, g, ghost);
        let lts = std::mem::replace(&mut self.lt_rec, saved).unwrap_or_default();
        (ty, hir::Lifetimes(lts))
    }

    fn record_lt(&mut self, lt: Option<&syn::Lifetime>) {
        if let Some(r) = &mut self.lt_rec {
            r.push(lt.map(|l| format!("'{}", l.ident)).unwrap_or_default());
        }
    }

    /// Number of lifetime parameters of an ADT.
    pub fn adt_lifetime_count(&self, id: ItemId) -> usize {
        match &self.res.items[id.0 as usize].src {
            ItemSrc::Struct(s) => s.generics.lifetimes().count(),
            ItemSrc::Enum(e) => e.generics.lifetimes().count(),
            _ => 0,
        }
    }

    pub fn err(&mut self, kind: DiagKind, span: Span, msg: impl Into<String>) {
        self.diags.error(kind, span, msg);
    }

    pub fn file_of(&self, m: ModId) -> FileId {
        self.res.mods[m.0 as usize].file
    }

    pub fn sp(&self, m: ModId, s: proc_macro2::Span) -> Span {
        Span::from_pm2(self.file_of(m), s)
    }

    /// Display name of an ADT for diagnostics.
    pub fn ty_str(&self, t: &Ty) -> String {
        let name = |id: ItemId| self.res.items[id.0 as usize].name.clone();
        t.display(&name).to_string()
    }

    // ------------------------------------------------------------------
    // attributes
    // ------------------------------------------------------------------

    /// Validates the common attributes of an item. `allowed` lists extra
    /// attribute names accepted for this item kind (`site`). Returns (docs,
    /// allows).
    fn common_attrs(&mut self, m: ModId, attrs: &[syn::Attribute], allowed: &[&str], ghost: bool, site: spec15::Site) -> (Vec<String>, Vec<String>) {
        let mut allows = Vec::new();
        for a in attrs {
            let span = self.sp(m, a.span());
            if crate::resolve::is_critical_attr(a) {
                self.diags.push(crate::resolve::critical_diagnostic(span));
                continue;
            }
            let path = a.path();
            if path.is_ident("doc") || path.is_ident("cfg") {
                continue;
            }
            if path.is_ident("allow") {
                allows.extend(self.allow_attr(m, a));
                continue;
            }
            // inner attributes (`#![..]` inside a function body or an `impl`
            // block): only docs and whitelisted `#![allow(..)]`
            if let syn::AttrStyle::Inner(_) = a.style {
                let n = path.to_token_stream().to_string().replace(' ', "");
                let d = match annotation_of(path) {
                    Some((an, _)) => Diagnostic::error(DiagKind::Attribute, span, format!("`#![{}]` is not allowed: sandblaster annotations are outer attributes", an.name())).note(spec15::placement_note(an, site)),
                    None => Diagnostic::error(DiagKind::Attribute, span, format!("inner attribute `#![{n}]` is not allowed on {}", site.text())).note("allowed inner attributes: docs and whitelisted `#![allow(..)]`"),
                };
                self.diags.push(d);
                continue;
            }
            if let Some((an, qualified)) = annotation_of(path) {
                self.annotation_arg_attrs(m, a);
                let name = an.name();
                if !allowed.contains(&name) {
                    let d = Diagnostic::error(DiagKind::Attribute, span, format!("`#[{name}]` is not allowed on {}", site.text()));
                    self.diags.push(d.note(spec15::placement_note(an, site)));
                    continue;
                }
                if !qualified && !ghost && !matches!(an, Annot::Spec | Annot::Lemma | Annot::Law | Annot::Proof | Annot::Rewrite) && !self.res.annotation_in_scope(m, name) {
                    self.diags.push(
                        Diagnostic::error(DiagKind::Resolve, span, format!("attribute `{name}` is not in scope"))
                            .note("add `use sandblaster::prelude::*;` so the baseline build (rustc with the erasing macros) resolves it"),
                    );
                }
                continue;
            }
            let name = path.to_token_stream().to_string().replace(' ', "");
            if allowed.contains(&name.as_str()) {
                continue;
            }
            let d = match name.as_str() {
                "warn" | "deny" | "forbid" | "expect" => Diagnostic::error(DiagKind::Attribute, span, format!("`#[{name}(..)]` is not allowed (only whitelisted `#[allow(..)]` lints)")),
                "repr" => Diagnostic::error(DiagKind::Attribute, span, "`#[repr]` is not supported"),
                "no_mangle" | "export_name" | "link_section" | "used" => Diagnostic::error(DiagKind::Attribute, span, format!("`#[{name}]` is not supported")),
                "cfg_attr" => Diagnostic::error(DiagKind::Attribute, span, "`#[cfg_attr]` is not supported"),
                "test" | "bench" => Diagnostic::error(DiagKind::Attribute, span, "tests do not belong in the DSL crate; write host tests"),
                "fully_specified" | "sandblaster::fully_specified" => Diagnostic::error(DiagKind::Attribute, span, "`#[fully_specified]` does not exist: sections are computed")
                    .note("every exported function must be fully specified anyway; `#[section(with = [..])]` only merges sections (DESIGN.md §15.5)"),
                _ => Diagnostic::error(DiagKind::Attribute, span, format!("attribute `#[{name}]` is not allowed here")),
            };
            self.diags.push(d);
        }
        (docs_of(attrs), allows)
    }

    /// Attributes nested in the argument of an annotation (e.g. a closure
    /// parameter `#[ensures(|#[ghost] r: u8| ..)]`): all rejected.
    fn annotation_arg_attrs(&mut self, m: ModId, a: &syn::Attribute) {
        if let syn::Meta::List(_) = &a.meta
            && let Ok(args) = a.parse_args_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        {
            let mut v = NestedAttrs::default();
            for e in &args {
                syn::visit::Visit::visit_expr(&mut v, e);
            }
            self.report_nested_attrs(m, v);
        }
    }

    /// Rejects every attribute inside a function body or a constant
    /// initializer — on statements, expressions, match arms, patterns,
    /// closure parameters, and the statements of `proof!` scripts. None is
    /// meaningful there: sandblaster annotations belong on items (DESIGN.md
    /// §3.1, §15), and rustc would accept most of them silently (the
    /// erasing macros pass any item through).
    pub fn check_nested_attrs(&mut self, m: ModId, block: Option<&syn::Block>, expr: Option<&syn::Expr>) {
        let mut v = NestedAttrs::default();
        if let Some(b) = block {
            syn::visit::Visit::visit_block(&mut v, b);
        }
        if let Some(e) = expr {
            syn::visit::Visit::visit_expr(&mut v, e);
        }
        self.report_nested_attrs(m, v);
    }

    fn report_nested_attrs(&mut self, m: ModId, v: NestedAttrs) {
        for (a, site) in v.found {
            let span = self.sp(m, a.span());
            let d = match annotation_of(a.path()) {
                Some((an, _)) => Diagnostic::error(DiagKind::Attribute, span, format!("`#[{}]` is not allowed on {site}", an.name())).note(spec15::placement_note(an, spec15::Site::Body)),
                None if site == NestedAttrs::LET => Diagnostic::error(DiagKind::Attribute, span, "attributes on `let` statements are not allowed"),
                None => {
                    let n = a.path().to_token_stream().to_string().replace(' ', "");
                    Diagnostic::error(DiagKind::Attribute, span, format!("attribute `#[{n}]` is not allowed on {site}")).note("attributes are only allowed on items, fields, variants and function parameters (DESIGN.md §3.1)")
                }
            };
            self.diags.push(d);
        }
    }

    /// Parses and whitelists `#[allow(..)]`.
    fn allow_attr(&mut self, m: ModId, a: &syn::Attribute) -> Vec<String> {
        let span = self.sp(m, a.span());
        let lints = match a.parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated) {
            Ok(l) => l,
            Err(e) => {
                self.err(DiagKind::Attribute, span, format!("malformed `#[allow]`: {e}"));
                return vec![];
            }
        };
        let mut out = Vec::new();
        for l in lints {
            let name = l.to_token_stream().to_string().replace(' ', "");
            if allow_whitelisted(&name) {
                out.push(name);
            } else {
                self.diags.push(
                    Diagnostic::error(DiagKind::Attribute, span, format!("`#[allow({name})]` is not allowed"))
                        .note("only `dead_code`, `unused_*`, `non_snake_case`, `non_camel_case_types`, `non_upper_case_globals` and `clippy::*` may be allowed (DESIGN.md §3.1)"),
                );
            }
        }
        out
    }

    /// Parses `#[derive(..)]` on a type.
    fn derives(&mut self, m: ModId, attrs: &[syn::Attribute], name_span: Span, name: &str) -> Derives {
        let mut d = Derives::default();
        for a in attrs.iter().filter(|a| a.path().is_ident("derive")) {
            let span = self.sp(m, a.span());
            let Ok(list) = a.parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated) else {
                self.err(DiagKind::Attribute, span, "malformed `#[derive]`");
                continue;
            };
            for p in list {
                let n = p.to_token_stream().to_string().replace(' ', "");
                match n.as_str() {
                    "Clone" => d.clone = true,
                    "Copy" => d.copy = true,
                    "PartialEq" => d.partial_eq = true,
                    "Eq" => d.eq = true,
                    "Debug" => d.debug = true,
                    _ => self.diags.push(Diagnostic::error(DiagKind::Trait, span, format!("`#[derive({n})]` is not supported")).note("allowed derives: Clone, Copy, PartialEq, Eq, Debug")),
                }
            }
        }
        if !(d.clone && d.copy) {
            self.diags.push(Diagnostic::error(DiagKind::Attribute, name_span, format!("`{name}` must derive `Clone, Copy`")).note("all user types are values (DESIGN.md §3.1)"));
        }
        if d.eq && !d.partial_eq {
            self.err(DiagKind::Attribute, name_span, "`Eq` requires `PartialEq`");
        }
        d
    }

    /// Lowers generics with bound `Copy` only (§3.1).
    fn generics(&mut self, m: ModId, g: &syn::Generics) -> Vec<TyParam> {
        let mut out = Vec::new();
        let where_bounds: Vec<(String, Vec<syn::TypeParamBound>)> = g
            .where_clause
            .iter()
            .flat_map(|w| w.predicates.iter())
            .filter_map(|p| match p {
                syn::WherePredicate::Type(t) => Some((t.bounded_ty.to_token_stream().to_string(), t.bounds.iter().cloned().collect())),
                _ => None,
            })
            .collect();
        for p in &g.params {
            match p {
                syn::GenericParam::Lifetime(_) => {}
                syn::GenericParam::Const(c) => {
                    self.err(DiagKind::Unsupported, self.sp(m, c.span()), "const generics are reserved (not supported in user code)");
                }
                syn::GenericParam::Type(t) => {
                    let name = t.ident.to_string();
                    let span = self.sp(m, t.span());
                    if t.default.is_some() {
                        self.err(DiagKind::Unsupported, span, "default type parameters are not supported");
                    }
                    let mut bounds: Vec<syn::TypeParamBound> = t.bounds.iter().cloned().collect();
                    for (n, b) in &where_bounds {
                        if *n == name {
                            bounds.extend(b.iter().cloned());
                        }
                    }
                    let mut has_copy = false;
                    for b in &bounds {
                        match b {
                            syn::TypeParamBound::Trait(tb) => {
                                let s = tb.path.to_token_stream().to_string().replace(' ', "");
                                if s == "Copy" || s == "core::marker::Copy" || s == "::core::marker::Copy" {
                                    has_copy = true;
                                } else {
                                    self.diags.push(Diagnostic::error(DiagKind::Trait, span, format!("trait bound `{s}` is not supported")).note("type parameters may only be bounded by `Copy` (DESIGN.md §3.1)"));
                                }
                            }
                            syn::TypeParamBound::Lifetime(_) => {}
                            _ => self.err(DiagKind::Trait, span, "unsupported bound"),
                        }
                    }
                    if !has_copy {
                        self.err(DiagKind::Trait, span, format!("type parameter `{name}` must be bounded by `Copy`"));
                    }
                    out.push(TyParam { name, span });
                }
            }
        }
        out
    }

    // ------------------------------------------------------------------
    // types
    // ------------------------------------------------------------------

    /// Lowers a `syn` type in module `m`.
    pub fn lower_ty(&mut self, m: ModId, t: &syn::Type, g: &GenScope, ghost: bool) -> Ty {
        let span = self.sp(m, t.span());
        match t {
            syn::Type::Paren(p) => self.lower_ty(m, &p.elem, g, ghost),
            syn::Type::Group(p) => self.lower_ty(m, &p.elem, g, ghost),
            syn::Type::Reference(r) => {
                self.record_lt(r.lifetime.as_ref());
                if r.mutability.is_some() {
                    self.diags.push(Diagnostic::error(DiagKind::MutRef, span, "`&mut` types are not supported").note("the only mutation through a reference is the `local.copy_from_slice(src)` statement (DESIGN.md §3.3)"));
                    return Ty::Error;
                }
                match &*r.elem {
                    syn::Type::Slice(s) => {
                        let e = self.lower_ty(m, &s.elem, g, ghost);
                        Ty::slice_ref(e)
                    }
                    other => {
                        let t = self.lower_ty(m, other, g, ghost);
                        Ty::reference(self.no_fn_in_data(&t, span))
                    }
                }
            }
            syn::Type::Slice(_) => {
                self.err(DiagKind::Unsupported, span, "unsized slice types must be behind a reference (`&[T]`)");
                Ty::Error
            }
            syn::Type::Array(a) => {
                let e = self.lower_ty(m, &a.elem, g, ghost);
                let e = self.no_fn_in_data(&e, span);
                match self.ce.eval(m, &a.len, Some(UintTy::Usize)) {
                    Ok(n) => Ty::array(e, n as u64),
                    Err(msg) => {
                        self.err(DiagKind::Type, self.sp(m, a.len.span()), format!("array length must be a literal or a constant: {msg}"));
                        Ty::Error
                    }
                }
            }
            syn::Type::Tuple(tt) => {
                if tt.elems.len() > 12 {
                    self.err(DiagKind::Unsupported, span, "tuples are limited to 12 elements");
                }
                let t = Ty::Tuple(tt.elems.iter().map(|e| self.lower_ty(m, e, g, ghost)).collect());
                self.no_fn_in_data(&t, span)
            }
            syn::Type::Never(_) => {
                self.err(DiagKind::Unsupported, span, "the never type `!` is not supported");
                Ty::Error
            }
            syn::Type::Ptr(_) => {
                self.err(DiagKind::RawPointer, span, "raw pointers are not supported");
                Ty::Error
            }
            syn::Type::BareFn(f) if ghost => self.ghost_fn_ty(m, f, g, span),
            syn::Type::BareFn(_) => {
                self.diags.push(Diagnostic::error(DiagKind::Closure, span, "function pointers are not supported").note("ghost code (specifications and proofs) may take function values of type `fn(A, ..) -> B`, which are erased (DESIGN.md §13.2)"));
                Ty::Error
            }
            syn::Type::TraitObject(_) => {
                self.err(DiagKind::Trait, span, "`dyn Trait` is not supported");
                Ty::Error
            }
            syn::Type::ImplTrait(_) => {
                self.err(DiagKind::Trait, span, "`impl Trait` is not supported");
                Ty::Error
            }
            syn::Type::Infer(_) => {
                self.err(DiagKind::Unsupported, span, "type placeholders `_` are not supported; write the type");
                Ty::Error
            }
            syn::Type::Macro(_) => {
                self.err(DiagKind::Macro, span, "type macros are not supported");
                Ty::Error
            }
            syn::Type::Path(p) => {
                if p.qself.is_some() {
                    self.err(DiagKind::Trait, span, "qualified paths (`<T as Trait>::X`) are not supported");
                    return Ty::Error;
                }
                self.lower_path_ty(m, &p.path, g, ghost, span)
            }
            _ => {
                self.err(DiagKind::Unsupported, span, "unsupported type");
                Ty::Error
            }
        }
    }

    /// The ghost function type `fn(A, ..) -> B` (ghost code only, DESIGN.md
    /// §13.2's `spec_fn`): a total function, the kernel's curried `Π`. Its
    /// components are first-order types or ghost function types themselves;
    /// `Nat` (no bound travels with a function value: write `Int`) and `Prop`
    /// (write `bool`) are rejected.
    fn ghost_fn_ty(&mut self, m: ModId, f: &syn::TypeBareFn, g: &GenScope, span: Span) -> Ty {
        if f.lifetimes.is_some() || f.unsafety.is_some() || f.abi.is_some() || f.variadic.is_some() {
            self.err(DiagKind::Closure, span, "a ghost function type is written `fn(A, ..) -> B` (no `for<..>`, `unsafe`, `extern` or `...`)");
            return Ty::Error;
        }
        let p = f;
        let mut comps: Vec<Ty> = p.inputs.iter().map(|a| self.lower_ty(m, &a.ty, g, true)).collect();
        let ret = match &p.output {
            syn::ReturnType::Default => Ty::unit(),
            syn::ReturnType::Type(_, t) => self.lower_ty(m, t, g, true),
        };
        comps.push(ret);
        for c in &comps {
            let mut bad = None;
            c.walk(&mut |t| match t {
                Ty::Nat if bad.is_none() => bad = Some("`Nat` (write `Int`: no bound travels with a function value)"),
                Ty::Prop | Ty::Proof if bad.is_none() => bad = Some("`Prop` (write `bool`)"),
                Ty::Never if bad.is_none() => bad = Some("`!`"),
                _ => {}
            });
            if let Some(why) = bad {
                self.err(DiagKind::Type, span, format!("a ghost function type cannot mention {why}"));
                return Ty::Error;
            }
        }
        let ret = comps.pop().unwrap_or(Ty::Error);
        if comps.is_empty() {
            self.err(DiagKind::Type, span, "a ghost function type takes at least one argument");
            return Ty::Error;
        }
        Ty::Fn(comps, Box::new(ret))
    }

    /// Function values live only in ghost parameters, ghost `let`s and lambdas:
    /// never inside data (sequences, options, tuples, arrays, references,
    /// structs, enums), whose equality and evaluation are first-order.
    pub fn no_fn_in_data(&mut self, t: &Ty, span: Span) -> Ty {
        if matches!(t, Ty::Fn(..)) || matches!(t, Ty::Tuple(ts) if ts.iter().any(|x| matches!(x, Ty::Fn(..)))) {
            self.diags.push(Diagnostic::error(DiagKind::Closure, span, "a function value cannot be stored in data, returned or instantiate a type parameter").note("ghost function types `fn(A, ..) -> B` are only the types of ghost parameters, ghost `let`s and lambdas"));
            return Ty::Error;
        }
        t.clone()
    }

    fn generic_args_of(&mut self, m: ModId, seg: &syn::PathSegment, g: &GenScope, ghost: bool) -> Vec<Ty> {
        match &seg.arguments {
            syn::PathArguments::None => vec![],
            syn::PathArguments::AngleBracketed(a) => {
                let mut out = Vec::new();
                for arg in &a.args {
                    match arg {
                        syn::GenericArgument::Type(t) => {
                            let ty = self.lower_ty(m, t, g, ghost);
                            let sp = self.sp(m, t.span());
                            out.push(self.no_fn_in_data(&ty, sp));
                        }
                        syn::GenericArgument::Lifetime(_) => {}
                        other => {
                            self.err(DiagKind::Unsupported, self.sp(m, other.span()), "unsupported generic argument");
                        }
                    }
                }
                out
            }
            syn::PathArguments::Parenthesized(p) => {
                self.err(DiagKind::Closure, self.sp(m, p.span()), "`Fn(..)` types are not supported");
                vec![]
            }
        }
    }

    fn lower_path_ty(&mut self, m: ModId, path: &syn::Path, g: &GenScope, ghost: bool, span: Span) -> Ty {
        let segs: Vec<(String, Span)> = path.segments.iter().map(|s| (s.ident.to_string(), self.sp(m, s.ident.span()))).collect();
        let last = path.segments.last().unwrap();
        // ADT lifetime arguments are recorded before the type arguments
        // (pre-order), so resolve the definition first when recording.
        let pre_def = if self.lt_rec.is_some() && !(segs.len() == 1 && (g.params.contains(&segs[0].0) || segs[0].0 == "Self")) {
            self.res.resolve_path_defs(m, &segs, Ns::Type, path.leading_colon.is_some(), ghost).ok()
        } else {
            None
        };
        if let Some(Def::Item(id)) = pre_def {
            let n = self.adt_lifetime_count(id);
            let written: Vec<syn::Lifetime> = match &last.arguments {
                syn::PathArguments::AngleBracketed(a) => a.args.iter().filter_map(|x| match x {
                    syn::GenericArgument::Lifetime(l) => Some(l.clone()),
                    _ => None,
                }).collect(),
                _ => vec![],
            };
            for i in 0..n {
                self.record_lt(written.get(i));
            }
        }
        let args = self.generic_args_of(m, last, g, ghost);
        // earlier segments must not have generic args
        for s in path.segments.iter().take(path.segments.len() - 1) {
            if !matches!(s.arguments, syn::PathArguments::None) {
                self.err(DiagKind::Unsupported, span, "generic arguments are only allowed on the last path segment of a type");
            }
        }
        if segs.len() == 1 && path.leading_colon.is_none() {
            let name = segs[0].0.as_str();
            if let Some(i) = g.params.iter().position(|p| p == name) {
                return self.no_args(Ty::Param(i as u32, name.to_string()), &args, span);
            }
            if name == "Self" {
                return match &g.self_ty {
                    Some(t) => t.clone(),
                    None => {
                        self.err(DiagKind::Resolve, span, "`Self` is only available in inherent impls");
                        Ty::Error
                    }
                };
            }
            if self.res.lookup(m, name, Ns::Type, ghost).is_none() {
                return self.prim_ty(name, span, &args);
            }
        }
        let def = match self.res.resolve_path_defs(m, &segs, Ns::Type, path.leading_colon.is_some(), ghost) {
            Ok(d) => d,
            Err(d) => {
                self.diags.push(d);
                return Ty::Error;
            }
        };
        self.def_ty(m, def, args, span, ghost)
    }

    fn no_args(&mut self, t: Ty, args: &[Ty], span: Span) -> Ty {
        if !args.is_empty() {
            self.err(DiagKind::Type, span, "unexpected generic arguments");
        }
        t
    }

    /// Primitive types by name (and precise rejections).
    pub fn prim_ty(&mut self, name: &str, span: Span, args: &[Ty]) -> Ty {
        if let Some(u) = UintTy::from_name(name) {
            return self.no_args(Ty::Uint(u), args, span);
        }
        match name {
            "bool" => self.no_args(Ty::Bool, args, span),
            "i8" | "i16" | "i32" | "i64" | "isize" => {
                self.diags.push(Diagnostic::error(DiagKind::Signed, span, format!("signed integer type `{name}` is not supported")).note("signed integers are reserved; only literal `i32` immediates of intrinsics are allowed (DESIGN.md §3.1)"));
                Ty::Error
            }
            "u128" | "i128" => {
                self.diags.push(Diagnostic::error(DiagKind::Wide, span, format!("`{name}` is not supported")).note("128-bit integers are reserved for the restricted widening multiply (DESIGN.md §9.6), not yet available"));
                Ty::Error
            }
            "f32" | "f64" => {
                self.err(DiagKind::Float, span, format!("floating point type `{name}` is not supported"));
                Ty::Error
            }
            "char" | "str" | "String" => {
                self.err(DiagKind::Unsupported, span, format!("`{name}` is not supported (no text types)"));
                Ty::Error
            }
            "Box" | "Vec" | "Rc" | "Arc" | "HashMap" | "BTreeMap" | "VecDeque" | "Cell" | "RefCell" => {
                self.diags.push(Diagnostic::error(DiagKind::Unsupported, span, format!("`{name}` is not supported")).note("no heap, collections or interior mutability (DESIGN.md §3.1)"));
                Ty::Error
            }
            _ => {
                self.err(DiagKind::Resolve, span, format!("cannot find type `{name}` in this scope"));
                Ty::Error
            }
        }
    }

    fn def_ty(&mut self, m: ModId, def: Def, args: Vec<Ty>, span: Span, ghost: bool) -> Ty {
        let _ = m;
        match def {
            Def::Item(id) => {
                let it = &self.res.items[id.0 as usize];
                if it.ghost && !ghost {
                    let name = it.name.clone();
                    self.err(DiagKind::Ghost, span, format!("exec code refers to ghost type `{name}`"));
                }
                match it.tag.clone() {
                    ItemTag::Struct { generics, .. } | ItemTag::Enum { generics, .. } => {
                        if args.len() != generics {
                            let name = it.name.clone();
                            self.err(DiagKind::Type, span, format!("`{name}` expects {generics} type argument(s), found {}", args.len()));
                            return Ty::Error;
                        }
                        Ty::Adt(id, args)
                    }
                    ItemTag::Alias => {
                        let t = self.alias_ty(id);
                        self.no_args(t, &args, span)
                    }
                    _ => {
                        let name = it.name.clone();
                        self.err(DiagKind::Type, span, format!("`{name}` is not a type"));
                        Ty::Error
                    }
                }
            }
            Def::Ext(Ext::OptionEnum) => {
                if args.len() != 1 {
                    self.err(DiagKind::Type, span, "`Option` expects one type argument");
                    return Ty::Error;
                }
                Ty::option(args.into_iter().next().unwrap())
            }
            Def::Ext(Ext::VecType(v)) => self.no_args(Ty::Vector(v), &args, span),
            Def::Ext(Ext::MaskType(8)) => Ty::Uint(UintTy::U8),
            Def::Ext(Ext::MaskType(_)) => Ty::Uint(UintTy::U16),
            Def::Ext(Ext::IntTy | Ext::PropTy | Ext::NatTy | Ext::SeqTy) => {
                if !ghost {
                    self.diags.push(Diagnostic::error(DiagKind::Ghost, span, "ghost type in exec code").note("`Int`, `Nat`, `Seq<T>` and `Prop` are only available in specs, lemmas, laws and proofs (DESIGN.md §4.1)"));
                    return Ty::Error;
                }
                match def {
                    Def::Ext(Ext::IntTy) => self.no_args(Ty::Int, &args, span),
                    Def::Ext(Ext::NatTy) => self.no_args(Ty::Nat, &args, span),
                    Def::Ext(Ext::SeqTy) => {
                        if args.len() != 1 {
                            self.err(DiagKind::Type, span, "`Seq` expects one type argument: `Seq<T>`");
                            return Ty::Error;
                        }
                        Ty::Seq(Box::new(args.into_iter().next().unwrap()))
                    }
                    _ => self.no_args(Ty::Prop, &args, span),
                }
            }
            _ => {
                self.err(DiagKind::Type, span, "expected a type");
                Ty::Error
            }
        }
    }

    /// Expanded type of an alias (cycle-checked).
    pub fn alias_ty(&mut self, id: ItemId) -> Ty {
        if let Some(t) = self.alias_tys.get(&id) {
            return t.clone();
        }
        let it = self.res.items[id.0 as usize].clone();
        if !self.alias_busy.insert(id) {
            self.err(DiagKind::Type, it.span, format!("type alias `{}` is recursive", it.name));
            return Ty::Error;
        }
        let ItemSrc::Type(src) = &it.src else { return Ty::Error };
        if !src.generics.params.is_empty() {
            self.err(DiagKind::Unsupported, it.span, "generic type aliases are not supported");
        }
        let saved = self.lt_rec.take();
        let t = self.lower_ty(it.module, &src.ty, &GenScope::default(), it.ghost);
        self.lt_rec = saved;
        self.alias_busy.remove(&id);
        self.alias_tys.insert(id, t.clone());
        t
    }

    // ------------------------------------------------------------------
    // signatures
    // ------------------------------------------------------------------

    /// Lowers every item signature.
    pub fn lower_signatures(&mut self) {
        // attributes of `impl` blocks (outer and inner), once per block
        for i in 0..self.res.impls.len() {
            let (module, ghost, attrs) = {
                let imp = &self.res.impls[i];
                (imp.module, imp.ghost, imp.item.attrs.clone())
            };
            let _ = self.common_attrs(module, &attrs, &[], ghost, spec15::Site::Impl);
        }
        let n = self.res.items.len();
        for i in 0..n {
            let id = ItemId(i as u32);
            let it = self.res.items[i].clone();
            match &it.src {
                ItemSrc::Type(src) => {
                    let (docs, allow) = self.common_attrs(it.module, &src.attrs, &[], it.ghost, spec15::Site::Alias);
                    self.item_docs.insert(id, (docs, allow));
                    let t = self.alias_ty(id);
                    let (_, lts) = self.lower_decl_ty(it.module, &src.ty, &GenScope::default(), it.ghost);
                    self.hir_items[i] = Some(hir::ItemKind::TypeAlias(hir::TypeAliasDef { ty: t, lts }));
                }
                ItemSrc::Struct(s) => {
                    let (docs, allow) = self.common_attrs(it.module, &s.attrs, &["derive", "must_use", "invariant", "view", "represents"], it.ghost, spec15::Site::Struct);
                    self.item_docs.insert(id, (docs, allow));
                    let derives = self.derives(it.module, &s.attrs, it.span, &it.name);
                    let generics = self.generics(it.module, &s.generics);
                    let g = GenScope { params: generics.iter().map(|p| p.name.clone()).collect(), self_ty: None };
                    let (shape, fields) = self.fields(it.module, &s.fields, &g, it.ghost);
                    let lifetimes = s.generics.lifetimes().map(|l| format!("'{}", l.lifetime.ident)).collect();
                    self.hir_items[i] = Some(hir::ItemKind::Struct(hir::StructDef { lifetimes, generics, shape, fields, derives, methods: vec![], invariant: None, view: None, represents: None }));
                }
                ItemSrc::Enum(e) => {
                    let (docs, allow) = self.common_attrs(it.module, &e.attrs, &["derive", "must_use", "view"], it.ghost, spec15::Site::Enum);
                    self.item_docs.insert(id, (docs, allow));
                    let derives = self.derives(it.module, &e.attrs, it.span, &it.name);
                    let generics = self.generics(it.module, &e.generics);
                    let g = GenScope { params: generics.iter().map(|p| p.name.clone()).collect(), self_ty: None };
                    let mut variants = Vec::new();
                    for v in &e.variants {
                        let vspan = self.sp(it.module, v.span());
                        if v.discriminant.is_some() {
                            self.err(DiagKind::Unsupported, vspan, "explicit enum discriminants are not supported");
                        }
                        let (vdocs, _) = self.common_attrs(it.module, &v.attrs, &[], it.ghost, spec15::Site::Variant);
                        let (shape, fields) = self.fields(it.module, &v.fields, &g, it.ghost);
                        variants.push(hir::VariantDef { name: v.ident.to_string(), shape, fields, span: vspan, docs: vdocs });
                    }
                    let lifetimes = e.generics.lifetimes().map(|l| format!("'{}", l.lifetime.ident)).collect();
                    self.hir_items[i] = Some(hir::ItemKind::Enum(hir::EnumDef { lifetimes, generics, variants, derives, methods: vec![], view: None }));
                }
                ItemSrc::Const(c) => {
                    // a ghost constant may carry `#[example(e)]` (§15.7)
                    let allowed: &[&str] = if it.ghost { &["example"] } else { &[] };
                    let (docs, allow) = self.common_attrs(it.module, &c.attrs, allowed, it.ghost, spec15::Site::Const);
                    self.item_docs.insert(id, (docs, allow));
                    let (t, lts) = self.lower_decl_ty(it.module, &c.ty, &GenScope::default(), it.ghost);
                    let t = self.no_fn_in_data(&t, it.span);
                    self.const_tys.insert(id, t);
                    self.const_lts.insert(id, lts);
                }
                ItemSrc::Fn(f) => {
                    let sig = self.fn_sig(id, &f.attrs, &f.sig, None, &GenScope::default(), &[]);
                    self.sigs.insert(id, sig);
                }
                ItemSrc::ImplFn { impl_idx, f } => {
                    let imp = &self.res.impls[*impl_idx];
                    let owner = imp.owner;
                    let (g, impl_generics) = match owner {
                        Some(o) => {
                            let impl_generics = self.generics(imp.module, &imp.item.generics.clone());
                            let params: Vec<String> = impl_generics.iter().map(|p| p.name.clone()).collect();
                            let self_ty = self.impl_self_ty(imp.module, &imp.item.self_ty.clone(), &params, o, imp.ghost);
                            (GenScope { params, self_ty: Some(self_ty) }, impl_generics)
                        }
                        None => (GenScope::default(), vec![]),
                    };
                    if let Some(o) = owner
                        && self.res.items[o.0 as usize].ghost && !it.ghost {
                            self.err(DiagKind::Ghost, it.span, "exec impl for a ghost type");
                        }
                    let mut sig = self.fn_sig(id, &f.attrs, &f.sig, owner, &g, &impl_generics);
                    let imp = &self.res.impls[*impl_idx];
                    sig.impl_block = Some(*impl_idx as u32);
                    sig.impl_lifetimes = imp.item.generics.lifetimes().map(|l| format!("'{}", l.lifetime.ident)).collect();
                    sig.impl_self_lts = match &*imp.item.self_ty {
                        syn::Type::Path(p) => match &p.path.segments.last().map(|s| s.arguments.clone()) {
                            Some(syn::PathArguments::AngleBracketed(a)) => a.args.iter().filter_map(|x| match x {
                                syn::GenericArgument::Lifetime(l) => Some(format!("'{}", l.ident)),
                                _ => None,
                            }).collect(),
                            _ => vec![],
                        },
                        _ => vec![],
                    };
                    self.sigs.insert(id, sig);
                }
            }
        }
        // method lists
        for imp in &self.res.impls {
            if let Some(o) = imp.owner {
                match &mut self.hir_items[o.0 as usize] {
                    Some(hir::ItemKind::Struct(s)) => s.methods.extend(imp.fns.iter().copied()),
                    Some(hir::ItemKind::Enum(e)) => e.methods.extend(imp.fns.iter().copied()),
                    _ => {}
                }
            }
        }
        self.check_recursive_types();
    }

    /// `Self` type of an inherent impl: the owner applied to the impl's
    /// parameters, in order (`impl<T: Copy> S<T>`).
    fn impl_self_ty(&mut self, m: ModId, self_ty: &syn::Type, params: &[String], owner: ItemId, ghost: bool) -> Ty {
        let g = GenScope { params: params.to_vec(), self_ty: None };
        let t = self.lower_ty(m, self_ty, &g, ghost);
        if let Ty::Adt(id, args) = &t {
            let ok = *id == owner && args.iter().enumerate().all(|(i, a)| matches!(a, Ty::Param(j, _) if *j as usize == i)) && args.len() == params.len();
            if !ok {
                self.err(DiagKind::Unsupported, self.sp(m, self_ty.span()), "inherent impls must be generic over exactly the type's parameters, in order");
            }
        }
        t
    }

    fn fields(&mut self, m: ModId, f: &syn::Fields, g: &GenScope, ghost: bool) -> (Shape, Vec<FieldDef>) {
        let (shape, list): (Shape, Vec<&syn::Field>) = match f {
            syn::Fields::Named(n) => (Shape::Named, n.named.iter().collect()),
            syn::Fields::Unnamed(u) => (Shape::Tuple, u.unnamed.iter().collect()),
            syn::Fields::Unit => (Shape::Unit, vec![]),
        };
        let mut out = Vec::new();
        for fd in list {
            let span = self.sp(m, fd.span());
            let (docs, _) = self.common_attrs(m, &fd.attrs, &[], ghost, spec15::Site::Field);
            let vis = vis_of(&fd.vis).unwrap_or(Vis::Private);
            let (ty, lts) = self.lower_decl_ty(m, &fd.ty, g, ghost);
            let ty = self.no_fn_in_data(&ty, span);
            out.push(FieldDef { name: fd.ident.as_ref().map(|i| i.to_string()), vis, ty, lts, span, docs });
        }
        (shape, out)
    }

    /// Whether `id` is a recursive spec type (see
    /// [`hir::Crate::is_recursive_adt`]; valid after
    /// [`Self::check_recursive_types`]).
    pub fn is_recursive_adt(&self, id: ItemId) -> bool {
        match &self.hir_items.get(id.0 as usize) {
            Some(Some(hir::ItemKind::Enum(e))) => e.variants.iter().any(|v| v.fields.iter().any(|f| matches!(&f.ty, Ty::Adt(c, _) if *c == id))),
            _ => false,
        }
    }

    /// Rejects recursive user types (§3.1), except **recursive spec
    /// types** (§15 S5, SEMANTICS.md §13.9): an enum declared in a
    /// `#[spec]` module may have fields of exactly its own type
    /// (`Cat(Tree, Tree)`), which the kernel accepts as an inductive with
    /// direct recursive occurrences (§5.4). Every other cycle — through a
    /// `Seq`, `Option`, tuple, array or reference, through another type, a
    /// struct, an exec type, or with other type arguments — stays an error
    /// (the kernel's positivity rule is syntactic: no nested occurrences).
    fn check_recursive_types(&mut self) {
        let adts: Vec<ItemId> = (0..self.hir_items.len()).map(|i| ItemId(i as u32)).filter(|i| matches!(self.hir_items[i.0 as usize], Some(hir::ItemKind::Struct(_) | hir::ItemKind::Enum(_)))).collect();
        let field_tys = |this: &Checker, id: ItemId| -> Vec<Ty> {
            match &this.hir_items[id.0 as usize] {
                Some(hir::ItemKind::Struct(s)) => s.fields.iter().map(|f| f.ty.clone()).collect(),
                Some(hir::ItemKind::Enum(e)) => e.variants.iter().flat_map(|v| v.fields.iter().map(|f| f.ty.clone())).collect(),
                _ => vec![],
            }
        };
        let children = |this: &Checker, id: ItemId| -> Vec<ItemId> {
            let mut out = Vec::new();
            for t in field_tys(this, id) {
                t.walk(&mut |x| {
                    if let Ty::Adt(c, _) = x {
                        out.push(*c);
                    }
                });
            }
            out
        };
        for &a in &adts {
            // `a`'s own fields: direct recursive occurrences `a<P0, .., Pn>`
            // (the type's parameters, in order) and everything else
            let is_direct = |t: &Ty| matches!(t, Ty::Adt(c, args) if *c == a && args.iter().enumerate().all(|(i, x)| matches!(x, Ty::Param(j, _) if *j as usize == i)));
            let mut direct = false;
            let mut stack = Vec::new();
            for t in field_tys(self, a) {
                if is_direct(&t) {
                    direct = true;
                    continue;
                }
                t.walk(&mut |x| {
                    if let Ty::Adt(c, _) = x {
                        stack.push(*c);
                    }
                });
            }
            // DFS from the other occurrences looking for `a`
            let mut seen = HashSet::new();
            let mut cyclic = false;
            while let Some(x) = stack.pop() {
                if x == a {
                    cyclic = true;
                    break;
                }
                if seen.insert(x) {
                    stack.extend(children(self, x));
                }
            }
            let it = &self.res.items[a.0 as usize];
            let (span, name) = (it.span, it.name.clone());
            let spec_enum = it.ghost && self.res.mods[it.module.0 as usize].spec && matches!(self.hir_items[a.0 as usize], Some(hir::ItemKind::Enum(_)));
            if cyclic || (direct && !spec_enum) {
                let note = if cyclic && direct && spec_enum {
                    "a recursive spec type may contain itself only as a direct field (`Cat(Tree, Tree)`), never inside a `Seq`, `Option`, tuple, array or another type (SEMANTICS.md §13.9)"
                } else {
                    "user types may not be recursive (DESIGN.md §3.1); use slices. Only an enum of a `#[spec]` module may have direct fields of its own type (SEMANTICS.md §13.9)"
                };
                self.diags.push(Diagnostic::error(DiagKind::Type, span, format!("recursive type `{name}` is not supported")).note(note));
                continue;
            }
            if direct {
                let derives = match &self.hir_items[a.0 as usize] {
                    Some(hir::ItemKind::Enum(e)) => e.derives.clone(),
                    _ => continue,
                };
                if derives.partial_eq || derives.eq {
                    self.diags.push(
                        Diagnostic::error(DiagKind::Unsupported, span, format!("`#[derive(PartialEq)]` is not supported on the recursive spec type `{name}`"))
                            .note("compare what the values stand for instead (for a tree, its evaluation); SEMANTICS.md §13.9"),
                    );
                }
            }
        }
    }

    /// Lowers a function signature and its attributes.
    fn fn_sig(&mut self, id: ItemId, attrs: &[syn::Attribute], sig: &syn::Signature, owner: Option<ItemId>, impl_g: &GenScope, impl_generics: &[TyParam]) -> FnSig {
        let it = self.res.items[id.0 as usize].clone();
        let m = it.module;
        let sig_span = self.sp(m, sig.span());
        // kind: every `fn` of a (ghost) `#[spec]` module is a spec fn unless
        // it says otherwise (§15.1)
        let in_spec_module = it.ghost && (self.res.mods[m.0 as usize].spec || self.res.mods[m.0 as usize].model);
        let mut kind = if in_spec_module { FnKind::Spec } else { FnKind::Exec };
        let mut explicit = false;
        for a in attrs {
            if let Some((an, _)) = annotation_of(a.path()) {
                let k = match an {
                    Annot::Spec => FnKind::Spec,
                    Annot::Lemma => FnKind::Lemma,
                    Annot::Law => FnKind::Law,
                    Annot::Proof => FnKind::Proof,
                    _ => continue,
                };
                if explicit {
                    self.err(DiagKind::Attribute, self.sp(m, a.span()), "a function can have only one of `#[spec]`, `#[lemma]`, `#[law]`, `#[proof]`");
                }
                kind = k;
                explicit = true;
            }
        }
        if kind.is_ghost() && !it.ghost {
            self.diags.push(
                Diagnostic::error(DiagKind::Ghost, it.span, format!("`#[{}]` functions must be ghost", kind.name()))
                    .note("add `#[cfg(sandblaster)]` or put the item in a `#[cfg(sandblaster)]` module (DESIGN.md §4.5)"),
            );
        }
        // `#[opaque]` on an exec function: only in lifted modules, where the
        // lift puts it for an attachment's `opaque();` (crate::lift)
        let lifted_mod = self.res.mods[m.0 as usize].lifted;
        let allowed: &[&str] = match kind {
            FnKind::Exec if lifted_mod => &["inline", "must_use", "target_feature", "requires", "ensures", "decreases", "implements", "specialize", "refines", "example", "section", "trusted_extern", "opaque"],
            FnKind::Exec => &["inline", "must_use", "target_feature", "requires", "ensures", "decreases", "implements", "specialize", "refines", "example", "section", "trusted_extern"],
            FnKind::Spec => &["spec", "requires", "decreases", "inline", "must_use", "example", "examples", "mirrors_impl", "assumption", "opaque"],
            // `#[rewrite]` on a lemma: an optimization lemma (`f(x̄) == g(x̄)`,
            // `driver::lowered`); proven, so it needs no human review
            FnKind::Lemma => &["lemma", "decreases", "induction", "fuel_sufficient", "rewrite"],
            FnKind::Law => &["law", "rewrite", "induction", "reduces_to", "definitional", "corollary"],
            FnKind::Proof => &["proof", "decreases", "induction"],
        };
        let (docs, allow) = self.common_attrs(m, attrs, allowed, it.ghost, spec15::Site::Fn(kind));
        self.item_docs.insert(id, (docs.clone(), allow.clone()));
        let spec = self.parse_fn_spec(m, attrs, kind, allowed);
        // qualifiers
        if let Some(c) = &sig.constness {
            self.err(DiagKind::Unsupported, self.sp(m, c.span()), "`const fn` is not supported");
        }
        if let Some(a) = &sig.asyncness {
            self.err(DiagKind::Unsupported, self.sp(m, a.span()), "`async fn` is not supported");
        }
        if let Some(u) = &sig.unsafety {
            self.diags.push(Diagnostic::error(DiagKind::Unsupported, self.sp(m, u.span()), "`unsafe fn` is not supported").note("functions with preconditions use `#[requires]`; codegen emits them as `unsafe fn` (DESIGN.md §3.1)"));
        }
        if let Some(abi) = &sig.abi {
            self.err(DiagKind::Unsupported, self.sp(m, abi.span()), "`extern` functions are not supported");
        }
        if let Some(v) = &sig.variadic {
            self.err(DiagKind::Unsupported, self.sp(m, v.span()), "variadic functions are not supported");
        }
        // generics
        let own = self.generics(m, &sig.generics);
        let mut generics: Vec<TyParam> = impl_generics.to_vec();
        generics.extend(own);
        let mut g = impl_g.clone();
        g.params = generics.iter().map(|p| p.name.clone()).collect();
        let ghost = it.ghost;
        // params
        let mut receiver = None;
        let mut params = Vec::new();
        let mut param_lts = Vec::new();
        let mut ghost_params = Vec::new();
        for (i, input) in sig.inputs.iter().enumerate() {
            match input {
                syn::FnArg::Receiver(r) => {
                    let span = self.sp(m, r.span());
                    if !r.attrs.is_empty() {
                        self.err(DiagKind::Attribute, span, "attributes are not allowed on `self` (a receiver cannot be `#[ghost]`)");
                    }
                    ghost_params.push(false);
                    if owner.is_none() && self.res.items[id.0 as usize].owner.is_none() {
                        self.err(DiagKind::Resolve, span, "`self` parameter outside an inherent impl");
                    }
                    if i != 0 {
                        self.err(DiagKind::Unsupported, span, "`self` must be the first parameter");
                    }
                    // `mut self` (a mutable by-value receiver): lifted code only, where
                    // it is the state-passing form of `&mut self` ([`crate::lift`])
                    let lifted_mut_self = r.reference.is_none() && self.res.mods[m.0 as usize].lifted;
                    if r.mutability.is_some() && !lifted_mut_self {
                        self.err(DiagKind::MutRef, span, "`mut self` / `&mut self` receivers are not supported (receivers: `self`, `&self`)");
                    }
                    if r.colon_token.is_some() {
                        self.err(DiagKind::Unsupported, span, "explicit `self: Type` receivers are not supported (receivers: `self`, `&self`)");
                    }
                    let self_ty = g.self_ty.clone().unwrap_or(Ty::Error);
                    let (rk, t) = if r.reference.is_some() { (Receiver::ByRef, Ty::reference(self_ty)) } else { (Receiver::ByValue, self_ty) };
                    receiver = Some(rk);
                    params.push(t);
                    param_lts.push(hir::Lifetimes::default());
                }
                syn::FnArg::Typed(pt) => {
                    let gp = self.param_attrs(m, &pt.attrs, kind, it.ghost);
                    ghost_params.push(gp);
                    let lifted = self.res.mods[m.0 as usize].lifted;
                    let (t, lts) = self.lower_decl_ty(m, &pt.ty, &g, ghost || gp || lifted);
                    let t = if matches!(t, Ty::Fn(..)) && !ghost {
                        let sp = self.sp(m, pt.span());
                        self.err(DiagKind::Closure, sp, "only ghost functions (spec functions, lemmas, laws, proofs) take function parameters");
                        Ty::Error
                    } else {
                        t
                    };
                    params.push(t);
                    param_lts.push(lts);
                }
            }
        }
        if let Some(first) = ghost_params.iter().position(|g| *g)
            && ghost_params[first..].iter().any(|g| !*g)
        {
            // the ghost parameters form one `Irr` binder after the others
            // (with the `requires` that mention them, `elab::items`)
            self.diags.push(
                Diagnostic::error(DiagKind::Ghost, sig_span, "`#[ghost]` parameters come after the other parameters")
                    .note("a function's ghost parameters, and the `requires` that mention them, are one irrelevant binder after its other parameters (DESIGN.md §15.3, §5.3): move the `#[ghost]` parameters to the end"),
            );
        }
        if ghost_params.iter().any(|g| *g) {
            // rustc accepts attribute macros on parameters only as inert
            // helpers of an attribute macro on the function, whose erasure
            // removes the ghost parameters in baseline builds
            let has_fn_annotation = attrs.iter().any(|a| annotation_of(a.path()).is_some_and(|(an, _)| !matches!(an, Annot::Ghost)));
            if !has_fn_annotation {
                self.diags.push(
                    Diagnostic::error(DiagKind::Attribute, sig_span, "a function with `#[ghost]` parameters needs a sandblaster function annotation (e.g. `#[requires]`, `#[ensures]`, `#[refines]`)")
                        .note("rustc accepts `#[ghost]` on a parameter only as a helper of an attribute macro on the function; that macro removes the ghost parameters in baseline builds (DESIGN.md §2, §15.3)"),
                );
            }
        }
        let (ret, ret_lts) = match &sig.output {
            syn::ReturnType::Default => (Ty::unit(), hir::Lifetimes::default()),
            syn::ReturnType::Type(_, t) => {
                let lifted = self.res.mods[m.0 as usize].lifted;
                let (r, lts) = self.lower_decl_ty(m, t, &g, ghost || lifted);
                (self.no_fn_in_data(&r, sig_span), lts)
            }
        };
        let lifetimes: Vec<String> = sig.generics.lifetimes().map(|l| format!("'{}", l.lifetime.ident)).collect();
        // attributes
        let mut target_features = Vec::new();
        let mut inline = None;
        let mut must_use = false;
        let mut specialize = false;
        let mut contracts = Contracts::default();
        for a in attrs {
            let span = self.sp(m, a.span());
            let path = a.path();
            if path.is_ident("inline") {
                inline = Some(match &a.meta {
                    syn::Meta::Path(_) => Inline::Hint,
                    syn::Meta::List(l) if l.tokens.to_string() == "always" => Inline::Always,
                    _ => {
                        self.err(DiagKind::Attribute, span, "only `#[inline]` and `#[inline(always)]` are allowed");
                        Inline::Hint
                    }
                });
            } else if path.is_ident("must_use") {
                must_use = true;
            } else if path.is_ident("target_feature") {
                match a.parse_args::<syn::MetaNameValue>() {
                    Ok(nv) if nv.path.is_ident("enable") => match &nv.value {
                        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => {
                            for f in s.value().split(',').map(str::trim).filter(|f| !f.is_empty()) {
                                if !is_known_feature(&self.res.target.arch, f) {
                                    self.err(DiagKind::Feature, span, format!("unknown target feature `{f}` for {}", self.res.target.arch.name()));
                                }
                                target_features.push(f.to_string());
                            }
                        }
                        _ => self.err(DiagKind::Attribute, span, "expected `#[target_feature(enable = \"..\")]`"),
                    },
                    _ => self.err(DiagKind::Attribute, span, "expected `#[target_feature(enable = \"..\")]`"),
                }
            } else if let Some((an, _)) = annotation_of(path) {
                match an {
                    Annot::Requires => match a.parse_args::<syn::Expr>() {
                        Ok(e) => contracts.requires.push(e),
                        Err(e) => self.err(DiagKind::Contract, span, format!("malformed `#[requires]`: {e}")),
                    },
                    Annot::Ensures => {
                        if contracts.ensures.is_some() {
                            self.err(DiagKind::Contract, span, "at most one `#[ensures]` per function");
                        }
                        match a.parse_args::<syn::Expr>() {
                            Ok(e) => contracts.ensures = Some(e),
                            Err(e) => self.err(DiagKind::Contract, span, format!("malformed `#[ensures]`: {e}")),
                        }
                    }
                    Annot::Decreases => match parse_decreases(a) {
                        Ok(d) => {
                            if contracts.decreases.is_some() {
                                self.err(DiagKind::Contract, span, "at most one `#[decreases]` per function");
                            }
                            contracts.decreases = Some(d);
                        }
                        Err(e) => self.err(DiagKind::Contract, span, e),
                    },
                    Annot::Implements => match a.parse_args::<syn::Path>() {
                        Ok(p) => contracts.implements = Some(p),
                        Err(e) => self.err(DiagKind::Contract, span, format!("malformed `#[implements]`: {e}")),
                    },
                    Annot::Specialize => specialize = true,
                    _ => {}
                }
            }
        }
        if inline == Some(Inline::Always) && !target_features.is_empty() {
            self.diags.push(Diagnostic::error(DiagKind::Attribute, sig_span, "`#[inline(always)]` cannot be combined with `#[target_feature]`").note("rustc rejects this combination (DESIGN.md §3.1)"));
        }
        let feature_set = feature_closure(&self.res.target.arch, &target_features);
        FnSig { kind, ghost, owner, receiver, generics, lifetimes, params, param_lts, ret, ret_lts, target_features, feature_set, inline, must_use, specialize, contracts, sig_span, docs, allow, gen_scope: g, impl_block: None, impl_lifetimes: vec![], impl_self_lts: vec![], spec, ghost_params }
    }

    // ------------------------------------------------------------------
    // bodies
    // ------------------------------------------------------------------

    /// The `#[example(e)]`s of a ghost constant: closed `bool` spec
    /// expressions, typed like a function's examples.
    fn const_examples(&mut self, m: ModId, attrs: &[syn::Attribute]) -> Vec<hir::Example> {
        let mut out = Vec::new();
        for a in attrs {
            if !matches!(annotation_of(a.path()), Some((Annot::Example, _))) {
                continue;
            }
            let span = self.sp(m, a.span());
            match a.parse_args::<syn::Expr>() {
                Ok(e) => {
                    let mut cx = expr::Cx::new(self, m, None, FnKind::Spec, true, Ty::Bool, GenScope::default(), vec![]);
                    let x = cx.check(&e, &Ty::Bool);
                    let locals = std::mem::take(&mut cx.locals);
                    out.push(hir::Example { expr: x, locals, span });
                }
                Err(e) => self.err(DiagKind::Attribute, span, format!("malformed `#[example]`: {e} (expected a closed `bool` spec expression)")),
            }
        }
        out
    }

    /// Type checks every constant initializer and function body.
    pub fn check_bodies(&mut self) {
        let n = self.res.items.len();
        // §15 type annotations first: bodies use the views of types for the
        // ghost view coercion (DESIGN.md §15.3)
        for i in 0..n {
            if matches!(self.res.items[i].src, ItemSrc::Struct(_) | ItemSrc::Enum(_)) {
                self.lower_type_spec(ItemId(i as u32));
            }
        }
        for i in 0..n {
            let id = ItemId(i as u32);
            let it = self.res.items[i].clone();
            match &it.src {
                ItemSrc::Const(c) => {
                    self.check_nested_attrs(it.module, None, Some(&c.expr));
                    let ty = self.const_tys.get(&id).cloned().unwrap_or(Ty::Error);
                    let (init, locals) = expr::check_const(self, id, &c.expr, &ty);
                    let value = match &ty {
                        Ty::Uint(_) => self.ce.eval_item(id).ok(),
                        Ty::Bool => match &init.kind {
                            hir::ExprKind::Lit(hir::Lit::Bool(b)) => Some(*b as u128),
                            _ => None,
                        },
                        _ => None,
                    };
                    let ty_lts = self.const_lts.get(&id).cloned().unwrap_or_default();
                    let examples = if it.ghost { self.const_examples(it.module, &c.attrs) } else { vec![] };
                    self.hir_items[i] = Some(hir::ItemKind::Const(hir::ConstDef { ty, ty_lts, init, locals, value, examples }));
                }
                ItemSrc::Fn(f) => {
                    let block = (*f.block).clone();
                    self.check_nested_attrs(it.module, Some(&block), None);
                    let inputs: Vec<syn::FnArg> = f.sig.inputs.iter().cloned().collect();
                    if let Some(def) = expr::check_fn(self, id, &inputs, &block) {
                        self.hir_items[i] = Some(hir::ItemKind::Fn(def));
                    }
                }
                ItemSrc::ImplFn { f, .. } => {
                    let block = f.block.clone();
                    self.check_nested_attrs(it.module, Some(&block), None);
                    let inputs: Vec<syn::FnArg> = f.sig.inputs.iter().cloned().collect();
                    if let Some(def) = expr::check_fn(self, id, &inputs, &block) {
                        self.hir_items[i] = Some(hir::ItemKind::Fn(def));
                    }
                }
                _ => {}
            }
        }
        self.check_imported_pattern_names();
    }
}

/// Collects the attributes nested in a body or an expression, with the
/// kind of place each one is on ([`Checker::check_nested_attrs`]). Nested
/// items are skipped (they are rejected as items); `proof!` script bodies
/// are parsed and walked.
#[derive(Default)]
struct NestedAttrs {
    found: Vec<(syn::Attribute, &'static str)>,
    /// Inside a closure parameter.
    in_param: bool,
}

impl NestedAttrs {
    const LET: &'static str = "a `let` statement";
    const PLACE: &'static str = "a statement or expression";

    fn steps(&mut self, steps: &[script::SynStep]) {
        for s in steps {
            match s {
                script::SynStep::Stmt(st) => syn::visit::Visit::visit_stmt(self, st),
                script::SynStep::Cases { range, body, .. } => {
                    syn::visit::Visit::visit_expr(self, range);
                    self.steps(body);
                }
                script::SynStep::ByCases { range, .. } => syn::visit::Visit::visit_expr(self, range),
            }
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for NestedAttrs {
    fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
        self.found.push((a.clone(), if self.in_param { "a closure parameter" } else { Self::PLACE }));
    }
    fn visit_expr_closure(&mut self, c: &'ast syn::ExprClosure) {
        c.attrs.iter().for_each(|a| self.visit_attribute(a));
        let outer = std::mem::replace(&mut self.in_param, true);
        c.inputs.iter().for_each(|p| self.visit_pat(p));
        self.in_param = outer;
        if let syn::ReturnType::Type(_, t) = &c.output {
            self.visit_type(t);
        }
        self.visit_expr(&c.body);
    }
    fn visit_local(&mut self, l: &'ast syn::Local) {
        self.found.extend(l.attrs.iter().map(|a| (a.clone(), Self::LET)));
        self.visit_pat(&l.pat);
        if let Some(init) = &l.init {
            self.visit_local_init(init);
        }
    }
    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        self.found.extend(arm.attrs.iter().map(|a| (a.clone(), "a match arm")));
        self.visit_pat(&arm.pat);
        if let Some((_, g)) = &arm.guard {
            self.visit_expr(g);
        }
        self.visit_expr(&arm.body);
    }
    fn visit_item(&mut self, _: &'ast syn::Item) {}
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if expr::is_macro(&m.path, "proof")
            && let Ok(s) = m.parse_body::<script::Steps>()
        {
            self.steps(&s.0);
        }
    }
}

/// Parses `#[decreases(e)]` / `#[decreases(e, max = C)]`.
pub fn parse_decreases(a: &syn::Attribute) -> Result<(syn::Expr, Option<u64>), String> {
    let args = a.parse_args_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated).map_err(|e| format!("malformed `#[decreases]`: {e}"))?;
    parse_decreases_args(&args.into_iter().collect::<Vec<_>>())
}

/// Shared by the attribute and the `decreases(..)` script statement.
pub fn parse_decreases_args(args: &[syn::Expr]) -> Result<(syn::Expr, Option<u64>), String> {
    match args {
        [e] => Ok((e.clone(), None)),
        [e, syn::Expr::Assign(asg)] => {
            let is_max = matches!(&*asg.left, syn::Expr::Path(p) if p.path.is_ident("max"));
            if !is_max {
                return Err("expected `max = C`".into());
            }
            match &*asg.right {
                syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(l), .. }) => {
                    let v: u64 = l.base10_parse().map_err(|e| e.to_string())?;
                    Ok((e.clone(), Some(v)))
                }
                _ => Err("`max` must be an integer literal".into()),
            }
        }
        _ => Err("expected `decreases(e)` or `decreases(e, max = C)`".into()),
    }
}
