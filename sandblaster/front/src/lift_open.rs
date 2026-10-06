//! In-place lifting, open-trait generics, operator impls and state
//! parameters (SEMANTICS.md §19.5–§19.10): the item skeleton of crates
//! whose verified code is spread over several host files
//! (commonware-storage's MMR arithmetic and Merkle proof verifier). A child
//! module of [`crate::lift`]; function bodies are rustc's MIR
//! ([`crate::mir`]).
//!
//! | Rust | lifted |
//! | --- | --- |
//! | `#[lift(in_place)] #[path = "../../src/x.rs"] mod x;` | the host's own file is the lifted source (verified where rustc compiles it) |
//! | `children = "a"` on an in-place declaration | the source's `mod a;` is lifted too, from rustc's standard location |
//! | another out-of-line `mod m;`, an item macro of another crate (`cfg_if::cfg_if!`) | dropped, listed (host code, not part of the lifted meaning) |
//! | `unverified_impls = "Tr"` | impls of `Tr` (and `Tr`'s declaration) stay unverified host code, listed |
//! | `instance = "Tr: path::S"` (an **open** trait at its one verified instance) | every type parameter bounded by `Tr` is `path::S`: the parameter is erased (`Position<F>` → `Position`, `F::X` → `path::S::X`); `unverified_instances` names the others |
//! | `impl Tr for S` of an open trait at its instance | inherent methods of `S`; `const C` → the module constant `S__C` (every `use` of `S` also imports it) |
//! | `impl Add<u64> for S` and the other operator traits, `PartialEq`, `PartialOrd`, `Ord`, `Deref`, `AsRef`, `Default`, `From`, `TryFrom`, `Iterator` | inherent methods; a trait argument other than `Self` is part of the name (`add__u64`, `eq__u64`, `from__usize`); impls on a primitive (`impl PartialEq<S> for u64`) are free functions `u64__eq__S` |
//! | impls of `Copy`, `Clone`, `Eq`, `Hash`, `Debug`, `Display` | dropped, listed (the model is by value; formatting and hashing are host code) |
//! | `#[derive(Default)]` | `fn default()` building every field's default, as rustc's derive |
//! | `PhantomData`, `core::cmp::Ordering`, `core::ops::Range<T>`, `Vec<T>` in types | `crate::__lift::{PhantomData, Ordering, Range<T>}`, `Seq<T>` |
//! | `items = "A, B"` on an in-place declaration | only those items (and impls of those types) are lifted; the rest is host code, listed (SEMANTICS.md §19.10) |
//! | an open trait declared in the lifted file, at its instance | the instance's impl and the provided methods it does not override are inherent methods of the instance; a name shared with an inherent method must be a pure delegation (impl) or the same parameters and body (provided) |
//! | an open-trait parameter in a type's arguments | dropped only where that item's own parameter was erased; substituted elsewhere (`Result<D, E>`) |
//! | `#[lift(host)]` type aliases, unit structs and their open-trait impls (in place) | host models (trusted, listed): `S::m` calls and `S::X` types read as the model |
//! | `&mut T` (a value), `&mut E` (`E: Iterator<Item: AsRef<[u8]>>`), `&mut Vec<T>`, `Option<&mut Vec<T>>` parameters | state passing: `T`, the items not yet yielded, `Seq<T>`, `Option<Seq<T>>` |

use std::collections::{HashMap, HashSet};

use proc_macro2::Span as PSpan;
use quote::{format_ident, quote, ToTokens};
use syn::spanned::Spanned;
use syn::visit_mut::VisitMut;

use super::Ctx;

// ---------------------------------------------------------------------------
// options
// ---------------------------------------------------------------------------

/// The options of a `#[lift(..)]` declaration.
#[derive(Clone, Debug, Default)]
pub struct LiftOpts {
    /// `host`: a host model (never emitted).
    pub host: bool,
    /// `in_place`: the lifted source is the host's own file (`#[path]`).
    pub in_place: bool,
    /// `unverified = "u128, i16"`: sealed-trait impl types left out.
    pub unverified: Vec<String>,
    /// `children = "iterator"`: out-of-line modules of the source lifted too.
    pub children: Vec<String>,
    /// `instance = "Family: crate::merkle::mmr::Family"`: open traits at
    /// their one verified instance.
    pub instances: Vec<(String, String)>,
    /// `unverified_instances = "Family: crate::merkle::mmb::Family"`: the
    /// other instances (reported, unchecked host code).
    pub unverified_instances: Vec<(String, String)>,
    /// `unverified_impls = "Debug, commonware_codec::Write"`: trait impls
    /// left as unverified host code (the last path segment is matched).
    pub unverified_impls: Vec<String>,
    /// `unverified_fns = "Type::method, .."`: methods of the lifted file left
    /// as unverified host code (dropped from their impl, listed; a lifted
    /// caller of one is an error). `Trait::method` names a provided method
    /// of a trait declared in the file.
    pub unverified_fns: Vec<String>,
    /// `items = "A, B"` (in place only): the items of the file to lift —
    /// the named structs, enums, traits, functions, constants and type
    /// aliases, and the impls whose self type is named; every other item is
    /// unverified host code, listed. Empty: every item.
    pub items: Vec<String>,
    /// `mir = "varint.sbmir"`: the bodies of the module's functions are read
    /// from rustc's MIR in that file (relative to the declaring file),
    /// [`crate::mir`], `docs/mir-lift.md` §20.
    pub mir: Option<String>,
}

impl LiftOpts {
    pub fn merge(&mut self, o: LiftOpts) {
        self.host |= o.host;
        self.in_place |= o.in_place;
        self.unverified.extend(o.unverified);
        self.children.extend(o.children);
        self.instances.extend(o.instances);
        self.unverified_instances.extend(o.unverified_instances);
        self.unverified_impls.extend(o.unverified_impls);
        self.unverified_fns.extend(o.unverified_fns);
        self.items.extend(o.items);
        if o.mir.is_some() {
            self.mir = o.mir;
        }
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

fn split_pairs(s: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for part in split_list(s) {
        let Some((a, b)) = part.split_once(':').filter(|(a, _)| !a.contains("::")) else {
            return Err(format!("expected `Trait: path::Type`, found `{part}`"));
        };
        out.push((a.trim().to_string(), b.trim().trim_start_matches(':').trim().to_string()));
    }
    Ok(out)
}

const LIFT_USAGE: &str = "expected `#[lift]`, `#[lift(host)]` or `#[lift(unverified = \"T, ..\")]`, and for the host's own files `#[lift(in_place, children = \"m\", instance = \"Trait: path::Type\", unverified_instances = \"Trait: path::Type\", unverified_impls = \"Trait, ..\", unverified_fns = \"Type::method, ..\", items = \"Item, ..\")]`; `mir = \"file.sbmir\"` on either reads the bodies from rustc's MIR";

/// Parses one `#[lift]` / `#[lift(..)]` attribute.
pub fn parse_lift_opts(a: &syn::Attribute) -> Result<LiftOpts, String> {
    let mut o = LiftOpts::default();
    let syn::Meta::List(_) = &a.meta else { return Ok(o) };
    let metas = a.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated).map_err(|_| LIFT_USAGE.to_string())?;
    for m in metas {
        match &m {
            syn::Meta::Path(p) if p.is_ident("host") => o.host = true,
            syn::Meta::Path(p) if p.is_ident("in_place") => o.in_place = true,
            syn::Meta::NameValue(nv) => {
                let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(ls), .. }) = &nv.value else { return Err(LIFT_USAGE.into()) };
                let v = ls.value();
                let key = nv.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
                match key.as_str() {
                    "unverified" => o.unverified.extend(split_list(&v)),
                    "children" => o.children.extend(split_list(&v)),
                    "instance" => o.instances.extend(split_pairs(&v)?),
                    "unverified_instances" => o.unverified_instances.extend(split_pairs(&v)?),
                    "unverified_impls" => o.unverified_impls.extend(split_list(&v)),
                    "unverified_fns" => o.unverified_fns.extend(split_list(&v)),
                    "items" => o.items.extend(split_list(&v)),
                    "mir" => o.mir = Some(v),
                    _ => return Err(LIFT_USAGE.into()),
                }
            }
            _ => return Err(LIFT_USAGE.into()),
        }
    }
    if !o.children.is_empty() && !o.in_place {
        return Err("`children = \"..\"` needs `in_place` (the children are the host's own files next to the source)".into());
    }
    if !o.items.is_empty() && !o.in_place {
        return Err("`items = \"..\"` needs `in_place` (it selects the verified items of a host file; a copied source is lifted whole)".into());
    }
    Ok(o)
}

// ---------------------------------------------------------------------------
// the lift-wide tables of this extension
// ---------------------------------------------------------------------------

/// What the extension knows about the lifted crate.
#[derive(Default)]
pub struct OpenCtx {
    /// Open trait → its instance path (`Family` → `crate::merkle::mmr::Family`).
    pub instances: HashMap<String, syn::Path>,
    /// Associated constants of lifted impls: `(S, C)` → `S__C`.
    pub assoc_consts: HashSet<(String, String)>,
    /// Operator / conversion impls: `(self type, trait, argument)` → method
    /// (or free function) name; the argument is `""` for `Self`.
    pub op_impls: HashMap<(String, String, String), String>,
    /// Structs with a `Deref` impl: struct → target type.
    pub deref: HashMap<String, syn::Type>,
    /// The DSL module path of each lifted module (`mmr` → `crate::merkle::mmr`).
    pub module_paths: HashMap<String, String>,
    /// Structs that get a synthesized `default()` (`#[derive(Default)]`).
    pub derive_default: HashSet<String>,
    /// The associated types of the impl being lifted (`Self::Output` ..).
    pub cur_impl_assoc: HashMap<String, syn::Type>,
    /// Associated constants whose initializer calls a function: lifted as
    /// constant functions `S__C()` (a DSL constant cannot call one).
    pub const_fns: HashSet<String>,
    /// Lifted functions with a `requires` attachment (for the record).
    pub host_obligations: Vec<(String, String)>,
    /// Lifted functions with a recursion depth bound (for the record).
    pub host_depth_bounds: Vec<(String, String)>,
    /// The module being emitted is lifted in place.
    pub cur_in_place: bool,
    /// Provided methods of the open traits declared in a lifted file, by
    /// trait: lifted at the instance unless its impl overrides them.
    pub trait_defaults: HashMap<String, Vec<syn::TraitItemFn>>,
    /// Inherent methods of the lifted structs, `(struct, method)` (a trait
    /// method of the same name must agree with them, `open_impl_method`).
    pub inherent_fns: HashMap<(String, String), syn::ImplItemFn>,
    /// Associated types of the impls of open traits at their instance,
    /// `(instance type, name)` → type: `S::Digest` names it.
    pub assoc_types: HashMap<(String, String), syn::Type>,
    /// The generic items of the lifted sources whose type parameters are
    /// erased (bounded by an open trait): name → the positions (among its
    /// type parameters) of the erased ones. Only there does erasure drop a
    /// type argument (`Position<F>` → `Position`); anywhere else an erased
    /// parameter is substituted (`Result<D, E>` → `Result<path::S, E>`).
    pub erased_params: HashMap<String, Vec<usize>>,
    /// The non-generic enums of the lifted sources (the local typing of
    /// `E::V`).
    pub enums: HashSet<String>,
}

/// Supertraits of an open trait declared in a lifted file that constrain
/// its impls only (never the meaning of a call at the instance).
pub const OPEN_MARKER_SUPERTRAITS: &[&str] = &["Clone", "Send", "Sync"];

/// Operator traits whose impls become inherent methods (their trait
/// argument, when not `Self`, is part of the name).
pub const OP_TRAITS: &[&str] = &[
    "Add", "Sub", "Mul", "Div", "Rem", "BitAnd", "BitOr", "BitXor", "Shl", "Shr", "AddAssign", "SubAssign", "MulAssign", "DivAssign", "RemAssign", "BitAndAssign", "BitOrAssign", "BitXorAssign", "ShlAssign", "ShrAssign", "PartialEq", "PartialOrd", "Ord", "From", "TryFrom",
];

/// Host traits whose impls on lifted structs become inherent methods.
pub const METHOD_TRAITS: &[&str] = &["Deref", "AsRef", "Default", "Iterator"];

/// Host traits whose impls are dropped (listed): value semantics and
/// formatting, never called by lifted code (a call would not resolve).
pub const DROPPED_TRAITS: &[&str] = &["Copy", "Clone", "Eq", "Hash", "Debug", "Display"];

/// The mangled name of an operator/conversion impl method: `m` for a trait
/// argument that is `Self` (or absent), else `m__<arg>`.
pub fn op_method_name(m: &str, arg: &str) -> String {
    if arg.is_empty() { m.to_string() } else { format!("{m}__{}", super::sanitize(arg)) }
}

/// The trait argument of an impl header (`PartialEq<u64>` → `u64`), `""`
/// for none or `Self`/the self type.
pub fn trait_arg(path: &syn::Path, self_ty: &syn::Type) -> String {
    let Some(last) = path.segments.last() else { return String::new() };
    let syn::PathArguments::AngleBracketed(a) = &last.arguments else { return String::new() };
    let Some(syn::GenericArgument::Type(t)) = a.args.iter().find(|x| matches!(x, syn::GenericArgument::Type(_))) else { return String::new() };
    let k = super::ty_key(t);
    if k == "Self" || k == super::ty_key(self_ty) { String::new() } else { k }
}

// ---------------------------------------------------------------------------
// open traits: erasure at the declared instance
// ---------------------------------------------------------------------------

/// Whether `t` names the instance (a suffix of its path: `Family`,
/// `mmr::Family`, `crate::merkle::mmr::Family`).
fn is_instance_path(p: &syn::Path, inst: &syn::Path) -> bool {
    let a: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
    let b: Vec<String> = inst.segments.iter().map(|s| s.ident.to_string()).collect();
    !a.is_empty() && a.len() <= b.len() && b[b.len() - a.len()..] == a[..] && p.segments.iter().all(|s| matches!(s.arguments, syn::PathArguments::None))
}

/// Substitutes the erased parameters of one item.
struct Erase<'a> {
    /// Erased parameter → instance path.
    params: HashMap<String, syn::Path>,
    instances: &'a HashMap<String, syn::Path>,
    /// [`OpenCtx::erased_params`].
    erased: &'a HashMap<String, Vec<usize>>,
}

impl Erase<'_> {
    fn erasable_arg(&self, a: &syn::GenericArgument) -> bool {
        let syn::GenericArgument::Type(syn::Type::Path(tp)) = a else { return false };
        if tp.qself.is_some() {
            return false;
        }
        if let Some(id) = tp.path.get_ident()
            && self.params.contains_key(&id.to_string())
        {
            return true;
        }
        self.instances.values().any(|inst| is_instance_path(&tp.path, inst))
    }

    fn erase_args(&self, p: &mut syn::Path) {
        for seg in p.segments.iter_mut() {
            // only an item whose own parameter at that position was erased
            // loses the argument (`Position<F>`, `Proof<F, D>`); elsewhere the
            // parameter is substituted by its instance (`Result<D, E>`)
            let Some(pos) = self.erased.get(&seg.ident.to_string()) else { continue };
            if let syn::PathArguments::AngleBracketed(a) = &mut seg.arguments {
                let mut ti = 0usize;
                let kept: syn::punctuated::Punctuated<syn::GenericArgument, syn::Token![,]> = a.args.iter().filter(|x| {
                    if !matches!(x, syn::GenericArgument::Type(_)) {
                        return true;
                    }
                    let i = ti;
                    ti += 1;
                    !(pos.contains(&i) && self.erasable_arg(x))
                }).cloned().collect();
                if kept.is_empty() {
                    seg.arguments = syn::PathArguments::None;
                } else {
                    a.args = kept;
                }
            }
        }
    }
}

impl VisitMut for Erase<'_> {
    fn visit_type_mut(&mut self, t: &mut syn::Type) {
        if let syn::Type::Path(tp) = t
            && tp.qself.is_none()
        {
            // `F` → the instance
            if let Some(id) = tp.path.get_ident()
                && let Some(inst) = self.params.get(&id.to_string())
            {
                tp.path = inst.clone();
                return;
            }
            // `F::X` (an associated type of the open trait) → `S::X`
            if tp.path.segments.len() == 2
                && let Some(inst) = self.params.get(&tp.path.segments[0].ident.to_string()).cloned()
            {
                let last = tp.path.segments[1].clone();
                let mut p = inst;
                p.segments.push(last);
                tp.path = p;
                return;
            }
            self.erase_args(&mut tp.path);
            // `PhantomData<..>` (its arguments erased) → the prelude marker
            if tp.path.segments.last().is_some_and(|s| s.ident == "PhantomData" && matches!(s.arguments, syn::PathArguments::None)) {
                *t = syn::parse_quote!(crate::__lift::PhantomData);
                return;
            }
        }
        syn::visit_mut::visit_type_mut(self, t);
    }

    fn visit_expr_path_mut(&mut self, e: &mut syn::ExprPath) {
        if e.qself.is_none() {
            // `F::m` → `S::m`
            if e.path.segments.len() >= 2
                && let Some(inst) = self.params.get(&e.path.segments[0].ident.to_string()).cloned()
            {
                let rest: Vec<syn::PathSegment> = e.path.segments.iter().skip(1).cloned().collect();
                let mut p = inst;
                for s in rest {
                    p.segments.push(s);
                }
                e.path = p;
                return;
            }
            self.erase_args(&mut e.path);
            if e.path.segments.last().is_some_and(|s| s.ident == "PhantomData") && e.path.segments.len() <= 3 {
                e.path = syn::parse_quote!(crate::__lift::PhantomData);
                return;
            }
        }
        syn::visit_mut::visit_expr_path_mut(self, e);
    }

    fn visit_path_mut(&mut self, p: &mut syn::Path) {
        self.erase_args(p);
        syn::visit_mut::visit_path_mut(self, p);
    }
}

/// Whether `item` is left out by an `items = ".."` selection: `None` when
/// it is lifted (a `use`, a named item, an impl of a named type), else a
/// description for the list of items left out.
fn not_selected(item: &syn::Item, sel: &[String]) -> Option<String> {
    let named = |i: &syn::Ident| sel.iter().any(|s| i == s.as_str());
    let (keep, what) = match item {
        syn::Item::Use(_) => (true, String::new()),
        syn::Item::Struct(s) => (named(&s.ident), format!("struct `{}`", s.ident)),
        syn::Item::Enum(e) => (named(&e.ident), format!("enum `{}`", e.ident)),
        syn::Item::Trait(t) => (named(&t.ident), format!("trait `{}`", t.ident)),
        syn::Item::Fn(f) => (named(&f.sig.ident), format!("function `{}`", f.sig.ident)),
        syn::Item::Const(c) => (named(&c.ident), format!("constant `{}`", c.ident)),
        syn::Item::Type(t) => (named(&t.ident), format!("type alias `{}`", t.ident)),
        syn::Item::Impl(im) => {
            let keep = super::type_name(&im.self_ty).is_some_and(|n| sel.contains(&n)) && !matches!(&*im.self_ty, syn::Type::Reference(_));
            let tn = im.trait_.as_ref().map(|(_, p, _)| format!("{} for ", p.to_token_stream().to_string().replace(' ', ""))).unwrap_or_default();
            (keep, format!("impl `{tn}{}`", super::ty_key(&im.self_ty)))
        }
        other => (false, describe_item(other)),
    };
    (!keep).then_some(what)
}

fn describe_item(item: &syn::Item) -> String {
    match item {
        syn::Item::Macro(m) => format!("item macro `{}!`", m.mac.path.to_token_stream().to_string().replace(' ', "")),
        syn::Item::Static(s) => format!("static `{}`", s.ident),
        syn::Item::Mod(m) => format!("module `{}`", m.ident),
        _ => "item".to_string(),
    }
}

/// Replaces `path::S::X` by the associated type `X` of the impl of an open
/// trait at its instance `S` (`Sha256::Digest` → the model's digest type),
/// repeatedly (an associated type may name another one: `type Digest =
/// H::Digest`), at most 8 rounds.
pub fn resolve_instance_assoc(t: &mut syn::Type, assoc: &HashMap<(String, String), syn::Type>) {
    struct R<'a> {
        assoc: &'a HashMap<(String, String), syn::Type>,
        changed: bool,
    }
    impl VisitMut for R<'_> {
        fn visit_type_mut(&mut self, t: &mut syn::Type) {
            if let syn::Type::Path(tp) = t
                && tp.qself.is_none()
                && tp.path.segments.len() >= 2
            {
                let n = tp.path.segments.len();
                let s = tp.path.segments[n - 2].ident.to_string();
                let x = tp.path.segments[n - 1].ident.to_string();
                if matches!(tp.path.segments[n - 1].arguments, syn::PathArguments::None)
                    && let Some(new) = self.assoc.get(&(s, x))
                {
                    *t = new.clone();
                    self.changed = true;
                    return;
                }
            }
            syn::visit_mut::visit_type_mut(self, t);
        }
    }
    for _ in 0..8 {
        let mut r = R { assoc, changed: false };
        r.visit_type_mut(t);
        if !r.changed {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// state parameters beyond `&mut self` and the buffers (SEMANTICS.md §19.1)
// ---------------------------------------------------------------------------

/// The type parameters of `g` bounded by `Iterator<Item: AsRef<[u8]>>` (or
/// `Iterator<Item = &[u8]>`): an iterator of byte strings, which the lift
/// reads as the items it has not yielded yet (`state_param`).
pub fn byte_iter_params(g: &syn::Generics) -> HashSet<String> {
    fn is_bytes_ref(t: &syn::Type) -> bool {
        matches!(t, syn::Type::Reference(r) if r.mutability.is_none() && matches!(&*r.elem, syn::Type::Slice(sl) if matches!(&*sl.elem, syn::Type::Path(p) if p.path.is_ident("u8"))))
    }
    fn as_ref_bytes(b: &syn::TypeParamBound) -> bool {
        let syn::TypeParamBound::Trait(tb) = b else { return false };
        let Some(last) = tb.path.segments.last() else { return false };
        if last.ident != "AsRef" {
            return false;
        }
        let syn::PathArguments::AngleBracketed(a) = &last.arguments else { return false };
        a.args.len() == 1 && matches!(a.args.first(), Some(syn::GenericArgument::Type(syn::Type::Slice(sl))) if matches!(&*sl.elem, syn::Type::Path(p) if p.path.is_ident("u8")))
    }
    fn byte_iter_bound(b: &syn::TypeParamBound) -> bool {
        let syn::TypeParamBound::Trait(tb) = b else { return false };
        let Some(last) = tb.path.segments.last() else { return false };
        if last.ident != "Iterator" {
            return false;
        }
        let syn::PathArguments::AngleBracketed(a) = &last.arguments else { return false };
        a.args.len() == 1
            && match a.args.first() {
                Some(syn::GenericArgument::Constraint(c)) => c.ident == "Item" && c.bounds.len() == 1 && c.bounds.iter().all(as_ref_bytes),
                Some(syn::GenericArgument::AssocType(at)) => at.ident == "Item" && is_bytes_ref(&at.ty),
                _ => false,
            }
    }
    let mut out = HashSet::new();
    for p in &g.params {
        if let syn::GenericParam::Type(tp) = p
            && tp.bounds.len() == 1
            && tp.bounds.iter().all(byte_iter_bound)
        {
            out.insert(tp.ident.to_string());
        }
    }
    if let Some(w) = &g.where_clause {
        for pred in &w.predicates {
            if let syn::WherePredicate::Type(pt) = pred
                && let syn::Type::Path(tp) = &pt.bounded_ty
                && let Some(id) = tp.path.get_ident()
                && pt.bounds.len() == 1
                && pt.bounds.iter().all(byte_iter_bound)
            {
                out.insert(id.to_string());
            }
        }
    }
    out
}

/// `T` of `Option<&mut Vec<T>>`.
fn option_mut_vec(t: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(p) = t else { return None };
    let last = p.path.segments.last()?;
    if last.ident != "Option" || p.qself.is_some() {
        return None;
    }
    let syn::PathArguments::AngleBracketed(a) = &last.arguments else { return None };
    let Some(syn::GenericArgument::Type(syn::Type::Reference(r))) = a.args.first() else { return None };
    r.mutability?;
    vec_elem(&r.elem)
}

/// `T` of `Vec<T>` (`alloc::vec::Vec`, `std::vec::Vec`), or of the `Seq<T>`
/// the lift already read it as (`CorePaths` runs before the parameters are
/// read).
pub fn vec_elem(t: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(p) = t else { return None };
    if p.qself.is_some() || !(core_prefixed(&p.path, "Vec", &[&[], &["vec"], &["alloc", "vec"], &["std", "vec"]]) || p.path.is_ident("Seq") || matches!(p.path.segments.first(), Some(s) if s.ident == "Seq" && p.path.segments.len() == 1)) {
        return None;
    }
    let syn::PathArguments::AngleBracketed(a) = &p.path.segments.last()?.arguments else { return None };
    match a.args.first() {
        Some(syn::GenericArgument::Type(t)) if a.args.len() == 1 => Some(t.clone()),
        _ => None,
    }
}

/// A state parameter (state passing, SEMANTICS.md §19.1: rustc checked the
/// exclusive borrow, so nothing else observes the state during the call; the
/// function takes it by value and returns it): the model type, the type its
/// name has in the body, and whether that is a marker (`__Buf`, ..).
///
/// | parameter | state | body |
/// | --- | --- | --- |
/// | `&mut impl Buf`, `&mut impl BufMut` | `Seq<u8>` | the buffer marker |
/// | `&mut E`, `E: Iterator<Item: AsRef<[u8]>>` | `&[&[u8]]`: the items not yet yielded, each as the bytes its `as_ref()` returns (host assumption: the iterator yields a fixed sequence and `as_ref` is pure, as for slice iterators over `&[u8]`, `Vec<u8>`, `[u8; N]`) | the iterator marker `__BytesIter` |
/// | `&mut Vec<T>` | `Seq<T>` (its elements) | the same |
/// | `Option<&mut Vec<T>>` | `Option<Seq<T>>` | the same |
/// | `&mut T`, `T` a value type (an integer, `bool`, a lifted struct) | `T` | `T` (`*x` is `x`) |
pub fn state_param(t: &syn::Type, byte_iters: &HashSet<String>) -> Option<(syn::Type, syn::Type, bool)> {
    if let Some(kind) = super::state_kind(t) {
        return Some((syn::parse_quote!(Seq<u8>), kind, true));
    }
    if let Some(inner) = option_mut_vec(t) {
        let st: syn::Type = syn::parse_quote!(Option<Seq<#inner>>);
        return Some((st.clone(), st, false));
    }
    let syn::Type::Reference(r) = t else { return None };
    r.mutability?;
    if let syn::Type::Path(p) = &*r.elem
        && p.qself.is_none()
        && let Some(id) = p.path.get_ident()
        && byte_iters.contains(&id.to_string())
    {
        return Some((syn::parse_quote!(&[&[u8]]), syn::parse_quote!(__BytesIter), true));
    }
    if let Some(inner) = vec_elem(&r.elem) {
        let st: syn::Type = syn::parse_quote!(Seq<#inner>);
        return Some((st.clone(), st, false));
    }
    match &*r.elem {
        syn::Type::Path(p) if p.qself.is_none() => {
            let n = p.path.segments.last()?.ident.to_string();
            // a value type: an integer, `bool`, or a named (lifted) type; never a
            // type parameter the lift does not know (it would not type check)
            (super::is_prim(&n) || n == "bool" || p.path.segments.len() > 1 || n.chars().next().is_some_and(|c| c.is_ascii_uppercase())).then(|| ((*r.elem).clone(), (*r.elem).clone(), false))
        }
        syn::Type::Tuple(_) | syn::Type::Array(_) => Some(((*r.elem).clone(), (*r.elem).clone(), false)),
        _ => None,
    }
}

/// The place a state argument names: `&mut x` and `x` are `x`; `x.as_deref_mut()`
/// of an `Option<&mut Vec<T>>` state is `x` (the same exclusive borrow).
pub fn state_place(a: &syn::Expr) -> syn::Expr {
    match a {
        syn::Expr::Reference(r) if r.mutability.is_some() => (*r.expr).clone(),
        syn::Expr::MethodCall(mc) if mc.method == "as_deref_mut" && mc.args.is_empty() => (*mc.receiver).clone(),
        syn::Expr::Paren(p) => state_place(&p.expr),
        other => other.clone(),
    }
}

/// The positions of the type parameters of `g` bounded by an open trait
/// (inline or in the `where` clause).
pub fn open_param_positions(g: &syn::Generics, instances: &HashMap<String, syn::Path>) -> Vec<usize> {
    let bound_open = |bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>| bounds.iter().any(|b| matches!(b, syn::TypeParamBound::Trait(tb) if tb.path.segments.last().is_some_and(|s| instances.contains_key(&s.ident.to_string()))));
    let mut out = Vec::new();
    for (i, tp) in g.type_params().enumerate() {
        let mut open = bound_open(&tp.bounds);
        if let Some(w) = &g.where_clause {
            for pred in &w.predicates {
                if let syn::WherePredicate::Type(pt) = pred
                    && matches!(&pt.bounded_ty, syn::Type::Path(p) if p.path.is_ident(&tp.ident))
                    && bound_open(&pt.bounds)
                {
                    open = true;
                }
            }
        }
        if open {
            out.push(i);
        }
    }
    out
}

/// [`OpenCtx::erased_params`] of `items` (inline modules included).
pub fn collect_erased_params(items: &[syn::Item], instances: &HashMap<String, syn::Path>, out: &mut HashMap<String, Vec<usize>>) {
    // `PhantomData<F>` loses its argument (it becomes the prelude's unit marker)
    out.insert("PhantomData".into(), vec![0]);
    for it in items {
        let (name, g) = match it {
            syn::Item::Struct(s) => (s.ident.to_string(), &s.generics),
            syn::Item::Enum(e) => (e.ident.to_string(), &e.generics),
            syn::Item::Trait(t) => (t.ident.to_string(), &t.generics),
            syn::Item::Type(t) => (t.ident.to_string(), &t.generics),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_erased_params(inner, instances, out);
                }
                continue;
            }
            _ => continue,
        };
        let pos = open_param_positions(g, instances);
        if !pos.is_empty() {
            out.insert(name, pos);
        }
    }
}

/// Removes the generic parameters bounded by an open trait from `g` and
/// returns them with their instances.
fn take_open_params(g: &mut syn::Generics, instances: &HashMap<String, syn::Path>) -> Result<HashMap<String, syn::Path>, String> {
    let mut out = HashMap::new();
    let bound_names = |bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>| -> Vec<String> {
        bounds.iter().filter_map(|b| match b {
            syn::TypeParamBound::Trait(tb) => tb.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        }).collect()
    };
    let mut where_bounds: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(w) = &g.where_clause {
        for pred in &w.predicates {
            if let syn::WherePredicate::Type(pt) = pred
                && let syn::Type::Path(tp) = &pt.bounded_ty
                && let Some(id) = tp.path.get_ident()
            {
                where_bounds.entry(id.to_string()).or_default().extend(bound_names(&pt.bounds));
            }
        }
    }
    let mut kept = syn::punctuated::Punctuated::<syn::GenericParam, syn::Token![,]>::new();
    for p in std::mem::take(&mut g.params) {
        if let syn::GenericParam::Type(tp) = &p {
            let n = tp.ident.to_string();
            let mut bs = bound_names(&tp.bounds);
            bs.extend(where_bounds.get(&n).cloned().unwrap_or_default());
            let open: Vec<&String> = bs.iter().filter(|b| instances.contains_key(*b)).collect();
            if let Some(first) = open.first() {
                let inst = instances[*first].clone();
                for o in &open[1..] {
                    if super::path_key(&instances[*o]) != super::path_key(&inst) {
                        return Err(format!("type parameter `{n}` is bounded by open traits with different instances (`{first}`, `{o}`)"));
                    }
                }
                out.insert(n, inst);
                continue;
            }
        }
        kept.push(p);
    }
    g.params = kept;
    if let Some(w) = &mut g.where_clause {
        let preds: syn::punctuated::Punctuated<syn::WherePredicate, syn::Token![,]> = w
            .predicates
            .iter()
            .filter(|pred| !matches!(pred, syn::WherePredicate::Type(pt) if matches!(&pt.bounded_ty, syn::Type::Path(tp) if tp.path.get_ident().is_some_and(|i| out.contains_key(&i.to_string())))))
            .cloned()
            .collect();
        w.predicates = preds;
        if w.predicates.is_empty() {
            g.where_clause = None;
        }
    }
    Ok(out)
}

impl Ctx {
    /// Erases the open-trait parameters of every item (module docs).
    pub(super) fn erase_open_generics(&mut self, items: &mut Vec<syn::Item>) {
        if self.open.instances.is_empty() {
            return;
        }
        let instances = self.open.instances.clone();
        let mut keep = Vec::new();
        for mut item in std::mem::take(items) {
            let generics: Option<&mut syn::Generics> = match &mut item {
                syn::Item::Struct(s) => Some(&mut s.generics),
                syn::Item::Enum(e) => Some(&mut e.generics),
                syn::Item::Fn(f) => Some(&mut f.sig.generics),
                syn::Item::Impl(im) => Some(&mut im.generics),
                syn::Item::Type(t) => Some(&mut t.generics),
                syn::Item::Trait(t) => Some(&mut t.generics),
                _ => None,
            };
            let params = match generics.map(|g| take_open_params(g, &instances)) {
                Some(Ok(p)) => p,
                Some(Err(e)) => {
                    self.err(item.span(), e);
                    HashMap::new()
                }
                None => HashMap::new(),
            };
            // methods of an impl may have open parameters of their own
            let mut method_params: HashMap<String, syn::Path> = HashMap::new();
            if let syn::Item::Impl(im) = &mut item {
                for ii in im.items.iter_mut() {
                    if let syn::ImplItem::Fn(f) = ii {
                        match take_open_params(&mut f.sig.generics, &instances) {
                            Ok(p) => method_params.extend(p),
                            Err(e) => self.err(f.sig.span(), e),
                        }
                    }
                }
            }
            let mut all = params;
            all.extend(method_params);
            let written = match &item {
                syn::Item::Impl(im) => super::ty_key(&im.self_ty),
                _ => String::new(),
            };
            let erased = std::mem::take(&mut self.open.erased_params);
            let mut er = Erase { params: all, instances: &instances, erased: &erased };
            er.visit_item_mut(&mut item);
            self.open.erased_params = erased;
            // an impl of an open trait for another type than its instance (a
            // reference or blanket impl included; judged after erasure, so
            // `Standard<H>` at `H`'s instance is `Standard`): an unverified instance
            if let syn::Item::Impl(im) = &item
                && let Some((_, tp, _)) = &im.trait_
                && let Some(tn) = tp.segments.last().map(|s| s.ident.to_string())
                && let Some(inst) = instances.get(&tn)
                && !matches!(&*im.self_ty, syn::Type::Path(st) if is_instance_path(&st.path, inst))
            {
                self.note_left_out(im);
                self.drop_item(im.span(), format!("impl `{tn}` for `{written}`"), "an instance of the open trait other than the verified one (`instance = ..`): unverified host code");
                continue;
            }
            keep.push(item);
        }
        *items = keep;
    }

    /// Drops the host items of a lifted source (module docs): out-of-line
    /// modules that are not lifted children, item macros of other crates,
    /// impls of the declared `unverified_impls` traits and their
    /// declarations.
    pub(super) fn host_filter(&mut self, items: Vec<syn::Item>, opts: &LiftOpts, children: &[String]) -> Vec<syn::Item> {
        let unverified_impl = |p: &syn::Path| p.segments.last().is_some_and(|s| opts.unverified_impls.iter().any(|u| u.rsplit("::").next() == Some(&s.ident.to_string())));
        let mut out = Vec::new();
        for item in items {
            // `items = ".."`: only the named items (and the impls of named types) are lifted
            if !opts.items.is_empty()
                && let Some(what) = not_selected(&item, &opts.items)
            {
                self.note_left_out(&item);
                self.drop_item(item.span(), what, "not among the file's selected `items`: unchecked host code");
                continue;
            }
            match &item {
                syn::Item::Mod(m) if m.content.is_none() => {
                    if !children.iter().any(|c| m.ident == c.as_str()) {
                        self.drop_item(m.span(), format!("module `{}`", m.ident), "a host module of the lifted file (not declared a lifted child)");
                    }
                    continue;
                }
                syn::Item::Macro(m) if m.mac.path.segments.len() >= 2 => {
                    self.note_left_out(m);
                    let name = m.mac.path.to_token_stream().to_string().replace(' ', "");
                    self.drop_item(m.span(), format!("item macro `{name}!`"), "a macro of another crate (host code; the items it expands to are not part of the lifted meaning)");
                    continue;
                }
                syn::Item::Impl(im) if im.trait_.as_ref().is_some_and(|(_, p, _)| unverified_impl(p)) => {
                    self.note_left_out(im);
                    let tn = im.trait_.as_ref().map(|(_, p, _)| p.to_token_stream().to_string().replace(' ', "")).unwrap_or_default();
                    self.drop_item(im.span(), format!("impl `{tn}` for `{}`", super::ty_key(&im.self_ty)), "declared `unverified_impls`: unchecked host code");
                    continue;
                }
                syn::Item::Impl(im) if im.trait_.as_ref().is_some_and(|(_, p, _)| p.segments.last().is_some_and(|s| DROPPED_TRAITS.contains(&s.ident.to_string().as_str()))) => {
                    self.note_left_out(im);
                    let tn = im.trait_.as_ref().map(|(_, p, _)| p.to_token_stream().to_string().replace(' ', "")).unwrap_or_default();
                    self.drop_item(im.span(), format!("impl `{tn}` for `{}`", super::ty_key(&im.self_ty)), "value semantics or formatting (the model is by value; `Copy`/`Clone` are derived on the model; formatting and hashing are host code)");
                    continue;
                }
                syn::Item::Trait(t) if opts.unverified_impls.iter().any(|u| u.rsplit("::").next() == Some(&t.ident.to_string())) => {
                    self.note_left_out(t);
                    self.drop_item(t.span(), format!("trait `{}`", t.ident), "declared `unverified_impls`: its impls are unchecked host code");
                    continue;
                }
                _ => {}
            }
            // declared unverified methods: dropped from their impl
            let mut item = item;
            if let syn::Item::Trait(t) = &mut item
                && !opts.unverified_fns.is_empty()
            {
                let tn = t.ident.to_string();
                let mut dropped = Vec::new();
                let mut left_out = Vec::new();
                t.items.retain(|ti| match ti {
                    syn::TraitItem::Fn(f) if f.default.is_some() && opts.unverified_fns.iter().any(|u| *u == format!("{tn}::{}", f.sig.ident)) => {
                        dropped.push((f.sig.ident.span(), format!("{tn}::{}", f.sig.ident)));
                        left_out.push(f.to_token_stream());
                        false
                    }
                    _ => true,
                });
                for ts in left_out {
                    self.note_left_out(&ts);
                }
                for (sp, name) in dropped {
                    self.drop_item(sp, format!("provided method `{name}`"), "declared `unverified_fns`: unchecked host code (the verified instance has no such method; a lifted caller does not load)");
                }
            }
            if let syn::Item::Impl(im) = &mut item
                && !opts.unverified_fns.is_empty()
                && let Some(tn) = super::type_name(&im.self_ty)
            {
                let mut dropped = Vec::new();
                let mut left_out = Vec::new();
                im.items.retain(|ii| match ii {
                    syn::ImplItem::Fn(f) if opts.unverified_fns.iter().any(|u| *u == format!("{tn}::{}", f.sig.ident)) => {
                        dropped.push((f.sig.ident.span(), format!("{tn}::{}", f.sig.ident)));
                        left_out.push(f.to_token_stream());
                        false
                    }
                    _ => true,
                });
                for ts in left_out {
                    self.note_left_out(&ts);
                }
                for (sp, name) in dropped {
                    self.drop_item(sp, format!("method `{name}`"), "declared `unverified_fns`: unchecked host code");
                }
            }
            out.push(item);
        }
        out
    }

}

// ---------------------------------------------------------------------------
// pruning unused imports and type aliases (in-place modules)
// ---------------------------------------------------------------------------

/// The names `items` (except the skipped ones) can refer to through an
/// import: the first segment of every path (in expressions, types,
/// patterns, attributes and macro bodies such as `proof! { .. }`).
fn used_idents(items: &[syn::Item], skip: &[usize]) -> HashSet<String> {
    struct V<'a>(&'a mut HashSet<String>);
    impl<'ast> syn::visit::Visit<'ast> for V<'_> {
        fn visit_path(&mut self, p: &'ast syn::Path) {
            if p.leading_colon.is_none()
                && let Some(f) = p.segments.first()
            {
                self.0.insert(f.ident.to_string());
            }
            syn::visit::visit_path(self, p);
        }
        fn visit_macro(&mut self, m: &'ast syn::Macro) {
            // macro bodies (`proof!`, `seq!`, attribute arguments): every identifier
            fn walk(ts: proc_macro2::TokenStream, out: &mut HashSet<String>) {
                for tt in ts {
                    match tt {
                        proc_macro2::TokenTree::Group(g) => walk(g.stream(), out),
                        proc_macro2::TokenTree::Ident(i) => {
                            out.insert(i.to_string());
                        }
                        _ => {}
                    }
                }
            }
            walk(m.tokens.clone(), self.0);
            syn::visit::visit_macro(self, m);
        }
        fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
            // a contract is an expression: its paths name what they use (a
            // qualified `crate::m::T::f` does not use an import of `T`)
            let contract = ["requires", "ensures", "invariant"].iter().any(|k| a.path().is_ident(k));
            if contract && let Ok(e) = a.parse_args::<syn::Expr>() {
                syn::visit::Visit::visit_expr(self, &e);
                return;
            }
            if let syn::Meta::List(ml) = &a.meta {
                fn walk(ts: proc_macro2::TokenStream, out: &mut HashSet<String>) {
                    for tt in ts {
                        match tt {
                            proc_macro2::TokenTree::Group(g) => walk(g.stream(), out),
                            proc_macro2::TokenTree::Ident(i) => {
                                out.insert(i.to_string());
                            }
                            _ => {}
                        }
                    }
                }
                walk(ml.tokens.clone(), self.0);
            }
        }
    }
    let mut out = HashSet::new();
    for (i, it) in items.iter().enumerate() {
        if !skip.contains(&i) {
            syn::visit::Visit::visit_item(&mut V(&mut out), it);
        }
    }
    out
}

/// Drops the leaves of a use tree whose imported name is unused; `false`
/// when nothing is left.
fn prune_use_tree(t: &mut syn::UseTree, used: &HashSet<String>, last: Option<&str>) -> bool {
    match t {
        syn::UseTree::Path(p) => {
            let id = p.ident.to_string();
            prune_use_tree(&mut p.tree, used, Some(&id))
        }
        syn::UseTree::Name(n) => {
            let s = n.ident.to_string();
            if s == "self" { last.is_some_and(|l| used.contains(l)) } else { used.contains(&s) }
        }
        syn::UseTree::Rename(r) => {
            let s = r.rename.to_string();
            s != "_" && used.contains(&s)
        }
        syn::UseTree::Glob(_) => true,
        syn::UseTree::Group(g) => {
            let items: Vec<syn::UseTree> = std::mem::take(&mut g.items).into_iter().filter_map(|mut x| if prune_use_tree(&mut x, used, last) { Some(x) } else { None }).collect();
            g.items = items.into_iter().collect();
            !g.items.is_empty()
        }
    }
}

/// `use a::{self}` → `use a;` (the DSL's `use` form).
fn simplify_self_use(t: &mut syn::UseTree) {
    match t {
        syn::UseTree::Path(p) => {
            if let syn::UseTree::Group(g) = &*p.tree
                && g.items.len() == 1
                && matches!(&g.items[0], syn::UseTree::Name(n) if n.ident == "self")
            {
                *t = syn::UseTree::Name(syn::UseName { ident: p.ident.clone() });
                return;
            }
            simplify_self_use(&mut p.tree);
        }
        syn::UseTree::Group(g) => {
            for x in g.items.iter_mut() {
                simplify_self_use(x);
            }
        }
        _ => {}
    }
}

impl Ctx {
    /// Prunes an in-place module's lifted items: `use` leaves and type
    /// aliases no other item names (neither is code: an unused one cannot
    /// change a meaning, and a used one is kept, so it resolves or fails).
    pub(super) fn prune_unused(&mut self, items: &mut Vec<syn::Item>) {
        // type aliases, to a fixpoint (an alias may be used by another)
        loop {
            let uses: Vec<usize> = items.iter().enumerate().filter(|(_, i)| matches!(i, syn::Item::Use(_))).map(|(k, _)| k).collect();
            let mut drop_at = None;
            for (k, it) in items.iter().enumerate() {
                if let syn::Item::Type(t) = it {
                    let mut skip = uses.clone();
                    skip.push(k);
                    if !used_idents(items, &skip).contains(&t.ident.to_string()) {
                        drop_at = Some(k);
                        break;
                    }
                }
            }
            let Some(k) = drop_at else { break };
            let it = items.remove(k);
            if let syn::Item::Type(t) = it {
                self.drop_item(t.span(), format!("type alias `{}`", t.ident), "not used by the lifted code (a type, not code)");
            }
        }
        // `use` leaves named by no non-`use` item
        let uses: Vec<usize> = items.iter().enumerate().filter(|(_, i)| matches!(i, syn::Item::Use(_))).map(|(k, _)| k).collect();
        let used = used_idents(items, &uses);
        let mut out = Vec::new();
        for mut it in std::mem::take(items) {
            if let syn::Item::Use(u) = &mut it {
                if !prune_use_tree(&mut u.tree, &used, None) {
                    continue;
                }
                simplify_self_use(&mut u.tree);
            }
            out.push(it);
        }
        *items = out;
    }
}

/// Whether an expression calls a function or a method.
/// A method whose body is exactly a call of the method of the same name
/// on `self` with its parameters in order: `Self::m(self, a, ..)` or
/// `self.m(a, ..)` (`open_impl_items`).
pub fn is_delegation(f: &syn::ImplItemFn) -> bool {
    let m = f.sig.ident.to_string();
    let mut params: Vec<String> = Vec::new();
    for i in &f.sig.inputs {
        match i {
            syn::FnArg::Receiver(r) if r.reference.is_some() && r.mutability.is_none() => {}
            syn::FnArg::Typed(pt) => match &*pt.pat {
                syn::Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none() => params.push(pi.ident.to_string()),
                _ => return false,
            },
            _ => return false,
        }
    }
    if !matches!(f.sig.inputs.first(), Some(syn::FnArg::Receiver(_))) || f.block.stmts.len() != 1 {
        return false;
    }
    let syn::Stmt::Expr(e, None) = &f.block.stmts[0] else { return false };
    let is_param = |e: &syn::Expr, want: &str| matches!(e, syn::Expr::Path(p) if p.qself.is_none() && p.path.is_ident(want));
    match e {
        syn::Expr::Call(c) => {
            let syn::Expr::Path(fp) = &*c.func else { return false };
            let segs: Vec<String> = fp.path.segments.iter().map(|s| s.ident.to_string()).collect();
            fp.qself.is_none() && segs == ["Self".to_string(), m] && c.args.len() == params.len() + 1 && is_param(&c.args[0], "self") && c.args.iter().skip(1).zip(&params).all(|(a, p)| is_param(a, p))
        }
        syn::Expr::MethodCall(mc) => mc.method == m.as_str() && mc.turbofish.is_none() && is_param(&mc.receiver, "self") && mc.args.len() == params.len() && mc.args.iter().zip(&params).all(|(a, p)| is_param(a, p)),
        _ => false,
    }
}

pub fn has_call(e: &syn::Expr) -> bool {
    struct V(bool);
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr_call(&mut self, _: &'ast syn::ExprCall) {
            self.0 = true;
        }
        fn visit_expr_method_call(&mut self, _: &'ast syn::ExprMethodCall) {
            self.0 = true;
        }
    }
    let mut v = V(false);
    syn::visit::Visit::visit_expr(&mut v, e);
    v.0
}

/// The mangled constant of an associated constant: `S__C`.
pub fn const_name(s: &str, c: &str) -> String {
    format!("{s}__{c}")
}

// ---------------------------------------------------------------------------
// core paths
// ---------------------------------------------------------------------------

/// Paths of core items with a prelude model: `core::cmp::Ordering`,
/// `PhantomData`, `core::ops::Range`, `Vec`.
pub struct CorePaths;

fn core_prefixed(p: &syn::Path, name: &str, prefixes: &[&[&str]]) -> bool {
    let segs: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
    let Some((last, init)) = segs.split_last() else { return false };
    last == name && prefixes.iter().any(|pre| init.len() == pre.len() && init.iter().zip(pre.iter()).all(|(a, b)| a == b))
}

impl VisitMut for CorePaths {
    fn visit_type_mut(&mut self, t: &mut syn::Type) {
        if let syn::Type::Path(tp) = t
            && tp.qself.is_none()
        {
            if core_prefixed(&tp.path, "Ordering", &[&[], &["cmp"], &["core", "cmp"], &["std", "cmp"]]) {
                *t = syn::parse_quote!(crate::__lift::Ordering);
                return;
            }
            if core_prefixed(&tp.path, "PhantomData", &[&[], &["marker"], &["core", "marker"], &["std", "marker"]]) && tp.path.segments.last().is_some_and(|s| matches!(s.arguments, syn::PathArguments::None)) {
                *t = syn::parse_quote!(crate::__lift::PhantomData);
                return;
            }
            // `core::ops::Range<T>`: the prelude struct with its two fields
            if core_prefixed(&tp.path, "Range", &[&[], &["ops"], &["core", "ops"], &["std", "ops"]])
                && let Some(syn::PathArguments::AngleBracketed(a)) = tp.path.segments.last().map(|s| s.arguments.clone())
                && a.args.len() == 1
            {
                let args = a.args.clone();
                *t = syn::parse_quote!(crate::__lift::Range<#args>);
                syn::visit_mut::visit_type_mut(self, t);
                return;
            }
            // `Vec<T>`: the sequence of its elements (ghost `Seq<T>`: lifted code
            // is checked, never printed)
            if let Some(el) = vec_elem(t) {
                *t = syn::parse_quote!(Seq<#el>);
                syn::visit_mut::visit_type_mut(self, t);
                return;
            }
        }
        syn::visit_mut::visit_type_mut(self, t);
    }
    fn visit_expr_path_mut(&mut self, e: &mut syn::ExprPath) {
        if e.qself.is_none() {
            if core_prefixed(&e.path, "PhantomData", &[&[], &["marker"], &["core", "marker"], &["std", "marker"]]) {
                e.path = syn::parse_quote!(crate::__lift::PhantomData);
                return;
            }
            // `Ordering::Less` (and the core-qualified forms)
            let segs: Vec<String> = e.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if segs.len() >= 2 && segs[segs.len() - 2] == "Ordering" && matches!(segs[segs.len() - 1].as_str(), "Less" | "Equal" | "Greater") {
                let mut prefix = e.path.clone();
                prefix.segments.pop();
                let pre = prefix.segments.pop().map(|p| p.into_value());
                let _ = pre;
                if core_prefixed(&syn::parse_str::<syn::Path>(&segs[..segs.len() - 1].join("::")).unwrap(), "Ordering", &[&[], &["cmp"], &["core", "cmp"], &["std", "cmp"]]) {
                    let v = format_ident!("{}", segs[segs.len() - 1]);
                    e.path = syn::parse_quote!(crate::__lift::Ordering::#v);
                    return;
                }
            }
        }
        syn::visit_mut::visit_expr_path_mut(self, e);
    }
}

// ---------------------------------------------------------------------------
// impls: declarations and emission
// ---------------------------------------------------------------------------

impl Ctx {
    /// Registers an impl this extension lifts (open-trait instances,
    /// operator and method traits); `true` when the impl is handled here.
    pub(super) fn collect_open_impl(&mut self, im: &syn::ItemImpl) -> bool {
        let Some((_, tp, _)) = &im.trait_ else { return false };
        let Some(tname) = tp.segments.last().map(|s| s.ident.to_string()) else { return false };
        let Some(sn) = super::type_name(&im.self_ty) else { return false };
        let prim_self = super::is_prim(&sn);
        if self.open.instances.contains_key(&tname) {
            // provided methods the impl does not override are methods of the instance too
            let overridden: HashSet<String> = im.items.iter().filter_map(|ii| match ii {
                syn::ImplItem::Fn(f) => Some(f.sig.ident.to_string()),
                _ => None,
            }).collect();
            for f in self.open.trait_defaults.get(&tname).cloned().unwrap_or_default() {
                if !overridden.contains(&f.sig.ident.to_string()) {
                    self.methods.insert((sn.clone(), f.sig.ident.to_string()), super::method_info(&f.sig));
                }
            }
            for ii in &im.items {
                match ii {
                    syn::ImplItem::Type(t) => {
                        self.open.assoc_types.insert((sn.clone(), t.ident.to_string()), t.ty.clone());
                    }
                    syn::ImplItem::Const(c) => {
                        self.open.assoc_consts.insert((sn.clone(), c.ident.to_string()));
                        self.consts.insert(const_name(&sn, &c.ident.to_string()), c.ty.clone());
                        if has_call(&c.expr) {
                            self.open.const_fns.insert(const_name(&sn, &c.ident.to_string()));
                        }
                    }
                    syn::ImplItem::Fn(f) => {
                        self.methods.insert((sn.clone(), f.sig.ident.to_string()), super::method_info(&f.sig));
                    }
                    _ => {}
                }
            }
            return true;
        }
        if OP_TRAITS.contains(&tname.as_str()) && !(prim_self && tname == "From") {
            let arg = trait_arg(tp, &im.self_ty);
            for ii in &im.items {
                if let syn::ImplItem::Fn(f) = ii {
                    let m = f.sig.ident.to_string();
                    if prim_self {
                        let name = format!("{sn}__{m}__{}", super::sanitize(if arg.is_empty() { "Self" } else { &arg }));
                        self.open.op_impls.insert((sn.clone(), tname.clone(), arg.clone()), name);
                    } else {
                        let name = op_method_name(&m, &arg);
                        self.open.op_impls.insert((sn.clone(), tname.clone(), arg.clone()), name.clone());
                        let mut sig = f.sig.clone();
                        sig.ident = format_ident!("{}", name);
                        self.methods.insert((sn.clone(), name), super::method_info(&sig));
                    }
                }
            }
            return true;
        }
        if METHOD_TRAITS.contains(&tname.as_str()) && tname != "Default" && !prim_self {
            for ii in &im.items {
                match ii {
                    syn::ImplItem::Fn(f) => {
                        self.methods.insert((sn.clone(), f.sig.ident.to_string()), super::method_info(&f.sig));
                    }
                    syn::ImplItem::Type(t) if tname == "Deref" && t.ident == "Target" => {
                        self.open.deref.insert(sn.clone(), t.ty.clone());
                    }
                    _ => {}
                }
            }
            return true;
        }
        false
    }

    /// The methods an impl of the open trait `tname` contributes at its
    /// instance `sname`: its own methods and the trait's provided methods
    /// it does not override. A method whose name is also an inherent method
    /// of `sname` is not lifted a second time: Rust resolves `x.m()` and
    /// `S::m(x)` on the concrete type to the inherent method, the lift reads
    /// every call at the instance that way, so the trait's method must mean
    /// the same — an impl method must be a pure delegation to the inherent
    /// one (`Self::m(self, a, ..)`, `self.m(a, ..)`), a provided method must
    /// have the inherent method's parameters and body, token for token (its
    /// calls resolve to the trait's methods, which agree with the inherent
    /// ones by the same rule). Anything else is refused.
    pub(super) fn open_impl_items(&mut self, sname: &str, tname: &str, im: &syn::ItemImpl) -> Vec<syn::ImplItem> {
        let mut out = Vec::new();
        let mut own: HashSet<String> = HashSet::new();
        for ii in &im.items {
            if let syn::ImplItem::Fn(f) = ii {
                let m = f.sig.ident.to_string();
                own.insert(m.clone());
                if self.open.inherent_fns.contains_key(&(sname.to_string(), m.clone())) {
                    if is_delegation(f) {
                        self.drop_item(f.sig.ident.span(), format!("method `{tname}::{m}` of `{sname}`"), "a pure delegation to the inherent method of the same name (both resolutions agree; the inherent method is lifted)");
                    } else {
                        self.err_note(f.sig.ident.span(), format!("`{tname}::{m}` of `{sname}` has the name of an inherent method of `{sname}` but is not a pure delegation to it"), "at the instance the lift reads every call of `m` as the inherent method (Rust's resolution on the concrete type); a trait method with other behavior would be read wrongly");
                    }
                    continue;
                }
            }
            out.push(ii.clone());
        }
        for f in self.open.trait_defaults.get(tname).cloned().unwrap_or_default() {
            let m = f.sig.ident.to_string();
            if own.contains(&m) {
                continue;
            }
            let Some(block) = f.default.clone() else { continue };
            if let Some(inh) = self.open.inherent_fns.get(&(sname.to_string(), m.clone())).cloned() {
                let same_inputs = f.sig.inputs.to_token_stream().to_string() == inh.sig.inputs.to_token_stream().to_string();
                let same_body = block.to_token_stream().to_string() == inh.block.to_token_stream().to_string();
                if same_inputs && same_body {
                    self.drop_item(f.sig.ident.span(), format!("provided method `{tname}::{m}` at `{sname}`"), "the same parameters and body as the inherent method of the same name (the inherent method is lifted)");
                } else {
                    self.err_note(f.sig.ident.span(), format!("the provided method `{tname}::{m}` has the name of an inherent method of `{sname}` but not its parameters and body"), "at the instance the lift reads every call of `m` as the inherent method; a generic caller reaches the provided one");
                }
                continue;
            }
            out.push(syn::ImplItem::Fn(syn::ImplItemFn { attrs: f.attrs.clone(), vis: syn::Visibility::Inherited, defaultness: None, sig: f.sig.clone(), block }));
        }
        out
    }

    /// An operator impl on a primitive: one free function per method,
    /// `u64__eq__Position(self_: &u64, other: &Position)`.
    pub(super) fn lift_prim_op_impl(&mut self, im: &syn::ItemImpl, tname: &str, ghost: bool) -> Vec<syn::Item> {
        let self_ty = (*im.self_ty).clone();
        let Some((_, tp, _)) = &im.trait_ else { return vec![] };
        let arg = trait_arg(tp, &self_ty);
        let sn = super::type_name(&self_ty).unwrap_or_default();
        self.open.cur_impl_assoc = im.items.iter().filter_map(|ii| match ii {
            syn::ImplItem::Type(t) => Some((t.ident.to_string(), t.ty.clone())),
            _ => None,
        }).collect();
        // the conformance harness calls `<u64 as PartialEq<S>>::eq`
        let trait_written = tp.to_token_stream().to_string().replace(' ', "");
        self.cur_impl = Some((Some(trait_written), super::in_mod_path(&im.attrs), super::ty_key(&self_ty)));
        let mut out = Vec::new();
        for ii in &im.items {
            if let syn::ImplItem::Fn(f) = ii {
                let name = self.open.op_impls.get(&(sn.clone(), tname.to_string(), arg.clone())).cloned().unwrap_or_else(|| format!("{sn}__{}__{}", f.sig.ident, super::sanitize(&arg)));
                let item_fn = syn::ItemFn { attrs: super::keep_fn_attrs(&f.attrs), vis: syn::Visibility::Public(Default::default()), sig: f.sig.clone(), block: Box::new(f.block.clone()) };
                out.extend(self.lift_fn(item_fn, HashMap::new(), Some(self_ty.clone()), ghost, Some(name)));
            }
        }
        self.cur_impl = None;
        self.open.cur_impl_assoc.clear();
        out
    }

    /// `#[derive(Default)]` on a struct: `fn default()` building each
    /// field's default, as rustc's derive does (integers `0`, `bool`
    /// `false`, `Option` `None`, a lifted struct its own `default()`).
    pub(super) fn derived_default(&mut self, s: &syn::ItemStruct, lifted: &syn::ItemStruct, ghost: bool) -> Option<syn::Item> {
        let dflt = |cx: &Ctx, t: &syn::Type| -> Option<syn::Expr> {
            let n = super::type_name(t)?;
            if let Some(bits) = super::uint_name_bits(&n) {
                let _ = bits;
                let lit = syn::LitInt::new(&format!("0{n}"), PSpan::call_site());
                return Some(syn::parse_quote!(#lit));
            }
            match n.as_str() {
                "bool" => Some(syn::parse_quote!(false)),
                "Option" => Some(syn::parse_quote!(None)),
                _ if cx.structs.contains_key(&n) => {
                    let m = cx.structs[&n].module.clone();
                    let mp = cx.open.module_paths.get(&m).cloned().unwrap_or_else(|| format!("crate::{m}"));
                    let p: syn::Path = syn::parse_str(&format!("{mp}::{n}")).ok()?;
                    Some(syn::parse_quote!(#p::default()))
                }
                _ => None,
            }
        };
        let name = &lifted.ident;
        let body: syn::Expr = match &lifted.fields {
            syn::Fields::Named(fs) => {
                let mut inits = Vec::new();
                for f in &fs.named {
                    let Some(e) = dflt(self, &f.ty) else {
                        self.err(f.span(), "`#[derive(Default)]`: the lift does not know this field type's default");
                        return None;
                    };
                    let id = f.ident.clone()?;
                    inits.push(quote!(#id: #e));
                }
                syn::parse_quote!(#name { #(#inits),* })
            }
            syn::Fields::Unnamed(fs) => {
                let mut inits = Vec::new();
                for f in &fs.unnamed {
                    let Some(e) = dflt(self, &f.ty) else {
                        self.err(f.span(), "`#[derive(Default)]`: the lift does not know this field type's default");
                        return None;
                    };
                    inits.push(e);
                }
                syn::parse_quote!(#name(#(#inits),*))
            }
            syn::Fields::Unit => syn::parse_quote!(#name),
        };
        // the conformance entry: `<S as Default>::default()` (rustc's derive)
        if !ghost {
            let src_ty = match &s.generics.params.is_empty() {
                true => s.ident.to_string(),
                false => self.instances.get(&name.to_string()).map(|(b, a)| format!("{b}<{}>", a.join(", "))).unwrap_or_else(|| s.ident.to_string()),
            };
            let modpath = self.struct_mods.get(&s.ident.to_string()).cloned().unwrap_or_default();
            self.conform.push(super::ConformEntry {
                module: self.cur_module.clone(),
                lifted: format!("{}::{name}::default", self.conform_module_path()),
                callee: super::ConformCallee::Trait { modpath, self_ty: src_ty, trait_path: "Default".into(), method: "default".into() },
                params: vec![],
                has_ret: true,
            });
        }
        // an attached contract (`#[lift_attach(S::default)]`: `ensures(..)`,
        // and `at_start! { .. }` proof steps before the body — the derive
        // has no precondition)
        let mut contract: Vec<syn::Attribute> = Vec::new();
        let mut ensures: Vec<(syn::Expr, bool)> = Vec::new();
        let mut steps: Vec<syn::Stmt> = Vec::new();
        // (attachments name it by its full path, `crate::m::S::default`)
        let key = self.attach_path(&format!("{}::default", s.ident));
        let mut srcs: Vec<syn::Attribute> = Vec::new();
        if let Some(at) = self.attach_fn.get(&key).cloned() {
            self.attach_used.insert(format!("fn {key}"));
            for (i, (st, &in_laws)) in at.stmts.iter().zip(&at.in_laws).enumerate() {
                if let syn::Stmt::Macro(m) = st
                    && m.mac.path.is_ident("at_start")
                {
                    match m.mac.parse_body_with(syn::Block::parse_within) {
                        Ok(v) => {
                            let mut rw = super::FnRw::new(self, HashMap::new(), true);
                            for mut s2 in v {
                                rw.ghost_stmt(&mut s2);
                                steps.push(s2);
                            }
                        }
                        Err(e) => self.err(m.span(), format!("malformed `at_start!`: {e}")),
                    }
                    continue;
                }
                let Some(mut e) = super::attach_call(st, "ensures") else {
                    self.errors.push((at.spans[i], "an attachment to a derived `default` holds `ensures(..);` and `at_start! { .. }` only".into(), vec![]));
                    continue;
                };
                let mut rw = super::FnRw::new(self, HashMap::new(), true);
                rw.expr(&mut e, None);
                drop(rw);
                ensures.push((e, in_laws));
                srcs.push(at.src_attr(i, "ensures"));
            }
            // the contract is the laws file's part (`super::ensures_attrs`)
            match super::ensures_attrs(ensures) {
                Ok(attrs) => contract.extend(attrs),
                Err(msg) => self.errors.push((at.span, msg, vec![])),
            }
            if !ghost {
                contract.extend(srcs);
            }
        }
        let proof: Option<syn::Stmt> = (!steps.is_empty()).then(|| syn::parse_quote!(proof! { #(#steps)* }));
        Some(syn::parse_quote!(impl #name {
            /// `#[derive(Default)]`: every field's default.
            #(#contract)*
            pub fn default() -> Self { #proof #body }
        }))
    }
}

impl Ctx {
    /// The mangled associated constants of a struct (`S__C`), sorted.
    pub(super) fn const_names_of(&self, s: &str) -> Vec<String> {
        let mut v: Vec<String> = self.open.assoc_consts.iter().filter(|(o, _)| o == s).map(|(o, c)| const_name(o, c)).collect();
        v.sort();
        v
    }
}
