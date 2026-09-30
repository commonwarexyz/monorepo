//! In-place lifting, open-trait generics, operator impls, closures and
//! core combinators (SEMANTICS.md §19.5–§19.9). A child module of
//! [`crate::lift`]: it extends the lift for crates whose verified code is
//! spread over several host files (commonware-storage's MMR arithmetic).
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
//! | `a + b`, `a += b`, `a == b`, `a < b`, `*a` on lifted structs | the impl's method, as Rust desugars them (`a < b` is `PartialOrd::lt`, i.e. `partial_cmp(a, b) == Some(Less)`) |
//! | `x.m()` on a struct without `m` that derefs to an integer | `(*x).m()` (auto-deref, integer methods only) |
//! | `#[derive(Default)]` | `fn default()` building every field's default, as rustc's derive |
//! | `PhantomData` | the unit struct `crate::__lift::PhantomData` |
//! | `recv.m(args)` for `recv` an `Option`, a `Result` or an integer and `m` a core method with a template in `lift/combinators.rs` | the template's body inlined: arguments bound by `let` in order, closure arguments inlined at their calls, `panic!` an obligation |
//! | `let f = \|x\| e;` called as `f(a)` | inlined as `{ let x = a; e }` (refused if a captured variable is re-bound or assigned after the closure) |
//! | `-> impl Iterator<Item = T>` | the concrete type of the body's result |
//! | `a..=b`, `a..b` as values, `core::iter::once(x)` | the prelude iterators `crate::__lift::{RangeInclusiveU32, ..}`, `crate::__lift::Once<T>` (their `next` transcribes core's) |
//! | `assert!(c, ..)`, `assert_eq!`, `assert_ne!`, `debug_assert*!`, `panic!(..)` | `if !c { unreachable!() }` (the panic is an obligation) |
//! | `while c { .. return .. continue .. }` followed by the rest of the body | a tail-recursive helper whose `else` branch is the rest |
//! | `for p in it { .. }` over a non-range iterator (or with `break`/`continue`/`return`) | a tail-recursive helper calling `next` |
//! | an unannotated `let x = <unsuffixed integer expression>;` | annotated with the type its uses force (what rustc infers); a wrong guess cannot type check |
//! | `items = "A, B"` on an in-place declaration | only those items (and impls of those types) are lifted; the rest is host code, listed (SEMANTICS.md §19.10) |
//! | an open trait declared in the lifted file, at its instance | the instance's impl and the provided methods it does not override are inherent methods of the instance; a name shared with an inherent method must be a pure delegation (impl) or the same parameters and body (provided) |
//! | an open-trait parameter in a type's arguments | dropped only where that item's own parameter was erased; substituted elsewhere (`Result<D, E>`) |
//! | `#[lift(host)]` type aliases, unit structs and their open-trait impls (in place) | host models (trusted, listed): `S::m` calls and `S::X` types read as the model |
//! | `&mut T` (a value), `&mut E` (`E: Iterator<Item: AsRef<[u8]>>`), `&mut Vec<T>`, `Option<&mut Vec<T>>` parameters | state passing: `T`, the items not yet yielded, `Seq<T>`, `Option<Seq<T>>` |
//! | `core::ops::Range<T>`, `Vec<T>` | `crate::__lift::Range<T>`, `Seq<T>` |

use std::collections::{BTreeSet, HashMap, HashSet};

use proc_macro2::Span as PSpan;
use quote::{format_ident, quote, ToTokens};
use syn::spanned::Spanned;
use syn::visit_mut::VisitMut;

use super::{Ctx, Dropped};

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
    /// `opt`: optimization alternatives — agent-written Rust in the host's
    /// dialect, lifted and verified like any code, never emitted as a
    /// module; `#[rewrite]` lemmas name its functions as the replacements of
    /// source functions (`driver::lowered`).
    pub opt: bool,
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
        self.opt |= o.opt;
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

const LIFT_USAGE: &str = "expected `#[lift]`, `#[lift(host)]`, `#[lift(opt)]` or `#[lift(unverified = \"T, ..\")]`, and for the host's own files `#[lift(in_place, children = \"m\", instance = \"Trait: path::Type\", unverified_instances = \"Trait: path::Type\", unverified_impls = \"Trait, ..\", unverified_fns = \"Type::method, ..\", items = \"Item, ..\")]`; `mir = \"file.sbmir\"` on either reads the bodies from rustc's MIR";

/// Parses one `#[lift]` / `#[lift(..)]` attribute.
pub fn parse_lift_opts(a: &syn::Attribute) -> Result<LiftOpts, String> {
    let mut o = LiftOpts::default();
    let syn::Meta::List(_) = &a.meta else { return Ok(o) };
    let metas = a.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated).map_err(|_| LIFT_USAGE.to_string())?;
    for m in metas {
        match &m {
            syn::Meta::Path(p) if p.is_ident("host") => o.host = true,
            syn::Meta::Path(p) if p.is_ident("in_place") => o.in_place = true,
            syn::Meta::Path(p) if p.is_ident("opt") => o.opt = true,
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
    if o.opt && (o.host || o.in_place) {
        return Err("`opt` (optimization alternatives) cannot be combined with `host` or `in_place`".into());
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
    /// Every method name defined by some impl of a struct in the lifted
    /// sources, dropped impls included (auto-deref never shadows them).
    pub all_methods: HashSet<(String, String)>,
    /// Templates (`lift/combinators.rs`), by name.
    pub templates: HashMap<String, syn::ItemFn>,
    /// The DSL module path of each free function of an impl on a primitive.
    pub prim_modules: HashMap<String, String>,
    /// The associated types of the impl being lifted (`Self::Output` ..).
    pub cur_impl_assoc: HashMap<String, syn::Type>,
    /// The source signatures of the free functions of impls on primitives.
    pub prim_sigs: HashMap<String, syn::Signature>,
    /// Associated constants whose initializer calls a function: lifted as
    /// constant functions `S__C()` (a DSL constant cannot call one).
    pub const_fns: HashSet<String>,
    /// Lifted functions with a `requires` attachment (for the record).
    pub host_obligations: Vec<(String, String)>,
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

/// The binary operator's trait and method (`+` → `Add::add`).
pub fn binop_trait(op: &syn::BinOp) -> Option<(&'static str, &'static str)> {
    use syn::BinOp as B;
    Some(match op {
        B::Add(_) => ("Add", "add"),
        B::Sub(_) => ("Sub", "sub"),
        B::Mul(_) => ("Mul", "mul"),
        B::Div(_) => ("Div", "div"),
        B::Rem(_) => ("Rem", "rem"),
        B::BitAnd(_) => ("BitAnd", "bitand"),
        B::BitOr(_) => ("BitOr", "bitor"),
        B::BitXor(_) => ("BitXor", "bitxor"),
        B::Shl(_) => ("Shl", "shl"),
        B::Shr(_) => ("Shr", "shr"),
        B::AddAssign(_) => ("AddAssign", "add_assign"),
        B::SubAssign(_) => ("SubAssign", "sub_assign"),
        B::MulAssign(_) => ("MulAssign", "mul_assign"),
        B::DivAssign(_) => ("DivAssign", "div_assign"),
        B::RemAssign(_) => ("RemAssign", "rem_assign"),
        B::BitAndAssign(_) => ("BitAndAssign", "bitand_assign"),
        B::BitOrAssign(_) => ("BitOrAssign", "bitor_assign"),
        B::BitXorAssign(_) => ("BitXorAssign", "bitxor_assign"),
        B::ShlAssign(_) => ("ShlAssign", "shl_assign"),
        B::ShrAssign(_) => ("ShrAssign", "shr_assign"),
        _ => return None,
    })
}

/// A comparison operator: `(PartialEq | PartialOrd, prelude predicate)`;
/// `==`/`!=` are `eq` / `!eq`, the orderings test `partial_cmp`'s result.
pub fn cmp_op(op: &syn::BinOp) -> Option<(&'static str, &'static str)> {
    use syn::BinOp as B;
    Some(match op {
        B::Eq(_) => ("PartialEq", "eq"),
        B::Ne(_) => ("PartialEq", "ne"),
        B::Lt(_) => ("PartialOrd", "ord_lt"),
        B::Le(_) => ("PartialOrd", "ord_le"),
        B::Gt(_) => ("PartialOrd", "ord_gt"),
        B::Ge(_) => ("PartialOrd", "ord_ge"),
        _ => return None,
    })
}

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

impl FnRw<'_> {
    /// The body's reading of the value, iterator and `Vec` states
    /// (`state_param`): `*x` is `x`; `x.next()` of the byte-string iterator is
    /// `crate::__lift::bytes_iter_next`; `v.push(e)` of a `Vec` state is
    /// `v = crate::__lift_model::vec_push(v, e)`; `if let Some(ref mut v) = o
    /// { B }` of an `Option<Seq<T>>` state is `if let Some(mut v) = o { B; o =
    /// Some(v); }` (the borrow writes back).
    pub(super) fn state_rewrite(&mut self, e: &syn::Expr) -> Option<syn::Expr> {
        let span = e.span();
        let state_ty = |me: &Self, x: &syn::Expr| -> Option<(String, syn::Type)> {
            let syn::Expr::Path(p) = x else { return None };
            let n = p.path.get_ident()?.to_string();
            let (_, t) = me.states.iter().rev().find(|(s, _)| *s == n)?;
            Some((n, t.clone()))
        };
        match e {
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                let (n, t) = state_ty(self, &u.expr)?;
                // a value state (not a buffer, an iterator or a `Vec`)
                if matches!(type_name_of(&t).as_deref(), Some("Seq" | "Option")) || matches!(t, syn::Type::Reference(_)) {
                    return None;
                }
                let id = format_ident!("{}", n, span = span);
                Some(syn::parse_quote_spanned!(span=> #id))
            }
            syn::Expr::MethodCall(mc) if mc.method == "next" && mc.args.is_empty() => {
                let syn::Expr::Path(p) = &*mc.receiver else { return None };
                let n = p.path.get_ident()?.to_string();
                if !self.is_state(&n) || self.ty_of(&mc.receiver).as_ref().and_then(super::type_name).as_deref() != Some("__BytesIter") {
                    return None;
                }
                let id = format_ident!("{}", n, span = span);
                let t = self.fresh("it");
                let r = self.fresh("r");
                Some(syn::parse_quote_spanned!(span=> { let (#t, #r) = crate::__lift::bytes_iter_next(#id); #id = #t; #r }))
            }
            syn::Expr::MethodCall(mc) if mc.method == "push" && mc.args.len() == 1 => {
                let syn::Expr::Path(p) = &*mc.receiver else { return None };
                let n = p.path.get_ident()?.to_string();
                let t = self.ty_of(&mc.receiver)?;
                if type_name_of(&t).as_deref() != Some("Seq") {
                    return None;
                }
                let mut a = mc.args[0].clone();
                self.expr(&mut a, None);
                let id = format_ident!("{}", n, span = span);
                Some(syn::parse_quote_spanned!(span=> { #id = crate::__lift_model::vec_push(#id, #a); }))
            }
            syn::Expr::If(i) => {
                let syn::Expr::Let(l) = &*i.cond else { return None };
                let (n, t) = state_ty(self, &l.expr)?;
                if type_name_of(&t).as_deref() != Some("Option") {
                    return None;
                }
                let syn::Pat::TupleStruct(ts) = &*l.pat else { return None };
                if !ts.path.is_ident("Some") || ts.elems.len() != 1 || i.else_branch.is_some() {
                    return None;
                }
                let syn::Pat::Ident(pi) = &ts.elems[0] else { return None };
                if pi.by_ref.is_none() || pi.mutability.is_none() || pi.subpat.is_some() {
                    return None;
                }
                let o = format_ident!("{}", n, span = span);
                let v = pi.ident.clone();
                let body = &i.then_branch;
                let mut new: syn::Expr = syn::parse_quote_spanned!(span=> if let Some(mut #v) = #o { #body #o = Some(#v); });
                // the rewritten `if let` binds `v` with the payload type
                if let syn::Expr::If(ni) = &mut new {
                    self.push_scope();
                    let inner: Option<syn::Type> = match &t {
                        syn::Type::Path(tp) => match &tp.path.segments.last().map(|s| s.arguments.clone()) {
                            Some(syn::PathArguments::AngleBracketed(a)) => a.args.first().and_then(|x| match x {
                                syn::GenericArgument::Type(t) => Some(t.clone()),
                                _ => None,
                            }),
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Some(it) = inner {
                        self.bind(&v.to_string(), it);
                    }
                    self.block(&mut ni.then_branch);
                    self.pop_scope();
                }
                Some(new)
            }
            _ => None,
        }
    }
}

fn type_name_of(t: &syn::Type) -> Option<String> {
    match t {
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
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
                if let syn::Item::Impl(im) = &item {
                    self.record_methods(im);
                }
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
                    let name = m.mac.path.to_token_stream().to_string().replace(' ', "");
                    self.drop_item(m.span(), format!("item macro `{name}!`"), "a macro of another crate (host code; the items it expands to are not part of the lifted meaning)");
                    continue;
                }
                syn::Item::Impl(im) if im.trait_.as_ref().is_some_and(|(_, p, _)| unverified_impl(p)) => {
                    let tn = im.trait_.as_ref().map(|(_, p, _)| p.to_token_stream().to_string().replace(' ', "")).unwrap_or_default();
                    self.record_methods(im);
                    self.drop_item(im.span(), format!("impl `{tn}` for `{}`", super::ty_key(&im.self_ty)), "declared `unverified_impls`: unchecked host code");
                    continue;
                }
                syn::Item::Impl(im) if im.trait_.as_ref().is_some_and(|(_, p, _)| p.segments.last().is_some_and(|s| DROPPED_TRAITS.contains(&s.ident.to_string().as_str()))) => {
                    let tn = im.trait_.as_ref().map(|(_, p, _)| p.to_token_stream().to_string().replace(' ', "")).unwrap_or_default();
                    self.record_methods(im);
                    self.drop_item(im.span(), format!("impl `{tn}` for `{}`", super::ty_key(&im.self_ty)), "value semantics or formatting (the model is by value; `Copy`/`Clone` are derived on the model; formatting and hashing are host code)");
                    continue;
                }
                syn::Item::Trait(t) if opts.unverified_impls.iter().any(|u| u.rsplit("::").next() == Some(&t.ident.to_string())) => {
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
                t.items.retain(|ti| match ti {
                    syn::TraitItem::Fn(f) if f.default.is_some() && opts.unverified_fns.iter().any(|u| *u == format!("{tn}::{}", f.sig.ident)) => {
                        dropped.push((f.sig.ident.span(), format!("{tn}::{}", f.sig.ident)));
                        false
                    }
                    _ => true,
                });
                for (sp, name) in dropped {
                    self.drop_item(sp, format!("provided method `{name}`"), "declared `unverified_fns`: unchecked host code (the verified instance has no such method; a lifted caller does not load)");
                }
            }
            if let syn::Item::Impl(im) = &mut item
                && !opts.unverified_fns.is_empty()
                && let Some(tn) = super::type_name(&im.self_ty)
            {
                let mut dropped = Vec::new();
                im.items.retain(|ii| match ii {
                    syn::ImplItem::Fn(f) if opts.unverified_fns.iter().any(|u| *u == format!("{tn}::{}", f.sig.ident)) => {
                        dropped.push((f.sig.ident.span(), format!("{tn}::{}", f.sig.ident)));
                        false
                    }
                    _ => true,
                });
                for (sp, name) in dropped {
                    self.drop_item(sp, format!("method `{name}`"), "declared `unverified_fns`: unchecked host code");
                }
            }
            out.push(item);
        }
        out
    }

    /// Remembers every method name an impl defines for its self type.
    pub(super) fn record_methods(&mut self, im: &syn::ItemImpl) {
        if let Some(sn) = super::type_name(&im.self_ty) {
            for ii in &im.items {
                if let syn::ImplItem::Fn(f) = ii {
                    self.open.all_methods.insert((sn.clone(), f.sig.ident.to_string()));
                }
            }
        }
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

// ---------------------------------------------------------------------------
// templates: core methods as their definitions (lift/combinators.rs)
// ---------------------------------------------------------------------------

/// The template file: core's definitions of the `Option`, `Result` and
/// integer methods the lift reads, as plain Rust (compiled natively by the
/// differential test, so each is checked against core).
pub const TEMPLATES: &str = include_str!("../lift/combinators.rs");

impl Ctx {
    /// Loads the templates (once per lift).
    pub(super) fn load_templates(&mut self) {
        if !self.open.templates.is_empty() {
            return;
        }
        let file = match syn::parse_file(TEMPLATES) {
            Ok(f) => f,
            Err(e) => {
                self.errors.push((crate::span::Span::DUMMY, format!("lift templates: {e}"), vec![]));
                return;
            }
        };
        let saved = std::mem::take(&mut self.macros);
        let items = self.preprocess(file.items, 0);
        self.macros = saved;
        for it in items {
            if let syn::Item::Fn(f) = it {
                self.open.templates.insert(f.sig.ident.to_string(), f);
            }
        }
    }

    /// The template of method `m` on a receiver of kind `kind`
    /// (`option`, `result`, `u64`, ..).
    pub(super) fn template(&self, kind: &str, m: &str) -> Option<syn::ItemFn> {
        self.open.templates.get(&format!("{kind}_{m}")).cloned()
    }
}

/// The template kind of a receiver type: `option`, `result` or the
/// primitive's name.
pub fn receiver_kind(t: &syn::Type) -> Option<String> {
    let n = super::type_name(&super::strip_refs(t))?;
    match n.as_str() {
        "Option" => Some("option".into()),
        "Result" => Some("result".into()),
        p if super::is_prim(p) => Some(p.to_string()),
        _ => None,
    }
}

/// Renames the identifier patterns and paths of `e` by `map` (template
/// hygiene: every local of a template gets a fresh name).
pub struct Rename<'a> {
    pub map: &'a HashMap<String, String>,
}

impl VisitMut for Rename<'_> {
    fn visit_pat_ident_mut(&mut self, p: &mut syn::PatIdent) {
        if let Some(n) = self.map.get(&p.ident.to_string()) {
            p.ident = syn::Ident::new(n, p.ident.span());
        }
        syn::visit_mut::visit_pat_ident_mut(self, p);
    }
    fn visit_expr_path_mut(&mut self, e: &mut syn::ExprPath) {
        if let Some(id) = e.path.get_ident()
            && let Some(n) = self.map.get(&id.to_string())
        {
            e.path = syn::Path::from(syn::Ident::new(n, id.span()));
        }
    }
    fn visit_field_value_mut(&mut self, f: &mut syn::FieldValue) {
        // `S { x }` shorthand: keep the field name, rename the value
        if f.colon_token.is_none()
            && let syn::Member::Named(n) = &f.member
            && let Some(new) = self.map.get(&n.to_string())
        {
            let id = syn::Ident::new(new, n.span());
            f.expr = syn::parse_quote!(#id);
            f.colon_token = Some(Default::default());
            return;
        }
        syn::visit_mut::visit_field_value_mut(self, f);
    }
}

/// The identifiers bound by the patterns of `b` (and the parameters).
pub fn bound_names(pats: &[&syn::Pat], body: &syn::Expr) -> BTreeSet<String> {
    struct V<'a>(&'a mut BTreeSet<String>);
    impl<'ast> syn::visit::Visit<'ast> for V<'_> {
        fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
            self.0.insert(p.ident.to_string());
            syn::visit::visit_pat_ident(self, p);
        }
    }
    let mut out = BTreeSet::new();
    for p in pats {
        syn::visit::Visit::visit_pat(&mut V(&mut out), p);
    }
    syn::visit::Visit::visit_expr(&mut V(&mut out), body);
    out
}

/// The free identifiers a closure body reads (paths of one segment that
/// are not its parameters or its own `let`s).
pub fn free_idents(c: &syn::ExprClosure) -> BTreeSet<String> {
    let pats: Vec<&syn::Pat> = c.inputs.iter().collect();
    let bound = bound_names(&pats, &c.body);
    struct V<'a>(&'a mut BTreeSet<String>);
    impl<'ast> syn::visit::Visit<'ast> for V<'_> {
        fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
            if let Some(i) = p.path.get_ident() {
                self.0.insert(i.to_string());
            }
        }
    }
    let mut all = BTreeSet::new();
    syn::visit::Visit::visit_expr(&mut V(&mut all), &c.body);
    all.difference(&bound).cloned().collect()
}

/// Whether a closure body can be inlined (no `return`, `?`, `async`,
/// nested closure or loop label escaping it).
pub fn closure_inlinable(c: &syn::ExprClosure) -> Result<(), &'static str> {
    if c.asyncness.is_some() || c.constness.is_some() || c.lifetimes.is_some() {
        return Err("an `async`, `const` or `for<..>` closure");
    }
    struct V(Option<&'static str>);
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.0 = Some("a closure body with `return`");
        }
        fn visit_expr_try(&mut self, _: &'ast syn::ExprTry) {
            self.0 = Some("a closure body with `?`");
        }
        fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {
            self.0 = Some("a closure inside a closure body");
        }
    }
    let mut v = V(None);
    syn::visit::Visit::visit_expr(&mut v, &c.body);
    match v.0 {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `{ let p1 = a1; ..; body }` with the closure's parameters renamed fresh
/// (`fresh` gives the new names): the inlined call of a closure.
pub fn inline_closure(c: &syn::ExprClosure, args: Vec<syn::Expr>, fresh: &mut dyn FnMut(&str) -> String) -> syn::Expr {
    let pats: Vec<&syn::Pat> = c.inputs.iter().collect();
    let names: BTreeSet<String> = bound_names(&pats, &syn::parse_quote!(())).into_iter().filter(|n| n.chars().next().is_some_and(|c| c.is_lowercase() || c == '_')).collect();
    // also the closure body's own `let`s shadowing nothing outside: rename the parameters only
    let map: HashMap<String, String> = names.iter().map(|n| (n.clone(), fresh(n))).collect();
    let mut stmts: Vec<syn::Stmt> = Vec::new();
    for (p, a) in c.inputs.iter().zip(args) {
        let mut p = p.clone();
        Rename { map: &map }.visit_pat_mut(&mut p);
        stmts.push(syn::parse_quote!(let #p = #a;));
    }
    let mut body = (*c.body).clone();
    Rename { map: &map }.visit_expr_mut(&mut body);
    stmts.push(syn::Stmt::Expr(body, None));
    syn::parse_quote!({ #(#stmts)* })
}

/// A type that is one identifier (a generic parameter).
fn pt_ident(t: &syn::Type) -> Option<String> {
    match t {
        syn::Type::Path(p) if p.qself.is_none() => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
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

/// Whether an expression (or a block's tail) is an unsuffixed integer
/// expression the DSL cannot type without an annotation: a literal, or an
/// operation whose left operand is one.
pub fn untyped_int(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => i.suffix().is_empty(),
        syn::Expr::Paren(p) => untyped_int(&p.expr),
        syn::Expr::Binary(b) => matches!(b.op, syn::BinOp::Shl(_) | syn::BinOp::Shr(_) | syn::BinOp::Add(_) | syn::BinOp::Sub(_) | syn::BinOp::Mul(_) | syn::BinOp::BitAnd(_) | syn::BinOp::BitOr(_) | syn::BinOp::BitXor(_)) && untyped_int(&b.left) && (matches!(b.op, syn::BinOp::Shl(_) | syn::BinOp::Shr(_)) || untyped_int(&b.right)),
        _ => false,
    }
}

/// Suffixes the unsuffixed literals at the root of an untyped integer
/// expression with `t` (the left operands of shifts, both operands of
/// arithmetic).
pub fn suffix_untyped(e: &mut syn::Expr, t: &syn::Type) {
    match e {
        syn::Expr::Lit(_) => super::suffix_literal(e, t),
        syn::Expr::Paren(p) => suffix_untyped(&mut p.expr, t),
        syn::Expr::Binary(b) => {
            suffix_untyped(&mut b.left, t);
            if !matches!(b.op, syn::BinOp::Shl(_) | syn::BinOp::Shr(_)) {
                suffix_untyped(&mut b.right, t);
            }
        }
        _ => {}
    }
}

/// A `Dropped` entry (for callers outside `Ctx`).
pub fn dropped(span: crate::span::Span, what: String, why: &str) -> Dropped {
    Dropped { span, what, why: why.to_string() }
}

#[allow(dead_code)]
fn _unused(_: PSpan) -> proc_macro2::TokenStream {
    let x = format_ident!("x");
    quote!(#x)
}

// ---------------------------------------------------------------------------
// core paths
// ---------------------------------------------------------------------------

/// Paths of core items with a prelude model: `core::cmp::Ordering`,
/// `PhantomData`, `core::iter::once`.
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
            if core_prefixed(&e.path, "once", &[&["iter"], &["core", "iter"], &["std", "iter"]]) {
                e.path = syn::parse_quote!(crate::__lift::once);
                return;
            }
        }
        syn::visit_mut::visit_expr_path_mut(self, e);
    }
}

// ---------------------------------------------------------------------------
// function rewriting
// ---------------------------------------------------------------------------

use super::FnRw;

/// Whether `b` has a `return`, `continue` or `break` outside nested loops
/// and closures (a `while` that needs a helper).
pub fn has_control(b: &syn::Block) -> (bool, bool, bool) {
    struct V(bool, bool, bool, usize);
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr_return(&mut self, r: &'ast syn::ExprReturn) {
            self.0 = true;
            syn::visit::visit_expr_return(self, r);
        }
        fn visit_expr_continue(&mut self, _: &'ast syn::ExprContinue) {
            if self.3 == 0 {
                self.1 = true;
            }
        }
        fn visit_expr_break(&mut self, _: &'ast syn::ExprBreak) {
            if self.3 == 0 {
                self.2 = true;
            }
        }
        fn visit_expr_while(&mut self, w: &'ast syn::ExprWhile) {
            self.3 += 1;
            syn::visit::visit_expr_while(self, w);
            self.3 -= 1;
        }
        fn visit_expr_for_loop(&mut self, f: &'ast syn::ExprForLoop) {
            self.3 += 1;
            syn::visit::visit_expr_for_loop(self, f);
            self.3 -= 1;
        }
        fn visit_expr_loop(&mut self, l: &'ast syn::ExprLoop) {
            self.3 += 1;
            syn::visit::visit_expr_loop(self, l);
            self.3 -= 1;
        }
        fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    }
    let mut v = V(false, false, false, 0);
    syn::visit::Visit::visit_block(&mut v, b);
    (v.0, v.1, v.2)
}

/// Replaces `continue` (outside nested loops) by `e`, and `break` by `brk`.
struct ReplaceControl<'a> {
    cont: &'a syn::Expr,
    brk: Option<&'a syn::Expr>,
    depth: usize,
    bad_break: bool,
}

impl VisitMut for ReplaceControl<'_> {
    fn visit_expr_mut(&mut self, e: &mut syn::Expr) {
        match e {
            syn::Expr::Continue(_) if self.depth == 0 => {
                *e = self.cont.clone();
                return;
            }
            syn::Expr::Break(b) if self.depth == 0 => {
                if b.expr.is_some() || b.label.is_some() {
                    self.bad_break = true;
                }
                match self.brk {
                    Some(x) => *e = x.clone(),
                    None => self.bad_break = true,
                }
                return;
            }
            syn::Expr::While(_) | syn::Expr::ForLoop(_) | syn::Expr::Loop(_) => {
                self.depth += 1;
                syn::visit_mut::visit_expr_mut(self, e);
                self.depth -= 1;
                return;
            }
            syn::Expr::Closure(_) => return,
            _ => {}
        }
        syn::visit_mut::visit_expr_mut(self, e);
    }
}

/// The identifiers of paths of one segment in `ts` (first-mention order).
fn idents_in(tokens: &[&dyn ToTokens]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tokens {
        let ts = t.to_token_stream();
        let e: syn::Result<syn::Block> = syn::parse2(quote!({ #ts }));
        if let Ok(b) = e {
            super::collect_idents(&b, &mut out);
        }
    }
    out
}

impl FnRw<'_> {
    /// The statements of loop `k`'s attachment, the bodies of its step
    /// macros spliced in: the locals it names become helper parameters
    /// (an invariant may relate the loop's state to a parameter the body
    /// never reads).
    fn loop_attach_stmts(&self, k: usize) -> Vec<syn::Stmt> {
        let Some(at) = self.cx.attach_loop.get(&(self.fn_name.clone(), k)) else { return Vec::new() };
        let mut out = Vec::new();
        for st in &at.stmts {
            match st {
                syn::Stmt::Macro(m) if m.mac.path.is_ident("at_start") || m.mac.path.is_ident("at_end") || m.mac.path.is_ident("after_loop") => {
                    if let Ok(v) = m.mac.parse_body_with(syn::Block::parse_within) {
                        out.extend(v);
                    }
                }
                _ => out.push(st.clone()),
            }
        }
        out
    }

    /// The lifted struct a type names (by its last segment), if any.
    pub(super) fn struct_of(&self, t: &syn::Type) -> Option<String> {
        let n = super::type_name(&super::strip_refs(t))?;
        self.cx.structs.contains_key(&n).then_some(n)
    }

    /// The full DSL path of a lifted struct (`crate::merkle::position::Position`).
    pub(super) fn struct_path(&self, s: &str) -> syn::Path {
        let m = self.cx.structs.get(s).map(|si| si.module.clone()).unwrap_or_default();
        let mp = self.cx.open.module_paths.get(&m).cloned().unwrap_or_else(|| format!("crate::{m}"));
        syn::parse_str(&format!("{mp}::{s}")).unwrap_or_else(|_| syn::parse_str(s).unwrap())
    }

    /// The method (or free function) of an operator impl for `(self, trait)`
    /// with the right operand typed `rt` (`None`: an integer the impl picks;
    /// the literal is typed accordingly). Returns the argument key.
    fn op_lookup(&self, sname: &str, tr: &str, rt: Option<&syn::Type>) -> Option<(String, String)> {
        let key = match rt {
            Some(t) => {
                let t = super::strip_refs(t);
                match super::type_name(&t) {
                    Some(n) if n == sname => String::new(),
                    Some(n) if self.cx.structs.contains_key(&n) => n,
                    _ => super::ty_key(&t),
                }
            }
            None => {
                let ints: Vec<&(String, String, String)> = self.cx.open.op_impls.keys().filter(|(s, t, a)| s == sname && t == tr && super::is_prim(a)).collect();
                match ints.as_slice() {
                    [one] => one.2.clone(),
                    _ => return None,
                }
            }
        };
        self.cx.open.op_impls.get(&(sname.to_string(), tr.to_string(), key.clone())).map(|m| (m.clone(), key))
    }

    /// Operators on lifted structs (module docs). `None` when `e` is not one.
    pub(super) fn operator_rewrite(&mut self, e: &mut syn::Expr) -> Option<syn::Expr> {
        let span = e.span();
        match e {
            syn::Expr::Binary(b) => {
                let lt = self.ty_of(&b.left);
                let rt = self.ty_of(&b.right);
                let ls = lt.as_ref().and_then(|t| self.struct_of(t));
                let rs = rt.as_ref().and_then(|t| self.struct_of(t));
                if ls.is_none() && rs.is_none() {
                    return None;
                }
                let (mut l, mut r) = ((*b.left).clone(), (*b.right).clone());
                // comparisons
                if let Some((tr, pred)) = cmp_op(&b.op) {
                    let (owner, other_t) = match (&ls, &rs) {
                        (Some(s), _) => (s.clone(), rt.clone()),
                        (None, Some(_)) => (lt.as_ref().and_then(super::type_name).unwrap_or_default(), rt.clone()),
                        _ => return None,
                    };
                    let Some((m, key)) = self.op_lookup(&owner, tr, other_t.as_ref()) else {
                        self.cx.err(span, format!("`{}` on `{owner}`: no `{tr}` impl for this right operand in the lifted sources", b.op.to_token_stream()));
                        return None;
                    };
                    if other_t.is_none() {
                        suffix_untyped(&mut r, &syn::parse_str(&key).unwrap());
                    }
                    self.expr(&mut l, None);
                    self.expr(&mut r, None);
                    // the receiver is by value in the lifted method; the other
                    // operand as the impl's parameter is typed (`other: &Rhs`)
                    let rarg: syn::Expr = if self.op_param_is_ref(&owner, &m, ls.is_none()) { syn::parse_quote!(&#r) } else { r.clone() };
                    let call: syn::Expr = if ls.is_some() {
                        let p = self.struct_path(&owner);
                        let mid = format_ident!("{}", m);
                        syn::parse_quote_spanned!(span=> #p::#mid(#l, #rarg))
                    } else {
                        let f = self.prim_fn_path(&owner, &m);
                        syn::parse_quote_spanned!(span=> #f(#l, #rarg))
                    };
                    return Some(match pred {
                        "eq" => call,
                        "ne" => syn::parse_quote_spanned!(span=> !#call),
                        p => {
                            let f = format_ident!("{}", p);
                            syn::parse_quote_spanned!(span=> crate::__lift::#f(#call))
                        }
                    });
                }
                let (tr, _) = binop_trait(&b.op)?;
                let Some(s) = ls.clone() else {
                    self.cx.err(span, format!("`{}` with a lifted struct on the right only is not lifted", b.op.to_token_stream()));
                    return None;
                };
                let Some((m, key)) = self.op_lookup(&s, tr, rt.as_ref()) else {
                    self.cx.err(span, format!("`{}` on `{s}`: no `{tr}` impl for this right operand in the lifted sources", b.op.to_token_stream()));
                    return None;
                };
                if rt.is_none() || untyped_int(&r) {
                    if let Ok(kt) = syn::parse_str::<syn::Type>(&key)
                        && super::is_prim(&key)
                    {
                        suffix_untyped(&mut r, &kt);
                    }
                }
                self.expr(&mut r, None);
                let p = self.struct_path(&s);
                let mid = format_ident!("{}", m);
                if tr.ends_with("Assign") {
                    // `place op= r`: the impl takes the place's value and returns the new one
                    let tmp = self.fresh("s");
                    let mut place = l.clone();
                    self.expr(&mut place, None);
                    return Some(syn::parse_quote_spanned!(span=> { let #tmp = #p::#mid(#place, #r); #l = #tmp; }));
                }
                self.expr(&mut l, None);
                Some(syn::parse_quote_spanned!(span=> #p::#mid(#l, #r)))
            }
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                let t = self.ty_of(&u.expr)?;
                if matches!(t, syn::Type::Reference(_)) {
                    return None;
                }
                let s = self.struct_of(&t)?;
                self.cx.open.deref.get(&s)?;
                let mut x = (*u.expr).clone();
                self.expr(&mut x, None);
                let p = self.struct_path(&s);
                Some(syn::parse_quote_spanned!(span=> *#p::deref(#x)))
            }
            _ => None,
        }
    }

    /// Whether the second parameter of an operator method is a reference
    /// (`PartialEq::eq(&self, other: &Rhs)`) in its source signature.
    fn op_param_is_ref(&self, owner: &str, m: &str, prim: bool) -> bool {
        let sig = if prim { self.cx.open.prim_sigs.get(m).cloned() } else { self.cx.methods.get(&(owner.to_string(), m.to_string())).and_then(|mi| mi.sig.clone()) };
        let Some(sig) = sig else { return true };
        sig.inputs.iter().filter_map(|i| match i {
            syn::FnArg::Typed(pt) => Some(matches!(&*pt.ty, syn::Type::Reference(_))),
            _ => None,
        }).next().unwrap_or(false)
    }

    /// The path of the free function of an impl on a primitive
    /// (`u64__eq__Position`), in its module.
    fn prim_fn_path(&self, prim: &str, name: &str) -> syn::Path {
        let module = self.cx.open.prim_fn_module(prim, name);
        syn::parse_str(&format!("{module}::{name}")).unwrap()
    }

    /// `assert!` and friends, `panic!` (module docs).
    pub(super) fn macro_rewrite(&mut self, m: &syn::ExprMacro) -> Option<syn::Expr> {
        let name = m.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        let span = m.span();
        let args = || m.mac.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated).ok();
        match name.as_str() {
            "assert" | "debug_assert" => {
                let a = args()?;
                let c = a.first()?.clone();
                Some(syn::parse_quote_spanned!(span=> if !(#c) { unreachable!() }))
            }
            "assert_eq" | "debug_assert_eq" => {
                let a = args()?;
                let (x, y) = (a.first()?.clone(), a.iter().nth(1)?.clone());
                Some(syn::parse_quote_spanned!(span=> if !(#x == #y) { unreachable!() }))
            }
            "assert_ne" | "debug_assert_ne" => {
                let a = args()?;
                let (x, y) = (a.first()?.clone(), a.iter().nth(1)?.clone());
                Some(syn::parse_quote_spanned!(span=> if #x == #y { unreachable!() }))
            }
            "panic" | "todo" | "unimplemented" => Some(syn::parse_quote_spanned!(span=> unreachable!())),
            "unreachable" if !m.mac.tokens.is_empty() => Some(syn::parse_quote_spanned!(span=> unreachable!())),
            _ => None,
        }
    }

    /// Inlines a template (module docs): `recv.m(args)`.
    pub(super) fn instantiate_template(&mut self, tpl: &syn::ItemFn, recv: syn::Expr, args: Vec<syn::Expr>, span: PSpan) -> Option<syn::Expr> {
        let params: Vec<(String, syn::Type)> = tpl.sig.inputs.iter().filter_map(|i| match i {
            syn::FnArg::Typed(pt) => Some((super::pat_ident(&pt.pat)?, (*pt.ty).clone())),
            _ => None,
        }).collect();
        // generic parameters with a closure bound
        let closure_params: HashSet<String> = tpl.sig.generics.params.iter().filter_map(|p| match p {
            syn::GenericParam::Type(tp) if tp.bounds.iter().any(|b| matches!(b, syn::TypeParamBound::Trait(tb) if tb.path.segments.last().is_some_and(|s| matches!(s.ident.to_string().as_str(), "FnOnce" | "Fn" | "FnMut")))) => Some(tp.ident.to_string()),
            _ => None,
        }).collect();
        // method-call auto-ref: a template receiver `self_: &T` takes `&recv`
        let recv_ref_param = params.first().is_some_and(|(_, t)| matches!(t, syn::Type::Reference(_)));
        let recv_is_ref = self.ty_of(&recv).is_some_and(|t| matches!(t, syn::Type::Reference(_)));
        let recv = if recv_ref_param && !recv_is_ref { syn::parse_quote!(&#recv) } else { recv };
        let mut all_args = vec![recv];
        all_args.extend(args);
        if all_args.len() != params.len() {
            self.cx.err(span, format!("`{}` takes {} argument(s)", tpl.sig.ident, params.len() - 1));
            return None;
        }
        self.fresh += 1;
        let tag = self.fresh;
        let body_expr: syn::Expr = syn::Expr::Block(syn::ExprBlock { attrs: vec![], label: None, block: (*tpl.block).clone() });
        let mut names: BTreeSet<String> = bound_names(&[], &body_expr).into_iter().filter(|n| n.chars().next().is_some_and(|c| c.is_lowercase() || c == '_')).collect();
        let mut stmts: Vec<syn::Stmt> = Vec::new();
        let mut closures: HashMap<String, syn::Expr> = HashMap::new();
        for ((pn, pt), a) in params.iter().zip(all_args) {
            let is_str = matches!(pt, syn::Type::Reference(r) if matches!(&*r.elem, syn::Type::Path(p) if p.path.is_ident("str")));
            if is_str {
                if !matches!(a, syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(_), .. })) {
                    self.cx.err(a.span(), "a message argument is lifted only as a string literal (it shapes the panic payload only)");
                }
                continue;
            }
            if matches!(pt, syn::Type::Path(p) if p.path.get_ident().is_some_and(|i| closure_params.contains(&i.to_string()))) {
                closures.insert(pn.clone(), a);
                continue;
            }
            names.insert(pn.clone());
            let id = format_ident!("__t{}_{}", tag, pn);
            stmts.push(syn::parse_quote!(let #id = #a;));
        }
        let map: HashMap<String, String> = names.iter().map(|n| (n.clone(), format!("__t{tag}_{n}"))).collect();
        let mut body = (*tpl.block).clone();
        Rename { map: &map }.visit_block_mut(&mut body);
        CorePaths.visit_block_mut(&mut body);
        // closure calls
        struct Calls<'a, 'b> {
            closures: &'a HashMap<String, syn::Expr>,
            rw: &'a mut FnRw<'b>,
            err: Option<(PSpan, String)>,
        }
        impl VisitMut for Calls<'_, '_> {
            fn visit_expr_mut(&mut self, e: &mut syn::Expr) {
                syn::visit_mut::visit_expr_mut(self, e);
                if let syn::Expr::Call(c) = e
                    && let syn::Expr::Path(p) = &*c.func
                    && let Some(id) = p.path.get_ident()
                    && let Some(f) = self.closures.get(&id.to_string())
                {
                    let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
                    match f {
                        syn::Expr::Closure(cl) => {
                            if let Err(why) = closure_inlinable(cl) {
                                self.err = Some((cl.span(), format!("{why} is not lifted")));
                                return;
                            }
                            if cl.inputs.len() != args.len() {
                                self.err = Some((cl.span(), "the closure takes a different number of arguments".into()));
                                return;
                            }
                            let rw = &mut *self.rw;
                            *e = inline_closure(cl, args, &mut |n| {
                                rw.fresh += 1;
                                format!("__c{}_{n}", rw.fresh)
                            });
                        }
                        syn::Expr::Path(fp) => {
                            *e = syn::parse_quote!(#fp(#(#args),*));
                        }
                        other => self.err = Some((other.span(), "a function argument of a core method is lifted as a closure or a path only".into())),
                    }
                }
            }
        }
        let mut calls = Calls { closures: &closures, rw: self, err: None };
        calls.visit_block_mut(&mut body);
        if let Some((sp, msg)) = calls.err {
            self.cx.err(sp, msg);
            return None;
        }
        stmts.extend(body.stmts);
        Some(syn::parse_quote_spanned!(span=> { #(#stmts)* }))
    }

    /// The result type of a template call (the receiver unified with the
    /// template's first parameter).
    pub(super) fn template_ret(&self, tpl: &syn::ItemFn, recv_t: &syn::Type, args: &[syn::Expr]) -> Option<syn::Type> {
        let syn::ReturnType::Type(_, rt) = &tpl.sig.output else { return Some(syn::parse_quote!(())) };
        let gens: Vec<String> = tpl.sig.generics.params.iter().filter_map(|p| match p {
            syn::GenericParam::Type(t) => Some(t.ident.to_string()),
            _ => None,
        }).collect();
        let first = tpl.sig.inputs.iter().find_map(|i| match i {
            syn::FnArg::Typed(pt) => Some((*pt.ty).clone()),
            _ => None,
        })?;
        let mut out: Vec<Option<syn::Type>> = vec![None; gens.len()];
        super::unify_names(&super::strip_refs(&first), &super::strip_refs(recv_t), &gens, &mut out);
        // closure arguments: their result types (the closure's parameters typed
        // by the bound's argument types)
        let bounds: HashMap<String, syn::TypeParamBound> = tpl.sig.generics.params.iter().filter_map(|p| match p {
            syn::GenericParam::Type(tp) => tp.bounds.iter().find(|b| matches!(b, syn::TypeParamBound::Trait(tb) if tb.path.segments.last().is_some_and(|s| s.ident.to_string().starts_with("Fn")))).map(|b| (tp.ident.to_string(), b.clone())),
            _ => None,
        }).collect();
        let ptys: Vec<syn::Type> = tpl.sig.inputs.iter().filter_map(|i| match i {
            syn::FnArg::Typed(pt) => Some((*pt.ty).clone()),
            _ => None,
        }).skip(1).collect();
        for (pt, a) in ptys.iter().zip(args) {
            let Some(g) = pt_ident(pt) else { continue };
            // a plain argument typed by a parameter of the template (`ok_or(err)`)
            if !bounds.contains_key(&g)
                && !matches!(a, syn::Expr::Closure(_))
                && let Some(i) = gens.iter().position(|x| *x == g)
                && out[i].is_none()
                && let Some(at) = self.ty_of(a)
            {
                out[i] = Some(at);
                continue;
            }
            let Some(syn::TypeParamBound::Trait(tb)) = bounds.get(&g) else { continue };
            let syn::Expr::Closure(cl) = a else { continue };
            let Some(seg) = tb.path.segments.last() else { continue };
            let syn::PathArguments::Parenthesized(pa) = &seg.arguments else { continue };
            let sigma_now: HashMap<String, syn::Type> = gens.iter().cloned().zip(out.iter().cloned()).filter_map(|(n, t)| t.map(|t| (n, t))).collect();
            let mut scope: HashMap<String, syn::Type> = HashMap::new();
            for (cp, at) in cl.inputs.iter().zip(pa.inputs.iter()) {
                let at = self.cx.subst_ty(at, &sigma_now);
                match cp {
                    syn::Pat::Ident(pi) => {
                        scope.insert(pi.ident.to_string(), at);
                    }
                    syn::Pat::Type(ptp) => {
                        if let Some(n) = super::pat_ident(&ptp.pat) {
                            scope.insert(n, (*ptp.ty).clone());
                        }
                    }
                    _ => {}
                }
            }
            self.extra_scopes.borrow_mut().push(scope);
            let bt = self.ty_of(&cl.body);
            self.extra_scopes.borrow_mut().pop();
            if let (Some(bt), syn::ReturnType::Type(_, rt)) = (bt, &pa.output) {
                super::unify_names(rt, &bt, &gens, &mut out);
            }
        }
        let sigma: HashMap<String, syn::Type> = gens.iter().cloned().zip(out).filter_map(|(n, t)| t.map(|t| (n, t))).collect();
        let mut r = self.cx.subst_ty(rt, &sigma);
        CorePaths.visit_type_mut(&mut r);
        // an unresolved generic parameter: unknown
        let s = super::ty_key(&r);
        if gens.iter().any(|g| s.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == g)) {
            return None;
        }
        Some(r)
    }

    /// The type an unannotated `let x = <untyped integer>` gets from its
    /// uses in `rest` (what rustc infers), when a use forces one.
    pub(super) fn infer_from_uses(&mut self, x: &str, rest: &[syn::Stmt]) -> Option<syn::Type> {
        self.push_scope();
        let mut found = None;
        for st in rest {
            if found.is_some() {
                break;
            }
            match st {
                syn::Stmt::Local(l) => {
                    if let Some(i) = &l.init {
                        found = self.demand(&i.expr, x, None);
                        if found.is_none()
                            && let Some(n) = super::pat_ident(&l.pat)
                        {
                            let t = match &l.pat {
                                syn::Pat::Type(pt) => Some((*pt.ty).clone()),
                                _ => self.ty_of(&i.expr),
                            };
                            if n == x {
                                break;
                            }
                            if let Some(t) = t {
                                self.bind(&n, t);
                            }
                        }
                    }
                }
                syn::Stmt::Expr(e, semi) => {
                    let exp = if semi.is_none() { self.ret.clone() } else { None };
                    found = self.demand(e, x, exp.as_ref());
                }
                _ => {}
            }
        }
        self.pop_scope();
        found
    }

    /// The type `e` (expected to have type `exp`) demands of the variable
    /// `x` at one of its uses.
    fn demand(&mut self, e: &syn::Expr, x: &str, exp: Option<&syn::Type>) -> Option<syn::Type> {
        use syn::BinOp as B;
        let is_x = |e: &syn::Expr| matches!(e, syn::Expr::Path(p) if p.path.is_ident(x));
        if is_x(e) {
            return exp.cloned();
        }
        match e {
            syn::Expr::Paren(p) => self.demand(&p.expr, x, exp),
            syn::Expr::Binary(b) => {
                let lt = self.ty_of(&b.left);
                let rt = self.ty_of(&b.right);
                match b.op {
                    B::Shl(_) | B::Shr(_) | B::ShlAssign(_) | B::ShrAssign(_) => self.demand(&b.left, x, exp.or(lt.as_ref())),
                    B::Eq(_) | B::Ne(_) | B::Lt(_) | B::Le(_) | B::Gt(_) | B::Ge(_) => {
                        let l = self.demand(&b.left, x, rt.as_ref());
                        l.or_else(|| self.demand(&b.right, x, lt.as_ref()))
                    }
                    B::And(_) | B::Or(_) => {
                        let l = self.demand(&b.left, x, None);
                        l.or_else(|| self.demand(&b.right, x, None))
                    }
                    _ => {
                        // compound assignment to a struct place: the impl's argument
                        let rexp: Option<syn::Type> = match (&lt, binop_trait(&b.op)) {
                            (Some(t), Some((tr, _))) if tr.ends_with("Assign") => match self.struct_of(t) {
                                Some(s) => self.op_lookup(&s, tr, None).and_then(|(_, k)| syn::parse_str(&k).ok()),
                                None => Some(t.clone()),
                            },
                            (Some(t), Some((tr, _))) if self.struct_of(t).is_some() => {
                                let s = self.struct_of(t).unwrap();
                                self.op_lookup(&s, tr, None).and_then(|(_, k)| syn::parse_str(&k).ok())
                            }
                            _ => None,
                        };
                        let assign = binop_trait(&b.op).is_some_and(|(tr, _)| tr.ends_with("Assign"));
                        let lexp = if assign { None } else { exp.cloned().or(rt.clone()) };
                        let l = self.demand(&b.left, x, lexp.as_ref());
                        l.or_else(|| {
                            let re = rexp.or(if assign { lt.clone() } else { exp.cloned().or(lt.clone()) });
                            self.demand(&b.right, x, re.as_ref())
                        })
                    }
                }
            }
            syn::Expr::Struct(s) => {
                let sname = s.path.segments.last().map(|p| p.ident.to_string()).map(|n| if n == "Self" { self.self_ty.as_ref().and_then(super::type_name).unwrap_or(n) } else { n })?;
                let si = self.cx.structs.get(&sname)?.clone();
                for f in &s.fields {
                    if let syn::Member::Named(fname) = &f.member {
                        let fty = si.def.fields.iter().find(|d| d.ident.as_ref() == Some(fname)).map(|d| d.ty.clone());
                        if let Some(t) = self.demand(&f.expr, x, fty.as_ref()) {
                            return Some(t);
                        }
                    }
                }
                None
            }
            syn::Expr::Assign(a) => {
                let lt = self.ty_of(&a.left);
                self.demand(&a.right, x, lt.as_ref())
            }
            syn::Expr::If(i) => {
                let c = self.demand(&i.cond, x, None);
                c.or_else(|| self.demand_block(&i.then_branch, x, exp)).or_else(|| i.else_branch.as_ref().and_then(|(_, e)| self.demand(e, x, exp)))
            }
            syn::Expr::While(w) => {
                let c = self.demand(&w.cond, x, None);
                c.or_else(|| self.demand_block(&w.body, x, None))
            }
            syn::Expr::Block(b) => self.demand_block(&b.block, x, exp),
            syn::Expr::Return(r) => {
                let ret = self.ret.clone();
                r.expr.as_ref().and_then(|e| self.demand(e, x, ret.as_ref()))
            }
            syn::Expr::Tuple(t) => {
                let elems: Vec<Option<syn::Type>> = match exp {
                    Some(syn::Type::Tuple(tt)) => tt.elems.iter().cloned().map(Some).collect(),
                    _ => vec![None; t.elems.len()],
                };
                t.elems.iter().zip(elems).find_map(|(e, et)| self.demand(e, x, et.as_ref()))
            }
            syn::Expr::MethodCall(mc) => {
                let r = self.demand(&mc.receiver, x, None);
                r.or_else(|| mc.args.iter().find_map(|a| self.demand(a, x, None)))
            }
            syn::Expr::Call(c) => c.args.iter().find_map(|a| self.demand(a, x, None)),
            syn::Expr::Macro(m) => {
                let args = m.mac.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated).ok()?;
                let v: Vec<syn::Expr> = args.into_iter().collect();
                if v.len() >= 2 && m.mac.path.segments.last().is_some_and(|s| s.ident.to_string().starts_with("assert_")) {
                    let t0 = self.ty_of(&v[0]);
                    let t1 = self.ty_of(&v[1]);
                    return self.demand(&v[0], x, t1.as_ref()).or_else(|| self.demand(&v[1], x, t0.as_ref()));
                }
                v.iter().find_map(|a| self.demand(a, x, None))
            }
            _ => None,
        }
    }

    fn demand_block(&mut self, b: &syn::Block, x: &str, exp: Option<&syn::Type>) -> Option<syn::Type> {
        let n = b.stmts.len();
        for (i, st) in b.stmts.iter().enumerate() {
            let r = match st {
                syn::Stmt::Local(l) => l.init.as_ref().and_then(|i| self.demand(&i.expr, x, None)),
                syn::Stmt::Expr(e, semi) => self.demand(e, x, if i + 1 == n && semi.is_none() { exp } else { None }),
                syn::Stmt::Macro(m) => {
                    let e = syn::Expr::Macro(syn::ExprMacro { attrs: vec![], mac: m.mac.clone() });
                    self.demand(&e, x, None)
                }
                _ => None,
            };
            if r.is_some() {
                return r;
            }
        }
        None
    }

    /// A `while` with `return`/`continue`/`break` at the top level of the
    /// body, followed by `rest`: a tail-recursive helper (module docs).
    /// Returns the call that replaces the loop and the rest.
    pub(super) fn while_helper(&mut self, w: syn::ExprWhile, rest: Vec<syn::Stmt>) -> syn::Expr {
        let k = self.while_index;
        self.while_index += 1;
        let hname = format_ident!("{}__while{}", self.lifted_name, k, span = w.span());
        let has_self = self.local_ty("self").is_some();
        let self_state = self.is_state("self");
        // the locals the loop and the rest mention, in scope here
        let at = self.loop_attach_stmts(k);
        let names = idents_in(&[&w.cond, &w.body, &RestTokens(&rest), &RestTokens(&at)]);
        let mut params: Vec<(String, syn::Type)> = Vec::new();
        for n in &names {
            if n == "self" || self.is_state(n) {
                continue;
            }
            if let Some(t) = self.local_ty(n) {
                params.push((n.clone(), t));
            }
        }
        let other_states: Vec<(String, syn::Type)> = self.states.iter().filter(|(s, _)| s != "self").cloned().collect();
        let call_args: Vec<syn::Ident> = params.iter().map(|(n, _)| format_ident!("{}", n)).chain(other_states.iter().map(|(n, _)| format_ident!("{}", n))).collect();
        let call: syn::Expr = if has_self {
            syn::parse_quote!(Self::#hname(self, #(#call_args),*))
        } else {
            syn::parse_quote!(#hname(#(#call_args),*))
        };
        // the rest, as the exit branch: its statements, then its value returned
        let mut rest = rest;
        let tail: syn::Expr = match rest.last() {
            Some(syn::Stmt::Expr(_, None)) => {
                let syn::Stmt::Expr(e, _) = rest.pop().unwrap() else { unreachable!() };
                e
            }
            _ => syn::parse_quote!(()),
        };
        let exit: syn::Block = syn::parse_quote!({ #(#rest)* return #tail; });
        // `continue` → the recursive call; `break` → the rest's value when
        // the rest is only a value
        let ret_call: syn::Expr = syn::parse_quote!(return #call);
        let brk: Option<syn::Expr> = if rest.is_empty() { Some(syn::parse_quote!(return #tail)) } else { None };
        let mut body = w.body.clone();
        let mut rc = ReplaceControl { cont: &ret_call, brk: brk.as_ref(), depth: 0, bad_break: false };
        rc.visit_block_mut(&mut body);
        if rc.bad_break {
            self.cx.err(w.span(), "a `break` (with a value or a label, or before more statements than a value) in a lifted `while` is not supported");
        }
        let cond = &w.cond;
        // the test is the branch condition itself (not its negation), so the
        // body's branch has `cond == true` as a fact in the form proof
        // steps name it
        let mut hbody: syn::Block = syn::parse_quote!({
            if #cond {
                #body
                return #call;
            } else #exit
        });
        // a `&mut self` helper works on `self`'s fields as locals (a struct
        // invariant may be broken between two field updates, as in any
        // unpacked value) and rebuilds `self` where it leaves: at returns
        // and at the recursive call (`rebuild_self`)
        let unpack = if has_self && self_state { self.self_fields() } else { None };
        let saved_unpacked = self.unpacked_self.take();
        if let Some(fields) = &unpack {
            let mut u = UnpackSelf { fields, bad: false };
            u.visit_block_mut(&mut hbody);
            if u.bad {
                self.cx.err(w.span(), "a lifted `while` in a `&mut self` method uses `self` other than through its fields");
            }
            // one `let` per field, bound to the projection (not a
            // destructuring match): the facts about `self`'s fields (its
            // invariant, `at_start!` steps) are facts about the locals
            for (i, (f, l)) in fields.iter().skip(1).enumerate() {
                let (f, l) = (format_ident!("{}", f), format_ident!("{}", l));
                let st: syn::Stmt = syn::parse_quote!(let mut #l = self.#f;);
                hbody.stmts.insert(i, st);
            }
            self.unpacked_self = Some(fields.clone());
        }
        // lift the helper's body with the parameters bound
        self.push_scope();
        for (n, t) in &params {
            self.bind(n, t.clone());
        }
        if let (Some(fields), Some(st)) = (&unpack, self.self_ty.clone())
            && let Some(sn) = super::type_name(&st)
            && let Some(si) = self.cx.structs.get(&sn).cloned()
        {
            for (f, l) in fields.iter().skip(1) {
                if let Some(fd) = si.def.fields.iter().find(|d| d.ident.as_ref().is_some_and(|i| i == f.as_str())) {
                    let mut t = fd.ty.clone();
                    self.ty(&mut t);
                    self.bind(l, t);
                }
            }
        }
        self.block(&mut hbody);
        self.pop_scope();
        self.unpacked_self = saved_unpacked;
        // attachment: measure, invariant, ensures
        let mut attrs: Vec<syn::Attribute> = Vec::new();
        let mut helper_start: Vec<syn::Stmt> = Vec::new();
        if let Some(at) = self.cx.attach_loop.get(&(self.fn_name.clone(), k)).cloned() {
            self.cx.attach_used.insert(format!("loop {}#{k}", self.fn_name));
            self.check_attach_params(&at);
            for st in &at.stmts {
                let saved = self.ghost;
                self.ghost = true;
                if let Some(mut e) = super::attach_call(st, "decreases") {
                    self.expr(&mut e, None);
                    attrs.push(syn::parse_quote!(#[decreases(#e)]));
                } else if let Some(mut e) = super::attach_call(st, "invariant") {
                    self.expr(&mut e, None);
                    attrs.push(syn::parse_quote!(#[requires(#e)]));
                } else if let Some(mut e) = super::attach_call(st, "ensures") {
                    self.expr(&mut e, None);
                    attrs.push(syn::parse_quote!(#[ensures(#e)]));
                } else if let syn::Stmt::Macro(m) = st
                    && m.mac.path.is_ident("at_start")
                {
                    match m.mac.parse_body_with(syn::Block::parse_within) {
                        Ok(mut steps) => {
                            for s2 in steps.iter_mut() {
                                self.ghost_stmt(s2);
                            }
                            // in a `&mut self` helper the steps run after the
                            // unpacking and speak of the field locals, the
                            // values the body's tests are about
                            if let Some(fields) = &unpack {
                                let mut u = UnpackSelf { fields, bad: false };
                                for s2 in steps.iter_mut() {
                                    u.visit_stmt_mut(s2);
                                }
                                if u.bad {
                                    self.cx.err(m.span(), "an `at_start!` of a `&mut self` loop uses `self` other than through its fields");
                                }
                            }
                            helper_start.push(syn::parse_quote!(proof! { #(#steps)* }));
                        }
                        Err(e) => self.cx.err(m.span(), format!("malformed `at_start!`: {e}")),
                    }
                } else {
                    self.cx.err(st.span(), "a loop attachment holds `invariant(..);`, `decreases(..);`, `ensures(..);` and `at_start! { .. }`");
                }
                self.ghost = saved;
            }
        }
        let at = unpack.as_ref().map_or(0, |f| f.len() - 1);
        for (i, st) in helper_start.into_iter().enumerate() {
            hbody.stmts.insert(at + i, st);
        }
        let mut inputs: Vec<syn::FnArg> = Vec::new();
        if has_self {
            inputs.push(if self_state { syn::parse_quote!(mut self) } else { syn::parse_quote!(self) });
        }
        for (n, t) in params.iter().chain(other_states.iter()) {
            let id = format_ident!("{}", n);
            inputs.push(syn::parse_quote!(mut #id: #t));
        }
        let out_ty: syn::Type = {
            let mut parts: Vec<syn::Type> = self.states.iter().map(|(_, t)| t.clone()).collect();
            if let Some(r) = &self.ret {
                parts.push(r.clone());
            }
            if parts.is_empty() { syn::parse_quote!(()) } else if parts.len() == 1 { parts.remove(0) } else { syn::parse_quote!((#(#parts),*)) }
        };
        if has_self {
            attrs.push(syn::parse_quote!(#[lift_method]));
        }
        let helper: syn::ItemFn = syn::parse_quote!(
            #(#attrs)*
            fn #hname(#(#inputs),*) -> #out_ty #hbody
        );
        self.helpers.push(syn::Item::Fn(helper));
        call
    }
}

/// `self.f` → the field's local, a recursive call's `self` → the rebuilt
/// value (`FnRw::while_helper`); any other `self` is refused.
struct UnpackSelf<'a> {
    fields: &'a [(String, String)],
    bad: bool,
}

impl VisitMut for UnpackSelf<'_> {
    fn visit_expr_mut(&mut self, e: &mut syn::Expr) {
        if let syn::Expr::Field(f) = e
            && matches!(&*f.base, syn::Expr::Path(p) if p.path.is_ident("self"))
            && let syn::Member::Named(n) = &f.member
            && let Some((_, l)) = self.fields.iter().skip(1).find(|(fname, _)| n == fname.as_str())
        {
            let id = format_ident!("{}", l);
            *e = syn::parse_quote!(#id);
            return;
        }
        if let syn::Expr::Call(c) = e
            && let syn::Expr::Path(fp) = &*c.func
            && fp.path.segments.first().is_some_and(|s| s.ident == "Self")
            && fp.path.segments.last().is_some_and(|s| s.ident.to_string().contains("__while"))
            && matches!(c.args.first(), Some(syn::Expr::Path(p)) if p.path.is_ident("self"))
        {
            c.args[0] = rebuild_self(self.fields);
            for a in c.args.iter_mut().skip(1) {
                self.visit_expr_mut(a);
            }
            return;
        }
        if matches!(e, syn::Expr::Path(p) if p.path.is_ident("self")) {
            self.bad = true;
        }
        syn::visit_mut::visit_expr_mut(self, e);
    }

    /// A macro's arguments (`assert!(self.a >= self.b, ..)`) are
    /// expressions too: the fields they read are the locals (a macro whose
    /// body is not a list of expressions is left alone; the lift refuses it
    /// later).
    fn visit_macro_mut(&mut self, m: &mut syn::Macro) {
        if let Ok(mut args) = m.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
            for a in args.iter_mut() {
                self.visit_expr_mut(a);
            }
            m.tokens = quote!(#args);
        }
    }
}

/// `S { f: local, .. }`: an unpacked `self` rebuilt (`fields[0]` is the
/// struct's name paired with nothing).
pub fn rebuild_self(fields: &[(String, String)]) -> syn::Expr {
    let name = format_ident!("{}", fields.first().map(|f| f.0.as_str()).unwrap_or("Self"));
    let inits: Vec<proc_macro2::TokenStream> = fields.iter().skip(1).map(|(f, l)| {
        let (f, l) = (format_ident!("{}", f), format_ident!("{}", l));
        quote!(#f: #l)
    }).collect();
    syn::parse_quote!(#name { #(#inits),* })
}

impl FnRw<'_> {
    /// The named fields of the method's `self` type, with their locals
    /// (`__self_f`), when it is a lifted struct with named fields.
    fn self_fields(&self) -> Option<Vec<(String, String)>> {
        let st = self.self_ty.as_ref()?;
        let sn = super::type_name(st)?;
        let si = self.cx.structs.get(&sn)?;
        let syn::Fields::Named(fs) = &si.def.fields else { return None };
        let mut v = vec![(sn.clone(), String::new())];
        v.extend(fs.named.iter().filter_map(|f| f.ident.as_ref().map(|i| (i.to_string(), format!("__self_{i}")))));
        Some(v)
    }
}

impl FnRw<'_> {
    /// Whether the next `while` of the function has an attachment with an
    /// `ensures(..)`: a summary of the loop and the rest of the body, so it
    /// is lifted as a helper (whose result the summary describes).
    pub(super) fn next_loop_has_ensures(&self) -> bool {
        self.cx.attach_loop.get(&(self.fn_name.clone(), self.while_index)).is_some_and(|at| at.stmts.iter().any(|st| super::attach_call(st, "ensures").is_some()))
    }
}

/// Tokens of a statement list (for [`idents_in`]).
struct RestTokens<'a>(&'a [syn::Stmt]);
impl ToTokens for RestTokens<'_> {
    fn to_tokens(&self, ts: &mut proc_macro2::TokenStream) {
        for s in self.0 {
            s.to_tokens(ts);
        }
    }
}

impl OpenCtx {
    /// The module path of a primitive impl's free function.
    pub fn prim_fn_module(&self, _prim: &str, name: &str) -> String {
        self.prim_modules.get(name).cloned().unwrap_or_else(|| "crate".into())
    }
}

// ---------------------------------------------------------------------------
// impls: declarations and emission
// ---------------------------------------------------------------------------

impl Ctx {
    /// Registers an impl this extension lifts (open-trait instances,
    /// operator and method traits); `true` when the impl is handled here.
    pub(super) fn collect_open_impl(&mut self, modname: &str, im: &syn::ItemImpl) -> bool {
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
                    self.methods.insert((sn.clone(), f.sig.ident.to_string()), super::method_info(&f.sig, vec![]));
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
                        self.methods.insert((sn.clone(), f.sig.ident.to_string()), super::method_info(&f.sig, vec![]));
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
                        self.open.op_impls.insert((sn.clone(), tname.clone(), arg.clone()), name.clone());
                        let mp = self.open.module_paths.get(modname).cloned().unwrap_or_else(|| format!("crate::{modname}"));
                        self.open.prim_modules.insert(name.clone(), mp);
                        self.open.prim_sigs.insert(name, f.sig.clone());
                    } else {
                        let name = op_method_name(&m, &arg);
                        self.open.op_impls.insert((sn.clone(), tname.clone(), arg.clone()), name.clone());
                        let mut sig = f.sig.clone();
                        sig.ident = format_ident!("{}", name);
                        self.methods.insert((sn.clone(), name), super::method_info(&sig, vec![]));
                    }
                }
            }
            return true;
        }
        if METHOD_TRAITS.contains(&tname.as_str()) && tname != "Default" && !prim_self {
            for ii in &im.items {
                match ii {
                    syn::ImplItem::Fn(f) => {
                        self.methods.insert((sn.clone(), f.sig.ident.to_string()), super::method_info(&f.sig, vec![]));
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
        let mut steps: Vec<syn::Stmt> = Vec::new();
        let key = format!("{}::default", s.ident);
        if let Some(at) = self.attach_fn.get(&key).cloned() {
            self.attach_used.insert(format!("fn {key}"));
            for st in &at.stmts {
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
                    self.err(st.span(), "an attachment to a derived `default` holds `ensures(..);` and `at_start! { .. }` only");
                    continue;
                };
                let mut rw = super::FnRw::new(self, HashMap::new(), true);
                rw.expr(&mut e, None);
                drop(rw);
                contract.push(syn::parse_quote!(#[ensures(#e)]));
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
    /// The concrete type of an `-> impl Iterator<Item = X>` function (module
    /// docs); a range tail becomes the prelude iterator.
    pub(super) fn impl_trait_concrete(&mut self, t: &syn::Type, block: &mut syn::Block, self_ty: Option<&syn::Type>) -> Option<syn::Type> {
        let syn::Type::ImplTrait(it) = t else { return None };
        let item: Option<syn::Type> = it.bounds.iter().find_map(|b| match b {
            syn::TypeParamBound::Trait(tb) => {
                let seg = tb.path.segments.last()?;
                if seg.ident != "Iterator" {
                    return None;
                }
                match &seg.arguments {
                    syn::PathArguments::AngleBracketed(a) => a.args.iter().find_map(|x| match x {
                        syn::GenericArgument::AssocType(at) if at.ident == "Item" => Some(at.ty.clone()),
                        _ => None,
                    }),
                    _ => None,
                }
            }
            _ => None,
        });
        let span = t.span();
        let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last_mut() else {
            self.err(span, "`impl Trait` result: the body must end in the returned expression");
            return None;
        };
        let elem = |item: &Option<syn::Type>| item.as_ref().and_then(super::type_name).filter(|n| matches!(n.as_str(), "u32" | "u64"));
        match tail {
            syn::Expr::Range(r) if r.start.is_some() && r.end.is_some() => {
                let Some(n) = elem(&item) else {
                    self.err(span, "a range returned as `impl Iterator` is lifted for `u32` and `u64` items");
                    return None;
                };
                let (a, b) = (r.start.clone().unwrap(), r.end.clone().unwrap());
                let up = n.to_uppercase();
                if matches!(r.limits, syn::RangeLimits::Closed(_)) {
                    let f = format_ident!("range_inclusive_{}", n);
                    *tail = syn::parse_quote!(crate::__lift::#f(#a, #b));
                    let ty = format_ident!("RangeInclusive{}", up);
                    Some(syn::parse_quote!(crate::__lift::#ty))
                } else {
                    let ty = format_ident!("Range{}", up);
                    *tail = syn::parse_quote!(crate::__lift::#ty { start: #a, end: #b });
                    Some(syn::parse_quote!(crate::__lift::#ty))
                }
            }
            syn::Expr::Call(c) => {
                let syn::Expr::Path(fp) = &*c.func else {
                    self.err(span, "`impl Trait` result: the lift cannot tell the concrete type");
                    return None;
                };
                let segs: Vec<String> = fp.path.segments.iter().map(|s| s.ident.to_string()).collect();
                if segs == ["crate", "__lift", "once"] {
                    let Some(it) = item else {
                        self.err(span, "`once(..)` returned as `impl Iterator` needs `Item = T`");
                        return None;
                    };
                    return Some(syn::parse_quote!(crate::__lift::Once<#it>));
                }
                // `path::S::m(..)` with `m` returning `Self`
                if segs.len() >= 2 {
                    let s = if segs[segs.len() - 2] == "Self" { self_ty.and_then(super::type_name).unwrap_or_default() } else { segs[segs.len() - 2].clone() };
                    if let Some(mi) = self.methods.get(&(s.clone(), segs[segs.len() - 1].clone()))
                        && mi.sig.as_ref().is_some_and(|sg| matches!(&sg.output, syn::ReturnType::Type(_, r) if super::type_name(r).as_deref() == Some("Self")))
                    {
                        let mut p = fp.path.clone();
                        p.segments.pop();
                        let pp: syn::Path = syn::Path { leading_colon: p.leading_colon, segments: p.segments.into_pairs().map(|x| x.into_value()).collect() };
                        return Some(syn::Type::Path(syn::TypePath { qself: None, path: pp }));
                    }
                }
                self.err(span, "`impl Trait` result: the lift cannot tell the concrete type of this call");
                None
            }
            _ => {
                self.err(span, "`impl Trait` result: the lift cannot tell the concrete type");
                None
            }
        }
    }
}

impl FnRw<'_> {
    /// Before a statement is lifted (exec code): a local closure is
    /// recorded and removed (`true`); an unannotated `let` of an untyped
    /// integer gets the type its uses in `rest` force.
    pub(super) fn pre_stmt(&mut self, st: &mut syn::Stmt, rest: &[syn::Stmt]) -> bool {
        if self.ghost {
            return false;
        }
        let syn::Stmt::Local(l) = st else { return false };
        let Some(init) = &mut l.init else { return false };
        if let syn::Expr::Closure(c) = &*init.expr
            && let syn::Pat::Ident(pi) = &l.pat
        {
            if let Err(why) = closure_inlinable(c) {
                self.cx.err(c.span(), format!("{why} is not lifted"));
                return true;
            }
            let captured = free_idents(c);
            // a captured variable re-bound or assigned while the closure lives
            // would change what an inlined call reads
            let mut bad: Option<String> = None;
            for s2 in rest {
                let ts = s2.to_token_stream();
                if let Ok(b) = syn::parse2::<syn::Block>(quote!({ #ts })) {
                    struct V<'a>(&'a BTreeSet<String>, Option<String>);
                    impl<'ast> syn::visit::Visit<'ast> for V<'_> {
                        fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
                            if self.0.contains(&p.ident.to_string()) {
                                self.1 = Some(p.ident.to_string());
                            }
                        }
                        fn visit_expr_assign(&mut self, a: &'ast syn::ExprAssign) {
                            if let syn::Expr::Path(p) = &*a.left
                                && let Some(i) = p.path.get_ident()
                                && self.0.contains(&i.to_string())
                            {
                                self.1 = Some(i.to_string());
                            }
                            syn::visit::visit_expr_assign(self, a);
                        }
                        fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
                            if binop_trait(&b.op).is_some_and(|(t, _)| t.ends_with("Assign"))
                                && let syn::Expr::Path(p) = &*b.left
                                && let Some(i) = p.path.get_ident()
                                && self.0.contains(&i.to_string())
                            {
                                self.1 = Some(i.to_string());
                            }
                            syn::visit::visit_expr_binary(self, b);
                        }
                    }
                    let mut v = V(&captured, None);
                    syn::visit::Visit::visit_block(&mut v, &b);
                    if v.1.is_some() {
                        bad = v.1;
                    }
                }
            }
            if let Some(n) = bad {
                self.cx.err(c.span(), format!("the closure captures `{n}`, which is re-bound or assigned while the closure lives: inlining its calls would read another value"));
                return true;
            }
            self.closures.insert(pi.ident.to_string(), (c.clone(), captured));
            return true;
        }
        if let syn::Pat::Ident(pi) = &l.pat
            && untyped_int(&init.expr)
        {
            let name = pi.ident.to_string();
            if let Some(t) = self.infer_from_uses(&name, rest)
                && super::type_name(&t).is_some_and(|n| super::is_prim(&n))
            {
                suffix_untyped(&mut init.expr, &t);
                let pat = l.pat.clone();
                l.pat = syn::Pat::Type(syn::PatType { attrs: vec![], pat: Box::new(pat), colon_token: Default::default(), ty: Box::new(t) });
            }
        }
        false
    }

    /// A call of a local closure: inlined.
    pub(super) fn closure_call(&mut self, c: &syn::ExprCall) -> Option<syn::Expr> {
        let syn::Expr::Path(p) = &*c.func else { return None };
        let id = p.path.get_ident()?.to_string();
        let (cl, _) = self.closures.get(&id)?.clone();
        if cl.inputs.len() != c.args.len() {
            self.cx.err(c.span(), format!("the closure `{id}` takes {} argument(s)", cl.inputs.len()));
            return None;
        }
        let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
        let mut fresh = |n: &str| {
            self.fresh += 1;
            format!("__c{}_{n}", self.fresh)
        };
        Some(inline_closure(&cl, args, &mut fresh))
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

impl FnRw<'_> {
    /// `S::from(x)` / `S::try_from(x)` for a lifted struct `S` with several
    /// conversion impls: the one for `x`'s type (`from__u64`).
    pub(super) fn conversion_call(&mut self, c: &syn::ExprCall) -> Option<syn::Expr> {
        let syn::Expr::Path(fp) = &*c.func else { return None };
        let n = fp.path.segments.len();
        if n < 2 || c.args.len() != 1 {
            return None;
        }
        let m = fp.path.segments[n - 1].ident.to_string();
        let tr = match m.as_str() {
            "from" => "From",
            "try_from" => "TryFrom",
            _ => return None,
        };
        let owner = fp.path.segments[n - 2].ident.to_string();
        let owner = if owner == "Self" { self.self_ty.as_ref().and_then(super::type_name)? } else { owner };
        if !self.cx.structs.contains_key(&owner) {
            return None;
        }
        let at = self.ty_of(&c.args[0]);
        let Some((name, _)) = self.op_lookup(&owner, tr, at.as_ref()) else {
            self.cx.err(c.span(), format!("`{owner}::{m}`: no `{tr}` impl for this argument in the lifted sources"));
            return None;
        };
        let mut path = fp.path.clone();
        if let Some(last) = path.segments.last_mut() {
            last.ident = format_ident!("{}", name, span = last.ident.span());
        }
        let mut a = c.args[0].clone();
        self.expr(&mut a, None);
        Some(syn::parse_quote!(#path(#a)))
    }

    /// The type of a call of `S::from` / `S::try_from` (its impl's result).
    pub(super) fn conversion_ty(&self, c: &syn::ExprCall) -> Option<syn::Type> {
        let syn::Expr::Path(fp) = &*c.func else { return None };
        let n = fp.path.segments.len();
        if n < 2 || c.args.len() != 1 {
            return None;
        }
        let m = fp.path.segments[n - 1].ident.to_string();
        let tr = match m.as_str() {
            "from" => "From",
            "try_from" => "TryFrom",
            _ => return None,
        };
        let owner = fp.path.segments[n - 2].ident.to_string();
        let owner = if owner == "Self" { self.self_ty.as_ref().and_then(super::type_name)? } else { owner };
        let at = self.ty_of(&c.args[0]);
        let (name, _) = self.op_lookup(&owner, tr, at.as_ref())?;
        let mi = self.cx.methods.get(&(owner.clone(), name))?;
        let syn::ReturnType::Type(_, r) = &mi.sig.as_ref()?.output else { return None };
        let mut r = (**r).clone();
        let st: syn::Type = syn::parse_str(&owner).ok()?;
        super::ReplaceSelfAny { ty: st }.visit_type_mut(&mut r);
        Some(r)
    }
}

// ---------------------------------------------------------------------------
// `for` over iterators
// ---------------------------------------------------------------------------

impl FnRw<'_> {
    /// The state-passing `next` of an iterator type: a lifted struct's
    /// `next` method (`S::next`), or a prelude iterator's function.
    fn next_fn(&self, t: &syn::Type) -> Option<syn::Path> {
        let n = super::type_name(t)?;
        if let Some(s) = self.struct_of(t)
            && self.cx.methods.get(&(s.clone(), "next".into())).is_some_and(|mi| mi.mut_self)
        {
            let p = self.struct_path(&s);
            return Some(syn::parse_quote!(#p::next));
        }
        let f = match n.as_str() {
            "RangeU32" => "range_u32_next",
            "RangeInclusiveU32" => "range_inclusive_u32_next",
            "RangeU64" => "range_u64_next",
            "RangeInclusiveU64" => "range_inclusive_u64_next",
            "Once" => "once_next",
            _ => return None,
        };
        let id = format_ident!("{}", f);
        Some(syn::parse_quote!(crate::__lift::#id))
    }

    /// A range used as an iterator value: the prelude iterator (by the
    /// element type) and its type.
    fn range_iter(&mut self, r: &syn::ExprRange) -> Option<(syn::Expr, syn::Type)> {
        let (a, b) = (r.start.clone()?, r.end.clone()?);
        let t = self.ty_of(&a).or_else(|| self.ty_of(&b))?;
        let n = super::type_name(&t)?;
        if !matches!(n.as_str(), "u32" | "u64") {
            return None;
        }
        let up = n.to_uppercase();
        let (mut a, mut b) = (*a, *b);
        super::suffix_literal(&mut a, &t);
        super::suffix_literal(&mut b, &t);
        if matches!(r.limits, syn::RangeLimits::Closed(_)) {
            let f = format_ident!("range_inclusive_{}", n);
            let ty = format_ident!("RangeInclusive{}", up);
            Some((syn::parse_quote!(crate::__lift::#f(#a, #b)), syn::parse_quote!(crate::__lift::#ty)))
        } else {
            let ty = format_ident!("Range{}", up);
            Some((syn::parse_quote!(crate::__lift::#ty { start: #a, end: #b }), syn::parse_quote!(crate::__lift::#ty)))
        }
    }

    /// Whether a `for` needs a helper: its iterable is not a range, or its
    /// body has `return`/`continue`/`break`.
    pub(super) fn for_needs_helper(&self, f: &syn::ExprForLoop) -> bool {
        let (r, c, k) = has_control(&f.body);
        r || c || k || !matches!(&*f.expr, syn::Expr::Range(_))
    }

    /// `for pat in it { B }` followed by `rest` (module docs): the iterator
    /// is the local `iter` (attachments name it so), stepped by its
    /// state-passing `next` in a tail-recursive helper.
    pub(super) fn for_helper(&mut self, f: syn::ExprForLoop, rest: Vec<syn::Stmt>, pre: &mut Vec<syn::Stmt>) -> syn::Expr {
        let span = f.span();
        let k = self.while_index;
        self.while_index += 1;
        let hname = format_ident!("{}__for{}", self.lifted_name, k, span = span);
        if self.local_ty("iter").is_some() {
            self.cx.err(span, "a lifted `for` names its iterator `iter`, which is already a local here");
        }
        // the iterator value and its type
        let (mut init, ity): (syn::Expr, Option<syn::Type>) = match &*f.expr {
            syn::Expr::Range(r) => match self.range_iter(r) {
                Some((e, t)) => (e, Some(t)),
                None => ((*f.expr).clone(), None),
            },
            other => ((*other).clone(), self.ty_of(other)),
        };
        // `for x in f(..)` with `f` a lifted `-> impl Iterator` function:
        // the concrete type its body returns (errors of that reading are
        // reported where `f` itself is lifted)
        let ity = match (&ity, &*f.expr) {
            (Some(t @ syn::Type::ImplTrait(_)), syn::Expr::Call(c)) => {
                let body = match &*c.func {
                    syn::Expr::Path(fp) => fp.path.get_ident().and_then(|id| self.cx.fns.get(&id.to_string())).and_then(|fi| fi.impl_body.clone()),
                    _ => None,
                };
                match body {
                    Some(mut b) => {
                        let n = self.cx.errors.len();
                        let ct = self.cx.impl_trait_concrete(t, &mut b, None);
                        self.cx.errors.truncate(n);
                        ct.or(ity)
                    }
                    None => ity,
                }
            }
            _ => ity,
        };
        let Some(ity) = ity else {
            self.cx.err(span, "the lift cannot tell the type of this `for` loop's iterator");
            return syn::parse_quote!(());
        };
        let Some(next) = self.next_fn(&ity) else {
            self.cx.err(span, format!("`for` over `{}`: the lift knows no `next` for it (a lifted struct with an `Iterator` impl, a range of `u32`/`u64`, `once`)", super::ty_key(&ity)));
            return syn::parse_quote!(());
        };
        self.expr(&mut init, Some(&ity));
        pre.push(syn::parse_quote!(let iter: #ity = #init;));
        self.bind("iter", ity.clone());
        let has_self = self.local_ty("self").is_some();
        let self_state = self.is_state("self");
        let at = self.loop_attach_stmts(k);
        let names = idents_in(&[&f.body, &RestTokens(&rest), &RestTokens(&at)]);
        let mut params: Vec<(String, syn::Type)> = vec![("iter".into(), ity.clone())];
        for n in &names {
            if n == "self" || n == "iter" || self.is_state(n) {
                continue;
            }
            if let Some(t) = self.local_ty(n) {
                params.push((n.clone(), t));
            }
        }
        let other_states: Vec<(String, syn::Type)> = self.states.iter().filter(|(s, _)| s != "self").cloned().collect();
        let call_args: Vec<syn::Ident> = params.iter().map(|(n, _)| format_ident!("{}", n)).chain(other_states.iter().map(|(n, _)| format_ident!("{}", n))).collect();
        let call: syn::Expr = if has_self { syn::parse_quote!(Self::#hname(self, #(#call_args),*)) } else { syn::parse_quote!(#hname(#(#call_args),*)) };
        let mut rest = rest;
        let tail: syn::Expr = match rest.last() {
            Some(syn::Stmt::Expr(_, None)) => {
                let syn::Stmt::Expr(e, _) = rest.pop().unwrap() else { unreachable!() };
                e
            }
            _ => syn::parse_quote!(()),
        };
        let ret_call: syn::Expr = syn::parse_quote!(return #call);
        let brk: Option<syn::Expr> = if rest.is_empty() { Some(syn::parse_quote!(return #tail)) } else { None };
        let mut body = f.body.clone();
        let mut rc = ReplaceControl { cont: &ret_call, brk: brk.as_ref(), depth: 0, bad_break: false };
        rc.visit_block_mut(&mut body);
        if rc.bad_break {
            self.cx.err(span, "a `break` (with a value or a label, or before more statements than a value) in a lifted `for` is not supported");
        }
        let pat = &f.pat;
        self.fresh += 1;
        let (sn, si) = (format_ident!("__it{}_next", self.fresh), format_ident!("__it{}_item", self.fresh));
        let mut hbody: syn::Block = syn::parse_quote!({
            let (#sn, #si) = #next(iter);
            iter = #sn;
            match #si {
                None => { #(#rest)* return #tail; }
                Some(#pat) => { #body return #call; }
            }
        });
        self.push_scope();
        for (n, t) in &params {
            self.bind(n, t.clone());
        }
        self.block(&mut hbody);
        self.pop_scope();
        let mut attrs: Vec<syn::Attribute> = Vec::new();
        if let Some(at) = self.cx.attach_loop.get(&(self.fn_name.clone(), k)).cloned() {
            self.cx.attach_used.insert(format!("loop {}#{k}", self.fn_name));
            for st in &at.stmts {
                let saved = self.ghost;
                self.ghost = true;
                if let Some(mut e) = super::attach_call(st, "decreases") {
                    self.expr(&mut e, None);
                    attrs.push(syn::parse_quote!(#[decreases(#e)]));
                } else if let Some(mut e) = super::attach_call(st, "invariant") {
                    self.expr(&mut e, None);
                    attrs.push(syn::parse_quote!(#[requires(#e)]));
                } else if let Some(mut e) = super::attach_call(st, "ensures") {
                    self.expr(&mut e, None);
                    attrs.push(syn::parse_quote!(#[ensures(#e)]));
                } else {
                    self.cx.err(st.span(), "a `for` attachment holds `invariant(..);`, `decreases(..);` and `ensures(..);`");
                }
                self.ghost = saved;
            }
        }
        let mut inputs: Vec<syn::FnArg> = Vec::new();
        if has_self {
            inputs.push(if self_state { syn::parse_quote!(mut self) } else { syn::parse_quote!(self) });
        }
        for (n, t) in params.iter().chain(other_states.iter()) {
            let id = format_ident!("{}", n);
            inputs.push(syn::parse_quote!(mut #id: #t));
        }
        let out_ty: syn::Type = {
            let mut parts: Vec<syn::Type> = self.states.iter().map(|(_, t)| t.clone()).collect();
            if let Some(r) = &self.ret {
                parts.push(r.clone());
            }
            if parts.is_empty() { syn::parse_quote!(()) } else if parts.len() == 1 { parts.remove(0) } else { syn::parse_quote!((#(#parts),*)) }
        };
        if has_self {
            attrs.push(syn::parse_quote!(#[lift_method]));
        }
        let helper: syn::ItemFn = syn::parse_quote!(
            #(#attrs)*
            fn #hname(#(#inputs),*) -> #out_ty #hbody
        );
        self.helpers.push(syn::Item::Fn(helper));
        call
    }
}
