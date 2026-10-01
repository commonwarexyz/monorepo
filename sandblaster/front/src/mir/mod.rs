//! Lifting from rustc's MIR (`docs/mir-lift.md` §20; DESIGN.md §2.1).
//!
//! `#[lift(mir = "varint.sbmir", ..)] mod varint;` reads the **bodies** of
//! the module's functions from rustc's own MIR — monomorphized, fully typed,
//! macros expanded, `?`/closures/operators/iterators desugared by the
//! compiler — instead of reading the surface syntax of the source. The
//! `.sbmir` file is written by `sandblaster-mirx` (a rustc driver on the
//! pinned nightly of the stable release the crate builds with; see
//! `sandblaster/mirx`) and checked in next to the laws; it names the source
//! files it was extracted from with their SHA-256, and a build whose sources
//! differ refuses it ("re-run the extraction").
//!
//! What stays with the source lift ([`crate::lift`]) is the **item
//! skeleton**: which items exist, their lifted names and signatures (state
//! passing), the struct and enum declarations, the sealed-trait families
//! the laws are monomorphized over, and the attachments. For every lifted
//! function the reading of its body comes from here; the lift's signature
//! is checked against rustc's (parameter count, which parameters are
//! `&mut` states). The source lift's body rewrites (`?`, combinator
//! templates, operator impls, loop desugaring, macro expansion, closures,
//! constant evaluation of `T::SIZE`) are not used for such a module.
//!
//! Trusted (TCB item 8, "the reading"): `read.rs` (the reading of MIR
//! constructs), the type and constructor names below, the builtin leaves
//! (`read::builtin_leaf`: `Ord::max`/`min`, `div_ceil`), and the printer
//! `sandblaster-mirx` (it transcribes rustc's data). Untrusted: the
//! S-expression parser, `cfg.rs` (it only chooses the shape), the matching
//! of lifted functions to MIR instances (a mismatch is a name or type
//! error). The lift conformance check compares every read function with
//! rustc's build of the source, as for the source lift.

pub mod cfg;
pub mod ir;
pub mod read;
pub mod sexp;

use std::collections::{BTreeMap, BTreeSet};

use ir::{Fn, Item, Sbmir, Ty};
use read::{Ctor, LiftedCallee, Names};

/// The host traits whose impls on module types are lifted as inherent
/// methods (as the source lift does).
const HOST_TRAITS: &[&str] = &["Write", "Read", "EncodeSize", "Default", "FixedSize"];
/// Operator, comparison and conversion traits (named by their right-hand
/// type, SEMANTICS.md §19.8) and the method traits lifted as inherent
/// methods — the source lift's tables (`lift_open::OP_TRAITS`,
/// `METHOD_TRAITS`).
const OP_TRAITS: &[&str] = &["Add", "Sub", "Mul", "Div", "Rem", "BitAnd", "BitOr", "BitXor", "Shl", "Shr", "AddAssign", "SubAssign", "MulAssign", "DivAssign", "RemAssign", "BitAndAssign", "BitOrAssign", "BitXorAssign", "ShlAssign", "ShrAssign", "PartialEq", "PartialOrd", "Ord", "From", "TryFrom"];
const METHOD_TRAITS: &[&str] = &["Deref", "AsRef", "Iterator"];

/// The names of a lifted module in the subset.
#[derive(Debug)]
pub struct ModuleNames {
    /// `commonware_codec::varint`.
    pub module: String,
    /// Sealed traits of the module (their impl methods are free functions).
    pub sealed: BTreeSet<String>,
    /// Host-model enums: name → variant names.
    pub host_enums: BTreeMap<String, Vec<String>>,
    /// Source functions with a `requires` attachment (`write`,
    /// `Decoder::feed`): their calls are obligations, bound where they occur.
    pub requires: BTreeSet<String>,
    /// Open traits read at one instance (SEMANTICS.md §19.6): trait name →
    /// the instance's path in the crate (`Family` → `merkle::mmr::Family`).
    /// The instance's type arguments are erased from names, and the
    /// instance's impl of the trait is its inherent methods.
    pub open: BTreeMap<String, String>,
    /// The DSL paths of the lifted modules (`crate::merkle::mmr::iterator`):
    /// an item of another lifted module is named by its path there.
    pub dsl_modules: Vec<String>,
    /// The DSL module whose function is being read (set by the lift).
    pub current: std::cell::RefCell<String>,
    /// The lifted associated constants of open-trait impls: `(self type,
    /// constant)` → whether it is a constant function (`Family__MAX_NODES()`)
    /// rather than a constant (SEMANTICS.md §19.6).
    pub consts: BTreeMap<(String, String), bool>,
    /// Module structs with an invariant (their lifted names).
    pub invariant_types: BTreeSet<String>,
    /// The host models of `#[lift(host)]` modules other than enums
    /// (SEMANTICS.md §19.10).
    pub host: HostModels,
}

/// Host models a library type of rustc's MIR is read as (SEMANTICS.md
/// §19.10, `docs/mir-lift.md` §20.2): matched by the type's own name.
#[derive(Debug, Default, Clone)]
pub struct HostModels {
    /// `pub type T = <exec type>;`: name → (DSL path, the exec type's
    /// tokens). A library struct `T` with exactly one field, of that exec
    /// type, is read as that type (a newtype read as its field).
    pub types: BTreeMap<String, (String, String)>,
    /// Unit structs whose impls are models: name → DSL path. A leaf call of
    /// a method at a library type `T` is the model's method `path::m`.
    pub structs: BTreeMap<String, String>,
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

fn prim_name(t: &Ty) -> Option<String> {
    match t {
        Ty::Int(false, 0) => Some("usize".into()),
        Ty::Int(true, 0) => Some("isize".into()),
        Ty::Int(false, b) => Some(format!("u{b}")),
        Ty::Int(true, b) => Some(format!("i{b}")),
        Ty::Bool => Some("bool".into()),
        _ => None,
    }
}

impl ModuleNames {
    /// A path of the extracted module(s) (`module` may list several,
    /// comma-separated: calls between them are calls by name).
    fn local(&self, path: &str) -> bool {
        self.module.split(", ").any(|m| path.starts_with(&format!("{m}::")))
    }

    /// The lifted name of a type as the source lift spells it in names
    /// (`UInt__u16`, `u16`).
    fn name_of(&self, m: &Sbmir, t: &Ty) -> Result<String, String> {
        if let Some(p) = prim_name(t) {
            return Ok(p);
        }
        // a module type by its lifted name, unqualified (names are keys)
        if let Ty::Adt(k) = t
            && let Some(d) = m.adts.get(k)
            && self.local(&d.path)
        {
            return self.local_adt_name(m, d);
        }
        let ty = self.ty(m, t)?;
        Ok(quote::ToTokens::to_token_stream(&ty).to_string().replace(' ', ""))
    }

    fn adt_base(&self, path: &str) -> String {
        path.rsplit("::").next().unwrap_or(path).to_string()
    }

    /// `name` qualified by the DSL module of the crate item `def_path`
    /// (bare within the module being read).
    fn qualify(&self, def_path: &str, name: &str) -> String {
        let krate = self.module.split("::").next().unwrap_or("");
        let best = self.dsl_modules.iter().filter(|d| {
            let cp = format!("{krate}{}", d.trim_start_matches("crate"));
            def_path.starts_with(&format!("{cp}::"))
        }).max_by_key(|d| d.len());
        match best {
            Some(d) if *d != *self.current.borrow() => format!("{d}::{name}"),
            _ => name.to_string(),
        }
    }

    /// A host model's DSL path: its crate path with the crate named
    /// `crate` (the DSL root mirrors the host crate's modules;
    /// `commonware_storage::merkle::Error` → `crate::merkle::Error`).
    fn host_path(&self, path: &str) -> Result<syn::Path, String> {
        let rest = path.split_once("::").map(|(_, r)| r).unwrap_or(path);
        syn::parse_str(&format!("crate::{rest}")).map_err(|e| e.to_string())
    }

    /// Whether `t` is the declared instance of an open trait.
    fn is_instance(&self, m: &Sbmir, t: &Ty) -> bool {
        let Ty::Adt(k) = t else { return false };
        let Some(d) = m.adts.get(k) else { return false };
        self.open.values().any(|inst| d.path.ends_with(&format!("::{inst}"))) || self.host_instance(m, k).is_some()
    }

    /// A library type that is the declared instance of an open trait whose
    /// instance is a host model (`CHasher: crate::merkle::host::Sha256`, the
    /// MIR's `commonware_cryptography::Sha256`): the model's DSL path, when
    /// the type has the model's name.
    fn host_instance(&self, m: &Sbmir, k: &str) -> Option<String> {
        let d = m.adts.get(k)?;
        if self.local(&d.path) {
            return None;
        }
        let base = self.adt_base(&d.path);
        let dsl = self.host.structs.get(&base).or_else(|| self.host.types.get(&base).map(|t| &t.0))?;
        self.open.values().any(|inst| format!("crate::{inst}") == *dsl).then(|| dsl.clone())
    }

    /// The library types of `m` that stand for host models: `(the model's
    /// DSL path, the type's Rust path, the field a newtype is read as)`
    /// (for the conformance harness, which calls the original code with
    /// the real types).
    pub fn host_types(&self, m: &Sbmir) -> Vec<(String, String, Option<String>)> {
        let mut out = Vec::new();
        for (k, d) in &m.adts {
            if let Some(p) = self.transparent_path(m, k) {
                out.push((p, format!("::{}", d.path), d.variants[0].fields.first().map(|f| f.0.clone())));
            } else if let Some(p) = self.host_instance(m, k)
                && d.args.is_empty()
            {
                out.push((p, format!("::{}", d.path), None));
            }
        }
        out
    }

    /// A library newtype read as its one field (a host model `pub type T =
    /// ..;` of the field's type): the model's DSL path.
    fn transparent_path(&self, m: &Sbmir, k: &str) -> Option<String> {
        let d = m.adts.get(k)?;
        if self.local(&d.path) || d.is_enum || d.variants.len() != 1 || d.variants[0].fields.len() != 1 {
            return None;
        }
        let (dsl, target) = self.host.types.get(&self.adt_base(&d.path))?;
        let ft = self.ty(m, &d.variants[0].fields[0].1).ok()?;
        // (an array length is printed `32usize` here, `32` in the model)
        let norm = |s: String| s.replace(' ', "").replace("usize]", "]");
        (norm(quote::ToTokens::to_token_stream(&ft).to_string()) == norm(target.clone())).then(|| dsl.clone())
    }

    /// The lifted name of a module ADT instance: `Decoder<u16>` →
    /// `Decoder__u16`; an open-trait instance argument is erased
    /// (`Position<mmr::Family>` → `Position`).
    fn local_adt_name(&self, m: &Sbmir, d: &ir::AdtDef) -> Result<String, String> {
        let mut s = self.adt_base(&d.path);
        for a in &d.args {
            if self.is_instance(m, a) {
                continue;
            }
            s.push_str("__");
            s.push_str(&sanitize(&self.name_of(m, a)?));
        }
        Ok(s)
    }

    /// An operator or conversion trait's method name at a right-hand type
    /// (`add__u64` for `Add<u64>`; `add` for `Add<Self>`), as the source
    /// lift names them (SEMANTICS.md §19.8).
    fn op_method(&self, m: &Sbmir, st: &Ty, targs: &[Ty], mname: &str) -> Option<String> {
        match targs.first() {
            None => Some(mname.to_string()),
            Some(a) if a == st => Some(mname.to_string()),
            Some(a) => Some(format!("{mname}__{}", sanitize(&self.name_of(m, a).ok()?))),
        }
    }

    /// The lifted name of a module function instance (`write__u16`,
    /// `Decoder__u16::feed`, `UPrim__u16__as_u8`, `u16__from__UInt__u16`).
    pub fn lifted_name(&self, m: &Sbmir, f: &Fn) -> Option<String> {
        // (the impl itself must be the module's: core's blanket `impl<T>
        // From<T> for T` at a module type is library code, inlined)
        if !self.local(&f.def) && !self.module.split(", ").any(|m| f.def.starts_with(&format!("<{m}::"))) && !matches!(&f.item, Item::Impl(t, ..) if prim_name(t).is_some()) {
            return None;
        }
        match &f.item {
            Item::Fn(name) => {
                // a tuple-struct constructor is not a function of the source;
                // a library trait's provided method at a module type
                // (`<Position as PartialOrd>::lt`) is library code: inlined
                if m.adts.values().any(|d| d.path == f.def) || !self.local(&f.def) {
                    return None;
                }
                let mut s = name.clone();
                for a in &f.args {
                    if matches!(a, Ty::Ref(..)) {
                        continue;
                    }
                    s.push_str("__");
                    s.push_str(&sanitize(&self.name_of(m, a).ok()?));
                }
                Some(s)
            }
            Item::Inherent(Ty::Adt(k), mname) => {
                let d = m.adts.get(k)?;
                if !self.local(&d.path) {
                    return None;
                }
                Some(format!("{}::{mname}", self.local_adt_name(m, d).ok()?))
            }
            Item::Impl(st, tr, targs, mname) => {
                let local_arg = |t: &Ty| matches!(t, Ty::Adt(k) if m.adts.get(k).is_some_and(|d| self.local(&d.path)));
                if let Some(p) = prim_name(st) {
                    if self.sealed.contains(tr) {
                        return Some(format!("{tr}__{}__{mname}", sanitize(&p)));
                    }
                    // `impl From<S> for u64`, `impl PartialEq<S> for u64`: free functions
                    if targs.len() == 1 && local_arg(&targs[0]) && OP_TRAITS.contains(&tr.as_str()) {
                        return Some(format!("{p}__{mname}__{}", sanitize(&self.name_of(m, &targs[0]).ok()?)));
                    }
                    return None;
                }
                if let Ty::Adt(k) = st {
                    let d = m.adts.get(k)?;
                    if !self.local(&d.path) {
                        return None;
                    }
                    let owner = self.local_adt_name(m, d).ok()?;
                    if HOST_TRAITS.contains(&tr.as_str()) || METHOD_TRAITS.contains(&tr.as_str()) || self.open.contains_key(tr) {
                        return Some(format!("{owner}::{mname}"));
                    }
                    if OP_TRAITS.contains(&tr.as_str()) {
                        return Some(format!("{owner}::{}", self.op_method(m, st, targs, mname)?));
                    }
                }
                None
            }
            _ => None,
        }
    }
}

impl Names for ModuleNames {
    fn ty(&self, m: &Sbmir, t: &Ty) -> Result<syn::Type, String> {
        Ok(match t {
            Ty::Bool => syn::parse_quote!(bool),
            Ty::Unit => syn::parse_quote!(()),
            Ty::Int(false, 0) => syn::parse_quote!(usize),
            Ty::Int(false, b) if matches!(b, 8 | 16 | 32 | 64) => {
                let i = quote::format_ident!("u{}", b);
                syn::parse_quote!(#i)
            }
            Ty::Int(true, b) if matches!(b, 16 | 32 | 64) => {
                let i = quote::format_ident!("I{}", b);
                syn::parse_quote!(crate::__lift::#i)
            }
            Ty::Tuple(ts) => {
                let ts: Vec<syn::Type> = ts.iter().map(|t| self.ty(m, t)).collect::<Result<_, _>>()?;
                syn::parse_quote!((#(#ts),*))
            }
            Ty::Array(e, n) => {
                let e = self.ty(m, e)?;
                let n = syn::LitInt::new(&format!("{n}usize"), proc_macro2::Span::call_site());
                syn::parse_quote!([#e; #n])
            }
            Ty::Ref(false, inner) => match &**inner {
                Ty::Slice(e) => {
                    let e = self.ty(m, e)?;
                    syn::parse_quote!(&[#e])
                }
                other => {
                    let t = self.ty(m, other)?;
                    syn::parse_quote!(&#t)
                }
            },
            Ty::Adt(k) => {
                let d = m.adts.get(k).ok_or_else(|| format!("no ADT `{k}`"))?;
                if let Some(p) = self.transparent_path(m, k) {
                    let p: syn::Path = syn::parse_str(&p).map_err(|e| e.to_string())?;
                    return Ok(syn::parse_quote!(#p));
                }
                if bytes_iter_model(m, t) {
                    // the byte strings not yet yielded (SEMANTICS.md §19.10)
                    return Ok(syn::parse_quote!(&[&[u8]]));
                }
                // `Option<&mut T>` (a state): the optional place's value
                if d.path.ends_with("option::Option")
                    && let [Ty::Ref(true, inner)] = d.args.as_slice()
                {
                    let it = self.ty(m, inner)?;
                    return Ok(syn::parse_quote!(Option<#it>));
                }
                let args: Vec<syn::Type> = d.args.iter().map(|a| self.ty(m, a)).collect::<Result<_, _>>()?;
                let base = self.adt_base(&d.path);
                if d.path.ends_with("vec::Vec") && d.args.len() == 2 && m.adts.get(match &d.args[1] { Ty::Adt(a) => a.as_str(), _ => "" }).is_some_and(|a| a.path.ends_with("alloc::Global")) {
                    // `Vec<T>` is `Seq<T>` (SEMANTICS.md §19.10)
                    let e = &args[0];
                    return Ok(syn::parse_quote!(Seq<#e>));
                }
                if d.path.ends_with("result::Result") {
                    syn::parse_quote!(Result<#(#args),*>)
                } else if d.path.ends_with("option::Option") {
                    syn::parse_quote!(Option<#(#args),*>)
                } else if self.local(&d.path) {
                    let n: syn::Path = syn::parse_str(&self.qualify(&d.path, &self.local_adt_name(m, d)?)).map_err(|e| e.to_string())?;
                    syn::parse_quote!(#n)
                } else if d.path == "bytes::TryGetError" {
                    syn::parse_quote!(TryGetError)
                } else if d.path.ends_with("marker::PhantomData") {
                    syn::parse_quote!(crate::__lift::PhantomData)
                } else if d.path.ends_with("cmp::Ordering") {
                    syn::parse_quote!(crate::__lift::Ordering)
                } else if let Some(t) = prelude_iter_ty(d) {
                    t
                } else if (d.path == "std::iter::Once" || d.path == "core::iter::Once") && args.len() == 1 {
                    syn::parse_quote!(crate::__lift::Once<#(#args),*>)
                } else if d.path == "std::ops::Range" || d.path == "core::ops::Range" {
                    // a range as a value (its fields; SEMANTICS.md §19.10)
                    syn::parse_quote!(crate::__lift::Range<#(#args),*>)
                } else if self.host_enums.contains_key(&base) {
                    // (a generic host enum's model is erased at the instance)
                    let n = self.host_path(&d.path)?;
                    syn::parse_quote!(#n)
                } else {
                    return Err(format!("the type `{}` (neither a module type, a host model, nor `Result`/`Option`)", d.path));
                }
            }
            other => return Err(format!("the type {other:?}")),
        })
    }

    fn ctor(&self, m: &Sbmir, adt: &str, variant: usize) -> Result<Ctor, String> {
        let d = m.adts.get(adt).ok_or_else(|| format!("no ADT `{adt}`"))?;
        let v = d.variants.get(variant).ok_or_else(|| format!("variant {variant} of `{adt}`"))?;
        let fields: Vec<String> = v.fields.iter().map(|f| f.0.clone()).collect();
        let named = fields.iter().any(|f| !f.chars().all(|c| c.is_ascii_digit()));
        let base = self.adt_base(&d.path);
        let id = |s: &str| syn::Ident::new(s, proc_macro2::Span::call_site());
        let path: syn::Path = if d.path.ends_with("result::Result") || d.path.ends_with("option::Option") {
            let v = id(&v.name);
            syn::parse_quote!(#v)
        } else if self.local(&d.path) {
            let n: syn::Path = syn::parse_str(&self.qualify(&d.path, &self.local_adt_name(m, d)?)).map_err(|e| e.to_string())?;
            if d.is_enum {
                let vn = id(&v.name);
                syn::parse_quote!(#n::#vn)
            } else {
                syn::parse_quote!(#n)
            }
        } else if d.path == "bytes::TryGetError" {
            syn::parse_quote!(TryGetError)
        } else if d.path.ends_with("marker::PhantomData") {
            syn::parse_quote!(crate::__lift::PhantomData)
        } else if d.path == "std::ops::Range" || d.path == "core::ops::Range" {
            syn::parse_quote!(crate::__lift::Range)
        } else if d.path.ends_with("cmp::Ordering") {
            let vn = id(&v.name);
            syn::parse_quote!(crate::__lift::Ordering::#vn)
        } else if let Some(vars) = self.host_enums.get(&base) {
            if !vars.contains(&v.name) {
                return Err(format!("`{base}::{}` is not in the host model of `{base}`", v.name));
            }
            let (n, vn) = (self.host_path(&d.path)?, id(&v.name));
            syn::parse_quote!(#n::#vn)
        } else {
            return Err(format!("a constructor of `{}`", d.path));
        };
        Ok(Ctor { path, fields, named })
    }

    fn const_item(&self, m: &Sbmir, owner: Option<&Ty>, name: &str) -> Option<syn::Expr> {
        let Some(Ty::Adt(k)) = owner else { return None };
        let d = m.adts.get(k)?;
        if !self.local(&d.path) {
            return None;
        }
        let owner_name = self.local_adt_name(m, d).ok()?;
        let is_fn = *self.consts.get(&(owner_name.clone(), name.to_string()))?;
        let p = self.qualify(&d.path, &format!("{owner_name}__{name}"));
        syn::parse_str(&if is_fn { format!("{p}()") } else { p }).ok()
    }

    fn transparent(&self, m: &Sbmir, adt: &str) -> bool {
        self.transparent_path(m, adt).is_some()
    }

    fn host_method(&self, m: &Sbmir, self_ty: &Ty, method: &str) -> Option<syn::Expr> {
        let Ty::Adt(k) = self_ty else { return None };
        let p = self.host_instance(m, k)?;
        if !self.host.structs.values().any(|s| *s == p) {
            return None;
        }
        syn::parse_str(&format!("{p}::{method}")).ok()
    }

    fn has_invariant(&self, m: &Sbmir, adt: &str) -> bool {
        m.adts.get(adt).is_some_and(|d| self.local(&d.path) && self.local_adt_name(m, d).is_ok_and(|n| self.invariant_types.contains(&n)))
    }

    fn lifted(&self, m: &Sbmir, f: &Fn) -> Option<LiftedCallee> {
        let name = self.lifted_name(m, f)?;
        // the item's module: the function's own path, or its self type's
        let item_path = match &f.item {
            Item::Inherent(Ty::Adt(k), _) | Item::Impl(Ty::Adt(k), ..) => m.adts.get(k).map(|d| d.path.clone()).unwrap_or_default(),
            _ => f.def.clone(),
        };
        let path: syn::Expr = syn::parse_str(&self.qualify(&item_path, &name)).ok()?;
        let states: Vec<usize> = (0..f.argc).filter(|i| f.locals.get(i + 1).is_some_and(|(t, _)| matches!(t, Ty::Ref(true, _)) || read::opt_mut(m, t).is_some())).collect();
        let has_ret = !matches!(f.locals.first(), Some((Ty::Unit, _)));
        // the source name its attachments use
        let orig = match &f.item {
            Item::Fn(n) => n.clone(),
            Item::Inherent(Ty::Adt(k), mname) | Item::Impl(Ty::Adt(k), _, _, mname) => format!("{}::{mname}", m.adts.get(k).map(|d| self.adt_base(&d.path)).unwrap_or_default()),
            Item::Impl(_, _, _, mname) => mname.clone(),
            _ => String::new(),
        };
        // (a lowered copy `__sandblaster_opt_g` of `g`, the lifted round
        // trip's, is bound where `g` is: binding is always a faithful order)
        let copy_of = orig.strip_prefix(crate::driver::lowered::HELPER_PREFIX);
        let total = !self.requires.contains(&orig) && !copy_of.is_some_and(|g| self.requires.contains(g));
        // a `&self` receiver: the lift takes `self` by value
        let by_value: Vec<usize> = if f.argc >= 1 && f.debug.iter().any(|(n, l)| n == "self" && *l == 1) && matches!(f.locals.get(1), Some((Ty::Ref(false, _), _))) { vec![0] } else { vec![] };
        Some(LiftedCallee { path, states, has_ret, total, by_value })
    }
}

/// core's iterators the lift prelude models (`crate::__lift`: core's
/// `next`, transcribed; SEMANTICS.md §19.9): `RangeInclusive<u32/u64>`,
/// `Once<T>`. They are built and stepped only through the leaves of
/// `read::builtin_leaf` (never field by field).
/// `Copied<slice::Iter<&[u8]>>`: the byte-string iterator model's type
/// (the extraction's instance of `E: Iterator<Item: AsRef<[u8]>>`).
pub fn bytes_iter_model(m: &Sbmir, t: &Ty) -> bool {
    let adt = |t: &Ty| match t {
        Ty::Adt(k) => m.adts.get(k),
        _ => None,
    };
    let byte_slice = Ty::Ref(false, Box::new(Ty::Slice(Box::new(Ty::Int(false, 8)))));
    adt(t).is_some_and(|d| {
        matches!(d.path.as_str(), "std::iter::Copied" | "core::iter::Copied")
            && d.args.len() == 1
            && adt(&d.args[0]).is_some_and(|i| matches!(i.path.as_str(), "std::slice::Iter" | "core::slice::Iter") && i.args == [byte_slice.clone()])
    })
}

fn prelude_iter_ty(d: &ir::AdtDef) -> Option<syn::Type> {
    let base = d.path.rsplit("::").next()?;
    Some(match (base, d.args.first()) {
        ("RangeInclusive", Some(Ty::Int(false, 32))) if d.path.contains("ops") => syn::parse_quote!(crate::__lift::RangeInclusiveU32),
        ("RangeInclusive", Some(Ty::Int(false, 64))) if d.path.contains("ops") => syn::parse_quote!(crate::__lift::RangeInclusiveU64),
        ("Once", Some(_)) if d.path.contains("iter") => return None,
        _ => return None,
    })
}

/// `1.98.1` / `1.98.0-nightly` → `1.98`.
fn release_series(v: &str) -> String {
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// A parsed `.sbmir` with its lifted-name index.
#[derive(Debug)]
pub struct Loaded {
    pub m: Sbmir,
    pub names: ModuleNames,
    /// Lifted name → MIR instance key.
    pub by_lifted: BTreeMap<String, String>,
}

/// Parses a `.sbmir` file and checks it against the sources it was
/// extracted from (`sources`: path relative to the host crate → text).
pub fn load(text: &str, sources: &dyn std::ops::Fn(&str) -> Option<Vec<u8>>, mut names: ModuleNames, module_suffix: &str) -> Result<Loaded, String> {
    let m = ir::parse(text)?;
    // the module, or a child module of it (`children = ".."`), is extracted
    let krate_of = |m1: &str| m1.split("::").next().unwrap_or("").to_string();
    let of_module = |m1: &str| {
        let full = format!("{}::{module_suffix}", krate_of(m1));
        full == m1 || full.starts_with(&format!("{m1}::"))
    };
    if !m.module.split(", ").any(of_module) {
        return Err(format!("the .sbmir file is the MIR of `{}`, not of the module `{module_suffix}` of a crate", m.module));
    }
    names.module = m.module.clone();
    // the build's compiler must be of the release the MIR was extracted
    // with (the nightly of that release): the same MIR building, the same core
    if let Ok(rustc) = std::env::var("RUSTC")
        && let Ok(o) = std::process::Command::new(&rustc).arg("-vV").output()
    {
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        let build = text.lines().find_map(|l| l.strip_prefix("release: ")).map(release_series);
        let extracted = m.rustc.split_whitespace().nth(1).map(release_series);
        if let (Some(b), Some(e)) = (build, extracted)
            && b != e
        {
            return Err(format!("the MIR was extracted with {} (release {e}), but this build's rustc is release {b}: extract it again with the nightly of {b} (sandblaster/mirx/rust-toolchain.toml)", m.rustc));
        }
    }
    if !m.overflow_checks {
        return Err("the .sbmir file was extracted without overflow checks (the workspace's profiles build with them)".into());
    }
    for (path, hash) in &m.sources {
        let Some(bytes) = sources(path) else { return Err(format!("the .sbmir file names the source `{path}`, which does not exist")) };
        let h = crate::surface::hex(&crate::surface::sha256(&bytes));
        if &h != hash {
            return Err(format!("the source `{path}` changed since the MIR was extracted (re-run the extraction: sandblaster/mirx/extract.sh)"));
        }
    }
    let mut by_lifted = BTreeMap::new();
    for k in &m.roots {
        if let Some(f) = m.fns.get(k)
            && let Some(n) = names.lifted_name(&m, f)
        {
            // an inherent method and an open trait's method of the same name
            // at the instance are one lifted function: the inherent one
            // (the lift requires the trait's to be a pure delegation to it,
            // or the same body, SEMANTICS.md §19.10)
            let inherent = matches!(f.item, Item::Inherent(..));
            if inherent || !by_lifted.contains_key(&n) {
                by_lifted.insert(n, k.clone());
            }
        }
    }
    Ok(Loaded { m, names, by_lifted })
}
