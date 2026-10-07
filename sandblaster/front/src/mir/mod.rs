//! Lifting from rustc's MIR (`docs/mir-lift.md` §20; DESIGN.md §2.1).
//!
//! `#[lift(mir = "varint.sbmir", ..)] mod varint;` reads the **bodies** of
//! the module's functions from rustc's own MIR — monomorphized, fully typed,
//! macros expanded, `?`/closures/operators/iterators desugared by the
//! compiler; the only reading of exec bodies there is (a lifted exec module
//! without `mir = ".."` is refused). The
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
//! constant evaluation of `T::SIZE`) are deleted (`docs/mir-lift.md` §6
//! step 3).
//!
//! Trusted (TCB item 8, "the reading", `docs/checked-structuring.md`
//! amendment (d)): the literal reading L (`literal.rs` and its library
//! `literal.core`), the statement of each function's theorem (`stmt.rs`),
//! the parse L reads (`ir.rs`, `sexp.rs`), the names and load checks below
//! (`load`, `ModuleNames::kernel_adt`, `is_transparent`,
//! `host_model_method`, `instance_global`), the printer `sandblaster-mirx`
//! (it transcribes rustc's data), and the gate's trusted check `gate.rs` (L
//! loaded only through it; a function accepted only when the kernel holds
//! its theorem with the trusted statement). Untrusted: the structured reading
//! `read.rs` (a proposer of S, checked by the theorems), `cfg.rs`, the
//! walker `simproof.rs` and its driver `checked.rs` (they build proof
//! terms the kernel and `gate.rs` check), the matching of lifted functions to MIR
//! instances by lifted name (`gate.rs` checks that each listed function's
//! instance is that function, `instance_global`). The lift conformance
//! check compares every read function, and the literal reading of it,
//! with rustc's build of the source.

pub mod arch;
pub mod cfg;
pub mod checked;
pub mod gate;
pub mod ir;
pub mod literal;
pub mod ptr;
pub mod read;
pub mod replay;
pub mod sexp;
pub mod simproof;
pub mod stmt;
pub mod unsafe_diag;
pub mod window;

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

/// The DSL module whose function is being read (set by the lift before
/// each reading; a lock, so that the names can travel with the lift's facts
/// to the elaboration thread). (The toolchain's crates do not depend on
/// `commonware_utils`.)
#[allow(clippy::disallowed_types)]
#[derive(Debug, Default)]
pub struct Current(std::sync::Mutex<String>);

impl Current {
    pub fn borrow(&self) -> std::sync::MutexGuard<'_, String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn replace(&self, s: String) -> String {
        std::mem::replace(&mut *self.borrow(), s)
    }
}

impl Clone for Current {
    #[allow(clippy::disallowed_types)]
    fn clone(&self) -> Self {
        Current(std::sync::Mutex::new(self.borrow().clone()))
    }
}

/// The names of a lifted module in the subset.
#[derive(Clone, Debug)]
pub struct ModuleNames {
    /// `commonware_codec::varint`.
    pub module: String,
    /// Sealed traits of the module (their impl methods are free functions).
    pub sealed: BTreeSet<String>,
    /// Host-model enums: name → variant names.
    pub host_enums: BTreeMap<String, Vec<String>>,
    /// Source functions with a `requires` attachment, by the full path the
    /// attachment names them by (`crate::varint::write`,
    /// `crate::varint::Decoder::feed`, `crate::m::u64__from__Pos`;
    /// `lift::Ctx::attach_path`): their calls are obligations, bound where
    /// they occur.
    pub requires: BTreeSet<String>,
    /// Open traits read at their instances (SEMANTICS.md §19.6): trait name
    /// → the instances' paths in the crate (`Family` →
    /// `[merkle::mmr::Family]`; `Engine` → its two verified engines). The
    /// instance's type arguments are erased from names, and an instance's
    /// impl of the trait is its inherent methods.
    pub open: BTreeMap<String, Vec<String>>,
    /// The DSL paths of the lifted modules (`crate::merkle::mmr::iterator`):
    /// an item of another lifted module is named by its path there.
    pub dsl_modules: Vec<String>,
    /// The DSL module whose function is being read (set by the lift).
    pub current: Current,
    /// The lifted associated constants of open-trait impls: `(self type,
    /// constant)` → whether it is a constant function (`Family__MAX_NODES()`)
    /// rather than a constant (SEMANTICS.md §19.6).
    pub consts: BTreeMap<(String, String), bool>,
    /// Module structs with an invariant (their lifted names).
    pub invariant_types: BTreeSet<String>,
    /// The host models of `#[lift(host)]` modules other than enums
    /// (SEMANTICS.md §19.10).
    pub host: HostModels,
    /// The build's target architecture (`aarch64`): an extraction that
    /// records another one is refused (`None`: not checked, the toolchain's
    /// own tests of extractions without a recorded target).
    pub target_arch: Option<String>,
    /// The build's statically enabled target features
    /// (`CARGO_CFG_TARGET_FEATURE`, `TargetInfo::features`): an extraction
    /// whose own are others is refused, and only once they are bound do the
    /// static features count as facts for the readings (`None`: not known,
    /// none count; DESIGN-UNSAFE-SIMD amendment A-S3).
    pub static_features: Option<Vec<String>>,
    /// The build's `-C target-cpu` (`None`: the target's default) and
    /// `-C target-feature` flags, when known: a build that changes the
    /// target's static features with them is refused (A-S3).
    pub codegen_flags: Option<(Option<String>, String)>,
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
    /// Enums of host models: name → DSL path (where the model declares it;
    /// the crate may re-export it elsewhere).
    pub enums: BTreeMap<String, String>,
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
    pub(crate) fn local(&self, path: &str) -> bool {
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
        match self.dsl_module(def_path) {
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
        self.open.values().flatten().any(|inst| d.path.ends_with(&format!("::{inst}"))) || self.host_instance(m, k).is_some()
    }

    /// Whether a primitive type is the declared instance of an open trait
    /// through a host model alias (`Word: crate::host::W`, `type W = u64;`).
    fn is_prim_instance(&self, t: &Ty) -> bool {
        let Some(p) = prim_name(t) else { return false };
        self.open.values().flatten().any(|inst| self.host.types.values().any(|(dsl, ty)| *dsl == format!("crate::{inst}") && ty.replace(' ', "") == p))
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
        self.open.values().flatten().any(|inst| format!("crate::{inst}") == *dsl).then(|| dsl.clone())
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
        // (a union is never its field: reading it so is a type pun)
        if self.local(&d.path) || d.is_enum || d.is_union || d.variants.len() != 1 || d.variants[0].fields.len() != 1 {
            return None;
        }
        let (dsl, target) = self.host.types.get(&self.adt_base(&d.path))?;
        let ft = self.ty(m, &d.variants[0].fields[0].1).ok()?;
        // (an array length is printed `32usize` here, `32` in the model)
        let norm = |s: String| s.replace(' ', "").replace("usize]", "]");
        (norm(quote::ToTokens::to_token_stream(&ft).to_string()) == norm(target.clone())).then(|| dsl.clone())
    }

    /// The kernel name of the subset's declaration a library or module ADT
    /// instance of rustc's MIR is read as, for the literal reading
    /// (`literal.rs`): a module type by its lifted name in its DSL module
    /// (`crate::varint::Decoder__u32`), a host-model enum by its crate path
    /// (`crate::error::Error`), the declared instance of an open trait that
    /// is a host model's unit struct (`crate::merkle::host::Sha256`).
    pub fn kernel_adt(&self, m: &Sbmir, key: &str) -> Option<String> {
        let d = m.adts.get(key)?;
        if self.local(&d.path) {
            return Some(format!("{}::{}", self.dsl_module(&d.path)?, self.local_adt_name(m, d).ok()?));
        }
        if self.host_enums.contains_key(&self.adt_base(&d.path)) {
            // where the crate's model declares it, under the module the crate
            // path names (`crate::merkle::host::Error` for `merkle::Error`)
            let hp = quote::ToTokens::to_token_stream(&self.host_path(&d.path).ok()?).to_string().replace(' ', "");
            let parent = hp.rsplit_once("::").map(|p| p.0).unwrap_or("crate");
            let same_crate = d.path.split("::").next() == self.module.split("::").next();
            return Some(self.host.enums.get(&self.adt_base(&d.path)).filter(|p| same_crate && p.starts_with(&format!("{parent}::"))).cloned().unwrap_or(hp));
        }
        self.host_instance(m, key).filter(|p| self.host.structs.values().any(|s| s == p))
    }

    /// A library newtype read as its one field (a host model alias of the
    /// field's type, SHA-256's `Digest`).
    pub fn is_transparent(&self, m: &Sbmir, key: &str) -> bool {
        self.transparent_path(m, key).is_some()
    }

    /// The host model's function for a leaf method of a library type that
    /// is a host model's declared instance (`<Sha256 as Hasher>::hash` →
    /// `crate::merkle::host::Sha256::hash`).
    pub fn host_model_method(&self, m: &Sbmir, self_ty: &Ty, method: &str) -> Option<String> {
        let Ty::Adt(k) = self_ty else { return None };
        let p = self.host_instance(m, k)?;
        self.host.structs.values().any(|s| *s == p).then(|| format!("{p}::{method}"))
    }

    /// The DSL module of an item of the extracted crate by its crate path
    /// (`commonware_codec::varint::Decoder` → `crate::varint`).
    fn dsl_module(&self, path: &str) -> Option<&String> {
        let krate = self.module.split("::").next().unwrap_or("");
        self.dsl_modules.iter().filter(|dm| path.starts_with(&format!("{krate}{}::", dm.trim_start_matches("crate")))).max_by_key(|dm| dm.len())
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
                    // (an open trait's parameter is erased at its instance:
                    // one function, `run`, not `run__Std`; a byte-string
                    // iterator's is a state, §19.10)
                    if matches!(a, Ty::Ref(..)) || self.is_instance(m, a) || self.is_prim_instance(a) || bytes_iter_model(m, a) {
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

    /// TRUSTED (`mir::gate`): the kernel name of the lifted function a module
    /// instance is, its lifted name in the DSL module of its item — the
    /// function's own path, its self type's, for a sealed trait's impl on a
    /// primitive the trait's, for an operator impl on a primitive its module
    /// type argument's (`crate::varint::UPrim__u16__as_u8`). The lift finds an
    /// instance by its lifted name alone, which another module may share.
    pub fn instance_global(&self, m: &Sbmir, f: &Fn) -> Option<String> {
        let path = match &f.item {
            Item::Impl(st, tr, ..) if prim_name(st).is_some() && self.sealed.contains(tr) => f.def.split(" as ").nth(1)?.split(['<', '>']).next()?.to_string(),
            Item::Inherent(Ty::Adt(k), _) | Item::Impl(Ty::Adt(k), ..) => m.adts.get(k)?.path.clone(),
            Item::Impl(_, _, targs, _) => m.adts.get(match targs.first() { Some(Ty::Adt(k)) => k, _ => return None })?.path.clone(),
            _ => f.def.clone(),
        };
        Some(format!("{}::{}", self.dsl_module(&path)?, self.lifted_name(m, f)?))
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
            // a `u128` is its (low, high) 64-bit words, as the lift reads it
            Ty::Int(false, 128) => syn::parse_quote!((u64, u64)),
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
            // a `core::arch` vector (§20.9): its `core::arch` path, which the
            // front end reads as its model representation
            Ty::Simd(p, lane, n) => {
                arch::vector(p, lane, *n)?;
                return syn::parse_str(p).map_err(|e| format!("the vector type `{p}`: {e}"));
            }
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
                // core's `IterMut` (docs/mir-lift.md §20.10): the index of the
                // element it yields next (the slice is the place it walks)
                if iter_mut_elem(m, t).is_some() {
                    return Ok(syn::parse_quote!(usize));
                }
                // core's slice iterator: the slice and the index of its next element
                if let Some(e) = slice_iter_elem(m, t) {
                    let e = self.ty(m, &e)?;
                    return Ok(syn::parse_quote!((&[#e], usize)));
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
        // attachments name a function by its full path (`lift::Ctx::
        // attach_path`): its module (its self type's for a method) and its
        // source name, or its lifted name (`u64__from__Position`, a
        // function of an impl on a primitive: `lift::Ctx::attach_key`)
        // (a sealed trait's impl on a primitive, `<u32 as m::sealed::T>::f`:
        // the trait's module)
        let modp = self.dsl_module(&item_path).or_else(|| item_path.split_once(" as ").and_then(|(_, r)| self.dsl_module(r))).cloned().unwrap_or_else(|| self.current.borrow().clone());
        let has_requires = |n: &str| self.requires.contains(&format!("{modp}::{n}"));
        let total = !has_requires(&orig) && !has_requires(&name);
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

/// core's `slice::Iter<'_, T>` (by its exact path): `T`. Both readings take it
/// as the slice and the index of the next element (`literal.core`'s
/// `leaf::slice_iter_*`); its own fields (raw pointers) are never read.
pub fn slice_iter_elem(m: &Sbmir, t: &Ty) -> Option<Ty> {
    let Ty::Adt(k) = t else { return None };
    let d = m.adts.get(k)?;
    match (d.path.as_str(), d.args.as_slice()) {
        ("std::slice::Iter" | "core::slice::Iter", [e]) => Some(e.clone()),
        _ => None,
    }
}

/// A library function read as a model rather than through its MIR (whose
/// raw pointers neither reading models), by the exact path of its
/// definition; the element type is the instance's first type argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Model {
    /// `<[T]>::iter`, `<&[T] as IntoIterator>::into_iter`, `slice::Iter::new`:
    /// the iterator at index 0 of the slice.
    SliceIterNew,
    /// `<slice::Iter<'_, T> as Iterator>::next`.
    SliceIterNext,
    /// `<Range<usize> as SliceIndex<[T]>>::get`.
    SliceGetRange,
    /// `<[T]>::iter_mut`: core's `IterMut<'_, T>` (raw pointers inside) as
    /// the slice's reference code and the index of the element it yields
    /// next, from 0 (DESIGN-UNSAFE-SIMD amendment A-S4).
    IterMutNew,
    /// `<IterMut<'_, T> as Iterator>::next`: the code of element `i`
    /// (`i < len`), the index one further; distinct calls yield distinct
    /// elements (the disjointness the write-backs rely on, A-S4).
    IterMutNext,
    /// `<I as IntoIterator>::into_iter` at an `IterMut`: the iterator itself.
    IterMutIntoIter,
    /// `<[T]>::split_at_mut(s, mid)`: the codes of the subslices `0..mid`
    /// and `mid..len` of `s` (`PRange`), or a panic when `mid > len`.
    SplitAtMut,
}

const MODEL_FNS: &[(&str, Model)] = &[
    ("core::slice::<impl [T]>::iter", Model::SliceIterNew),
    ("core::slice::iter::<impl std::iter::IntoIterator for &'a [T]>::into_iter", Model::SliceIterNew),
    ("core::slice::iter::<impl core::iter::IntoIterator for &'a [T]>::into_iter", Model::SliceIterNew),
    ("std::slice::Iter::<'a, T>::new", Model::SliceIterNew),
    ("core::slice::Iter::<'a, T>::new", Model::SliceIterNew),
    ("<std::slice::Iter<'a, T> as std::iter::Iterator>::next", Model::SliceIterNext),
    ("<core::slice::Iter<'a, T> as core::iter::Iterator>::next", Model::SliceIterNext),
    ("<std::ops::Range<usize> as std::slice::SliceIndex<[T]>>::get", Model::SliceGetRange),
    ("<core::ops::Range<usize> as core::slice::SliceIndex<[T]>>::get", Model::SliceGetRange),
    ("core::slice::<impl [T]>::iter_mut", Model::IterMutNew),
    ("<std::slice::IterMut<'a, T> as std::iter::Iterator>::next", Model::IterMutNext),
    ("<core::slice::IterMut<'a, T> as core::iter::Iterator>::next", Model::IterMutNext),
    ("core::slice::<impl [T]>::split_at_mut", Model::SplitAtMut),
];

/// core's `slice::IterMut<'_, T>` (by its exact path): `T`.
pub fn iter_mut_elem(m: &Sbmir, t: &Ty) -> Option<Ty> {
    let Ty::Adt(k) = t else { return None };
    let d = m.adts.get(k)?;
    match (d.path.as_str(), d.args.as_slice()) {
        ("std::slice::IterMut" | "core::slice::IterMut", [e]) => Some(e.clone()),
        _ => None,
    }
}

/// The model a function is read as, and its element type `T`.
pub fn model_of(f: &Fn) -> Option<(Model, Ty)> {
    if let Some((_, m)) = MODEL_FNS.iter().find(|(p, _)| *p == f.def) {
        return Some((*m, f.args.first()?.clone()));
    }
    // `<I as IntoIterator>::into_iter` at core's `IterMut<'_, T>` (the identity)
    if matches!(f.def.as_str(), "<I as std::iter::IntoIterator>::into_iter" | "<I as core::iter::IntoIterator>::into_iter")
        && let [Ty::Adt(k)] = f.args.as_slice()
        && (k.starts_with("std::slice::IterMut<") || k.starts_with("core::slice::IterMut<"))
    {
        return Some((Model::IterMutIntoIter, f.args[0].clone()));
    }
    None
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

/// The MIR optimization level of the extraction both readings read
/// (`cargo check`'s own; `sandblaster-mirx` pins it): its MIR is what L and
/// S read, and every lock and theorem was made from it.
pub const MIR_OPT_LEVEL: u32 = 1;
/// The MIR optimization level of the window extraction (`window_mir =
/// ".."`, DESIGN-UNSAFE-SIMD amendment A-S1): no optimization, so the MIR's
/// accesses and reference flow are the source's (level 1 already runs
/// `CopyProp`, `SimplifyLocals`, `RemoveZsts`). Only the window (aliasing)
/// analysis of pointers reads it; L and S never do.
pub const WINDOW_MIR_OPT_LEVEL: u32 = 0;

/// A parsed `.sbmir` with its lifted-name index.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub m: Sbmir,
    pub names: ModuleNames,
    /// Lifted name → MIR instance key.
    pub by_lifted: BTreeMap<String, String>,
    /// The window extraction of the same module ([`load_window`]), when
    /// declared: read by nothing but the window analysis.
    pub window: Option<std::sync::Arc<Sbmir>>,
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
    // the MIR is the image of one optimization level's passes: the readings'
    // own (`None`: an extraction older than the record, which `cargo check`
    // made at its default, this level)
    if let Some(l) = m.mir_opt_level
        && l != MIR_OPT_LEVEL
    {
        return Err(format!("the MIR was extracted at -Zmir-opt-level={l}; the readings read MIR of level {MIR_OPT_LEVEL} (extract it again without `--mir-opt-level`; an unoptimized extraction is a `window_mir`)"));
    }
    // MIR of another architecture is not what this build compiles (its
    // `core::arch` and `cfg(target_arch)` code is another's)
    if let (Some((triple, arch)), Some(build)) = (&m.target, &names.target_arch)
        && arch != build
    {
        return Err(format!("the MIR was extracted for `{triple}` ({arch}), but this build is for {build}: extract it for the build's target (`extract.sh --target`)"));
    }
    // the reading of existing `unsafe` (DESIGN-UNSAFE-SIMD): the static
    // target features are facts only when they are the build's own and come
    // from the target's defaults (amendment A-S3); the targets are
    // little-endian (the byte views)
    let mut m = m;
    if m.unsafe_reading {
        if m.endian.as_deref() != Some("little") {
            return Err(format!("the MIR was extracted for a {} target: the byte views of raw-pointer loads and stores are little-endian", m.endian.as_deref().unwrap_or("unknown-endian")));
        }
        if let Some(build) = &names.static_features {
            match (&m.target_cpu, m.target_feature_flags.as_deref()) {
                (Some((None, _)), Some("")) => {}
                (cpu, flags) => return Err(format!("the MIR was extracted with -C target-cpu={:?} and -C target-feature={flags:?}: its static target features would not be the target's (extract it without them; DESIGN-UNSAFE-SIMD A-S3)", cpu.as_ref().and_then(|c| c.0.clone()))),
            }
            if let Some((cpu, feats)) = &names.codegen_flags
                && (cpu.is_some() || !feats.is_empty())
            {
                return Err(format!("this build sets -C target-cpu={cpu:?} / -C target-feature={feats:?}: the static target features the MIR's reading counts would not be the shipped binary's (DESIGN-UNSAFE-SIMD A-S3)"));
            }
            let rec: BTreeSet<&str> = m.static_features.iter().flatten().map(String::as_str).collect();
            let got: BTreeSet<&str> = build.iter().map(String::as_str).collect();
            if rec != got {
                return Err(format!("the MIR was extracted with the static target features {rec:?}, but this build's are {got:?}: extract it again for this build's configuration (DESIGN-UNSAFE-SIMD A-S3)"));
            }
            m.static_facts = m.static_features.clone();
        }
    }
    for (path, hash) in &m.sources {
        let Some(bytes) = sources(path) else { return Err(format!("the .sbmir file names the source `{path}`, which does not exist")) };
        let h = crate::surface::hex(&crate::surface::sha256(&bytes));
        if &h != hash {
            return Err(format!("the source `{path}` changed since the MIR was extracted (re-run the extraction: sandblaster/mirx/extract.sh)"));
        }
    }
    // one extraction may hold several modules (`a, b`): a function of this
    // module wins over a same-named one of another (`a::third`, `b::third`)
    let own = format!("{}::{module_suffix}::", krate_of(&m.module));
    let owns = |f: &Fn| {
        let p = match &f.item {
            Item::Inherent(Ty::Adt(k), _) | Item::Impl(Ty::Adt(k), ..) => m.adts.get(k).map(|d| d.path.clone()).unwrap_or_default(),
            _ => f.def.clone(),
        };
        p.starts_with(&own) || p.contains(&format!(" as {own}"))
    };
    let mut by_lifted: BTreeMap<String, String> = BTreeMap::new();
    let mut rank: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for k in &m.roots {
        if let Some(f) = m.fns.get(k)
            && let Some(n) = names.lifted_name(&m, f)
        {
            // an inherent method and an open trait's method of the same name
            // at the instance are one lifted function: the inherent one
            // (the lift requires the trait's to be a pure delegation to it,
            // or the same body, SEMANTICS.md §19.10)
            let r = (owns(f), matches!(f.item, Item::Inherent(..)));
            if rank.get(&n).is_none_or(|old| r > *old || (r == *old && r.1)) {
                rank.insert(n.clone(), r);
                by_lifted.insert(n, k.clone());
            }
        }
    }
    Ok(Loaded { m, names, by_lifted, window: None })
}

/// Parses the window extraction of `main`'s module (`window_mir = ".."`)
/// and checks that it is the same program at MIR optimization level
/// [`WINDOW_MIR_OPT_LEVEL`]: the level recorded, exactly; the same
/// compiler, crate, module, overflow checks, target, exclusions, sources
/// (by SHA-256: `main`'s were checked against the files) and roots; and
/// every function of `main` with the same definition, item, parameters,
/// return type, body presence and target features. Its other locals and
/// its blocks differ by construction (the passes level 1 runs), and it may
/// follow library functions `main` does not.
pub fn load_window(text: &str, main: &mut Loaded) -> Result<(), String> {
    let w = ir::parse(text)?;
    let m = &main.m;
    if w.mir_opt_level != Some(WINDOW_MIR_OPT_LEVEL) {
        return Err(format!("the window extraction must be of -Zmir-opt-level={WINDOW_MIR_OPT_LEVEL} (`extract.sh --mir-opt-level {WINDOW_MIR_OPT_LEVEL}`); it records {:?}", w.mir_opt_level));
    }
    let same = |what: &str, a: String, b: String| if a == b { Ok(()) } else { Err(format!("the window extraction's {what} is {b}, the extraction's {a}")) };
    same("compiler", m.rustc.clone(), w.rustc.clone())?;
    same("crate", m.krate.clone(), w.krate.clone())?;
    same("module", m.module.clone(), w.module.clone())?;
    same("overflow checks", m.overflow_checks.to_string(), w.overflow_checks.to_string())?;
    same("target", format!("{:?}", m.target), format!("{:?}", w.target))?;
    same("exclusions", format!("{:?}", m.exclude), format!("{:?}", w.exclude))?;
    same("sources", format!("{:?}", m.sources), format!("{:?}", w.sources))?;
    same("roots", format!("{:?}", m.roots), format!("{:?}", w.roots))?;
    for (k, f) in &m.fns {
        let Some(g) = w.fns.get(k) else { return Err(format!("the window extraction has no `{k}`")) };
        let sig = |f: &Fn| format!("{} {:?} {} {:?} {:?} {} {:?}", f.def, f.item, f.argc, f.spread_arg, f.locals.iter().take(f.argc + 1).collect::<Vec<_>>(), f.has_body, f.target_features);
        same(&format!("signature of `{k}`"), sig(f), sig(g))?;
    }
    if m.unsafe_reading != w.unsafe_reading {
        return Err("the window extraction and the extraction were made by different printers (`(unsafe-reading ..)`)".into());
    }
    // the window rule's verdicts on the formations of crate code, carried to
    // the extraction the readings read (DESIGN-UNSAFE-SIMD §2.6, A-S1)
    let verdicts: BTreeMap<String, Vec<window::Verdict>> = w.fns.iter().filter(|(k, g)| g.local && m.fns.contains_key(*k)).map(|(k, g)| (k.clone(), window::check(&w, g))).collect();
    for (k, v) in verdicts {
        if let Some(f) = main.m.fns.get_mut(&k) {
            f.window = Some(v);
        }
    }
    main.window = Some(std::sync::Arc::new(w));
    Ok(())
}
