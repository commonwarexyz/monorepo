//! The literal reading L of rustc's MIR (`docs/mir-lift.md` §20.4,
//! `docs/checked-structuring.md` §2). TRUSTED: L is what a MIR body means;
//! the structured reading S of `read.rs` is checked against it.
//!
//! Every MIR instance becomes kernel definitions `L::<id>::{Root, St, Blk,
//! rank, g<i>, s<i>, run}`, written as core text and checked by the kernel:
//!
//! * `St` has one `Option` slot per local (`None`: not initialized) and one
//!   per **cell**, the referent of a `&mut` parameter (state passing);
//! * `run : (fuel : List(Unit)) -> (b : Blk) -> (os : Option(St)) ->
//!   Option(Out)` has one arm per block `b<k>` and per switch dispatcher
//!   `d<k>`, by measure recursion (`len(fuel) * 65536 + rank(b)`); a jump
//!   to a loop header and a self-call consume one unit of fuel;
//! * a `&mut` value is a **reference code** `(root, path)` of the frame; a
//!   shared reference is its referent's value (a snapshot);
//! * statements run in the option monad (`mir::bind`).
//!
//! Each construct is read locally, and each reading function names the MIR
//! construct it reads. `None` is undefined behaviour, a panic, running out of
//! fuel, or a construct this reading does not model: it can make a theorem
//! unprovable, never false. Every construct read as `None` is recorded in
//! [`LFn::faults`], named by its MIR construct. The reading never structures
//! (no joins, loops or carried values).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::Rel;

use super::ir::*;
use super::ModuleNames;

/// The fixed library (`literal.core`): the base, then the leaves.
pub const LIBRARY: &str = include_str!("literal.core");
const LEAVES: &str = "-- LEAVES";
const RANK_MULT: i64 = 65536;

/// The library's base (every definition but the leaves), templates expanded.
pub fn library() -> String {
    let base = LIBRARY.split(LEAVES).next().unwrap_or("");
    sandblaster_kernel::expand_templates(base).expect("literal.core templates")
}

/// A leaf's definition in `literal.core` (`leaf::vec_push`): its paragraph.
fn leaf_text(name: &str) -> Option<String> {
    let leaves = LIBRARY.split(LEAVES).nth(1)?;
    leaves.split("\n\n").find(|p| p.contains(&format!("def[prelude] {name} :"))).map(|p| p.trim().to_string())
}

/// The names L reads types with: the lift's names (`ModuleNames`, trusted,
/// `mir/mod.rs`) and the kernel environment of the structured reading, used
/// only for the constructors (in kernel order) of the declarations named.
pub struct KNames<'a> {
    pub names: &'a ModuleNames,
    pub env: &'a Env,
}

/// The library types (SEMANTICS.md §19.5–§19.10): a MIR path (under `std`
/// or `core`; a `bytes::` path as written) → the kernel type (`$0`, `$1`:
/// its arguments' L types).
const LIB_ADTS: &[(&str, &str)] = &[
    ("option::Option", "Option($0)"),
    ("result::Result", "crate::__lift::Result($0, $1)"),
    ("ops::ControlFlow", "mir::ControlFlow($0, $1)"),
    ("convert::Infallible", "mir::Infallible"),
    ("bytes::TryGetError", "crate::__lift::TryGetError"),
    ("cmp::Ordering", "crate::__lift::Ordering"),
    ("marker::PhantomData", "crate::__lift::PhantomData"),
    ("ops::Range", "crate::__lift::Range($0)"),
];

/// Whether the MIR path `path` is the library path `p` of a table: `p`
/// under `std` or `core` exactly (a crate or module that merely ends in
/// `ops::Range` is not core's), a `bytes::` path as written.
fn lib_path(p: &str, path: &str) -> bool {
    if p.starts_with("bytes::") { path == p } else { path.strip_prefix("std::").or_else(|| path.strip_prefix("core::")) == Some(p) }
}

/// One generated function.
#[derive(Clone, Debug)]
pub struct LFn {
    pub key: String,
    pub id: String,
    /// `L::<id>::run`.
    pub run: String,
    pub st: String,
    pub blk: String,
    pub out_ty: String,
    /// Its components: the cells' final values, then the return place.
    pub out_parts: Vec<String>,
    /// L types of the locals (slot payloads; `@RC@` is this function's code type).
    pub local_tys: Vec<String>,
    pub cells: Vec<Cell>,
    pub nblocks: usize,
    /// Loop headers (a jump to one consumes fuel).
    pub headers: Vec<usize>,
    /// Constructs read as `None` that are not panics: undefined behaviour
    /// and unmodeled cases, each named by its MIR construct.
    pub faults: Vec<String>,
    /// Blocks read as `None` because every path from them panics (or is
    /// unreachable): exactly their meaning.
    pub panics: Vec<usize>,
}

/// A cell: the referent of a `&mut` parameter (or of a `&mut` inside it).
#[derive(Clone, Debug)]
pub struct Cell {
    /// Its L type (`@RC@`: the function's code type).
    pub ty: String,
    pub mir_ty: Ty,
    /// The referent sits under an `Option` (`Option<&mut T>`): absent or not.
    pub optional: bool,
    /// The parameter it comes from.
    pub param: usize,
    /// For a referent of a `&mut` held by another cell's referent: that cell.
    pub parent: Option<usize>,
}

/// The kernel view of a MIR ADT instance.
#[derive(Clone, Debug)]
pub struct AdtL {
    pub ty: String,
    /// Explicit constructor parameters (`Some[U8](..)`).
    pub params: Vec<String>,
    /// Kernel constructors in kernel order: (name, the MIR variant it is).
    pub kctors: Vec<(String, usize)>,
    /// A library newtype read as its field (`Digest`).
    pub newtype: bool,
    /// A model type whose fields are not read (`Vec`, the byte-string iterator).
    pub opaque: bool,
}

/// The reading of one module's MIR (the instances it generates, in order).
pub struct Gen<'a> {
    pub m: &'a Sbmir,
    pub k: &'a KNames<'a>,
    pub out: String,
    emitted: BTreeSet<String>,
    pub fns: BTreeMap<String, LFn>,
    ids: BTreeMap<String, String>,
    adts: BTreeMap<String, Result<AdtL, String>>,
    busy: BTreeSet<String>,
    /// The functions generated, callees first.
    pub order: Vec<String>,
}

type R<T> = Result<T, String>;

// ----- text ------------------------------------------------------------------

fn bind(a: &str, b: &str, v: &str, x: &str, body: &str) -> String {
    format!("mir::bind {a} {b} ({v}) (fun ({x} : {a}) => {body})")
}
fn map(a: &str, b: &str, v: &str, x: &str, body: &str) -> String {
    format!("mir::map {a} {b} ({v}) (fun ({x} : {a}) => {body})")
}
fn some(t: &str, v: &str) -> String {
    format!("Some[{t}]({v})")
}
fn none(t: &str) -> String {
    format!("None[{t}]")
}
/// `match x : T as _ return Option(R) with arms end`.
fn mat(x: &str, t: &str, r: &str, arms: &str) -> String {
    format!("match {x} : {t} as _ return {r} with {arms} end")
}
/// The selection `if i == k0 { e0 } else if ..` over `(k, e)`, else `dflt`.
fn select(i: &str, cases: &[(usize, String)], r: &str, dflt: &str) -> String {
    cases.iter().rev().fold(dflt.to_string(), |acc, (k, e)| format!("match #eq_usize({i}, {k}usize) : Bool as _ return {r} with | false => {acc} | true => {e} end"))
}
fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}
fn fxhash(s: &str) -> u64 {
    s.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}
/// A short, unique name tag for a type.
fn tag(t: &Ty) -> String {
    let s = sanitize(&format!("{t:?}"));
    if s.len() > 60 { format!("h{}", fxhash(&s)) } else { s }
}
fn mask(bits: u32) -> u128 {
    if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 }
}
fn short(c: &str) -> String {
    c.rsplit("::").next().unwrap_or(c).split('[').next().unwrap_or(c).to_string()
}
/// The tuple type and constructor of `n` components (`Unit`, `mir::Tuple1`, `TupleN`).
fn tuple(tys: &[String], vals: &[String]) -> (String, String) {
    match tys.len() {
        0 => ("Unit".into(), "tt".into()),
        1 => (format!("mir::Tuple1({})", tys[0]), format!("mir::Tuple1::tuple1[{}]({})", tys[0], vals[0])),
        n => (format!("Tuple{n}({})", tys.join(", ")), format!("tuple{n}[{}]({})", tys.join(", "), vals.join(", "))),
    }
}
/// An output (one component is itself, else the tuple).
fn out_tuple(tys: &[String], vals: &[String]) -> (String, String) {
    if tys.len() == 1 { (tys[0].clone(), vals[0].clone()) } else { tuple(tys, vals) }
}
fn tuple_pat(n: usize) -> &'static str {
    ["", "tuple1", "tuple2", "tuple3", "tuple4", "tuple5", "tuple6", "tuple7", "tuple8"].get(n).copied().unwrap_or("tupleN")
}

// ----- MIR words --------------------------------------------------------------

/// An integer type: its bits' width (`u8`..`usize`) and, when signed, the
/// lift's bit model (`i16`..`i64` are `crate::__lift::I<n>(u<n>)`; `i8` and
/// `isize` are their bits: `""`).
fn int(t: &Ty) -> Option<(&'static str, Option<&'static str>)> {
    let Ty::Int(s, b) = t else { return None };
    // (`u128`/`i128` are not modeled: no kernel word holds them)
    let w = match (s, b) {
        (_, 8) => "u8",
        (_, 16) => "u16",
        (_, 32) => "u32",
        (_, 64) | (true, 0) => "u64",
        (false, 0) => "usize",
        _ => return None,
    };
    Some((w, s.then(|| match b {
        16 => "crate::__lift::I16",
        32 => "crate::__lift::I32",
        64 => "crate::__lift::I64",
        _ => "",
    })))
}
pub(super) fn width(t: &Ty) -> Option<&'static str> {
    int(t).filter(|i| i.1.is_none()).map(|i| i.0)
}
fn signed(t: &Ty) -> bool {
    int(t).is_some_and(|i| i.1.is_some())
}
fn wty(w: &str) -> String {
    if w == "usize" { "Usize".into() } else { w.to_uppercase() }
}
fn bits_of(w: &str) -> u32 {
    w.trim_start_matches('u').parse().unwrap_or(64)
}
/// The bits of `x` of an integer type `t`: (their width, the term).
fn bits(t: &Ty, x: &str) -> Option<(&'static str, String)> {
    Some(match int(t)? {
        (w, Some(st)) if !st.is_empty() => (w, format!("(match {x} : {st} as _ return {} with | {}(b) => b end)", wty(w), short(st))),
        (w, _) => (w, x.to_string()),
    })
}
/// The value of type `t` with bits `b`.
fn of_bits(t: &Ty, b: &str) -> String {
    match int(t) {
        Some((_, Some(st))) if !st.is_empty() => format!("{st}::{}({b})", short(st)),
        _ => b.to_string(),
    }
}
fn is_unit(t: &Ty) -> bool {
    matches!(t, Ty::Unit) || matches!(t, Ty::Tuple(v) if v.is_empty())
}
/// `Option<&mut T>`: `T`.
fn opt_mut(m: &Sbmir, t: &Ty) -> Option<Ty> {
    let Ty::Adt(k) = t else { return None };
    let d = m.adts.get(k)?;
    match d.args.as_slice() {
        [Ty::Ref(true, inner)] if d.path.ends_with("option::Option") => Some((**inner).clone()),
        _ => None,
    }
}
/// The buffer model's referent (`&[u8]`/`&mut [u8]` behind a `&mut`, SEMANTICS.md §19.1).
fn is_buffer(t: &Ty) -> bool {
    matches!(t, Ty::Ref(_, s) if matches!(&**s, Ty::Slice(e) if **e == Ty::Int(false, 8)))
}
pub fn place_ty(f: &Fn, p: &Place) -> R<Ty> {
    let mut t = f.locals.get(p.local).map(|l| l.0.clone()).ok_or("a place's local out of range")?;
    for pr in &p.proj {
        t = proj_ty(&t, pr)?;
    }
    Ok(t)
}
fn proj_ty(t: &Ty, pr: &Proj) -> R<Ty> {
    Ok(match (pr, t) {
        (Proj::Deref, Ty::Ref(_, inner)) => (**inner).clone(),
        (Proj::Field(_, ft), _) => ft.clone(),
        (Proj::Index(_), Ty::Array(e, _) | Ty::Slice(e)) => (**e).clone(),
        (Proj::Downcast(_), t) => t.clone(),
        (pr, t) => return Err(format!("the projection {pr:?} of {t:?}")),
    })
}
/// The printer's rendering of a string constant (`&str`).
const STR_CONST: &str = "constant of type (ref shared str)";

fn const_ty(c: &Const) -> R<Ty> {
    match c {
        Const::Unsupported(s) if s == STR_CONST => Ok(Ty::Ref(false, Box::new(Ty::Str))),
        Const::Int(t, _) | Const::Zst(t) | Const::Agg(t, _, _) => Ok(t.clone()),
        Const::Ref(inner) => Ok(Ty::Ref(false, Box::new(const_ty(inner.value())?))),
        Const::Item(_, _, v) => const_ty(v.value()),
        Const::Unsupported(s) => Err(format!("the constant {s}")),
    }
}
fn op_ty(f: &Fn, o: &Operand) -> R<Ty> {
    match o {
        Operand::Copy(p) | Operand::Move(p) => place_ty(f, p),
        Operand::Const(c) => const_ty(c.value()),
        Operand::RuntimeChecks(_) => Ok(Ty::Bool),
    }
}

/// Depth-first post-order numbers of the blocks and the targets of the back
/// edges (the loop headers). The rank (`2 post + 2`) decreases along every
/// other edge, which the kernel checks for every jump.
/// A terminator's successors (the unwind edges are not followed: an unwind is `None`).
fn succs(t: &Term) -> Vec<usize> {
    match t {
        Term::Goto(b) | Term::Drop(_, _, b) | Term::Assert(_, _, _, b) | Term::Call(_, _, _, Some(b)) => vec![*b],
        Term::Switch(_, arms, o) => arms.iter().map(|a| a.1).chain([*o]).collect(),
        _ => vec![],
    }
}

fn dfs_order(f: &Fn) -> (Vec<usize>, Vec<usize>) {
    struct D {
        succ: Vec<Vec<usize>>,
        state: Vec<u8>,
        post: Vec<usize>,
        headers: Vec<usize>,
        n: usize,
    }
    fn go(d: &mut D, b: usize) {
        d.state[b] = 1;
        for t in d.succ[b].clone() {
            match d.state.get(t) {
                Some(0) => go(d, t),
                Some(1) if !d.headers.contains(&t) => d.headers.push(t),
                _ => {}
            }
        }
        (d.post[b], d.n, d.state[b]) = (d.n, d.n + 1, 2);
    }
    let nb = f.blocks.len();
    let mut d = D { succ: f.blocks.iter().map(|bl| succs(&bl.term)).collect(), state: vec![0; nb], post: vec![0; nb], headers: vec![], n: 0 };
    for root in 0..nb {
        if d.state[root] == 0 {
            go(&mut d, root);
        }
    }
    d.headers.sort();
    (d.post, d.headers)
}

/// Whether every path from block `b` ends in a diverging call,
/// `unreachable`, an abort or an unwind without returning or looping: the
/// block is `None` (nothing on it can reach a return).
fn must_diverge(f: &Fn, b: usize, visiting: &mut Vec<usize>) -> bool {
    let Some(bl) = f.blocks.get(b) else { return false };
    if visiting.contains(&b) {
        return false;
    }
    match &bl.term {
        Term::Unreachable | Term::Abort | Term::Resume | Term::Call(Callee::Diverge(_), ..) | Term::Call(_, _, _, None) => true,
        Term::Return | Term::Unsupported(_) => false,
        t => {
            visiting.push(b);
            let ss = succs(t);
            let r = !ss.is_empty() && ss.iter().all(|x| must_diverge(f, *x, visiting));
            visiting.pop();
            r
        }
    }
}

// ----- types ------------------------------------------------------------------

/// What a [`Gen`] has generated (to continue in a later environment, after
/// its text was loaded).
#[derive(Clone, Debug, Default)]
pub struct GenState {
    emitted: BTreeSet<String>,
    pub fns: BTreeMap<String, LFn>,
    ids: BTreeMap<String, String>,
    adts: BTreeMap<String, Result<AdtL, String>>,
}

impl GenState {
    /// The L type an ADT instance was read as.
    pub fn adt_ty(&self, key: &str) -> Option<String> {
        self.adts.get(key)?.as_ref().ok().map(|a| a.ty.clone())
    }
}

impl<'a> Gen<'a> {
    pub fn new(m: &'a Sbmir, k: &'a KNames<'a>) -> Self {
        Gen { m, k, out: String::new(), emitted: BTreeSet::new(), fns: BTreeMap::new(), ids: BTreeMap::new(), adts: BTreeMap::new(), busy: BTreeSet::new(), order: Vec::new() }
    }

    /// Continues from `st` (its text is loaded: only new definitions are emitted).
    pub fn resume(m: &'a Sbmir, k: &'a KNames<'a>, st: GenState) -> Self {
        Gen { emitted: st.emitted, fns: st.fns, ids: st.ids, adts: st.adts, ..Gen::new(m, k) }
    }

    pub fn state(&self) -> GenState {
        GenState { emitted: self.emitted.clone(), fns: self.fns.clone(), ids: self.ids.clone(), adts: self.adts.clone() }
    }

    fn emit(&mut self, name: &str, text: String) {
        if self.emitted.insert(name.to_string()) {
            self.out.push_str(&text);
            self.out.push('\n');
        }
    }

    /// The L type of a MIR type (`Err`: not modeled). A `&mut` is the
    /// function's code type `@RC@`.
    pub fn ty(&mut self, t: &Ty) -> R<String> {
        Ok(match t {
            Ty::Bool => "Bool".into(),
            Ty::Unit => "Unit".into(),
            Ty::Never => "Empty".into(),
            Ty::Str => "mir::Str".into(),
            Ty::Int(..) => match int(t).ok_or("an integer type")? {
                (_, Some(model)) if !model.is_empty() => model.to_string(),
                (w, _) => wty(w),
            },
            Ty::Tuple(ts) => {
                let parts: Vec<String> = ts.iter().map(|x| self.ty(x)).collect::<R<_>>()?;
                tuple(&parts, &parts).0
            }
            Ty::Array(e, n) => format!("(Array {} {n}usize)", self.ty(e)?),
            // a shared reference is its referent's value
            Ty::Ref(false, inner) => match &**inner {
                Ty::Slice(e) => format!("(Slice {})", self.ty(e)?),
                other => self.ty(other)?,
            },
            Ty::Ref(true, _) => "@RC@".into(),
            Ty::Adt(k) => self.adt(k)?.ty,
            Ty::Closure(_, caps) => self.ty(caps)?,
            Ty::FnDef(..) => "Unit".into(),
            other => return Err(format!("the type {other:?}")),
        })
    }

    /// The kernel constructors of `ind` by MIR variant name, in kernel order.
    fn kctors(&self, ind: &str, d: &AdtDef, qualify: bool) -> R<Vec<(String, usize)>> {
        let id = self.k.env.lookup_ind(ind).ok_or_else(|| format!("no kernel declaration `{ind}`"))?;
        let decl = self.k.env.inductive_decl(id).ok_or("no inductive")?;
        decl.ctors.iter().map(|c| {
            // a struct's one constructor is its one variant; an enum's by name
            let vi = if !d.is_enum && decl.ctors.len() == 1 && d.variants.len() == 1 { Some(0) } else { d.variants.iter().position(|v| v.name == *c.name) };
            let vi = vi.ok_or_else(|| format!("`{ind}::{}` is no variant of `{}`", c.name, d.path))?;
            Ok((if qualify { format!("{ind}::{}", c.name) } else { c.name.to_string() }, vi))
        }).collect()
    }

    /// The kernel view of an ADT instance (§20.4 "Types").
    pub fn adt(&mut self, key: &str) -> R<AdtL> {
        if let Some(a) = self.adts.get(key) {
            return a.clone();
        }
        let r = self.adt_new(key);
        self.adts.insert(key.to_string(), r.clone());
        r
    }

    fn adt_new(&mut self, key: &str) -> R<AdtL> {
        let d = self.m.adts.get(key).cloned().ok_or_else(|| format!("no ADT `{key}`"))?;
        let args: Vec<R<String>> = d.args.iter().map(|a| self.ty(a)).collect();
        let plain = |ty: String| AdtL { ty, params: vec![], kctors: vec![], newtype: false, opaque: false };
        // model types: `Vec<T>` is the list of its elements, the byte-string
        // iterator the byte strings not yet yielded (SEMANTICS.md §19.10), a
        // library newtype of a host model alias its field
        if ["std::vec::Vec", "alloc::vec::Vec"].contains(&d.path.as_str()) && matches!(d.args.get(1), Some(Ty::Adt(a)) if self.m.adts.get(a).is_some_and(|g| g.path.ends_with("alloc::Global"))) {
            return Ok(AdtL { opaque: true, ..plain(format!("List({})", args[0].clone()?)) });
        }
        if super::bytes_iter_model(self.m, &Ty::Adt(key.to_string())) {
            return Ok(AdtL { opaque: true, ..plain("(Slice (Slice U8))".into()) });
        }
        if self.k.names.is_transparent(self.m, key) {
            return Ok(AdtL { newtype: true, ..plain(self.ty(&d.variants[0].fields[0].1)?) });
        }
        if let Some((_, tmpl)) = LIB_ADTS.iter().find(|(p, _)| lib_path(p, &d.path)) {
            let a: Vec<String> = args.into_iter().collect::<R<_>>()?;
            let ty = a.iter().enumerate().fold(tmpl.to_string(), |s, (i, x)| s.replace(&format!("${i}"), x));
            let base = ty.split('(').next().unwrap_or(&ty).to_string();
            let prelude = base == "Option";
            return Ok(AdtL { kctors: self.kctors(&base, &d, !prelude)?, params: if ty.contains('(') { a } else { vec![] }, ..plain(ty) });
        }
        // module types, host enums, host instances: the subset's declaration,
        // unless it carries invariant proofs (then L's own mirror below)
        if let Some(name) = self.k.names.kernel_adt(self.m, key) {
            let irr = self.k.env.lookup_ind(&name).and_then(|i| self.k.env.inductive_decl(i)).is_some_and(|dd| dd.ctors.iter().any(|c| c.fields.iter().any(|f| f.1 == Rel::Irr)));
            if !irr {
                return Ok(AdtL { kctors: self.kctors(&name, &d, true)?, ..plain(name) });
            }
        }
        // L's own inductive: one constructor per variant, its fields in order
        let name = format!("L::{}{}", sanitize(d.path.rsplit("::").next().unwrap_or("T")), fxhash(key) % 100_000);
        let mut decl = format!("inductive {name} {{");
        let mut kctors = Vec::new();
        for (vi, v) in d.variants.iter().enumerate() {
            let fs: Vec<String> = v.fields.iter().enumerate().map(|(i, (_, ft))| Ok(format!("f{i} : {}", self.ty(ft)?))).collect::<R<_>>()?;
            if fs.iter().any(|f| f.contains("@RC@")) {
                return Err(format!("the library type `{}` holding a `&mut`", d.path));
            }
            let c = format!("v{vi}_{}", sanitize(&v.name));
            let _ = if fs.is_empty() { write!(decl, " | {c}") } else { write!(decl, " | {c}({})", fs.join(", ")) };
            kctors.push((format!("{name}::{c}"), vi));
        }
        decl.push_str(" }");
        self.emit(&name, decl);
        Ok(AdtL { kctors, ..plain(name) })
    }

    /// Variant `v` of ADT `k` built from `args` (`Err`: a variant the host
    /// model does not name).
    pub fn ctor(&mut self, k: &str, v: usize, args: &[String]) -> R<String> {
        let a = self.adt(k)?;
        if a.newtype && args.len() == 1 {
            return Ok(args[0].clone());
        }
        let c = a.kctors.iter().find(|c| c.1 == v).map(|c| c.0.clone()).ok_or_else(|| format!("variant {v} of `{k}`, which its model does not name"))?;
        let head = if a.params.is_empty() { c } else { format!("{c}[{}]", a.params.join(", ")) };
        Ok(if args.is_empty() { head } else { format!("{head}({})", args.join(", ")) })
    }

    /// Field `i` of variant `v` of `x : t`: an `Option(F)` term (`None` on
    /// another variant).
    fn field_of(&mut self, rc: &str, t: &Ty, v: usize, i: usize, x: &str) -> R<String> {
        // a closure's fields are its captures
        if let Ty::Closure(_, caps) = t {
            return self.field_of(rc, caps, v, i, x);
        }
        let tt = self.ty(t)?.replace("@RC@", rc);
        match t {
            Ty::Tuple(ts) => {
                let ft = self.ty(ts.get(i).ok_or("a field out of range")?)?.replace("@RC@", rc);
                let bs: Vec<String> = (0..ts.len()).map(|j| format!("{x}f{j}")).collect();
                Ok(mat(x, &tt, &format!("Option({ft})"), &format!("| {}({}) => {}", tuple_pat(ts.len()), bs.join(", "), some(&ft, &bs[i]))))
            }
            Ty::Adt(k) => {
                let d = self.m.adts.get(k).cloned().ok_or("no ADT")?;
                let a = self.adt(k)?;
                let ft = self.ty(&d.variants.get(v).and_then(|vd| vd.fields.get(i)).ok_or("a field out of range")?.1)?.replace("@RC@", rc);
                if a.newtype {
                    return Ok(some(&ft, x));
                }
                if a.opaque {
                    return Err(format!("a field of the model type `{}`", d.path));
                }
                let arms = self.arms(k, &format!("{x}f"), |_, vi, bs| Ok(if vi == v { some(&ft, &bs[i]) } else { none(&ft) }))?;
                Ok(mat(x, &tt, &format!("Option({ft})"), &arms))
            }
            other => Err(format!("a field of {other:?}")),
        }
    }

    /// `x` with field `i` of variant `v` replaced by `z`: an `Option(T)` term.
    fn with_field(&mut self, rc: &str, t: &Ty, v: usize, i: usize, x: &str, z: &str) -> R<String> {
        if let Ty::Closure(_, caps) = t {
            return self.with_field(rc, caps, v, i, x, z);
        }
        let tt = self.ty(t)?.replace("@RC@", rc);
        let ot = format!("Option({tt})");
        match t {
            Ty::Tuple(ts) => {
                let tys: Vec<String> = ts.iter().map(|y| Ok(self.ty(y)?.replace("@RC@", rc))).collect::<R<_>>()?;
                let bs: Vec<String> = (0..ts.len()).map(|j| format!("{x}w{j}")).collect();
                let mut nb = bs.clone();
                nb[i] = z.to_string();
                Ok(mat(x, &tt, &ot, &format!("| {}({}) => {}", tuple_pat(ts.len()), bs.join(", "), some(&tt, &tuple(&tys, &nb).1))))
            }
            Ty::Adt(k) => {
                let d = self.m.adts.get(k).cloned().ok_or("no ADT")?;
                let a = self.adt(k)?;
                if a.newtype {
                    return Ok(some(&tt, z));
                }
                if a.opaque {
                    return Err(format!("a field of the model type `{}`", d.path));
                }
                let arms = self.arms(k, &format!("{x}w"), |g, vi, bs| {
                    if vi != v {
                        return Ok(none(&tt));
                    }
                    let mut nb = bs.to_vec();
                    nb[i] = z.to_string();
                    Ok(some(&tt, &g.ctor(k, vi, &nb)?))
                })?;
                Ok(mat(x, &tt, &ot, &arms))
            }
            other => Err(format!("a field update of {other:?}")),
        }
    }

    /// One arm per kernel constructor of ADT `k`, its fields bound
    /// `{x}<j>`: ` | C(..) => body(variant, binders)`.
    fn arms(&mut self, k: &str, x: &str, mut body: impl FnMut(&mut Self, usize, &[String]) -> R<String>) -> R<String> {
        let (d, a) = (self.m.adts.get(k).cloned().ok_or("no ADT")?, self.adt(k)?);
        let mut out = String::new();
        for (c, vi) in &a.kctors {
            let bs: Vec<String> = (0..d.variants[*vi].fields.len()).map(|j| format!("{x}{j}")).collect();
            let pat = if bs.is_empty() { short(c) } else { format!("{}({})", short(c), bs.join(", ")) };
            let _ = write!(out, " | {pat} => {}", body(self, *vi, &bs)?);
        }
        Ok(out)
    }
}

// ----- functions --------------------------------------------------------------

/// Per-function context.
struct FnCx {
    p: String,
    rc: String,
    f: Fn,
    key: String,
    slot_tys: Vec<String>,
    /// Locals whose type is not modeled (any use of them is `None`).
    unmodeled: BTreeSet<usize>,
    nl: usize,
    cells: Vec<Cell>,
    out_ty: String,
    post: Vec<usize>,
    headers: Vec<usize>,
    /// Targets reached through codes (their `deref`/`write` functions).
    targets: BTreeMap<String, Target>,
    /// The constructor (`b<k>`/`d<k>`) being generated.
    cur: String,
}

/// What a code is followed to: a value of a MIR type, or the buffer model.
#[derive(Clone, Debug)]
enum Target {
    Ty(Ty),
    Buf,
}

/// A compiled place.
enum PlaceC {
    /// A local with static projections.
    Static(usize, Vec<Proj>),
    /// Through a reference code (an `Option(RC)` term) at a type.
    Dyn(String, Ty),
}

impl FnCx {
    fn st(&self) -> String {
        format!("{}::St", self.p)
    }
    fn root(&self) -> String {
        format!("{}::Root", self.p)
    }
    fn rank(&self, b: usize) -> i64 {
        2 * self.post[b] as i64 + 2
    }
    fn none_out(&self) -> String {
        none(&self.out_ty)
    }
}

impl<'a> Gen<'a> {
    fn ty_rc(&mut self, t: &Ty, rc: &str) -> R<String> {
        Ok(self.ty(t)?.replace("@RC@", rc))
    }

    /// The cells of parameter `param` of MIR type `t` (§20.4 "References"):
    /// a `&mut T` parameter's referent, an `Option<&mut T>`'s when present,
    /// and a referent's own `&mut U` / `Option<&mut U>` (a nested cell).
    fn cells_of(&mut self, t: &Ty, param: usize, parent: Option<usize>, cells: &mut Vec<Cell>) -> R<()> {
        let (inner, optional) = match (t, opt_mut(self.m, t)) {
            (Ty::Ref(true, inner), _) => ((**inner).clone(), false),
            (_, Some(inner)) => (inner, true),
            _ => return Ok(()),
        };
        let buffer = is_buffer(&inner);
        let ty = if buffer { "List(U8)".to_string() } else { self.ty(&inner)? };
        cells.push(Cell { ty, mir_ty: inner.clone(), optional, param, parent });
        let j = cells.len() - 1;
        if !buffer && parent.is_none() && (matches!(inner, Ty::Ref(true, _)) || opt_mut(self.m, &inner).is_some()) {
            self.cells_of(&inner, param, Some(j), cells)?;
        }
        Ok(())
    }

    /// The literal reading of `key` and of every function it calls (callees
    /// first).
    pub fn function(&mut self, key: &str) -> R<LFn> {
        if let Some(f) = self.fns.get(key) {
            return Ok(f.clone());
        }
        let f = self.m.fns.get(key).ok_or_else(|| format!("no MIR for `{key}`"))?.clone();
        if !f.has_body {
            return Err(format!("`{key}` has no MIR body"));
        }
        if !self.busy.insert(key.to_string()) {
            return Err(format!("`{key}` is mutually recursive with its caller (not read)"));
        }
        // callees first (a self-call is `rec`; a failing callee is `None` at its calls)
        for b in &f.blocks {
            if let Term::Call(Callee::Fn(k2), ..) = &b.term
                && k2 != key
                && self.m.fns.get(k2).is_some_and(|g| g.has_body)
            {
                let _ = self.function(k2);
            }
        }
        let id = format!("f{}", self.ids.len());
        self.ids.insert(key.to_string(), id.clone());
        let p = format!("L::{id}");
        let rc = format!("Tuple2({p}::Root, List(mir::Proj))");
        let mut cells = Vec::new();
        for i in 1..=f.argc.min(f.locals.len().saturating_sub(1)) {
            let t = f.locals[i].0.clone();
            if let Err(e) = self.cells_of(&t, i, None, &mut cells) {
                self.busy.remove(key);
                return Err(format!("the referent of parameter {i}: {e}"));
            }
        }
        let nl = f.locals.len();
        let mut unmodeled = BTreeSet::new();
        let mut slot_tys = Vec::new();
        for (i, (t, _)) in f.locals.iter().enumerate() {
            slot_tys.push(self.ty_rc(t, &rc).unwrap_or_else(|_| {
                unmodeled.insert(i);
                "mir::Unmodeled".into()
            }));
        }
        let local_tys: Vec<String> = f.locals.iter().map(|(t, _)| self.ty(t).unwrap_or_else(|_| "mir::Unmodeled".into())).collect();
        slot_tys.extend(cells.iter().map(|c| c.ty.replace("@RC@", &rc)));
        let st = format!("{p}::St");
        let fields: Vec<String> = slot_tys.iter().enumerate().map(|(i, t)| if i < nl { format!("l{i} : Option({t})") } else { format!("c{} : Option({t})", i - nl) }).collect();
        let roots: String = (0..nl).map(|i| format!(" | r{i}")).chain((0..cells.len()).map(|j| format!(" | rc{j}"))).collect();
        self.emit(&format!("{p}::__key"), format!("-- {p}: {key}"));
        self.emit(&format!("{p}::Root"), format!("inductive {p}::Root {{{roots} }}"));
        self.emit(&format!("{p}::St"), format!("inductive {p}::St {{ | st({}) }}", fields.join(", ")));
        // slot accessors
        let xs: Vec<String> = (0..slot_tys.len()).map(|i| format!("x{i}")).collect();
        for (i, t) in slot_tys.iter().enumerate() {
            let mut upd = xs.clone();
            upd[i] = some(t, "v");
            self.emit(&format!("{p}::g{i}"), format!("def[prelude] {p}::g{i} : (s : {st}) -> Option({t}) := fun (s : {st}) => {}", mat("s", &st, &format!("Option({t})"), &format!("| st({}) => x{i}", xs.join(", ")))));
            self.emit(&format!("{p}::s{i}"), format!("def[prelude] {p}::s{i} : (s : {st}) -> (v : {t}) -> {st} := fun (s : {st}) (v : {t}) => {}", mat("s", &st, &st, &format!("| st({}) => {st}::st({})", xs.join(", "), upd.join(", ")))));
        }
        // blocks, their dispatchers and ranks
        let nb = f.blocks.len();
        if 2 * nb as i64 + 2 >= RANK_MULT {
            self.busy.remove(key);
            return Err("too many blocks".into());
        }
        let (post, headers) = dfs_order(&f);
        let blk: String = (0..nb).map(|b| format!(" | b{b} | d{b}")).collect();
        self.emit(&format!("{p}::Blk"), format!("inductive {p}::Blk {{{blk} }}"));
        let ranks: String = (0..nb).map(|b| format!(" | b{b} => {}int | d{b} => {}int", 2 * post[b] + 2, 2 * post[b] + 1)).collect();
        self.emit(&format!("{p}::rank"), format!("def[prelude] {p}::rank : (b : {p}::Blk) -> Int := fun (b : {p}::Blk) => match b : {p}::Blk as _ return Int with{ranks} end"));
        // the output: every cell's final value (an optional one as an
        // `Option`), then the return place unless it is `()`
        let mut outs: Vec<String> = cells.iter().map(|c| if c.optional { format!("Option({})", c.ty.replace("@RC@", &rc)) } else { c.ty.replace("@RC@", &rc) }).collect();
        if !is_unit(&f.locals[0].0) {
            outs.push(slot_tys[0].clone());
        }
        let out_ty = out_tuple(&outs, &outs).0;
        let lf = LFn { key: key.to_string(), id: id.clone(), run: format!("{p}::run"), st: st.clone(), blk: format!("{p}::Blk"), out_ty: out_ty.clone(), out_parts: outs.clone(), local_tys, cells: cells.clone(), nblocks: nb, headers: headers.clone(), faults: vec![], panics: vec![] };
        self.fns.insert(key.to_string(), lf.clone());
        let mut fx = FnCx { p: p.clone(), rc, f: f.clone(), key: key.to_string(), slot_tys, unmodeled, nl, cells, out_ty: out_ty.clone(), post, headers, targets: BTreeMap::new(), cur: String::new() };
        let mut arms = Vec::new();
        let mut faults = Vec::new();
        let panics: Vec<usize> = (0..nb).filter(|b| must_diverge(&f, *b, &mut Vec::new())).collect();
        for b in 0..nb {
            for (pre, code) in [("b", self.block(&mut fx, b)), ("d", self.dispatcher(&mut fx, b))] {
                let code = if panics.contains(&b) { Ok(code.unwrap_or_else(|_| fx.none_out())) } else { code };
                let code = code.unwrap_or_else(|e| {
                    faults.push(format!("bb{b}{}: {e}", if pre == "d" { " (switch)" } else { "" }));
                    fx.none_out()
                });
                arms.push(format!("| {pre}{b} => {code}"));
            }
        }
        for (name, t) in fx.targets.clone() {
            self.deref_fns(&fx, &name, &t)?;
        }
        let run = format!(
            "def[exec] {p}::run : (fuel : List(Unit)) -> (b : {p}::Blk) -> (os : Option({st})) -> Option({out_ty}) :=\n  fun (fuel : List(Unit)) (b : {p}::Blk) (os : Option({st})) =>\n    match os : Option({st}) as _ return Option({out_ty}) with\n    | None => None[{out_ty}]\n    | Some(s) => match b : {p}::Blk as yb return Option({out_ty}) using .eb with\n      {}\n      end\n    end\n  measure (#iadd(#imul(seq::len Unit fuel, {RANK_MULT}int), {p}::rank b))",
            arms.join("\n      ")
        );
        let run = run.replace("@RC@", &fx.rc);
        self.emit(&format!("{p}::run"), run);
        let lf = LFn { faults, panics, ..lf };
        self.fns.insert(key.to_string(), lf.clone());
        self.order.push(key.to_string());
        self.busy.remove(key);
        Ok(lf)
    }

    /// Block `b`: its statements' bind chain, then its terminator; a block
    /// from which every path diverges is `None`.
    fn block(&mut self, fx: &mut FnCx, b: usize) -> R<String> {
        fx.cur = format!("b{b}");
        if must_diverge(&fx.f, b, &mut Vec::new()) {
            return Err("every path from here panics or is unreachable".into());
        }
        let st = fx.st();
        let bl = fx.f.blocks[b].clone();
        let mut code = String::new();
        let mut cur = some(&st, "s");
        for (i, s) in bl.stmts.iter().enumerate() {
            let step = self.stmt(fx, s).map_err(|e| format!("statement {i} `{}`: {e}", show(s)))?;
            if let Some(step) = step {
                let _ = write!(code, "let os{i} : Option({st}) = {}; ", bind(&st, &st, &cur, "s", &step));
                cur = format!("os{i}");
            }
        }
        let term = self.terminator(fx, b, &cur).map_err(|e| format!("terminator `{}`: {e}", show(&bl.term)))?;
        Ok((code + &term).replace("@RC@", &fx.rc))
    }

    /// A jump to block `to` with state `os`: free when the rank decreases,
    /// else (a loop header) it consumes one unit of fuel.
    fn jump(&mut self, fx: &FnCx, from_rank: i64, to: usize, os: &str) -> String {
        let (p, tr) = (&fx.p, fx.rank(to));
        if tr < from_rank && !fx.headers.contains(&to) {
            format!("rec(fuel, {p}::Blk::b{to}, {os}; {})", decrease(p, &fx.cur, tr, from_rank, false))
        } else {
            let o = &fx.out_ty;
            format!("match fuel : List(Unit) as yf return Option({o}) using .ef with | Nil => None[{o}] | Cons(u, f1) => rec(f1, {p}::Blk::b{to}, {os}; {}) end", decrease(p, &fx.cur, tr, from_rank, true))
        }
    }

    /// `Goto`, `Return`, `Assert`, `SwitchInt` (to its dispatcher), `Drop`,
    /// `Call`; `Unreachable`/`Resume`/`Abort` are `None`.
    fn terminator(&mut self, fx: &mut FnCx, b: usize, os: &str) -> R<String> {
        let (st, rb) = (fx.st(), fx.rank(b));
        Ok(match &fx.f.blocks[b].term.clone() {
            Term::Goto(t) => self.jump(fx, rb, *t, os),
            Term::Return => {
                // (cells.., return place)
                let mut parts: Vec<(String, String)> = Vec::new();
                for (j, c) in fx.cells.iter().enumerate() {
                    let (slot, t) = (fx.nl + j, fx.slot_tys[fx.nl + j].clone());
                    parts.push(if c.optional { (some(&format!("Option({t})"), &format!("{}::g{slot} s", fx.p)), format!("Option({t})")) } else { (format!("{}::g{slot} s", fx.p), t) });
                }
                if !is_unit(&fx.f.locals[0].0) {
                    self.live(fx, 0)?;
                    parts.push((format!("{}::g0 s", fx.p), fx.slot_tys[0].clone()));
                }
                let (tys, vars): (Vec<String>, Vec<String>) = parts.iter().enumerate().map(|(i, (_, t))| (t.clone(), format!("o{i}"))).unzip();
                let body = parts.iter().enumerate().rev().fold(some(&fx.out_ty, &out_tuple(&tys, &vars).1), |acc, (i, (g, t))| bind(t, &fx.out_ty, g, &format!("o{i}"), &acc));
                bind(&st, &fx.out_ty, os, "s", &body)
            }
            Term::Unreachable | Term::Resume | Term::Abort => return Err("unreachable, an unwind or an abort".into()),
            Term::Drop(_, false, t) => self.jump(fx, rb, *t, os),
            // a drop with glue: nothing for a variant without glue (`no-glue`), else not read
            Term::Drop(pl, true, t) => {
                let pt = place_ty(&fx.f, pl)?;
                let Ty::Adt(k) = &pt else { return Err("a drop with drop glue".into()) };
                let (d, a) = (self.m.adts.get(k).cloned().ok_or("no ADT")?, self.adt(k)?);
                if a.newtype || a.opaque || !d.variants.iter().any(|v| v.no_glue) {
                    return Err(format!("a drop of `{}` with drop glue", d.path));
                }
                let ptt = self.ty_rc(&pt, &fx.rc)?;
                let arms = self.arms(k, "y", |_, vi, _| Ok(if d.variants[vi].no_glue { some(&st, "s") } else { none(&st) }))?;
                let v = self.read(fx, pl)?;
                let dropped = bind(&st, &st, os, "s", &bind(&ptt, &st, &v, "x", &format!("match x : {ptt} as _ return Option({st}) with{arms} end")));
                self.jump(fx, rb, *t, &dropped)
            }
            Term::Assert(c, expected, _, t) => {
                let cv = self.operand(fx, c)?;
                let cond = if *expected { cv } else { map("Bool", "Bool", &cv, "c0", "bool::not c0") };
                let guarded = bind(&st, &st, os, "s", &bind("Bool", &st, &cond, "c", &format!("mir::guard {st} c s")));
                self.jump(fx, rb, *t, &guarded)
            }
            Term::Switch(..) => format!("rec(fuel, {}::Blk::d{b}, {os}; {})", fx.p, decrease(&fx.p, &fx.cur, rb - 1, rb, false)),
            Term::Call(callee, args, dest, target) => self.call(fx, b, callee, args, dest, *target, os)?,
            Term::Unsupported(s) => return Err(format!("the terminator {s}")),
        })
    }

    /// The dispatcher `d<b>` of a `SwitchInt`: the operand compared with each
    /// arm's value, then the jump (`None` when `b` is not a switch).
    fn dispatcher(&mut self, fx: &mut FnCx, b: usize) -> R<String> {
        fx.cur = format!("d{b}");
        let Term::Switch(op, arms, otherwise) = fx.f.blocks[b].term.clone() else { return Ok(fx.none_out()) };
        if must_diverge(&fx.f, b, &mut Vec::new()) {
            return Ok(fx.none_out());
        }
        let (out, rd) = (fx.out_ty.clone(), fx.rank(b) - 1);
        let t = op_ty(&fx.f, &op)?;
        let v = self.operand(fx, &op)?;
        let os = some(&fx.st(), "s");
        let mut jumps: BTreeMap<usize, String> = BTreeMap::new();
        for tg in arms.iter().map(|a| a.1).chain([otherwise]) {
            let j = self.jump(fx, rd, tg, &os);
            jumps.entry(tg).or_insert(j);
        }
        let ro = format!("Option({out})");
        let body = if t == Ty::Bool {
            let pick = |k: u128| arms.iter().find(|a| a.0 == k).map(|a| a.1).unwrap_or(otherwise);
            mat("x", "Bool", &ro, &format!("| false => {} | true => {}", jumps[&pick(0)], jumps[&pick(1)]))
        } else {
            let (w, xb) = bits(&t, "x").ok_or_else(|| format!("a switch on {t:?}"))?;
            arms.iter().rev().fold(jumps[&otherwise].clone(), |e, (val, tg)| mat(&format!("#eq_{w}({xb}, {}{w})", val & mask(bits_of(w))), "Bool", &ro, &format!("| false => {e} | true => {}", jumps[tg])))
        };
        let tt = self.ty_rc(&t, &fx.rc)?;
        Ok(bind(&tt, &out, &v, "x", &body).replace("@RC@", &fx.rc))
    }

    /// A statement as an `Option(St)` term over `s` (`None`: no effect).
    fn stmt(&mut self, fx: &mut FnCx, s: &Stmt) -> R<Option<String>> {
        let st = fx.st();
        Ok(match s {
            // `Assume(c)`: undefined behaviour unless `c`
            Stmt::Assume(o, _) => Some(bind("Bool", &st, &self.operand(fx, o)?, "c", &format!("mir::guard {st} c s"))),
            Stmt::Assign(_, Rvalue::Ref(k, _), _) if k == "fake" => None,
            Stmt::Assign(pl, rv, _) => {
                let dt = place_ty(&fx.f, pl)?;
                let v = self.rvalue(fx, rv, &dt)?;
                let tt = self.ty_rc(&dt, &fx.rc)?;
                Some(bind(&tt, &st, &v, "v", &self.write(fx, pl, "v")?))
            }
            Stmt::Unsupported(x) => return Err(format!("the statement {x}")),
        })
    }

    fn live(&self, fx: &FnCx, l: usize) -> R<()> {
        if fx.unmodeled.contains(&l) { Err(format!("local {l}, whose type is not modeled")) } else { Ok(()) }
    }

    /// An operand as an `Option(T)` term over `s` (`copy`/`move` read the
    /// place; a move leaves the slot: later reads do not occur in borrow-checked MIR).
    fn operand(&mut self, fx: &mut FnCx, o: &Operand) -> R<String> {
        match o {
            Operand::Copy(p) | Operand::Move(p) => self.read(fx, p),
            Operand::Const(c) => {
                let tt = self.ty_rc(&const_ty(c.value())?, &fx.rc)?;
                Ok(some(&tt, &self.konst(c.value())?))
            }
            // the build's overflow checks (on: `load` refuses MIR without them)
            Operand::RuntimeChecks(k) if k == "overflow" => Ok(some("Bool", if self.m.overflow_checks { "true" } else { "false" })),
            Operand::RuntimeChecks(k) if k == "ub" => Ok(some("Bool", "false")),
            Operand::RuntimeChecks(k) => Err(format!("the runtime check {k}")),
        }
    }

    /// A constant's value (integers at their width, `bool`, ZSTs,
    /// aggregates, `&c`, a constant item's value).
    fn konst(&mut self, c: &Const) -> R<String> {
        Ok(match c {
            Const::Int(Ty::Bool, v) => (if *v != 0 { "true" } else { "false" }).into(),
            Const::Int(t, v) => {
                let (w, _) = bits(t, "").ok_or_else(|| format!("an integer constant of {t:?}"))?;
                of_bits(t, &format!("{}{w}", (*v as u128) & mask(bits_of(w))))
            }
            Const::Zst(Ty::Unit | Ty::Closure(..) | Ty::FnDef(..)) => "tt".into(),
            // a zero-sized ADT value: the one variant of a type with one variant
            Const::Zst(Ty::Adt(k)) if self.m.adts.get(k).is_some_and(|d| d.variants.len() == 1) => self.ctor(k, 0, &[])?,
            Const::Agg(t, v, fs) => {
                let args: Vec<String> = fs.iter().map(|x| self.konst(x.value())).collect::<R<_>>()?;
                match t {
                    Ty::Adt(k) => self.ctor(k, *v, &args)?,
                    Ty::Tuple(ts) => {
                        let tys: Vec<String> = ts.iter().map(|x| self.ty(x)).collect::<R<_>>()?;
                        tuple(&tys, &args).1
                    }
                    other => return Err(format!("an aggregate constant of {other:?}")),
                }
            }
            Const::Ref(inner) => self.konst(inner.value())?,
            Const::Item(_, _, v) => self.konst(v.value())?,
            Const::Unsupported(s) if s == STR_CONST => "mir::Str::str".into(),
            other => return Err(format!("the constant {other:?}")),
        })
    }

    // ----- places --------------------------------------------------------------

    /// A place: its local with static projections, or (after the `Deref` of
    /// a `&mut`) the code it holds followed by the rest of the path. The
    /// `Deref` of a shared reference is the snapshot itself.
    fn place(&mut self, fx: &mut FnCx, pl: &Place) -> R<PlaceC> {
        self.live(fx, pl.local)?;
        let mut t = fx.f.locals[pl.local].0.clone();
        let mut cur = PlaceC::Static(pl.local, vec![]);
        for pr in &pl.proj {
            match (pr, &t) {
                (Proj::Deref, Ty::Ref(false, inner)) => t = (**inner).clone(),
                (Proj::Deref, Ty::Ref(true, _)) => {
                    let code = self.read_c(fx, &cur)?;
                    cur = PlaceC::Dyn(code, proj_ty(&t, pr)?);
                }
                (Proj::Field(..) | Proj::Downcast(_) | Proj::Index(_), _) => {
                    let nt = proj_ty(&t, pr)?;
                    cur = match cur {
                        PlaceC::Static(k, mut ps) => {
                            ps.push(pr.clone());
                            PlaceC::Static(k, ps)
                        }
                        PlaceC::Dyn(code, _) => {
                            let (rc, root) = (fx.rc.clone(), fx.root());
                            let step = self.proj_code(fx, pr)?;
                            let ext = format!("Some[{rc}](tuple2[{root}, List(mir::Proj)](rc::fst {root} q, seq::append mir::Proj (rc::snd {root} q) (Cons[mir::Proj]({}, Nil[mir::Proj]))))", step.1);
                            PlaceC::Dyn(bind(&rc, &rc, &code, "q", &step.0.replace("@K@", &ext)), nt.clone())
                        }
                    };
                    t = nt;
                }
                (pr, t) => return Err(format!("the projection {pr:?} of {t:?}")),
            }
        }
        Ok(cur)
    }

    /// A projection as a `mir::Proj` term: (a wrapper with `@K@` for the
    /// continuation, the term); an index reads its local now.
    fn proj_code(&mut self, fx: &mut FnCx, pr: &Proj) -> R<(String, String)> {
        Ok(match pr {
            Proj::Field(i, _) => ("@K@".into(), format!("mir::Proj::PField({i}usize)")),
            Proj::Downcast(v) => ("@K@".into(), format!("mir::Proj::PDown({v}usize)")),
            Proj::Index(l) => {
                self.live(fx, *l)?;
                (bind("Usize", &fx.rc, &format!("{}::g{l} s", fx.p), &format!("i{l}"), "@K@"), format!("mir::Proj::PIndex(i{l})"))
            }
            other => return Err(format!("the projection {other:?}")),
        })
    }

    fn need(&mut self, fx: &mut FnCx, t: Target) -> String {
        let name = match &t {
            Target::Buf => "buf".to_string(),
            Target::Ty(ty) => tag(ty),
        };
        fx.targets.insert(name.clone(), t);
        name
    }

    /// Reads a compiled place: an `Option(T)` term over `s`.
    fn read_c(&mut self, fx: &mut FnCx, pc: &PlaceC) -> R<String> {
        match pc {
            PlaceC::Static(k, ps) if ps.is_empty() => Ok(format!("{}::g{k} s", fx.p)),
            PlaceC::Static(k, ps) => {
                let lt = fx.f.locals[*k].0.clone();
                let ltt = self.ty_rc(&lt, &fx.rc)?;
                let (get, rt) = self.static_get(fx, &lt, ps, "x")?;
                let rtt = self.ty_rc(&rt, &fx.rc)?;
                Ok(bind(&ltt, &rtt, &format!("{}::g{k} s", fx.p), "x", &get))
            }
            PlaceC::Dyn(code, ty) => {
                let tt = self.ty_rc(ty, &fx.rc)?;
                let n = self.need(fx, Target::Ty(ty.clone()));
                Ok(bind(&fx.rc, &tt, code, "q", &format!("{p}::deref__{n} s (rc::fst {r} q) (rc::snd {r} q)", p = fx.p, r = fx.root())))
            }
        }
    }

    fn read(&mut self, fx: &mut FnCx, pl: &Place) -> R<String> {
        // a place of a data-free type (`()`, a closure without captures, a
        // function item) holds its one value: rustc's `RemoveZsts` drops the
        // assignments of such values (MIR reads `_29` of `let f = |n| ..`
        // without ever assigning it)
        let pt = place_ty(&fx.f, pl)?;
        if is_unit(&pt) || matches!(&pt, Ty::FnDef(..)) || matches!(&pt, Ty::Closure(_, caps) if is_unit(caps)) {
            self.live(fx, pl.local)?;
            return Ok(some("Unit", "tt"));
        }
        let pc = self.place(fx, pl)?;
        Ok(self.read_c(fx, &pc)?.replace("@RC@", &fx.rc))
    }

    /// Writes the variable `v` into a place: an `Option(St)` term over `s`.
    fn write(&mut self, fx: &mut FnCx, pl: &Place, v: &str) -> R<String> {
        let (st, p) = (fx.st(), fx.p.clone());
        let r = match self.place(fx, pl)? {
            PlaceC::Static(k, ps) if ps.is_empty() => some(&st, &format!("{p}::s{k} s {v}")),
            PlaceC::Static(k, ps) => {
                let lt = fx.f.locals[k].0.clone();
                let ltt = self.ty_rc(&lt, &fx.rc)?;
                let set = self.static_set(fx, &lt, &ps, "x", v)?;
                bind(&ltt, &st, &format!("{p}::g{k} s"), "x", &map(&ltt, &st, &set, "x2", &format!("{p}::s{k} s x2")))
            }
            PlaceC::Dyn(code, ty) => {
                let n = self.need(fx, Target::Ty(ty));
                bind(&fx.rc, &st, &code, "q", &format!("{p}::write__{n} s (rc::fst {r} q) (rc::snd {r} q) {v}", r = fx.root()))
            }
        };
        Ok(r.replace("@RC@", &fx.rc))
    }

    /// `x.ps` (static projections): an `Option(T)` term, with `T`.
    fn static_get(&mut self, fx: &mut FnCx, t: &Ty, ps: &[Proj], x: &str) -> R<(String, Ty)> {
        if let (Ty::Ref(false, inner), Some(_)) = (t, ps.first()) {
            return self.static_get(fx, inner, ps, x);
        }
        let Some((first, rest)) = ps.split_first() else { return Ok((some(&self.ty_rc(t, &fx.rc)?, x), t.clone())) };
        let y = format!("{x}y");
        let (fe, ft, rest) = match (first, rest.split_first()) {
            (Proj::Field(i, ft), _) => (self.field_of(&fx.rc, t, 0, *i, x)?, ft.clone(), rest),
            (Proj::Downcast(v), Some((Proj::Field(i, ft), rest2))) => (self.field_of(&fx.rc, t, *v, *i, x)?, ft.clone(), rest2),
            (Proj::Index(l), _) => {
                self.live(fx, *l)?;
                let (e, getter) = match t {
                    Ty::Array(e, n) => ((**e).clone(), format!("mir::array_get {} {n}usize {x} i", self.ty_rc(e, &fx.rc)?)),
                    Ty::Slice(e) => ((**e).clone(), format!("slice::get {} {x} i", self.ty_rc(e, &fx.rc)?)),
                    _ => return Err(format!("an index of {t:?}")),
                };
                let (inner, rt) = self.static_get(fx, &e, rest, &y)?;
                let (et, rtt) = (self.ty_rc(&e, &fx.rc)?, self.ty_rc(&rt, &fx.rc)?);
                return Ok((bind("Usize", &rtt, &format!("{}::g{l} s", fx.p), "i", &bind(&et, &rtt, &getter, &y, &inner)), rt));
            }
            (pr, _) => return Err(format!("the projection {pr:?} (a downcast must be followed by a field)")),
        };
        let (inner, rt) = self.static_get(fx, &ft, rest, &y)?;
        let (ftt, rtt) = (self.ty_rc(&ft, &fx.rc)?, self.ty_rc(&rt, &fx.rc)?);
        Ok((bind(&ftt, &rtt, &fe, &y, &inner), rt))
    }

    /// `x.ps = v` (static projections): the updated `x` as an `Option(T)` term.
    fn static_set(&mut self, fx: &mut FnCx, t: &Ty, ps: &[Proj], x: &str, v: &str) -> R<String> {
        let tt = self.ty_rc(t, &fx.rc)?;
        let Some((first, rest)) = ps.split_first() else { return Ok(some(&tt, v)) };
        let (y, z) = (format!("{x}y"), format!("{x}z"));
        let (vi, i, ft, rest) = match (first, rest.split_first()) {
            (Proj::Field(i, ft), _) => (0, *i, ft.clone(), rest),
            (Proj::Downcast(vi), Some((Proj::Field(i, ft), rest2))) => (*vi, *i, ft.clone(), rest2),
            (Proj::Index(l), _) => {
                self.live(fx, *l)?;
                let Ty::Array(e, n) = t else { return Err(format!("an index update of {t:?}")) };
                let et = self.ty_rc(e, &fx.rc)?;
                let inner = self.static_set(fx, e, rest, &y, v)?;
                let set = bind(&et, &tt, &format!("mir::array_get {et} {n}usize {x} i"), &y, &bind(&et, &tt, &inner, &z, &format!("mir::array_set {et} {n}usize {x} i {z}")));
                return Ok(bind("Usize", &tt, &format!("{}::g{l} s", fx.p), "i", &set));
            }
            (pr, _) => return Err(format!("the projection {pr:?} (a downcast must be followed by a field)")),
        };
        let fe = self.field_of(&fx.rc, t, vi, i, x)?;
        let ftt = self.ty_rc(&ft, &fx.rc)?;
        let inner = self.static_set(fx, &ft, rest, &y, v)?;
        let rebuilt = self.with_field(&fx.rc, t, vi, i, x, &z)?;
        Ok(bind(&ftt, &tt, &fe, &y, &bind(&ftt, &tt, &inner, &z, &rebuilt)))
    }

    /// `deref__<n>`/`write__<n>` through a code: per root (a local or a
    /// cell), the path followed in the root's current value. A buffer cell
    /// is read and written whole (`Target::Buf`).
    fn deref_fns(&mut self, fx: &FnCx, n: &str, t: &Target) -> R<()> {
        let (p, st) = (fx.p.clone(), fx.st());
        let tt = match t {
            Target::Buf => "List(U8)".to_string(),
            Target::Ty(ty) => self.ty_rc(ty, &fx.rc)?,
        };
        let (mut darms, mut warms) = (String::new(), String::new());
        for i in 0..fx.slot_tys.len() {
            let rname = if i < fx.nl { format!("r{i}") } else { format!("rc{}", i - fx.nl) };
            let rt = fx.slot_tys[i].clone();
            let buf_cell = i >= fx.nl && is_buffer(&fx.cells[i - fx.nl].mir_ty);
            let mt = if i < fx.nl { fx.f.locals[i].0.clone() } else { fx.cells[i - fx.nl].mir_ty.clone() };
            let get = format!("{p}::g{i} s");
            let (d, w) = match t {
                // a buffer cell: read and written whole
                Target::Buf if buf_cell => (
                    bind(&rt, &tt, &get, "x", &mat("path", "List(mir::Proj)", &format!("Option({tt})"), &format!("| Nil => {} | Cons(h, t) => {}", some(&tt, "x"), none(&tt)))),
                    mat("path", "List(mir::Proj)", &format!("Option({st})"), &format!("| Nil => {} | Cons(h, t) => {}", some(&st, &format!("{p}::s{i} s v")), none(&st))),
                ),
                Target::Ty(ty) if !buf_cell && !fx.unmodeled.contains(&i) => match self.follow(fx, &mt, ty)? {
                    Some((f, u)) => (bind(&rt, &tt, &get, "x", &format!("{f} x path")), bind(&rt, &st, &get, "x", &map(&rt, &st, &format!("{u} x path v"), "x2", &format!("{p}::s{i} s x2")))),
                    None => (none(&tt), none(&st)),
                },
                _ => (none(&tt), none(&st)),
            };
            let _ = write!(darms, " | {rname} => {d}");
            let _ = write!(warms, " | {rname} => {w}");
        }
        let root = fx.root();
        self.emit(&format!("{p}::deref__{n}"), format!("def[prelude] {p}::deref__{n} : (s : {st}) -> (r : {root}) -> (path : List(mir::Proj)) -> Option({tt}) := fun (s : {st}) (r : {root}) (path : List(mir::Proj)) => match r : {root} as _ return Option({tt}) with{darms} end").replace("@RC@", &fx.rc));
        self.emit(&format!("{p}::write__{n}"), format!("def[prelude] {p}::write__{n} : (s : {st}) -> (r : {root}) -> (path : List(mir::Proj)) -> (v : {tt}) -> Option({st}) := fun (s : {st}) (r : {root}) (path : List(mir::Proj)) (v : {tt}) => match r : {root} as _ return Option({st}) with{warms} end").replace("@RC@", &fx.rc));
        Ok(())
    }

    /// `follow__A__T : A -> path -> Option(T)` and `update__A__T : A -> path
    /// -> T -> Option(A)` when `T` can occur in `A`: `PField(i)` of a struct
    /// or tuple, `PDown(v)` then `PField(i)` of an enum, `PIndex(i)` of an array.
    fn follow(&mut self, fx: &FnCx, a: &Ty, t: &Ty) -> R<Option<(String, String)>> {
        if !occurs(self.m, t, a, 0) {
            return Ok(None);
        }
        let tg = { let s = format!("{}__{}", tag(a), tag(t)); if s.len() > 80 { format!("h{}", fxhash(&s)) } else { s } };
        let (fname, uname) = (format!("{}::follow__{tg}", fx.p), format!("{}::update__{tg}", fx.p));
        if self.emitted.contains(&fname) {
            return Ok(Some((fname, uname)));
        }
        self.emitted.insert(fname.clone());
        let (att, tt) = (self.ty_rc(a, &fx.rc)?, self.ty_rc(t, &fx.rc)?);
        let (ot, oa) = (format!("Option({tt})"), format!("Option({att})"));
        // the steps through field `i` of variant `v` (the path's rest is `rest`)
        let via = |g: &mut Self, v: usize, fields: &[Ty], rest: &str| -> R<(String, String)> {
            let (mut fc, mut uc) = (Vec::new(), Vec::new());
            for (i, ft) in fields.iter().enumerate() {
                if let Some((f2, u2)) = g.follow(fx, ft, t)? {
                    let fe = g.field_of(&fx.rc, a, v, i, "x")?;
                    let ftt = g.ty_rc(ft, &fx.rc)?;
                    let rebuilt = g.with_field(&fx.rc, a, v, i, "x", "z")?;
                    fc.push((i, bind(&ftt, &tt, &fe, "y", &format!("{f2} y {rest}"))));
                    uc.push((i, bind(&ftt, &att, &fe, "y", &bind(&ftt, &att, &format!("{u2} y {rest} v"), "z", &rebuilt))));
                }
            }
            Ok((select("i", &fc, &ot, &none(&tt)), select("i", &uc, &oa, &none(&att))))
        };
        // `PDown(v)` then `PField(i)`: the field step under the variant
        let under = |x: &str, b: &str| mat("rest", "List(mir::Proj)", &format!("Option({x})"), &format!("| Nil => {} | Cons(h2, rest2) => match h2 : mir::Proj as _ return Option({x}) with | PField(i) => {b} | PDown(v1) => {} | PIndex(i1) => {} end", none(x), none(x), none(x)));
        let (mut fsel, mut usel) = (none(&tt), none(&att));
        let (mut fdown, mut udown) = (none(&tt), none(&att));
        let (mut fidx, mut uidx) = (none(&tt), none(&att));
        match a {
            Ty::Tuple(ts) => (fsel, usel) = via(self, 0, ts, "rest")?,
            Ty::Adt(k) if !self.adt(k)?.opaque && !self.adt(k)?.newtype => {
                let d = self.m.adts.get(k).cloned().ok_or("no ADT")?;
                if d.is_enum {
                    let (mut fv, mut uv) = (Vec::new(), Vec::new());
                    for (_, vi) in self.adt(k)?.kctors {
                        let fields: Vec<Ty> = d.variants[vi].fields.iter().map(|f| f.1.clone()).collect();
                        let (f1, u1) = via(self, vi, &fields, "rest2")?;
                        fv.push((vi, under(&tt, &f1)));
                        uv.push((vi, under(&att, &u1)));
                    }
                    (fdown, udown) = (select("v0", &fv, &ot, &none(&tt)), select("v0", &uv, &oa, &none(&att)));
                } else if let Some(v) = d.variants.first() {
                    let fields: Vec<Ty> = v.fields.iter().map(|f| f.1.clone()).collect();
                    (fsel, usel) = via(self, 0, &fields, "rest")?;
                }
            }
            Ty::Array(e, n) => {
                if let Some((f2, u2)) = self.follow(fx, e, t)? {
                    let et = self.ty_rc(e, &fx.rc)?;
                    fidx = bind(&et, &tt, &format!("mir::array_get {et} {n}usize x i0"), "y", &format!("{f2} y rest"));
                    uidx = bind(&et, &att, &format!("mir::array_get {et} {n}usize x i0"), "y", &bind(&et, &att, &format!("{u2} y rest v"), "z", &format!("mir::array_set {et} {n}usize x i0 z")));
                }
            }
            _ => {}
        }
        let here = a == t;
        let body = |nil: String, sel: &str, down: &str, idx: &str, r: &str| mat("path", "List(mir::Proj)", r, &format!("| Nil => {nil} | Cons(h, rest) => match h : mir::Proj as _ return {r} with | PField(i) => {sel} | PDown(v0) => {down} | PIndex(i0) => {idx} end"));
        let fdef = format!("def[prelude] {fname} : (x : {att}) -> (path : List(mir::Proj)) -> {ot} := fun (x : {att}) (path : List(mir::Proj)) => {}", body(if here { some(&tt, "x") } else { none(&tt) }, &fsel, &fdown, &fidx, &ot));
        let udef = format!("def[prelude] {uname} : (x : {att}) -> (path : List(mir::Proj)) -> (v : {tt}) -> {oa} := fun (x : {att}) (path : List(mir::Proj)) (v : {tt}) => {}", body(if here { some(&att, "v") } else { none(&att) }, &usel, &udown, &uidx, &oa));
        self.out.push_str(&(fdef.replace("@RC@", &fx.rc) + "\n"));
        self.emit(&uname, udef.replace("@RC@", &fx.rc));
        Ok(Some((fname, uname)))
    }
}

// ----- rvalues ----------------------------------------------------------------

/// Binary operators on words (`BinOp`): the L term over the bits `a`, `b`
/// (`{s}`: a shift amount as a `u32`), the result (`w` the operands' type,
/// `b` `Bool`, `o` `Ordering`), and whether it is total (else `Option`-valued).
/// Signed operands use the rows marked signed-safe on their bits, `lt`..`ge`
/// as signed comparisons and `shr` as the arithmetic shift.
const BINOPS: &[(&str, &str, char, bool)] = &[
    ("add", "#wadd_{w}({a}, {b})", 'w', true),
    ("sub", "#wsub_{w}({a}, {b})", 'w', true),
    ("mul", "#wmul_{w}({a}, {b})", 'w', true),
    ("add-unchecked", "mir::add_unchecked_{w} {a} {b}", 'w', false),
    ("sub-unchecked", "mir::sub_unchecked_{w} {a} {b}", 'w', false),
    ("mul-unchecked", "mir::mul_unchecked_{w} {a} {b}", 'w', false),
    ("div", "mir::div_{w} {a} {b}", 'w', false),
    ("rem", "mir::rem_{w} {a} {b}", 'w', false),
    ("shl", "#wshl_{w}({a}, {s})", 'w', true),
    ("shr", "#wshr_{w}({a}, {s})", 'w', true),
    ("shl-unchecked", "mir::shl_unchecked_{w} {a} ({s})", 'w', false),
    ("shr-unchecked", "mir::shr_unchecked_{w} {a} ({s})", 'w', false),
    ("and", "#and_{w}({a}, {b})", 'w', true),
    ("or", "#or_{w}({a}, {b})", 'w', true),
    ("xor", "#xor_{w}({a}, {b})", 'w', true),
    ("eq", "#eq_{w}({a}, {b})", 'b', true),
    ("ne", "#ne_{w}({a}, {b})", 'b', true),
    ("lt", "#lt_{w}({a}, {b})", 'b', true),
    ("le", "#le_{w}({a}, {b})", 'b', true),
    ("gt", "#gt_{w}({a}, {b})", 'b', true),
    ("ge", "#ge_{w}({a}, {b})", 'b', true),
    ("cmp", "mir::cmp_{w} {a} {b}", 'o', true),
];
/// The same operators on signed bits (two's complement): only those whose
/// meaning on the bits is the signed one.
const SIGNED_BINOPS: &[(&str, &str, char, bool)] = &[
    ("add", "#wadd_{w}({a}, {b})", 'w', true),
    ("sub", "#wsub_{w}({a}, {b})", 'w', true),
    ("mul", "#wmul_{w}({a}, {b})", 'w', true),
    ("shl", "#wshl_{w}({a}, {s})", 'w', true),
    ("shr", "mir::sar_{w} {a} ({s})", 'w', true),
    ("and", "#and_{w}({a}, {b})", 'w', true),
    ("or", "#or_{w}({a}, {b})", 'w', true),
    ("xor", "#xor_{w}({a}, {b})", 'w', true),
    ("eq", "#eq_{w}({a}, {b})", 'b', true),
    ("ne", "#ne_{w}({a}, {b})", 'b', true),
    ("lt", "mir::slt_{w} {a} {b}", 'b', true),
    ("le", "mir::sle_{w} {a} {b}", 'b', true),
    ("gt", "mir::slt_{w} {b} {a}", 'b', true),
    ("ge", "mir::sle_{w} {b} {a}", 'b', true),
];
/// Intrinsic calls: (name, result: `w` the argument's type, `u` `U32`, `p`
/// the pair (value, overflow flag)), the L term over `a0`, `a1` at `{w}`.
const INTRINSICS: &[(&str, char, &str)] = &[
    ("ctlz", 'u', "#leading_zeros_{w}(a0)"),
    ("cttz", 'u', "#trailing_zeros_{w}(a0)"),
    ("ctpop", 'u', "#count_ones_{w}(a0)"),
    ("bswap", 'w', "mir::bswap_{w} a0"),
    ("saturating_add", 'w', "#sat_add_{w}(a0, a1)"),
    ("saturating_sub", 'w', "#sat_sub_{w}(a0, a1)"),
    ("add_with_overflow", 'p', "mir::checked_add_{w} a0 a1"),
    ("sub_with_overflow", 'p', "mir::checked_sub_{w} a0 a1"),
    ("mul_with_overflow", 'p', "mir::checked_mul_{w} a0 a1"),
];
/// Leaves with a `&mut` argument (the first): MIR path → the `literal.core`
/// leaf over its referent (the buffer model, or the pointee's value) and
/// the other arguments, returning (the new referent, the result).
const STATE_LEAVES: &[(&str, &str, bool)] = &[
    ("bytes::Buf::try_get_u8", "leaf::buf_try_get_u8", true),
    ("bytes::BufMut::put_u8", "leaf::bufmut_put_u8", true),
    ("bytes::BufMut::put_slice", "leaf::bufmut_put_slice", true),
    ("std::vec::Vec::<T, A>::push", "leaf::vec_push", false),
    ("alloc::vec::Vec::<T, A>::push", "leaf::vec_push", false),
    ("std::iter::Iterator::next", "leaf::bytes_iter_next", false),
    ("core::iter::Iterator::next", "leaf::bytes_iter_next", false),
];
/// `<[T; N] as Index<range>>::index(&a, r)`: the range type → the leaf (its
/// fields are the leaf's last arguments).
const INDEX_LEAVES: &[(&str, &str)] = &[
    ("ops::RangeToInclusive", "leaf::array_index_to_inclusive"),
    ("ops::RangeTo", "leaf::array_index_to"),
    ("ops::RangeFrom", "leaf::array_index_from"),
    ("ops::Range", "leaf::array_index_range"),
];

impl<'a> Gen<'a> {
    /// An rvalue as an `Option(T)` term over `s`.
    fn rvalue(&mut self, fx: &mut FnCx, rv: &Rvalue, dt: &Ty) -> R<String> {
        let dtt = self.ty_rc(dt, &fx.rc)?;
        Ok(match rv {
            Rvalue::Use(o) => self.operand(fx, o)?,
            Rvalue::Bin(op, a, b) => self.binop(fx, op, a, b)?,
            // `CheckedAdd/Sub/Mul`: (the wrapped value, the overflow flag)
            Rvalue::Checked(op, a, b) => {
                let ta = op_ty(&fx.f, a)?;
                let w = width(&ta).filter(|_| ["add", "sub", "mul"].contains(&op.as_str())).ok_or_else(|| format!("checked {op} on {ta:?}"))?;
                let (av, bv, wt) = (self.operand(fx, a)?, self.operand(fx, b)?, wty(w));
                let pt = format!("Tuple2({wt}, Bool)");
                bind(&wt, &pt, &av, "a", &map(&wt, &pt, &bv, "b", &format!("mir::checked_{op}_{w} a b")))
            }
            Rvalue::Un(op, a) => {
                let ta = op_ty(&fx.f, a)?;
                let (av, tat) = (self.operand(fx, a)?, self.ty_rc(&ta, &fx.rc)?);
                let e = match (op.as_str(), &ta, bits(&ta, "x")) {
                    ("not", Ty::Bool, _) => "bool::not x".to_string(),
                    ("not", _, Some((w, b))) => of_bits(&ta, &format!("#not_{w}({b})")),
                    ("neg", _, Some((w, b))) if signed(&ta) => of_bits(&ta, &format!("#wneg_{w}({b})")),
                    // the metadata of a slice reference: its length
                    ("ptr-metadata", Ty::Ref(false, inner), _) if matches!(&**inner, Ty::Slice(_)) => {
                        let Ty::Slice(e) = &**inner else { unreachable!() };
                        format!("slice::len {} x", self.ty_rc(e, &fx.rc)?)
                    }
                    _ => return Err(format!("the unary {op} on {ta:?}")),
                };
                map(&tat, &dtt, &av, "x", &e)
            }
            Rvalue::Cast(kind, a, to) => self.cast(fx, kind, a, to)?,
            Rvalue::Ref(k, q) if k == "shared" => self.read(fx, q)?,
            Rvalue::Ref(k, q) if k == "mut" => self.borrow(fx, q)?,
            Rvalue::Discr(q) => {
                let qt = place_ty(&fx.f, q)?;
                let Ty::Adt(k) = &qt else { return Err(format!("the discriminant of {qt:?}")) };
                let (v, qtt) = (self.read(fx, q)?, self.ty_rc(&qt, &fx.rc)?);
                let dfn = self.discr_fn(fx, k, dt)?;
                map(&qtt, &dtt, &v, "x", &format!("{dfn} x"))
            }
            // `[x; N]`: the array of `N` copies
            Rvalue::Repeat(o, n) => {
                let ott = self.ty_rc(&op_ty(&fx.f, o)?, &fx.rc)?;
                map(&ott, &dtt, &self.operand(fx, o)?, "x", &format!("array::repeat {ott} {n}usize x .refl(Int, {n}int)"))
            }
            Rvalue::Agg(kind, ops) => {
                let (mut vals, mut tys) = (Vec::new(), Vec::new());
                for o in ops {
                    tys.push(self.ty_rc(&op_ty(&fx.f, o)?, &fx.rc)?);
                    vals.push(self.operand(fx, o)?);
                }
                let vars: Vec<String> = (0..vals.len()).map(|i| format!("a{i}")).collect();
                let built = match kind {
                    AggKind::Tuple | AggKind::Closure(_) => tuple(&tys, &vars).1,
                    AggKind::Adt(Ty::Adt(k), v) => self.ctor(k, *v, &vars)?,
                    // `[a0, ..]`: the list of its elements, with its length
                    AggKind::Array(et) => {
                        let ett = self.ty_rc(et, &fx.rc)?;
                        let l = vars.iter().rev().fold(format!("Nil[{ett}]"), |l, v| format!("Cons[{ett}]({v}, {l})"));
                        format!("pair(Array {ett} {}usize, {l}, refl(Int, {}int))", vars.len(), vars.len())
                    }
                    other => return Err(format!("the aggregate {other:?}")),
                };
                vals.iter().zip(tys.iter()).enumerate().rev().fold(some(&dtt, &built), |e, (i, (v, t))| bind(t, &dtt, v, &format!("a{i}"), &e))
            }
            Rvalue::Ref(k, _) => return Err(format!("a {k} borrow")),
            Rvalue::Len(_) => return Err("`Len`".into()),
            Rvalue::Unsupported(s) => return Err(format!("the rvalue {s}")),
        })
    }

    /// `L::discr__<ADT>`: each variant's discriminant at the destination's width.
    fn discr_fn(&mut self, fx: &FnCx, k: &str, dt: &Ty) -> R<String> {
        let (w, _) = bits(dt, "").ok_or_else(|| format!("a discriminant of type {dt:?}"))?;
        let (d, mut a) = (self.m.adts.get(k).cloned().ok_or("no ADT")?, self.adt(k)?);
        // (a type holding a `&mut` holds this function's codes: its own function)
        let owner = if a.ty.contains("@RC@") { format!("{}::", fx.p) } else { "L::".into() };
        a.ty = a.ty.replace("@RC@", &fx.rc);
        let name = format!("{owner}discr__{}__{w}", if k.len() > 60 { format!("h{}", fxhash(k)) } else { sanitize(k) });
        if a.newtype || a.opaque {
            return Err(format!("the discriminant of the model type `{}`", d.path));
        }
        let arms = self.arms(k, "x", |_, vi, _| Ok(of_bits(dt, &format!("{}{w}", (d.variants[vi].discr as u128) & mask(bits_of(w))))))?;
        let dtt = self.ty(dt)?;
        self.emit(&name, format!("def[prelude] {name} : (x : {}) -> {dtt} := fun (x : {}) => match x : {} as _ return {dtt} with{arms} end", a.ty, a.ty, a.ty));
        Ok(name)
    }

    /// `&mut place`: its reference code (an index projection stores the
    /// index's value now); `&mut *r` is the code `r` holds, extended.
    fn borrow(&mut self, fx: &mut FnCx, q: &Place) -> R<String> {
        let (rc, root) = (fx.rc.clone(), fx.root());
        Ok(match self.place(fx, q)? {
            PlaceC::Static(k, ps) => {
                let (mut wraps, mut path) = (Vec::new(), "Nil[mir::Proj]".to_string());
                for pr in ps.iter().rev() {
                    let (w, c) = self.proj_code(fx, pr)?;
                    wraps.push(w);
                    path = format!("Cons[mir::Proj]({c}, {path})");
                }
                let code = some(&rc, &format!("tuple2[{root}, List(mir::Proj)]({root}::r{k}, {path})"));
                wraps.iter().fold(code, |acc, w| w.replace("@K@", &acc))
            }
            PlaceC::Dyn(code, _) => code,
        })
    }

    fn binop(&mut self, fx: &mut FnCx, op: &str, a: &Operand, b: &Operand) -> R<String> {
        let (ta, tb) = (op_ty(&fx.f, a)?, op_ty(&fx.f, b)?);
        let (av, bv) = (self.operand(fx, a)?, self.operand(fx, b)?);
        let (tat, tbt) = (self.ty_rc(&ta, &fx.rc)?, self.ty_rc(&tb, &fx.rc)?);
        let (rt, body, total) = if ta == Ty::Bool {
            let e = ["and", "or", "xor", "eq", "ne"].iter().find(|o| **o == op).ok_or_else(|| format!("{op} on booleans"))?;
            ("Bool".to_string(), format!("bool::{e} a b"), true)
        } else {
            let (w, ab) = bits(&ta, "a").ok_or_else(|| format!("{op} on {ta:?}"))?;
            let (_, bb) = bits(&tb, "b").ok_or_else(|| format!("{op} with an operand of {tb:?}"))?;
            let table = if signed(&ta) { SIGNED_BINOPS } else { BINOPS };
            let (_, tmpl, res, total) = table.iter().find(|r| r.0 == op).ok_or_else(|| format!("the operator {op} on {ta:?}"))?;
            // a shift amount as a `u32` (its bits: MIR masks or bounds it)
            let s = match bits(&tb, "b") {
                Some(("u32", x)) => x,
                Some((bw, x)) => format!("#cast_{bw}_u32({x})"),
                None => String::new(),
            };
            if op.starts_with("sh") && s.is_empty() {
                return Err(format!("{op} on {ta:?}"));
            }
            let mut e = tmpl.replace("{w}", w).replace("{s}", &s).replace("{a}", &ab).replace("{b}", &bb);
            // `ShlUnchecked`/`ShrUnchecked` by an amount of another width: undefined
            // behaviour unless the amount itself (not its low 32 bits) is below the width
            if op.ends_with("-unchecked") && op.starts_with("sh")
                && let Some((bw, x)) = bits(&tb, "b").filter(|(bw, _)| *bw != "u32")
            {
                e = format!("match #lt_{bw}({x}, {}{bw}) : Bool as _ return Option({tat}) with | false => None[{tat}] | true => {e} end", bits_of(w));
            }
            match res {
                'w' => (tat.clone(), of_bits(&ta, &e), *total),
                'b' => ("Bool".to_string(), e, *total),
                _ => ("crate::__lift::Ordering".to_string(), e, *total),
            }
        };
        let inner = if total { some(&rt, &body) } else { body };
        Ok(bind(&tat, &rt, &av, "a", &bind(&tbt, &rt, &bv, "b", &inner)))
    }

    /// `Cast`: `IntToInt` on the bits (sign extension from a signed type,
    /// zero extension or truncation otherwise; a `bool` is 0 or 1),
    /// `Transmute` of an unsigned word to its little-endian bytes, `Unsize`
    /// of `&[T; N]` to `&[T]`.
    fn cast(&mut self, fx: &mut FnCx, kind: &str, a: &Operand, to: &Ty) -> R<String> {
        let from = op_ty(&fx.f, a)?;
        let (av, ft, tt) = (self.operand(fx, a)?, self.ty_rc(&from, &fx.rc)?, self.ty_rc(to, &fx.rc)?);
        let e = match (kind, &from, to) {
            ("int-to-int", Ty::Bool, _) => {
                let (w, _) = bits(to, "").ok_or_else(|| format!("a cast of a bool to {to:?}"))?;
                of_bits(to, &format!("mir::bool_as_{w} x"))
            }
            ("int-to-int", _, _) => {
                let ((fw, fb), (tw, _)) = (bits(&from, "x").ok_or("a cast from a non-integer")?, bits(to, "").ok_or("a cast to a non-integer")?);
                let c = if fw == tw {
                    fb
                } else if signed(&from) && bits_of(tw) > bits_of(fw) {
                    let x = format!("mir::sext_{fw}_{} ({fb})", if tw == "usize" { "u64" } else { tw });
                    if tw == "usize" { format!("#cast_u64_usize({x})") } else { x }
                } else {
                    format!("#cast_{fw}_{tw}({fb})")
                };
                of_bits(to, &c)
            }
            // the targets are little-endian (SEMANTICS.md §19)
            ("transmute", _, Ty::Array(e, n)) if **e == Ty::Int(false, 8) && width(&from).is_some_and(|w| ["u16", "u32", "u64"].contains(&w) && bits_of(w) == 8 * *n as u32) => {
                format!("{}::to_le_bytes x", width(&from).unwrap())
            }
            ("unsize", Ty::Ref(false, fa), Ty::Ref(false, tb)) if matches!((&**fa, &**tb), (Ty::Array(..), Ty::Slice(_))) => {
                let Ty::Array(e, n) = &**fa else { unreachable!() };
                return Ok(bind(&ft, &tt, &av, "x", &format!("mir::as_slice {} {n}usize x", self.ty_rc(e, &fx.rc)?)));
            }
            _ => return Err(format!("the cast {kind} {from:?} -> {to:?}")),
        };
        Ok(map(&ft, &tt, &av, "x", &e))
    }

    // ----- calls ---------------------------------------------------------------

    /// `Call`: then the jump to the target.
    #[allow(clippy::too_many_arguments)]
    fn call(&mut self, fx: &mut FnCx, b: usize, callee: &Callee, args: &[Operand], dest: &Place, target: Option<usize>, os: &str) -> R<String> {
        let (st, rb) = (fx.st(), fx.rank(b));
        let t = target.ok_or("a call that does not return")?;
        let after = match callee {
            Callee::Diverge(n) => return Err(format!("a call of the diverging `{n}`")),
            // a hint without effect
            Callee::Intrinsic(name, _) if name == "cold_path" => bind(&st, &st, os, "s", &self.write(fx, dest, "tt")?),
            Callee::Intrinsic(name, _) => {
                let w = args.first().map(|a| op_ty(&fx.f, a)).transpose()?.as_ref().and_then(width).ok_or_else(|| format!("the intrinsic {name} on a non-word"))?;
                let (_, res, tmpl) = INTRINSICS.iter().find(|r| r.0 == name && !(r.0 == "bswap" && w == "u8")).ok_or_else(|| format!("the intrinsic {name}"))?;
                let wt = wty(w);
                let rt = match res {
                    'u' => "U32".to_string(),
                    'p' => format!("Tuple2({wt}, Bool)"),
                    _ => wt.clone(),
                };
                let vals: Vec<String> = args.iter().map(|a| self.operand(fx, a)).collect::<R<_>>()?;
                let e = vals.iter().enumerate().rev().fold(some(&rt, &tmpl.replace("{w}", w)), |e, (i, v)| bind(&wt, &rt, v, &format!("a{i}"), &e));
                bind(&st, &st, os, "s", &bind(&rt, &st, &e, "r", &self.write(fx, dest, "r")?))
            }
            Callee::Leaf(path, tys) => self.leaf(fx, path, tys, args, dest, os)?,
            // `Deref::deref` of a library newtype of bytes (its MIR is not exported)
            Callee::Fn(k2) if !self.m.fns.get(k2).is_some_and(|g| g.has_body) => {
                let at = args.first().map(|a| op_ty(&fx.f, a)).transpose()?;
                let n = match at.as_ref().map(|t| self.ty_rc(t, &fx.rc)).transpose()?.as_deref() {
                    Some(s) if k2.ends_with("as std::ops::Deref>::deref") => s.strip_prefix("(Array U8 ").and_then(|r| r.strip_suffix("usize)")).map(str::to_string),
                    _ => None,
                };
                let n = n.ok_or_else(|| format!("`{k2}`, which has no MIR body"))?;
                self.leaf_def("leaf::bytes_deref");
                let e = bind(&format!("(Array U8 {n}usize)"), "(Slice U8)", &self.operand(fx, &args[0])?, "x", &format!("leaf::bytes_deref {n}usize x"));
                bind(&st, &st, os, "s", &bind("(Slice U8)", &st, &e, "r", &self.write(fx, dest, "r")?))
            }
            Callee::Fn(k2) => return self.call_fn(fx, b, k2, args, dest, t, os),
            Callee::Unextracted(k) | Callee::Unsupported(k) => return Err(format!("a call of `{k}`, which was not extracted")),
        };
        Ok(self.jump(fx, rb, t, &after))
    }

    /// A call of a function with MIR (§20.4 "Calls"): the callee's `run` on
    /// the same fuel (a self-call: `rec` on one unit less) from its initial
    /// state; each callee cell is the referent of the caller's code for it,
    /// read before and written back after; codes the callee returns (in its
    /// cells or its result) are translated back to the caller's codes.
    #[allow(clippy::too_many_arguments)]
    fn call_fn(&mut self, fx: &mut FnCx, b: usize, k2: &str, args: &[Operand], dest: &Place, t: usize, os: &str) -> R<String> {
        let (st, p, rc, root, rb) = (fx.st(), fx.p.clone(), fx.rc.clone(), fx.root(), fx.rank(b));
        let g = self.m.fns.get(k2).cloned().ok_or("no MIR")?;
        let self_call = k2 == fx.key;
        let gl = if self_call { self.fns.get(k2).cloned().ok_or("self")? } else { self.function(k2).map_err(|e| format!("the callee `{k2}`: {e}"))? };
        // the arguments (a closure body takes its parameters one by one, its
        // callers pass their tuple; a shim with `spread-arg` keeps the tuple)
        let mut argv: Vec<(String, Ty)> = args.iter().map(|a| Ok((self.operand(fx, a)?, op_ty(&fx.f, a)?))).collect::<R<_>>()?;
        if matches!(g.item, Item::Closure) && let Some((tv, tt)) = argv.pop() {
            let Ty::Tuple(ts) = &tt else { return Err(format!("a closure called with {tt:?}")) };
            let ttt = self.ty_rc(&tt, &rc)?;
            for (i, ft) in ts.iter().enumerate() {
                let (fe, ftt) = (self.field_of(&rc, &tt, 0, i, "tp")?, self.ty_rc(ft, &rc)?);
                argv.push((bind(&ttt, &ftt, &tv, "tp", &fe), ft.clone()));
            }
        }
        if argv.len() != g.argc {
            return Err(format!("`{k2}` takes {} arguments, called with {}", g.argc, argv.len()));
        }
        let (gp, grc) = (format!("L::{}", gl.id), format!("Tuple2(L::{}::Root, List(mir::Proj))", gl.id));
        let groot = format!("{gp}::Root");
        let gcode = |j: usize| format!("tuple2[{groot}, List(mir::Proj)]({groot}::rc{j}, Nil[mir::Proj])");
        let orc = format!("Option({rc})");
        let mut pre = String::new();
        let mut closers = 0;
        let mut open = |pre: &mut String, a: &str, v: &str, x: &str| {
            let _ = write!(pre, "mir::bind {a} {st} ({v}) (fun ({x} : {a}) => ");
            closers += 1;
        };
        for (i, (v, at)) in argv.iter().enumerate() {
            let att = self.ty_rc(at, &rc)?;
            open(&mut pre, &att, v, &format!("a{i}"));
        }
        // each callee cell: the caller's code (`cc<j> : Option(RC)`, `None` for
        // an absent optional referent), its initial value (`cv<j>`, read
        // through it: a held code is the nested cell's), and its write-back
        let (ncells, nl) = (gl.cells.len(), gl.local_tys.len());
        let mut slots: Vec<String> = vec![String::new(); nl + ncells];
        let has_ret = !is_unit(&g.locals[0].0);
        let nparts = ncells + has_ret as usize;
        let parts: Vec<String> = if nparts == 1 { vec!["res".into()] } else { (0..nparts).map(|i| format!("o{i}")).collect() };
        let mut steps: Vec<String> = Vec::new();
        for (j, c) in gl.cells.iter().enumerate() {
            let a = format!("a{}", c.param - 1);
            let buffer = is_buffer(&c.mir_ty);
            let n = self.need(fx, if buffer { Target::Buf } else { Target::Ty(c.mir_ty.clone()) });
            let (ct, ctr) = (c.ty.replace("@RC@", &grc), if buffer { "List(U8)".to_string() } else { self.ty_rc(&c.mir_ty, &rc)? });
            let cc = match c.parent {
                None if c.optional => a.clone(),
                None => some(&rc, &a),
                // the parent's referent holds this referent's code
                Some(k) => {
                    let (pn, ptt) = (self.need(fx, Target::Ty(gl.cells[k].mir_ty.clone())), self.ty_rc(&gl.cells[k].mir_ty, &rc)?);
                    let inner = if c.optional { "v".to_string() } else { some(&rc, "v") };
                    bind(&rc, &rc, &format!("cc{k}"), "q", &bind(&ptt, &rc, &format!("{p}::deref__{pn} s (rc::fst {root} q) (rc::snd {root} q)"), "v", &inner))
                }
            };
            let child = (j + 1..ncells).find(|x| gl.cells[*x].parent == Some(j));
            if child.is_none() && !buffer && (matches!(c.mir_ty, Ty::Ref(true, _)) || opt_mut(self.m, &c.mir_ty).is_some()) {
                return Err(format!("a referent holding a reference of `{k2}` beyond one level"));
            }
            let xin = match child {
                Some(n2) if gl.cells[n2].optional => mat("v", &orc, &format!("Option({grc})"), &format!("| None => {} | Some(q2) => {}", none(&grc), some(&grc, &gcode(n2)))),
                Some(n2) => gcode(n2),
                None => "v".to_string(),
            };
            let (oct, ost) = (format!("Option({ct})"), format!("Option({st})"));
            let cv = mat(&format!("cc{j}"), &orc, &format!("Option({oct})"), &format!("| None => {} | Some(q) => {}", some(&oct, &none(&ct)), map(&ctr, &oct, &format!("{p}::deref__{n} s (rc::fst {root} q) (rc::snd {root} q)"), "v", &some(&ct, &xin))));
            let _ = write!(pre, "let cc{j} : {orc} = {cc}; ");
            open(&mut pre, &oct, &cv, &format!("cv{j}"));
            slots[nl + j] = format!("cv{j}");
            if c.parent.is_none() {
                let pt = gl.local_tys[c.param].replace("@RC@", &grc);
                slots[c.param] = if c.optional { mat(&a, &orc, &format!("Option({pt})"), &format!("| None => {} | Some(q) => {}", some(&pt, &none(&grc)), some(&pt, &some(&grc, &gcode(j))))) } else { some(&pt, &gcode(j)) };
            }
            // the write-back: the final value (`None`: the callee lost it) through the caller's code
            let fin = if c.optional { parts[j].clone() } else { some(&ct, &parts[j]) };
            let wb = format!("{p}::write__{n} s (rc::fst {root} q) (rc::snd {root} q)");
            let back = if buffer { format!("{wb} w") } else { bind(&ctr, &st, &self.xout(&gl, fx, &c.mir_ty, "w")?, "w2", &format!("{wb} w2")) };
            steps.push(mat(&format!("cc{j}"), &orc, &ost, &format!("| None => {} | Some(q) => {}", some(&st, "s"), mat(&fin, &oct, &ost, &format!("| None => {} | Some(w) => {back}", none(&st))))));
        }
        for (i, s) in slots.iter_mut().enumerate().take(nl) {
            if s.is_empty() {
                let lt = gl.local_tys[i].replace("@RC@", &grc);
                *s = if (1..=g.argc).contains(&i) { some(&lt, &format!("a{}", i - 1)) } else { none(&lt) };
            }
        }
        let gst = format!("{gp}::St");
        let init = some(&gst, &format!("{gst}::st({})", slots.join(", ")));
        let run = if self_call { format!("rec(f1, {p}::Blk::b0, {init}; {})", decrease(&p, &fx.cur, fx.rank(0), rb, true)) } else { format!("{gp}::run fuel {gp}::Blk::b0 ({init})") };
        let dt = place_ty(&fx.f, dest)?;
        if has_ret {
            let dtt = self.ty_rc(&dt, &rc)?;
            steps.push(bind(&dtt, &st, &self.xout(&gl, fx, &g.locals[0].0, &parts[nparts - 1])?, "rr", &self.write(fx, dest, "rr")?));
        } else {
            steps.push(self.write(fx, dest, "tt")?);
        }
        let chain = steps.iter().rev().fold(some(&st, "s"), |acc, stp| bind(&st, &st, stp, "s", &acc));
        let gout = gl.out_ty.clone();
        let body = if nparts > 1 { mat("res", &gout, &format!("Option({st})"), &format!("| {}({}) => {chain}", tuple_pat(nparts), parts.join(", "))) } else { chain };
        let full = bind(&st, &st, os, "s", &format!("{pre}{}{}", bind(&gout, &st, &run, "res", &body), ")".repeat(closers)));
        Ok(if self_call {
            let o = &fx.out_ty;
            format!("match fuel : List(Unit) as yf return Option({o}) using .ef with | Nil => None[{o}] | Cons(u, f1) => rec(f1, {p}::Blk::b{t}, {full}; {}) end", decrease(&p, &fx.cur, fx.rank(t), rb, true))
        } else {
            self.jump(fx, rb, t, &full)
        })
    }

    /// A value of MIR type `t` in the callee `gl`'s terms, in the caller's
    /// (`Option(T)`): a code rooted at a callee cell is the caller's code for
    /// that cell extended by its path; one rooted at a callee local cannot
    /// occur (a dangling reference) and is `None`.
    fn xout(&mut self, gl: &LFn, fx: &FnCx, t: &Ty, v: &str) -> R<String> {
        let (rc, root) = (fx.rc.as_str(), fx.root());
        let (tt, groot, orc) = (self.ty_rc(t, rc)?, format!("L::{}::Root", gl.id), format!("Option({rc})"));
        let xlate = |q: &str| {
            let arms: String = (0..gl.local_tys.len()).map(|i| format!(" | r{i} => {}", none(rc))).chain((0..gl.cells.len()).map(|j| format!(" | rc{j} => {}", bind(rc, rc, &format!("cc{j}"), "c", &some(rc, &format!("tuple2[{root}, List(mir::Proj)](rc::fst {root} c, seq::append mir::Proj (rc::snd {root} c) (rc::snd {groot} {q}))")))))).collect();
            format!("match rc::fst {groot} {q} : {groot} as _ return {orc} with{arms} end")
        };
        Ok(match (t, opt_mut(self.m, t)) {
            (Ty::Ref(true, _), _) => xlate(v),
            (_, Some(_)) => mat(v, &format!("Option(Tuple2({groot}, List(mir::Proj)))"), &format!("Option({tt})"), &format!("| None => {} | Some(q3) => {}", some(&tt, &none(rc)), map(rc, &tt, &xlate("q3"), "c3", &some(rc, "c3")))),
            _ if self.ty(t)?.contains("@RC@") => return Err("a value holding references returned by a callee".into()),
            _ => some(&tt, v),
        })
    }

    fn leaf_def(&mut self, name: &str) {
        if let Some(text) = leaf_text(name) {
            self.emit(name, text);
        }
    }

    /// A leaf call (§20.4 "Leaves"): a library function without MIR whose
    /// meaning is a model of `literal.core` or of a host model.
    fn leaf(&mut self, fx: &mut FnCx, path: &str, tys: &[Ty], args: &[Operand], dest: &Place, os: &str) -> R<String> {
        let (st, rc, root, p) = (fx.st(), fx.rc.clone(), fx.root(), fx.p.clone());
        let dtt = self.ty_rc(&place_ty(&fx.f, dest)?, &rc)?;
        // a leaf with a `&mut` first argument: its referent through the code
        let norm = path.replace("bytes::buf::buf_impl::Buf::", "bytes::Buf::").replace("bytes::buf::buf_mut::BufMut::", "bytes::BufMut::");
        if let Some((_, leaf, buffer)) = STATE_LEAVES.iter().find(|l| norm == l.0) {
            let Some(Ty::Ref(true, pointee)) = args.first().map(|a| op_ty(&fx.f, a)).transpose()? else { return Err(format!("the leaf `{path}` without a `&mut` receiver")) };
            let (target, sty) = if *buffer { (Target::Buf, "List(U8)".to_string()) } else { (Target::Ty((*pointee).clone()), self.ty_rc(&pointee, &rc)?) };
            if leaf.ends_with("bytes_iter_next") && sty != "(Slice (Slice U8))" {
                return Err(format!("`Iterator::next` of {pointee:?} (not the byte-string iterator model)"));
            }
            let tparam = if leaf.ends_with("vec_push") { format!(" {}", sty.strip_prefix("List(").and_then(|x| x.strip_suffix(')')).ok_or("push on a non-`Vec`")?) } else { String::new() };
            self.leaf_def(leaf);
            let n = self.need(fx, target);
            let code = self.operand(fx, &args[0])?;
            let mut call = format!("{leaf}{tparam} x0");
            let mut binds = Vec::new();
            for (i, a) in args.iter().enumerate().skip(1) {
                binds.push((self.ty_rc(&op_ty(&fx.f, a)?, &rc)?, self.operand(fx, a)?, format!("x{i}")));
                let _ = write!(call, " x{i}");
            }
            let rt = format!("Tuple2({sty}, {dtt})");
            let m = mat(&call, &rt, &format!("Option({st})"), &format!("| tuple2(nx, r) => {}", bind(&st, &st, &format!("{p}::write__{n} s (rc::fst {root} q) (rc::snd {root} q) nx"), "s", &self.write(fx, dest, "r")?)));
            let inner = binds.iter().rev().fold(m, |e, (t, v, x)| bind(t, &st, v, x, &e));
            return Ok(bind(&st, &st, os, "s", &bind(&rc, &st, &code, "q", &bind(&sty, &st, &format!("{p}::deref__{n} s (rc::fst {root} q) (rc::snd {root} q)"), "x0", &inner))));
        }
        // a value leaf: a model at the arguments (a range's fields), `Option`-valued or total
        let method = path.rsplit("::").next().unwrap_or("");
        let (f, partial, vals) = match tys {
            // `<[T; N] as Index<range>>::index(&a, r)`
            [Ty::Array(e, n), Ty::Adt(rk)] if path.ends_with("ops::Index::index") => {
                let rd = self.m.adts.get(rk).cloned().ok_or("no ADT")?;
                let (_, leaf) = INDEX_LEAVES.iter().find(|(r, _)| lib_path(r, &rd.path)).ok_or_else(|| format!("an index by `{}`", rd.path))?;
                self.leaf_def(leaf);
                let (rty, et) = (Ty::Adt(rk.clone()), self.ty_rc(e, &rc)?);
                let mut vals = vec![(format!("(Array {et} {n}usize)"), self.operand(fx, &args[0])?)];
                for (i, (_, ft)) in rd.variants[0].fields.iter().enumerate() {
                    let (rtt, ftt, rv) = (self.ty_rc(&rty, &rc)?, self.ty_rc(ft, &rc)?, self.operand(fx, &args[1])?);
                    vals.push((ftt.clone(), bind(&rtt, &ftt, &rv, "xr", &self.field_of(&rc, &rty, 0, i, "xr")?)));
                }
                (format!("{leaf} {et} {n}usize"), true, vals)
            }
            // a host model's method
            [t, ..] if self.k.names.host_model_method(self.m, t, method).is_some() => {
                let vals = args.iter().map(|a| Ok((self.ty_rc(&op_ty(&fx.f, a)?, &rc)?, self.operand(fx, a)?))).collect::<R<_>>()?;
                (self.k.names.host_model_method(self.m, t, method).unwrap(), false, vals)
            }
            _ => return Err(format!("the leaf `{path}` (no model)")),
        };
        let call = (0..vals.len()).fold(f, |c, i| format!("{c} a{i}"));
        let e = vals.iter().enumerate().rev().fold(if partial { call } else { some(&dtt, &call) }, |e, (i, (t, v))| bind(t, &dtt, v, &format!("a{i}"), &e));
        Ok(bind(&st, &st, os, "s", &bind(&dtt, &st, &e, "r", &self.write(fx, dest, "r")?)))

    }
}

/// Whether `t` can occur inside a value of type `a` (through fields and
/// array elements; never through a reference).
fn occurs(m: &Sbmir, t: &Ty, a: &Ty, depth: u32) -> bool {
    a == t
        || depth < 8
            && match a {
                Ty::Tuple(ts) => ts.iter().any(|x| occurs(m, t, x, depth + 1)),
                Ty::Array(e, _) => occurs(m, t, e, depth + 1),
                Ty::Adt(k) => m.adts.get(k).is_some_and(|d| d.variants.iter().any(|v| v.fields.iter().any(|(_, ft)| occurs(m, t, ft, depth + 1)))),
                _ => false,
            }
}

/// The decrease proof of a jump from a block of rank `from` to one of rank
/// `to` (`linarith` over the block match's path equation `eb`, and with fuel
/// the fuel match's `ef`): `len·M + to < len·M + rank b`.
fn decrease(p: &str, cur: &str, to: i64, from: i64, fuel: bool) -> String {
    let m = RANK_MULT;
    let n = if fuel { "f1" } else { "fuel" };
    let mt = format!("#iadd(#imul(seq::len Unit {n}, {m}int), {to}int)");
    let mp = format!("#iadd(#imul(seq::len Unit fuel, {m}int), {p}::rank b)");
    let mut facts = format!("eq::cong {p}::Blk Int {p}::rank b {p}::Blk::{cur} eb : Eq(Int, {p}::rank b, {from}int)");
    if fuel {
        facts.push_str(", eq::cong (List(Unit)) Int (seq::len Unit) fuel (Cons[Unit](u, f1)) ef : Eq(Int, seq::len Unit fuel, #iadd(1int, seq::len Unit f1))");
    }
    format!("pair(Sigma (_ : Eq(Bool, #le_int(0int, {mt}), true)), Eq(Bool, #lt_int({mt}, {mp}), true), linarith([]; Eq(Bool, #le_int(0int, {mt}), true); []), linarith([{facts}]; Eq(Bool, #lt_int({mt}, {mp}), true); []))")
}

/// A short rendering of a MIR construct (fault messages name it).
fn show(x: &impl std::fmt::Debug) -> String {
    let t = format!("{x:?}");
    if t.len() > 200 { format!("{}..", &t[..t.char_indices().nth(200).map(|c| c.0).unwrap_or(t.len())]) } else { t }
}
