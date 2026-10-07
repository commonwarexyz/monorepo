//! The literal reading L of rustc's MIR (`docs/mir-lift.md` §20.4,
//! `docs/checked-structuring.md` §2). TRUSTED: L is what a MIR body means;
//! the structured reading S of `read.rs` is checked against it.
//!
//! Every MIR instance becomes kernel definitions `L::<id>::{Root, St, Blk,
//! rank, g<i>, s<i>, run}`, written as core text and checked by the kernel:
//!
//! * `St` has one `Option` slot per local (`None`: not initialized) and one
//!   per **cell**, the referent of a `&mut` parameter (state passing);
//! * `run : (fuel : List(Unit)) -> (b : Blk) -> (os : mir::Res(St)) ->
//!   mir::Res(Out)` has one arm per block `b<k>` and per switch dispatcher
//!   `d<k>`, by measure recursion (`len(fuel) * 65536 + rank(b)`); a jump
//!   to a loop header and a self-call consume one unit of fuel;
//! * a `&mut` value is a **reference code** `(root, path)` of the frame; a
//!   shared reference is its referent's value (a snapshot);
//! * statements run in the option monad (`mir::bind`); a terminator hands
//!   the next block a `mir::Res(St)`.
//!
//! **Outcomes** (`mir::Res`, docs/mir-lift.md §20.4): `Ret(v)` a value;
//! `Panic` an explicit panic of the code, which only a terminator causes —
//! a failed `Assert` of a kind whose failure panics ([`PANIC_ASSERT_KINDS`],
//! `mir::check`; any other kind is stuck where it fails,
//! `mir::check_or_stuck`), a block every path of which panics
//! ([`must_panic`]: it ends in a call of a panic function, [`PANIC_FNS`]),
//! a callee's panic (`mir::then`); `Stuck` anything else that gives no
//! value: undefined behaviour, running out of fuel, a construct this
//! reading does not model (inside a block `None`, made `Stuck` at its
//! terminator). Neither failure can make a theorem false, only unprovable;
//! a `Panic` is claimed only where the MIR certainly panics. Every
//! construct read as stuck is recorded in [`LFn::faults`], named by its
//! MIR construct. The reading never structures (no joins, loops or carried
//! values).
//!
//! Not trusted (`cfg.rs`, see there): the blocks' ranks and loop headers
//! (where fuel is consumed: the kernel checks every decrease), the blocks
//! from which every path diverges (read as stuck unless [`must_panic`]
//! reads them as a panic), which types a code can reach inside which
//! (pruning: `None`), and the rendering of fault messages. Within this
//! file, text is written with `@RC@` for the function's code type and
//! replaced where each definition is emitted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::Rel;

use super::cfg::{dfs_order, occurs, panic_blocks, show};
use super::ir::*;
use super::ModuleNames;

/// The fixed library (`literal.core`): the base, then the leaves.
pub const LIBRARY: &str = include_str!("literal.core");
const LEAVES: &str = "-- LEAVES";
const RANK_MULT: i64 = 65536;

/// The library's base (every definition but the leaves), templates expanded.
pub fn library() -> String { sandblaster_kernel::expand_templates(LIBRARY.split(LEAVES).next().unwrap_or("")).expect("literal.core templates") }

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
fn lib_path(p: &str, path: &str) -> bool { if p.starts_with("bytes::") { path == p } else { path.strip_prefix("std::").or_else(|| path.strip_prefix("core::")) == Some(p) } }

/// The integer types, `(signed, bits)` (bits 0: `usize`/`isize`) → the word
/// holding their bits and, when signed, the lift's bit model (`""`: `i8` and
/// `isize` are their bits). `u128`/`i128` are not modeled: no kernel word
/// holds them.
const INTS: &[(bool, u32, &str, &str)] = &[
    (false, 8, "u8", ""), (false, 16, "u16", ""), (false, 32, "u32", ""), (false, 64, "u64", ""), (false, 0, "usize", ""),
    (true, 8, "u8", ""), (true, 16, "u16", "crate::__lift::I16"), (true, 32, "u32", "crate::__lift::I32"), (true, 64, "u64", "crate::__lift::I64"), (true, 0, "u64", ""),
];

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
    /// Loop headers (a jump to one consumes fuel).
    pub headers: Vec<usize>,
    /// Constructs read as stuck: undefined behaviour and unmodeled cases,
    /// each named by its MIR construct.
    pub faults: Vec<String>,
    /// Blocks read as `Panic` because every path from them ends in a call
    /// of a panic function ([`must_panic`]): exactly their meaning.
    pub panics: Vec<usize>,
    /// Blocks read as stuck because every path from them diverges (an
    /// `unreachable`, an abort, a call that does not return) without each
    /// path being a panic ([`must_panic`]).
    pub diverging: Vec<usize>,
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
    pub fn adt_ty(&self, key: &str) -> Option<String> { self.adts.get(key)?.as_ref().ok().map(|a| a.ty.clone()) }
}

/// The reading of one module's MIR (the instances it generates, in order).
pub struct Gen<'a> {
    pub m: &'a Sbmir,
    pub k: &'a KNames<'a>,
    pub out: String,
    s: GenState,
    busy: BTreeSet<String>,
}

type R<T> = Result<T, String>;

// ----- text ------------------------------------------------------------------

fn bind(a: &str, b: &str, v: &str, x: &str, body: &str) -> String { format!("mir::bind {a} {b} ({v}) (fun ({x} : {a}) => {body})") }
fn map(a: &str, b: &str, v: &str, x: &str, body: &str) -> String { format!("mir::map {a} {b} ({v}) (fun ({x} : {a}) => {body})") }
fn some(t: &str, v: &str) -> String { format!("Some[{t}]({v})") }
fn none(t: &str) -> String { format!("None[{t}]") }
/// The outcomes (`mir::Res`): a value, stuck, a panic.
fn ret(t: &str, v: &str) -> String { format!("mir::Res::Ret[{t}]({v})") }
fn stuck(t: &str) -> String { format!("mir::Res::Stuck[{t}]") }
fn panicked(t: &str) -> String { format!("mir::Res::Panic[{t}]") }
/// A block's `Option` (`None`: stuck) as an outcome.
fn res_of(t: &str, o: &str) -> String { format!("mir::st {t} ({o})") }
/// `mir::bind` of an `Option` into an outcome (`None`: stuck).
fn bindr(a: &str, b: &str, v: &str, x: &str, body: &str) -> String { format!("mir::bindr {a} {b} ({v}) (fun ({x} : {a}) => {body})") }
/// A callee's outcome continued (its panic or stuck propagated).
fn then(a: &str, b: &str, v: &str, x: &str, body: &str) -> String { format!("mir::then {a} {b} ({v}) (fun ({x} : {a}) => {body})") }
/// `match x : T as _ return R with arms end`.
fn mat(x: &str, t: &str, r: &str, arms: &str) -> String { format!("match {x} : {t} as _ return {r} with {arms} end") }
/// The selection `if i == k0 { e0 } else if ..` over `(k, e)`, else `dflt`.
fn select(i: &str, cases: &[(usize, String)], r: &str, dflt: &str) -> String {
    cases.iter().rev().fold(dflt.to_string(), |acc, (k, e)| mat(&format!("#eq_usize({i}, {k}usize)"), "Bool", r, &format!("| false => {acc} | true => {e}")))
}
/// The reference code `(r, path)` at the root type `root`.
fn code(root: &str, r: &str, path: &str) -> String { format!("tuple2[{root}, List(mir::Proj)]({r}, {path})") }
/// The code `q` extended by the path `ps`.
fn code_app(root: &str, q: &str, ps: &str) -> String { code(root, &format!("rc::fst {root} {q}"), &format!("seq::append mir::Proj (rc::snd {root} {q}) ({ps})")) }
fn sanitize(s: &str) -> String { s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect() }
fn fxhash(s: &str) -> u64 { s.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3)) }
/// A short, unique name tag (hashed beyond `max` characters).
fn tag(s: &str, max: usize) -> String {
    let s = sanitize(s);
    if s.len() > max { format!("h{}", fxhash(&s)) } else { s }
}
fn short(c: &str) -> String { c.rsplit("::").next().unwrap_or(c).split('[').next().unwrap_or(c).to_string() }
/// The tuple type and constructor of `n` components (`Unit`, `mir::Tuple1`, `TupleN`).
fn tuple(tys: &[String], vals: &[String]) -> (String, String) {
    match tys.len() {
        0 => ("Unit".into(), "tt".into()),
        1 => (format!("mir::Tuple1({})", tys[0]), format!("mir::Tuple1::tuple1[{}]({})", tys[0], vals[0])),
        n => (format!("Tuple{n}({})", tys.join(", ")), format!("tuple{n}[{}]({})", tys.join(", "), vals.join(", "))),
    }
}
/// An output (one component is itself, else the tuple).
fn out_tuple(tys: &[String], vals: &[String]) -> (String, String) { if tys.len() == 1 { (tys[0].clone(), vals[0].clone()) } else { tuple(tys, vals) } }
fn tuple_pat(n: usize) -> &'static str { ["", "tuple1", "tuple2", "tuple3", "tuple4", "tuple5", "tuple6", "tuple7", "tuple8"].get(n).copied().unwrap_or("tupleN") }
/// Slot `i` of a frame with `nl` locals: the local's name `{l}<i>`, else the cell's `{c}<j>`.
fn slot(i: usize, nl: usize, l: &str, c: &str) -> String { if i < nl { format!("{l}{i}") } else { format!("{c}{}", i - nl) } }

// ----- MIR words --------------------------------------------------------------

/// An integer type: its bits' width and, when signed, its model ([`INTS`]).
fn int(t: &Ty) -> Option<(&'static str, Option<&'static str>)> {
    let Ty::Int(s, b) = t else { return None };
    INTS.iter().find(|r| (r.0, r.1) == (*s, *b)).map(|r| (r.2, s.then_some(r.3)))
}
pub(super) fn width(t: &Ty) -> Option<&'static str> { int(t).filter(|i| i.1.is_none()).map(|i| i.0) }
fn signed(t: &Ty) -> bool { int(t).is_some_and(|i| i.1.is_some()) }
fn wty(w: &str) -> String { if w == "usize" { "Usize".into() } else { w.to_uppercase() } }
fn bits_of(w: &str) -> u32 { w.trim_start_matches('u').parse().unwrap_or(64) }
/// The literal of the low bits of `v` at the word `w` (`255u8`).
fn word_lit(v: u128, w: &str) -> String { format!("{}{w}", v & (u128::MAX >> (128 - bits_of(w)))) }
/// The bits of `x` of an integer type `t`: (their width, the term).
fn bits(t: &Ty, x: &str) -> Option<(&'static str, String)> {
    Some(match int(t)? {
        (w, Some(st)) if !st.is_empty() => (w, format!("(match {x} : {st} as _ return {} with | {}(b) => b end)", wty(w), short(st))),
        (w, _) => (w, x.to_string()),
    })
}
/// The value of type `t` with bits `b`.
fn of_bits(t: &Ty, b: &str) -> String {
    if let Some((_, Some(st))) = int(t) && !st.is_empty() { format!("{st}::{}({b})", short(st)) } else { b.to_string() }
}
fn is_unit(t: &Ty) -> bool { matches!(t, Ty::Unit) || matches!(t, Ty::Tuple(v) if v.is_empty()) }
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
fn is_buffer(t: &Ty) -> bool { matches!(t, Ty::Ref(_, s) if matches!(&**s, Ty::Slice(e) if **e == Ty::Int(false, 8))) }
/// A reference to a cell or a nested `Option<&mut T>` (a referent holding a code).
fn holds_ref(m: &Sbmir, t: &Ty) -> bool { matches!(t, Ty::Ref(true, _)) || opt_mut(m, t).is_some() }
fn place_ty(f: &Fn, p: &Place) -> R<Ty> {
    let t = f.locals.get(p.local).map(|l| l.0.clone()).ok_or("a place's local out of range")?;
    p.proj.iter().try_fold(t, |t, pr| proj_ty(&t, pr))
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

// ----- types ------------------------------------------------------------------

impl<'a> Gen<'a> {
    /// Continues from `s` (its text is loaded: only new definitions are emitted).
    pub fn resume(m: &'a Sbmir, k: &'a KNames<'a>, s: GenState) -> Self { Gen { m, k, out: String::new(), s, busy: BTreeSet::new() } }

    pub fn state(&self) -> GenState { self.s.clone() }

    fn emit(&mut self, name: &str, text: String) {
        if self.s.emitted.insert(name.to_string()) {
            let _ = writeln!(self.out, "{text}");
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
            // a `core::arch` vector: its model representation (§20.9)
            Ty::Simd(p, lane, n) => super::arch::core_ty_text(super::arch::vector(p, lane, *n)?),
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
        if let Some(a) = self.s.adts.get(key) {
            return a.clone();
        }
        let r = self.adt_new(key);
        self.s.adts.insert(key.to_string(), r.clone());
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
        // core's slice iterator: the slice and the index of its next element
        if let Some(e) = super::slice_iter_elem(self.m, &Ty::Adt(key.to_string())) {
            return Ok(AdtL { opaque: true, ..plain(format!("Tuple2((Slice {}), Usize)", self.ty(&e)?)) });
        }
        if self.k.names.is_transparent(self.m, key) {
            return Ok(AdtL { newtype: true, ..plain(self.ty(&d.variants[0].fields[0].1)?) });
        }
        if let Some((_, tmpl)) = LIB_ADTS.iter().find(|(p, _)| lib_path(p, &d.path)) {
            let a: Vec<String> = args.into_iter().collect::<R<_>>()?;
            let ty = a.iter().enumerate().fold(tmpl.to_string(), |s, (i, x)| s.replace(&format!("${i}"), x));
            let base = ty.split('(').next().unwrap_or(&ty).to_string();
            return Ok(AdtL { kctors: self.kctors(&base, &d, base != "Option")?, params: if ty.contains('(') { a } else { vec![] }, ..plain(ty) });
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
        self.emit(&name, decl + " }");
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

    /// The one value of an enum all of whose variants but one have a field of
    /// an empty type (`!`, an enum without variants), that one without fields:
    /// `Option<Infallible>`'s `None` (`None`: another type).
    fn single_value(&mut self, t: &Ty) -> Option<R<String>> {
        let Ty::Adt(k) = t else { return None };
        let d = self.m.adts.get(k)?;
        let empty = |ft: &Ty| matches!(ft, Ty::Never) || matches!(ft, Ty::Adt(e) if self.m.adts.get(e).is_some_and(|de| de.is_enum && de.variants.is_empty()));
        let live: Vec<usize> = d.variants.iter().filter(|v| !v.fields.iter().any(|f| empty(&f.1))).map(|v| v.idx).collect();
        match live.as_slice() {
            [v] if d.variants.len() > 1 && d.variants[*v].fields.is_empty() => Some(self.ctor(k, *v, &[])),
            _ => None,
        }
    }

    /// Field `i` of variant `v` of `x : t`: an `Option(F)` term (`None` on
    /// another variant); with `set = Some(z)`, `x` with that field replaced
    /// by `z`: an `Option(T)` term.
    fn field(&mut self, t: &Ty, v: usize, i: usize, x: &str, set: Option<&str>) -> R<String> {
        // a closure's fields are its captures
        if let Ty::Closure(_, caps) = t {
            return self.field(caps, v, i, x, set);
        }
        let tt = self.ty(t)?;
        let bx = format!("{x}{}", if set.is_some() { "w" } else { "f" });
        match t {
            Ty::Tuple(ts) => {
                let tys: Vec<String> = ts.iter().map(|y| self.ty(y)).collect::<R<_>>()?;
                let ft = tys.get(i).ok_or("a field out of range")?.clone();
                let mut bs: Vec<String> = (0..ts.len()).map(|j| format!("{bx}{j}")).collect();
                let pat = format!("| {}({}) => ", tuple_pat(ts.len()), bs.join(", "));
                Ok(match set {
                    None => mat(x, &tt, &format!("Option({ft})"), &(pat + &some(&ft, &bs[i]))),
                    Some(z) => {
                        bs[i] = z.to_string();
                        mat(x, &tt, &format!("Option({tt})"), &(pat + &some(&tt, &tuple(&tys, &bs).1)))
                    }
                })
            }
            Ty::Adt(k) => {
                let (d, a) = (self.m.adts.get(k).cloned().ok_or("no ADT")?, self.adt(k)?);
                // the result's payload: the field's type, or the updated value's
                let rt = if set.is_some() { tt.clone() } else { self.ty(&d.variants.get(v).and_then(|vd| vd.fields.get(i)).ok_or("a field out of range")?.1)? };
                if a.newtype {
                    return Ok(some(&rt, set.unwrap_or(x)));
                }
                if a.opaque {
                    return Err(format!("a field of the model type `{}`", d.path));
                }
                let arms = self.arms(k, &bx, |g, vi, bs| match set {
                    _ if vi != v => Ok(none(&rt)),
                    None => Ok(some(&rt, &bs[i])),
                    Some(z) => {
                        let mut nb = bs.to_vec();
                        nb[i] = z.to_string();
                        Ok(some(&rt, &g.ctor(k, vi, &nb)?))
                    }
                })?;
                Ok(mat(x, &tt, &format!("Option({rt})"), &arms))
            }
            other => Err(format!("{} {other:?}", if set.is_some() { "a field update of" } else { "a field of" })),
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
    /// The output's components ([`LFn::out_parts`]).
    outs: Vec<String>,
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
    fn st(&self) -> String { format!("{}::St", self.p) }
    fn root(&self) -> String { format!("{}::Root", self.p) }
    fn rank(&self, b: usize) -> i64 { 2 * self.post[b] as i64 + 2 }
    fn stuck_out(&self) -> String { stuck(&self.out_ty) }
    fn panic_out(&self) -> String { panicked(&self.out_ty) }
    /// The block's state (`Option(St)`, `None`: stuck) handed to a jump.
    fn res_st(&self, os: &str) -> String { res_of(&self.st(), os) }
    /// Slot `i` of the state `s`.
    fn get(&self, i: usize) -> String { format!("{}::g{i} s", self.p) }
    /// `deref__<n>` / `write__<n>` (`f`) of the state `s` through the code `q`.
    fn through(&self, f: &str, n: &str, q: &str) -> String { format!("{p}::{f}__{n} s (rc::fst {r} {q}) (rc::snd {r} {q})", p = self.p, r = self.root()) }
    fn live(&self, l: usize) -> R<()> { if self.unmodeled.contains(&l) { Err(format!("local {l}, whose type is not modeled")) } else { Ok(()) } }
    /// The name of the `deref`/`write` functions to a target (generated after the blocks).
    fn need(&mut self, t: Target) -> String {
        let name = match &t {
            Target::Buf => "buf".to_string(),
            Target::Ty(ty) => tag(&format!("{ty:?}"), 60),
        };
        self.targets.insert(name.clone(), t);
        name
    }
}

impl<'a> Gen<'a> {
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
        if !buffer && parent.is_none() && holds_ref(self.m, &inner) {
            self.cells_of(&inner, param, Some(cells.len() - 1), cells)?;
        }
        Ok(())
    }

    /// The literal reading of `key` and of every function it calls (callees
    /// first).
    pub fn function(&mut self, key: &str) -> R<LFn> {
        if let Some(f) = self.s.fns.get(key) {
            return Ok(f.clone());
        }
        let f = self.m.fns.get(key).ok_or_else(|| format!("no MIR for `{key}`"))?.clone();
        if !f.has_body {
            return Err(format!("`{key}` has no MIR body"));
        }
        if !self.busy.insert(key.to_string()) {
            return Err(format!("`{key}` is mutually recursive with its caller (not read)"));
        }
        let r = self.read_fn(key, f);
        self.busy.remove(key);
        r
    }

    fn read_fn(&mut self, key: &str, f: Fn) -> R<LFn> {
        // callees first (a self-call is `rec`; a failing callee is `None` at its calls)
        for b in &f.blocks {
            if let Term::Call(Callee::Fn(k2), ..) = &b.term
                && k2 != key
                && self.m.fns.get(k2).is_some_and(|g| g.has_body && super::model_of(g).is_none())
            {
                let _ = self.function(k2);
            }
        }
        let id = format!("f{}", self.s.ids.len());
        self.s.ids.insert(key.to_string(), id.clone());
        let (p, nl) = (format!("L::{id}"), f.locals.len());
        let rc = format!("Tuple2({p}::Root, List(mir::Proj))");
        let mut cells = Vec::new();
        for i in 1..=f.argc.min(nl.saturating_sub(1)) {
            self.cells_of(&f.locals[i].0, i, None, &mut cells).map_err(|e| format!("the referent of parameter {i}: {e}"))?;
        }
        let tys: Vec<R<String>> = f.locals.iter().map(|(t, _)| self.ty(t)).collect();
        let unmodeled: BTreeSet<usize> = (0..nl).filter(|i| tys[*i].is_err()).collect();
        let local_tys: Vec<String> = tys.into_iter().map(|t| t.unwrap_or_else(|_| "mir::Unmodeled".into())).collect();
        let slot_tys: Vec<String> = local_tys.iter().chain(cells.iter().map(|c| &c.ty)).map(|t| t.replace("@RC@", &rc)).collect();
        let st = format!("{p}::St");
        let fields: Vec<String> = slot_tys.iter().enumerate().map(|(i, t)| format!("{} : Option({t})", slot(i, nl, "l", "c"))).collect();
        let roots: String = (0..slot_tys.len()).map(|i| format!(" | {}", slot(i, nl, "r", "rc"))).collect();
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
            return Err("too many blocks".into());
        }
        let (post, headers) = dfs_order(&f);
        let blk: String = (0..nb).map(|b| format!(" | b{b} | d{b}")).collect();
        self.emit(&format!("{p}::Blk"), format!("inductive {p}::Blk {{{blk} }}"));
        let ranks: String = (0..nb).map(|b| format!(" | b{b} => {}int | d{b} => {}int", 2 * post[b] + 2, 2 * post[b] + 1)).collect();
        self.emit(&format!("{p}::rank"), format!("def[prelude] {p}::rank : (b : {p}::Blk) -> Int := fun (b : {p}::Blk) => match b : {p}::Blk as _ return Int with{ranks} end"));
        // the output: every cell's final value (an optional one as an
        // `Option`), then the return place unless it is `()`
        let mut outs: Vec<String> = cells.iter().zip(&slot_tys[nl..]).map(|(c, t)| if c.optional { format!("Option({t})") } else { t.clone() }).collect();
        if !is_unit(&f.locals[0].0) {
            outs.push(slot_tys[0].clone());
        }
        let out_ty = out_tuple(&outs, &outs).0;
        let lf = LFn { key: key.to_string(), id, run: format!("{p}::run"), st: st.clone(), blk: format!("{p}::Blk"), out_ty: out_ty.clone(), out_parts: outs.clone(), local_tys, cells: cells.clone(), headers: headers.clone(), faults: vec![], panics: vec![], diverging: vec![] };
        self.s.fns.insert(key.to_string(), lf.clone());
        let mut fx = FnCx { p: p.clone(), rc, f: f.clone(), key: key.to_string(), slot_tys, unmodeled, nl, cells, out_ty: out_ty.clone(), outs, post, headers, targets: BTreeMap::new(), cur: String::new() };
        // a block every path of which panics ([`must_panic`], trusted) is
        // `Panic`; another from which every path diverges (`cfg.rs`, not
        // trusted: an `unreachable`, an abort, a call that does not return)
        // is stuck; both without reading their code (a panic's message)
        let (mut arms, mut faults) = (Vec::new(), Vec::new());
        let mut memo = BTreeMap::new();
        let panics: Vec<usize> = (0..nb).filter(|b| must_panic(&f, *b, &mut Vec::new(), &mut memo)).collect();
        let diverging: Vec<usize> = panic_blocks(&f).into_iter().filter(|b| !panics.contains(b)).collect();
        for b in 0..nb {
            let codes = if panics.contains(&b) {
                [Ok(fx.panic_out()), Ok(fx.panic_out())]
            } else if diverging.contains(&b) {
                [Ok(fx.stuck_out()), Ok(fx.stuck_out())]
            } else {
                [self.block(&mut fx, b), self.dispatcher(&mut fx, b)]
            };
            for (pre, code) in ["b", "d"].into_iter().zip(codes) {
                let code = code.unwrap_or_else(|e| {
                    faults.push(format!("bb{b}{}: {e}", if pre == "d" { " (switch)" } else { "" }));
                    fx.stuck_out()
                });
                arms.push(format!("| {pre}{b} => {code}"));
            }
        }
        for (name, t) in fx.targets.clone() {
            self.deref_fns(&fx, &name, &t)?;
        }
        let run = format!(
            "def[exec] {p}::run : (fuel : List(Unit)) -> (b : {p}::Blk) -> (os : mir::Res({st})) -> mir::Res({out_ty}) :=\n  fun (fuel : List(Unit)) (b : {p}::Blk) (os : mir::Res({st})) =>\n    match os : mir::Res({st}) as _ return mir::Res({out_ty}) with\n    | Stuck => mir::Res::Stuck[{out_ty}]\n    | Ret(s) => match b : {p}::Blk as yb return mir::Res({out_ty}) using .eb with\n      {}\n      end\n    | Panic => mir::Res::Panic[{out_ty}]\n    end\n  measure (#iadd(#imul(seq::len Unit fuel, {RANK_MULT}int), {p}::rank b))",
            arms.join("\n      ")
        );
        self.emit(&format!("{p}::run"), run.replace("@RC@", &fx.rc));
        let lf = LFn { faults, panics, diverging, ..lf };
        self.s.fns.insert(key.to_string(), lf.clone());
        Ok(lf)
    }

    /// Block `b`: its statements' bind chain, then its terminator.
    fn block(&mut self, fx: &mut FnCx, b: usize) -> R<String> {
        fx.cur = format!("b{b}");
        let (st, bl) = (fx.st(), fx.f.blocks[b].clone());
        let (mut code, mut cur) = (String::new(), some(&st, "s"));
        for (i, s) in bl.stmts.iter().enumerate() {
            if let Some(step) = self.stmt(fx, s).map_err(|e| format!("statement {i} `{}`: {e}", show(s)))? {
                let _ = write!(code, "let os{i} : Option({st}) = {}; ", bind(&st, &st, &cur, "s", &step));
                cur = format!("os{i}");
            }
        }
        let term = self.terminator(fx, b, &cur).map_err(|e| format!("terminator `{}`: {e}", show(&bl.term)))?;
        Ok(code + &term)
    }

    /// A jump to block `to` with the state `os` (a `mir::Res(St)`): free
    /// when the rank decreases, else (a loop header) it consumes one unit of
    /// fuel.
    fn jump(&self, fx: &FnCx, from_rank: i64, to: usize, os: &str) -> String {
        let tr = fx.rank(to);
        if tr < from_rank && !fx.headers.contains(&to) { format!("rec(fuel, {}::Blk::b{to}, {os}; {})", fx.p, decrease(&fx.p, &fx.cur, tr, from_rank, false)) } else { fuel_jump(fx, from_rank, to, os) }
    }

    /// `Goto`, `Return`, `Assert`, `SwitchInt` (to its dispatcher), `Drop`,
    /// `Call` (`os`: the block's state after its statements, an
    /// `Option(St)`); `Unreachable`/`Resume`/`Abort` are stuck.
    fn terminator(&mut self, fx: &mut FnCx, b: usize, os: &str) -> R<String> {
        let (st, rb) = (fx.st(), fx.rank(b));
        Ok(match &fx.f.blocks[b].term.clone() {
            // (a drop without glue does nothing)
            Term::Goto(t) | Term::Drop(_, false, t) => self.jump(fx, rb, *t, &fx.res_st(os)),
            Term::Return => {
                // `Ret((cells.., return place))`: each read (an optional cell
                // as an `Option`), stuck when one is uninitialized
                let mut gets: Vec<String> = fx.cells.iter().enumerate().map(|(j, c)| if c.optional { some(&fx.outs[j], &fx.get(fx.nl + j)) } else { fx.get(fx.nl + j) }).collect();
                if !is_unit(&fx.f.locals[0].0) {
                    fx.live(0)?;
                    gets.push(fx.get(0));
                }
                let vars: Vec<String> = (0..gets.len()).map(|i| format!("o{i}")).collect();
                bindr(&st, &fx.out_ty, os, "s", &bindsr(&gets, &fx.outs, &fx.out_ty, "o", ret(&fx.out_ty, &out_tuple(&fx.outs, &vars).1)))
            }
            Term::Unreachable | Term::Resume | Term::Abort => return Err("unreachable, an unwind or an abort".into()),
            // a drop with glue: nothing for a variant without glue (`no-glue`), else not read
            Term::Drop(pl, true, t) => {
                let pt = place_ty(&fx.f, pl)?;
                let Ty::Adt(k) = &pt else { return Err("a drop with drop glue".into()) };
                let (d, a) = (self.m.adts.get(k).cloned().ok_or("no ADT")?, self.adt(k)?);
                if a.newtype || a.opaque || !d.variants.iter().any(|v| v.no_glue) {
                    return Err(format!("a drop of `{}` with drop glue", d.path));
                }
                let ptt = self.ty(&pt)?;
                let arms = self.arms(k, "y", |_, vi, _| Ok(if d.variants[vi].no_glue { some(&st, "s") } else { none(&st) }))?;
                let v = self.read(fx, pl)?;
                let dropped = bind(&st, &st, os, "s", &bind(&ptt, &st, &v, "x", &format!("match x : {ptt} as _ return Option({st}) with{arms} end")));
                self.jump(fx, rb, *t, &fx.res_st(&dropped))
            }
            // `Assert(c, expected)`: on to the target when `c == expected`,
            // else a panic where the assertion's kind panics, stuck where its
            // failure aborts (reading `c` may be stuck)
            Term::Assert(c, expected, kind, t) => {
                let cv = self.operand(fx, c)?;
                let cond = if *expected { cv } else { map("Bool", "Bool", &cv, "c0", "bool::not c0") };
                let check = if assert_panics(kind) { "mir::check" } else { "mir::check_or_stuck" };
                let checked = bindr(&st, &st, os, "s", &bindr("Bool", &st, &cond, "c", &format!("{check} {st} c s")));
                self.jump(fx, rb, *t, &checked)
            }
            Term::Switch(..) => format!("rec(fuel, {}::Blk::d{b}, {}; {})", fx.p, fx.res_st(os), decrease(&fx.p, &fx.cur, rb - 1, rb, false)),
            Term::Call(callee, args, dest, target) => self.call(fx, b, callee, args, dest, *target, os)?,
            Term::Unsupported(s) => return Err(format!("the terminator {s}")),
        })
    }

    /// The dispatcher `d<b>` of a `SwitchInt`: the operand compared with each
    /// arm's value, then the jump (stuck when `b` is not a switch).
    fn dispatcher(&mut self, fx: &mut FnCx, b: usize) -> R<String> {
        fx.cur = format!("d{b}");
        let Term::Switch(op, arms, otherwise) = fx.f.blocks[b].term.clone() else { return Ok(fx.stuck_out()) };
        let (ro, rd, t) = (format!("mir::Res({})", fx.out_ty), fx.rank(b) - 1, op_ty(&fx.f, &op)?);
        let v = self.operand(fx, &op)?;
        let jump = |tg: usize| self.jump(fx, rd, tg, &ret(&fx.st(), "s"));
        let body = if t == Ty::Bool {
            let pick = |k: u128| arms.iter().find(|a| a.0 == k).map(|a| a.1).unwrap_or(otherwise);
            mat("x", "Bool", &ro, &format!("| false => {} | true => {}", jump(pick(0)), jump(pick(1))))
        } else {
            let (w, xb) = bits(&t, "x").ok_or_else(|| format!("a switch on {t:?}"))?;
            arms.iter().rev().fold(jump(otherwise), |e, (val, tg)| mat(&format!("#eq_{w}({xb}, {})", word_lit(*val, w)), "Bool", &ro, &format!("| false => {e} | true => {}", jump(*tg))))
        };
        Ok(bindr(&self.ty(&t)?, &fx.out_ty, &v, "x", &body))
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
                Some(bind(&self.ty(&dt)?, &st, &v, "v", &self.write(fx, pl, "v")?))
            }
            Stmt::Unsupported(x) => return Err(format!("the statement {x}")),
        })
    }

    /// An operand as an `Option(T)` term over `s` (`copy`/`move` read the
    /// place; a move leaves the slot: later reads do not occur in borrow-checked MIR).
    fn operand(&mut self, fx: &mut FnCx, o: &Operand) -> R<String> {
        match o {
            Operand::Copy(p) | Operand::Move(p) => self.read(fx, p),
            Operand::Const(c) => Ok(some(&self.ty(&const_ty(c.value())?)?, &self.konst(c.value())?)),
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
            Const::Int(t, v) => of_bits(t, &word_lit(*v as u128, bits(t, "").ok_or_else(|| format!("an integer constant of {t:?}"))?.0)),
            Const::Zst(Ty::Unit | Ty::Closure(..) | Ty::FnDef(..)) => "tt".into(),
            // a zero-sized ADT value: the one variant of a type with one variant
            Const::Zst(Ty::Adt(k)) if self.m.adts.get(k).is_some_and(|d| d.variants.len() == 1) => self.ctor(k, 0, &[])?,
            // the one value of a type whose other variants are empty (`Option<Infallible>`'s `None`)
            Const::Zst(t @ Ty::Adt(_)) if let Some(v) = self.single_value(t) => v?,
            Const::Agg(t, v, fs) => {
                let args: Vec<String> = fs.iter().map(|x| self.konst(x.value())).collect::<R<_>>()?;
                match t {
                    Ty::Adt(k) => self.ctor(k, *v, &args)?,
                    Ty::Tuple(ts) => tuple(&ts.iter().map(|x| self.ty(x)).collect::<R<Vec<_>>>()?, &args).1,
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
        fx.live(pl.local)?;
        let mut t = fx.f.locals[pl.local].0.clone();
        let mut cur = PlaceC::Static(pl.local, vec![]);
        for pr in &pl.proj {
            match (pr, &t) {
                (Proj::Deref, Ty::Ref(false, inner)) => t = (**inner).clone(),
                (Proj::Deref, Ty::Ref(true, _)) => cur = PlaceC::Dyn(self.read_c(fx, &cur)?, proj_ty(&t, pr)?),
                (Proj::Field(..) | Proj::Downcast(_) | Proj::Index(_), _) => {
                    let nt = proj_ty(&t, pr)?;
                    cur = match cur {
                        PlaceC::Static(k, mut ps) => {
                            ps.push(pr.clone());
                            PlaceC::Static(k, ps)
                        }
                        // the code extended by the projection
                        PlaceC::Dyn(c, _) => {
                            let (wrap, step) = self.proj_code(fx, pr)?;
                            let ext = some(&fx.rc, &code_app(&fx.root(), "q", &format!("Cons[mir::Proj]({step}, Nil[mir::Proj])")));
                            PlaceC::Dyn(bind(&fx.rc, &fx.rc, &c, "q", &wrap.replace("@K@", &ext)), nt.clone())
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
                fx.live(*l)?;
                (bind("Usize", &fx.rc, &fx.get(*l), &format!("i{l}"), "@K@"), format!("mir::Proj::PIndex(i{l})"))
            }
            other => return Err(format!("the projection {other:?}")),
        })
    }

    /// Reads a compiled place: an `Option(T)` term over `s`.
    fn read_c(&mut self, fx: &mut FnCx, pc: &PlaceC) -> R<String> {
        match pc {
            PlaceC::Static(k, ps) if ps.is_empty() => Ok(fx.get(*k)),
            PlaceC::Static(k, ps) => {
                let lt = fx.f.locals[*k].0.clone();
                let ltt = self.ty(&lt)?;
                let (get, rt) = self.static_get(fx, &lt, ps, "x")?;
                Ok(bind(&ltt, &self.ty(&rt)?, &fx.get(*k), "x", &get))
            }
            PlaceC::Dyn(code, ty) => {
                let tt = self.ty(ty)?;
                let n = fx.need(Target::Ty(ty.clone()));
                Ok(bind(&fx.rc, &tt, code, "q", &fx.through("deref", &n, "q")))
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
            fx.live(pl.local)?;
            return Ok(some("Unit", "tt"));
        }
        // so is a type whose one variant without an empty field has no fields
        // (`Option<Infallible>`: `?`'s residual, read unassigned)
        if let Some(v) = self.single_value(&pt) {
            fx.live(pl.local)?;
            return Ok(some(&self.ty(&pt)?, &v?));
        }
        let pc = self.place(fx, pl)?;
        self.read_c(fx, &pc)
    }

    /// Writes the variable `v` into a place: an `Option(St)` term over `s`.
    fn write(&mut self, fx: &mut FnCx, pl: &Place, v: &str) -> R<String> {
        let (st, p) = (fx.st(), fx.p.clone());
        Ok(match self.place(fx, pl)? {
            PlaceC::Static(k, ps) if ps.is_empty() => some(&st, &format!("{p}::s{k} s {v}")),
            PlaceC::Static(k, ps) => {
                let lt = fx.f.locals[k].0.clone();
                let ltt = self.ty(&lt)?;
                let set = self.static_set(fx, &lt, &ps, "x", v)?;
                bind(&ltt, &st, &fx.get(k), "x", &map(&ltt, &st, &set, "x2", &format!("{p}::s{k} s x2")))
            }
            PlaceC::Dyn(code, ty) => {
                let n = fx.need(Target::Ty(ty));
                bind(&fx.rc, &st, &code, "q", &format!("{} {v}", fx.through("write", &n, "q")))
            }
        })
    }

    /// `x.ps` (static projections): an `Option(T)` term, with `T`.
    fn static_get(&mut self, fx: &mut FnCx, t: &Ty, ps: &[Proj], x: &str) -> R<(String, Ty)> {
        if let (Ty::Ref(false, inner), Some(_)) = (t, ps.first()) {
            return self.static_get(fx, inner, ps, x);
        }
        let Some((first, rest)) = ps.split_first() else { return Ok((some(&self.ty(t)?, x), t.clone())) };
        let y = format!("{x}y");
        let (fe, ft, rest) = match (first, rest.split_first()) {
            (Proj::Field(i, ft), _) => (self.field(t, 0, *i, x, None)?, ft.clone(), rest),
            (Proj::Downcast(v), Some((Proj::Field(i, ft), rest2))) => (self.field(t, *v, *i, x, None)?, ft.clone(), rest2),
            (Proj::Index(l), _) => {
                fx.live(*l)?;
                let (e, getter) = match t {
                    Ty::Array(e, n) => ((**e).clone(), format!("mir::array_get {} {n}usize {x} i", self.ty(e)?)),
                    Ty::Slice(e) => ((**e).clone(), format!("slice::get {} {x} i", self.ty(e)?)),
                    _ => return Err(format!("an index of {t:?}")),
                };
                let (inner, rt) = self.static_get(fx, &e, rest, &y)?;
                let (et, rtt) = (self.ty(&e)?, self.ty(&rt)?);
                return Ok((bind("Usize", &rtt, &fx.get(*l), "i", &bind(&et, &rtt, &getter, &y, &inner)), rt));
            }
            (pr, _) => return Err(format!("the projection {pr:?} (a downcast must be followed by a field)")),
        };
        let (inner, rt) = self.static_get(fx, &ft, rest, &y)?;
        let (ftt, rtt) = (self.ty(&ft)?, self.ty(&rt)?);
        Ok((bind(&ftt, &rtt, &fe, &y, &inner), rt))
    }

    /// `x.ps = v` (static projections): the updated `x` as an `Option(T)` term.
    fn static_set(&mut self, fx: &mut FnCx, t: &Ty, ps: &[Proj], x: &str, v: &str) -> R<String> {
        let tt = self.ty(t)?;
        let Some((first, rest)) = ps.split_first() else { return Ok(some(&tt, v)) };
        let (y, z) = (format!("{x}y"), format!("{x}z"));
        let (vi, i, ft, rest) = match (first, rest.split_first()) {
            (Proj::Field(i, ft), _) => (0, *i, ft.clone(), rest),
            (Proj::Downcast(vi), Some((Proj::Field(i, ft), rest2))) => (*vi, *i, ft.clone(), rest2),
            (Proj::Index(l), _) => {
                fx.live(*l)?;
                let Ty::Array(e, n) = t else { return Err(format!("an index update of {t:?}")) };
                let et = self.ty(e)?;
                let inner = self.static_set(fx, e, rest, &y, v)?;
                let set = bind(&et, &tt, &format!("mir::array_get {et} {n}usize {x} i"), &y, &bind(&et, &tt, &inner, &z, &format!("mir::array_set {et} {n}usize {x} i {z}")));
                return Ok(bind("Usize", &tt, &fx.get(*l), "i", &set));
            }
            (pr, _) => return Err(format!("the projection {pr:?} (a downcast must be followed by a field)")),
        };
        let fe = self.field(t, vi, i, x, None)?;
        let ftt = self.ty(&ft)?;
        let inner = self.static_set(fx, &ft, rest, &y, v)?;
        let rebuilt = self.field(t, vi, i, x, Some(&z))?;
        Ok(bind(&ftt, &tt, &fe, &y, &bind(&ftt, &tt, &inner, &z, &rebuilt)))
    }

    /// `deref__<n>`/`write__<n>` through a code: per root (a local or a
    /// cell), the path followed in the root's current value. A buffer cell
    /// is read and written whole (`Target::Buf`).
    fn deref_fns(&mut self, fx: &FnCx, n: &str, t: &Target) -> R<()> {
        let (p, st, root) = (fx.p.clone(), fx.st(), fx.root());
        let tt = match t {
            Target::Buf => "List(U8)".to_string(),
            Target::Ty(ty) => self.ty(ty)?,
        };
        let (mut darms, mut warms) = (String::new(), String::new());
        for (i, rt) in fx.slot_tys.iter().enumerate() {
            let buf_cell = i >= fx.nl && is_buffer(&fx.cells[i - fx.nl].mir_ty);
            let mt = if i < fx.nl { fx.f.locals[i].0.clone() } else { fx.cells[i - fx.nl].mir_ty.clone() };
            let (d, w) = match t {
                // a buffer cell: read and written whole
                Target::Buf if buf_cell => (
                    bind(rt, &tt, &fx.get(i), "x", &mat("path", "List(mir::Proj)", &format!("Option({tt})"), &format!("| Nil => {} | Cons(h, t) => {}", some(&tt, "x"), none(&tt)))),
                    mat("path", "List(mir::Proj)", &format!("Option({st})"), &format!("| Nil => {} | Cons(h, t) => {}", some(&st, &format!("{p}::s{i} s v")), none(&st))),
                ),
                Target::Ty(ty) if !buf_cell && !fx.unmodeled.contains(&i) => match self.follow(fx, &mt, ty)? {
                    Some((f, u)) => (bind(rt, &tt, &fx.get(i), "x", &format!("{f} x path")), bind(rt, &st, &fx.get(i), "x", &map(rt, &st, &format!("{u} x path v"), "x2", &format!("{p}::s{i} s x2")))),
                    None => (none(&tt), none(&st)),
                },
                _ => (none(&tt), none(&st)),
            };
            let _ = write!(darms, " | {} => {d}", slot(i, fx.nl, "r", "rc"));
            let _ = write!(warms, " | {} => {w}", slot(i, fx.nl, "r", "rc"));
        }
        self.emit(&format!("{p}::deref__{n}"), format!("def[prelude] {p}::deref__{n} : (s : {st}) -> (r : {root}) -> (path : List(mir::Proj)) -> Option({tt}) := fun (s : {st}) (r : {root}) (path : List(mir::Proj)) => match r : {root} as _ return Option({tt}) with{darms} end").replace("@RC@", &fx.rc));
        self.emit(&format!("{p}::write__{n}"), format!("def[prelude] {p}::write__{n} : (s : {st}) -> (r : {root}) -> (path : List(mir::Proj)) -> (v : {tt}) -> Option({st}) := fun (s : {st}) (r : {root}) (path : List(mir::Proj)) (v : {tt}) => match r : {root} as _ return Option({st}) with{warms} end").replace("@RC@", &fx.rc));
        Ok(())
    }

    /// `follow__A__T : A -> path -> Option(T)` and `update__A__T : A -> path
    /// -> T -> Option(A)` when `T` can occur in `A`: `PField(i)` of a struct
    /// or tuple, `PDown(v)` then `PField(i)` of an enum, `PIndex(i)` of an array.
    /// (Each is generated as the pair `[follow, update]`.)
    fn follow(&mut self, fx: &FnCx, a: &Ty, t: &Ty) -> R<Option<(String, String)>> {
        if !occurs(self.m, t, a, 0) {
            return Ok(None);
        }
        let tg = tag(&format!("{}__{}", tag(&format!("{a:?}"), 60), tag(&format!("{t:?}"), 60)), 80);
        let (fname, uname) = (format!("{}::follow__{tg}", fx.p), format!("{}::update__{tg}", fx.p));
        if !self.s.emitted.insert(fname.clone()) {
            return Ok(Some((fname, uname)));
        }
        let (att, tt) = (self.ty(a)?, self.ty(t)?);
        let (r, nn) = ([format!("Option({tt})"), format!("Option({att})")], [none(&tt), none(&att)]);
        // the steps through field `i` of variant `v` (the path's rest is `rest`)
        let via = |g: &mut Self, v: usize, fields: &[Ty], rest: &str| -> R<[String; 2]> {
            let mut cs = [Vec::new(), Vec::new()];
            for (i, ft) in fields.iter().enumerate() {
                if let Some((f2, u2)) = g.follow(fx, ft, t)? {
                    let fe = g.field(a, v, i, "x", None)?;
                    let ftt = g.ty(ft)?;
                    let rebuilt = g.field(a, v, i, "x", Some("z"))?;
                    cs[0].push((i, bind(&ftt, &tt, &fe, "y", &format!("{f2} y {rest}"))));
                    cs[1].push((i, bind(&ftt, &att, &fe, "y", &bind(&ftt, &att, &format!("{u2} y {rest} v"), "z", &rebuilt))));
                }
            }
            Ok([0, 1].map(|j| select("i", &cs[j], &r[j], &nn[j])))
        };
        let (mut sel, mut down, mut idx) = (nn.clone(), nn.clone(), nn.clone());
        match a {
            Ty::Tuple(ts) => sel = via(self, 0, ts, "rest")?,
            Ty::Adt(k) if !self.adt(k)?.opaque && !self.adt(k)?.newtype => {
                let d = self.m.adts.get(k).cloned().ok_or("no ADT")?;
                if d.is_enum {
                    // `PDown(v)` then `PField(i)`: the field step under the variant
                    let mut cs = [Vec::new(), Vec::new()];
                    for (_, vi) in self.adt(k)?.kctors {
                        let fields: Vec<Ty> = d.variants[vi].fields.iter().map(|f| f.1.clone()).collect();
                        let fu = via(self, vi, &fields, "rest2")?;
                        for (j, c) in cs.iter_mut().enumerate() {
                            c.push((vi, mat("rest", "List(mir::Proj)", &r[j], &format!("| Nil => {} | Cons(h2, rest2) => match h2 : mir::Proj as _ return {} with | PField(i) => {} | PDown(v1) => {} | PIndex(i1) => {} end", nn[j], r[j], fu[j], nn[j], nn[j]))));
                        }
                    }
                    down = [0, 1].map(|j| select("v0", &cs[j], &r[j], &nn[j]));
                } else if let Some(v) = d.variants.first() {
                    sel = via(self, 0, &v.fields.iter().map(|f| f.1.clone()).collect::<Vec<Ty>>(), "rest")?;
                }
            }
            Ty::Array(e, n) => {
                if let Some((f2, u2)) = self.follow(fx, e, t)? {
                    let et = self.ty(e)?;
                    let get = format!("mir::array_get {et} {n}usize x i0");
                    idx = [bind(&et, &tt, &get, "y", &format!("{f2} y rest")), bind(&et, &att, &get, "y", &bind(&et, &att, &format!("{u2} y rest v"), "z", &format!("mir::array_set {et} {n}usize x i0 z")))];
                }
            }
            _ => {}
        }
        let here = if a == t { [some(&tt, "x"), some(&att, "v")] } else { nn.clone() };
        let body = |j: usize| mat("path", "List(mir::Proj)", &r[j], &format!("| Nil => {} | Cons(h, rest) => match h : mir::Proj as _ return {} with | PField(i) => {} | PDown(v0) => {} | PIndex(i0) => {} end", here[j], r[j], sel[j], down[j], idx[j]));
        let _ = writeln!(self.out, "{}", format!("def[prelude] {fname} : (x : {att}) -> (path : List(mir::Proj)) -> {} := fun (x : {att}) (path : List(mir::Proj)) => {}", r[0], body(0)).replace("@RC@", &fx.rc));
        self.emit(&uname, format!("def[prelude] {uname} : (x : {att}) -> (path : List(mir::Proj)) -> (v : {tt}) -> {} := fun (x : {att}) (path : List(mir::Proj)) (v : {tt}) => {}", r[1], body(1)).replace("@RC@", &fx.rc));
        Ok(Some((fname, uname)))
    }
}

// ----- panics -----------------------------------------------------------------

/// The panic functions, by their library path under `std::` or `core::`
/// with generic arguments dropped ([`lib_fn`]): functions returning `!`
/// that panic (start unwinding) whatever their arguments, which are only
/// the panic's message. A call of another function returning `!` (the
/// aborting `panic_nounwind*`, `process::exit`, a crate's own) is stuck.
pub const PANIC_FNS: &[&str] = &[
    "panicking::panic",
    "panicking::panic_fmt",
    "panicking::panic_display",
    "panicking::panic_explicit",
    "panicking::panic_str_2015",
    "panicking::unreachable_display",
    "panicking::assert_failed",
    "panicking::panic_bounds_check",
    "panicking::begin_panic",
    // (std's re-exports, the paths `panic!` and `assert!` call through)
    "rt::panic_fmt",
    "rt::panic_display",
    "rt::begin_panic",
    "option::unwrap_failed",
    "option::expect_failed",
    "result::unwrap_failed",
    "slice::index::slice_start_index_len_fail",
    "slice::index::slice_end_index_len_fail",
    "slice::index::slice_index_order_fail",
];

/// The constructors of a panic's message (`fmt::Arguments` and its
/// arguments), by library path as in [`PANIC_FNS`]: a call returns,
/// without a panic or undefined behaviour, whatever its arguments.
pub const PANIC_MSG_FNS: &[&str] = &[
    "fmt::Arguments::<'_>::from_str",
    "fmt::Arguments::<'_>::new_const",
    "fmt::Arguments::<'_>::new_v1",
    "fmt::Arguments::<'_>::new_v1_formatted",
    "fmt::rt::Argument::<'_>::new_display",
    "fmt::rt::Argument::<'_>::new_debug",
];

/// A MIR instance key of core or std (`core::panicking::assert_failed::<u64,
/// u64>`) as its path below the crate, its final generic arguments dropped
/// (`panicking::assert_failed`); `None` for any other crate's. (rustc writes
/// no `::<` inside a type argument; a key cut wrongly matches no table.)
pub fn lib_fn(key: &str) -> Option<&str> {
    let p = key.strip_prefix("std::").or_else(|| key.strip_prefix("core::"))?;
    Some(if p.ends_with('>') { p.rsplit_once("::<").map_or(p, |x| x.0) } else { p })
}

/// The kinds of `Assert` whose failure panics, by the names `mirx` prints
/// for rustc's `AssertMessage` (TRUSTED): an overflow (arithmetic or shift),
/// a negation's overflow, a bounds check, a division or remainder by zero.
/// Every other kind (`other`: a misaligned or null pointer dereference, an
/// invalid enum construction, whose failure aborts the process; a kind the
/// parse does not name) is read as stuck where it fails, and a panic's
/// path ([`must_panic`]) may not run it.
pub const PANIC_ASSERT_KINDS: &[&str] = &["overflow", "overflow-neg", "bounds", "div-zero", "rem-zero"];

/// Whether a failed `Assert` of kind `kind` panics ([`PANIC_ASSERT_KINDS`]).
pub fn assert_panics(kind: &str) -> bool {
    PANIC_ASSERT_KINDS.contains(&kind)
}

/// Whether every path from block `b` of `f` panics (TRUSTED: such a block
/// is read as `Panic` without reading its code, its message's
/// construction; docs/mir-lift.md §20.4 "Panics"). Every path is acyclic
/// and ends in a call of a panic function ([`PANIC_FNS`]); on the way it
/// runs only statements that cannot be undefined behaviour
/// ([`panic_path_ok`]), `Goto`, `SwitchInt` (every target panics),
/// `Assert` of a kind whose failure is a panic too ([`assert_panics`]),
/// drops without glue and calls of message constructors
/// ([`PANIC_MSG_FNS`]), each of which returns. So the
/// MIR's execution from `b` panics, in every state the function's own
/// execution reaches `b` in (borrow-checked MIR: a place's index passed its
/// bounds check). (`path`: the blocks on the current path; `memo`: the
/// answers so far, which do not depend on the path: a block that reaches
/// the path again is on a cycle.)
pub fn must_panic(f: &Fn, b: usize, path: &mut Vec<usize>, memo: &mut BTreeMap<usize, bool>) -> bool {
    if let Some(r) = memo.get(&b) {
        return *r;
    }
    let Some(bl) = f.blocks.get(b) else { return false };
    if path.contains(&b) {
        return false;
    }
    let lib = |k: &str, table: &[&str]| lib_fn(k).is_some_and(|p| table.contains(&p));
    let next: Option<Vec<usize>> = if !bl.stmts.iter().all(|s| panic_path_ok(f, s)) {
        None
    } else {
        match &bl.term {
            Term::Call(Callee::Diverge(k), args, _, _) if lib(k, PANIC_FNS) && args.iter().all(|a| operand_ok(f, a)) => Some(vec![]),
            Term::Goto(t) | Term::Drop(_, false, t) => Some(vec![*t]),
            Term::Assert(c, _, kind, t) if operand_ok(f, c) && assert_panics(kind) => Some(vec![*t]),
            Term::Switch(o, arms, other) if operand_ok(f, o) => Some(arms.iter().map(|a| a.1).chain([*other]).collect()),
            Term::Call(Callee::Fn(k), args, dest, Some(t)) if lib(k, PANIC_MSG_FNS) && args.iter().all(|a| operand_ok(f, a)) && place_ok(f, dest) => Some(vec![*t]),
            _ => None,
        }
    };
    let r = match next {
        None => false,
        Some(ts) => {
            path.push(b);
            let r = ts.iter().all(|t| must_panic(f, *t, path, memo));
            path.pop();
            r
        }
    };
    memo.insert(b, r);
    r
}

/// The operators and casts a panic's path may run ([`panic_path_ok`]), by
/// the parse's names: none can be undefined behaviour (MIR's `add`, `sub`,
/// `mul` and `neg` wrap, its shifts mask the amount). Not the unchecked
/// operators, `div`, `rem`, `offset`, `transmute`, nor any the parse does
/// not name.
const PANIC_PATH_BIN: &[&str] = &["add", "sub", "mul", "xor", "and", "or", "shl", "shr", "eq", "lt", "le", "ne", "ge", "gt", "cmp"];
const PANIC_PATH_UN: &[&str] = &["not", "neg", "ptr-metadata"];
const PANIC_PATH_CASTS: &[&str] = &["int-to-int", "unsize", "reify-fn-pointer"];

/// A statement a panic's path may run ([`must_panic`]): an assignment that
/// cannot be undefined behaviour (no `Assume`; operators and casts only from
/// the lists above; places only through references; nothing the parse does
/// not know).
fn panic_path_ok(f: &Fn, s: &Stmt) -> bool {
    let Stmt::Assign(pl, rv, _) = s else { return false };
    let ops_ok = |ops: &[&Operand]| ops.iter().all(|o| operand_ok(f, o));
    place_ok(f, pl)
        && match rv {
            Rvalue::Use(o) | Rvalue::Repeat(o, _) => ops_ok(&[o]),
            Rvalue::Un(op, o) => PANIC_PATH_UN.contains(&op.as_str()) && ops_ok(&[o]),
            Rvalue::Bin(op, a, b) => PANIC_PATH_BIN.contains(&op.as_str()) && ops_ok(&[a, b]),
            Rvalue::Checked(_, a, b) => ops_ok(&[a, b]),
            Rvalue::Cast(kind, o, _) => PANIC_PATH_CASTS.contains(&kind.as_str()) && ops_ok(&[o]),
            Rvalue::Ref(_, q) | Rvalue::Discr(q) | Rvalue::Len(q) => place_ok(f, q),
            Rvalue::Agg(_, ops) => ops.iter().all(|o| operand_ok(f, o)),
            Rvalue::Unsupported(_) => false,
        }
}

/// An operand a panic's path may read: a constant, or a place through
/// references only.
fn operand_ok(f: &Fn, o: &Operand) -> bool {
    match o {
        Operand::Copy(p) | Operand::Move(p) => place_ok(f, p),
        Operand::Const(_) | Operand::RuntimeChecks(_) => true,
    }
}

/// A place whose every `Deref` is of a reference (never a raw pointer) and
/// whose projections the parse knows.
fn place_ok(f: &Fn, p: &Place) -> bool {
    let Some(mut t) = f.locals.get(p.local).map(|l| l.0.clone()) else { return false };
    for pr in &p.proj {
        if matches!(pr, Proj::Unsupported(_)) || (matches!(pr, Proj::Deref) && !matches!(t, Ty::Ref(..))) {
            return false;
        }
        match proj_ty(&t, pr) {
            Ok(n) => t = n,
            Err(_) => return false,
        }
    }
    true
}

// ----- rvalues ----------------------------------------------------------------

/// Binary operators on words (`BinOp`): the L term over the bits `a`, `b`
/// (`{s}`: a shift amount as a `u32`) of unsigned operands, the term over
/// signed bits (two's complement: `=` the same term; `""`: not read, the
/// bits' meaning is not the signed one), the result (`w` the operands' type,
/// `b` `Bool`, `o` `Ordering`), and whether it is total (else `Option`-valued).
const BINOPS: &[(&str, &str, &str, char, bool)] = &[
    ("add", "#wadd_{w}({a}, {b})", "=", 'w', true),
    ("sub", "#wsub_{w}({a}, {b})", "=", 'w', true),
    ("mul", "#wmul_{w}({a}, {b})", "=", 'w', true),
    ("add-unchecked", "mir::add_unchecked_{w} {a} {b}", "", 'w', false),
    ("sub-unchecked", "mir::sub_unchecked_{w} {a} {b}", "", 'w', false),
    ("mul-unchecked", "mir::mul_unchecked_{w} {a} {b}", "", 'w', false),
    ("div", "mir::div_{w} {a} {b}", "", 'w', false),
    ("rem", "mir::rem_{w} {a} {b}", "", 'w', false),
    ("shl", "#wshl_{w}({a}, {s})", "=", 'w', true),
    // (an arithmetic shift on signed bits)
    ("shr", "#wshr_{w}({a}, {s})", "mir::sar_{w} {a} ({s})", 'w', true),
    ("shl-unchecked", "mir::shl_unchecked_{w} {a} ({s})", "", 'w', false),
    ("shr-unchecked", "mir::shr_unchecked_{w} {a} ({s})", "", 'w', false),
    ("and", "#and_{w}({a}, {b})", "=", 'w', true),
    ("or", "#or_{w}({a}, {b})", "=", 'w', true),
    ("xor", "#xor_{w}({a}, {b})", "=", 'w', true),
    ("eq", "#eq_{w}({a}, {b})", "=", 'b', true),
    ("ne", "#ne_{w}({a}, {b})", "=", 'b', true),
    ("lt", "#lt_{w}({a}, {b})", "mir::slt_{w} {a} {b}", 'b', true),
    ("le", "#le_{w}({a}, {b})", "mir::sle_{w} {a} {b}", 'b', true),
    ("gt", "#gt_{w}({a}, {b})", "mir::slt_{w} {b} {a}", 'b', true),
    ("ge", "#ge_{w}({a}, {b})", "mir::sle_{w} {b} {a}", 'b', true),
    ("cmp", "mir::cmp_{w} {a} {b}", "", 'o', true),
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
    // (the amount, a `u32`, taken modulo the width)
    ("rotate_left", 'w', "#rotl_{w}(a0, a1)"),
    ("rotate_right", 'w', "#rotr_{w}(a0, a1)"),
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
/// fields are the leaf's last arguments); of a slice `[T]`, the same leaf
/// named `leaf::slice_*`.
const INDEX_LEAVES: &[(&str, &str)] = &[
    ("ops::RangeToInclusive", "leaf::array_index_to_inclusive"),
    ("ops::RangeTo", "leaf::array_index_to"),
    ("ops::RangeFrom", "leaf::array_index_from"),
    ("ops::Range", "leaf::array_index_range"),
];

impl<'a> Gen<'a> {
    /// An rvalue as an `Option(T)` term over `s`.
    fn rvalue(&mut self, fx: &mut FnCx, rv: &Rvalue, dt: &Ty) -> R<String> {
        let dtt = self.ty(dt)?;
        Ok(match rv {
            Rvalue::Use(o) => self.operand(fx, o)?,
            Rvalue::Bin(op, a, b) => self.binop(fx, op, a, b)?,
            // `CheckedAdd/Sub/Mul`: (the wrapped value, the overflow flag)
            Rvalue::Checked(op, a, b) => {
                let ta = op_ty(&fx.f, a)?;
                // a signed `add`/`sub` on its bits (`mir::scheck_*`), the result back in its type
                if signed(&ta) && ["add", "sub"].contains(&op.as_str()) {
                    let ((w, ab), (_, bb), tat) = (bits(&ta, "a").ok_or("bits")?, bits(&ta, "b").ok_or("bits")?, self.ty(&ta)?);
                    let (pt, wt) = (format!("Tuple2({tat}, Bool)"), wty(w));
                    let e = mat(&format!("mir::scheck_{op}_{w} {ab} {bb}"), &format!("Tuple2({wt}, Bool)"), &pt, &format!("| tuple2(r, o) => tuple2[{tat}, Bool]({}, o)", of_bits(&ta, "r")));
                    return Ok(bind(&tat, &pt, &self.operand(fx, a)?, "a", &map(&tat, &pt, &self.operand(fx, b)?, "b", &e)));
                }
                let w = width(&ta).filter(|_| ["add", "sub", "mul"].contains(&op.as_str())).ok_or_else(|| format!("checked {op} on {ta:?}"))?;
                let (av, bv, wt) = (self.operand(fx, a)?, self.operand(fx, b)?, wty(w));
                let pt = format!("Tuple2({wt}, Bool)");
                bind(&wt, &pt, &av, "a", &map(&wt, &pt, &bv, "b", &format!("mir::checked_{op}_{w} a b")))
            }
            // `UnOp`: `Not` of a `bool` or bits, `Neg` of signed bits, the metadata of a slice reference (its length)
            Rvalue::Un(op, a) => {
                let ta = op_ty(&fx.f, a)?;
                let (av, tat) = (self.operand(fx, a)?, self.ty(&ta)?);
                let e = match (op.as_str(), &ta, bits(&ta, "x")) {
                    ("not", Ty::Bool, _) => "bool::not x".to_string(),
                    ("not", _, Some((w, b))) => of_bits(&ta, &format!("#not_{w}({b})")),
                    ("neg", _, Some((w, b))) if signed(&ta) => of_bits(&ta, &format!("#wneg_{w}({b})")),
                    ("ptr-metadata", Ty::Ref(false, inner), _) if matches!(&**inner, Ty::Slice(_)) => {
                        let Ty::Slice(e) = &**inner else { unreachable!() };
                        format!("slice::len {} x", self.ty(e)?)
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
                let (v, qtt) = (self.read(fx, q)?, self.ty(&qt)?);
                let dfn = self.discr_fn(fx, k, dt)?;
                map(&qtt, &dtt, &v, "x", &format!("{dfn} x"))
            }
            // `[x; N]`: the array of `N` copies
            Rvalue::Repeat(o, n) => {
                let ott = self.ty(&op_ty(&fx.f, o)?)?;
                map(&ott, &dtt, &self.operand(fx, o)?, "x", &format!("array::repeat {ott} {n}usize x .refl(Int, {n}int)"))
            }
            Rvalue::Agg(kind, ops) => {
                let (mut vals, mut tys) = (Vec::new(), Vec::new());
                for o in ops {
                    tys.push(self.ty(&op_ty(&fx.f, o)?)?);
                    vals.push(self.operand(fx, o)?);
                }
                let vars: Vec<String> = (0..vals.len()).map(|i| format!("a{i}")).collect();
                let built = match kind {
                    AggKind::Tuple | AggKind::Closure(_) => tuple(&tys, &vars).1,
                    AggKind::Adt(Ty::Adt(k), v) => self.ctor(k, *v, &vars)?,
                    // `[a0, ..]`: the list of its elements, with its length
                    AggKind::Array(et) => {
                        let ett = self.ty(et)?;
                        let l = vars.iter().rev().fold(format!("Nil[{ett}]"), |l, v| format!("Cons[{ett}]({v}, {l})"));
                        format!("pair(Array {ett} {}usize, {l}, refl(Int, {}int))", vars.len(), vars.len())
                    }
                    other => return Err(format!("the aggregate {other:?}")),
                };
                binds(&vals, &tys, &dtt, "a", some(&dtt, &built))
            }
            Rvalue::Ref(k, _) => return Err(format!("a {k} borrow")),
            Rvalue::Len(_) => return Err("`Len`".into()),
            Rvalue::Unsupported(s) => return Err(format!("the rvalue {s}")),
        })
    }

    /// `L::discr__<ADT>`: each variant's discriminant at the destination's width.
    fn discr_fn(&mut self, fx: &FnCx, k: &str, dt: &Ty) -> R<String> {
        let (w, _) = bits(dt, "").ok_or_else(|| format!("a discriminant of type {dt:?}"))?;
        let (d, a) = (self.m.adts.get(k).cloned().ok_or("no ADT")?, self.adt(k)?);
        // (a type holding a `&mut` holds this function's codes: its own function)
        let owner = if a.ty.contains("@RC@") { format!("{}::", fx.p) } else { "L::".into() };
        let at = a.ty.replace("@RC@", &fx.rc);
        let name = format!("{owner}discr__{}__{w}", if k.len() > 60 { format!("h{}", fxhash(k)) } else { sanitize(k) });
        if a.newtype || a.opaque {
            return Err(format!("the discriminant of the model type `{}`", d.path));
        }
        let arms = self.arms(k, "x", |_, vi, _| Ok(of_bits(dt, &word_lit(d.variants[vi].discr as u128, w))))?;
        let dtt = self.ty(dt)?;
        self.emit(&name, format!("def[prelude] {name} : (x : {at}) -> {dtt} := fun (x : {at}) => match x : {at} as _ return {dtt} with{arms} end"));
        Ok(name)
    }

    /// `&mut place`: its reference code (an index projection stores the
    /// index's value now); `&mut *r` is the code `r` holds, extended.
    fn borrow(&mut self, fx: &mut FnCx, q: &Place) -> R<String> {
        Ok(match self.place(fx, q)? {
            PlaceC::Static(k, ps) => {
                let (mut wraps, mut path) = (Vec::new(), "Nil[mir::Proj]".to_string());
                for pr in ps.iter().rev() {
                    let (w, c) = self.proj_code(fx, pr)?;
                    wraps.push(w);
                    path = format!("Cons[mir::Proj]({c}, {path})");
                }
                let root = fx.root();
                wraps.iter().fold(some(&fx.rc, &code(&root, &format!("{root}::r{k}"), &path)), |acc, w| w.replace("@K@", &acc))
            }
            PlaceC::Dyn(code, _) => code,
        })
    }

    fn binop(&mut self, fx: &mut FnCx, op: &str, a: &Operand, b: &Operand) -> R<String> {
        let (ta, tb) = (op_ty(&fx.f, a)?, op_ty(&fx.f, b)?);
        let (av, bv) = (self.operand(fx, a)?, self.operand(fx, b)?);
        let (tat, tbt) = (self.ty(&ta)?, self.ty(&tb)?);
        let (rt, body, total) = if ta == Ty::Bool {
            let e = ["and", "or", "xor", "eq", "ne"].iter().find(|o| **o == op).ok_or_else(|| format!("{op} on booleans"))?;
            ("Bool".to_string(), format!("bool::{e} a b"), true)
        } else {
            let (w, ab) = bits(&ta, "a").ok_or_else(|| format!("{op} on {ta:?}"))?;
            let (_, bb) = bits(&tb, "b").ok_or_else(|| format!("{op} with an operand of {tb:?}"))?;
            let sg = signed(&ta);
            let (_, ut, stm, res, total) = BINOPS.iter().find(|r| r.0 == op && !(sg && r.2.is_empty())).ok_or_else(|| format!("the operator {op} on {ta:?}"))?;
            // a shift amount as a `u32` (its bits: MIR masks or bounds it)
            let s = match bits(&tb, "b") {
                Some(("u32", x)) => x,
                Some((bw, x)) => format!("#cast_{bw}_u32({x})"),
                None => String::new(),
            };
            if op.starts_with("sh") && s.is_empty() {
                return Err(format!("{op} on {ta:?}"));
            }
            let mut e = (if sg && *stm != "=" { stm } else { ut }).replace("{w}", w).replace("{s}", &s).replace("{a}", &ab).replace("{b}", &bb);
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
        let (av, ft, tt) = (self.operand(fx, a)?, self.ty(&from)?, self.ty(to)?);
        let e = match (kind, &from, to) {
            ("int-to-int", Ty::Bool, _) => of_bits(to, &format!("mir::bool_as_{} x", bits(to, "").ok_or_else(|| format!("a cast of a bool to {to:?}"))?.0)),
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
            ("transmute", Ty::Array(e, n), _) if **e == Ty::Int(false, 8) && width(to).is_some_and(|w| ["u16", "u32", "u64"].contains(&w) && bits_of(w) == 8 * *n as u32) => {
                format!("{}::from_le_bytes x", width(to).unwrap())
            }
            ("unsize", Ty::Ref(false, fa), Ty::Ref(false, tb)) if matches!((&**fa, &**tb), (Ty::Array(..), Ty::Slice(_))) => {
                let Ty::Array(e, n) = &**fa else { unreachable!() };
                return Ok(bind(&ft, &tt, &av, "x", &format!("mir::as_slice {} {n}usize x", self.ty(e)?)));
            }
            _ => return Err(format!("the cast {kind} {from:?} -> {to:?}")),
        };
        Ok(map(&ft, &tt, &av, "x", &e))
    }

    // ----- calls ---------------------------------------------------------------

    /// `Call`: then the jump to the target.
    #[allow(clippy::too_many_arguments)]
    fn call(&mut self, fx: &mut FnCx, b: usize, callee: &Callee, args: &[Operand], dest: &Place, target: Option<usize>, os: &str) -> R<String> {
        let st = fx.st();
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
                // (each argument at its own type: a rotation's amount is a `u32`)
                let tys: Vec<String> = args.iter().map(|a| self.ty(&op_ty(&fx.f, a)?)).collect::<R<_>>()?;
                let e = binds(&vals, &tys, &rt, "a", some(&rt, &tmpl.replace("{w}", w)));
                self.result(fx, dest, os, &rt, &e)?
            }
            Callee::Leaf(path, tys) => {
                let after = self.leaf(fx, path, tys, args, dest, os)?;
                return Ok(self.jump(fx, fx.rank(b), t, &after));
            }
            // a `core::arch` intrinsic: its validated target model (§20.9)
            Callee::Arch(a) => {
                let (rt, e) = self.arch_call(fx, a, args, dest)?;
                self.result(fx, dest, os, &rt, &e)?
            }
            // core's slice iterator and range `get` (raw pointers): their models
            Callee::Fn(k2) if let Some((model, elem)) = self.m.fns.get(k2).and_then(super::model_of) => self.model_call(fx, model, &elem, args, dest, os)?,
            // `Deref::deref` of a library newtype of bytes (its MIR is not exported)
            Callee::Fn(k2) if !self.m.fns.get(k2).is_some_and(|g| g.has_body) => {
                let at = args.first().map(|a| op_ty(&fx.f, a)).transpose()?;
                let n = match at.as_ref().map(|t| self.ty(t)).transpose()?.as_deref() {
                    Some(s) if k2.ends_with("as std::ops::Deref>::deref") => s.strip_prefix("(Array U8 ").and_then(|r| r.strip_suffix("usize)")).map(str::to_string),
                    _ => None,
                };
                let n = n.ok_or_else(|| format!("`{k2}`, which has no MIR body"))?;
                self.leaf_def("leaf::bytes_deref");
                let e = bind(&format!("(Array U8 {n}usize)"), "(Slice U8)", &self.operand(fx, &args[0])?, "x", &format!("leaf::bytes_deref {n}usize x"));
                self.result(fx, dest, os, "(Slice U8)", &e)?
            }
            Callee::Fn(k2) => return self.call_fn(fx, b, k2, args, dest, t, os),
            Callee::Unextracted(k) | Callee::Unsupported(k) => return Err(format!("a call of `{k}`, which was not extracted")),
        };
        Ok(self.jump(fx, fx.rank(b), t, &fx.res_st(&after)))
    }

    /// A call of a function with MIR (§20.4 "Calls"): the callee's `run` on
    /// the same fuel (a self-call: `rec` on one unit less) from its initial
    /// state; each callee cell is the referent of the caller's code for it,
    /// read before and written back after; codes the callee returns (in its
    /// cells or its result) are translated back to the caller's codes.
    #[allow(clippy::too_many_arguments)]
    fn call_fn(&mut self, fx: &mut FnCx, b: usize, k2: &str, args: &[Operand], dest: &Place, t: usize, os: &str) -> R<String> {
        let (st, p, rc, rb) = (fx.st(), fx.p.clone(), fx.rc.clone(), fx.rank(b));
        let g = self.m.fns.get(k2).cloned().ok_or("no MIR")?;
        let self_call = k2 == fx.key;
        let gl = if self_call { self.s.fns.get(k2).cloned().ok_or("self")? } else { self.function(k2).map_err(|e| format!("the callee `{k2}`: {e}"))? };
        // the arguments (a closure body takes its parameters one by one, its
        // callers pass their tuple; a shim with `spread-arg` keeps the tuple)
        let mut argv: Vec<(String, Ty)> = args.iter().map(|a| Ok((self.operand(fx, a)?, op_ty(&fx.f, a)?))).collect::<R<_>>()?;
        if matches!(g.item, Item::Closure) && let Some((tv, tt)) = argv.pop() {
            let Ty::Tuple(ts) = &tt else { return Err(format!("a closure called with {tt:?}")) };
            let ttt = self.ty(&tt)?;
            for (i, ft) in ts.iter().enumerate() {
                let (fe, ftt) = (self.field(&tt, 0, i, "tp", None)?, self.ty(ft)?);
                argv.push((bind(&ttt, &ftt, &tv, "tp", &fe), ft.clone()));
            }
        }
        if argv.len() != g.argc {
            return Err(format!("`{k2}` takes {} arguments, called with {}", g.argc, argv.len()));
        }
        let (gp, grc) = (format!("L::{}", gl.id), format!("Tuple2(L::{}::Root, List(mir::Proj))", gl.id));
        let gcode = |j: usize| code(&format!("{gp}::Root"), &format!("{gp}::Root::rc{j}"), "Nil[mir::Proj]");
        let (orc, ost) = (format!("Option({rc})"), format!("Option({st})"));
        // around the callee's run: the arguments `a<i>`, then per cell `cc<j>` and `cv<j>`
        // (`(let, type, value, binder)`)
        let mut pre: Vec<(String, String, String, String)> = Vec::new();
        for (i, (v, at)) in argv.iter().enumerate() {
            pre.push((String::new(), self.ty(at)?, v.clone(), format!("a{i}")));
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
            let n = fx.need(if buffer { Target::Buf } else { Target::Ty(c.mir_ty.clone()) });
            let (ct, ctr) = (c.ty.replace("@RC@", &grc), if buffer { "List(U8)".to_string() } else { self.ty(&c.mir_ty)? });
            let cc = match c.parent {
                None if c.optional => a.clone(),
                None => some(&rc, &a),
                // the parent's referent holds this referent's code
                Some(k) => {
                    let (pn, ptt) = (fx.need(Target::Ty(gl.cells[k].mir_ty.clone())), self.ty(&gl.cells[k].mir_ty)?);
                    let inner = if c.optional { "v".to_string() } else { some(&rc, "v") };
                    bind(&rc, &rc, &format!("cc{k}"), "q", &bind(&ptt, &rc, &fx.through("deref", &pn, "q"), "v", &inner))
                }
            };
            let child = (j + 1..ncells).find(|x| gl.cells[*x].parent == Some(j));
            if child.is_none() && !buffer && holds_ref(self.m, &c.mir_ty) {
                return Err(format!("a referent holding a reference of `{k2}` beyond one level"));
            }
            let xin = match child {
                Some(n2) if gl.cells[n2].optional => mat("v", &orc, &format!("Option({grc})"), &format!("| None => {} | Some(q2) => {}", none(&grc), some(&grc, &gcode(n2)))),
                Some(n2) => gcode(n2),
                None => "v".to_string(),
            };
            let oct = format!("Option({ct})");
            let cv = mat(&format!("cc{j}"), &orc, &format!("Option({oct})"), &format!("| None => {} | Some(q) => {}", some(&oct, &none(&ct)), map(&ctr, &oct, &fx.through("deref", &n, "q"), "v", &some(&ct, &xin))));
            pre.push((format!("let cc{j} : {orc} = {cc}; "), oct.clone(), cv, format!("cv{j}")));
            slots[nl + j] = format!("cv{j}");
            if c.parent.is_none() {
                let pt = gl.local_tys[c.param].replace("@RC@", &grc);
                slots[c.param] = if c.optional { mat(&a, &orc, &format!("Option({pt})"), &format!("| None => {} | Some(q) => {}", some(&pt, &none(&grc)), some(&pt, &some(&grc, &gcode(j))))) } else { some(&pt, &gcode(j)) };
            }
            // the write-back: the final value (`None`: the callee lost it) through the caller's code
            let fin = if c.optional { parts[j].clone() } else { some(&ct, &parts[j]) };
            let wb = fx.through("write", &n, "q");
            let back = if buffer { format!("{wb} w") } else { bind(&ctr, &st, &self.xout(&gl, fx, &c.mir_ty, "w")?, "w2", &format!("{wb} w2")) };
            steps.push(mat(&format!("cc{j}"), &orc, &ost, &format!("| None => {} | Some(q) => {}", some(&st, "s"), mat(&fin, &oct, &ost, &format!("| None => {} | Some(w) => {back}", none(&st))))));
        }
        // the other parameters' slots: their arguments; the other locals: uninitialized
        for (i, s) in slots.iter_mut().enumerate().take(nl) {
            if s.is_empty() {
                let lt = gl.local_tys[i].replace("@RC@", &grc);
                *s = if (1..=g.argc).contains(&i) { some(&lt, &format!("a{}", i - 1)) } else { none(&lt) };
            }
        }
        let gst = format!("{gp}::St");
        let init = ret(&gst, &format!("{gst}::st({})", slots.join(", ")));
        let run = if self_call { format!("rec(f1, {p}::Blk::b0, {init}; {})", decrease(&p, &fx.cur, fx.rank(0), rb, true)) } else { format!("{gp}::run fuel {gp}::Blk::b0 ({init})") };
        let dt = place_ty(&fx.f, dest)?;
        steps.push(if has_ret { bind(&self.ty(&dt)?, &st, &self.xout(&gl, fx, &g.locals[0].0, &parts[nparts - 1])?, "rr", &self.write(fx, dest, "rr")?) } else { self.write(fx, dest, "tt")? });
        let chain = steps.iter().rev().fold(some(&st, "s"), |acc, stp| bind(&st, &st, stp, "s", &acc));
        let body = if nparts > 1 { mat("res", &gl.out_ty, &ost, &format!("| {}({}) => {chain}", tuple_pat(nparts), parts.join(", "))) } else { chain };
        // the callee's outcome: its value goes on to the write-backs, its
        // panic or stuck is the caller's (`mir::then`)
        let called = pre.iter().rev().fold(then(&gl.out_ty, &st, &run, "res", &fx.res_st(&body)), |acc, (l, a, v, x)| format!("{l}{}", bindr(a, &st, v, x, &acc)));
        let full = bindr(&st, &st, os, "s", &called);
        // (a self-call consumes one unit of fuel)
        Ok(if self_call { fuel_jump(fx, rb, t, &full) } else { self.jump(fx, rb, t, &full) })
    }

    /// A value of MIR type `t` in the callee `gl`'s terms, in the caller's
    /// (`Option(T)`): a code rooted at a callee cell is the caller's code for
    /// that cell extended by its path; one rooted at a callee local cannot
    /// occur (a dangling reference) and is `None`.
    fn xout(&mut self, gl: &LFn, fx: &FnCx, t: &Ty, v: &str) -> R<String> {
        let (rc, root) = (fx.rc.as_str(), fx.root());
        let (tt, groot, orc) = (self.ty(t)?, format!("L::{}::Root", gl.id), format!("Option({rc})"));
        let xlate = |q: &str| {
            let arms: String = (0..gl.local_tys.len()).map(|i| format!(" | r{i} => {}", none(rc))).chain((0..gl.cells.len()).map(|j| format!(" | rc{j} => {}", bind(rc, rc, &format!("cc{j}"), "c", &some(rc, &code_app(&root, "c", &format!("rc::snd {groot} {q}"))))))).collect();
            format!("match rc::fst {groot} {q} : {groot} as _ return {orc} with{arms} end")
        };
        Ok(match (t, opt_mut(self.m, t)) {
            (Ty::Ref(true, _), _) => xlate(v),
            (_, Some(_)) => mat(v, &format!("Option(Tuple2({groot}, List(mir::Proj)))"), &format!("Option({tt})"), &format!("| None => {} | Some(q3) => {}", some(&tt, &none(rc)), map(rc, &tt, &xlate("q3"), "c3", &some(rc, "c3")))),
            _ if tt.contains("@RC@") => return Err("a value holding references returned by a callee".into()),
            _ => some(&tt, v),
        })
    }

    fn leaf_def(&mut self, name: &str) {
        if let Some(text) = leaf_text(name) {
            self.emit(name, text);
        }
    }

    /// A call of a `core::arch` intrinsic (§20.9, `mir::arch`): the model
    /// global applied to the immediates (each with its range proofs, by
    /// evaluation) and the arguments (a signed scalar as its bits), a total
    /// value: (the result's L type, the `Option` term). `Err` (stuck) for a
    /// call `mir::arch` does not read.
    fn arch_call(&mut self, fx: &mut FnCx, a: &ArchCall, args: &[Operand], dest: &Place) -> R<(String, String)> {
        let cm = super::arch::model(self.m, a, &fx.f.target_features)?;
        super::arch::loaded(self.k.env, cm)?;
        let imms = super::arch::immediates(cm, a)?;
        if args.len() != cm.params.len() {
            return Err(format!("`{}` called with {} argument(s); its model takes {}", a.path, args.len(), cm.params.len()));
        }
        let (mut vals, mut tys, mut xs) = (Vec::new(), Vec::new(), Vec::new());
        for (i, (o, (pname, pt))) in args.iter().zip(cm.params).enumerate() {
            let ot = op_ty(&fx.f, o)?;
            if !super::arch::same_ty(&ot, *pt) {
                return Err(format!("`{}`'s argument `{pname}` of {ot:?}, not its model's {}", a.path, pt.text()));
            }
            let x = format!("a{i}");
            xs.push(match &ot {
                Ty::Simd(..) => x.clone(),
                t => bits(t, &x).ok_or_else(|| format!("the bits of {t:?}"))?.1,
            });
            vals.push(self.operand(fx, o)?);
            tys.push(self.ty(&ot)?);
        }
        let dt = place_ty(&fx.f, dest)?;
        if !super::arch::same_ty(&dt, cm.ret) {
            return Err(format!("`{}`'s result as {dt:?}, not its model's {}", a.path, cm.ret.text()));
        }
        let xr: Vec<&str> = xs.iter().map(String::as_str).collect();
        let call = cm.apply_text(&imms, &xr)?;
        let rt = self.ty(&dt)?;
        let r = match &dt {
            Ty::Simd(..) => call,
            t => of_bits(t, &format!("({call})")),
        };
        Ok((rt.clone(), binds(&vals, &tys, &rt, "a", some(&rt, &r))))
    }

    /// A leaf call (§20.4 "Leaves"): a library function without MIR whose
    /// meaning is a model of `literal.core` or of a host model. The state
    /// after it, a `mir::Res(St)`: an index leaf panics where core's `index`
    /// does (`leaf::*_index_*`), a failure of any other leaf is stuck.
    fn leaf(&mut self, fx: &mut FnCx, path: &str, tys: &[Ty], args: &[Operand], dest: &Place, os: &str) -> R<String> {
        let dtt = self.ty(&place_ty(&fx.f, dest)?)?;
        // a leaf with a `&mut` first argument: its referent through the code
        let norm = path.replace("bytes::buf::buf_impl::Buf::", "bytes::Buf::").replace("bytes::buf::buf_mut::BufMut::", "bytes::BufMut::");
        if let Some((_, leaf, buffer)) = STATE_LEAVES.iter().find(|l| norm == l.0) {
            let Some(Ty::Ref(true, pointee)) = args.first().map(|a| op_ty(&fx.f, a)).transpose()? else { return Err(format!("the leaf `{path}` without a `&mut` receiver")) };
            let (target, sty) = if *buffer { (Target::Buf, "List(U8)".to_string()) } else { (Target::Ty((*pointee).clone()), self.ty(&pointee)?) };
            if leaf.ends_with("bytes_iter_next") && sty != "(Slice (Slice U8))" {
                return Err(format!("`Iterator::next` of {pointee:?} (not the byte-string iterator model)"));
            }
            let tparam = if leaf.ends_with("vec_push") { format!(" {}", sty.strip_prefix("List(").and_then(|x| x.strip_suffix(')')).ok_or("push on a non-`Vec`")?) } else { String::new() };
            self.leaf_def(leaf);
            let after = self.state_leaf(fx, target, &sty, &format!("{leaf}{tparam}"), args, dest, os)?;
            return Ok(fx.res_st(&after));
        }
        // a value leaf: a model at the arguments (a range's fields), an
        // outcome (an index leaf: its panic) or total
        let method = path.rsplit("::").next().unwrap_or("");
        let (f, partial, vals) = match tys {
            // `<[T; N] as Index<range>>::index(&a, r)`, `<[T] as Index<range>>::index(&s, r)`
            // (core's `Index`, by its exact path): the array's leaf, or the slice's (`leaf::slice_*`)
            [base @ (Ty::Array(..) | Ty::Slice(_)), Ty::Adt(rk)] if lib_path("ops::Index::index", path) => {
                let rd = self.m.adts.get(rk).cloned().ok_or("no ADT")?;
                let (_, leaf) = INDEX_LEAVES.iter().find(|(r, _)| lib_path(r, &rd.path)).ok_or_else(|| format!("an index by `{}`", rd.path))?;
                let (e, n) = match base {
                    Ty::Array(e, n) => (e, Some(n)),
                    Ty::Slice(e) => (e, None),
                    _ => return Err("an index of neither an array nor a slice".into()),
                };
                let leaf = if n.is_some() { leaf.to_string() } else { leaf.replace("leaf::array_", "leaf::slice_") };
                self.leaf_def(&leaf);
                let (rty, et) = (Ty::Adt(rk.clone()), self.ty(e)?);
                let (head, base_ty) = match n {
                    Some(n) => (format!("{leaf} {et} {n}usize"), format!("(Array {et} {n}usize)")),
                    None => (format!("{leaf} {et}"), format!("(Slice {et})")),
                };
                let mut vals = vec![(base_ty, self.operand(fx, &args[0])?)];
                for (i, (_, ft)) in rd.variants[0].fields.iter().enumerate() {
                    let (rtt, ftt, rv) = (self.ty(&rty)?, self.ty(ft)?, self.operand(fx, &args[1])?);
                    vals.push((ftt.clone(), bind(&rtt, &ftt, &rv, "xr", &self.field(&rty, 0, i, "xr", None)?)));
                }
                (head, true, vals)
            }
            // a host model's method
            [t, ..] if self.k.names.host_model_method(self.m, t, method).is_some() => {
                let vals = args.iter().map(|a| Ok((self.ty(&op_ty(&fx.f, a)?)?, self.operand(fx, a)?))).collect::<R<_>>()?;
                (self.k.names.host_model_method(self.m, t, method).unwrap(), false, vals)
            }
            // runtime feature detection (§20.9): refused, with its reason
            _ if super::arch::detection(path).is_some() => return Err(super::arch::detection(path).unwrap_or_default()),
            _ => return Err(format!("the leaf `{path}` (no model)")),
        };
        let call = (0..vals.len()).fold(f, |c, i| format!("{c} a{i}"));
        let (tys, vals): (Vec<String>, Vec<String>) = vals.into_iter().unzip();
        if !partial {
            let e = binds(&vals, &tys, &dtt, "a", some(&dtt, &call));
            let after = self.result(fx, dest, os, &dtt, &e)?;
            return Ok(fx.res_st(&after));
        }
        // (the leaf's outcome: its value written to `dest`, its panic the run's)
        let st = fx.st();
        let w = self.write(fx, dest, "r")?;
        let written = then(&dtt, &st, &call, "r", &fx.res_st(&w));
        Ok(bindr(&st, &st, os, "s", &bindsr(&vals, &tys, &st, "a", written)))
    }

    /// A leaf whose first argument is a `&mut`: its referent (of L type
    /// `sty`) read through the code, `call x0 x1 ..` (a `Tuple2(the new
    /// referent, the result)`), the new referent written back through the
    /// code and the result written to `dest`.
    #[allow(clippy::too_many_arguments)]
    fn state_leaf(&mut self, fx: &mut FnCx, target: Target, sty: &str, call0: &str, args: &[Operand], dest: &Place, os: &str) -> R<String> {
        let (st, rc) = (fx.st(), fx.rc.clone());
        let dtt = self.ty(&place_ty(&fx.f, dest)?)?;
        let n = fx.need(target);
        let code = self.operand(fx, &args[0])?;
        let mut call = format!("{call0} x0");
        let mut binds = Vec::new();
        for (i, a) in args.iter().enumerate().skip(1) {
            binds.push((self.ty(&op_ty(&fx.f, a)?)?, self.operand(fx, a)?, format!("x{i}")));
            let _ = write!(call, " x{i}");
        }
        let m = mat(&call, &format!("Tuple2({sty}, {dtt})"), &format!("Option({st})"), &format!("| tuple2(nx, r) => {}", bind(&st, &st, &format!("{} nx", fx.through("write", &n, "q")), "s", &self.write(fx, dest, "r")?)));
        let inner = binds.iter().rev().fold(m, |e, (t, v, x)| bind(t, &st, v, x, &e));
        Ok(bind(&st, &st, os, "s", &bind(&rc, &st, &code, "q", &bind(sty, &st, &fx.through("deref", &n, "q"), "x0", &inner))))
    }

    /// A library function read as its model (`mod.rs`'s `Model`, with
    /// `literal.core`'s `leaf::slice_*`) instead of its MIR, whose raw
    /// pointers L does not model: core's slice iterator (the slice and the
    /// index of its next element) and a slice's `get` by a `Range<usize>`.
    fn model_call(&mut self, fx: &mut FnCx, model: super::Model, elem: &Ty, args: &[Operand], dest: &Place, os: &str) -> R<String> {
        let et = self.ty(elem)?;
        let (sl, it) = (format!("(Slice {et})"), format!("Tuple2((Slice {et}), Usize)"));
        match (model, args) {
            (super::Model::SliceIterNew, [s]) => {
                self.leaf_def("leaf::slice_iter_new");
                let e = map(&sl, &it, &self.operand(fx, s)?, "x", &format!("leaf::slice_iter_new {et} x"));
                self.result(fx, dest, os, &it, &e)
            }
            (super::Model::SliceIterNext, [a]) => {
                let Ty::Ref(true, pointee) = op_ty(&fx.f, a)? else { return Err("`Iterator::next` of a slice iterator without a `&mut` receiver".into()) };
                if self.ty(&pointee)? != it {
                    return Err(format!("`Iterator::next` of {pointee:?} as a slice iterator of {elem:?}"));
                }
                self.leaf_def("leaf::slice_iter_next");
                self.state_leaf(fx, Target::Ty((*pointee).clone()), &it, &format!("leaf::slice_iter_next {et}"), args, dest, os)
            }
            (super::Model::SliceGetRange, [r, s]) => {
                // the range's fields (core's `Range<usize>`, by its exact path)
                let rt = op_ty(&fx.f, r)?;
                let Ty::Adt(rk) = &rt else { return Err(format!("`SliceIndex::get` by {rt:?}")) };
                if !self.m.adts.get(rk).is_some_and(|d| lib_path("ops::Range", &d.path) && d.args == [Ty::Int(false, 0)]) {
                    return Err(format!("`SliceIndex::get` by `{rk}`"));
                }
                self.leaf_def("leaf::slice_get_range");
                let (rtt, rv) = (self.ty(&rt)?, self.operand(fx, r)?);
                let ends: Vec<String> = (0..2).map(|i| Ok(bind(&rtt, "Usize", &rv, "xr", &self.field(&rt, 0, i, "xr", None)?))).collect::<R<_>>()?;
                let ot = format!("Option({sl})");
                let vals = [self.operand(fx, s)?, ends[0].clone(), ends[1].clone()];
                let e = binds(&vals, &[sl.clone(), "Usize".into(), "Usize".into()], &ot, "a", some(&ot, &format!("leaf::slice_get_range {et} a0 a1 a2")));
                self.result(fx, dest, os, &ot, &e)
            }
            _ => Err(format!("the model {model:?} with {} arguments", args.len())),
        }
    }

    /// The state `os`, then the result `r` (the `Option(rt)` term `e`) written to `dest`.
    fn result(&mut self, fx: &mut FnCx, dest: &Place, os: &str, rt: &str, e: &str) -> R<String> {
        let st = fx.st();
        Ok(bind(&st, &st, os, "s", &bind(rt, &st, e, "r", &self.write(fx, dest, "r")?)))
    }
}

/// `mir::bind`s of the values `vals` (of types `tys`) to `{x}0, {x}1, ..`
/// around `body`, at the result type `r`.
fn binds(vals: &[String], tys: &[String], r: &str, x: &str, body: String) -> String {
    vals.iter().zip(tys).enumerate().rev().fold(body, |e, (i, (v, t))| bind(t, r, v, &format!("{x}{i}"), &e))
}

/// [`binds`] into an outcome (`body` a `mir::Res(r)`; `None`: stuck).
fn bindsr(vals: &[String], tys: &[String], r: &str, x: &str, body: String) -> String {
    vals.iter().zip(tys).enumerate().rev().fold(body, |e, (i, (v, t))| bindr(t, r, v, &format!("{x}{i}"), &e))
}

/// A jump to block `to` that consumes one unit of fuel (stuck without it).
fn fuel_jump(fx: &FnCx, from_rank: i64, to: usize, os: &str) -> String {
    let o = &fx.out_ty;
    format!("match fuel : List(Unit) as yf return mir::Res({o}) using .ef with | Nil => {} | Cons(u, f1) => rec(f1, {}::Blk::b{to}, {os}; {}) end", stuck(o), fx.p, decrease(&fx.p, &fx.cur, fx.rank(to), from_rank, true))
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
