//! Elaboration-semantics definitions that the kernel prelude does not
//! provide (TCB: they give meaning to exec constructs, DESIGN.md §1.1 item 2;
//! `SEMANTICS.md` prints them). They are added to every environment before
//! any user item:
//!
//! * `Tuple1(A0)` — the 1-tuple `(a,)` (the prelude has `Tuple2..Tuple12`).
//! * `array::copy_range T N a lo hi s .h0 .h1 .h2 : Array T N` — the value of
//!   the array local `a` after `a[lo..hi].copy_from_slice(s)` (§3.3): the
//!   list `take(a, lo) ++ list(s) ++ drop(a, hi)`, with preconditions
//!   `lo ≤ hi`, `hi ≤ N` and `hi − lo = s.len()` (exactly the conditions
//!   under which Rust does not panic). Its length proof is built here from
//!   the prelude lemmas `len_append`, `len_take`, `len_drop`, `ok_len` and a
//!   linear-arithmetic certificate; the kernel checks it.
//!
//! * the ghost-language library `ghost.core` ([`GHOST_CORE`], §4.1: the
//!   `Seq<T>` operations the kernel prelude lacks and the `Nat` functions
//!   `pow2`, `log2`, `popcount`; TCB item 6), loaded once
//!   ([`load_ghost_library`]).
//!
//! Proposed for the kernel prelude (they belong with the other §3.4
//! meanings); kept here so the elaborator does not edit kernel files.

use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{CtorDecl, DefDecl, DefKind, GlobalId, IndId, InductiveDecl, Lvl, PrimOp, Recursion, Rel, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Budget, VEnv};

use crate::hir::ItemId;

/// Ids of the elaboration-semantics definitions.
#[derive(Clone, Debug)]
pub struct Semantics {
    pub tuple1: IndId,
    pub copy_range: GlobalId,
    /// Intrinsic models loaded from `sandblaster/targets/core/*.core`
    /// (§9.2), by intrinsic name; empty when the models are not available.
    pub intrinsics: std::collections::HashMap<String, GlobalId>,
    /// Items the elaborator treats as hardware (filled by the driver).
    pub hw: Vec<ItemId>,
}

/// A telescope under construction (context + evaluation environment).
pub struct Tele<'e> {
    pub env: &'e Env,
    pub ctx: Ctx,
    pub venv: VEnv,
}

impl<'e> Tele<'e> {
    pub fn new(env: &'e Env) -> Tele<'e> {
        Tele { env, ctx: Ctx::default(), venv: VEnv::default() }
    }
    pub fn depth(&self) -> u32 {
        self.ctx.entries.len() as u32
    }
    /// `Var` of the binder at level `l`.
    pub fn v(&self, l: u32) -> Tm {
        mk::var(self.depth() - 1 - l)
    }
    pub fn push(&mut self, name: &str, rel: Rel, ty: &Tm) -> Result<u32, String> {
        let mut b = Budget { steps: 10_000_000 };
        let tv = self.env.eval(&self.venv, Lvl(self.depth()), ty, &mut b).map_err(|e| format!("{e:?}"))?;
        let entry = self.env.fresh_var(Lvl(self.depth()), rel, &tv);
        let l = self.depth();
        let mut es = (*self.ctx.entries).clone();
        es.push(CtxEntry { name: Rc::from(name), rel, ty: tv, def: None });
        self.ctx = Ctx { entries: Rc::new(es) };
        let mut ve = (*self.venv.0).clone();
        ve.push(entry);
        self.venv = VEnv(Rc::new(ve));
        Ok(l)
    }
}

/// The ghost-language library (`ghost.core`): the `Seq<T>` operations the
/// kernel prelude does not provide (`ghost::seq_get`, `ghost::seq_map`,
/// `ghost::seq_flatten`, `ghost::arrays_flatten`; SEMANTICS.md §13.5),
/// `ghost::seq_all` (the well-formedness hypothesis of a `Seq` holding
/// `Nat`s) and the `Nat` functions. TCB (DESIGN.md §1.1 item 6).
pub const GHOST_CORE: &str = include_str!("ghost.core");

/// The lift semantics `lift.core` (SEMANTICS.md §19): integer methods of
/// lifted code the kernel prelude lacks (`div_ceil`).
pub const LIFT_CORE: &str = include_str!("lift.core");

fn g(env: &Env, n: &str) -> Result<GlobalId, String> {
    env.lookup_global(n).ok_or_else(|| format!("prelude global `{n}` is missing"))
}

/// Installs the definitions (see the module docs), and the intrinsic
/// models of `arch` when their core transcription exists.
pub fn install(env: &mut Env, arch: &crate::target::Arch) -> Result<Semantics, String> {
    let tuple1 = env
        .add_inductive(InductiveDecl { name: Rc::from("Tuple1"), params: vec![(Rc::from("A0"), mk::ty())], ctors: vec![CtorDecl { name: Rc::from("tuple1"), fields: vec![(Rc::from("x0"), Rel::Rel, mk::var(0))] }] })
        .map_err(|e| e.to_string())?;
    let copy_range = copy_range(env)?;
    // the ghost-language library (DESIGN.md §4.1, §1.1 item 6), unless the
    // prelude lemmas already loaded it (`lemmas/nat.core` states facts
    // about its `Nat` functions)
    load_ghost_library(env)?;
    if env.lookup_global("u64::div_ceil").is_none() {
        let mut b = Budget { steps: 10_000_000 };
        env.load_core(LIFT_CORE, &mut b).map_err(|e| format!("the lift semantics failed to load: {e}"))?;
    }
    let intrinsics = load_intrinsics(env, arch.name());
    Ok(Semantics { tuple1, copy_range, intrinsics, hw: vec![] })
}

/// Loads the ghost-language library `ghost.core` into `env` once (the
/// prelude lemmas load it before `lemmas/nat.core`, the elaboration
/// semantics otherwise).
pub fn load_ghost_library(env: &mut Env) -> Result<(), String> {
    if env.lookup_global("ghost::seq_get").is_some() {
        return Ok(());
    }
    let mut b = Budget { steps: 100_000_000 };
    env.load_core(GHOST_CORE, &mut b).map(|_| ()).map_err(|e| format!("the ghost-language library failed to load: {e}"))
}

/// Loads the target intrinsic models if the core transcriptions exist
/// (§9.2). Missing or failing files leave the table empty: hardware
/// variants are then deferred (phase 3).
fn load_intrinsics(env: &mut Env, arch: &str) -> std::collections::HashMap<String, GlobalId> {
    let mut out = std::collections::HashMap::new();
    let f = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../targets/core/{arch}.core"));
    let Ok(text) = std::fs::read_to_string(&f) else { return out };
    let before = env.num_globals();
    let mut b = Budget { steps: 1_000_000_000 };
    if env.load_core(&text, &mut b).is_err() {
        return out;
    }
    for i in before..env.num_globals() {
        let id = GlobalId(i);
        if let Some(n) = env.global_name(id) {
            out.insert(n.to_string(), id);
        }
    }
    out
}

/// `array::copy_range` (see the module docs).
fn copy_range(env: &mut Env) -> Result<GlobalId, String> {
    let bool_ = env.bool_ind();
    let usize_t = || mk::int_ty(Width::Usize);
    let int_t = || mk::int_ty(Width::Int);
    let array = g(env, "Array")?;
    let slice = g(env, "Slice")?;
    let (take, drop, append, len) = (g(env, "seq::take")?, g(env, "seq::drop")?, g(env, "seq::append")?, g(env, "seq::len")?);
    let (len_append, len_take, len_drop, ok_len_s, ok_len_a) = (g(env, "seq::len_append")?, g(env, "seq::len_take")?, g(env, "seq::len_drop")?, g(env, "slice::ok_len")?, g(env, "array::ok_len")?);
    let p0 = |op: PrimOp, args: Vec<Tm>| mk::prim(op, args, vec![]);
    let holds = |t: Tm| mk::eq_bool(bool_, t, true);
    let cast = |t: Tm| p0(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![t]);
    let app = |f: GlobalId, args: Vec<Tm>| mk::apps(mk::global(f), args.into_iter().map(|a| (Rel::Rel, a)));

    let envr: &Env = env;
    let mut t = Tele::new(envr);
    let mut binders: Vec<(&str, Rel, Tm)> = Vec::new();
    macro_rules! bind {
        ($name:expr, $rel:expr, $ty:expr) => {{
            let ty: Tm = $ty;
            binders.push(($name, $rel, ty.clone()));
            t.push($name, $rel, &ty)?
        }};
    }
    let lt = bind!("T", Rel::Rel, mk::ty());
    let ln = bind!("N", Rel::Rel, usize_t());
    let la = bind!("a", Rel::Rel, app(array, vec![t.v(lt), t.v(ln)]));
    let llo = bind!("lo", Rel::Rel, usize_t());
    let lhi = bind!("hi", Rel::Rel, usize_t());
    let ls = bind!("s", Rel::Rel, app(slice, vec![t.v(lt)]));
    let lh0 = bind!("h0", Rel::Irr, holds(p0(PrimOp::Le(Width::Usize), vec![t.v(llo), t.v(lhi)])));
    let lh1 = bind!("h1", Rel::Irr, holds(p0(PrimOp::Le(Width::Usize), vec![t.v(lhi), t.v(ln)])));
    let sub = mk::prim(PrimOp::Sub(Width::Usize), vec![t.v(lhi), t.v(llo)], vec![t.v(lh0)]);
    let lh2 = bind!("h2", Rel::Irr, holds(p0(PrimOp::Eq(Width::Usize), vec![sub, mk::fst(t.v(ls))])));
    let _ = lh2;

    // body terms at depth 9
    let ty_t = t.v(lt);
    let l = mk::fst(t.v(la));
    let sl = mk::fst(mk::snd(t.v(ls)));
    let lo_i = cast(t.v(llo));
    let hi_i = cast(t.v(lhi));
    let take_ = app(take, vec![ty_t.clone(), l.clone(), lo_i.clone()]);
    let drop_ = app(drop, vec![ty_t.clone(), l.clone(), hi_i.clone()]);
    let rest = app(append, vec![ty_t.clone(), sl.clone(), drop_.clone()]);
    let res = app(append, vec![ty_t.clone(), take_.clone(), rest.clone()]);
    let lenof = |x: Tm| app(len, vec![ty_t.clone(), x]);
    let eqi = |a: Tm, b: Tm| mk::eq(int_t(), a, b);
    let le_i = |a: Tm, b: Tm| holds(p0(PrimOp::Le(Width::Int), vec![a, b]));
    let lin = |hyps: Vec<(Tm, Tm)>, goal: Tm| -> Result<Tm, String> { super::basic::linarith_term(t.env, &t.ctx, hyps, goal) };

    let h6 = (app(ok_len_a, vec![ty_t.clone(), t.v(ln), t.v(la)]), eqi(lenof(l.clone()), cast(t.v(ln))));
    let h0 = (t.v(lh0), holds(p0(PrimOp::Le(Width::Usize), vec![t.v(llo), t.v(lhi)])));
    let h1 = (t.v(lh1), holds(p0(PrimOp::Le(Width::Usize), vec![t.v(lhi), t.v(ln)])));
    let h2 = (t.v(lh2), holds(p0(PrimOp::Eq(Width::Usize), vec![mk::prim(PrimOp::Sub(Width::Usize), vec![t.v(lhi), t.v(llo)], vec![t.v(lh0)]), mk::fst(t.v(ls))])));
    let pp0 = lin(vec![], le_i(mk::lit(Width::Int, 0u8), lo_i.clone()))?;
    let pp1 = lin(vec![h0.clone(), h1.clone(), h6.clone()], le_i(lo_i.clone(), lenof(l.clone())))?;
    let qq0 = lin(vec![], le_i(mk::lit(Width::Int, 0u8), hi_i.clone()))?;
    let qq1 = lin(vec![h1.clone(), h6.clone()], le_i(hi_i.clone(), lenof(l.clone())))?;
    let ia = |a: Tm, b: Tm| p0(PrimOp::IAdd, vec![a, b]);
    let hyps = vec![
        (app(len_append, vec![ty_t.clone(), take_.clone(), rest.clone()]), eqi(lenof(res.clone()), ia(lenof(take_.clone()), lenof(rest.clone())))),
        (app(len_append, vec![ty_t.clone(), sl.clone(), drop_.clone()]), eqi(lenof(rest.clone()), ia(lenof(sl.clone()), lenof(drop_.clone())))),
        (app(len_take, vec![ty_t.clone(), l.clone(), lo_i.clone(), pp0, pp1]), eqi(lenof(take_.clone()), lo_i.clone())),
        (app(len_drop, vec![ty_t.clone(), l.clone(), hi_i.clone(), qq0, qq1]), eqi(lenof(drop_.clone()), p0(PrimOp::ISub, vec![lenof(l.clone()), hi_i.clone()]))),
        (app(ok_len_s, vec![ty_t.clone(), t.v(ls)]), eqi(lenof(sl.clone()), cast(mk::fst(t.v(ls))))),
        h6,
        h0,
        h1,
        h2,
    ];
    let proof = lin(hyps, eqi(lenof(res.clone()), cast(t.v(ln))))?;
    let arr_ty = app(array, vec![ty_t.clone(), t.v(ln)]);
    let body_inner = mk::pair(arr_ty.clone(), res, proof);
    // assemble Π / λ telescopes
    let mut ty = app(array, vec![mk::var(8), mk::var(7)]);
    let mut body = body_inner;
    for (name, rel, bty) in binders.iter().rev() {
        ty = mk::pi(name, *rel, bty.clone(), ty);
        body = mk::lam(name, *rel, bty.clone(), body);
    }
    drop_telescope(t);
    let d = DefDecl { name: Rc::from("array::copy_range"), kind: DefKind::Prelude, ty, body, recursion: Recursion::None, arity: 9, opaque: false };
    let mut b = Budget { steps: 100_000_000 };
    env.add_def(d, &mut b).map_err(|e| format!("array::copy_range: {e}"))
}

fn drop_telescope(_t: Tele<'_>) {}
