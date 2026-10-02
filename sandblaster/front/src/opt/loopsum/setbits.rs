//! The set-bit iteration rung (optimizer design §7.6 rung 3; plan O6).
//!
//! A loop with a fuel `f` (its measure, `K, K−1, …, 0` from the call), a
//! `BitDigit` variable `v` and its halving width `w = w₀ >> (K − f)` (the
//! idle test `v < w`) visits one width per iteration although only the set
//! bits of `v` do anything: every idle iteration only decrements the fuel
//! and halves the width. The rung's helper visits the set bits only:
//!
//! ```text
//! fn loop__bits(f, x̄) -> R          // the loop's parameters without `w`
//!     requires Req_loop(f, x̄), f ≤ K;  decreases f
//! {
//!     let w = w₀ >> (K − f);
//!     if f != 0 && v < w { loop__bits(min(f − 1, B − 1 + s₀ − lz(v)), x̄) }   // the next set bit
//!     else { <the loop's body, recursing into loop__bits> }
//! }
//! ```
//!
//! (`B` is the width of `v` in bits — any of `u8` … `u64` and `usize`;
//! `s₀ = K − log₂ w₀`: the width at fuel `f` is `2^(f − s₀)`, so the next
//! peak is at fuel `bitlen(v) − 1 + s₀`.) Two **enumeration lemmas**
//! (`enumerate`, design §7.5 "symbolic fuel") link it to the loop, both
//! kernel-checked:
//!
//! ```text
//! <loop>::bits::idle  : Π f f₂ x̄ (f ≤ K) (f₂ ≤ f) (B − 1 + s₀ − f₂ ≤ lz(v)) Req(f) Req(f₂).
//!                       Eq(R, loop(f, x̄, W(f)), loop(f₂, x̄, W(f₂)))        // an idle run
//! <loop>::bits::equiv : Π f x̄ Req_H. Eq(R, loop__bits(f, x̄), loop(f, x̄, W(f)))
//! ```
//!
//! `idle`'s arm `c` either has `f₂ = c` (both sides agree) or unfolds the
//! loop once — its idle test decided by `lz_ge` from the hypothesis — and
//! applies the induction hypothesis at `c − 1`. `equiv`'s arm `c` unfolds
//! both sides and splits their shared tests: the idle arm is the induction
//! hypothesis at the jump target (below `c`: `min`) followed by `idle`
//! (its hypothesis from `lz_lower` and `min`), the other arms step in
//! lockstep to the induction hypothesis at `c − 1`. The call site uses an
//! entry wrapper `loop__bits_entry(d̄) = loop__bits(statics, d̄)` linked by
//! `equiv` at the call's static arguments (`W(K) = w₀`).
//!
//! Selection: after the closed form and the early exit (a loop without a
//! `FirstMatch` payload), or forced by `LoopConfig::prefer_set_bits`
//! (tests); the cost model (plan O8) is to weigh it against the early exit
//! (3.76 ns at N = 1 but 32.5 ns at N = 32 measured). Calibrated on QMDB
//! only: those timings are the development set's (QMDB's `shape_go`), and
//! the rung order awaits held-out numbers.

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{GlobalId, Lvl, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, Neutral, V, Value};

use super::classify::{Class, Loop};
use super::enumerate::{self, ArmProver, EnumSpec, Ih};
use super::{LoopFailure, LoopHelper, LoopKey};
use crate::auto::bitlib::{self, Family};
use crate::auto::search::{Engine, R};
use crate::auto::state::St;
use crate::auto::util::{apps, as_eq};
use crate::hir::*;

/// The set-bit rung's plan (see the module docs): parameter indices.
#[derive(Clone, Debug)]
pub struct SetBits {
    pub fuel: u32,
    pub v: u32,
    pub wp: u32,
    pub w0: u128,
    pub k: u32,
    pub s0: u32,
    pub fw: Width,
    pub vw: Width,
    pub ww: Width,
}

/// Plans the rung for the classified loop (see the module docs).
pub fn plan(lp: &Loop, fuel: u32) -> Result<SetBits, String> {
    let n = lp.params.len() as u32;
    let k = lp.k;
    let bd: Vec<(u32, u32, u32)> = (0..n).filter_map(|i| match lp.classes[i as usize] { Class::BitDigit { wp, e } => Some((i, wp, e)), _ => None }).collect();
    let [(v, wp, e)] = bd[..] else { return Err("no single BitDigit variable".into()) };
    if lp.classes[fuel as usize] != Class::Static {
        return Err("the fuel is not static".into());
    }
    // the fuel counts down from K to 0, the width halves from 2^e
    let num = |j: usize, i: u32| lp.static_seq.get(j).and_then(|s| s.get(i as usize)).and_then(|x| x.as_ref()).and_then(|x| x.num());
    for jj in 0..=k as usize {
        if num(jj, fuel) != Some((k as usize - jj) as u128) {
            return Err("the fuel does not count down to 0".into());
        }
    }
    let w0 = num(0, wp).ok_or("the width")?;
    let s0 = k.checked_sub(e).filter(|s| *s >= 1).ok_or("the width does not reach 1 before the exhaustion")?;
    // only the fuel and the width are static; the idle paths change nothing else
    for i in 0..n {
        if lp.classes[i as usize] == Class::Static && i != fuel && i != wp {
            return Err("another static parameter".into());
        }
    }
    let vw = lp.params[v as usize].width.ok_or("v")?;
    let ww = lp.params[wp as usize].width.ok_or("w")?;
    let fw = lp.params[fuel as usize].width.ok_or("fuel")?;
    let idle = |c: &super::classify::ContPath| {
        c.guards.iter().any(|(g, b)| *b && matches!(&**g, super::expr::CE::Op(PrimOp::Lt(_), a) if a[0] == super::expr::var(v, vw) && a[1] == super::expr::var(wp, ww)))
    };
    for c in lp.cont.iter().filter(|c| idle(c)) {
        for i in 0..n {
            if i == fuel || i == wp {
                continue;
            }
            let keeps = match &c.next[i as usize] {
                super::classify::SVal::Param(p) => *p == i,
                super::classify::SVal::Ce(e) => matches!(&**e, super::expr::CE::Var(p, _) if *p == i),
                _ => false,
            };
            if !keeps {
                return Err("an idle iteration changes more than the fuel and the width".into());
            }
        }
    }
    // any machine width: the jump and the idle lemma are stated at `B − 1`
    // for `B` the width of `v` (`lz` and its stdlib lemmas exist per width)
    if vw == Width::Int || uint(vw).is_none() {
        return Err("a BitDigit variable that is not a machine integer".into());
    }
    Ok(SetBits { fuel, v, wp, w0, k, s0, fw, vw, ww })
}

fn expr_bits(w: Width) -> u32 {
    super::expr::bits(w)
}

/// `B − 1` for `B` the width of `w` in bits (the index of its top bit).
fn top_bit(w: Width) -> u32 {
    expr_bits(w) - 1
}

// ---------------------------------------------------------------------------
// The helper (HIR).
// ---------------------------------------------------------------------------

fn uint(w: Width) -> Option<UintTy> {
    Some(match w {
        Width::U8 => UintTy::U8,
        Width::U16 => UintTy::U16,
        Width::U32 => UintTy::U32,
        Width::U64 => UintTy::U64,
        Width::Usize => UintTy::Usize,
        Width::Int => return None,
    })
}

fn lit(n: u128, w: Width, span: crate::span::Span) -> Expr {
    Expr::new(ExprKind::Lit(Lit::Int(n)), Ty::Uint(uint(w).unwrap()), span)
}

/// The helper's definition (see the module docs); `fault`: the jump one
/// fuel too far (the must-reject suite).
fn helper_fn(fd: &FnDef, fid: ItemId, hid: ItemId, sb: &SetBits, fault: bool, span: crate::span::Span) -> Result<FnDef, String> {
    let local = |i: u32| -> Result<(LocalId, Ty), String> {
        match &fd.params.get(i as usize).ok_or("a parameter")?.pat.kind {
            PatKind::Binding { local, sub: None, .. } => Ok((*local, fd.params[i as usize].ty.clone())),
            _ => Err("a parameter pattern".into()),
        }
    };
    let (fl, ft) = local(sb.fuel)?;
    let (vl, vt) = local(sb.v)?;
    let (wl, wt) = local(sb.wp)?;
    let FnBody::Exec(body) = &fd.body else { return Err("no exec body".into()) };
    let mut src = body.clone();
    crate::opt::multiversion::rename_calls(&mut src, &|i| (i == fid).then_some(hid));
    let loc = |l: LocalId, t: &Ty| Expr::new(ExprKind::Local(l), t.clone(), span);
    let bin = |op: BinOp, a: Expr, b: Expr, t: Ty| Expr::new(ExprKind::Binary(op, Box::new(a), Box::new(b)), t, span);
    let call_int = |m: crate::builtins::IntMethod, w: UintTy, args: Vec<Expr>, t: Ty| Expr::new(ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Int(m, w), vec![]), args }, t, span);
    // the jump: min(f − 1, B − 1 + s₀ − lz(v)); the fault (R29) one fuel too
    // far down, past the set bit
    let lz = call_int(crate::builtins::IntMethod::LeadingZeros, uint(sb.vw).unwrap(), vec![loc(vl, &vt)], Ty::u32());
    let tgt32 = bin(BinOp::Sub, lit(sb.s0 as u128 + top_bit(sb.vw) as u128, Width::U32, span), lz, Ty::u32());
    let tgt32 = if fault { call_int(crate::builtins::IntMethod::SaturatingSub, UintTy::U32, vec![tgt32, lit(1, Width::U32, span)], Ty::u32()) } else { tgt32 };
    let tgt = if sb.fw == Width::U32 { tgt32 } else { Expr::new(ExprKind::Cast(Box::new(tgt32), ft.clone()), ft.clone(), span) };
    let fm1 = bin(BinOp::Sub, loc(fl, &ft), lit(1, sb.fw, span), ft.clone());
    let f2 = call_int(crate::builtins::IntMethod::Min, uint(sb.fw).unwrap(), vec![fm1, tgt], ft.clone());
    // the width at the target: w₀ >> (K − f₂), in the wrapping operations
    // of the lemmas' `W(f)` (the same values: f₂ ≤ K; no checks printed)
    let f2_id = LocalId(fd.locals.len() as u32);
    let f2_loc = Expr::new(ExprKind::Local(f2_id), ft.clone(), span);
    let kf = call_int(crate::builtins::IntMethod::WrappingSub, uint(sb.fw).unwrap(), vec![lit(sb.k as u128, sb.fw, span), f2_loc.clone()], ft.clone());
    let kf32 = if sb.fw == Width::U32 { kf } else { Expr::new(ExprKind::Cast(Box::new(kf), Ty::u32()), Ty::u32(), span) };
    let w_at = call_int(crate::builtins::IntMethod::WrappingShr, uint(sb.ww).unwrap(), vec![lit(sb.w0, sb.ww, span), kf32], wt.clone());
    let mut jargs = Vec::new();
    for (i, p) in fd.params.iter().enumerate() {
        if i as u32 == sb.wp {
            jargs.push(w_at.clone());
            continue;
        }
        if i as u32 == sb.fuel {
            jargs.push(f2_loc.clone());
            continue;
        }
        let PatKind::Binding { local, .. } = &p.pat.kind else { return Err("a parameter pattern".into()) };
        jargs.push(loc(*local, &p.ty));
    }
    let ret = body.ty.clone();
    let jump = Expr::new(ExprKind::Call { callee: Callee::Item(hid, vec![]), args: jargs }, ret.clone(), span);
    let f2_pat = Pat { kind: PatKind::Binding { local: f2_id, mode: BindingMode::ByValue, sub: None }, ty: ft.clone(), span };
    let then = Expr::new(ExprKind::Block(Block { stmts: vec![Stmt { kind: StmtKind::Let { pat: f2_pat, init: f2, els: None }, span }], tail: Some(Box::new(jump)), span }), ret.clone(), span);
    let nz = bin(BinOp::Ne, loc(fl, &ft), lit(0, sb.fw, span), Ty::Bool);
    let idle = bin(BinOp::Lt, loc(vl, &vt), loc(wl, &wt), Ty::Bool);
    let cond = bin(BinOp::And, nz, idle, Ty::Bool);
    let els = Expr::new(ExprKind::Block(Block { stmts: vec![], tail: Some(Box::new(src)), span }), ret.clone(), span);
    let body2 = Expr::new(ExprKind::If { cond: Box::new(cond), then: Box::new(then), els: Some(Box::new(els)) }, ret, span);
    let mut hf = fd.clone();
    hf.locals.push(LocalDecl { name: "next_fuel".into(), ty: ft.clone(), mutable: false, ghost: false, span });
    let le = bin(BinOp::Le, loc(fl, &ft), lit(sb.k as u128, sb.fw, span), Ty::Bool);
    hf.requires.push(Expr::new(ExprKind::Coerce(Coercion::BoolToProp, Box::new(le)), Ty::Prop, span));
    hf.body = FnBody::Exec(body2);
    hf.ensures = None;
    hf.specialize = false;
    hf.implements = None;
    hf.inline = None;
    Ok(hf)
}

// ---------------------------------------------------------------------------
// The lemmas.
// ---------------------------------------------------------------------------

fn eval_in(env: &Env, ctx: &Ctx, t: &Tm) -> Result<V, String> {
    env.eval(&env.ctx_venv(ctx), ctx.depth(), t, &mut Budget { steps: 100_000_000 }).map_err(|e| format!("eval: {e:?}"))
}

/// A closed Π statement from the binders of `st` (their types at their
/// levels) and a conclusion value.
fn close(env: &Env, st: &St, concl: &V) -> Tm {
    let d = st.depth();
    let mut t = env.quote(Lvl(d), concl, false);
    for (i, e) in st.ctx.entries.iter().enumerate().rev() {
        t = mk::pi(&e.name, e.rel, env.quote(Lvl(i as u32), &e.ty, false), t);
    }
    t
}

/// A folded application (a neutral) of `g`.
fn app(g: GlobalId, args: Vec<Arg>) -> V {
    Rc::new(Value::Neu(Neutral { head: Head::Global { def: g, args }, spine: vec![] }))
}

/// `w₀ >> (K − f)` as a value (`f` a fuel value).
fn width_at(env: &Env, sb: &SetBits, st: &St, f: &V) -> Result<V, String> {
    let f_tm = st.quote(env, f);
    let kf = Rc::new(Term::Prim { op: PrimOp::WSub(sb.fw), args: vec![mk::lit(sb.fw, sb.k), f_tm], proofs: vec![] });
    let kf32 = if sb.fw == Width::U32 { kf } else { Rc::new(Term::Prim { op: PrimOp::Cast { from: sb.fw, to: Width::U32 }, args: vec![kf], proofs: vec![] }) };
    let t = Rc::new(Term::Prim { op: PrimOp::WShr(sb.ww), args: vec![mk::lit(sb.ww, sb.w0), kf32], proofs: vec![] });
    eval_in(env, &st.ctx, &t)
}

/// Pushes the loop's `requires` at the relevant arguments `rel` (by
/// parameter) as named irrelevant binders; returns their entries' args.
fn push_requires(env: &Env, st: &mut St, def: GlobalId, rel: &[V], tag: &str) -> Result<Vec<Arg>, String> {
    let tele = crate::opt::symex::telescope(env, def).ok_or("no telescope")?;
    let mut vals: Vec<EnvEntry> = rel.iter().map(|v| EnvEntry::Rel(v.clone())).collect();
    let mut out = Vec::new();
    for (i, (_, r, dom)) in tele.binders.iter().enumerate().skip(rel.len()) {
        if *r != Rel::Irr {
            return Err("a relevant binder after the parameters".into());
        }
        let ty = env.eval(&sandblaster_kernel::value::VEnv(Rc::new(vals.clone())), Lvl(st.depth()), dom, &mut Budget { steps: 20_000_000 }).map_err(|e| format!("{e:?}"))?;
        let lvl = st.depth();
        let e = st.push_raw(env, Rc::from(format!("{tag}{}", i - rel.len()).as_str()), Rel::Irr, ty.clone());
        st.add_ctx_fact(lvl, ty, crate::auto::state::Origin::Intro);
        out.push(crate::auto::util::entry_arg(&e));
        vals.push(e);
    }
    Ok(out)
}

/// Proves an irrelevant binder's type in `st`: conversion, an assumption,
/// linear arithmetic with `extra` hints, `auto`.
fn obligation(e: &mut Engine<'_>, st: &St, dom: &V, extra: &[(Tm, V)]) -> Option<Tm> {
    let env = e.env;
    if let Some(p) = super::lemmas::trivial(env, &st.ctx, dom, &mut Budget { steps: 10_000_000 }) {
        return Some(p);
    }
    let mut st2 = st.child();
    for (p, ty) in extra {
        st2.push_fact(env, ty.clone(), crate::auto::util::shift(p, (st2.depth() - st.depth()) as i64), crate::auto::state::Origin::Hint);
    }
    if let Ok(Some(p)) = e.lin_prove(&st2, dom, true) {
        return Some(st2.finish(e.promote(&st2, dom, p)));
    }
    match e.solve(&st2, dom.clone(), true) {
        Ok(Some(p)) => Some(st2.finish(p)),
        _ => None,
    }
}

/// [`obligation`]; under a simulated fault (`trust`) linear arithmetic
/// only, then a certificate-free claim the kernel judges with the lemma
/// (the fault's false goals are not searched to exhaustion).
fn prove_or_claim(e: &mut Engine<'_>, st: &St, dom: &V, extra: &[(Tm, V)], trust: bool) -> Option<Tm> {
    let env = e.env;
    if !trust {
        return obligation(e, st, dom, extra);
    }
    if let Some(p) = super::lemmas::trivial(env, &st.ctx, dom, &mut Budget { steps: 10_000_000 }) {
        return Some(p);
    }
    let mut st2 = st.child();
    for (p, ty) in extra {
        st2.push_fact(env, ty.clone(), crate::auto::util::shift(p, (st2.depth() - st.depth()) as i64), crate::auto::state::Origin::Hint);
    }
    if let Ok(Some(p)) = e.lin_prove(&st2, dom, true) {
        return Some(st2.finish(e.promote(&st2, dom, p)));
    }
    Some(Rc::new(Term::Linarith { hyps: vec![], goal: env.quote_typed(&st.ctx, dom, None, false), cert: vec![] }))
}

/// A boolean test decided: linear arithmetic (with `extra` as facts) for
/// either value first, the full search only then (not under a simulated
/// fault, `lin_only`); the value and the proof of `Eq(Bool, c, value)`.
fn decide_test(e: &mut Engine<'_>, st: &St, c_tm: &Tm, extra: &[(Tm, V)], lin_only: bool) -> Option<(bool, Tm)> {
    let env = e.env;
    let bi = env.bool_ind();
    let goals: Vec<(bool, V)> = [true, false].iter().filter_map(|&want| eval_in(env, &st.ctx, &mk::eq(mk::bool_ty(bi), c_tm.clone(), mk::bool_lit(bi, want))).ok().map(|g| (want, g))).collect();
    let mut st2 = st.child();
    for (p, ty) in extra {
        st2.push_fact(env, ty.clone(), crate::auto::util::shift(p, (st2.depth() - st.depth()) as i64), crate::auto::state::Origin::Hint);
    }
    for (want, g) in &goals {
        if let Some(p) = super::lemmas::trivial(env, &st.ctx, g, &mut Budget { steps: 10_000_000 }) {
            return Some((*want, p));
        }
        if let Ok(Some(p)) = e.lin_prove(&st2, g, true) {
            return Some((*want, st2.finish(e.promote(&st2, g, p))));
        }
    }
    if lin_only {
        return None;
    }
    for (want, g) in &goals {
        if let Ok(Some(p)) = e.solve(&st2, g.clone(), true) {
            return Some((*want, st2.finish(p)));
        }
    }
    None
}

/// The first stuck match of a value: scrutinee, inductive, parameters.
fn first_match(v: &V) -> Option<(V, sandblaster_kernel::term::IndId, Vec<V>)> {
    let Value::Neu(n) = &**v else { return None };
    let i = n.spine.iter().position(|e| matches!(e, Elim::Match { .. }))?;
    let Elim::Match { ind, params, .. } = &n.spine[i] else { return None };
    Some((crate::auto::util::prefix(n, i), *ind, params.clone()))
}

fn call_of(v: &V, g: GlobalId) -> Option<Vec<Arg>> {
    match &**v {
        Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if *def == g && spine.is_empty() => Some(args.clone()),
        _ => None,
    }
}

/// Hints for `v`'s magnitude: `lz_lower_k` (from `v < 2^k`) and `lz_ge_k`
/// (from `w − k ≤ lz(v)`) for every `k` whose hypothesis linear arithmetic
/// proves.
fn lz_hints(e: &mut Engine<'_>, st: &St, v: &V, vw: Width, lower: bool) -> Vec<(Tm, V)> {
    let env = e.env;
    let bi = env.bool_ind();
    let v_tm = st.quote(env, v);
    let bits = expr_bits(vw);
    let mut out = Vec::new();
    // binary search for the tightest k (monotone in k)
    let hyp = |k: u32| -> Tm {
        if lower {
            mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Lt(vw), args: vec![v_tm.clone(), mk::lit(vw, 1u128 << k)], proofs: vec![] }), mk::bool_lit(bi, true))
        } else {
            let lz = Rc::new(Term::Prim { op: PrimOp::LeadingZeros(vw), args: vec![v_tm.clone()], proofs: vec![] });
            mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Le(Width::U32), args: vec![mk::lit(Width::U32, bits - k), lz], proofs: vec![] }), mk::bool_lit(bi, true))
        }
    };
    let proves = |e: &mut Engine<'_>, k: u32| -> Option<Tm> {
        let g = eval_in(env, &st.ctx, &hyp(k)).ok()?;
        match e.lin_prove(st, &g, true) {
            Ok(Some(p)) => Some(e.promote(st, &g, p)),
            _ => None,
        }
    };
    let (mut lo, mut hi) = (0u32, bits - 1);
    let mut best: Option<(u32, Tm)> = None;
    while lo <= hi {
        let m = (lo + hi) / 2;
        match proves(e, m) {
            Some(p) => {
                best = Some((m, p));
                if m == 0 {
                    break;
                }
                hi = m - 1;
            }
            None => lo = m + 1,
        }
    }
    if let Some((k, p)) = best {
        let fam = if lower { Family::LzLower } else { Family::LzGe };
        if let Some(g) = env.lookup_global(&bitlib::lemma_name(fam, vw, k)) {
            let t = apps(mk::global(g), [(Rel::Rel, v_tm.clone()), (Rel::Irr, p)]);
            if let Ok(ty) = env.infer(&st.ctx, &t, &mut Budget { steps: 5_000_000 }) {
                out.push((t, ty));
            }
        }
    }
    out
}

/// `idle`'s arms (see the module docs).
struct IdleArms<'a> {
    def: GlobalId,
    sb: &'a SetBits,
    /// Telescope positions: f₂ and `v` (the idle lemma's binders).
    f2: usize,
    v: usize,
    /// The loop's relevant parameters (count).
    np: usize,
    /// For each relevant loop parameter: its idle-lemma binder (`None` for
    /// the fuel and the width).
    xmap: Vec<Option<usize>>,
    trust: bool,
    failure: Option<String>,
}

impl IdleArms<'_> {
    fn note(&mut self, env: &Env, st: &St, what: &str, v: &V) {
        if self.failure.is_none() {
            let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
            self.failure = Some(format!("{what}: {}", crate::elab::show::value(env, &names, v, 600)));
        }
    }
}

impl IdleArms<'_> {
    /// f₂ = c: both sides the same loop state (proofs apart).
    fn same_state(&mut self, e2: &mut Engine<'_>, a2: &mut St, tk: &V, f2: &V, c: u32) -> R<Option<Tm>> {
        let env = e2.env;
        let fw = self.sb.fw;
        let g: V = Rc::new(Value::Eq { ty: Rc::new(Value::IntTy(fw)), lhs: f2.clone(), rhs: Rc::new(Value::Lit { w: fw, n: sandblaster_kernel::term::BigInt::from(c) }) });
        let Some(p) = e2.lin_prove(a2, &g, true)?.map(|p| e2.promote(a2, &g, p)) else {
            self.note(env, a2, "f₂ is not pinned", &g);
            return Ok(None);
        };
        let litv: V = Rc::new(Value::Lit { w: fw, n: sandblaster_kernel::term::BigInt::from(c) });
        let Some((ch, t2, w)) = enumerate::rewrite_intro(e2, a2, tk, &Rc::new(Value::IntTy(fw)), f2, &litv, p)? else { return Ok(None) };
        Ok(super::lemmas::trivial(env, &ch.ctx, &t2, &mut Budget { steps: 50_000_000 }).map(w))
    }
}

impl ArmProver for IdleArms<'_> {
    fn failure(&self) -> Option<String> {
        self.failure.clone()
    }

    fn arm(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, c: u32, ih: &Ih) -> R<Option<Tm>> {
        let env = e.env;
        let bi = env.bool_ind();
        let fw = self.sb.fw;
        let f2 = match &st.venv.0[self.f2] {
            EnvEntry::Rel(v) => v.clone(),
            _ => return Ok(None),
        };
        let f2_tm = st.quote(env, &f2);
        // (at c = 0, f₂ ≤ c pins f₂: no idle iteration)
        if c == 0 {
            return self.same_state(e, st, goal, &f2, c);
        }
        // split on f₂ < c
        let test = Rc::new(Term::Prim { op: PrimOp::Lt(fw), args: vec![f2_tm, mk::lit(fw, c)], proofs: vec![] });
        let Ok(tv) = eval_in(env, &st.ctx, &test) else { return Ok(None) };
        let d = st.depth_left;
        // (the arm's proof first: the contradiction search over these
        // facts — magnitudes near 2^62 — is the costly step, and the arms
        // are rarely contradictory)
        let mut attempt = |e2: &mut Engine<'_>, a2: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
            let env = e2.env;
            if k == 0 {
                return self.same_state(e2, a2, &tk, &f2, c);
            }
            // f₂ < c: unfold the loop at c once (an idle iteration)
            let Some((rty, lhs, rhs)) = as_eq(&tk) else { return Ok(None) };
            let (rty, lhs, rhs) = (rty.clone(), lhs.clone(), rhs.clone());
            let Some(largs) = call_of(&lhs, self.def) else {
                self.note(env, a2, "the left side is not the loop", &tk);
                return Ok(None);
            };
            let lhs_tm = a2.quote(env, &lhs);
            let (ty_tm, rhs_tm) = (a2.quote(env, &rty), a2.quote(env, &rhs));
            let mut args = Vec::new();
            let mut h = &lhs_tm;
            while let Term::App { rel, fun, arg } = &**h {
                args.push((*rel, arg.clone()));
                h = fun;
            }
            args.reverse();
            let _ = largs;
            let body = apps(env.global_body(self.def).ok_or(crate::auto::search::Stop::Budget)?, args.clone());
            let delta = Rc::new(Term::Delta { def: self.def, args: args.iter().map(|(_, a)| a.clone()).collect() });
            let Ok(g1) = eval_in(env, &a2.ctx, &mk::eq(ty_tm.clone(), body.clone(), rhs_tm.clone())) else { return Ok(None) };
            // the idle test v < W(c), from B − 1 + s₀ − f₂ ≤ lz(v) and f₂ < c
            let v = match &a2.venv.0[self.v] {
                EnvEntry::Rel(v) => v.clone(),
                _ => return Ok(None),
            };
            let hints = lz_hints(e2, a2, &v, self.sb.vw, false);
            let mut cur = g1;
            // the tests decided and rewritten by the engine's checked
            // motive (the body's proofs mention them: the dependent-match
            // idiom's path equations, checked arithmetic's certificates),
            // each in a child state (its equation binder introduced)
            let mut ws = a2.child();
            let mut wraps: Vec<super::lemmas::Wrap> = Vec::new();
            for _ in 0..6 {
                let Some((_, l, _)) = as_eq(&cur) else { break };
                if call_of(l, self.def).is_some() {
                    break;
                }
                let Some((cnd, ind, _)) = first_match(l) else { break };
                if ind != bi {
                    break;
                }
                let bt = mk::bool_ty(bi);
                let btv: V = Rc::new(Value::Ind { ind: bi, params: vec![] });
                let c_tm = ws.quote(env, &cnd);
                let mut done = false;
                let hs: Vec<(Tm, V)> = hints.iter().map(|(p, t)| (crate::auto::util::shift(p, (ws.depth() - a2.depth()) as i64), t.clone())).collect();
                let decided = decide_test(e2, &ws, &c_tm, &hs, self.trust).or_else(|| {
                    // a simulated fault's claim (the idle test true): the kernel judges it
                    self.trust.then(|| eval_in(env, &ws.ctx, &mk::eq(bt.clone(), c_tm.clone(), mk::bool_lit(bi, true))).ok()).flatten().map(|g| (true, Rc::new(Term::Linarith { hyps: vec![], goal: env.quote_typed(&ws.ctx, &g, None, false), cert: vec![] }) as Tm))
                });
                if let Some((want, p)) = decided {
                    let litv: V = Rc::new(Value::Ctor { ind: bi, ctor: want as u32, params: vec![], args: vec![] });
                    if let Some((ch, t2, w)) = enumerate::rewrite_intro(e2, &ws, &cur, &btv, &cnd, &litv, p)? {
                        cur = t2;
                        ws = ch;
                        wraps.push(w);
                        done = true;
                    }
                }
                if !done {
                    self.note(env, &ws, "an idle iteration's test", &cnd);
                    return Ok(None);
                }
            }
            let Some((_, l, _)) = as_eq(&cur) else { return Ok(None) };
            let p = match call_of(l, self.def) {
                None => {
                    // the next call at a literal fuel evaluated away (the
                    // last iteration): f₂ is pinned to c − 1, both sides
                    // that state
                    match self.same_state(e2, &mut ws, &cur, &f2, c - 1)? {
                        Some(p) => p,
                        None => {
                            self.failure = None;
                            self.note(env, &ws, &format!("an idle iteration that is not the next one (at {c})"), &cur);
                            return Ok(None);
                        }
                    }
                }
                Some(next) => {
                    // the induction hypothesis at c − 1: f, f₂, x̄ from the call
                    let rel: Vec<V> = next.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
                    let mut rel_vals = vec![rel[self.sb.fuel as usize].clone(), f2.clone()];
                    for i in 0..self.np {
                        if self.xmap[i].is_some() {
                            rel_vals.push(rel[i].clone());
                        }
                    }
                    let trust = self.trust;
                    let mut prove = |e3: &mut Engine<'_>, s3: &St, dom: &V, _n: &str| -> Option<Tm> {
                        prove_or_claim(e3, s3, dom, &[], trust)
                    };
                    match ih.apply(e2, &ws, rel_vals, &mut prove)? {
                        Some(p) => p,
                        None => {
                            self.note(env, &ws, "the induction hypothesis of an idle run", &cur);
                            return Ok(None);
                        }
                    }
                }
            };
            let mut p = p;
            while let Some(w) = wraps.pop() {
                p = w(p);
            }
            let trans = env.lookup_global("eq::trans").expect("eq::trans");
            Ok(Some(apps(mk::global(trans), [(Rel::Rel, ty_tm), (Rel::Rel, lhs_tm), (Rel::Rel, body), (Rel::Rel, rhs_tm), (Rel::Rel, delta), (Rel::Rel, p)])))
        };
        let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
            if let Some(p) = attempt(e2, a2, tk.clone(), k)? {
                return Ok(Some(p));
            }
            let mut ch = a2.child();
            if let Ok(Some(p)) = e2.contradiction(&mut ch) {
                return Ok(Some(e2.absurd(a2, &tk, ch.finish(p))));
            }
            Ok(None)
        };
        e.case_split_with(st, &tv, bi, &[], goal, true, d, &mut arm_fn)
    }
}

/// `equiv`'s arms (see the module docs).
struct EquivArms<'a> {
    def: GlobalId,
    h: GlobalId,
    idle: GlobalId,
    sb: &'a SetBits,
    /// Its binder of `v`.
    hv: usize,
    trust: bool,
    failure: Option<String>,
}

impl EquivArms<'_> {
    fn note(&mut self, env: &Env, st: &St, what: &str, v: &V) {
        if self.failure.is_none() {
            let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
            self.failure = Some(format!("{what}: {}", crate::elab::show::value(env, &names, v, 600)));
        }
    }

    /// A jump whose loop side (fuel c − 1) evaluated away (the last
    /// iteration): IH(f₂)'s right side `loop(f₂, …)` unfolded (`delta`),
    /// its tests decided by linear arithmetic (`f₂ = c − 1` with the `lz`
    /// hints) and rewritten, then closed by evaluation.
    #[allow(clippy::too_many_arguments)]
    fn jump_to_last(&mut self, e: &mut Engine<'_>, st: &St, goal: &V, c: u32, rel: &[V], hints: &[(Tm, V)], p_ih: &Tm, ih_ty: &V) -> Option<Tm> {
        let env = e.env;
        let bi = env.bool_ind();
        let (rty, l, r) = as_eq(goal)?;
        let Some((_, _, mid)) = as_eq(ih_ty) else {
            self.note(env, st, "the induction hypothesis' statement", ih_ty);
            return None;
        };
        let _ = (rel, c);
        let (ty_tm, l_tm, mid_tm, r_tm) = (st.quote(env, rty), st.quote(env, l), st.quote(env, mid), st.quote(env, r));
        // loop(f₂, …) = its body
        let mut args = Vec::new();
        let mut h = &mid_tm;
        while let Term::App { rel, fun, arg } = &**h {
            args.push((*rel, arg.clone()));
            h = fun;
        }
        args.reverse();
        if !matches!(&**h, Term::Global(g) if *g == self.def) {
            self.note(env, st, "the induction hypothesis' right side is not the loop", mid);
            return None;
        }
        let body = apps(env.global_body(self.def)?, args.clone());
        let delta = Rc::new(Term::Delta { def: self.def, args: args.iter().map(|(_, a)| a.clone()).collect() });
        let mut cur = eval_in(env, &st.ctx, &mk::eq(ty_tm.clone(), body.clone(), r_tm.clone())).ok()?;
        let mut ws = st.child();
        let mut wraps: Vec<super::lemmas::Wrap> = Vec::new();
        let btv: V = Rc::new(Value::Ind { ind: bi, params: vec![] });
        for _ in 0..4 {
            if super::lemmas::trivial(env, &ws.ctx, &cur, &mut Budget { steps: 20_000_000 }).is_some() {
                break;
            }
            let Some((_, cl, _)) = as_eq(&cur) else { break };
            let Some((cnd, ind, _)) = first_match(cl) else { break };
            if ind != bi {
                break;
            }
            let c_tm = ws.quote(env, &cnd);
            let hs: Vec<(Tm, V)> = hints.iter().map(|(p, t)| (crate::auto::util::shift(p, (ws.depth() - st.depth()) as i64), t.clone())).collect();
            let mut done = false;
            if let Some((want, p)) = decide_test(e, &ws, &c_tm, &hs, self.trust) {
                let litv: V = Rc::new(Value::Ctor { ind: bi, ctor: want as u32, params: vec![], args: vec![] });
                if let Ok(Some((ch, t2, w))) = enumerate::rewrite_intro(e, &ws, &cur, &btv, &cnd, &litv, p) {
                    cur = t2;
                    ws = ch;
                    wraps.push(w);
                    done = true;
                }
            }
            if !done {
                self.note(env, &ws, "the last iteration's test", &cnd);
                return None;
            }
        }
        let Some(mut q) = super::lemmas::trivial(env, &ws.ctx, &cur, &mut Budget { steps: 50_000_000 }) else {
            self.note(env, &ws, "the last iteration's two sides", &cur);
            return None;
        };
        while let Some(w) = wraps.pop() {
            q = w(q);
        }
        // mid = body = r
        let trans = env.lookup_global("eq::trans")?;
        let q = apps(mk::global(trans), [(Rel::Rel, ty_tm.clone()), (Rel::Rel, mid_tm.clone()), (Rel::Rel, body), (Rel::Rel, r_tm.clone()), (Rel::Rel, delta), (Rel::Rel, q)]);
        Some(apps(mk::global(trans), [(Rel::Rel, ty_tm), (Rel::Rel, l_tm), (Rel::Rel, mid_tm), (Rel::Rel, r_tm), (Rel::Rel, p_ih.clone()), (Rel::Rel, q)]))
    }

    /// Both bodies from the split on the idle test: shared tests split, the
    /// recursive calls by the induction hypothesis (and `idle` at the jump).
    fn walk(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, c: u32, ih: &Ih, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        if let Some(p) = super::lemmas::trivial(env, &st.ctx, goal, &mut Budget { steps: 50_000_000 }) {
            return Ok(Some(p));
        }
        let Some((rty, l, r)) = as_eq(goal) else { return Ok(None) };
        let (rty, l, r) = (rty.clone(), l.clone(), r.clone());
        if let Some(hargs) = call_of(&l, self.h) {
            let rel: Vec<V> = hargs.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
            let fuel_next = rel.get(self.sb.fuel as usize).cloned();
            let peak = fuel_next.as_ref().is_some_and(|f| matches!(&**f, Value::Lit { .. }));
            // (the induction hypothesis' binders: the parameters without the width)
            let ih_vals: Vec<V> = rel.iter().enumerate().filter(|(i, _)| *i != self.sb.wp as usize).map(|(_, x)| x.clone()).collect();
            // (at the jump, the target `min(c − 1, B − 1 + s₀ − lz(v))`: linear
            // arithmetic reads `min` by its definition once `lz_lower` bounds
            // `lz(v)` — for the induction hypothesis' requires and decrease
            // as for `idle`'s hypotheses)
            let hints = if peak { Vec::new() } else { lz_hints(e, st, &rel[self.hv], self.sb.vw, true) };
            let trust = self.trust;
            let hs = hints.clone();
            let mut prove = move |e3: &mut Engine<'_>, s3: &St, dom: &V, _n: &str| -> Option<Tm> { prove_or_claim(e3, s3, dom, &hs, trust) };
            let Some((p_ih, ih_ty)) = ih.apply_typed(e, st, ih_vals, &mut prove)? else {
                self.note(env, st, "the induction hypothesis", goal);
                return Ok(None);
            };
            if peak {
                return Ok(Some(p_ih));
            }
            let Some(rargs) = call_of(&r, self.def) else {
                // the loop's side at the literal fuel c − 1 evaluated away
                // (the last iteration): the jump target is pinned to c − 1
                // and IH(f₂)'s right side is that state
                return Ok(self.jump_to_last(e, st, goal, c, &rel, &hints, &p_ih, &ih_ty));
            };
            // the jump: IH(f₂) then `idle(c − 1, f₂)` reversed
            let rrel: Vec<V> = rargs.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
            let Some(mut cur) = env.global_type_value(self.idle) else { return Ok(None) };
            let mut iargs: Vec<(Rel, Tm)> = Vec::new();
            // f = c − 1 (the loop's call), f₂ (the helper's fuel), x̄ (the
            // other parameters but the width)
            let (fu, wp) = (self.sb.fuel as usize, self.sb.wp as usize);
            let mut rel_vals = vec![rrel[fu].clone(), rel[fu].clone()];
            rel_vals.extend(rel.iter().enumerate().filter(|(i, _)| *i != fu && *i != wp).map(|(_, x)| x.clone()));
            let mut ri = 0usize;
            while let Value::Pi { rel: rr, dom, cod, .. } = &*cur.clone() {
                let entry = match rr {
                    Rel::Rel => {
                        let Some(x) = rel_vals.get(ri).cloned() else { return Ok(None) };
                        ri += 1;
                        iargs.push((Rel::Rel, st.quote(env, &x)));
                        EnvEntry::Rel(x)
                    }
                    Rel::Irr => {
                        let p = prove_or_claim(e, st, dom, &hints, self.trust);
                        let Some(p) = p else {
                            self.note(env, st, "the idle run's hypothesis", dom);
                            return Ok(None);
                        };
                        iargs.push((Rel::Irr, p.clone()));
                        crate::auto::util::irr_entry(&st.venv, &p)
                    }
                };
                let Some(next) = e.inst(cod, vec![entry], st.depth())? else { return Ok(None) };
                cur = next;
            }
            let idle_app = apps(mk::global(self.idle), iargs);
            // idle_app : loop(c−1, …) = loop(f₂, …); p_ih : H(f₂) = loop(f₂, …)
            // (its statement by instantiation, not inference: a simulated
            // fault's claims are judged by the kernel with the lemma)
            let ity = cur;
            let Some((_, il, ir)) = as_eq(&ity) else { return Ok(None) };
            let (ty_tm, l_tm, mid_tm, r_tm) = (st.quote(env, &rty), st.quote(env, &l), st.quote(env, ir), st.quote(env, il));
            let (sym, trans) = (env.lookup_global("eq::sym").expect("sym"), env.lookup_global("eq::trans").expect("trans"));
            let back = apps(mk::global(sym), [(Rel::Rel, ty_tm.clone()), (Rel::Rel, r_tm.clone()), (Rel::Rel, mid_tm.clone()), (Rel::Rel, idle_app)]);
            return Ok(Some(apps(mk::global(trans), [(Rel::Rel, ty_tm), (Rel::Rel, l_tm), (Rel::Rel, mid_tm), (Rel::Rel, r_tm), (Rel::Rel, p_ih), (Rel::Rel, back)])));
        }
        if depth > 0
            && let Some((cnd, ind, params)) = first_match(&l).or_else(|| first_match(&r))
        {
            let d = st.depth_left;
            // (the walk first, the costly contradiction search after)
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
                if let Some(p) = self.walk(e2, a2, &tk, c, ih, depth - 1)? {
                    return Ok(Some(p));
                }
                let mut ch = a2.child();
                if let Ok(Some(p)) = e2.contradiction(&mut ch) {
                    return Ok(Some(e2.absurd(a2, &tk, ch.finish(p))));
                }
                Ok(None)
            };
            return e.case_split_with(st, &cnd, ind, &params, goal, true, d, &mut arm_fn);
        }
        self.note(env, st, "the two bodies differ", goal);
        Ok(None)
    }
}

/// Builds `idle` (see the module docs).
fn idle_lemma(env: &mut Env, def: GlobalId, sb: &SetBits, lp: &Loop, name: &str, trust: bool, fault: Option<enumerate::EnumFault>) -> Result<GlobalId, String> {
    let tele = crate::opt::symex::telescope(env, def).ok_or("no telescope")?;
    let np = lp.params.len();
    let bi = env.bool_ind();
    let (ty, xmap, vpos, f2pos) = {
        let envr: &Env = env;
        let mut st = St::new(envr, &Ctx::default(), 0);
        let mut vals: Vec<EnvEntry> = Vec::new();
        let f_ty = envr.eval(&Default::default(), Lvl(0), &tele.binders[sb.fuel as usize].2, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("{e:?}"))?;
        let f = st.push_raw(envr, Rc::from("f"), Rel::Rel, f_ty.clone());
        let f2 = st.push_raw(envr, Rc::from("f2"), Rel::Rel, f_ty);
        let mut xmap: Vec<Option<usize>> = vec![None; np];
        let mut vpos = 0usize;
        for i in 0..np {
            if i as u32 == sb.fuel || i as u32 == sb.wp {
                continue;
            }
            let dom = &tele.binders[i].2;
            let mut closed = true;
            crate::elab::tm::any_node(dom, &mut |n| {
                if matches!(n, Term::Var(_)) {
                    closed = false;
                }
                !closed
            });
            if !closed {
                return Err("a dependent parameter type".into());
            }
            let tv = envr.eval(&Default::default(), Lvl(0), dom, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("{e:?}"))?;
            xmap[i] = Some(st.depth() as usize);
            if i as u32 == sb.v {
                vpos = st.depth() as usize;
            }
            let x = st.push_raw(envr, tele.binders[i].0.clone(), Rel::Rel, tv);
            vals.push(x);
        }
        let _ = vals;
        let fv = match &f {
            EnvEntry::Rel(v) => v.clone(),
            _ => unreachable!(),
        };
        let f2v = match &f2 {
            EnvEntry::Rel(v) => v.clone(),
            _ => unreachable!(),
        };
        let prop = |st: &mut St, name: &str, t: Tm| -> Result<(), String> {
            let v = eval_in(envr, &st.ctx, &t)?;
            let lvl = st.depth();
            st.push_raw(envr, Rc::from(name), Rel::Irr, v.clone());
            st.add_ctx_fact(lvl, v, crate::auto::state::Origin::Intro);
            Ok(())
        };
        let fw = sb.fw;
        let f_tm = st.var(0);
        let f2_tm = st.var(1);
        prop(&mut st, "hb", mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Le(fw), args: vec![f_tm.clone(), mk::lit(fw, sb.k)], proofs: vec![] }), mk::bool_lit(bi, true)))?;
        let f_tm = st.var(0);
        let f2_tm2 = st.var(1);
        let _ = f2_tm;
        prop(&mut st, "hle", mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Le(fw), args: vec![f2_tm2, f_tm], proofs: vec![] }), mk::bool_lit(bi, true)))?;
        let f2_32 = if fw == Width::U32 { st.var(1) } else { Rc::new(Term::Prim { op: PrimOp::Cast { from: fw, to: Width::U32 }, args: vec![st.var(1)], proofs: vec![] }) };
        let lhs = Rc::new(Term::Prim { op: PrimOp::WSub(Width::U32), args: vec![mk::lit(Width::U32, top_bit(sb.vw) + sb.s0), f2_32], proofs: vec![] });
        let lz = Rc::new(Term::Prim { op: PrimOp::LeadingZeros(sb.vw), args: vec![st.var(vpos as u32)], proofs: vec![] });
        prop(&mut st, "hv", mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Le(Width::U32), args: vec![lhs, lz], proofs: vec![] }), mk::bool_lit(bi, true)))?;
        // the loop's arguments at f and at f₂
        let args_at = |st: &St, fv: &V| -> Result<Vec<V>, String> {
            let mut out = Vec::new();
            for i in 0..np {
                out.push(if i as u32 == sb.fuel {
                    fv.clone()
                } else if i as u32 == sb.wp {
                    width_at(envr, sb, st, fv)?
                } else {
                    match &st.venv.0[xmap[i].unwrap()] {
                        EnvEntry::Rel(v) => v.clone(),
                        _ => return Err("x".into()),
                    }
                });
            }
            Ok(out)
        };
        let a_f = args_at(&st, &fv)?;
        let h_f = push_requires(envr, &mut st, def, &a_f, "hf")?;
        let a_f2 = args_at(&st, &f2v)?;
        let h_f2 = push_requires(envr, &mut st, def, &a_f2, "hg")?;
        let mut la: Vec<Arg> = a_f.into_iter().map(Arg::Rel).collect();
        la.extend(h_f);
        let mut ra: Vec<Arg> = a_f2.into_iter().map(Arg::Rel).collect();
        ra.extend(h_f2);
        let r_ty = envr.eval(&sandblaster_kernel::value::VEnv(Rc::new(la.iter().map(crate::auto::util::arg_entry).collect())), Lvl(st.depth()), &tele.ret, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("{e:?}"))?;
        let concl: V = Rc::new(Value::Eq { ty: r_ty, lhs: app(def, la), rhs: app(def, ra) });
        (close(envr, &st, &concl), xmap, vpos, 1usize)
    };
    for k in 0..expr_bits(sb.vw) {
        let lim = super::meter::cap(400_000_000);
        let mut fb = Budget { steps: lim };
        let _ = bitlib::ensure(env, Family::LzGe, sb.vw, k, &mut fb);
        super::meter::charge(lim - fb.steps);
    }
    let _ = (tele, lp);
    let arity = {
        let mut a = 0u32;
        let mut t = &ty;
        while let Term::Pi { cod, .. } = &**t {
            a += 1;
            t = cod;
        }
        a
    };
    // the measure: `f` (the first binder)
    let spec = EnumSpec { name: name.to_string(), ty, f: 0, w: sb.fw, bound: sb.k, measure: mk::var(arity - 1), m_w: sb.fw, fault };
    let mut arms = IdleArms { def, sb, f2: f2pos, v: vpos, np, xmap, trust, failure: None };
    enumerate::build(env, &spec, &mut arms, 400_000_000)
}

/// Builds `equiv` (see the module docs).
#[allow(clippy::too_many_arguments)]
fn equiv_lemma(env: &mut Env, def: GlobalId, h: GlobalId, idle: GlobalId, sb: &SetBits, name: &str, trust: bool, fault: Option<enumerate::EnumFault>) -> Result<GlobalId, String> {
    let tele_h = crate::opt::symex::telescope(env, h).ok_or("the helper has no telescope")?;
    let tele_l = crate::opt::symex::telescope(env, def).ok_or("the loop has no telescope")?;
    let np_l = tele_l.binders.iter().take_while(|b| b.1 == Rel::Rel).count();
    let nr_l = tele_l.binders.len() - np_l;
    let np_h = tele_h.binders.iter().take_while(|b| b.1 == Rel::Rel).count();
    if np_h != np_l || tele_h.binders.len() < np_h + nr_l {
        return Err("the helper's telescope is not the loop's".into());
    }
    // binders: the parameters without the width (it is W(fuel)), then the
    // helper's requires at them
    let (ty, n) = {
        let envr: &Env = env;
        let mut st = St::new(envr, &Ctx::default(), 0);
        let mut vals: Vec<EnvEntry> = Vec::new();
        let mut fuel_v: Option<V> = None;
        for (i, (nm, rel, dom)) in tele_h.binders.iter().enumerate() {
            let tv = envr.eval(&sandblaster_kernel::value::VEnv(Rc::new(vals.clone())), Lvl(st.depth()), dom, &mut Budget { steps: 10_000_000 }).map_err(|e| format!("{e:?}"))?;
            if i == sb.wp as usize {
                let f = fuel_v.clone().ok_or("the fuel after the width")?;
                vals.push(EnvEntry::Rel(width_at(envr, sb, &st, &f)?));
                continue;
            }
            let lvl = st.depth();
            let e = st.push_raw(envr, nm.clone(), *rel, tv.clone());
            if *rel == Rel::Irr {
                st.add_ctx_fact(lvl, tv, crate::auto::state::Origin::Intro);
            }
            if i == sb.fuel as usize {
                fuel_v = match &e {
                    EnvEntry::Rel(v) => Some(v.clone()),
                    _ => None,
                };
            }
            vals.push(e);
        }
        let hargs: Vec<Arg> = vals.iter().map(crate::auto::util::entry_arg).collect();
        let mut la: Vec<Arg> = hargs[..np_l].to_vec();
        la.extend(hargs[np_h..np_h + nr_l].iter().cloned());
        let r_ty = envr.eval(&sandblaster_kernel::value::VEnv(Rc::new(vals.clone())), Lvl(st.depth()), &tele_h.ret, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("{e:?}"))?;
        let concl: V = Rc::new(Value::Eq { ty: r_ty, lhs: app(h, hargs), rhs: app(def, la) });
        (close(envr, &st, &concl), st.depth())
    };
    for k in 0..expr_bits(sb.vw) {
        let lim = super::meter::cap(400_000_000);
        let mut fb = Budget { steps: lim };
        let _ = bitlib::ensure(env, Family::LzLower, sb.vw, k, &mut fb);
        super::meter::charge(lim - fb.steps);
    }
    let hv = sb.v as usize;
    // the fuel's binder (the width's is not one)
    let fb = if sb.fuel > sb.wp { sb.fuel as usize - 1 } else { sb.fuel as usize };
    let spec = EnumSpec { name: name.to_string(), ty, f: fb, w: sb.fw, bound: sb.k, measure: mk::var(n - 1 - fb as u32), m_w: sb.fw, fault };
    struct Arms<'a>(EquivArms<'a>);
    impl ArmProver for Arms<'_> {
        fn failure(&self) -> Option<String> {
            self.0.failure.clone()
        }
        fn arm(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, c: u32, ih: &Ih) -> R<Option<Tm>> {
            let env = e.env;
            // unfold both sides (Delta), then walk
            let Some((rty, l, r)) = as_eq(goal) else { return Ok(None) };
            let (rty, l, r) = (rty.clone(), l.clone(), r.clone());
            let (ty_tm, l_tm, r_tm) = (st.quote(env, &rty), st.quote(env, &l), st.quote(env, &r));
            let split = |t: &Tm| -> Option<(GlobalId, Vec<(Rel, Tm)>)> {
                let mut args = Vec::new();
                let mut h = t;
                while let Term::App { rel, fun, arg } = &**h {
                    args.push((*rel, arg.clone()));
                    h = fun;
                }
                args.reverse();
                match &**h {
                    Term::Global(g) => Some((*g, args)),
                    _ => None,
                }
            };
            let (Some((hg, hargs)), Some((lg, largs))) = (split(&l_tm), split(&r_tm)) else {
                // (evaluation already unfolded a side: walk as it is)
                return self.0.walk(e, st, goal, c, ih, 16);
            };
            let hb = apps(env.global_body(hg).ok_or(crate::auto::search::Stop::Budget)?, hargs.clone());
            let lb = apps(env.global_body(lg).ok_or(crate::auto::search::Stop::Budget)?, largs.clone());
            let dh = Rc::new(Term::Delta { def: hg, args: hargs.iter().map(|(_, a)| a.clone()).collect() });
            let dl = Rc::new(Term::Delta { def: lg, args: largs.iter().map(|(_, a)| a.clone()).collect() });
            let Ok(g1) = eval_in(env, &st.ctx, &mk::eq(ty_tm.clone(), hb.clone(), lb.clone())) else { return Ok(None) };
            let Some(p) = self.0.walk(e, st, &g1, c, ih, 16)? else { return Ok(None) };
            let (sym, trans) = (env.lookup_global("eq::sym").expect("sym"), env.lookup_global("eq::trans").expect("trans"));
            // H ā = hb = lb = def ā'
            let back = apps(mk::global(sym), [(Rel::Rel, ty_tm.clone()), (Rel::Rel, r_tm.clone()), (Rel::Rel, lb.clone()), (Rel::Rel, dl)]);
            let mid = apps(mk::global(trans), [(Rel::Rel, ty_tm.clone()), (Rel::Rel, hb.clone()), (Rel::Rel, lb.clone()), (Rel::Rel, r_tm.clone()), (Rel::Rel, p), (Rel::Rel, back)]);
            Ok(Some(apps(mk::global(trans), [(Rel::Rel, ty_tm), (Rel::Rel, l_tm), (Rel::Rel, hb), (Rel::Rel, r_tm), (Rel::Rel, dh), (Rel::Rel, mid)])))
        }
    }
    let mut arms = Arms(EquivArms { def, h, idle, sb, hv, trust, failure: None });
    enumerate::build(env, &spec, &mut arms, 400_000_000)
}

// ---------------------------------------------------------------------------
// The rung, end to end.
// ---------------------------------------------------------------------------

/// Builds the set-bit rung for `key` (see the module docs).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_set_bits(cx: &mut crate::opt::Ctx<'_>, ext: &mut Crate, chain: &mut crate::elab::ProverChain, eopts: &crate::elab::Options, key: &LoopKey, user_globals: &HashMap<GlobalId, ItemId>, fault: Option<super::LoopFault>, why_not: &str) -> Result<LoopHelper, LoopFailure> {
    let fail = |reason: String, steps: u64| LoopFailure { reason: format!("{why_not}; no set-bit iteration: {reason}"), steps };
    let fid = *user_globals.get(&key.def).ok_or_else(|| fail("the loop is not a user function".into(), 0))?;
    let fd = ext.fn_def(fid).cloned().ok_or_else(|| fail("the loop is not a function".into(), 0))?;
    if !fd.generics.is_empty() {
        return Err(fail("a generic loop".into(), 0));
    }
    let fuel = match crate::opt::drive::measure_of(fid, &fd) {
        Some(crate::opt::drive::Measure::Param(i)) => i as u32,
        _ => return Err(fail("the loop's measure is not a parameter".into(), 0)),
    };
    let env = &cx.out.env;
    let one = super::onestep::one_step(env, key.def, 20_000_000).map_err(|e| fail(e, 0))?;
    let steps = one.steps;
    let statics = super::statics_of(env, key, one.nparams as usize).map_err(|e| fail(e, steps))?;
    let lp = super::classify::classify(env, one, statics).map_err(|e| fail(e, steps))?;
    let sb = plan(&lp, fuel).map_err(|e| fail(e, steps))?;
    if lp.statics[fuel as usize].is_none() || lp.statics[sb.wp as usize].is_none() {
        return Err(fail("the fuel or the width is not static at the call".into(), steps));
    }
    let name = env.global_name(key.def).map(|s| s.to_string()).unwrap_or_default();
    let orig = ext.item(fid).clone();
    let n = super::with_registry(|r| {
        let c = r.count.entry(key.def).or_insert(0);
        let n = *c;
        *c += 1;
        n
    });
    let suffix = if n > 0 { format!("{n}") } else { String::new() };
    let hname = format!("{}__bits{suffix}", orig.name);
    let hid_next = ItemId(ext.items.len() as u32);
    let wrong = fault == Some(super::LoopFault::SetBitsWrongJump);
    let hf = helper_fn(&fd, fid, hid_next, &sb, wrong, orig.span).map_err(|e| fail(e, steps))?;
    let hid = crate::opt::push_elaborate(cx, ext, chain, eopts, &orig, hname.clone(), hf, false).map_err(|(why, _)| fail(format!("the helper `{hname}` did not elaborate: {why}"), steps))?;
    if hid != hid_next {
        crate::opt::pop_driven(cx, ext, hid);
        return Err(fail("the helper's item id moved".into(), steps));
    }
    let Some(hg) = cx.out.fn_globals.get(&hid).copied() else {
        crate::opt::pop_driven(cx, ext, hid);
        return Err(fail("the helper has no global".into(), steps));
    };
    let trust = fault.is_some();
    let efault = (fault == Some(super::LoopFault::EnumArmMisstated)).then_some(enumerate::EnumFault::MisstatedArm);
    let prefix = format!("{name}::bits{suffix}");
    let timing = std::env::var_os("SANDBLASTER_LOOPSUM_TIMING").is_some();
    let t0 = std::time::Instant::now();
    let lemmas = idle_lemma(&mut cx.out.env, key.def, &sb, &lp, &format!("{prefix}::idle"), trust, efault).and_then(|idle| {
        if timing {
            eprintln!("opt: timing set bits of {name}: idle {:?}", t0.elapsed());
        }
        equiv_lemma(&mut cx.out.env, key.def, hg, idle, &sb, &format!("{prefix}::equiv"), trust, None).map(|e| (idle, e))
    });
    if timing {
        eprintln!("opt: timing set bits of {name}: lemmas {:?}", t0.elapsed());
    }
    let (idle, eq_g) = match lemmas {
        Ok(x) => x,
        Err(e) => {
            ext.items[hid.0 as usize].ghost = true;
            crate::opt::pop_driven(cx, ext, hid);
            return Err(fail(e, steps));
        }
    };
    cx.set_aside_obligations(hid);
    // the entry wrapper at the call's static arguments
    let (wid, wg, link) = match entry(cx, ext, chain, eopts, key, &lp, &sb, &fd, &orig, hg, eq_g, &suffix) {
        Ok(x) => x,
        Err(e) => return Err(fail(e, steps)),
    };
    let describe = format!("set-bit iteration over `{}` (width `{}`): helper {hname}; lemmas `{}` (idle runs), `{}`", lp.params[sb.v as usize].name, lp.params[sb.wp as usize].name, cx.out.env.global_name(idle).map(|s| s.to_string()).unwrap_or_default(), cx.out.env.global_name(eq_g).map(|s| s.to_string()).unwrap_or_default());
    let _ = wid;
    Ok(LoopHelper { item: wid, global: wg, lemma: link, rung: crate::opt::Rung::SetBits, facts: Vec::new(), loop_facts: None, summary_lemma: cx.out.env.global_name(eq_g).map(|s| s.to_string()).unwrap_or_default(), describe, steps })
}

/// The entry wrapper `loop__bits_entry(d̄) = loop__bits(statics, d̄)` (always
/// inlined) and its link `Π d̄ h̄. Eq(R, entry d̄ h̄, loop(statics, d̄) h̄)`:
/// `Delta(entry)` then `equiv` at the static arguments.
#[allow(clippy::too_many_arguments)]
fn entry(cx: &mut crate::opt::Ctx<'_>, ext: &mut Crate, chain: &mut crate::elab::ProverChain, eopts: &crate::elab::Options, key: &LoopKey, lp: &Loop, sb: &SetBits, fd: &FnDef, orig: &Item, hg: GlobalId, equiv: GlobalId, suffix: &str) -> Result<(ItemId, GlobalId, GlobalId), String> {
    let dy = lp.dynamic();
    let mut smap: HashMap<LocalId, Expr> = HashMap::new();
    for (i, p) in fd.params.iter().enumerate() {
        if let Some(t) = &lp.statics[i]
            && let PatKind::Binding { local, .. } = &p.pat.kind
            && let Term::Lit { n: v, .. } = &**t
            && let Some(v) = num_traits::ToPrimitive::to_u128(v)
        {
            smap.insert(*local, Expr::new(ExprKind::Lit(Lit::Int(v)), p.ty.clone(), p.span));
        }
    }
    let mut wf = fd.clone();
    wf.params = dy.iter().map(|i| fd.params[*i as usize].clone()).collect();
    wf.requires = fd.requires.iter().map(|r| super::subst_requires(r, &smap)).collect::<Option<Vec<_>>>().ok_or("a requires over a non-integer static argument")?;
    wf.ensures = None;
    wf.decreases = None;
    wf.recursion = crate::hir::Recursion::None;
    wf.specialize = false;
    wf.implements = None;
    wf.inline = Some(Inline::Always);
    let (body, locals) = {
        let env = &cx.out.env;
        let tele_h = crate::opt::symex::telescope(env, hg).ok_or("the helper has no telescope")?;
        let statics = super::statics_of(env, key, lp.params.len())?;
        let mut st = St::new(env, &Ctx::default(), 0);
        for i in &dy {
            let ty = lp.one.root.ctx.entries[*i as usize].ty.clone();
            st.push_raw(env, Rc::from(super::invariant::sanitize(&lp.params[*i as usize].name).as_str()), Rel::Rel, ty);
        }
        let mut args = Vec::new();
        let mut li = 0usize;
        for (_, rel, _) in tele_h.binders.iter() {
            match rel {
                Rel::Rel => {
                    // (the helper's parameters are the loop's)
                    let i = li;
                    li += 1;
                    args.push((Rel::Rel, match &statics[i] {
                        Some(t) => t.clone(),
                        None => st.var(dy.iter().position(|d| *d as usize == i).ok_or("a dynamic parameter")? as u32),
                    }));
                }
                Rel::Irr => args.push((Rel::Irr, Rc::new(Term::Erased))),
            }
        }
        let t = apps(mk::global(hg), args);
        let op = |g: GlobalId| g == hg;
        let v = env.eval_opaque(&env.ctx_venv(&st.ctx), Lvl(st.depth()), &t, &op, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("the entry's value: {e:?}"))?;
        let node = crate::opt::drive::tree::Node { depth: st.depth() + wf.requires.len() as u32, steps: vec![], kind: crate::opt::drive::tree::NodeKind::Leaf(v) };
        let maps = crate::opt::residual::Maps::new(env, ext, &cx.out.fn_globals, &cx.out.adts)?;
        let ev = crate::opt::drive::step::Eval { env, opaque: &op };
        let r = crate::opt::residual::tree::build_tree(env, &maps, ext, &wf, &node, &ev, &std::collections::BTreeMap::new(), &std::collections::BTreeMap::new(), 1_000, orig.span, None).map_err(|e| format!("the entry is not printable: {e}"))?;
        (r.body, r.locals)
    };
    wf.body = FnBody::Exec(body);
    wf.locals = locals;
    let wname = format!("{}__bits_entry{suffix}", orig.name);
    let wid = crate::opt::push_elaborate(cx, ext, chain, eopts, orig, wname.clone(), wf, false).map_err(|(why, _)| format!("the entry `{wname}` did not elaborate: {why}"))?;
    let Some(wg) = cx.out.fn_globals.get(&wid).copied() else {
        crate::opt::pop_driven(cx, ext, wid);
        return Err("the entry has no global".into());
    };
    match entry_link(&mut cx.out.env, key, lp, sb, wg, hg, equiv) {
        Ok(l) => {
            cx.set_aside_obligations(wid);
            Ok((wid, wg, l))
        }
        Err(e) => {
            ext.items[wid.0 as usize].ghost = true;
            crate::opt::pop_driven(cx, ext, wid);
            Err(format!("the entry's link: {e}"))
        }
    }
}

/// `Π d̄ h̄. Eq(R, entry d̄ h̄, loop(statics, d̄) h̄)`: `Delta(entry)`, then
/// `equiv` at the statics (its `f ≤ K` requires by evaluation).
fn entry_link(env: &mut Env, key: &LoopKey, lp: &Loop, sb: &SetBits, wg: GlobalId, hg: GlobalId, equiv: GlobalId) -> Result<GlobalId, String> {
    let tele_w = crate::opt::symex::telescope(env, wg).ok_or("the entry has no telescope")?;
    let tele_l = crate::opt::symex::telescope(env, key.def).ok_or("the loop has no telescope")?;
    let tele_h = crate::opt::symex::telescope(env, hg).ok_or("the helper has no telescope")?;
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let (ty, body) = {
        let envr: &Env = env;
        let mut st = St::new(envr, &Ctx::default(), 16);
        let mut vals: Vec<EnvEntry> = Vec::new();
        for (nm, rel, dom) in &tele_w.binders {
            let tv = envr.eval(&sandblaster_kernel::value::VEnv(Rc::new(vals.clone())), Lvl(st.depth()), dom, &mut Budget { steps: 10_000_000 }).map_err(|e| format!("{e:?}"))?;
            let lvl = st.depth();
            let e = st.push_raw(envr, nm.clone(), *rel, tv.clone());
            if *rel == Rel::Irr {
                st.add_ctx_fact(lvl, tv, crate::auto::state::Origin::Intro);
            }
            vals.push(e);
        }
        let dy = lp.dynamic();
        let statics = super::statics_of(envr, key, lp.params.len())?;
        let np_w = tele_w.binders.iter().take_while(|b| b.1 == Rel::Rel).count();
        // the loop at the statics
        let mut la: Vec<Arg> = Vec::new();
        for i in 0..lp.params.len() {
            la.push(Arg::Rel(match &statics[i] {
                Some(t) => st.eval(envr, t, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("{e:?}"))?,
                None => match &vals[dy.iter().position(|d| *d as usize == i).ok_or("dyn")?] {
                    EnvEntry::Rel(v) => v.clone(),
                    _ => return Err("an irrelevant parameter".into()),
                },
            }));
        }
        for v in vals.iter().skip(np_w) {
            la.push(crate::auto::util::entry_arg(v));
        }
        let wargs: Vec<Arg> = vals.iter().map(crate::auto::util::entry_arg).collect();
        let r_ty = envr.eval(&sandblaster_kernel::value::VEnv(Rc::new(vals.clone())), Lvl(st.depth()), &tele_w.ret, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("{e:?}"))?;
        let concl: V = Rc::new(Value::Eq { ty: r_ty.clone(), lhs: app(wg, wargs.clone()), rhs: app(key.def, la.clone()) });
        let ty = close(envr, &st, &concl);
        // equiv at the statics: its relevant args (the loop's without the width), then its requires
        // (the loop summary's step meter, `super::meter`: capped; its kernel
        // checks are charged by `add_lemma`)
        let mut sb2 = Budget { steps: super::meter::cap(200_000_000) };
        let db = {
            let mut db = crate::auto::lemmas::LemmaDb::default();
            db.refresh(envr);
            db
        };
        let mut e = Engine::new(envr, &mut sb2, &cfg, &db, vec![], st.depth());
        let Some(mut cur) = envr.global_type_value(equiv) else { return Err("equiv's type".into()) };
        let mut eargs: Vec<(Rel, Tm)> = Vec::new();
        let rel_l: Vec<V> = la.iter().take(lp.params.len()).filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
        let mut hi = 0usize;
        while let Value::Pi { rel, dom, cod, .. } = &*cur.clone() {
            let entry = match rel {
                Rel::Rel => {
                    let i = if hi >= sb.wp as usize { hi + 1 } else { hi };
                    hi += 1;
                    let x = rel_l.get(i).cloned().ok_or("an argument")?;
                    eargs.push((Rel::Rel, st.quote(envr, &x)));
                    EnvEntry::Rel(x)
                }
                Rel::Irr => {
                    let p = obligation(&mut e, &st, dom, &[]).ok_or("equiv's requires at the call")?;
                    eargs.push((Rel::Irr, p.clone()));
                    crate::auto::util::irr_entry(&st.venv, &p)
                }
            };
            cur = e.inst(cod, vec![entry], st.depth()).ok().flatten().ok_or("equiv's statement")?;
        }
        let inst = apps(mk::global(equiv), eargs);
        let d = st.depth();
        let w_tm = st.quote(envr, &app(wg, wargs.clone()));
        let h_tm = {
            let Some((_, l, _)) = as_eq(&envr.infer(&st.ctx, &inst, &mut Budget { steps: 20_000_000 }).map_err(|e| format!("{e}"))?).map(|(a, l, r)| (a.clone(), l.clone(), r.clone())) else { return Err("equiv's instance".into()) };
            st.quote(envr, &l)
        };
        let l_tm = st.quote(envr, &app(key.def, la));
        let r_tm = st.quote(envr, &r_ty);
        let wa: Vec<Tm> = (0..d).map(|i| st.var(i)).collect();
        let delta = Rc::new(Term::Delta { def: wg, args: wa });
        let trans = envr.lookup_global("eq::trans").ok_or("eq::trans")?;
        let p = apps(mk::global(trans), [(Rel::Rel, r_tm), (Rel::Rel, w_tm), (Rel::Rel, h_tm), (Rel::Rel, l_tm), (Rel::Rel, delta), (Rel::Rel, inst)]);
        let _ = tele_l;
        let _ = tele_h;
        let mut body = st.finish(p);
        let mut t = &ty;
        let mut lams: Vec<(sandblaster_kernel::term::Name, Rel, Tm)> = Vec::new();
        while let Term::Pi { name, rel, dom, cod } = &**t {
            lams.push((name.clone(), *rel, dom.clone()));
            t = cod;
        }
        for (nm, rel, dom) in lams.into_iter().rev() {
            body = mk::lam(&nm, rel, dom, body);
        }
        (ty, body)
    };
    let name = format!("{}::equiv", env.global_name(wg).map(|s| s.to_string()).unwrap_or_default());
    let (g, _) = super::lemmas::add_lemma(env, &name, ty, body, 400_000_000)?;
    Ok(g)
}
