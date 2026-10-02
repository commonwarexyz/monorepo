//! The summary plan and its invariant (optimizer design §7.2–§7.5).
//!
//! From a classified loop and its traces:
//!
//! * **templates**: each parameter's closed form in the ghost inputs and the
//!   iteration `j` ([`templates`]);
//! * the **kind** of loop: `FirstMatch` (a payload set once, no dynamic
//!   exit: QMDB's `shape_go`, corpus P4) or `Search` (a dynamic exit:
//!   P1, P2, P6, P11), with the synthesized **witness** iteration `E(ḡ)`
//!   (where the payload is set, or the loop exits);
//! * the **result** `R(ḡ)`: the exit value with every parameter replaced by
//!   its template at the witness (or at the exhaustion `K`).
//!
//! Every candidate is validated on the traces before any proof work
//! ([`validate`]). The per-literal lemma statements are rendered from the
//! plan by [`Spec`]: `inv(f, s̄, ḡ)` is the conjunction of the
//! per-parameter closed forms (as equations) and the entry facts they need.

use std::rc::Rc;

use num_traits::ToPrimitive;
use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{Lvl, PrimOp, Rel, Width};
use sandblaster_kernel::value::{Budget, EnvEntry, VEnv};

use super::classify::{CVal, Class, Loop, SVal, eval_sval};
use super::expr::{self, CE, E, Val};
use super::traces::Traces;

/// A ghost input: the entry value of a dynamic parameter.
#[derive(Clone, Debug)]
pub struct Ghost {
    pub param: u32,
    /// Its binder name in the lemmas (a `Const` parameter's ghost is the
    /// parameter's own binder).
    pub name: String,
    pub width: Width,
    pub shared: bool,
}

/// What kind of loop (see the module docs).
#[derive(Clone, Debug)]
pub enum Kind {
    /// The payload of parameter `param` is set once: `pr` is the predicate
    /// over the **state** (at any iteration) that it has been set; the
    /// payload is `payload(ḡ)` (in ghost space) and `unset` its value
    /// before (the static entry value).
    FirstMatch { param: u32, pr: E, payload: SVal, unset: SVal },
    /// The loop exits at the first iteration `E(ḡ)` whose exit condition
    /// holds (`E = K` for the exhaustion).
    Search,
}

/// The summary plan of one loop call.
pub struct Plan {
    pub lp: Loop,
    pub ghosts: Vec<Ghost>,
    /// Per parameter: its closed form (ghost space, with `J`); `None` for a
    /// static parameter without a symbolic form, or the `FirstMatch` one.
    pub templates: Vec<Option<E>>,
    pub kind: Kind,
    /// The witness iteration `E(ḡ)` (ghost space, `U32`).
    pub witness: E,
    /// The result `R(ḡ)` (ghost space).
    pub result: SVal,
    pub traces: Traces,
    /// Witness-synthesis classes enumerated.
    pub synth_candidates: usize,
}

/// The entry value of parameter `p` in ghost space.
fn entry(lp: &Loop, ghosts: &[Ghost], env: &Env, p: u32) -> Option<E> {
    match &lp.statics[p as usize] {
        Some(t) => match super::classify::closed_cval(env, t)? {
            CVal::N(Val::W(w, n)) => Some(expr::lit(w, n)),
            CVal::N(Val::B(b)) => Some(Rc::new(CE::BoolLit(b))),
            _ => None,
        },
        None => {
            let g = ghosts.iter().position(|g| g.param == p)?;
            Some(expr::var(g as u32, ghosts[g].width))
        }
    }
}

/// A symbolic form of a static sequence: constant, affine in `j`, or a
/// shift of a constant by a multiple of `j`.
fn fit_static(w: Width, vals: &[u128]) -> Option<E> {
    let jw = |e: E| if w == Width::U32 { e } else { expr::op(PrimOp::Cast { from: Width::U32, to: w }, vec![e]) };
    let m = expr::mask(w);
    let a = vals[0];
    if vals.iter().all(|v| *v == a) {
        return Some(expr::lit(w, a));
    }
    // a + s·j (mod 2^w)
    let s = vals[1].wrapping_sub(a) & m;
    if vals.iter().enumerate().all(|(j, v)| a.wrapping_add(s.wrapping_mul(j as u128)) & m == *v) {
        let neg = (m - s + 1) & m;
        return Some(if neg < s {
            expr::op2(PrimOp::WSub(w), expr::lit(w, a), expr::op2(PrimOp::WMul(w), expr::lit(w, neg), jw(expr::j())))
        } else if s == 1 {
            expr::op2(PrimOp::WAdd(w), expr::lit(w, a), jw(expr::j()))
        } else {
            expr::op2(PrimOp::WAdd(w), expr::lit(w, a), expr::op2(PrimOp::WMul(w), expr::lit(w, s), jw(expr::j())))
        });
    }
    // a >> (s·j), a << (s·j) (mathematical shifts)
    for s in 1..=8u32 {
        let amt = || if s == 1 { expr::j() } else { expr::op2(PrimOp::WMul(Width::U32), expr::lit(Width::U32, s as u128), expr::j()) };
        let b = expr::bits(w);
        if vals.iter().enumerate().all(|(j, v)| {
            let k = s as u128 * j as u128;
            *v == if k >= b as u128 { 0 } else { a >> k }
        }) {
            return Some(Rc::new(CE::ShrSat(expr::lit(w, a), amt())));
        }
        if vals.iter().enumerate().all(|(j, v)| {
            let k = s as u128 * j as u128;
            *v == if k >= b as u128 { 0 } else { (a << k) & m }
        }) {
            return Some(Rc::new(CE::ShlSat(expr::lit(w, a), amt())));
        }
    }
    None
}

/// The per-parameter templates (see the module docs).
pub fn templates(env: &Env, lp: &Loop, ghosts: &[Ghost]) -> Result<Vec<Option<E>>, String> {
    let n = lp.params.len();
    let mut t: Vec<Option<E>> = vec![None; n];
    // static and base classes first, then linear ones (which refer to them)
    for i in 0..n {
        let p = &lp.params[i];
        t[i] = match &lp.classes[i] {
            Class::Static => match p.width {
                Some(w) => {
                    let vals: Option<Vec<u128>> = lp.static_seq.iter().map(|s| s[i].as_ref().and_then(|c| c.num())).collect();
                    vals.and_then(|v| fit_static(w, &v))
                }
                None => None,
            },
            Class::Const => entry(lp, ghosts, env, i as u32),
            Class::Shift(k) => {
                let w = p.width.unwrap();
                let e0 = entry(lp, ghosts, env, i as u32).ok_or("an entry value")?;
                let amt = if *k == 1 { expr::j() } else { expr::op2(PrimOp::WMul(Width::U32), expr::lit(Width::U32, *k as u128), expr::j()) };
                let _ = w;
                Some(Rc::new(CE::ShrSat(e0, amt)))
            }
            Class::BitDigit { e, .. } => {
                let w = p.width.unwrap();
                let e0 = entry(lp, ghosts, env, i as u32).ok_or("an entry value")?;
                // v0 & (2·w_j − 1) = v0 & (MAX >> (bits − 1 − e + j))
                let off = expr::bits(w) - 1 - e;
                let amt = if off == 0 { expr::j() } else { expr::op2(PrimOp::WAdd(Width::U32), expr::j(), expr::lit(Width::U32, off as u128)) };
                Some(expr::op2(PrimOp::And(w), e0, Rc::new(CE::ShrSat(expr::lit(w, expr::mask(w)), amt))))
            }
            _ => None,
        };
    }
    for i in 0..n {
        if let Class::GuardCount { v } = &lp.classes[i] {
            let w = lp.params[i].width.unwrap();
            let Class::BitDigit { e, .. } = lp.classes[*v as usize] else { return Err("a GuardCount without its BitDigit".into()) };
            let vw = lp.params[*v as usize].width.unwrap();
            let c0 = entry(lp, ghosts, env, i as u32).ok_or("an entry value")?;
            let v0 = entry(lp, ghosts, env, *v).ok_or("an entry value")?;
            // bits of v0 at positions ≥ e + 1 − j
            let amt = expr::op2(PrimOp::WSub(Width::U32), expr::lit(Width::U32, e as u128 + 1), expr::j());
            let cnt = expr::op(PrimOp::CountOnes(vw), vec![Rc::new(CE::ShrSat(v0, amt))]);
            let cnt = if w == Width::U32 { cnt } else { expr::op(PrimOp::Cast { from: Width::U32, to: w }, vec![cnt]) };
            t[i] = Some(expr::op2(PrimOp::WAdd(w), c0, cnt));
        }
    }
    for i in 0..n {
        if let Class::MaskedCount { .. } = &lp.classes[i] {
            t[i] = Some(masked_template(env, lp, ghosts, i as u32, false).ok_or("a MaskedCount's entry values")?);
        }
    }
    // linear: c_p·x_p = K0 − Σ c_q·x_q  (c_p = ±1), K0 = Σ c_q·x_q(0)
    for _ in 0..n {
        for i in 0..n {
            if t[i].is_some() {
                continue;
            }
            let Class::Linear { rel } = &lp.classes[i] else { continue };
            let w = lp.params[i].width.unwrap();
            let ci = rel.iter().find(|(v, _)| *v == i as u32).map(|x| x.1).unwrap_or(0);
            if rel.iter().any(|(v, _)| *v != i as u32 && t[*v as usize].is_none()) {
                continue;
            }
            // x_i = ci·(K0 − Σ_{q≠i} c_q·x_q) = ci·Σ_q c_q·(x_q(0) − x_q) + x_i(0)
            let mut acc = entry(lp, ghosts, env, i as u32).ok_or("an entry value")?;
            for (q, c) in rel {
                if *q == i as u32 {
                    continue;
                }
                let k = c * ci; // coefficient of (x_q(0) − x_q)
                let d = expr::op2(PrimOp::WSub(w), cast_to(entry(lp, ghosts, env, *q).ok_or("an entry value")?, w), cast_to(t[*q as usize].clone().unwrap(), w));
                let term = if k.unsigned_abs() == 1 { d } else { expr::op2(PrimOp::WMul(w), expr::lit(w, k.unsigned_abs()), d) };
                acc = if k > 0 { expr::op2(PrimOp::WAdd(w), acc, term) } else { expr::op2(PrimOp::WSub(w), acc, term) };
            }
            t[i] = Some(acc);
        }
    }
    Ok(t)
}

/// The popcount `P(k)` of a [`Class::MaskedCount`]'s source above the
/// threshold (`cnt(n >> (k + 1))` for `idx > k`, `cnt(n >> k)` for
/// `idx ≥ k`), exact while the threshold is below the width (its regime),
/// in ghost space (`U32`).
pub fn masked_p(env: &Env, lp: &Loop, ghosts: &[Ghost], i: u32) -> Option<E> {
    let Class::MaskedCount { src, thr, strict, .. } = lp.classes[i as usize] else { return None };
    let sw = lp.params[src as usize].width?;
    let n0 = entry(lp, ghosts, env, src)?;
    let k0 = entry(lp, ghosts, env, thr)?;
    let tw = lp.params[thr as usize].width?;
    let k32 = cast_to(k0, Width::U32);
    let _ = tw;
    let amt = if strict { expr::op2(PrimOp::WAdd(Width::U32), k32, expr::lit(Width::U32, 1)) } else { k32 };
    Some(expr::op(PrimOp::CountOnes(sw), vec![expr::op2(PrimOp::WShr(sw), n0, amt)]))
}

/// A [`Class::MaskedCount`]'s closed form at the iteration `J`: the entry
/// value plus the source's set bits at positions `p < J` past the
/// threshold — `k < J ? P(k) − cnt(n >> J) : 0` (the regime split). In the
/// counter's width (wrapping; the values are small), or in `Int` (`int`,
/// the lemmas' conjunct: no carries).
pub fn masked_template(env: &Env, lp: &Loop, ghosts: &[Ghost], i: u32, int: bool) -> Option<E> {
    let Class::MaskedCount { src, thr, .. } = lp.classes[i as usize] else { return None };
    let w = lp.params[i as usize].width?;
    let sw = lp.params[src as usize].width?;
    let c0 = entry(lp, ghosts, env, i)?;
    let n0 = entry(lp, ghosts, env, src)?;
    let k0 = cast_to(entry(lp, ghosts, env, thr)?, Width::U32);
    let p = masked_p(env, lp, ghosts, i)?;
    let cur = expr::op(PrimOp::CountOnes(sw), vec![Rc::new(CE::ShrSat(n0, expr::j()))]);
    let regime = expr::op2(PrimOp::Lt(Width::U32), k0, expr::j());
    if int {
        let to_int = |e: E, from: Width| expr::op(PrimOp::Cast { from, to: Width::Int }, vec![e]);
        let delta = expr::op2(PrimOp::ISub, to_int(p, Width::U32), to_int(cur, Width::U32));
        Some(expr::op2(PrimOp::IAdd, to_int(c0, w), expr::ite(regime, delta, expr::lit(Width::Int, 0))))
    } else {
        let delta = cast_to(expr::op2(PrimOp::WSub(Width::U32), p, cur), w);
        Some(expr::op2(PrimOp::WAdd(w), c0, expr::ite(regime, delta, expr::lit(w, 0))))
    }
}

fn cast_to(e: E, w: Width) -> E {
    match e.width() {
        Some(x) if x == w => e,
        Some(x) => expr::op(PrimOp::Cast { from: x, to: w }, vec![e]),
        None => e,
    }
}

/// Algebraic peepholes on top of [`expr::fold`] (identities of `&`, `|`,
/// `^`, `+`, `−`, `·` with `0`/`1`/all-ones), bottom-up.
pub fn simp(e: &E, jv: Option<u128>) -> E {
    let e = expr::fold(e, jv);
    peep(&e)
}

fn peep(e: &E) -> E {
    use PrimOp::*;
    match &**e {
        CE::Op(o, a) => {
            let a: Vec<E> = a.iter().map(peep).collect();
            let lit = |x: &E| if let CE::Lit(_, n) = &**x { Some(*n) } else { None };
            let r = match (o, a.as_slice()) {
                (And(w), [x, y]) if lit(y) == Some(0) || lit(x) == Some(0) => {
                    let _ = x;
                    return expr::lit(*w, 0);
                }
                (And(w), [x, y]) if lit(y) == Some(expr::mask(*w)) => return x.clone(),
                (Or(_) | Xor(_) | WAdd(_) | WSub(_), [x, y]) if lit(y) == Some(0) => return x.clone(),
                (Or(_) | Xor(_) | WAdd(_), [x, y]) if lit(x) == Some(0) => return y.clone(),
                (WAdd(w), [x, y]) if matches!(&**y, CE::Op(WSub(_), b) if lit(&b[0]) == Some(0)) => {
                    let CE::Op(_, b) = &**y else { unreachable!() };
                    return expr::op2(WSub(*w), x.clone(), b[1].clone());
                }
                (WMul(_), [x, y]) if lit(y) == Some(1) => return x.clone(),
                (WMul(_), [x, y]) if lit(x) == Some(1) => return y.clone(),
                _ => expr::op(*o, a.clone()),
            };
            r
        }
        CE::Ite(c, a, b) => expr::ite(peep(c), peep(a), peep(b)),
        CE::ShrSat(a, b) => Rc::new(CE::ShrSat(peep(a), peep(b))),
        CE::ShlSat(a, b) => Rc::new(CE::ShlSat(peep(a), peep(b))),
        CE::DivLit(a, c) => Rc::new(CE::DivLit(peep(a), *c)),
        _ => e.clone(),
    }
}

/// A state-space structured value with every parameter replaced by its
/// template (`fm`: the `FirstMatch` parameter's template as a structured
/// value), then `J` by `jv`.
pub fn to_ghost(s: &SVal, t: &[Option<E>], fm: Option<(u32, &SVal)>, j: &E) -> Option<SVal> {
    let by: Vec<Option<E>> = t.iter().map(|x| x.as_ref().map(|e| expr::subst_j(e, j))).collect();
    Some(match s {
        SVal::Ce(e) => {
            let mut vs = Vec::new();
            e.vars(&mut vs);
            if vs.iter().any(|v| by.get(*v as usize).cloned().flatten().is_none()) {
                return None;
            }
            SVal::Ce(expr::subst_vars(e, &by))
        }
        SVal::Ctor { ind, ctor, params, args } => SVal::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: args.iter().map(|a| to_ghost(a, t, fm, j)).collect::<Option<_>>()? },
        SVal::Ite(c, a, b) => {
            let SVal::Ce(c) = to_ghost(&SVal::Ce(c.clone()), t, fm, j)? else { return None };
            SVal::Ite(c, Box::new(to_ghost(a, t, fm, j)?), Box::new(to_ghost(b, t, fm, j)?))
        }
        SVal::Param(p) => match fm {
            Some((q, v)) if q == *p => subst_sval_j(v, j),
            _ => return None,
        },
    })
}

fn subst_sval_j(s: &SVal, j: &E) -> SVal {
    match s {
        SVal::Ce(e) => SVal::Ce(expr::subst_j(e, j)),
        SVal::Ctor { ind, ctor, params, args } => SVal::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: args.iter().map(|a| subst_sval_j(a, j)).collect() },
        SVal::Ite(c, a, b) => SVal::Ite(expr::subst_j(c, j), Box::new(subst_sval_j(a, j)), Box::new(subst_sval_j(b, j))),
        SVal::Param(p) => SVal::Param(*p),
    }
}

/// Simplifies every expression of a ghost-space structured value.
pub fn simp_sval(s: &SVal, jv: Option<u128>) -> SVal {
    match s {
        SVal::Ce(e) => SVal::Ce(simp(e, jv)),
        SVal::Ctor { ind, ctor, params, args } => SVal::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: args.iter().map(|a| simp_sval(a, jv)).collect() },
        SVal::Ite(c, a, b) => {
            let c = simp(c, jv);
            match &*c {
                CE::BoolLit(true) => simp_sval(a, jv),
                CE::BoolLit(false) => simp_sval(b, jv),
                _ => match (simp_sval(a, jv), simp_sval(b, jv)) {
                    (SVal::Ce(x), SVal::Ce(y)) => SVal::Ce(expr::ite(c, x, y)),
                    (x, y) => SVal::Ite(c, Box::new(x), Box::new(y)),
                },
            }
        }
        SVal::Param(p) => SVal::Param(*p),
    }
}

/// Evaluates a ghost-space structured value on ghost inputs (and `J`).
pub fn eval_ghost(s: &SVal, g: &[u128], jv: Option<u128>) -> Option<CVal> {
    Some(match s {
        SVal::Ce(e) => CVal::N(e.eval(g, jv)?),
        SVal::Ctor { ind, ctor, args, .. } => CVal::Ctor { ind: ind.0, ctor: *ctor, args: args.iter().map(|a| eval_ghost(a, g, jv)).collect::<Option<_>>()? },
        SVal::Ite(c, a, b) => {
            if c.eval(g, jv)?.as_bool()? {
                eval_ghost(a, g, jv)?
            } else {
                eval_ghost(b, g, jv)?
            }
        }
        SVal::Param(_) => return None,
    })
}

/// The ghost inputs of a loop: one per dynamic parameter.
pub fn ghosts(lp: &Loop) -> Result<Vec<Ghost>, String> {
    let mut out = Vec::new();
    for i in lp.dynamic() {
        let p = &lp.params[i as usize];
        let w = p.width.ok_or_else(|| format!("the dynamic parameter `{}` is not a machine integer", p.name))?;
        let shared = lp.classes[i as usize] == Class::Const;
        let name = if shared { sanitize(&p.name) } else { format!("g_{}", sanitize(&p.name)) };
        out.push(Ghost { param: i, name, width: w, shared });
    }
    Ok(out)
}

/// A binder name usable in core text.
pub fn sanitize(s: &str) -> String {
    let mut t: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    if t.is_empty() || t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        t.insert(0, 'v');
    }
    t
}

/// The ghost inputs of a trace (its dynamic entry values, as numbers).
pub fn trace_ghosts(tr: &super::traces::Trace) -> Vec<u128> {
    tr.input.iter().map(|c| c.num().unwrap_or(0)).collect()
}

/// Builds the plan (see the module docs).
pub fn plan(env: &Env, lp: Loop, traces: Traces, synth_max: usize, fault: Option<super::LoopFault>) -> Result<Plan, String> {
    for (i, c) in lp.classes.iter().enumerate() {
        if let Class::Unknown(why) = c {
            return Err(format!("parameter {i}: {why}"));
        }
    }
    let ghosts = ghosts(&lp)?;
    let mut t = templates(env, &lp, &ghosts)?;
    // fault R8: a GuardCount invariant one bit off
    if fault == Some(super::LoopFault::GuardCountShift) {
        for (i, c) in lp.classes.iter().enumerate() {
            if let Class::GuardCount { .. } = c
                && let Some(e) = &t[i]
            {
                t[i] = Some(shift_amounts(e, 1));
            }
        }
    }
    let widths: Vec<Width> = ghosts.iter().map(|g| g.width).collect();
    // the synthesis' constants: harvested from this loop (`pool`)
    let pool = super::pool::Pool::harvest(&lp);
    let gin: Vec<Vec<u128>> = traces.traces.iter().map(trace_ghosts).collect();
    let fm: Vec<u32> = (0..lp.params.len() as u32).filter(|i| lp.classes[*i as usize] == Class::FirstMatch).collect();
    let dyn_exit = has_dynamic_exit(&lp);
    let k = lp.k;
    match (fm.as_slice(), dyn_exit) {
        ([f], false) => {
            let f = *f;
            // the payload: the constructor leaf of the update's select tree
            fn leaf(s: &SVal) -> Option<SVal> {
                match s {
                    SVal::Ctor { .. } => Some(s.clone()),
                    SVal::Ite(_, a, b) => leaf(a).or_else(|| leaf(b)),
                    _ => None,
                }
            }
            let payload_state = lp.cont.iter().find_map(|c| leaf(&c.next[f as usize])).ok_or("no payload")?;
            let unset_t = lp.statics[f as usize].clone().ok_or("the FirstMatch parameter is not static at the call")?;
            let unset_c = super::classify::closed_cval(env, &unset_t).ok_or("its entry value")?;
            // the set predicate over the state: a comparison of two numeric
            // parameters, true exactly when the payload is set
            let mut target = Vec::new();
            let mut rows: Vec<Vec<CVal>> = Vec::new();
            for tr in &traces.traces {
                for st in &tr.states {
                    target.push(st[f as usize] != unset_c);
                    rows.push(st.clone());
                }
            }
            let atoms: Vec<(E, Vec<Val>)> = (0..lp.params.len())
                .filter_map(|i| {
                    let w = lp.params[i].width?;
                    let vals: Option<Vec<Val>> = rows.iter().map(|r| match &r[i] {
                        CVal::N(v) => Some(*v),
                        _ => None,
                    }).collect();
                    Some((expr::var(i as u32, w), vals?))
                })
                .collect();
            let pr = super::synth::predicate(&atoms, &target).ok_or("no predicate over the state says when the payload is set")?;
            // the witness: the iteration whose update sets the payload
            let mut wt_in = Vec::new();
            let mut wt = Vec::new();
            for (ti, tr) in traces.traces.iter().enumerate() {
                if let Some(jh) = (0..tr.states.len().saturating_sub(1)).find(|&jj| tr.states[jj][f as usize] == unset_c && tr.states[jj + 1][f as usize] != unset_c) {
                    wt_in.push(gin[ti].clone());
                    wt.push(Val::W(Width::U32, jh as u128));
                }
            }
            if wt.len() < 8 {
                return Err("too few traces set the payload".into());
            }
            let (witness, found_n) = super::guards::witness(&widths, &wt_in, &wt, synth_max, &pool).ok_or("no witness expression found (synthesis)")?;
            let witness = orient_xor(&witness, &wt_in);
            // fault R7: the witness off by one
            let witness = if fault == Some(super::LoopFault::WitnessPlusOne) { simp(&expr::op2(PrimOp::WAdd(Width::U32), witness, expr::lit(Width::U32, 1)), None) } else { witness };
            // the payload at the witness, the FirstMatch template, the result
            let payload = simp_sval(&to_ghost(&payload_state, &t, None, &witness).ok_or("the payload has no closed form")?, None);
            // shifts whose amount stays below the width on the hit traces are plain
            let hit_ghosts: Vec<Vec<u128>> = wt_in.clone();
            let payload = unsat_sval(&payload, &hit_ghosts);
            let unset = sval_of_cval(env, &unset_t).ok_or("the unset value")?;
            let pr_j = to_ghost(&SVal::Ce(pr.clone()), &t, None, &expr::j()).ok_or("the set predicate has no closed form")?;
            let SVal::Ce(pr_j) = pr_j else { unreachable!() };
            let fm_t = SVal::Ite(pr_j, Box::new(payload.clone()), Box::new(unset.clone()));
            // the result: the exit value at the exhaustion
            let ex = lp.exits.iter().find(|e| exit_feasible_at(&lp, e, k)).ok_or("no exit at the exhaustion")?;
            let result = simp_sval(&to_ghost(&ex.value, &t, Some((f, &fm_t)), &expr::lit(Width::U32, k as u128)).ok_or("the result has no closed form")?, None);
            let plan = Plan { lp, ghosts, templates: t, kind: Kind::FirstMatch { param: f, pr, payload, unset }, witness, result, traces, synth_candidates: found_n };
            // (a simulated fault skips the trace validation: the kernel judges)
            if fault.is_none() {
                validate(&plan)?;
            }
            Ok(plan)
        }
        ([], true) => {
            // the witness: the exit iteration
            let wt: Vec<Val> = traces.traces.iter().map(|tr| Val::W(Width::U32, tr.exit_iter as u128)).collect();
            let (witness, cands_n) = super::guards::witness(&widths, &gin, &wt, synth_max, &pool).ok_or("no witness expression found (synthesis)")?;
            // the result: one exit value at the witness, or the dynamic exit
            // below K and the static one at K
            let at = |e: &super::classify::ExitPath, jj: &E| to_ghost(&e.value, &t, None, jj).map(|v| simp_sval(&v, None));
            let mut cands: Vec<SVal> = Vec::new();
            for e in &lp.exits {
                if let Some(v) = at(e, &witness) {
                    cands.push(v);
                }
            }
            let dyn_exits: Vec<&super::classify::ExitPath> = lp.exits.iter().filter(|e| !exit_static(&lp, e)).collect();
            let st_exits: Vec<&super::classify::ExitPath> = lp.exits.iter().filter(|e| exit_static(&lp, e)).collect();
            if let (Some(d), Some(s)) = (dyn_exits.first(), st_exits.first())
                && let (Some(dv), Some(sv)) = (at(d, &witness), at(s, &expr::lit(Width::U32, k as u128)))
            {
                let below = expr::op2(PrimOp::Lt(Width::U32), witness.clone(), expr::lit(Width::U32, k as u128));
                cands.push(simp_sval(&SVal::Ite(below, Box::new(dv), Box::new(sv)), None));
            }
            let mut last_err = String::from("no exit value has a closed form");
            let mut chosen = None;
            for result in cands {
                match validate_parts(&lp, &t, &Kind::Search, &result, &traces) {
                    Ok(()) => {
                        chosen = Some(result);
                        break;
                    }
                    Err(e) => last_err = e,
                }
            }
            let result = chosen.ok_or(last_err)?;
            Ok(Plan { lp, ghosts, templates: t, kind: Kind::Search, witness, result, traces, synth_candidates: cands_n })
        }
        ([], false) => {
            // a reduction to the static exhaustion (no payload, no dynamic
            // exit): a MaskedCount counter's value after the last iteration
            let mc: Vec<u32> = (0..lp.params.len() as u32).filter(|i| matches!(lp.classes[*i as usize], Class::MaskedCount { .. })).collect();
            let [c] = mc[..] else { return Err("a reduction loop without a counting variable".into()) };
            let Class::MaskedCount { src, thr, strict, .. } = lp.classes[c as usize] else { unreachable!() };
            let w = lp.params[c as usize].width.ok_or("a counter that is not an integer")?;
            let sw = lp.params[src as usize].width.ok_or("a source that is not an integer")?;
            let c0 = entry(&lp, &ghosts, env, c).ok_or("an entry value")?;
            let k0 = cast_to(entry(&lp, &ghosts, env, thr).ok_or("an entry value")?, Width::U32);
            let p = masked_p(env, &lp, &ghosts, c).ok_or("the counted bits")?;
            // every position below the width past the threshold: `k < T`
            let t_bound = if strict { expr::bits(sw) - 1 } else { expr::bits(sw) };
            let regime = expr::op2(PrimOp::Lt(Width::U32), k0, expr::lit(Width::U32, t_bound as u128));
            let result = SVal::Ce(simp(&expr::op2(PrimOp::WAdd(w), c0, expr::ite(regime, cast_to(p, w), expr::lit(w, 0))), None));
            let witness = expr::lit(Width::U32, k as u128);
            validate_parts(&lp, &t, &Kind::Search, &result, &traces)?;
            Ok(Plan { lp, ghosts, templates: t, kind: Kind::Search, witness, result, traces, synth_candidates: 0 })
        }
        _ => Err("neither a single-payload search without exits nor a search with dynamic exits".into()),
    }
}

/// Whether the loop has a dynamic exit: an exit path with a guard on a
/// dynamic parameter that is feasible before the static exhaustion (an
/// exit only at the exhaustion, whose guards select the last iteration's
/// update, is a reduction's).
pub fn has_dynamic_exit(lp: &Loop) -> bool {
    lp.exits.iter().any(|e| {
        let dynamic = e.guards.iter().any(|(g, _)| {
            let mut vs = Vec::new();
            g.vars(&mut vs);
            vs.iter().any(|v| lp.classes[*v as usize] != Class::Static)
        });
        dynamic && (0..lp.k).any(|jj| exit_feasible_at(lp, e, jj))
    })
}

/// Whether an exit path's guards mention only static parameters.
pub fn exit_static(lp: &Loop, e: &super::classify::ExitPath) -> bool {
    e.guards.iter().all(|(g, _)| {
        let mut vs = Vec::new();
        g.vars(&mut vs);
        vs.iter().all(|v| lp.classes[*v as usize] == Class::Static)
    })
}

/// Whether an exit path is feasible at iteration `jj` (its static guards
/// hold there).
pub fn exit_feasible_at(lp: &Loop, e: &super::classify::ExitPath, jj: u32) -> bool {
    let st: Vec<CVal> = lp.static_seq[jj as usize].iter().map(|c| c.clone().unwrap_or(CVal::N(Val::W(Width::U64, 0)))).collect();
    e.guards.iter().all(|(g, b)| {
        let mut vs = Vec::new();
        g.vars(&mut vs);
        if vs.iter().any(|v| lp.classes[*v as usize] != Class::Static) {
            return true;
        }
        eval_sval(&SVal::Ce(g.clone()), &st).map(|v| v == CVal::N(Val::B(*b))).unwrap_or(true)
    })
}

/// A structured value of a closed kernel term.
fn sval_of_cval(env: &Env, t: &sandblaster_kernel::term::Tm) -> Option<SVal> {
    let mut b = Budget { steps: 1_000_000 };
    let v = env.eval(&VEnv::default(), Lvl(0), t, &mut b).ok()?;
    match &*v {
        sandblaster_kernel::value::Value::Ctor { ind, ctor, params, args } if *ind != env.bool_ind() => {
            let mut out = Vec::new();
            for a in args {
                if let sandblaster_kernel::value::Arg::Rel(x) = a {
                    let q = env.quote(Lvl(0), x, false);
                    out.push(sval_of_cval(env, &q)?);
                }
            }
            Some(SVal::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: out })
        }
        _ => match super::classify::closed_cval(env, t)? {
            CVal::N(Val::W(w, n)) => Some(SVal::Ce(expr::lit(w, n))),
            CVal::N(Val::B(bb)) => Some(SVal::Ce(Rc::new(CE::BoolLit(bb)))),
            _ => None,
        },
    }
}

/// Validates the plan on the traces, conjunct by conjunct at every
/// recorded iteration (design §7.5, order of checks): every template
/// against the state, the `FirstMatch` template, and the result.
pub fn validate(p: &Plan) -> Result<(), String> {
    validate_parts(&p.lp, &p.templates, &p.kind, &p.result, &p.traces)
}

/// [`validate`] on the plan's parts.
pub fn validate_parts(lp: &Loop, templates: &[Option<E>], kind: &Kind, result: &SVal, traces: &Traces) -> Result<(), String> {
    for tr in &traces.traces {
        let g = trace_ghosts(tr);
        for (jj, st) in tr.states.iter().enumerate() {
            for (i, t) in templates.iter().enumerate() {
                if lp.classes[i] == Class::Static && t.is_none() {
                    continue;
                }
                let Some(t) = t else { continue };
                let v = t.eval(&g, Some(jj as u128));
                if v.map(CVal::N).as_ref() != Some(&st[i]) {
                    return Err(format!("the closed form of `{}` fails on a trace at iteration {jj} (input {:?}: {v:?} vs {:?})", lp.params[i].name, tr.input, st[i]));
                }
            }
            if let Kind::FirstMatch { param, pr, payload, unset } = kind {
                let nums: Vec<u128> = st.iter().map(|c| c.num().unwrap_or(0)).collect();
                let set = pr.eval(&nums, None).and_then(|v| v.as_bool()).ok_or("the set predicate does not evaluate")?;
                let want = if set { eval_ghost(payload, &g, None) } else { eval_ghost(unset, &g, None) };
                if want.as_ref() != Some(&st[*param as usize]) {
                    return Err(format!("the FirstMatch invariant fails on a trace at iteration {jj} (input {:?})", tr.input));
                }
            }
        }
        let r = eval_ghost(result, &g, None);
        if r.as_ref() != Some(&tr.result) {
            return Err(format!("the closed form of the result fails on input {:?}: {r:?} vs {:?}", tr.input, tr.result));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core text of the plan's terms.
// ---------------------------------------------------------------------------

/// Renders structured values and types as core text.
pub struct Render<'a> {
    pub env: &'a Env,
}

impl Render<'_> {
    /// Core text of a closed type value.
    pub fn ty(&self, v: &sandblaster_kernel::value::V) -> String {
        let t = self.env.quote(Lvl(0), v, false);
        self.env.print_term(&[], &t)
    }

    /// The constructor's name (as the core printer writes it).
    pub fn ctor_name(&self, ind: sandblaster_kernel::term::IndId, ctor: u32) -> String {
        let t = sandblaster_kernel::util::mk::ctor(ind, ctor, vec![], vec![]);
        self.env.print_term(&[], &t)
    }

    /// Core text of a structured value (ghost or state space: `names` binds
    /// `CE::Var`), `jtext` for `J`.
    pub fn sval(&self, s: &SVal, names: &[String], jtext: Option<&str>) -> String {
        match s {
            SVal::Ce(e) => e.text(names, jtext),
            SVal::Ctor { ind, ctor, params, args } => {
                let mut out = self.ctor_name(*ind, *ctor);
                if !params.is_empty() {
                    out.push('[');
                    out.push_str(&params.iter().map(|p| self.ty(p)).collect::<Vec<_>>().join(", "));
                    out.push(']');
                }
                if !args.is_empty() {
                    out.push('(');
                    out.push_str(&args.iter().map(|a| self.sval(a, names, jtext)).collect::<Vec<_>>().join(", "));
                    out.push(')');
                }
                out
            }
            SVal::Ite(c, a, b) => {
                format!("match {} : Bool as _ return {} with | false => {} | true => {} end", c.text(names, jtext), self.sval_ty(s), self.sval(b, names, jtext), self.sval(a, names, jtext))
            }
            SVal::Param(p) => names.get(*p as usize).cloned().unwrap_or_else(|| "?".into()),
        }
    }

    /// The type of a structured value (a constructor's type from its
    /// inductive and parameters).
    pub fn sval_ty(&self, s: &SVal) -> String {
        match s {
            SVal::Ce(e) => expr::ty_text(e.ty()),
            SVal::Ctor { ind, params, .. } => {
                let t = sandblaster_kernel::util::mk::ind(*ind, params.iter().map(|p| self.env.quote(Lvl(0), p, false)).collect());
                self.env.print_term(&[], &t)
            }
            SVal::Ite(_, a, _) => self.sval_ty(a),
            SVal::Param(_) => "?".into(),
        }
    }
}

/// A context of named binders for rendering terms evaluated in it.
pub fn names_of(ctx: &Ctx) -> Vec<String> {
    ctx.entries.iter().map(|e| e.name.to_string()).collect()
}

/// Evaluates the loop's `requires` binder types at iteration `jj` (static
/// parameters at their values there; the dynamic ones as the binders named
/// `dyn_names`), rendered as core text in those names.
pub fn requires_text(env: &Env, lp: &Loop, jj: Option<u32>, dyn_names: &[String]) -> Result<Vec<String>, String> {
    let tele = crate::opt::symex::telescope(env, lp.one.def).ok_or("no telescope")?;
    let mut st = crate::auto::state::St::new(env, &Ctx::default(), 0);
    let mut venv: Vec<EnvEntry> = Vec::new();
    let mut b = Budget { steps: 10_000_000 };
    let mut di = 0;
    let mut out = Vec::new();
    for (i, (_, rel, dom)) in tele.binders.iter().enumerate() {
        match rel {
            Rel::Rel => {
                let is_static = lp.classes[i] == Class::Static || lp.statics[i].is_some() && jj.is_none();
                if is_static && lp.classes[i] == Class::Static {
                    let c = match jj {
                        Some(jj) => lp.static_seq[jj as usize][i].clone().ok_or("a static value")?,
                        None => super::classify::closed_cval(env, lp.statics[i].as_ref().unwrap()).ok_or("a static value")?,
                    };
                    let v = super::traces::cval_value(env, &c).ok_or("a static value")?;
                    venv.push(EnvEntry::Rel(v));
                } else if lp.statics[i].is_some() && jj.is_none() {
                    let t = lp.statics[i].as_ref().unwrap();
                    let v = env.eval(&VEnv::default(), Lvl(0), t, &mut b).map_err(|e| format!("{e:?}"))?;
                    venv.push(EnvEntry::Rel(v));
                } else if lp.statics[i].is_some() && lp.classes[i] != Class::Static {
                    // a dynamic-evolving parameter static at the call: a binder
                    let ty = env.eval(&VEnv(Rc::new(venv.clone())), Lvl(st.depth()), dom, &mut b).map_err(|e| format!("{e:?}"))?;
                    let name: sandblaster_kernel::term::Name = Rc::from(dyn_names.get(di).ok_or("a binder name")?.as_str());
                    di += 1;
                    let e = st.push_raw(env, name, Rel::Rel, ty);
                    venv.push(e);
                } else {
                    let ty = env.eval(&VEnv(Rc::new(venv.clone())), Lvl(st.depth()), dom, &mut b).map_err(|e| format!("{e:?}"))?;
                    let name: sandblaster_kernel::term::Name = Rc::from(dyn_names.get(di).ok_or("a binder name")?.as_str());
                    di += 1;
                    let e = st.push_raw(env, name, Rel::Rel, ty);
                    venv.push(e);
                }
            }
            Rel::Irr => {
                let tv = env.eval(&VEnv(Rc::new(venv.clone())), Lvl(st.depth()), dom, &mut b).map_err(|e| format!("{e:?}"))?;
                let tm = env.quote(Lvl(st.depth()), &tv, false);
                let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
                out.push(env.print_term(&names, &tm));
                let e = st.push_raw(env, Rc::from(format!(".r{}", out.len() - 1).as_str()), Rel::Irr, tv);
                venv.push(e);
            }
        }
    }
    Ok(out)
}

/// Pretty form of the plan for the report.
pub fn describe(p: &Plan, env: &Env) -> String {
    let names: Vec<String> = p.ghosts.iter().map(|g| g.name.clone()).collect();
    let snames: Vec<String> = p.lp.params.iter().map(|x| x.name.clone()).collect();
    let r = Render { env };
    let mut s = format!("K = {}; witness j* = {}; result = {}", p.lp.k, expr::show(&p.witness, &names), r.sval(&p.result, &names, Some("j")));
    for (i, c) in p.lp.classes.iter().enumerate() {
        s.push_str(&format!("; {}: {c:?}", snames[i]));
    }
    let _ = ToPrimitive::to_u64(&0u8);
    s
}

/// Saturating shifts whose amount is below the width on every sample
/// become plain shifts (the printed closed form; the per-literal lemmas
/// check the result wherever it is used).
pub fn unsat(e: &E, samples: &[Vec<u128>]) -> E {
    match &**e {
        CE::ShrSat(a, b) | CE::ShlSat(a, b) => {
            let (a2, b2) = (unsat(a, samples), unsat(b, samples));
            let w = a2.width().unwrap_or(Width::U64);
            let bits = expr::bits(w) as u128;
            let amts: Vec<Option<u128>> = samples.iter().map(|g| b2.eval(g, None).and_then(|v| v.as_u128())).collect();
            let safe = amts.iter().all(|x| x.is_some_and(|x| x < bits));
            // an amount in [1, w]: two plain shifts, `(x ⊙ (a − 1)) ⊙ 1`
            let split = amts.iter().all(|x| x.is_some_and(|x| (1..=bits).contains(&x)));
            let shr = matches!(&**e, CE::ShrSat(..));
            let o = if shr { PrimOp::WShr(w) } else { PrimOp::WShl(w) };
            if safe {
                expr::op2(o, a2, b2)
            } else if split {
                let am1 = expr::op2(PrimOp::WSub(Width::U32), b2, expr::lit(Width::U32, 1));
                expr::op2(o, expr::op2(o, a2, am1), expr::lit(Width::U32, 1))
            } else if shr {
                Rc::new(CE::ShrSat(a2, b2))
            } else {
                Rc::new(CE::ShlSat(a2, b2))
            }
        }
        CE::Op(o, a) => expr::op(*o, a.iter().map(|x| unsat(x, samples)).collect()),
        CE::Ite(c, a, b) => expr::ite(unsat(c, samples), unsat(a, samples), unsat(b, samples)),
        CE::DivLit(a, c) => Rc::new(CE::DivLit(unsat(a, samples), *c)),
        _ => e.clone(),
    }
}

/// [`unsat`] over a structured value.
pub fn unsat_sval(s: &SVal, samples: &[Vec<u128>]) -> SVal {
    match s {
        SVal::Ce(e) => SVal::Ce(unsat(e, samples)),
        SVal::Ctor { ind, ctor, params, args } => SVal::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: args.iter().map(|a| unsat_sval(a, samples)).collect() },
        SVal::Ite(c, a, b) => SVal::Ite(unsat(c, samples), Box::new(unsat_sval(a, samples)), Box::new(unsat_sval(b, samples))),
        SVal::Param(p) => SVal::Param(*p),
    }
}

/// Orients `lz(a ^ b)` in a witness so that `a` has the bit at the
/// leading-zero position set on the samples (the prefix lemma's `x`).
pub fn orient_xor(e: &E, samples: &[Vec<u128>]) -> E {
    match &**e {
        CE::Op(PrimOp::LeadingZeros(w), a) if matches!(&*a[0], CE::Op(PrimOp::Xor(_), _)) => {
            let CE::Op(xo, xy) = &*a[0] else { unreachable!() };
            let b = expr::bits(*w);
            let mut a_has = 0usize;
            let mut b_has = 0usize;
            for g in samples {
                let (Some(x), Some(y), Some(z)) = (xy[0].eval(g, None).and_then(|v| v.as_u128()), xy[1].eval(g, None).and_then(|v| v.as_u128()), e.eval(g, None).and_then(|v| v.as_u128())) else { continue };
                if z >= b as u128 {
                    continue;
                }
                let k = b as u128 - 1 - z;
                if (x >> k) & 1 == 1 {
                    a_has += 1;
                }
                if (y >> k) & 1 == 1 {
                    b_has += 1;
                }
            }
            if b_has > a_has {
                expr::op(PrimOp::LeadingZeros(*w), vec![expr::op2(*xo, xy[1].clone(), xy[0].clone())])
            } else {
                e.clone()
            }
        }
        CE::Op(o, a) => expr::op(*o, a.iter().map(|x| orient_xor(x, samples)).collect()),
        CE::Ite(c, a, b) => expr::ite(c.clone(), orient_xor(a, samples), orient_xor(b, samples)),
        CE::DivLit(a, c) => Rc::new(CE::DivLit(orient_xor(a, samples), *c)),
        _ => e.clone(),
    }
}

/// `e` with the amount of every saturating right shift increased by `d`
/// (fault R8).
fn shift_amounts(e: &E, d: u128) -> E {
    match &**e {
        CE::ShrSat(a, b) => Rc::new(CE::ShrSat(a.clone(), expr::op2(PrimOp::WSub(Width::U32), b.clone(), expr::lit(Width::U32, d)))),
        CE::Op(o, a) => expr::op(*o, a.iter().map(|x| shift_amounts(x, d)).collect()),
        _ => e.clone(),
    }
}
