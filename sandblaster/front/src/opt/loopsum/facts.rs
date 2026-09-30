//! Exported facts of a loop summary (optimizer design §6.4 "output facts",
//! §12.1; plan O6: `shape` exports `height ≤ 62`, `before + after ≤ 61`,
//! `index < width`).
//!
//! **Candidates.** For a `FirstMatch` loop whose payload is `Some(C(f̄))`
//! over a struct `C` with machine-integer fields, the candidate facts about
//! the payload `v` are, Houdini-style ([`candidates`]):
//!
//! * `fᵢ ≤ c` — `c` the largest value of the field at the hit iteration
//!   when the field is a function of the static parameters alone (the
//!   height `fuel − 1`), else the largest value on the traces;
//! * `fᵢ < fⱼ` for two fields of one width that hold on every trace;
//! * `fᵢ + fⱼ ≤ c` (in `Int`) with `c` the traces' largest sum, when that
//!   is tighter than the sum of the two fields' own bounds.
//!
//! Candidates are filtered on the traces before any proof work.
//!
//! **Proof: the fact chain.** `holds(o) = match o { None => true, Some(v)
//! => P₀(v) && P₁(v) && … }` (a transparent kernel definition) and, per
//! literal `j` as in the summary's own chain (`lemmas`), the
//! non-recursive lemma
//!
//! ```text
//! fact_j : Π s̄ ḡ (.r) (.gf) (inv_j without the payload's conjunct) (.q : holds(found) = true).
//!          Eq(Bool, holds(h(j, s̄)), true)
//! ```
//!
//! `fact_K` holds because the exhausted loop returns `found`; `fact_j`
//! unfolds one iteration and splits on the body's tests, applying
//! `fact_{j+1}` at each recursive call — the invariant at the next state as
//! obligations, and `.q` for the next payload: unchanged (the assumption)
//! or, at the hit, the payload constructor over the state, whose
//! conjuncts are proven by linear arithmetic over the state's facts with
//! the bit library (`popcnt_le_k` instances for the popcount fields). The
//! entry lemma `<prefix>::fact : Π d̄ h̄. Eq(Bool, holds(loop(statics, d̄)
//! h̄), true)` applies `fact_0` at the call's static arguments (the
//! payload unset: `holds(None)` computes to `true`). Every lemma is
//! committed with `Env::add_def`: the kernel checks it. A candidate whose
//! conjunct fails is dropped and the chain built again once.

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{Arm, DefDecl, DefKind, GlobalId, IndId, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, Neutral, V, Value};

use super::classify::{CVal, Class, SVal};
use super::expr;
use super::invariant::{Kind, Plan};
use super::lemmas::{self, Spec};
use crate::auto::bitlib::{self, Family};
use crate::auto::search::{Engine, R};
use crate::auto::state::St;
use crate::auto::util::{apps, as_eq, irr_entry};

/// At most this many candidate facts are proven per loop.
pub const MAX_FACTS: usize = 6;

/// One candidate fact about the payload's fields (field indices into the
/// payload constructor's relevant fields).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cand {
    Le { field: usize, c: u128 },
    Lt { a: usize, b: usize },
    SumLe { a: usize, b: usize, c: u128 },
}

/// The payload's shape: `Some(C(f̄))`.
#[derive(Clone, Debug)]
pub struct Payload {
    /// The result's inductive (`Option`) and its type parameters, the
    /// constructor of the set payload and of the unset value.
    pub opt: IndId,
    pub opt_params: Vec<V>,
    pub some: u32,
    pub none: u32,
    /// The struct and its type parameters.
    pub st: IndId,
    pub st_params: Vec<V>,
    /// Per field: its machine width (`None`: not an integer).
    pub widths: Vec<Option<Width>>,
    /// Field names (the report).
    pub names: Vec<String>,
}

/// The loop's exported facts.
#[derive(Clone, Debug)]
pub struct LoopFacts {
    /// `holds : R → Bool`.
    pub holds: GlobalId,
    /// Per conjunct: the opaque `<prefix>::conj<k> : S → Bool` (`holds`'
    /// conjuncts: they stay folded in the proofs, which unfold them one at
    /// a time by `Delta`).
    pub conj_defs: Vec<GlobalId>,
    /// `<prefix>::fact : Π d̄ h̄. Eq(Bool, holds(loop(statics, d̄) h̄), true)`
    /// (the helper's telescope).
    pub entry: GlobalId,
    /// The proven conjuncts, in `holds`' order, with what they state.
    pub conjuncts: Vec<(Cand, String)>,
    pub payload: Payload,
    pub steps: u64,
}

/// The payload's shape, if the plan is a `FirstMatch` loop with an
/// `Option`-of-struct payload.
pub fn payload_shape(env: &Env, p: &Plan) -> Option<Payload> {
    let Kind::FirstMatch { payload, unset, .. } = &p.kind else { return None };
    let SVal::Ctor { ind: opt, ctor: some, params: opt_params, args } = payload else { return None };
    let SVal::Ctor { ctor: none, .. } = unset else { return None };
    let [SVal::Ctor { ind: st, ctor: 0, params: st_params, args: fields }] = &args[..] else { return None };
    let decl = env.inductive_decl(*st)?;
    if decl.ctors.len() != 1 {
        return None;
    }
    let widths: Vec<Option<Width>> = fields.iter().map(|f| match f {
        SVal::Ce(e) => match e.ty() {
            expr::Ty::W(w) if w != Width::Int => Some(w),
            _ => None,
        },
        _ => None,
    }).collect();
    let names: Vec<String> = decl.ctors[0].fields.iter().filter(|f| f.1 == Rel::Rel).map(|f| f.0.to_string()).collect();
    if names.len() != widths.len() {
        return None;
    }
    Some(Payload { opt: *opt, opt_params: opt_params.clone(), some: *some, none: *none, st: *st, st_params: st_params.clone(), widths, names })
}

/// The payload's fields in **state** space at the hit (the constructor leaf
/// of the payload parameter's update select tree).
fn payload_state(p: &Plan) -> Option<Vec<SVal>> {
    let Kind::FirstMatch { param, .. } = &p.kind else { return None };
    fn leaf(s: &SVal) -> Option<SVal> {
        match s {
            SVal::Ctor { .. } => Some(s.clone()),
            SVal::Ite(_, a, b) => leaf(a).or_else(|| leaf(b)),
            _ => None,
        }
    }
    let s = p.lp.cont.iter().find_map(|c| leaf(&c.next[*param as usize]))?;
    let SVal::Ctor { args, .. } = s else { return None };
    let [SVal::Ctor { args: fields, .. }] = &args[..] else { return None };
    Some(fields.clone())
}

/// An infeasible arm by one linear-arithmetic query over its facts (the
/// full contradiction search, a query per disequality fact, is the costly
/// step of the fact chain: it runs only after the arm's own proof failed,
/// [`full_absurd`]).
fn quick_absurd(e: &mut Engine<'_>, st: &mut St, goal: &V) -> R<Option<Tm>> {
    let empty: V = Rc::new(Value::Ind { ind: e.env.empty_ind(), params: vec![] });
    let ch = st.child();
    match e.lin_prove(&ch, &empty, true)? {
        Some(p) => Ok(Some(e.absurd(st, goal, ch.finish(p)))),
        None => Ok(None),
    }
}

/// An infeasible arm by the full contradiction search.
fn full_absurd(e: &mut Engine<'_>, st: &mut St, goal: &V) -> R<Option<Tm>> {
    let mut ch = st.child();
    match e.contradiction(&mut ch) {
        Ok(Some(p)) => Ok(Some(e.absurd(st, goal, ch.finish(p)))),
        _ => Ok(None),
    }
}

/// The trace payloads' field values (traces that set the payload).
fn trace_fields(p: &Plan, pl: &Payload) -> Vec<Vec<u128>> {
    let mut out = Vec::new();
    for tr in &p.traces.traces {
        if let CVal::Ctor { ctor, args, .. } = &tr.result
            && *ctor == pl.some
            && let [CVal::Ctor { args: fs, .. }] = &args[..]
        {
            out.push(fs.iter().map(|f| f.num().unwrap_or(u128::MAX)).collect());
        }
    }
    out
}

/// The candidate facts (see the module docs), filtered on the traces.
pub fn candidates(p: &Plan, pl: &Payload) -> Vec<Cand> {
    let rows = trace_fields(p, pl);
    if rows.len() < 8 {
        return Vec::new();
    }
    let n = pl.widths.len();
    let st_fields = payload_state(p);
    let lp = &p.lp;
    // per field: its bound (static at the hit, else the traces' largest)
    let mut bound: Vec<Option<(u128, bool)>> = vec![None; n];
    for i in 0..n {
        let Some(w) = pl.widths[i] else { continue };
        let tmax = rows.iter().map(|r| r[i]).max().unwrap_or(0);
        let stat = st_fields.as_ref().and_then(|fs| match &fs[i] {
            SVal::Ce(e) => {
                let mut vs = Vec::new();
                e.vars(&mut vs);
                if !vs.iter().all(|v| lp.classes[*v as usize] == Class::Static) {
                    return None;
                }
                let mut m: Option<u128> = None;
                for jj in 0..lp.k as usize {
                    let nums: Vec<u128> = lp.static_seq[jj].iter().map(|c| c.as_ref().and_then(|x| x.num()).unwrap_or(0)).collect();
                    let v = e.eval(&nums, None)?.as_u128()?;
                    m = Some(m.map_or(v, |x| x.max(v)));
                }
                m
            }
            _ => None,
        });
        match stat {
            Some(c) => bound[i] = Some((c, true)),
            None if tmax < expr::mask(w) => bound[i] = Some((tmax, false)),
            None => {}
        }
    }
    let mut out = Vec::new();
    // unary bounds: only the static ones (exact; a traces' maximum is only
    // a guess, and the sums below imply the useful ones)
    for i in 0..n {
        if let (Some((c, true)), Some(w)) = (bound[i], pl.widths[i])
            && c < expr::mask(w)
            && rows.iter().all(|r| r[i] <= c)
        {
            out.push(Cand::Le { field: i, c });
        }
    }
    // strict relations between two fields of one width
    for a in 0..n {
        for b in 0..n {
            if a == b || pl.widths[a].is_none() || pl.widths[a] != pl.widths[b] {
                continue;
            }
            if rows.iter().all(|r| r[a] < r[b]) {
                out.push(Cand::Lt { a, b });
            }
        }
    }
    // sums of two small fields (counts: bounded by the word size on every
    // trace), tighter than the two fields' own bounds
    let small = |i: usize| bound[i].is_some_and(|(c, _)| c <= 1 << 16);
    for a in 0..n {
        for b in a + 1..n {
            if pl.widths[a].is_none() || pl.widths[a] != pl.widths[b] || !small(a) || !small(b) {
                continue;
            }
            let (Some((ba, _)), Some((bb, _))) = (bound[a], bound[b]) else { continue };
            let c = rows.iter().map(|r| r[a].saturating_add(r[b])).max().unwrap_or(0);
            if c.saturating_add(1) < ba.saturating_add(bb) {
                out.push(Cand::SumLe { a, b, c });
            }
        }
    }
    out.truncate(MAX_FACTS);
    out
}

impl Cand {
    /// What it states, over the field names.
    pub fn describe(&self, names: &[String]) -> String {
        match self {
            Cand::Le { field, c } => format!("{} <= {c}", names[*field]),
            Cand::Lt { a, b } => format!("{} < {}", names[*a], names[*b]),
            Cand::SumLe { a, b, c } => format!("{} + {} <= {c}", names[*a], names[*b]),
        }
    }
}

// ---------------------------------------------------------------------------
// Terms.
// ---------------------------------------------------------------------------

/// `πₖ s` of the payload struct (the elaborator's projection form: a match
/// with one arm), at the depth `s` lives in (`params` quoted there).
pub fn proj(env: &Env, pl: &Payload, params: &[Tm], s: Tm, k: usize) -> Tm {
    let nf = env.inductive_decl(pl.st).map(|d| d.ctors[0].fields.len()).unwrap_or(pl.widths.len());
    let w = pl.widths[k].unwrap_or(Width::U64);
    let names: Vec<sandblaster_kernel::term::Name> = (0..nf).map(|_| Rc::from("x")).collect();
    Rc::new(Term::Match { ind: pl.st, params: params.to_vec(), scrut: s, motive: mk::int_ty(w), arms: vec![Arm { names, body: mk::var((nf - 1 - k) as u32) }] })
}

/// The Bool term of a candidate over the payload `v` (a term at its depth;
/// `params` the struct's type parameters quoted there).
pub fn cand_term(env: &Env, pl: &Payload, params: &[Tm], v: &Tm, c: &Cand) -> Tm {
    let f = |k: usize| proj(env, pl, params, v.clone(), k);
    let prim = |op: PrimOp, args: Vec<Tm>| Rc::new(Term::Prim { op, args, proofs: vec![] });
    match c {
        Cand::Le { field, c } => {
            let w = pl.widths[*field].unwrap();
            prim(PrimOp::Le(w), vec![f(*field), mk::lit(w, *c)])
        }
        Cand::Lt { a, b } => prim(PrimOp::Lt(pl.widths[*a].unwrap()), vec![f(*a), f(*b)]),
        Cand::SumLe { a, b, c } => {
            let wa = pl.widths[*a].unwrap();
            let to_int = |t: Tm| prim(PrimOp::Cast { from: wa, to: Width::Int }, vec![t]);
            prim(PrimOp::Le(Width::Int), vec![prim(PrimOp::IAdd, vec![to_int(f(*a)), to_int(f(*b))]), mk::lit(Width::Int, *c)])
        }
    }
}

/// The conjunction `c₀ && (c₁ && …)` (`bool::and`), or `true`.
fn conj(env: &Env, cs: Vec<Tm>) -> Tm {
    let bi = env.bool_ind();
    let and = env.lookup_global("bool::and").expect("bool::and");
    let mut it = cs.into_iter().rev();
    let Some(mut acc) = it.next() else { return mk::bool_lit(bi, true) };
    for c in it {
        acc = apps(mk::global(and), [(Rel::Rel, c), (Rel::Rel, acc)]);
    }
    acc
}

/// Commits the conjuncts `<name>::conj<k> : S → Bool` (opaque) and `holds :
/// R → Bool` (see the module docs) for the result type `ret` (closed).
fn commit_holds(env: &mut Env, pl: &Payload, ret: &Tm, cands: &[Cand], name: &str) -> Result<(GlobalId, Vec<GlobalId>), String> {
    let decl = env.inductive_decl(pl.opt).ok_or("the result type")?;
    let bi = env.bool_ind();
    let st_params1: Vec<Tm> = pl.st_params.iter().map(|p| crate::auto::util::shift(&env.quote(sandblaster_kernel::term::Lvl(0), p, false), 1)).collect();
    let s_ty = mk::ind(pl.st, pl.st_params.iter().map(|p| env.quote(sandblaster_kernel::term::Lvl(0), p, false)).collect());
    let mut defs = Vec::new();
    for (k, c) in cands.iter().enumerate() {
        let body = mk::lam("v", Rel::Rel, s_ty.clone(), cand_term(env, pl, &st_params1, &mk::var(0), c));
        let ty = mk::pi("v", Rel::Rel, s_ty.clone(), mk::bool_ty(bi));
        let cname = format!("{name}::conj{k}");
        let mut b = Budget { steps: 20_000_000 };
        let g = env.add_def(DefDecl { name: Rc::from(cname.as_str()), kind: DefKind::Spec, ty, body, recursion: Recursion::None, arity: 1, opaque: true }, &mut b).map_err(|e| format!("`{cname}`: {e}"))?;
        defs.push(g);
    }
    // `o` at depth 1; `v` at depth 2 in the payload arm
    let opt_params: Vec<Tm> = pl.opt_params.iter().map(|p| crate::auto::util::shift(&env.quote(sandblaster_kernel::term::Lvl(0), p, false), 1)).collect();
    let mut arms = Vec::new();
    for (k, c) in decl.ctors.iter().enumerate() {
        let names: Vec<sandblaster_kernel::term::Name> = c.fields.iter().map(|f| f.0.clone()).collect();
        let body = if k as u32 == pl.some && names.len() == 1 {
            conj(env, defs.iter().map(|g| apps(mk::global(*g), [(Rel::Rel, mk::var(0))])).collect())
        } else {
            mk::bool_lit(bi, true)
        };
        arms.push(Arm { names, body });
    }
    let m = Rc::new(Term::Match { ind: pl.opt, params: opt_params, scrut: mk::var(0), motive: mk::bool_ty(bi), arms });
    let body = mk::lam("o", Rel::Rel, ret.clone(), m);
    let ty = mk::pi("o", Rel::Rel, ret.clone(), mk::bool_ty(bi));
    let mut b = Budget { steps: 20_000_000 };
    let h = env.add_def(DefDecl { name: Rc::from(name), kind: DefKind::Spec, ty, body, recursion: Recursion::None, arity: 1, opaque: false }, &mut b).map_err(|e| format!("`{name}`: {e}"))?;
    Ok((h, defs))
}

// ---------------------------------------------------------------------------
// The fact chain.
// ---------------------------------------------------------------------------

fn eval_in(env: &Env, ctx: &Ctx, t: &Tm) -> Result<V, String> {
    env.eval(&env.ctx_venv(ctx), ctx.depth(), t, &mut Budget { steps: 50_000_000 }).map_err(|e| format!("eval: {e:?}"))
}

/// The first stuck match of a value: its scrutinee, inductive, type
/// parameters, and whether a later match of the spine is on `later` (a
/// select inside `holds`' payload).
fn first_match(v: &V, later: Option<IndId>) -> Option<(V, IndId, Vec<V>, bool)> {
    let Value::Neu(n) = &**v else { return None };
    let i = n.spine.iter().position(|e| matches!(e, Elim::Match { .. }))?;
    let Elim::Match { ind, params, .. } = &n.spine[i] else { return None };
    let inner = later.is_some_and(|o| n.spine[i + 1..].iter().any(|e| matches!(e, Elim::Match { ind, .. } if *ind == o)));
    Some((crate::auto::util::prefix(n, i), *ind, params.clone(), inner))
}

/// The loop application a value is at its head (under `holds`' match):
/// its arguments.
fn loop_under(v: &V, func: GlobalId) -> Option<Vec<Arg>> {
    match &**v {
        Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if *def == func && spine.iter().all(|e| matches!(e, Elim::Match { .. })) => Some(args.clone()),
        _ => None,
    }
}

/// Proof search for the fact chain.
struct FactB<'s> {
    spec: &'s Spec,
    holds: GlobalId,
    /// The conjuncts' opaque definitions (their index is the candidate's).
    conj_defs: Vec<GlobalId>,
    b: lemmas::Builder<'s>,
    /// Per popcount atom shape: the exponent (offset from the remaining
    /// fuel) of its last `popcnt_le` instance (tried first).
    le_memo: HashMap<String, (i64, i64)>,
    /// The `popcnt_le` instances found for the atoms of the arm whose
    /// conjuncts are being proven (by atom term; the conjuncts of one arm
    /// share its facts' atoms), emptied per arm ([`Self::q`]).
    arm_hints: HashMap<String, Option<Tm>>,
    /// Conjuncts that failed (indices), for the retry.
    failed: Vec<usize>,
    /// The result's inductive (`Option`): `holds`' match.
    opt: IndId,
    failure: Option<String>,
}

impl FactB<'_> {
    fn note(&mut self, env: &Env, st: &St, what: &str, v: &V) {
        if self.failure.is_none() {
            let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
            self.failure = Some(format!("fact_{} {what}: {}", self.b.j, crate::elab::show::value(env, &names, v, 600)));
        }
    }

    /// `popcnt_le_k` instances for the popcount atoms of `vals`: the
    /// smallest `k` with `y < 2^k` provable (memoized per atom shape).
    fn popcnt_le_hints(&mut self, e: &mut Engine<'_>, st: &St, vals: &[V]) -> Vec<Tm> {
        let env = e.env;
        let mut atoms: Vec<(Width, V)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for v in vals {
            crate::auto::util::walk(v, &mut |x| {
                if let Some((PrimOp::CountOnes(w), a)) = crate::auto::util::as_prim(x)
                    && seen.insert(Rc::as_ptr(&a[0]) as usize)
                {
                    atoms.push((w, a[0].clone()));
                }
                true
            });
        }
        let f_now = self.spec.k as i64 - self.b.j as i64;
        let mut out = Vec::new();
        let bi = env.bool_ind();
        for (w, y) in atoms {
            let y_tm = st.quote(env, &y);
            let exact_key = format!("{w:?}:{y_tm:?}");
            if let Some(h) = self.arm_hints.get(&exact_key) {
                out.extend(h.iter().cloned());
                continue;
            }
            let n_out = out.len();
            let key = format!("{w:?}:{}", shape_key(&y_tm));
            let bits = expr::bits(w);
            let proves = |e: &mut Engine<'_>, k: u32| -> Option<Tm> {
                if k >= bits {
                    return None;
                }
                let g = mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Lt(w), args: vec![y_tm.clone(), mk::lit(w, 1u128 << k)], proofs: vec![] }), mk::bool_lit(bi, true));
                let gv = eval_in(env, &st.ctx, &g).ok()?;
                match e.lin_prove(st, &gv, true) {
                    Ok(Some(p)) => Some(e.promote(st, &gv, p)),
                    _ => None,
                }
            };
            let mut found: Option<(u32, Tm)> = None;
            // the last instance's exponent, as an offset from the fuel or
            // against it (`k − f` or `k + f` constant along the chain)
            if let Some(&(off, sum)) = self.le_memo.get(&key) {
                for k in [f_now + off, sum - f_now] {
                    if found.is_some() || k < 0 {
                        continue;
                    }
                    if let Some(p) = proves(e, k as u32) {
                        found = Some((k as u32, p));
                        // (and not one lower: the smallest bound)
                        if k >= 1
                            && let Some(p2) = proves(e, k as u32 - 1)
                        {
                            found = None;
                            let _ = p2;
                        }
                    }
                }
            }
            if found.is_none() {
                // binary search for the smallest k (monotone)
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
                found = best;
            }
            if let Some((k, p)) = found {
                self.le_memo.insert(key, (k as i64 - f_now, k as i64 + f_now));
                if let Some(g) = env.lookup_global(&bitlib::lemma_name(Family::PopcntLe, w, k)) {
                    out.push(apps(mk::global(g), [(Rel::Rel, y_tm.clone()), (Rel::Irr, p)]));
                }
            }
            self.arm_hints.insert(exact_key, out.get(n_out).cloned());
        }
        out
    }

    /// A proof of `Eq(Bool, conj_k(C), true)` for the conjunct application
    /// `app` (`conj_k` opaque): `Delta` to its body at the payload
    /// constructor, proven by linear arithmetic over the state's facts
    /// (with the bit library's popcount bounds).
    fn conjunct(&mut self, e: &mut Engine<'_>, arm: &mut St, app: &V, k: usize) -> Option<Tm> {
        let env = e.env;
        let bi = env.bool_ind();
        let app_tm = arm.quote(env, app);
        let Term::App { arg, .. } = &*app_tm else { return None };
        let delta = Rc::new(Term::Delta { def: self.conj_defs[k], args: vec![arg.clone()] });
        let body = apps(env.global_body(self.conj_defs[k])?, [(Rel::Rel, arg.clone())]);
        let g = eval_in(env, &arm.ctx, &mk::eq(mk::bool_ty(bi), body.clone(), mk::bool_lit(bi, true))).ok()?;
        let mut vals = vec![g.clone()];
        for f in &arm.facts {
            vals.push(f.ty.clone());
        }
        let t0 = std::time::Instant::now();
        let extra = self.popcnt_le_hints(e, arm, &vals);
        let t1 = t0.elapsed();
        let r = self.b.obligation(e, arm, &g, &format!("fact.conj{k}"), &extra);
        if self.b.trace {
            eprintln!("[loopsum] fact_{} conjunct {k}: {} (hints {t1:?}, {} of them; total {:?})", self.b.j, r.is_some(), extra.len(), t0.elapsed());
        }
        let Some(p) = r else {
            if !self.failed.contains(&k) {
                self.failed.push(k);
            }
            self.note(env, arm, &format!("conjunct {k}"), &g);
            return None;
        };
        // conj_k(C) = body = true
        let trans = env.lookup_global("eq::trans")?;
        Some(apps(mk::global(trans), [(Rel::Rel, mk::bool_ty(bi)), (Rel::Rel, app_tm.clone()), (Rel::Rel, body), (Rel::Rel, mk::bool_lit(bi, true)), (Rel::Rel, delta), (Rel::Rel, p)]))
    }

    /// Which conjunct an application is (`conj_k(C)`).
    fn conj_of(&self, v: &V) -> Option<usize> {
        match &**v {
            Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if spine.is_empty() && args.len() == 1 => self.conj_defs.iter().position(|g| g == def),
            _ => None,
        }
    }

    /// Proves `target` (`Eq(Bool, c, true)`, `c` the payload's conjunction
    /// once the payload is a constructor: `conj₀(C) && (conj₁(C) && …)`, the
    /// conjuncts opaque): each in turn proven ([`Self::conjunct`]) and
    /// rewritten to `true`.
    fn conjuncts(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        if let Some(p) = lemmas::trivial(env, &arm.ctx, target, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        let Some((_, lhs, _)) = as_eq(target) else { return Ok(None) };
        let lhs = lhs.clone();
        // the last conjunct: the goal itself
        if let Some(k) = self.conj_of(&lhs) {
            return Ok(self.conjunct(e, arm, &lhs, k));
        }
        let Some((c, _, _, _)) = first_match(&lhs, None) else {
            self.note(env, arm, "a payload that is not a conjunction", target);
            return Ok(None);
        };
        let Some(k) = self.conj_of(&c) else {
            self.note(env, arm, "a test that is not a conjunct", target);
            return Ok(None);
        };
        if depth == 0 {
            return Ok(None);
        }
        let Some(p) = self.conjunct(e, arm, &c, k) else { return Ok(None) };
        let bi = env.bool_ind();
        let bt = mk::bool_ty(bi);
        let c_tm = arm.quote(env, &c);
        let sym = env.lookup_global("eq::sym").expect("eq::sym");
        let t = mk::bool_lit(bi, true);
        let eq = apps(mk::global(sym), [(Rel::Rel, bt.clone()), (Rel::Rel, c_tm.clone()), (Rel::Rel, t.clone()), (Rel::Rel, p)]);
        match lemmas::rewrite(env, arm, target, &c_tm, &t, bt, eq) {
            Some((t2, w)) => Ok(self.conjuncts(e, arm, &t2, depth - 1)?.map(w)),
            None => Ok(None),
        }
    }

    /// `.q` at the next state: `Eq(Bool, holds(found'), true)` — the
    /// assumption when the payload is unchanged; the payload's selects are
    /// split (an infeasible arm closes by contradiction) down to the old
    /// payload or its constructor, whose conjuncts are proven.
    fn q(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        if let Some(p) = lemmas::trivial(env, &arm.ctx, target, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        let Some((_, lhs, _)) = as_eq(target) else { return Ok(None) };
        let lhs = lhs.clone();
        let opt = self.opt;
        if let Some((c, ind, params, true)) = first_match(&lhs, Some(opt))
            && depth > 0
        {
            let d = arm.depth_left;
            // (the arm's own proof first: the payload's arms are nearly all
            // feasible, where the infeasibility query only fails — 376 of
            // 378 on QMDB's `shape_go` — and a conjunct over contradictory
            // facts closes by the same linear arithmetic anyway)
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
                let saved = (self.failed.clone(), self.failure.clone());
                match self.q(e2, a2, &tk, depth - 1) {
                    Ok(Some(p)) => return Ok(Some(p)),
                    Ok(None) => {}
                    Err(err) => {
                        if let Ok(Some(p)) = quick_absurd(e2, a2, &tk) {
                            (self.failed, self.failure) = saved;
                            return Ok(Some(p));
                        }
                        return Err(err);
                    }
                }
                let p = match quick_absurd(e2, a2, &tk)? {
                    Some(p) => Some(p),
                    None => full_absurd(e2, a2, &tk)?,
                };
                if p.is_some() {
                    // (an infeasible arm: its attempt's failures do not count)
                    (self.failed, self.failure) = saved;
                }
                Ok(p)
            };
            return e.case_split_with(arm, &c, ind, &params, target, true, d, &mut arm_fn);
        }
        self.arm_hints.clear();
        let r = self.conjuncts(e, arm, target, 16);
        self.arm_hints.clear();
        r
    }

    /// Applies `prev` (`fact_{j+1}`) at the recursive call `args`.
    fn apply_prev(&mut self, e: &mut Engine<'_>, arm: &mut St, prev: GlobalId, call: &[Arg]) -> R<Option<Tm>> {
        let env = e.env;
        let spec = self.spec;
        let rel_args: Vec<V> = call.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
        let mut rel_vals: Vec<V> = spec.state.iter().map(|(_, _, i)| rel_args[*i as usize].clone()).collect();
        for (g, _) in &spec.ghosts {
            match lemmas::parse_in(env, &arm.ctx, g).and_then(|t| eval_in(env, &arm.ctx, &t)) {
                Ok(v) => rel_vals.push(v),
                Err(_) => return Ok(None),
            }
        }
        self.apply_with(e, arm, prev, rel_vals)
    }

    /// Applies a lemma of the fact chain (state binders, then ghosts) to
    /// `rel_vals`, proving its irrelevant binders.
    fn apply_with(&mut self, e: &mut Engine<'_>, arm: &mut St, lem: GlobalId, rel_vals: Vec<V>) -> R<Option<Tm>> {
        let env = e.env;
        let Some(mut cur) = env.global_type_value(lem) else { return Ok(None) };
        let mut ri = 0;
        let mut args: Vec<(Rel, Tm)> = Vec::new();
        while let Value::Pi { name, rel, dom, cod } = &*cur.clone() {
            let entry = match rel {
                Rel::Rel => {
                    let Some(v) = rel_vals.get(ri).cloned() else { return Ok(None) };
                    ri += 1;
                    args.push((Rel::Rel, arm.quote(env, &v)));
                    EnvEntry::Rel(v)
                }
                Rel::Irr => {
                    let nm = name.to_string();
                    let p = if nm == "q" {
                        self.q(e, arm, dom, 6)?
                    } else if nm.starts_with('r') || nm.starts_with("gf") {
                        match lemmas::trivial(env, &arm.ctx, dom, &mut Budget { steps: 5_000_000 }) {
                            Some(p) => Some(p),
                            None => self.b.obligation(e, arm, dom, &format!("fact.{nm}"), &[]),
                        }
                    } else {
                        self.b.obligation(e, arm, dom, &format!("fact.{nm}"), &[])
                    };
                    let Some(p) = p else {
                        self.note(env, arm, &format!("binder `{nm}`"), dom);
                        return Ok(None);
                    };
                    args.push((Rel::Irr, p.clone()));
                    irr_entry(&arm.venv, &p)
                }
            };
            let Some(next) = e.inst(cod, vec![entry], arm.depth())? else { return Ok(None) };
            cur = next;
        }
        Ok(Some(apps(mk::global(lem), args)))
    }

    /// Splits the goal's left side (`holds(…)` of the unfolded body) on its
    /// stuck tests down to the recursive call (`prev`) or an exit.
    fn split(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, prev: Option<GlobalId>, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        if let Some(p) = lemmas::trivial(env, &st.ctx, goal, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        let Some((_, lhs, _)) = as_eq(goal) else { return Ok(None) };
        let lhs = lhs.clone();
        if let Some(call) = loop_under(&lhs, self.spec.func) {
            let Some(prev) = prev else { return Ok(None) };
            return self.apply_prev(e, st, prev, &call);
        }
        let bi = env.bool_ind();
        if let Some((c, _, _, _)) = first_match(&lhs, None).filter(|m| m.1 == bi)
            && depth > 0
        {
            // an infeasible arm closes by contradiction
            let d = st.depth_left;
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
                if let Some(p) = quick_absurd(e2, a2, &tk)? {
                    return Ok(Some(p));
                }
                let saved = (self.failed.clone(), self.failure.clone());
                if let Some(p) = self.split(e2, a2, &tk, prev, depth - 1)? {
                    return Ok(Some(p));
                }
                let p = full_absurd(e2, a2, &tk)?;
                if p.is_some() {
                    (self.failed, self.failure) = saved;
                }
                Ok(p)
            };
            return e.case_split_with(st, &c, bi, &[], goal, true, d, &mut arm_fn);
        }
        self.note(env, st, "an exit that is not the payload", goal);
        Ok(None)
    }

    /// `fact_j`'s body in its statement's telescope.
    fn lemma(&mut self, e: &mut Engine<'_>, ty: &Tm, prev: Option<GlobalId>) -> Result<Option<Tm>, String> {
        let env = e.env;
        let mut st = St::new(env, &Ctx::default(), 64);
        let goal = lemmas::open(e, &mut st, ty)?;
        if let Some(p) = lemmas::trivial(env, &st.ctx, &goal, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(st.finish(p)));
        }
        let (_, lhs, _) = as_eq(&goal).ok_or("a fact statement that is not an equation")?;
        let func = self.spec.func;
        let Some(call) = loop_under(lhs, func) else {
            // the kernel's evaluation already unfolded the call (the
            // exhaustion): split what is left
            let pf = self.split(e, &mut st, &goal, prev, 8).map_err(|s| format!("{s:?}"))?;
            return Ok(pf.map(|p| st.finish(p)));
        };
        // Delta: holds(loop ā) from holds(body ā), by a transport along
        // `Delta(loop; ā)`
        let app_v: V = Rc::new(Value::Neu(Neutral { head: Head::Global { def: func, args: call }, spine: vec![] }));
        let app_tm = st.quote(env, &app_v);
        let mut args = Vec::new();
        let mut h = &app_tm;
        while let Term::App { rel, fun, arg } = &**h {
            args.push((*rel, arg.clone()));
            h = fun;
        }
        args.reverse();
        let r_tm = {
            let tele = crate::opt::symex::telescope(env, func).ok_or("the loop has no telescope")?;
            crate::opt::proof::steps::subst_n(&tele.ret, &args.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>())
        };
        let body = apps(self.b.body.clone().or_else(|| env.global_body(func)).ok_or("the loop has no body")?, args.clone());
        let delta = Rc::new(Term::Delta { def: func, args: args.iter().map(|(_, a)| a.clone()).collect() });
        let bi = env.bool_ind();
        let holds_g = self.holds;
        let holds_of = |t: Tm| mk::eq(mk::bool_ty(bi), apps(mk::global(holds_g), [(Rel::Rel, t)]), mk::bool_lit(bi, true));
        let g1 = eval_in(env, &st.ctx, &holds_of(body.clone()))?;
        let pf = self.split(e, &mut st, &g1, prev, 8).map_err(|s| format!("{s:?}"))?;
        let Some(pf) = pf else { return Ok(None) };
        // transport(R, body, app, sym(delta), y. holds(y) = true, pf)
        let sym = env.lookup_global("eq::sym").ok_or("eq::sym")?;
        let back = apps(mk::global(sym), [(Rel::Rel, r_tm.clone()), (Rel::Rel, app_tm.clone()), (Rel::Rel, body.clone()), (Rel::Rel, delta)]);
        let motive = holds_of(mk::var(0));
        let p = Rc::new(Term::Transport { ty: r_tm, lhs: body, rhs: app_tm, eq: back, motive, val: pf });
        Ok(Some(st.finish(p)))
    }
}

/// A structural key of a term, its numbers dropped (the same atom at the
/// next literal has the same key).
fn shape_key(t: &Tm) -> String {
    let s = format!("{t:?}");
    s.chars().filter(|c| !c.is_ascii_digit()).take(400).collect()
}

/// The invariant conjuncts the facts' proofs need: those of the state
/// variables the candidates' payload fields read (at the hit), and of the
/// variables their closed forms relate them to. `None`: all of them.
pub fn needed_conjuncts(p: &Plan, cands: &[Cand]) -> Option<Vec<String>> {
    let fields = payload_state(p)?;
    let mut used: Vec<usize> = Vec::new();
    for c in cands {
        match c {
            Cand::Le { field, .. } => used.push(*field),
            Cand::Lt { a, b } | Cand::SumLe { a, b, .. } => used.extend([*a, *b]),
        }
    }
    let mut vars: Vec<u32> = Vec::new();
    for f in used {
        fields.get(f)?.state_vars(&mut vars);
    }
    // the classes' own dependencies: a GuardCount needs its BitDigit
    let mut more = Vec::new();
    for v in &vars {
        if let Class::GuardCount { v: d } = p.lp.classes[*v as usize] {
            more.push(d);
        }
        if let Class::Linear { rel } = &p.lp.classes[*v as usize] {
            more.extend(rel.iter().map(|(x, _)| *x));
        }
    }
    vars.extend(more);
    vars.sort();
    vars.dedup();
    Some(vars.iter().map(|v| format!(".i_{}", super::invariant::sanitize(&p.lp.params[*v as usize].name))).collect())
}

/// The statement of `fact_j` (text): the summary chain's binders without
/// the payload's invariant conjunct (and without the conjuncts the facts
/// do not need, `keep`), then `.q`.
fn statement(env: &Env, spec: &Spec, holds_name: &str, j: u32, keep: Option<&[String]>) -> Result<Tm, String> {
    let pb = spec.payload_binder.clone().ok_or("no payload binder")?;
    let drop = format!(".i_{pb}");
    let mut bs: Vec<(String, String)> = spec.binders(j).into_iter().filter(|(n, _)| *n != drop && (!n.starts_with(".i_") || keep.is_none_or(|k| k.contains(n)))).collect();
    bs.push((".q".into(), format!("Eq(Bool, {holds_name} {pb}, true)")));
    let pis: String = bs.iter().map(|(n, t)| format!("({n} : {t}) -> ")).collect();
    let src = format!("{pis}Eq(Bool, {holds_name} ({}), true)", spec.lhs[j as usize]);
    spec.parse_closed(env, &src).map_err(|e| format!("fact_{j} statement: {e}\n{src}"))
}

/// Builds and commits the loop's facts (see the module docs): `None` when
/// the loop has no candidate facts; an error when no candidate survives.
#[allow(clippy::too_many_arguments)]
pub fn build(env: &mut Env, plan: &Plan, spec: &Spec, prefix: &str, helper: GlobalId, key: &super::LoopKey, field_names: &dyn Fn(IndId) -> Option<Vec<String>>, cache: Option<&crate::opt::cache::Cache>, trust: bool) -> Result<Option<LoopFacts>, String> {
    let Some(mut pl) = payload_shape(env, plan) else { return Ok(None) };
    // the source's field names (the report)
    if let Some(ns) = field_names(pl.st).filter(|n| n.len() == pl.names.len()) {
        pl.names = ns;
    }
    let mut cands = candidates(plan, &pl);
    if cands.is_empty() {
        return Ok(None);
    }
    let tele = crate::opt::symex::telescope(env, spec.func).ok_or("the loop has no telescope")?;
    let ret = tele.ret.clone();
    let mut steps = 0u64;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let tag = if attempt == 1 { String::new() } else { format!("{attempt}") };
        let holds_name = format!("{prefix}::holds{tag}");
        let (holds, conj_defs) = commit_holds(env, &pl, &ret, &cands, &holds_name)?;
        let keep = needed_conjuncts(plan, &cands);
        match chain(env, spec, &holds_name, holds, &conj_defs, pl.opt, keep.as_deref(), prefix, &tag, cache, trust) {
            Ok((Some(fact0), s)) => {
                steps += s;
                let entry = entry_lemma(env, plan, spec, &holds_name, holds, pl.opt, fact0, prefix, &tag, helper, key)?;
                let names = pl.names.clone();
                let conjuncts = cands.iter().map(|c| (c.clone(), c.describe(&names))).collect();
                return Ok(Some(LoopFacts { holds, conj_defs, entry, conjuncts, payload: pl, steps }));
            }
            Ok((None, _)) => return Err("the fact chain did not close".into()),
            Err((why, failed, s)) => {
                steps += s;
                if attempt >= 2 || failed.is_empty() || trust {
                    return Err(why);
                }
                let keep: Vec<Cand> = cands.iter().enumerate().filter(|(i, _)| !failed.contains(i)).map(|(_, c)| c.clone()).collect();
                if keep.is_empty() {
                    return Err(why);
                }
                cands = keep;
            }
        }
    }
}

/// The chain `fact_K … fact_0`: `fact_0`'s global and the steps.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
fn chain(env: &mut Env, spec: &Spec, holds_name: &str, holds: GlobalId, conj_defs: &[GlobalId], opt: IndId, keep: Option<&[String]>, prefix: &str, tag: &str, cache: Option<&crate::opt::cache::Cache>, trust: bool) -> Result<(Option<GlobalId>, u64), (String, Vec<usize>, u64)> {
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(3600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let mut fb = FactB { spec, holds, conj_defs: conj_defs.to_vec(), b: lemmas::Builder::new(spec), le_memo: HashMap::new(), arm_hints: HashMap::new(), failed: Vec::new(), opt, failure: None };
    fb.b.trust = trust;
    // the summary chain's outlined body (its outlined lemmas, not new
    // copies: the obligations at the recursive call are then the summary
    // chain's, whose proofs `Builder::obligation` carries over)
    fb.b.body = lemmas::shared_body(spec.func).or_else(|| {
        let mut outl = crate::opt::outline::Outlines::default();
        outl.ensure(env, spec.func);
        outl.get(spec.func).map(|o| o.1.clone())
    });
    let mut db = crate::auto::lemmas::LemmaDb::default();
    let mut prev: Option<GlobalId> = None;
    let mut steps = 0u64;
    for j in (0..=spec.k).rev() {
        for (f, w, k) in lemmas::families_at(spec, j) {
            let lim = super::meter::cap(400_000_000);
            let mut fb = Budget { steps: lim };
            let _ = bitlib::ensure(env, f, w, k, &mut fb);
            super::meter::charge(lim - fb.steps);
        }
        // the popcount bounds of the payload's count fields
        let w = spec.word;
        for k in 0..expr::bits(w) {
            let fam = bitlib::lemma_name(Family::PopcntLe, w, k);
            if env.lookup_global(&fam).is_none() && (j == spec.k || j == 0) {
                let lim = super::meter::cap(400_000_000);
                let mut fb = Budget { steps: lim };
                let _ = bitlib::ensure(env, Family::PopcntLe, w, k, &mut fb);
                super::meter::charge(lim - fb.steps);
            }
        }
        fb.b.j = j;
        let ty = statement(env, spec, holds_name, j, keep).map_err(|e| (e, vec![], steps))?;
        let name = format!("{prefix}::fact{tag}_{j}");
        // a cached proof, charged the steps its build took (as in
        // `lemmas::build_chain_trusting`)
        // (one key per lemma: the statement's globals do not change)
        let key = cache.map(|c| c.key(env, &name, &ty));
        if let (Some(c), Some(key)) = (cache, &key) {
            if let Some((body, cost)) = c.load_costed(env, key)
                && cost.build.saturating_add(cost.check) <= super::meter::cap(u64::MAX)
            {
                super::meter::charge(cost.build);
                match lemmas::add_lemma(env, &name, ty.clone(), body, lemmas::LEMMA_STEPS) {
                    Ok((g, s)) => {
                        super::meter::recharge(s, cost.check);
                        steps += cost.build + cost.check;
                        prev = Some(g);
                        continue;
                    }
                    Err(e) => {
                        super::meter::refund(cost.build);
                        c.reject(key, &name, &e);
                    }
                }
            }
        }
        db.refresh(env);
        let lim = super::meter::cap(lemmas::LEMMA_STEPS);
        let mut sb = Budget { steps: lim };
        let proof = {
            let envr: &Env = env;
            let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
            fb.lemma(&mut e, &ty, if j == spec.k { None } else { prev })
        };
        let built = lim - sb.steps;
        super::meter::charge(built);
        steps += built;
        let proof = proof.map_err(|e| (e, vec![], steps))?;
        let Some(p) = proof else {
            if std::env::var_os("SANDBLASTER_LOOPSUM_TIMING").is_some() {
                eprintln!("[loopsum] fact chain failed at fact_{j}: {} steps\n{}", steps, fb.b.stats.report());
            }
            let why = format!("fact_{j} not proven: {}", fb.failure.clone().unwrap_or_default());
            return Err((why, fb.failed.clone(), steps));
        };
        let p = lemmas::hashcons(&p);
        match lemmas::add_consed(env, &name, ty.clone(), p.clone(), lemmas::LEMMA_STEPS) {
            Ok((g, s)) => {
                steps += s;
                prev = Some(g);
                if let (Some(c), Some(key)) = (cache, &key) {
                    c.store_lemma(env, key, &p, g, crate::opt::cache::Cost { build: built, check: s });
                }
            }
            Err(e) => return Err((format!("kernel rejected fact_{j}: {e}"), vec![], steps)),
        }
    }
    let _ = holds;
    if std::env::var_os("SANDBLASTER_LOOPSUM_TIMING").is_some() {
        eprintln!("[loopsum] fact chain: {} steps\n{}", steps, fb.b.stats.report());
    }
    Ok((prev, steps))
}

/// `<prefix>::fact : Π d̄ h̄. Eq(Bool, holds(loop(statics, d̄) h̄), true)` over
/// the helper's telescope: `fact_0` at the call's static arguments.
#[allow(clippy::too_many_arguments)]
fn entry_lemma(env: &mut Env, plan: &Plan, spec: &Spec, holds_name: &str, holds: GlobalId, opt: IndId, fact0: GlobalId, prefix: &str, tag: &str, helper: GlobalId, key: &super::LoopKey) -> Result<GlobalId, String> {
    let lp = &plan.lp;
    let tele_h = crate::opt::symex::telescope(env, helper).ok_or("the helper has no telescope")?;
    let tele_l = crate::opt::symex::telescope(env, key.def).ok_or("the loop has no telescope")?;
    let n = tele_h.binders.len();
    let np = tele_h.binders.iter().filter(|(_, r, _)| *r == Rel::Rel).count();
    let var = |b: usize| mk::var((n - 1 - b) as u32);
    let dy = lp.dynamic();
    let statics = super::statics_of(env, key, lp.params.len())?;
    let mut largs = Vec::new();
    let mut ri = 0usize;
    for (i, (_, rel, _)) in tele_l.binders.iter().enumerate() {
        match rel {
            Rel::Rel => largs.push((Rel::Rel, match &statics[i] {
                Some(t) => t.clone(),
                None => var(dy.iter().position(|d| *d as usize == i).ok_or("a dynamic parameter")?),
            })),
            Rel::Irr => {
                largs.push((Rel::Irr, var(np + ri)));
                ri += 1;
            }
        }
    }
    if np + ri != n {
        return Err("the helper's requires are not the loop's".into());
    }
    let bi = env.bool_ind();
    let loop_app = apps(mk::global(key.def), largs);
    let concl = mk::eq(mk::bool_ty(bi), apps(mk::global(holds), [(Rel::Rel, loop_app)]), mk::bool_lit(bi, true));
    let mut ty = concl;
    for (nm, rel, dom) in tele_h.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    let _ = holds_name;
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(3600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let lim = super::meter::cap(200_000_000);
    let mut sb = Budget { steps: lim };
    let body = (|| -> Result<Tm, String> {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = St::new(envr, &Ctx::default(), 64);
        let _goal = lemmas::open(&mut e, &mut st, &ty)?;
        let mut fb = FactB { spec, holds, conj_defs: Vec::new(), b: lemmas::Builder::new(spec), le_memo: HashMap::new(), arm_hints: HashMap::new(), failed: Vec::new(), opt, failure: None };
        fb.b.j = 0;
        let mut rel_vals = Vec::new();
        for (_, _, pi) in &spec.state {
            let v = match &statics[*pi as usize] {
                Some(t) => st.eval(envr, t, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("{e:?}"))?,
                None => {
                    let b = dy.iter().position(|d| d == pi).ok_or("a dynamic parameter")?;
                    match &st.venv.0[b] {
                        EnvEntry::Rel(v) => v.clone(),
                        _ => return Err("an irrelevant parameter".into()),
                    }
                }
            };
            rel_vals.push(v);
        }
        for g in plan.ghosts.iter().filter(|g| !g.shared) {
            let b = dy.iter().position(|d| *d == g.param).ok_or("a ghost's parameter")?;
            match &st.venv.0[b] {
                EnvEntry::Rel(v) => rel_vals.push(v.clone()),
                _ => return Err("an irrelevant parameter".into()),
            }
        }
        let p = fb.apply_with(&mut e, &mut st, fact0, rel_vals).map_err(|s| format!("{s:?}"))?.ok_or_else(|| format!("the entry of the fact chain: {}", fb.failure.clone().unwrap_or_default()))?;
        Ok(st.finish(p))
    })();
    super::meter::charge(lim - sb.steps);
    let body = body?;
    let name = format!("{prefix}::fact{tag}");
    let (g, _) = lemmas::add_lemma(env, &name, ty, body, 400_000_000)?;
    Ok(g)
}
