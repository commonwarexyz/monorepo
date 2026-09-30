//! Fact lemmas of summarized functions at their call sites (optimizer
//! design §6.4 "output facts"; plan O6: the facts `shape` exports reach the
//! checks of `reconstruct_checked` / `reconstruct_finish`).
//!
//! **Export.** A driven function `f` whose residual summarizes a loop with
//! exported facts (`loopsum::facts`: `holds(loop(statics, d̄)) = true`)
//! gets, per conjunct `P_k` of `holds`, the kernel-checked lemma
//!
//! ```text
//! <f>::fact#k : Π x̄ (v : S) (.e : Eq(R, f x̄, Some(v))) (h̄ : Req_f). Eq(Bool, P_k(v), true)
//! ```
//!
//! proven from `A : Π x̄ h̄. Eq(Bool, holds(f x̄ h̄), true)` — `f` unfolded and
//! split on its tests; a leaf that is the loop call applies the loop's
//! fact, a constant leaf computes — transported along `e` and projected
//! out of the conjunction (`bool::and_left/right`). The lemmas are
//! registered per function ([`register`], reset per crate) and, by their
//! name (`::fact#`), used by `auto` as forward rules on path equations
//! (`auto::lemmas::LemmaDb`), so the elaborator re-proves the residuals'
//! obligations with them.
//!
//! **Import.** In the driver's decisions (and the proof builder's replay of
//! them), every path equation `e : Eq(R, f ā, Some(v))` of a split on a
//! kept call of such an `f` contributes the facts `fact#k ā v e ā'` — no
//! new binders: they are `let` facts of a child state ([`with_imports`]),
//! and the decision's proof closes over them.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{GlobalId, IndId, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, EnvEntry, Head, Neutral, V, Value};

use crate::auto::search::{Engine, R};
use crate::auto::state::{Origin, St};
use crate::auto::util::{apps, as_eq, irr_entry};

/// One exported fact of a function (see the module docs).
#[derive(Clone, Debug)]
pub struct FnFact {
    pub lemma: GlobalId,
    pub name: String,
    /// What it states (`height <= 62`).
    pub states: String,
    /// The result's inductive (`Option`) and the payload constructor.
    pub opt: IndId,
    pub some: u32,
}

thread_local! {
    static REG: RefCell<BTreeMap<GlobalId, Vec<FnFact>>> = const { RefCell::new(BTreeMap::new()) };
}

/// Forgets the registered facts (one crate's optimization).
pub fn reset() {
    REG.with(|r| r.borrow_mut().clear());
    INV.with(|m| m.borrow_mut().clear());
}

/// Registers `f`'s facts.
pub fn register(f: GlobalId, facts: Vec<FnFact>) {
    REG.with(|r| {
        r.borrow_mut().insert(f, facts);
    });
}

/// `f`'s facts.
pub fn of(f: GlobalId) -> Vec<FnFact> {
    REG.with(|r| r.borrow().get(&f).cloned().unwrap_or_default())
}

/// Whether some function has registered facts.
pub fn any() -> bool {
    REG.with(|r| !r.borrow().is_empty())
}

/// Whether `f` has facts.
pub fn has(f: GlobalId) -> bool {
    REG.with(|r| r.borrow().contains_key(&f))
}

// ---------------------------------------------------------------------------
// Import.
// ---------------------------------------------------------------------------

/// The imported facts of `st` (see the module docs): `(proof, statement)`.
pub fn imports(env: &Env, st: &St) -> Vec<(Tm, V)> {
    imports_by(env, st, &|_| None)
}

/// [`imports`], with `lets` giving the folded call a `let` variable (by
/// level) stands for where the context's value of it is unfolded (the
/// proof builder's `let`s of kept calls).
pub fn imports_by(env: &Env, st: &St, lets: &dyn Fn(u32) -> Option<V>) -> Vec<(Tm, V)> {
    if !any() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let trace = std::env::var_os("SANDBLASTER_OPT_TRACE_FACTS").is_some();
    for f in &st.facts {
        if trace {
            let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
            eprintln!("opt: facts: fact {:?}: {}", f.origin, crate::elab::show::value(env, &names, &f.ty, 300));
        }
        if !matches!(f.origin, Origin::Split) {
            continue;
        }
        let Some((_, lhs, rhs)) = as_eq(&f.ty) else { continue };
        let lhs = through_lets(st, lhs, lets);
        let Value::Neu(Neutral { head: Head::Global { def, args }, spine }) = &*lhs else { continue };
        if !spine.is_empty() {
            continue;
        }
        let facts = of(*def);
        if facts.is_empty() {
            continue;
        }
        let Value::Ctor { ind, ctor, args: cargs, .. } = &**rhs else { continue };
        let [Arg::Rel(v)] = &cargs[..] else { continue };
        for fx in facts {
            if fx.opt != *ind || fx.some != *ctor {
                continue;
            }
            // fact#k x̄ v .e h̄: its statement by instantiating the lemma's
            // type (not by kernel inference: the driver's context holds
            // `f`'s call folded, which plain conversion does not unfold;
            // the proof itself is checked with the finished proof)
            let mut targs: Vec<(Rel, Tm)> = Vec::new();
            let mut entries: Vec<EnvEntry> = Vec::new();
            for a in args.iter().filter(|a| matches!(a, Arg::Rel(_))) {
                let Arg::Rel(x) = a else { unreachable!() };
                targs.push((Rel::Rel, st.quote(env, x)));
                entries.push(EnvEntry::Rel(x.clone()));
            }
            targs.push((Rel::Rel, st.quote(env, v)));
            entries.push(EnvEntry::Rel(v.clone()));
            let e_tm = st.var(f.lvl);
            entries.push(irr_entry(&st.venv, &e_tm));
            targs.push((Rel::Irr, e_tm));
            if args.iter().any(|a| matches!(a, Arg::Irr(_))) {
                continue;
            }
            let Some(mut cur) = env.global_type_value(fx.lemma) else { continue };
            let mut ok = true;
            for en in entries {
                let Value::Pi { cod, .. } = &*cur.clone() else {
                    ok = false;
                    break;
                };
                match crate::auto::util::inst(env, cod, vec![en], st.depth(), &mut Budget { steps: 5_000_000 }) {
                    Ok(next) => cur = next,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok || matches!(&*cur, Value::Pi { .. }) {
                if trace {
                    eprintln!("opt: facts: `{}` does not apply", fx.name);
                }
                continue;
            }
            out.push((apps(mk::global(fx.lemma), targs), cur));
        }
    }
    out
}

/// A `let`-bound variable's value (the proof builder splits on the `let`
/// of a kept call; its path equation's side is the variable).
fn through_lets(st: &St, v: &V, lets: &dyn Fn(u32) -> Option<V>) -> V {
    let mut cur = v.clone();
    for _ in 0..4 {
        let Value::Neu(Neutral { head: Head::Var(l), spine }) = &*cur else { break };
        if !spine.is_empty() {
            break;
        }
        if let Some(x) = lets(l.0) {
            cur = x;
            continue;
        }
        match st.ctx.entries.get(l.0 as usize).and_then(|e| e.def.clone()) {
            Some(Arg::Rel(x)) => cur = x,
            _ => break,
        }
    }
    cur
}

/// A `let`'s value term (at depth `lvl`) as a folded call of a function
/// with facts, evaluated in `st` (deeper): `f ā` with relevant `ā`.
pub fn folded_call(env: &Env, st: &St, lvl: u32, val: &Tm) -> Option<V> {
    let mut args: Vec<Tm> = Vec::new();
    let mut cur = val;
    while let Term::App { rel, fun, arg } = &**cur {
        if *rel != Rel::Rel {
            return None;
        }
        args.push(arg.clone());
        cur = fun;
    }
    let Term::Global(g) = &**cur else { return None };
    if !has(*g) {
        return None;
    }
    args.reverse();
    let d = st.depth().checked_sub(lvl)?;
    let mut vals = Vec::new();
    for a in args {
        let v = st.eval(env, &crate::auto::util::shift(&a, d as i64), &mut Budget { steps: 1_000_000 }).ok()?;
        vals.push(Arg::Rel(v));
    }
    Some(Rc::new(Value::Neu(Neutral { head: Head::Global { def: *g, args: vals }, spine: Vec::new() })))
}

/// Whether `st` has imported facts.
pub fn has_imports(env: &Env, st: &St) -> bool {
    any() && !imports(env, st).is_empty()
}

/// The levels of the payloads `v` of the path equations `Eq(R, f ā,
/// Some(v))` on kept calls of functions with facts (the values the
/// imported facts are about).
pub fn imported_payloads(st: &St) -> Vec<u32> {
    if !any() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for f in &st.facts {
        if !matches!(f.origin, Origin::Split) {
            continue;
        }
        let Some((_, lhs, rhs)) = as_eq(&f.ty) else { continue };
        let lhs = through_lets(st, lhs, &|_| None);
        let Value::Neu(Neutral { head: Head::Global { def, .. }, spine }) = &*lhs else { continue };
        if !spine.is_empty() || !has(*def) {
            continue;
        }
        if let Value::Ctor { args, .. } = &**rhs
            && let [Arg::Rel(v)] = &args[..]
            && let Value::Neu(Neutral { head: Head::Var(l), spine }) = &**v
            && spine.is_empty()
        {
            out.push(l.0);
        }
    }
    out
}

/// Whether a value mentions a variable at one of `lvls`.
pub fn mentions(v: &V, lvls: &[u32]) -> bool {
    if lvls.is_empty() {
        return false;
    }
    let mut hit = false;
    crate::auto::util::walk(v, &mut |x| {
        if let Value::Neu(Neutral { head: Head::Var(l), .. }) = &**x
            && lvls.contains(&l.0)
        {
            hit = true;
        }
        !hit
    });
    hit
}

/// Whether the body of `g` applies a function with facts (a straight-line
/// residual keeping such a call is driven too: its callees may use them).
pub fn body_applies(env: &Env, g: GlobalId) -> bool {
    if !any() {
        return false;
    }
    let Some(b) = env.global_body(g) else { return false };
    crate::elab::tm::any_node(&crate::roundtrip::strip(&b), &mut |n| matches!(n, Term::Global(h) if has(*h)))
}

/// Whether a value is a kept call of a function with facts.
pub fn is_fact_call(v: &V) -> bool {
    matches!(&**v, Value::Neu(Neutral { head: Head::Global { def, .. }, spine }) if spine.is_empty() && has(*def))
}

/// A child of `st` with the imported facts as `let` facts (`finish` closes
/// a proof over them), or `None` without any.
pub fn with_imports(env: &Env, st: &St) -> Option<St> {
    with_imports_by(env, st, &|_| None)
}

/// A proof made in a [`with_imports`] state, at the parent's depth: the
/// imported facts' `let`s substituted (bound inside the irrelevant position
/// the proof goes to, they could only be used irrelevantly there, and
/// linarith hypotheses are not).
pub fn close(st2: &St, p: Tm) -> Tm {
    let mut t = st2.finish(p);
    while let Term::Let { val, body, .. } = &*t.clone() {
        t = crate::auto::util::subst0(body, val);
    }
    t
}

/// The facts a decision on `c` gets besides the path's (the driver's
/// decisions and the proof builder's replay of them alike): the imported
/// fact lemmas ([`imports_by`]) and the invariants (§15 S2) of the values
/// `c` mentions ([`invariant_facts`]), as `let` facts of a child state;
/// `None` when there are none. Close a proof made in it with [`close`].
pub fn with_decision_facts(env: &Env, st: &St, c: &V, lets: &dyn Fn(u32) -> Option<V>) -> Option<St> {
    let mut im = imports_by(env, st, lets);
    im.extend(invariant_facts(env, st, c));
    if im.is_empty() {
        return None;
    }
    let mut ch = st.child();
    for (p, ty) in im {
        let d = ch.depth() - st.depth();
        ch.push_fact(env, ty, crate::auto::util::shift(&p, d as i64), Origin::Derived("fact lemma"));
    }
    Some(ch)
}

thread_local! {
    /// The `S::inv#k` lemmas of each inductive (per crate, [`reset`]).
    static INV: RefCell<BTreeMap<IndId, Vec<GlobalId>>> = const { RefCell::new(BTreeMap::new()) };
}

/// The invariant lemmas `S::inv#k : Π(T..)(s : S T..). P_k(s)` of the
/// struct `ind` (§15 S2; `elab/invariant.rs`, looked up by name as the
/// elaborator's resumed elaborations do): empty for types without an
/// invariant.
fn inv_lemmas(env: &Env, ind: IndId) -> Vec<GlobalId> {
    if let Some(v) = INV.with(|m| m.borrow().get(&ind).cloned()) {
        return v;
    }
    let v: Vec<GlobalId> = match env.inductive_decl(ind) {
        Some(d) => (0..).map_while(|k| env.lookup_global(&format!("{}::inv#{k}", d.name))).collect(),
        None => Vec::new(),
    };
    INV.with(|m| m.borrow_mut().insert(ind, v.clone()));
    v
}

/// The invariant facts (§15 S2 `#[invariant]`, an `Irr` constructor field)
/// of the context's values of invariant types that `c` mentions: for
/// `x : S T..`, the instances `S::inv#k T.. x` — the free facts the
/// elaborator gives every such value (`FactOrigin::TypeBound`) — as
/// `(proof, statement)` at `st`'s depth. A parameter of an invariant type
/// thus decides the tests its invariant implies, in the driver and in the
/// proof builder alike.
pub fn invariant_facts(env: &Env, st: &St, c: &V) -> Vec<(Tm, V)> {
    let mut out = Vec::new();
    let d = st.depth();
    for (l, e) in st.ctx.entries.iter().enumerate() {
        // (parameters, split fields and `let`s alike)
        if e.rel != Rel::Rel {
            continue;
        }
        let Value::Ind { ind, params } = &*e.ty else { continue };
        let lemmas = inv_lemmas(env, *ind);
        if lemmas.is_empty() || !mentions(c, &[l as u32]) {
            continue;
        }
        for g in lemmas {
            let Some(rels) = env.global_param_rels(g) else { continue };
            if rels.len() != params.len() + 1 {
                continue;
            }
            let mut args: Vec<(Rel, Tm)> = params.iter().zip(&rels).map(|(p, r)| (*r, env.quote(sandblaster_kernel::term::Lvl(d), p, false))).collect();
            args.push((rels[params.len()], mk::var(d - 1 - l as u32)));
            let p = apps(mk::global(g), args);
            let Ok(ty) = env.infer(&st.ctx, &p, &mut Budget { steps: 2_000_000 }) else { continue };
            out.push((p, ty));
        }
    }
    out
}

/// [`with_imports`] with [`imports_by`]'s `lets`.
pub fn with_imports_by(env: &Env, st: &St, lets: &dyn Fn(u32) -> Option<V>) -> Option<St> {
    let im = imports_by(env, st, lets);
    if im.is_empty() {
        return None;
    }
    let mut c = st.child();
    for (p, ty) in im {
        let d = c.depth() - st.depth();
        c.push_fact(env, ty, crate::auto::util::shift(&p, d as i64), Origin::Derived("fact lemma"));
    }
    Some(c)
}

// ---------------------------------------------------------------------------
// Export.
// ---------------------------------------------------------------------------

/// The loop call a value is under `holds`' match: the loop's arguments.
fn loop_call(v: &V, def: GlobalId) -> Option<Vec<Arg>> {
    match &**v {
        Value::Neu(Neutral { head: Head::Global { def: d, args }, spine }) if *d == def && spine.iter().all(|e| matches!(e, sandblaster_kernel::value::Elim::Match { .. })) => Some(args.clone()),
        _ => None,
    }
}

/// Proof of `holds(f x̄ h̄) = true` by unfolding and splitting (see the
/// module docs).
struct Lift<'a> {
    key: &'a crate::opt::loopsum::LoopKey,
    lf: &'a crate::opt::loopsum::facts::LoopFacts,
    failure: Option<String>,
}

impl Lift<'_> {
    fn note(&mut self, env: &Env, st: &St, what: &str, v: &V) {
        if self.failure.is_none() {
            let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
            self.failure = Some(format!("{what}: {}", crate::elab::show::value(env, &names, v, 500)));
        }
    }

    fn go(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        if let Some(p) = crate::opt::loopsum::lemmas::trivial(env, &st.ctx, goal, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        let Some((_, lhs, _)) = as_eq(goal) else { return Ok(None) };
        let lhs = lhs.clone();
        if let Some(args) = loop_call(&lhs, self.key.def) {
            return self.apply_entry(e, st, &args);
        }
        let Value::Neu(n) = &*lhs else {
            self.note(env, st, "a leaf", goal);
            return Ok(None);
        };
        let Some(i) = n.spine.iter().position(|x| matches!(x, sandblaster_kernel::value::Elim::Match { .. })) else {
            self.note(env, st, "a leaf", goal);
            return Ok(None);
        };
        let sandblaster_kernel::value::Elim::Match { ind, params, .. } = &n.spine[i] else { unreachable!() };
        let (ind, params) = (*ind, params.clone());
        if depth == 0 || ind != env.bool_ind() {
            self.note(env, st, "a split that is not a test", goal);
            return Ok(None);
        }
        let c = crate::auto::util::prefix(n, i);
        let d = st.depth_left;
        let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
            let mut ch = a2.child();
            if let Ok(Some(p)) = e2.contradiction(&mut ch) {
                return Ok(Some(e2.absurd(a2, &tk, ch.finish(p))));
            }
            self.go(e2, a2, &tk, depth - 1)
        };
        e.case_split_with(st, &c, ind, &params, goal, true, d, &mut arm_fn)
    }

    /// The loop's entry fact at the call's dynamic arguments; its requires
    /// (the loop's at the static arguments) by linear arithmetic.
    fn apply_entry(&mut self, e: &mut Engine<'_>, st: &mut St, args: &[Arg]) -> R<Option<Tm>> {
        let env = e.env;
        let rel: Vec<V> = args.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
        // the call must be at the key's static arguments
        let Some((k2, _)) = crate::opt::loopsum::key_of_rel(env, self.key.def, &rel) else { return Ok(None) };
        if &k2 != self.key {
            return Ok(None);
        }
        let statics: Vec<usize> = self.key.statics.iter().map(|(i, _)| *i).collect();
        let dyn_vals: Vec<V> = rel.iter().enumerate().filter(|(i, _)| !statics.contains(i)).map(|(_, v)| v.clone()).collect();
        let Some(mut cur) = env.global_type_value(self.lf.entry) else { return Ok(None) };
        let mut out: Vec<(Rel, Tm)> = Vec::new();
        let mut ri = 0usize;
        while let Value::Pi { rel: r, dom, cod, .. } = &*cur.clone() {
            let entry = match r {
                Rel::Rel => {
                    let Some(v) = dyn_vals.get(ri).cloned() else { return Ok(None) };
                    ri += 1;
                    out.push((Rel::Rel, st.quote(env, &v)));
                    EnvEntry::Rel(v)
                }
                Rel::Irr => {
                    let p = match crate::opt::loopsum::lemmas::trivial(env, &st.ctx, dom, &mut Budget { steps: 5_000_000 }) {
                        Some(p) => p,
                        None => match e.lin_prove(st, dom, true)? {
                            Some(p) => e.promote(st, dom, p),
                            None => match e.solve(st, dom.clone(), true)? {
                                Some(p) => p,
                                None => {
                                    self.note(env, st, "the loop's requires at the call", dom);
                                    return Ok(None);
                                }
                            },
                        },
                    };
                    out.push((Rel::Irr, p.clone()));
                    irr_entry(&st.venv, &p)
                }
            };
            let Some(next) = e.inst(cod, vec![entry], st.depth())? else { return Ok(None) };
            cur = next;
        }
        Ok(Some(apps(mk::global(self.lf.entry), out)))
    }
}

/// Lifts a loop's facts to the driven function `f` that summarizes it (see
/// the module docs); returns `f`'s facts (registered by the caller).
pub fn lift(env: &mut Env, f: GlobalId, key: &crate::opt::loopsum::LoopKey, lf: &crate::opt::loopsum::facts::LoopFacts) -> Result<Vec<FnFact>, String> {
    let tele = crate::opt::symex::telescope(env, f).ok_or("no telescope")?;
    let fname = env.global_name(f).map(|s| s.to_string()).ok_or("no name")?;
    let n = tele.binders.len();
    let bi = env.bool_ind();
    // the result type must be the loop's (`holds`' domain)
    let hdom = match env.global_type(lf.holds).as_deref() {
        Some(Term::Pi { dom, .. }) => dom.clone(),
        _ => return Err("`holds` has no domain".into()),
    };
    if !env.alpha_eq_relevant(&tele.ret, &hdom, &|x, y| x == y) {
        return Err("the function's result is not the loop's".into());
    }
    let vars = |extra: u32| -> Vec<(Rel, Tm)> { tele.binders.iter().enumerate().map(|(i, (_, r, _))| (*r, mk::var(n as u32 + extra - 1 - i as u32))).collect() };
    let close = |mut t: Tm| -> Tm {
        for (nm, rel, dom) in tele.binders.iter().rev() {
            t = mk::pi(nm, *rel, dom.clone(), t);
        }
        t
    };
    // A : Π x̄ h̄. Eq(Bool, holds(f x̄ h̄), true)
    let a_ty = close(mk::eq(mk::bool_ty(bi), apps(mk::global(lf.holds), [(Rel::Rel, apps(mk::global(f), vars(0)))]), mk::bool_lit(bi, true)));
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let a_body = {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut sb = Budget { steps: 100_000_000 };
        let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = St::new(envr, &Ctx::default(), 32);
        let goal = crate::opt::loopsum::lemmas::open(&mut e, &mut st, &a_ty)?;
        let mut lift = Lift { key, lf, failure: None };
        let p = lift.go(&mut e, &mut st, &goal, 8).map_err(|s| format!("{s:?}"))?.ok_or_else(|| format!("`holds` of `{fname}`: {}", lift.failure.clone().unwrap_or_default()))?;
        st.finish(p)
    };
    let a_name = format!("{fname}::facts");
    let (a_g, _) = crate::opt::loopsum::lemmas::add_lemma(env, &a_name, a_ty, a_body, 200_000_000)?;
    // per conjunct: the forward form
    let pl = &lf.payload;
    let opt_params: Vec<Tm> = pl.opt_params.iter().map(|p| env.quote(sandblaster_kernel::term::Lvl(0), p, false)).collect();
    let st_params: Vec<Tm> = pl.st_params.iter().map(|p| env.quote(sandblaster_kernel::term::Lvl(0), p, false)).collect();
    let s_ty = mk::ind(pl.st, st_params.clone());
    let np = tele.binders.iter().take_while(|(_, r, _)| *r == Rel::Rel).count();
    let nreq = n - np;
    let (and_l, and_r) = (env.lookup_global("bool::and_left").ok_or("bool::and_left")?, env.lookup_global("bool::and_right").ok_or("bool::and_right")?);
    let nc = lf.conjuncts.len();
    let mut out = Vec::new();
    for (k, (cand, states)) in lf.conjuncts.iter().enumerate() {
        // binders: x̄ (np), v, .e, h̄ (nreq): depth np + 2 + nreq
        let depth = (np + 2 + nreq) as u32;
        // x̄ at the binders' own depths: a param i is var(depth − 1 − i);
        // v is var(depth − 1 − np); e var(depth − 2 − np); h_r var(depth − 1 − (np + 2 + r))
        let x_at = |d: u32, i: usize| mk::var(d - 1 - i as u32);
        // the telescope with the requires after e: the requires' types
        // refer to x̄ (and earlier requires) at their own depth; they sat
        // right after x̄ in f's telescope, now after v and e: shift the
        // requires' binder types by 2 at cutoff (their index among the
        // requires)
        let mut ty = {
            // conclusion: Eq(Bool, P_k(v), true) at depth
            let v = mk::var(depth - 1 - np as u32);
            let sp: Vec<Tm> = st_params.iter().map(|p| crate::auto::util::shift(p, depth as i64)).collect();
            mk::eq(mk::bool_ty(bi), crate::opt::loopsum::facts::cand_term(env, pl, &sp, &v, cand), mk::bool_lit(bi, true))
        };
        for r in (0..nreq).rev() {
            let (nm, _, dom) = &tele.binders[np + r];
            // dom at depth np + r (x̄ and h_0..h_{r−1}); now at depth np + 2 + r:
            // the x̄ indices shift by 2 (v, e in between), the earlier
            // requires' do not
            let dom2 = crate::auto::util::shift_from(dom, 2, r as u32);
            ty = mk::pi(nm, Rel::Irr, dom2, ty);
        }
        {
            // .e : Eq(R, f x̄ h̄?, Some(v)) at depth np + 1 — f applied to x̄
            // only needs the requires: an application with irrelevant
            // holes (`Erased`) is not a term; state it over f's
            // relevant-only view when f has no requires, else skip
            if nreq > 0 {
                return Err("facts of a function with requires are not exported".into());
            }
            let d = np as u32 + 1;
            let f_app = apps(mk::global(f), (0..np).map(|i| (Rel::Rel, x_at(d, i))));
            let r_ty = crate::auto::util::shift(&tele.ret, 1);
            let some_v = mk::ctor(pl.opt, pl.some, opt_params.iter().map(|p| crate::auto::util::shift(p, d as i64)).collect(), vec![mk::var(0)]);
            ty = mk::pi("e", Rel::Irr, mk::eq(r_ty, f_app, some_v), ty);
            ty = mk::pi("v", Rel::Rel, crate::auto::util::shift(&s_ty, np as i64), ty);
        }
        for (nm, rel, dom) in tele.binders.iter().take(np).rev() {
            ty = mk::pi(nm, *rel, dom.clone(), ty);
        }
        // body: λ x̄ v e. and_k(transport(R, f x̄, Some v, e, y. Eq(Bool, holds y, true), A x̄))
        let d = depth;
        let f_app = apps(mk::global(f), (0..np).map(|i| (Rel::Rel, x_at(d, i))));
        let r_ty = crate::auto::util::shift(&tele.ret, d as i64);
        let v = mk::var(d - 1 - np as u32);
        let some_v = mk::ctor(pl.opt, pl.some, opt_params.iter().map(|p| crate::auto::util::shift(p, d as i64)).collect(), vec![v.clone()]);
        let a_app = apps(mk::global(a_g), (0..np).map(|i| (Rel::Rel, x_at(d, i))));
        let motive = mk::eq(mk::bool_ty(bi), apps(mk::global(lf.holds), [(Rel::Rel, mk::var(0))]), mk::bool_lit(bi, true));
        let e_var = mk::var(d - 2 - np as u32);
        let mut h: Tm = Rc::new(Term::Transport { ty: r_ty, lhs: f_app, rhs: some_v, eq: e_var, motive, val: a_app });
        // h : Eq(Bool, and(conj₀ v, and(conj₁ v, …)), true): project the k-th
        let sp: Vec<Tm> = st_params.iter().map(|p| crate::auto::util::shift(p, d as i64)).collect();
        let terms: Vec<Tm> = lf.conj_defs.iter().map(|g| apps(mk::global(*g), [(Rel::Rel, v.clone())])).collect();
        let rest = |from: usize| -> Tm {
            // and(t_from, and(…)) or t_last
            let and = env.lookup_global("bool::and").unwrap();
            let mut acc = terms[nc - 1].clone();
            for t in terms[from..nc - 1].iter().rev() {
                acc = apps(mk::global(and), [(Rel::Rel, t.clone()), (Rel::Rel, acc)]);
            }
            acc
        };
        for i in 0..k {
            h = apps(mk::global(and_r), [(Rel::Rel, terms[i].clone()), (Rel::Rel, rest(i + 1)), (Rel::Irr, h)]);
        }
        if k + 1 < nc {
            h = apps(mk::global(and_l), [(Rel::Rel, terms[k].clone()), (Rel::Rel, rest(k + 1)), (Rel::Irr, h)]);
        }
        // conj_k v = P_k v (its definition): P_k v = true
        let pk = crate::opt::loopsum::facts::cand_term(env, pl, &sp, &v, cand);
        let delta = Rc::new(Term::Delta { def: lf.conj_defs[k], args: vec![v.clone()] });
        let (sym, trans) = (env.lookup_global("eq::sym").ok_or("eq::sym")?, env.lookup_global("eq::trans").ok_or("eq::trans")?);
        let back = apps(mk::global(sym), [(Rel::Rel, mk::bool_ty(bi)), (Rel::Rel, terms[k].clone()), (Rel::Rel, pk.clone()), (Rel::Rel, delta)]);
        h = apps(mk::global(trans), [(Rel::Rel, mk::bool_ty(bi)), (Rel::Rel, pk), (Rel::Rel, terms[k].clone()), (Rel::Rel, mk::bool_lit(bi, true)), (Rel::Rel, back), (Rel::Rel, h)]);
        // λ over the statement's binders (their domains are the Π's)
        let body = {
            let mut t = h;
            let mut tys: Vec<(sandblaster_kernel::term::Name, Rel, Tm)> = Vec::new();
            let mut cur = &ty;
            while let Term::Pi { name, rel, dom, cod } = &**cur {
                tys.push((name.clone(), *rel, dom.clone()));
                cur = cod;
            }
            for (nm, rel, dom) in tys.into_iter().rev() {
                t = mk::lam(&nm, rel, dom, t);
            }
            t
        };
        let name = format!("{fname}::fact#{k}");
        let (g, _) = crate::opt::loopsum::lemmas::add_lemma(env, &name, ty, body, 50_000_000)?;
        out.push(FnFact { lemma: g, name, states: states.clone(), opt: pl.opt, some: pl.some });
    }
    Ok(out)
}
