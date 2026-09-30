//! The recursive enumeration lemma (optimizer design §7.5, "symbolic
//! fuel"; plan O6).
//!
//! A statement `Π … (f : W) … (.hb : Eq(Bool, #le_W(f, C), true)) …. G(f)`
//! about a loop at a **symbolic** fuel (or index) `f` is proven by one
//! measure-recursive lemma whose body enumerates `f`: a chain of dependent
//! tests
//!
//! ```text
//! match f < 1 { true => arm(0) | false => match f < 2 { true => arm(1) | … | false => absurd } }
//! ```
//!
//! In arm `c` the facts `c ≤ f < c + 1` give `f = c` by linear arithmetic;
//! `f` is rewritten to the literal `c` in the goal and every hypothesis
//! that mentions it is restated at `c` (transports), so the arm's proof —
//! supplied by the caller ([`ArmProver`]) — works on literals exactly like a
//! per-literal lemma, its recursive calls at smaller measures being the
//! **induction hypothesis** ([`Ih::apply`]: `Rec` with the decrease proven
//! by linear arithmetic). The last arm has `f ≥ C + 1` against `.hb`: it
//! closes by `absurd`, its contradiction found by linear arithmetic. The
//! kernel checks the lemma (`Env::add_def`, measure recursion).
//!
//! A simulated fault ([`EnumFault::MisstatedArm`], the must-reject suite)
//! makes arm `c` claim `f = c + 1` (a certificate-free `linarith` term):
//! the kernel's check rejects the lemma.

use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Lvl, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Budget, EnvEntry, V, Value};

use crate::auto::search::{Engine, R};
use crate::auto::state::St;
use crate::auto::util::{apps, as_eq, irr_entry, venv_push};

/// A simulated fault of an enumeration lemma (must-reject suite only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnumFault {
    /// Arm `c` claims `f = c + 1`.
    MisstatedArm,
}

/// What [`build`] proves (see the module docs).
pub struct EnumSpec {
    pub name: String,
    /// The Π-closed statement.
    pub ty: Tm,
    /// The enumerated binder's telescope index and width.
    pub f: usize,
    pub w: Width,
    /// The bound `C` (the statement has a hypothesis `f ≤ C`).
    pub bound: u32,
    /// The measure over the telescope (machine width `m_w`).
    pub measure: Tm,
    pub m_w: Width,
    pub fault: Option<EnumFault>,
}

/// The induction hypothesis of an enumeration lemma.
pub struct Ih {
    /// The statement (the lemma's own type).
    pub stmt: Tm,
    pub measure: Tm,
    pub m_w: Width,
    /// The telescope's arity (binders before the conclusion).
    pub arity: usize,
    /// The telescope's binder values in the lemma's context (the current
    /// measure's arguments).
    pub params: Vec<Tm>,
}

impl Ih {
    /// The induction hypothesis at the relevant values `rel_vals` (in
    /// binder order): its irrelevant binders proven by `prove`, the
    /// measure's decrease by linear arithmetic; a `Rec` term at `st`'s
    /// depth.
    pub fn apply(&self, e: &mut Engine<'_>, st: &St, rel_vals: Vec<V>, prove: &mut dyn FnMut(&mut Engine<'_>, &St, &V, &str) -> Option<Tm>) -> R<Option<Tm>> {
        Ok(self.apply_typed(e, st, rel_vals, prove)?.map(|(p, _)| p))
    }

    /// [`Ih::apply`] with the instance's statement.
    pub fn apply_typed(&self, e: &mut Engine<'_>, st: &St, rel_vals: Vec<V>, prove: &mut dyn FnMut(&mut Engine<'_>, &St, &V, &str) -> Option<Tm>) -> R<Option<(Tm, V)>> {
        let env = e.env;
        let Ok(mut cur) = env.eval(&Default::default(), Lvl(0), &self.stmt, &mut Budget { steps: 20_000_000 }) else { return Ok(None) };
        let mut args: Vec<Tm> = Vec::new();
        let mut ri = 0usize;
        for _ in 0..self.arity {
            let Value::Pi { name, rel, dom, cod } = &*cur.clone() else { return Ok(None) };
            let entry = match rel {
                Rel::Rel => {
                    let Some(v) = rel_vals.get(ri).cloned() else { return Ok(None) };
                    ri += 1;
                    args.push(st.quote(env, &v));
                    EnvEntry::Rel(v)
                }
                Rel::Irr => {
                    let Some(p) = prove(e, st, dom, name.as_ref()) else { return Ok(None) };
                    args.push(p.clone());
                    irr_entry(&st.venv, &p)
                }
            };
            let Some(next) = e.inst(cod, vec![entry], st.depth())? else { return Ok(None) };
            cur = next;
        }
        // the decrease: m(args) < m(params)
        let d = st.depth();
        let shifted: Vec<Tm> = self.params.iter().map(|t| crate::auto::util::shift(t, (d as i64) - (self.params_depth() as i64))).collect();
        let m_next = crate::opt::proof::steps::subst_n(&self.measure, &args);
        let m_cur = crate::opt::proof::steps::subst_n(&self.measure, &shifted);
        let bi = env.bool_ind();
        let g_tm = mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Lt(self.m_w), args: vec![m_next, m_cur], proofs: vec![] }), mk::bool_lit(bi, true));
        let Ok(g) = env.eval(&env.ctx_venv(&st.ctx), st.ctx.depth(), &g_tm, &mut Budget { steps: 20_000_000 }) else { return Ok(None) };
        let dec = match e.lin_prove(st, &g, true)? {
            Some(p) => e.promote(st, &g, p),
            // (a simulated fault's prover may claim it: the kernel judges)
            None => match prove(e, st, &g, "the measure's decrease") {
                Some(p) => p,
                None => return Ok(None),
            },
        };
        Ok(Some((Rc::new(Term::Rec { args, proof: Some(dec) }), cur)))
    }

    /// The depth the `params` terms live at (the lemma's telescope).
    fn params_depth(&self) -> u32 {
        self.arity as u32
    }
}

/// The arms of an enumeration lemma.
pub trait ArmProver {
    /// A proof of `goal` in `st`, where the enumerated binder is the
    /// literal `c` (the goal rewritten, the hypotheses restated).
    fn arm(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, c: u32, ih: &Ih) -> R<Option<Tm>>;
    /// Why an arm failed (the report).
    fn failure(&self) -> Option<String> {
        None
    }
}

fn eval_in(env: &Env, ctx: &Ctx, t: &Tm) -> Result<V, String> {
    env.eval(&env.ctx_venv(ctx), ctx.depth(), t, &mut Budget { steps: 50_000_000 }).map_err(|e| format!("eval: {e:?}"))
}

/// Restates the facts of `st` that mention the value `x` with `x := lit`
/// (`eq : Eq(W, x, lit)`), as `let` facts of a child state.
pub fn restate(env: &Env, st: &St, x: &V, lit: &Tm, w: Width, eq: &Tm) -> St {
    let mut st2 = st.child();
    let wt = mk::int_ty(w);
    let Ok(litv) = eval_in(env, &st.ctx, lit) else { return st2 };
    let x_tm = st.quote(env, x);
    for f in st.facts.clone() {
        let mut mentions = false;
        crate::auto::util::walk(&f.ty, &mut |y| {
            if Rc::ptr_eq(y, x) || matches!((&**y, &**x), (Value::Neu(a), Value::Neu(b)) if a.spine.is_empty() && b.spine.is_empty() && matches!((&a.head, &b.head), (sandblaster_kernel::value::Head::Var(p), sandblaster_kernel::value::Head::Var(q)) if p == q)) {
                mentions = true;
            }
            !mentions
        });
        if !mentions {
            continue;
        }
        let d = st2.depth();
        let Ok(motive) = env.abstract_occurrences(&st2.ctx, &f.ty, x, &mut Budget { steps: 20_000_000 }) else { continue };
        let Ok(ty2) = env.eval(&venv_push(&st2.venv, EnvEntry::Rel(litv.clone())), Lvl(d + 1), &motive, &mut Budget { steps: 20_000_000 }) else { continue };
        let mut pf = st2.var(f.lvl);
        if st2.ctx.entries.get(f.lvl as usize).is_some_and(|e| e.rel == Rel::Irr)
            && let Some((a, l, r)) = as_eq(&f.ty)
            && let Some(promote) = env.lookup_global("eq::promote")
        {
            let (at, lt, rt) = (st2.quote(env, a), st2.quote(env, l), st2.quote(env, r));
            pf = apps(mk::global(promote), [(Rel::Rel, at), (Rel::Rel, lt), (Rel::Rel, rt), (Rel::Irr, pf)]);
        }
        let sh = (d - st.depth()) as i64;
        let p = Rc::new(Term::Transport { ty: wt.clone(), lhs: crate::auto::util::shift(&x_tm, sh), rhs: lit.clone(), eq: crate::auto::util::shift(eq, sh), motive, val: pf });
        st2.push_fact(env, ty2, p, crate::auto::state::Origin::Derived("enumeration arm"));
    }
    st2
}

/// `goal` rewritten along `e_ft : Eq(a, from, to)` by the engine's checked
/// motive (proofs whose types mention `from` — a loop call's `requires`
/// arguments — transported along the equation), its equation binder
/// introduced: the child state, the new goal, and the proof's wrapper
/// (from the child's depth to `st`'s).
pub fn rewrite_intro(e: &mut Engine<'_>, st: &St, goal: &V, a: &V, from: &V, to: &V, e_ft: Tm) -> R<Option<(St, V, super::lemmas::Wrap)>> {
    let env = e.env;
    let Some((t2, k)) = e.rewrite(st, goal, a, from, to, e_ft)? else { return Ok(None) };
    let d = st.depth();
    let mut ch = st.child();
    let mut g = t2;
    if let Value::Pi { name, rel, dom, cod } = &*g.clone() {
        let is_prop = e.is_prop(dom, ch.depth());
        let entry = ch.push_lam(env, name.clone(), *rel, dom.clone(), is_prop);
        let Some(next) = e.inst(cod, vec![entry], ch.depth())? else { return Ok(None) };
        g = next;
    }
    let closer = ch.clone();
    Ok(Some((ch, g, Box::new(move |p: Tm| k.apply(d, closer.finish(p))))))
}

/// Builds and commits the enumeration lemma (see the module docs).
pub fn build(env: &mut Env, spec: &EnumSpec, prover: &mut dyn ArmProver, budget: u64) -> Result<GlobalId, String> {
    let mut arity = 0usize;
    let mut t = &spec.ty;
    while let Term::Pi { cod, .. } = &**t {
        arity += 1;
        t = cod;
    }
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let lim = super::meter::cap(budget);
    let mut sb = Budget { steps: lim };
    let body = {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = St::new(envr, &Ctx::default(), 96);
        let goal = super::lemmas::open(&mut e, &mut st, &spec.ty)?;
        let params: Vec<Tm> = (0..arity as u32).map(|i| st.var(i)).collect();
        let ih = Ih { stmt: spec.ty.clone(), measure: spec.measure.clone(), m_w: spec.m_w, arity, params };
        let f_val = match &st.venv.0[spec.f] {
            EnvEntry::Rel(v) => v.clone(),
            _ => return Err("the enumerated binder is irrelevant".into()),
        };
        let mut ch = Chain { spec, ih: &ih, f_val, failure: None };
        let p = ch.arm_from(&mut e, &mut st, &goal, 0, prover).map_err(|s| format!("{s:?}"))?;
        let p = p.ok_or_else(|| format!("{}: {}", spec.name, ch.failure.clone().or_else(|| prover.failure()).unwrap_or_default()))?;
        st.finish(p)
    };
    super::meter::charge(lim - sb.steps);
    let body = super::lemmas::hashcons(&body);
    let lim = super::meter::cap(budget);
    let mut b = Budget { steps: lim };
    let r = env.add_def(DefDecl { name: Rc::from(spec.name.as_str()), kind: DefKind::Lemma, ty: spec.ty.clone(), body, recursion: Recursion::Measure { measure: spec.measure.clone() }, arity: arity as u32, opaque: true }, &mut b);
    super::meter::charge(lim - b.steps);
    r.map_err(|e| {
            if std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some() {
                eprintln!("[loopsum] the kernel rejected `{}`: {e}", spec.name);
            }
            format!("the kernel rejected `{}`: {}", spec.name, e.to_string().chars().take(600).collect::<String>())
        })
}

struct Chain<'a> {
    spec: &'a EnumSpec,
    ih: &'a Ih,
    f_val: V,
    failure: Option<String>,
}

impl Chain<'_> {
    /// The chain's link at `c`: split on `f < c + 1`.
    fn arm_from(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, c: u32, prover: &mut dyn ArmProver) -> R<Option<Tm>> {
        let env = e.env;
        let w = self.spec.w;
        let bi = env.bool_ind();
        let f_tm = st.quote(env, &self.f_val);
        let test = Rc::new(Term::Prim { op: PrimOp::Lt(w), args: vec![f_tm, mk::lit(w, c as u128 + 1)], proofs: vec![] });
        let Ok(tv) = eval_in(env, &st.ctx, &test) else { return Ok(None) };
        let d = st.depth_left;
        let d0 = st.depth();
        let f_val = self.f_val.clone();
        let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
            let env = e2.env;
            if k == 0 {
                if c >= self.spec.bound {
                    // f ≥ C + 1 against f ≤ C
                    let mut chk = a2.child();
                    return match e2.contradiction(&mut chk)? {
                        Some(p) => Ok(Some(e2.absurd(a2, &tk, chk.finish(p)))),
                        None => {
                            self.failure.get_or_insert_with(|| "the enumeration's last arm is not contradictory".into());
                            Ok(None)
                        }
                    };
                }
                return self.arm_from(e2, a2, &tk, c + 1, prover);
            }
            // c ≤ f < c + 1: f = c
            let claim = if self.spec.fault == Some(EnumFault::MisstatedArm) { c + 1 } else { c };
            let lit = mk::lit(w, claim as u128);
            let g: V = Rc::new(Value::Eq { ty: Rc::new(Value::IntTy(w)), lhs: f_val.clone(), rhs: Rc::new(Value::Lit { w, n: sandblaster_kernel::term::BigInt::from(claim) }) });
            let p_eq = if self.spec.fault.is_some() {
                // a simulated fault's claim: the kernel's linarith check judges it
                Rc::new(Term::Linarith { hyps: vec![], goal: env.quote_typed(&a2.ctx, &g, None, false), cert: vec![] })
            } else {
                match e2.lin_prove(a2, &g, true)? {
                    Some(p) => e2.promote(a2, &g, p),
                    None => {
                        self.failure.get_or_insert_with(|| format!("arm {c}: the enumerated value is not pinned"));
                        return Ok(None);
                    }
                }
            };
            let litv: V = Rc::new(Value::Lit { w, n: sandblaster_kernel::term::BigInt::from(claim) });
            let Some((ch, t2, wrap)) = rewrite_intro(e2, a2, &tk, &Rc::new(Value::IntTy(w)), &f_val, &litv, p_eq.clone())? else {
                self.failure.get_or_insert_with(|| format!("arm {c}: the goal does not mention the enumerated value"));
                return Ok(None);
            };
            let sh = (ch.depth() - a2.depth()) as i64;
            let mut a3 = restate(env, &ch, &f_val, &lit, w, &crate::auto::util::shift(&p_eq, sh));
            let p = prover.arm(e2, &mut a3, &t2, claim, self.ih)?;
            Ok(p.map(|p| wrap(a3.finish(p))))
        };
        let _ = d0;
        e.case_split_with(st, &tv, bi, &[], goal, true, d, &mut arm_fn)
    }
}
