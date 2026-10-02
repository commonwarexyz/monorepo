//! Rewriting (DESIGN.md §8.1 steps 6, 8, 9, 10).
//!
//! * **Stuck-term equations** (step 6): a fact `Eq(A, l, r)` whose one side
//!   is a stuck neutral and whose other side is canonical (a literal, a
//!   constructor, a pair) is a rewrite rule `l ↦ r`. The target `T` is
//!   rewritten through a motive `M` with `M[l] ≡ T` built by term-level
//!   abstraction ([`super::abstraction`]; the kernel's
//!   `Env::abstract_occurrences` compares whole values only and cannot
//!   abstract scrutinee prefixes): the new target is `M[r]` (re-evaluated,
//!   so matches on `r` compute) and the proof is `transport(A, r, l,
//!   sym(e), y. M, p)`. Every motive is type-checked before use. Equations
//!   between two variables (including eta-expanded array variables)
//!   substitute the newer variable; an equation between two stuck terms
//!   (an induction hypothesis) rewrites an occurring side once per branch.
//! * **Arithmetic decision** (step 8): a stuck comparison used as a match
//!   scrutinee is decided by linarith; the decided equation becomes a fact
//!   and a rewrite rule.
//! * **Arithmetic congruence** (step 9): an equation whose sides differ only
//!   in integer subterms is closed by proving each differing pair equal
//!   (linarith) and rewriting.
//! * **`Delta` unfolding** (step 10): a stuck recursive application is
//!   replaced by its body (`Delta(g; args) : Eq(R, g args, body)`) when that
//!   exposes a match whose scrutinee can then be decided (checked on the
//!   unfolded value before any motive is built). Opaque definitions are
//!   unfolded only on an `Unfold` hint (DESIGN.md §5.6: they are used
//!   through their `ensures`).

use std::rc::Rc;

use sandblaster_kernel::term::{GlobalId, IndId, Lvl, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Elim, EnvEntry, Head, Neutral, V, Value};

use super::search::{Cont, Engine, R, ctx_with, is_type_sort};

/// Largest proposition (term nodes) abstracted into a rewrite or
/// case-split motive.
pub const MAX_MOTIVE_NODES: u64 = 100_000;
use super::state::{Fact, Origin, St};
use super::util::*;
use crate::prover::Hint;

/// What kind of stuck subterm.
#[derive(Clone, Debug)]
pub enum StuckKind {
    /// The scrutinee of a stuck match on `ind(params)`.
    Scrut { ind: IndId, params: Vec<V> },
    /// A stuck application of an unfoldable (recursive/opaque) global.
    App { def: GlobalId },
}

/// A stuck subterm of a value.
#[derive(Clone, Debug)]
pub struct Stuck {
    pub val: V,
    pub kind: StuckKind,
}

/// A motive, see [`Engine::motive`].
#[derive(Clone, Debug)]
pub struct Motive {
    pub body: Tm,
    /// Whether the motive starts with the equation binder `Π(e :Irr Eq(A, c, y))`.
    pub has_e: bool,
}

/// A rewrite rule from a fact: `from ↦ to` with a proof of
/// `Eq(ty, from, to)`.
#[derive(Clone, Debug)]
pub struct EqRule {
    pub ty: V,
    pub from: V,
    pub to: V,
    /// The fact's level, and whether the fact is `Eq(ty, to, from)`.
    pub lvl: u32,
    pub rev: bool,
}

/// Head key of a neutral (a cheap pre-filter for occurrence checks).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Key {
    Var(u32),
    Global(u32),
    Prim(PrimOp),
    Other,
}

fn key_of(v: &V) -> Option<Key> {
    match &**v {
        Value::Neu(n) => Some(match &n.head {
            Head::Var(l) => Key::Var(l.0),
            Head::Global { def, .. } => Key::Global(def.0),
            Head::Prim { op, .. } => Key::Prim(*op),
            _ => Key::Other,
        }),
        _ => None,
    }
}

/// Head keys of all neutrals in a value.
fn keys_in(v: &V) -> Vec<Key> {
    let mut out = Vec::new();
    walk(v, &mut |x| {
        if let Some(k) = key_of(x)
            && !out.contains(&k)
        {
            out.push(k);
        }
        true
    });
    out
}

impl<'a> Engine<'a> {
    /// Stuck subterms of a value, outermost first (closures are not
    /// entered).
    pub fn collect_stuck(&self, v: &V, out: &mut Vec<Stuck>) {
        walk(v, &mut |x| {
            if let Value::Neu(n) = &**x {
                if let Head::Global { def, args } = &n.head
                    && self.is_unfoldable_head(*def, args.len())
                {
                    out.push(Stuck { val: prefix(n, 0), kind: StuckKind::App { def: *def } });
                }
                for (i, e) in n.spine.iter().enumerate() {
                    if let Elim::Match { ind, params, .. } = e {
                        out.push(Stuck { val: prefix(n, i), kind: StuckKind::Scrut { ind: *ind, params: params.clone() } });
                    }
                }
            }
            true
        });
    }

    /// Rewrite rules from the state's facts (most recent first).
    pub fn fact_rules(&self, st: &St) -> Vec<EqRule> {
        super::meter::spend(1 + st.facts.len() as u64);
        let mut out = Vec::new();
        for f in st.facts.iter().rev() {
            if let Some(r) = self.rule_of(f) {
                out.push(r);
            }
        }
        out
    }

    /// The rewrite rule a fact stands for, if any.
    pub fn rule_of(&self, f: &Fact) -> Option<EqRule> {
        let (ty, l, r) = as_eq(&f.ty)?;
        let ln = as_neu(l).is_some();
        let rn = as_neu(r).is_some();
        // a stuck term (a variable included) equal to a canonical value, or
        // a stuck non-variable term equal to a variable (a simpler normal
        // form: `f(x) == y` rewrites `f(x)` to `y`)
        let lv = as_var(l).is_some();
        let rv = as_var(r).is_some();
        if ln && (is_canonical(r) || (rv && !lv)) {
            Some(EqRule { ty: ty.clone(), from: l.clone(), to: r.clone(), lvl: f.lvl, rev: false })
        } else if rn && (is_canonical(l) || (lv && !rv)) {
            Some(EqRule { ty: ty.clone(), from: r.clone(), to: l.clone(), lvl: f.lvl, rev: true })
        } else {
            None
        }
    }

    /// The proof of `Eq(ty, from, to)` of a rule, at the state's depth.
    pub fn rule_proof(&self, st: &St, r: &EqRule) -> Tm {
        let v = st.var(r.lvl);
        if !r.rev {
            return v;
        }
        let a = self.quote(st, &r.ty);
        let to = st.quote_at(self.env, &r.to, &r.ty);
        let from = st.quote_at(self.env, &r.from, &r.ty);
        // fact: Eq(ty, to, from); sym gives Eq(ty, from, to)
        self.sym(&a, &to, &from, &v)
    }

    /// The motive `y. Π(e :Irr Eq(A, from, y)). T[y]` abstracting `from` in
    /// `t` (a term at depth `d + 1`, variable 0 = the abstracted value),
    /// type-checked; `None` if `from` does not occur or the motive is
    /// ill-typed. Proofs in `t` whose own types mention `from` are
    /// transported along `e` ([`super::abstraction`]), so the motive stays
    /// well typed without generalizing facts.
    pub fn motive(&mut self, st: &St, t: &V, a: &V, from: &V) -> R<Option<Motive>> {
        self.motive_e(st, t, a, from, true)
    }

    /// [`Engine::motive`]; with `want_e = false` the equation binder is
    /// omitted when nothing uses it ([`Motive::has_e`]).
    pub fn motive_e(&mut self, st: &St, t: &V, a: &V, from: &V, want_e: bool) -> R<Option<Motive>> {
        self.tick()?;
        let d = st.depth();
        let g_tm = self.quote(st, t);
        // a motive is about as large as the proposition it abstracts, and
        // type-checking it costs several steps per node: propositions far
        // beyond any useful motive are not abstracted (the largest motive
        // of the test suites and the QMDB build has ~5k nodes)
        if super::meter::term_size(&g_tm, MAX_MOTIVE_NODES + 1) > MAX_MOTIVE_NODES {
            self.note(format!("no motive: the proposition has more than {MAX_MOTIVE_NODES} nodes"));
            return Ok(None);
        }
        let f_tm = st.quote_at(self.env, from, a);
        let a_tm = self.quote(st, a);
        let facts = self.reachable_fact_types(st, &g_tm);
        let ab = super::abstraction::abstract_prop(self.env, d, &g_tm, &f_tm, &a_tm, facts, &st.venv, from);
        self.b.steps = self.b.steps.saturating_sub(ab.steps);
        if ab.count == 0 {
            if self.trace {
                eprintln!("[auto] no motive: `{}` does not occur (relevantly) in `{}`", self.show(st, from), super::search::truncate(self.show(st, t), 300));
            }
            return Ok(None);
        }
        let has_e = want_e || ab.uses_e > 0;
        let mut m = if has_e {
            mk::pi("e", Rel::Irr, mk::eq(shift(&a_tm, 1), shift(&f_tm, 1), mk::var(0)), ab.body)
        } else {
            // Drop the (unused) equation binder below the motive variable.
            shift_from(&ab.body, -1, 1)
        };
        let cy = ctx_with(&st.ctx, a);
        self.settle();
        let mut r = self.env.infer(&cy, &m, self.b);
        if let Err(e) = &r
            && ((e.kind == sandblaster_kernel::api::KernelErrorKind::Linarith && super::repair::has_linarith(&m))
                || (e.kind == sandblaster_kernel::api::KernelErrorKind::Erased && super::repair::has_erased(&m)))
        {
            // Proofs quoted from evaluated code may carry stale certificates
            // or `Erased` placeholders (bounded, charged to the goal's
            // budget).
            let mut sb = sandblaster_kernel::value::Budget { steps: self.b.steps.min(20_000_000) };
            let start = sb.steps;
            let (m2, n) = super::repair::repair(self.env, &cy, &m, &mut sb);
            self.b.steps = self.b.steps.saturating_sub(start - sb.steps);
            if n > 0 {
                m = m2;
                self.settle();
                r = self.env.infer(&cy, &m, self.b);
            }
        }
        if self.trace
            && let Err(e) = &r
        {
            let mut names = st.names();
            names.push(Rc::from("y"));
            eprintln!(
                "[auto] ill-typed motive for `{}` ({} nodes): {e}\n    motive: {}",
                self.show(st, from),
                crate::elab::tm::size_capped(&m, 10_000_000),
                super::search::truncate(sandblaster_kernel::syntax::printer::print_term_bounded(self.env, &names, &m, 1200), 600)
            );
            if let Ok(dir) = std::env::var("SANDBLASTER_AUTO_DUMP") {
                let n = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
                let _ = std::fs::write(format!("{dir}/motive-{n}.txt"), format!("{e}\n{}", sandblaster_kernel::syntax::printer::print_term_bounded(self.env, &names, &m, 200_000)));
            }
        }
        match self.k_err(r)? {
            Some(s) if is_type_sort(&s) => Ok(Some(Motive { body: m, has_e })),
            other => {
                if self.trace {
                    eprintln!("[auto] no motive for `{}`: its sort is {:?}", self.show(st, from), other.map(|s| self.show(st, &s)));
                }
                Ok(None)
            }
        }
    }

    /// Types (terms at the state's depth) of the proof variables of the
    /// context (irrelevant binders, and relevant binders of proposition
    /// type: the hypotheses of lemma and law bodies) reachable from `g`
    /// through types.
    fn reachable_fact_types(&mut self, st: &St, g: &Tm) -> std::collections::BTreeMap<u32, Tm> {
        let d = st.depth();
        let props: Vec<bool> = st.ctx.entries.iter().map(|e| e.rel == Rel::Irr || self.is_prop(&e.ty, d)).collect();
        let irr = |l: u32| props.get(l as usize).copied().unwrap_or(false);
        let mut work: Vec<u32> = super::abstraction::free_levels(g, d).into_iter().filter(|l| irr(*l)).collect();
        let mut types: std::collections::BTreeMap<u32, Tm> = std::collections::BTreeMap::new();
        while let Some(l) = work.pop() {
            if types.contains_key(&l) {
                continue;
            }
            let p = self.quote(st, &st.ctx.entries[l as usize].ty.clone());
            for x in super::abstraction::free_levels(&p, d) {
                if irr(x) && !types.contains_key(&x) {
                    work.push(x);
                }
            }
            types.insert(l, p);
        }
        types
    }

    /// Evaluate a motive at a value.
    pub fn motive_at(&mut self, st: &St, m: &Tm, v: &V) -> R<Option<V>> {
        let venv = venv_push(&st.venv, EnvEntry::Rel(v.clone()));
        let r = self.env.eval(&venv, Lvl(st.depth()), m, self.b);
        self.ev_err(r)
    }

    /// Rewrite the target `t` with `e_ft : Eq(a, from, to)` (term at the
    /// state's depth).
    pub fn rewrite(&mut self, st: &St, t: &V, a: &V, from: &V, to: &V, e_ft: Tm) -> R<Option<(V, Cont)>> {
        let Some(m) = self.motive_e(st, t, a, from, false)? else { return Ok(None) };
        let Some(t2) = self.motive_at(st, &m.body, to)? else { return Ok(None) };
        let a_tm = self.quote(st, a);
        let f_tm = st.quote_at(self.env, from, a);
        let t_tm = st.quote_at(self.env, to, a);
        let e_tf = self.sym(&a_tm, &f_tm, &t_tm, &e_ft);
        let pre = if m.has_e { vec![mk::refl(a_tm.clone(), f_tm.clone())] } else { vec![] };
        Ok(Some((t2, Cont { depth: st.depth(), ty: a_tm, lhs: t_tm, rhs: f_tm, eq: e_tf, motive: m.body, pre })))
    }

    /// Rewrite a fact with `e_ft : Eq(a, from, to)`: the new type and its
    /// proof `transport(a, from, to, e, y. M, λ(e :Irr ..). h) .e`.
    pub fn rewrite_fact(&mut self, st: &St, f: &Fact, a: &V, from: &V, to: &V, e_ft: Tm) -> R<Option<(V, Tm)>> {
        self.rewrite_prop(st, &f.ty, &st.var(f.lvl), a, from, to, e_ft)
    }

    /// [`Engine::rewrite_fact`] for a proposition `ty` with the proof `h` (a
    /// term at the state's depth, used irrelevantly).
    #[allow(clippy::too_many_arguments)]
    pub fn rewrite_prop(&mut self, st: &St, ty: &V, h: &Tm, a: &V, from: &V, to: &V, e_ft: Tm) -> R<Option<(V, Tm)>> {
        let Some(m) = self.motive(st, ty, a, from)? else { return Ok(None) };
        let Some(mut ty2) = self.motive_at(st, &m.body, to)? else { return Ok(None) };
        let d = st.depth();
        let a_tm = self.quote(st, a);
        let f_tm = st.quote_at(self.env, from, a);
        // λ(e :Irr Eq(a, from, from)). h — the fact's type depends on e only
        // in proof positions, so `h` has the motive's type at `from` by
        // conversion.
        let val = mk::lam("e", Rel::Irr, mk::eq(a_tm.clone(), f_tm.clone(), f_tm.clone()), shift(h, 1));
        let mut proof: Tm = Rc::new(Term::Transport {
            ty: a_tm,
            lhs: f_tm,
            rhs: st.quote_at(self.env, to, a),
            eq: e_ft.clone(),
            motive: m.body.clone(),
            val,
        });
        // Apply to the equation itself (the motive's equation binder).
        let Value::Pi { cod, .. } = &*ty2.clone() else { return Ok(None) };
        let Some(next) = self.inst(cod, vec![irr_entry(&st.venv, &e_ft)], d)? else { return Ok(None) };
        ty2 = next;
        proof = Rc::new(Term::App { rel: Rel::Irr, fun: proof, arg: e_ft });
        Ok(Some((ty2, proof)))
    }

    /// Step 6: rewrite the target with a fact rule whose left side occurs
    /// in it.
    pub fn rewrite_with_facts(&mut self, st: &mut St, t: &V) -> R<Option<(V, Cont)>> {
        let keys = keys_in(t);
        for r in self.fact_rules(st) {
            match key_of(&r.from) {
                Some(k) if keys.contains(&k) => {}
                _ => continue,
            }
            // a term back to a variable the target was expanded from
            if !st.expanded.is_empty() && self.def_var(&r.to).is_some_and(|x| st.expanded.contains(&x)) {
                continue;
            }
            let e = self.rule_proof(st, &r);
            if let Some(res) = self.rewrite(st, t, &r.ty, &r.from, &r.to, e)? {
                self.note("rewrite with a fact equation");
                return Ok(Some(res));
            }
        }
        // Equations between two stuck terms (e.g. an induction hypothesis
        // `f(n', xs) == g(..)`): rewrite an occurring side to the other,
        // once per fact and branch, so that congruence or conversion can
        // finish (`f(n + 1 - 1, xs) == g(..)` becomes `f(n + 1 - 1, xs) ==
        // f(n', xs)`).
        for f in st.scan_facts().iter().rev() {
            if st.used_eqs.contains(&f.lvl) {
                continue;
            }
            let Some((ty, l, r)) = as_eq(&f.ty) else { continue };
            if as_neu(l).is_none() || as_neu(r).is_none() || (as_var(l).is_some() && as_var(r).is_some()) {
                continue;
            }
            for (from, to, rev) in [(r, l, true), (l, r, false)] {
                if !key_of(from).is_some_and(|k| keys.contains(&k)) {
                    continue;
                }
                // a variable is never rewritten away here; a stuck term is
                // rewritten to a variable only when the variable occurs in it
                // (`drop(xs, 0) == xs`): the target shrinks, so this cannot loop
                if as_var(from).is_some() || (as_var(to).is_some() && !self.occurs_in(st, to, from)) {
                    continue;
                }
                // a side that occurs inside the other (`L = append(take(L, n),
                // drop(L, n))`): rewriting it only grows the target, and the
                // rewritten copies of the fact would repeat it forever
                if self.occurs_in(st, from, to) {
                    continue;
                }
                // the same equation as one used already (either way round)
                let mut again = false;
                for (a, b) in st.used_eq_sides.clone() {
                    if (self.conv(st.depth(), &a, from)? && self.conv(st.depth(), &b, to)?) || (self.conv(st.depth(), &a, to)? && self.conv(st.depth(), &b, from)?) {
                        again = true;
                        break;
                    }
                }
                if again {
                    continue;
                }
                let rule = EqRule { ty: ty.clone(), from: from.clone(), to: to.clone(), lvl: f.lvl, rev };
                let e = self.rule_proof(st, &rule);
                let attempt = self.rewrite(st, t, ty, from, to, e)?;
                if attempt.is_none() && self.trace {
                    let shown = self.show(st, from);
                    self.note(format!("no rewrite with fact h{} ({}): {shown}", f.lvl, if rev { "reversed" } else { "forward" }));
                }
                if let Some(res) = attempt {
                    st.used_eqs.push(f.lvl);
                    st.used_eq_sides.push((from.clone(), to.clone()));
                    if self.trace {
                        let shown = self.show(st, &res.0);
                        self.note(format!("rewrite with an equation between stuck terms (fact h{}{}): {shown}", f.lvl, if rev { ", reversed" } else { "" }));
                    }
                    return Ok(Some(res));
                }
            }
        }
        Ok(None)
    }

    /// Whether the value `x` occurs (syntactically, after quoting) inside
    /// the value `y`.
    fn occurs_in(&mut self, st: &St, x: &V, y: &V) -> bool {
        let (xt, yt) = (self.quote(st, x), self.quote(st, y));
        fn go(env: &sandblaster_kernel::api::Env, t: &Tm, x: &Tm, b: u32, seen: &mut std::collections::HashSet<(*const Term, u32)>, budget: &mut u32) -> bool {
            if *budget == 0 || !seen.insert((Rc::as_ptr(t), b)) {
                return false;
            }
            *budget -= 1;
            if std::mem::discriminant(&**t) == std::mem::discriminant(&**x) {
                let xb = if b == 0 { x.clone() } else { shift(x, b as i64) };
                if env.alpha_eq_relevant(t, &xb, &|a, c| a == c) {
                    return true;
                }
            }
            let mut found = false;
            crate::elab::tm::children_depth(t, &mut |c, k| {
                if !found && go(env, c, x, b + k, seen, budget) {
                    found = true;
                }
            });
            found
        }
        go(self.env, &yt, &xt, 0, &mut std::collections::HashSet::new(), &mut 20_000)
    }

    /// Step 6 for equations between two variables (`x == y`, including
    /// eta-expanded array variables, DESIGN.md §5.9): substitute the newer
    /// variable by the older one in the target.
    pub fn rewrite_with_var_equations(&mut self, st: &mut St, t: &V) -> R<Option<(V, Cont)>> {
        let keys = keys_in(t);
        for f in st.scan_facts().iter().rev() {
            let Some((ty, l, r)) = as_eq(&f.ty) else { continue };
            let (Some(a), Some(b)) = (self.var_like(l), self.var_like(r)) else { continue };
            if a == b || !keys.contains(&Key::Var(a.max(b))) {
                continue;
            }
            let (from, to, rev) = if a > b { (l, r, false) } else { (r, l, true) };
            let rule = EqRule { ty: ty.clone(), from: from.clone(), to: to.clone(), lvl: f.lvl, rev };
            let e = self.rule_proof(st, &rule);
            if let Some(res) = self.rewrite(st, t, ty, from, to, e)? {
                self.note("substitute a variable equation");
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    /// The level of a variable or of an eta-expanded array variable.
    pub fn var_like(&self, v: &V) -> Option<u32> {
        if let Some(l) = as_var(v) {
            return Some(l);
        }
        match &**v {
            Value::Pair { fst, snd: Arg::Irr(_) } => self.eta_list_var(fst).map(|l| l.0),
            _ => None,
        }
    }

    /// Step 8: decide a stuck comparison scrutinee of the target by
    /// linarith and rewrite with the decided equation.
    pub fn decide_scrutinee(&mut self, st: &mut St, t: &V) -> R<Option<(V, Cont)>> {
        let mut stuck = Vec::new();
        self.collect_stuck(t, &mut stuck);
        for s in stuck {
            let StuckKind::Scrut { ind, params } = s.kind else { continue };
            // a sequence that linear arithmetic says is empty (`len l == 0`)
            if Some(ind) == self.n.list
                && let Some((fty, p)) = self.decide_empty(st, &s.val, &params)?
            {
                self.note("decide an empty sequence by linarith");
                let lty = Rc::new(Value::Ind { ind, params: params.clone() });
                let Value::Eq { rhs: nil, .. } = &*fty else { continue };
                let nil = nil.clone();
                let lvl = st.push_fact(self.env, fty, p, Origin::Derived("empty sequence"));
                let e = st.var(lvl);
                if let Some(res) = self.rewrite(st, t, &lty, &s.val, &nil, e)? {
                    return Ok(Some(res));
                }
                continue;
            }
            if ind != self.n.bool_ind {
                continue;
            }
            // a sequence compared with itself (`seq::eq(xs, xs)`, the bytes of
            // one encoding on both sides of `agree`): `true` by `seq::eq_refl`,
            // not element by element
            if let Some(p) = self.seq_eq_refl_proof(st, &s.val)? {
                self.note("decide a sequence compared with itself");
                let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
                let lit = self.bool_v(true);
                let fty = Rc::new(Value::Eq { ty: bt.clone(), lhs: s.val.clone(), rhs: lit.clone() });
                let lvl = st.push_fact(self.env, fty, p, Origin::Derived("sequence equal to itself"));
                let e = st.var(lvl);
                if let Some(res) = self.rewrite(st, t, &bt, &s.val, &lit, e)? {
                    return Ok(Some(res));
                }
                continue;
            }
            let Some((op, _)) = as_prim(&s.val) else { continue };
            if cmp_width(op).is_none() {
                continue;
            }
            let Some((b, p)) = self.decide_bool(st, &s.val)? else { continue };
            self.note("decide a stuck comparison by linarith");
            let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
            let lit = self.bool_v(b);
            let fty = Rc::new(Value::Eq { ty: bt.clone(), lhs: s.val.clone(), rhs: lit.clone() });
            let lvl = st.push_fact(self.env, fty, p, Origin::Derived("decided comparison"));
            let e = st.var(lvl);
            if let Some(res) = self.rewrite(st, t, &bt, &s.val, &lit, e)? {
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    /// A proof of `seq::eq T eq a b == true` for a stuck boolean
    /// `seq::eq T eq a b` over machine integers whose sides convert
    /// (`seq::eq_refl` with the element type's `eq_complete`).
    fn seq_eq_refl_proof(&mut self, st: &St, v: &V) -> R<Option<Tm>> {
        let Some((def, args)) = as_global_app(v) else { return Ok(None) };
        if self.env.global_name(def).as_deref() != Some("seq::eq") || args.len() != 4 {
            return Ok(None);
        }
        let (Arg::Rel(t), Arg::Rel(eqf), Arg::Rel(a), Arg::Rel(b)) = (&args[0], &args[1], &args[2], &args[3]) else { return Ok(None) };
        let Value::IntTy(w) = &**t else { return Ok(None) };
        let (Some(refl_g), Some(compl_g), Some(list)) = (self.env.lookup_global("seq::eq_refl"), self.env.lookup_global(&format!("{}::eq_complete", sandblaster_kernel::prim::width_suffix(*w))), self.n.list) else { return Ok(None) };
        if !self.conv(st.depth(), a, b)? {
            return Ok(None);
        }
        let list_ty = Rc::new(Value::Ind { ind: list, params: vec![t.clone()] });
        let (tt, eqt, at) = (self.quote(st, t), self.quote(st, eqf), st.quote_at(self.env, a, &list_ty));
        let complete = mk::lam("x", Rel::Rel, tt.clone(), mk::apps(mk::global(compl_g), [(Rel::Rel, mk::var(0)), (Rel::Rel, mk::var(0)), (Rel::Irr, mk::refl(sandblaster_kernel::util::shift(&tt, 1), mk::var(0)))]));
        let p = mk::apps(mk::global(refl_g), [(Rel::Rel, tt), (Rel::Rel, eqt), (Rel::Rel, complete), (Rel::Rel, at)]);
        // checked here (irrelevantly): a malformed term only costs the step
        let ok = self.infer_irr(st, &p)?.is_some();
        Ok(ok.then_some(p))
    }

    /// `l == Nil` (its type and proof, `seq::len_zero`) for a stuck
    /// sequence scrutinee `l : List(T)` whose length is 0 by linarith.
    pub fn decide_empty(&mut self, st: &St, l: &V, params: &[V]) -> R<Option<(V, Tm)>> {
        let (Some(len_g), Some(list), Some(lz)) = (self.n.seq_len, self.n.list, self.env.lookup_global("seq::len_zero")) else { return Ok(None) };
        let [elem] = params else { return Ok(None) };
        let (et, lt) = (self.quote(st, elem), st.quote_at(self.env, l, &Rc::new(Value::Ind { ind: list, params: params.to_vec() })));
        let len_t = mk::apps(mk::global(len_g), [(Rel::Rel, et.clone()), (Rel::Rel, lt.clone())]);
        let goal_t = mk::eq(mk::int_ty(Width::Int), len_t, mk::lit(Width::Int, 0u8));
        let Some(goal) = self.eval(st, &goal_t)? else { return Ok(None) };
        let Some(p) = self.lin_prove(st, &goal, true)? else { return Ok(None) };
        // the lemma's hypothesis is a relevant argument
        let p = self.promote(st, &goal, p);
        let nil = mk::ctor(list, 0, vec![et.clone()], vec![]);
        let fty_t = mk::eq(mk::ind(list, vec![et.clone()]), lt.clone(), nil);
        let Some(fty) = self.eval(st, &fty_t)? else { return Ok(None) };
        let pf = mk::apps(mk::global(lz), [(Rel::Rel, et), (Rel::Rel, lt), (Rel::Rel, p)]);
        Ok(Some((fty, pf)))
    }

    /// Decide a boolean comparison by linarith: `(b, proof of Eq(Bool, c,
    /// b))`.
    pub fn decide_bool(&mut self, st: &St, c: &V) -> R<Option<(bool, Tm)>> {
        let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
        let probe = std::mem::replace(&mut self.lin_probe, true);
        let mut out = Ok(None);
        for b in [true, false] {
            let g = Rc::new(Value::Eq { ty: bt.clone(), lhs: c.clone(), rhs: self.bool_v(b) });
            match self.lin_prove(st, &g, true) {
                Ok(None) => {}
                r => {
                    out = r.map(|p| p.map(|p| (b, p)));
                    break;
                }
            }
        }
        self.lin_probe = probe;
        out
    }

    /// [`Engine::decide_bool`] with one round of linear arithmetic over
    /// the facts as they are (no enrichment, no integer cuts): the
    /// simplifier's decider, cheap enough to try on every guard of a fact.
    pub fn decide_bool_cheap(&mut self, st: &St, c: &V) -> R<Option<(bool, Tm)>> {
        let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
        let saved = std::mem::replace(&mut self.lin_no_cuts, true);
        let probe = std::mem::replace(&mut self.lin_probe, true);
        let mut out = None;
        for b in [true, false] {
            let g = Rc::new(Value::Eq { ty: bt.clone(), lhs: c.clone(), rhs: self.bool_v(b) });
            match self.lin_prove(st, &g, true) {
                Ok(Some(p)) => {
                    out = Some((b, p));
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    self.lin_no_cuts = saved;
                    self.lin_probe = probe;
                    return Err(e);
                }
            }
        }
        self.lin_no_cuts = saved;
        self.lin_probe = probe;
        Ok(out)
    }

    /// A proof of `Eq(Bool, #le_int(0, e), true)` from `e`'s own range, by
    /// linear arithmetic over no facts: the built-in ranges of its atoms (a
    /// length, an unsigned cast), and the `Nat` range lemma of the spec
    /// function at `e`'s head (`f::nat_range`, `elab::ensures`: `0 <= f(a..)`
    /// for a `Nat` result, one conjunct per `Nat` component of a struct or
    /// tuple result, so `0 <= honest(db, i).leaves`).
    fn nat_guard(&mut self, st: &St, c: &V) -> R<Option<Tm>> {
        let Some((PrimOp::Le(Width::Int), args)) = as_prim(c) else { return Ok(None) };
        if args.len() != 2 || !matches!(&*args[0], Value::Lit { n, .. } if *n == num_bigint::BigInt::from(0)) {
            return Ok(None);
        }
        // only a term with a range of its own: a spec function's application
        // (or a component of one), a length
        let Value::Neu(Neutral { head: Head::Global { def: hd, .. }, spine }) = &*args[1] else { return Ok(None) };
        let is_len = Some(*hd) == self.n.seq_len && spine.is_empty();
        let has_lemma = self.env.global_name(*hd).is_some_and(|n| self.env.lookup_global(&format!("{n}::nat_range")).is_some());
        if self.trace {
            eprintln!("[auto] Nat guard: {} (length {is_len}, range lemma {has_lemma})", super::search::truncate(self.show(st, c), 200));
        }
        if !is_len && !has_lemma {
            return Ok(None);
        }
        let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
        let goal = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: self.bool_v(true) });
        let mut hyps: Vec<(Tm, Tm)> = Vec::new();
        if has_lemma
            && let Value::Neu(Neutral { head: Head::Global { def, args: gargs }, .. }) = &*args[1]
            && let Some(name) = self.env.global_name(*def)
            && let Some(lg) = self.env.lookup_global(&format!("{name}::nat_range"))
            && let Some(ar) = self.env.global_arity(*def)
            && gargs.len() == ar as usize
            && gargs.iter().all(|a| matches!(a, Arg::Rel(_)))
            && let (Some(lty), Some(rels)) = (self.env.global_type(lg), self.env.global_param_rels(lg))
            && rels.len() == ar as usize
        {
            let targs: Vec<Tm> = gargs.iter().map(|a| match a {
                Arg::Rel(v) => self.quote(st, v),
                Arg::Irr(_) => Rc::new(Term::Erased),
            }).collect();
            let mut body = lty;
            for _ in 0..ar {
                let Term::Pi { cod, .. } = &*body.clone() else { return Ok(None) };
                body = cod.clone();
            }
            let stmt = crate::elab::tm::subst_closed(&body, &targs);
            let pf = apps(mk::global(lg), rels.iter().copied().zip(targs.iter().cloned()));
            // its conjuncts, each with its projection of the proof
            let mut work = vec![(stmt, pf)];
            while let Some((t, p)) = work.pop() {
                if hyps.len() >= 16 {
                    break;
                }
                match &*t {
                    Term::Sigma { fst, snd, .. } if !sandblaster_kernel::util::occurs(snd, 0) => {
                        work.push((sandblaster_kernel::util::shift(snd, -1), mk::snd(p.clone())));
                        work.push((fst.clone(), mk::fst(p)));
                    }
                    Term::Eq { .. } => hyps.push((p, t.clone())),
                    _ => {}
                }
            }
        }
        self.lin_with(st, &hyps, &goal)
    }

    /// The simplifier's decision of a stuck `bool` scrutinee: a fact
    /// equation (`c == true`), else cheap linear arithmetic for a
    /// comparison (at most once per scrutinee until the branch has more
    /// facts). The decided value and a proof of `Eq(Bool, c, value)` at the
    /// state's depth; a linear decision is pushed as a fact first, so the
    /// returned proof is that fact (`pushed` says so: terms built before
    /// must be shifted by one).
    fn simp_decide(&mut self, st: &mut St, rules: &[EqRule], c: &V, skip_lvl: u32, lin: bool) -> R<Option<(V, Tm, bool)>> {
        for r in rules {
            if r.lvl == skip_lvl || !is_canonical(&r.to) {
                continue;
            }
            if self.conv(st.depth(), &r.from, c)? {
                return Ok(Some((r.to.clone(), self.rule_proof(st, r), false)));
            }
        }
        let Some((op, _)) = as_prim(c) else { return Ok(None) };
        if cmp_width(op).is_none() {
            return Ok(None);
        }
        // a `Nat` guard `0 <= e` of the target decided by `e`'s own range (a
        // length, a spec function's `Nat` result or component), whatever the
        // size of the context (the target's comparisons are otherwise left to
        // `decide_scrutinee`, one at a time; a fact's guards to the linear
        // decisions below, which a large context runs out of — deciding every
        // fact's guards here would unfold facts the goal never needs)
        if !lin {
            if let Some(p) = self.nat_guard(st, c)? {
                let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
                let lit = self.bool_v(true);
                let fty = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: lit.clone() });
                let lvl = st.push_fact(self.env, fty, p, Origin::Derived("Nat range"));
                return Ok(Some((lit, st.var(lvl), true)));
            }
            return Ok(None);
        }
        for (u, n) in st.simp_undecided.clone() {
            if st.facts.len() < n + 8 && self.conv(st.depth(), &u, c)? {
                return Ok(None);
            }
        }
        if st.simp_lin >= 48 {
            return Ok(None);
        }
        st.simp_lin += 1;
        match self.decide_bool_cheap(st, c)? {
            Some((b, p)) => {
                let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
                let lit = self.bool_v(b);
                let fty = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: lit.clone() });
                let lvl = st.push_fact(self.env, fty, p, Origin::Derived("decided comparison"));
                Ok(Some((lit, st.var(lvl), true)))
            }
            None => {
                st.simp_undecided.push((c.clone(), st.facts.len()));
                Ok(None)
            }
        }
    }

    /// The target's simplification in one step: every stuck `bool`
    /// scrutinee of the target that a fact equation decides is rewritten
    /// with its value (the facts are simplified already, so these are the
    /// same deciders; a comparison that only linear arithmetic decides is
    /// left to `decide_scrutinee`, one at a time). The new target and the
    /// rewrites' continuations.
    pub fn simp_target(&mut self, st: &mut St, t: &V) -> R<Option<(V, Vec<Cont>)>> {
        const MAX_STEPS: u32 = 24;
        if self.no_simp {
            return Ok(None);
        }
        let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
        let mut cur = t.clone();
        let mut conts: Vec<Cont> = Vec::new();
        let mut undecided: Vec<V> = Vec::new();
        'outer: while (conts.len() as u32) < MAX_STEPS {
            let mut stuck = Vec::new();
            self.collect_stuck(&cur, &mut stuck);
            let rules = self.fact_rules(st);
            for s in stuck {
                let StuckKind::Scrut { ind, .. } = s.kind else { continue };
                if ind != self.n.bool_ind {
                    continue;
                }
                let mut known = false;
                for u in &undecided {
                    if self.conv(st.depth(), u, &s.val)? {
                        known = true;
                        break;
                    }
                }
                if known {
                    continue;
                }
                let Some((to, e, pushed)) = self.simp_decide(st, &rules, &s.val, u32::MAX, false)? else {
                    undecided.push(s.val.clone());
                    continue;
                };
                // (a pushed decision is a new binder: the continuations
                // record their own depth, `Cont::apply` shifts them)
                let _ = pushed;
                match self.rewrite(st, &cur, &bt, &s.val, &to, e)? {
                    Some((t2, k)) => {
                        cur = t2;
                        conts.push(k);
                        continue 'outer;
                    }
                    None => undecided.push(s.val.clone()),
                }
            }
            // the cast normal form (the facts get the same one)
            if let Some((from, to, e)) = self.cast_norm_step(st, &cur)? {
                let int = Rc::new(Value::IntTy(Width::Int));
                if let Some((t2, k)) = self.rewrite(st, &cur, &int, &from, &to, e)? {
                    cur = t2;
                    conts.push(k);
                    continue 'outer;
                }
            }
            break;
        }
        if conts.is_empty() {
            return Ok(None);
        }
        self.simp_used = true;
        if self.trace {
            eprintln!("[auto] simplified the target in {} step(s): {} ⟶ {}", conts.len(), super::search::truncate(self.show(st, t), 300), super::search::truncate(self.show(st, &cur), 300));
        }
        self.note("simplify the target");
        Ok(Some((cur, conts)))
    }

    /// One step of the simplifier's normal form for integer casts (D3): an
    /// innermost `x as Int` of a checked word operation — `a + b`, `a - b`,
    /// `a * k`, `a / k`, `a % k` for a literal `k > 0` — becomes the same
    /// operation on `Int` of the casts (`(n / 2) as Int` is `(n as Int) /
    /// 2`, `(e - 1) as Int` is `e as Int - 1`). The checked operation's
    /// proof says it does not wrap, so the two sides are equal; the equation
    /// `Eq(Int, from, to)` is proven by a `Linarith` term (no hypotheses:
    /// the kernel's linearization has both sides), which the kernel
    /// re-checks. Facts and targets go through the same step, so the two
    /// meet in one normal form. `(from, to, proof)`.
    pub fn cast_norm_step(&mut self, st: &St, v: &V) -> R<Option<(V, V, Tm)>> {
        if self.no_cast {
            return Ok(None);
        }
        let mut cands: Vec<(V, PrimOp, Vec<V>, Width)> = Vec::new();
        walk(v, &mut |x| {
            if let Value::Neu(n) = &**x
                && n.spine.is_empty()
                && let Head::Prim { op: PrimOp::Cast { from, to: Width::Int }, args, .. } = &n.head
                && args.len() == 1
                && let Value::Neu(m) = &*args[0]
                && m.spine.is_empty()
                && let Head::Prim { op, args: inner, .. } = &m.head
                && inner.len() == 2
            {
                let lit = |i: usize| matches!(&*inner[i], Value::Lit { n, .. } if *n > sandblaster_kernel::term::BigInt::from(0));
                let ok = match op {
                    PrimOp::Add(w) | PrimOp::Sub(w) => w == from,
                    PrimOp::Mul(w) => w == from && (lit(0) || lit(1)),
                    PrimOp::Div(w) | PrimOp::Rem(w) => w == from && lit(1),
                    _ => false,
                };
                if ok {
                    cands.push((x.clone(), *op, inner.clone(), *from));
                }
            }
            true
        });
        if self.trace && !cands.is_empty() {
            eprintln!("[auto] cast normal form: {} candidate(s) in {}", cands.len(), super::search::truncate(self.show(st, v), 200));
        }
        // innermost first: the last candidate found in pre-order whose
        // operands carry no other candidate
        for (from, op, inner, w) in cands.into_iter().rev() {
            self.tick()?;
            let cast = |t: Tm| mk::prim(PrimOp::Cast { from: w, to: Width::Int }, vec![t], vec![]);
            let lit_int = |x: &V| match &**x {
                Value::Lit { n, .. } => Some(mk::lit(Width::Int, n.clone())),
                _ => None,
            };
            let ity = Rc::new(Value::IntTy(w));
            let a = st.quote_at(self.env, &inner[0], &ity);
            let b = st.quote_at(self.env, &inner[1], &ity);
            if crate::elab::tm::has_erased(&a) || crate::elab::tm::has_erased(&b) {
                continue;
            }
            let to_tm = match op {
                PrimOp::Add(_) => mk::prim(PrimOp::IAdd, vec![cast(a), cast(b)], vec![]),
                PrimOp::Sub(_) => mk::prim(PrimOp::ISub, vec![cast(a), cast(b)], vec![]),
                PrimOp::Mul(_) => {
                    let (x, y) = (lit_int(&inner[0]).unwrap_or_else(|| cast(a.clone())), lit_int(&inner[1]).unwrap_or_else(|| cast(b.clone())));
                    mk::prim(PrimOp::IMul, vec![x, y], vec![])
                }
                PrimOp::Div(_) => mk::prim(PrimOp::IDiv, vec![cast(a), lit_int(&inner[1]).unwrap()], vec![]),
                PrimOp::Rem(_) => mk::prim(PrimOp::IMod, vec![cast(a), lit_int(&inner[1]).unwrap()], vec![]),
                _ => continue,
            };
            let int = Rc::new(Value::IntTy(Width::Int));
            let mut from_tm = st.quote_at(self.env, &from, &int);
            if crate::elab::tm::has_erased(&from_tm) {
                // the operation's proof slot read back from a value lost its
                // proof (D1): re-prove it from the facts
                let hyps = self.lin_hyps(st);
                from_tm = self.refill_erased(st, &from_tm, &hyps)?;
                if crate::elab::tm::has_erased(&from_tm) {
                    continue;
                }
            }
            let Some(to) = self.eval(st, &to_tm)? else { continue };
            let goal = mk::eq(mk::int_ty(Width::Int), from_tm, to_tm);
            let Some(sys) = self.linearize(st, &[], &goal)? else { continue };
            let Some(cert) = super::simplex::certificate(&sys) else {
                if self.trace {
                    eprintln!("[auto] cast normal form: no certificate for {}", super::search::truncate(self.show(st, &from), 200));
                }
                continue;
            };
            self.cast_used = true;
            return Ok(Some((from, to, Rc::new(Term::Linarith { hyps: vec![], goal, cert }))));
        }
        Ok(None)
    }

    pub fn bool_v(&self, b: bool) -> V {
        Rc::new(Value::Ctor { ind: self.n.bool_ind, ctor: b as u32, params: vec![], args: vec![] })
    }

    /// The `Delta` term and equation `(delta, R, lhs, rhs)` for a stuck
    /// global application.
    pub fn delta_eq(&mut self, st: &St, app: &V, def: GlobalId) -> R<Option<(Tm, V, V, V)>> {
        let tm = self.quote(st, app);
        let mut args = Vec::new();
        let mut h = &tm;
        while let Term::App { arg, fun, .. } = &**h {
            args.push(arg.clone());
            h = fun;
        }
        if !matches!(&**h, Term::Global(g) if *g == def) {
            return Ok(None);
        }
        args.reverse();
        let delta = Rc::new(Term::Delta { def, args });
        let r = self.env.infer(&st.ctx, &delta, self.b);
        let Some(ty) = self.k_err(r)? else { return Ok(None) };
        let Some((rt, l, rhs)) = as_eq(&ty) else { return Ok(None) };
        Ok(Some((delta.clone(), rt.clone(), l.clone(), rhs.clone())))
    }

    /// Step 10: unfold a stuck application in the target when that exposes
    /// a decidable match (or any application of `only`, for `unfold(f)`).
    pub fn delta_step(&mut self, st: &mut St, t: &V, only: Option<GlobalId>) -> R<Option<(V, Cont)>> {
        let mut stuck = Vec::new();
        self.collect_stuck(t, &mut stuck);
        let mut seen: Vec<V> = Vec::new();
        for s in stuck {
            let StuckKind::App { def } = s.kind else { continue };
            if only.is_some_and(|g| g != def) {
                continue;
            }
            // `by_arithmetic()` unfolds nothing, `by_unfolding(..)` exactly
            // the definitions it names
            if !self.cfg.mode.allows_delta(def) {
                continue;
            }
            // Opaque definitions are used through their `ensures` and
            // revealed only on request (an `Unfold` hint, DESIGN.md §5.6,
            // or naming them in `by_unfolding(..)`).
            if only.is_none() && self.env.global_opaque(def).unwrap_or(false) && self.cfg.mode == super::Mode::Full {
                continue;
            }
            let mut dup = false;
            for x in &seen {
                if self.conv(st.depth(), x, &s.val)? {
                    dup = true;
                    break;
                }
            }
            if dup {
                continue;
            }
            seen.push(s.val.clone());
            let Some((dt, rt, l, rhs)) = self.delta_eq(st, &s.val, def)? else {
                if self.trace {
                    eprintln!("[auto] no delta for {}", self.show(st, &s.val));
                }
                continue;
            };
            // a body whose read-back hides proofs (`absurd(T, _)` in the
            // impossible arm of `seq::index`): the unfolded target could not
            // be stated in a checked proof
            if crate::elab::tm::has_erased(&st.quote_at(self.env, &rhs, &rt)) {
                continue;
            }
            // a recursive definition applied to a constructor with fields
            // (`fits(Hash(x), Hash(y))`, `clash(Cat(..), Cat(..))`): one
            // step consumes the constructor, so it always makes progress
            // (not a list: a recursion over an expanded array or literal list
            // would unfold once per element)
            let ctor_step = only.is_none() && self.is_recursive(def) && ctor_arg(&s.val, self.n.list);
            // Cheap pre-check on the unfolded value before building (and
            // type-checking) the motive.
            if only.is_none() && !ctor_step && !self.may_unblock(st, t, &s.val, &rhs)? {
                if self.trace {
                    eprintln!("[auto] unfolding {} does not unblock the target", self.show(st, &s.val));
                }
                continue;
            }
            let Some((t2, c)) = self.rewrite(st, t, &rt, &l, &rhs, dt)? else {
                if self.trace {
                    eprintln!("[auto] no motive to unfold {}", self.show(st, &s.val));
                }
                continue;
            };
            if only.is_some() || ctor_step || self.unblocks(st, &t2)? {
                self.note(format!("unfold {}", self.env.global_name(def).map(|n| n.to_string()).unwrap_or_default()));
                return Ok(Some((t2, c)));
            }
            if self.trace {
                eprintln!("[auto] unfolded {} does not unblock the target", self.show(st, &s.val));
            }
        }
        if only.is_none() {
            return self.defined_step(st, t);
        }
        Ok(None)
    }

    /// Step 10 for the named definitions of a `by_unfolding(..)` view
    /// ([`Hint::ViewFunction`] with an equation): a full application of the definition's variable
    /// is replaced by its body through the defining equation, when the
    /// kernel's evaluation would unfold the global (the body does not stop
    /// at a match or checked primitive on an unknown value) or when that
    /// unblocks the target (as for `Delta`).
    fn defined_step(&mut self, st: &mut St, t: &V) -> R<Option<(V, Cont)>> {
        let defined: Vec<(GlobalId, u32, u32, usize)> = self
            .hints
            .iter()
            .filter_map(|h| match h {
                Hint::ViewFunction { def, var, eq: Some(eq), arity } => Some((*def, var.0, eq.0, *arity as usize)),
                _ => None,
            })
            .collect();
        if defined.is_empty() {
            return Ok(None);
        }
        let mut cands: Vec<(V, GlobalId, u32)> = Vec::new();
        walk(t, &mut |x| {
            if let Value::Neu(n) = &**x
                && let Head::Var(l) = &n.head
                && let Some((def, _, eq, ar)) = defined.iter().find(|d| d.1 == l.0)
                && *ar > 0
                && n.spine.len() >= *ar
                && n.spine[..*ar].iter().all(|e| matches!(e, Elim::App(_)))
            {
                cands.push((prefix(n, *ar), *def, *eq));
            }
            true
        });
        let mut seen: Vec<V> = Vec::new();
        for (app, def, eq) in cands {
            let mut dup = false;
            for x in &seen {
                if self.conv(st.depth(), x, &app)? {
                    dup = true;
                    break;
                }
            }
            if dup {
                continue;
            }
            seen.push(app.clone());
            // the equation instance `eq a.. : Eq(R, var a.., body[a..])`
            let tm = self.quote(st, &app);
            let mut args = Vec::new();
            let mut h = &tm;
            while let Term::App { rel, arg, fun } = &**h {
                args.push((*rel, arg.clone()));
                h = fun;
            }
            if !matches!(&**h, Term::Var(_)) {
                continue;
            }
            args.reverse();
            let pf = mk::apps(st.var(eq), args);
            let r = self.env.infer(&st.ctx, &pf, self.b);
            let Some(ty) = self.k_err(r)? else { continue };
            let Some((rt, l, rhs)) = as_eq(&ty) else { continue };
            let (rt, l, rhs) = (rt.clone(), l.clone(), rhs.clone());
            let evaluates = !stops_at_unknown(&rhs);
            if !evaluates && !self.may_unblock(st, t, &app, &rhs)? {
                continue;
            }
            let Some((t2, c)) = self.rewrite(st, t, &rt, &l, &rhs, pf)? else { continue };
            if evaluates || self.unblocks(st, &t2)? {
                self.note(format!("unfold {} (named)", self.env.global_name(def).map(|n| n.to_string()).unwrap_or_default()));
                return Ok(Some((t2, c)));
            }
        }
        Ok(None)
    }

    /// Can unfolding `app` (to `body`) in `t` unblock it: `body` exposes a
    /// decidable scrutinee, or `app` is a side of the equation `t` and
    /// `body` converts with the other side.
    fn may_unblock(&mut self, st: &St, t: &V, app: &V, body: &V) -> R<bool> {
        let d = st.depth();
        if let Some((_, l, r)) = as_eq(t) {
            for (x, y) in [(l, r), (r, l)] {
                if self.conv(d, x, app)? && self.conv(d, body, y)? {
                    return Ok(true);
                }
            }
        }
        self.decidable_scrutinee(st, body)
    }

    /// Does the (unfolded) target expose a decidable scrutinee, or become
    /// closable by conversion?
    fn unblocks(&mut self, st: &St, t: &V) -> R<bool> {
        if let Some((_, l, r)) = as_eq(t)
            && self.conv(st.depth(), l, r)?
        {
            return Ok(true);
        }
        self.decidable_scrutinee(st, t)
    }

    /// Does `t` have a stuck scrutinee that a fact rewrites or linarith
    /// decides?
    fn decidable_scrutinee(&mut self, st: &St, t: &V) -> R<bool> {
        let mut stuck = Vec::new();
        self.collect_stuck(t, &mut stuck);
        let rules = self.fact_rules(st);
        // the first scrutinees (the stuck applications among them, such as
        // the indexing terms of an eta-expanded array, are not counted)
        for s in stuck.iter().filter(|s| matches!(s.kind, StuckKind::Scrut { .. })).take(8) {
            let StuckKind::Scrut { ind, .. } = &s.kind else { continue };
            if self.trace {
                eprintln!("[auto] stuck scrutinee: {} (bool {}, neu {})", self.show(st, &s.val).chars().take(300).collect::<String>(), *ind == self.n.bool_ind, matches!(&*s.val, Value::Neu(_)));
            }
            for r in &rules {
                if self.conv(st.depth(), &r.from, &s.val)? {
                    return Ok(true);
                }
            }
            if *ind == self.n.bool_ind
                && let Some((op, _)) = as_prim(&s.val)
                && cmp_width(op).is_some()
                && self.decide_bool(st, &s.val)?.is_some()
            {
                return Ok(true);
            }
            if Some(*ind) == self.n.list
                && let StuckKind::Scrut { params, .. } = &s.kind
                && self.decide_empty(st, &s.val, params)?.is_some()
            {
                return Ok(true);
            }
            // a `bool` test of two values that a fact equates (`eval(x) !=
            // eval(y)` with the fact `eval(x) == eval(y)`: neither side is
            // canonical, so the fact is no rewrite rule)
            if *ind == self.n.bool_ind && self.equated_test(st, &s.val)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Is `v` a (possibly negated) application whose two value arguments
    /// are the sides of an equation among the facts?
    fn equated_test(&mut self, st: &St, v: &V) -> R<bool> {
        let d = st.depth();
        let rel = |a: &Arg| match a {
            Arg::Rel(x) => Some(x.clone()),
            Arg::Irr(_) => None,
        };
        let args: Vec<V> = match &**v {
            Value::Neu(Neutral { head: Head::Global { args, .. }, spine }) if spine.is_empty() && args.len() <= 8 => args.iter().filter_map(rel).collect(),
            Value::Neu(Neutral { head: Head::Prim { args, .. }, spine }) if spine.is_empty() && args.len() <= 8 => args.clone(),
            Value::Neu(Neutral { spine, .. }) if spine.len() <= 8 => spine.iter().filter_map(|e| match e {
                Elim::App(a) => rel(a),
                _ => None,
            }).collect(),
            _ => return Ok(false),
        };
        // a negation: the test inside
        if args.len() == 1 {
            return self.equated_test(st, &args[0]);
        }
        if args.len() < 2 {
            return Ok(false);
        }
        // one value on both sides (`seq::eq(xs, xs)`, which does not compute
        // on an unknown `xs`): the false case contradicts reflexivity
        if self.conv(d, &args[args.len() - 2], &args[args.len() - 1])? {
            return Ok(true);
        }
        let eqs: Vec<(V, V)> = st.facts.iter().filter_map(|f| as_eq(&f.ty).map(|(_, l, r)| (l.clone(), r.clone()))).filter(|(l, r)| as_neu(l).is_some() && as_neu(r).is_some()).take(64).collect();
        let (a, b) = (&args[args.len() - 2], &args[args.len() - 1]);
        if self.trace {
            eprintln!("[auto] equated test: {} args, {} equations among {} facts", args.len(), eqs.len(), st.facts.len());
        }
        for (l, r) in &eqs {
            if (self.conv(d, a, l)? && self.conv(d, b, r)?) || (self.conv(d, a, r)? && self.conv(d, b, l)?) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Step 9: arithmetic congruence for an equation target whose sides
    /// differ only in integer subterms: when every differing pair is provably
    /// equal, rewrite the first one (the atomic loop continues).
    pub fn congruence_step(&mut self, st: &mut St, t: &V) -> R<Option<(V, Cont)>> {
        let Some((_, l, r)) = as_eq(t) else { return Ok(None) };
        let (l, r) = (l.clone(), r.clone());
        let mut pairs: Vec<(V, V, Width)> = Vec::new();
        if !self.diff(st, &l, &r, &mut pairs, 0)? || pairs.is_empty() || pairs.len() > 64 {
            return Ok(None);
        }
        let mut proofs = Vec::new();
        for (x, y, w) in &pairs {
            let it = Rc::new(Value::IntTy(*w));
            let g = Rc::new(Value::Eq { ty: it.clone(), lhs: x.clone(), rhs: y.clone() });
            let Some(p) = self.close_int_eq(st, &g)? else { return Ok(None) };
            proofs.push((it, p));
        }
        for ((x, y, _), (it, p)) in pairs.iter().zip(proofs) {
            if let Some(res) = self.rewrite(st, t, &it, x, y, p)? {
                self.note(format!("arithmetic congruence ({} integer argument pairs)", pairs.len()));
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    /// Prove an integer equation by conversion, a fact or linarith.
    fn close_int_eq(&mut self, st: &St, g: &V) -> R<Option<Tm>> {
        if let Some((a, l, r)) = as_eq(g)
            && self.conv(st.depth(), l, r)?
        {
            return Ok(Some(mk::refl(self.quote(st, a), st.quote_at(self.env, l, a))));
        }
        for f in st.scan_facts().iter().rev() {
            if self.conv(st.depth(), &f.ty, g)? {
                return Ok(Some(st.var(f.lvl)));
            }
        }
        self.lin_prove(st, g, true)
    }

    /// Structural difference of two values: pairs of differing integer
    /// subterms. `false` if they differ elsewhere.
    fn diff(&mut self, st: &St, a: &V, b: &V, out: &mut Vec<(V, V, Width)>, n: u32) -> R<bool> {
        if n > 64 || self.conv(st.depth(), a, b)? {
            return Ok(true);
        }
        // Maximal differing integer subterms are compared as wholes.
        if matches!(&**a, Value::Neu(_) | Value::Lit { .. })
            && matches!(&**b, Value::Neu(_) | Value::Lit { .. })
            && let Some(w) = self.int_width(st, a)?
        {
            out.push((a.clone(), b.clone(), w));
            return Ok(true);
        }
        let int_pair = |this: &mut Self, out: &mut Vec<(V, V, Width)>| -> R<bool> {
            match this.int_width(st, a)?.or(this.int_width(st, b)?) {
                Some(w) => {
                    out.push((a.clone(), b.clone(), w));
                    Ok(true)
                }
                None => Ok(false),
            }
        };
        match (&**a, &**b) {
            (Value::Ctor { ind: i1, ctor: c1, args: a1, .. }, Value::Ctor { ind: i2, ctor: c2, args: a2, .. }) => {
                if i1 != i2 || c1 != c2 || a1.len() != a2.len() {
                    return Ok(false);
                }
                for (x, y) in a1.iter().zip(a2) {
                    if let (Arg::Rel(x), Arg::Rel(y)) = (x, y)
                        && !self.diff(st, x, y, out, n + 1)?
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (Value::Pair { fst: f1, snd: s1 }, Value::Pair { fst: f2, snd: s2 }) => {
                if !self.diff(st, f1, f2, out, n + 1)? {
                    return Ok(false);
                }
                if let (Arg::Rel(x), Arg::Rel(y)) = (s1, s2) {
                    return self.diff(st, x, y, out, n + 1);
                }
                Ok(true)
            }
            (Value::Neu(p), Value::Neu(q)) if p.spine.len() == q.spine.len() => {
                let same_head = match (&p.head, &q.head) {
                    (Head::Global { def: d1, args: a1 }, Head::Global { def: d2, args: a2 }) if d1 == d2 && a1.len() == a2.len() => {
                        let mut ok = true;
                        for (x, y) in a1.iter().zip(a2) {
                            if let (Arg::Rel(x), Arg::Rel(y)) = (x, y)
                                && !self.diff(st, x, y, out, n + 1)?
                            {
                                ok = false;
                                break;
                            }
                        }
                        ok
                    }
                    (Head::Var(x), Head::Var(y)) => x == y,
                    (Head::Prim { op: o1, args: a1, .. }, Head::Prim { op: o2, args: a2, .. }) if o1 == o2 && a1.len() == a2.len() => {
                        let mut ok = true;
                        for (x, y) in a1.iter().zip(a2) {
                            if !self.diff(st, x, y, out, n + 1)? {
                                ok = false;
                                break;
                            }
                        }
                        ok
                    }
                    _ => false,
                };
                if !same_head {
                    return int_pair(self, out);
                }
                for (e1, e2) in p.spine.iter().zip(&q.spine) {
                    match (e1, e2) {
                        (Elim::App(Arg::Rel(x)), Elim::App(Arg::Rel(y))) => {
                            if !self.diff(st, x, y, out, n + 1)? {
                                return Ok(false);
                            }
                        }
                        (Elim::App(Arg::Irr(_)), Elim::App(Arg::Irr(_))) | (Elim::Fst, Elim::Fst) | (Elim::Snd, Elim::Snd) => {}
                        // Arms are compared by the final conversion check.
                        (Elim::Match { ind: i1, .. }, Elim::Match { ind: i2, .. }) if i1 == i2 => {}
                        _ => return int_pair(self, out),
                    }
                }
                Ok(true)
            }
            _ => int_pair(self, out),
        }
    }

    /// The machine/`Int` width of an integer-typed value, if it is one.
    pub fn int_width(&mut self, st: &St, v: &V) -> R<Option<Width>> {
        if let Some((w, _)) = lit(v) {
            return Ok(Some(w));
        }
        if let Some((op, _)) = as_prim(v) {
            return Ok(sandblaster_kernel::prim::prim_sig(op).and_then(|s| match s.result {
                sandblaster_kernel::prim::PrimTy::Int(w) => Some(w),
                _ => None,
            }));
        }
        if !matches!(&**v, Value::Neu(_)) {
            return Ok(None);
        }
        let tm = self.quote(st, v);
        let r = self.env.infer(&st.ctx, &tm, self.b);
        Ok(match self.k_err(r)? {
            Some(ty) => match &*ty {
                Value::IntTy(w) => Some(*w),
                _ => None,
            },
            None => None,
        })
    }

    /// Apply the goal's rewrite / unfold hints to the target (once).
    pub fn apply_hints(&mut self, st: &mut St, t: &V) -> R<Option<(V, Vec<Cont>)>> {
        let hints: Vec<Hint> = self.hints.iter().filter(|h| matches!(h, Hint::Rewrite { .. } | Hint::Unfold(_))).cloned().collect();
        if hints.is_empty() {
            return Ok(None);
        }
        let mut cur = t.clone();
        let mut conts = Vec::new();
        let k = (st.depth() - self.goal_depth) as i64;
        for h in hints {
            match h {
                Hint::Rewrite { eq, rev, motive } => {
                    let e = shift(&eq, k);
                    let Some(ety) = self.infer_irr(st, &e)? else { continue };
                    let Some((a, l, r)) = as_eq(&ety) else { continue };
                    let (a, l, r) = (a.clone(), l.clone(), r.clone());
                    let (from, to) = if rev { (r.clone(), l.clone()) } else { (l.clone(), r.clone()) };
                    let a_tm = self.quote(st, &a);
                    let (l_tm, r_tm) = (st.quote_at(self.env, &l, &a), st.quote_at(self.env, &r, &a));
                    let e_ft = if rev { self.sym(&a_tm, &l_tm, &r_tm, &e) } else { e.clone() };
                    let res = match motive {
                        Some(m) => {
                            let m = shift_from(&m, k, 1);
                            let Some(t2) = self.motive_at(st, &m, &to)? else { continue };
                            let (f_tm, t_tm) = (st.quote_at(self.env, &from, &a), st.quote_at(self.env, &to, &a));
                            let e_tf = self.sym(&a_tm, &f_tm, &t_tm, &e_ft);
                            Some((t2, Cont { depth: st.depth(), ty: a_tm, lhs: t_tm, rhs: f_tm, eq: e_tf, motive: m, pre: vec![] }))
                        }
                        None => self.rewrite(st, &cur, &a, &from, &to, e_ft)?,
                    };
                    if let Some((t2, c)) = res {
                        self.note("rewrite hint");
                        cur = t2;
                        conts.push(c);
                    } else {
                        self.note("rewrite hint did not apply");
                    }
                }
                Hint::Unfold(g) => {
                    if !self.cfg.mode.allows_delta(g) {
                        continue;
                    }
                    for _ in 0..16 {
                        match self.delta_step(st, &cur, Some(g))? {
                            Some((t2, c)) => {
                                cur = t2;
                                conts.push(c);
                            }
                            None => break,
                        }
                    }
                }
                _ => {}
            }
        }
        if conts.is_empty() { Ok(None) } else { Ok(Some((cur, conts))) }
    }

    /// Rewrite older facts that have `rule.from` as a stuck scrutinee.
    pub fn rewrite_facts_with(&mut self, st: &mut St, rule: &EqRule, upto: usize) -> R<()> {
        for i in 0..upto.min(st.facts.len()) {
            if st.fact_rewrites >= self.cfg.max_fact_rewrites {
                return Ok(());
            }
            let f = st.facts[i].clone();
            if f.lvl == rule.lvl || st.rewritten.contains(&(f.lvl, rule.lvl)) || (matches!(&*f.ty, Value::Sigma { .. }) && std::env::var_os("SANDBLASTER_X_SIGMA").is_none()) {
                continue;
            }
            if !self.has_scrutinee(st, &f.ty, &rule.from)? && !(fixes_var(rule) && self.mentions_level(st, &f.ty, as_var(&rule.from).unwrap_or(u32::MAX))) {
                continue;
            }
            let e = self.rule_proof(st, rule);
            if let Some((ty2, p)) = self.rewrite_fact(st, &f, &rule.ty, &rule.from, &rule.to, e)? {
                st.fact_rewrites += 1;
                st.rewritten.push((f.lvl, rule.lvl));
                st.push_fact(self.env, ty2, p, Origin::Derived("rewritten fact"));
            }
        }
        Ok(())
    }

    /// Simplify a fact in one step (the simplifier's normal form for facts):
    /// every stuck `bool` scrutinee of the fact that a fact equation (`c ==
    /// true`) or linear arithmetic over the facts decides is rewritten with
    /// that value, one after the other, and only the final fact is pushed.
    /// The goal's simplification (`simplify`: fact equations, then
    /// `decide_scrutinee`) uses the same two deciders, so facts and goals
    /// reach the same normal form. Returns whether the fact was replaced:
    /// the caller then does not split or rewrite the original (its partly
    /// simplified copies would multiply with every guard — a spec
    /// predicate with five `Nat` parameters has five nested `0 <= n`
    /// guards). Each rewrite is a `transport` the kernel re-checks.
    pub fn simp_fact(&mut self, st: &mut St, f: &Fact) -> R<bool> {
        const MAX_STEPS: u32 = 24;
        // path equations and decided scrutinees are atoms already; a
        // conjunction is split first and its conjuncts are simplified (a
        // conjunct may decide another's guards)
        if matches!(f.origin, Origin::Split | Origin::Derived("decided comparison") | Origin::Derived("determined scrutinee"))
            || matches!(&*f.ty, Value::Sigma { .. })
            || self.no_simp
        {
            return Ok(false);
        }
        let bt = Rc::new(Value::Ind { ind: self.n.bool_ind, params: vec![] });
        let mut ty = f.ty.clone();
        let mut proof = st.var(f.lvl);
        let mut steps = 0u32;
        let mut undecided: Vec<V> = Vec::new();
        'outer: while steps < MAX_STEPS {
            let mut stuck = Vec::new();
            self.collect_stuck(&ty, &mut stuck);
            let rules = self.fact_rules(st);
            for s in stuck {
                let StuckKind::Scrut { ind, .. } = s.kind else { continue };
                if ind != self.n.bool_ind {
                    continue;
                }
                let mut known = false;
                for u in &undecided {
                    if self.conv(st.depth(), u, &s.val)? {
                        known = true;
                        break;
                    }
                }
                if known {
                    continue;
                }
                let decided = match self.simp_decide(st, &rules, &s.val, f.lvl, true)? {
                    Some((to, e, pushed)) => {
                        if pushed {
                            // the new binder shifts the proof under construction
                            proof = shift(&proof, 1);
                        }
                        Some((to, e))
                    }
                    None => None,
                };
                let Some((to, e)) = decided else {
                    undecided.push(s.val.clone());
                    continue;
                };
                match self.rewrite_prop(st, &ty, &proof, &bt, &s.val, &to, e)? {
                    Some((ty2, p2)) => {
                        ty = ty2;
                        proof = p2;
                        steps += 1;
                        continue 'outer;
                    }
                    None => undecided.push(s.val.clone()),
                }
            }
            // the cast normal form (the target gets the same one)
            if let Some((from, to, e)) = self.cast_norm_step(st, &ty)? {
                let int = Rc::new(Value::IntTy(Width::Int));
                if let Some((ty2, p2)) = self.rewrite_prop(st, &ty, &proof, &int, &from, &to, e)? {
                    ty = ty2;
                    proof = p2;
                    steps += 1;
                    continue 'outer;
                }
            }
            break;
        }
        if steps == 0 {
            return Ok(false);
        }
        if self.trace {
            eprintln!("[auto] simplified fact h{} in {steps} step(s): {}", f.lvl, super::search::truncate(self.show(st, &ty), 300));
        }
        self.simp_used = true;
        self.note("simplify a fact");
        st.push_fact(self.env, ty, proof, Origin::Derived("simplified fact"));
        Ok(true)
    }

    /// Rewrite a fact with every applicable rule of the state.
    pub fn rewrite_fact_with_rules(&mut self, st: &mut St, f: &Fact) -> R<()> {
        // a conjunction's conjuncts are rewritten one by one: rewriting the
        // conjunction as well doubles the facts at every rule
        if matches!(&*f.ty, Value::Sigma { .. }) && std::env::var_os("SANDBLASTER_X_SIGMA").is_none() {
            return Ok(());
        }
        let mut stuck = Vec::new();
        self.collect_stuck(&f.ty, &mut stuck);
        if self.trace {
            eprintln!("[auto] fact h{} ({:?}): {} stuck subterm(s): {}", f.lvl, f.origin, stuck.len(), super::search::truncate(self.show(st, &f.ty), 400));
        }
        if !stuck.iter().any(|s| matches!(s.kind, StuckKind::Scrut { .. })) {
            return Ok(());
        }
        for r in self.fact_rules(st) {
            if st.fact_rewrites >= self.cfg.max_fact_rewrites {
                return Ok(());
            }
            if r.lvl == f.lvl {
                continue;
            }
            // a variable a fact fixes to a literal (`first == false`), also
            // where it is not a scrutinee (an arm of a stuck match: `c ||
            // first` is `match c { true => true, false => first }`)
            let mut hit = fixes_var(&r) && self.mentions_level(st, &f.ty, as_var(&r.from).unwrap_or(u32::MAX));
            for s in &stuck {
                if hit {
                    break;
                }
                if matches!(s.kind, StuckKind::Scrut { .. }) && self.conv(st.depth(), &s.val, &r.from)? {
                    hit = true;
                    break;
                }
            }
            if !hit {
                continue;
            }
            // the first applicable rule rewrites the fact; done already (by
            // `rewrite_facts_with` when the rule was saturated): nothing to do
            if st.rewritten.contains(&(f.lvl, r.lvl)) {
                return Ok(());
            }
            let e = self.rule_proof(st, &r);
            if let Some((ty2, p)) = self.rewrite_fact(st, f, &r.ty, &r.from, &r.to, e)? {
                st.fact_rewrites += 1;
                st.rewritten.push((f.lvl, r.lvl));
                st.push_fact(self.env, ty2, p, Origin::Derived("rewritten fact"));
                return Ok(());
            }
            if self.trace {
                eprintln!("[auto] fact h{} not rewritten with rule h{} ({})", f.lvl, r.lvl, self.show(st, &r.from));
            }
        }
        Ok(())
    }

    /// Does the variable of level `l` occur in the value only inside the
    /// arms of its stuck matches (closures, read back), where the rules
    /// that rewrite scrutinees never reach it (`c || first` is `match c {
    /// true => true, false => first }`)? A variable that also occurs
    /// outside needs no such rewrite: the fact's other rewrites and the
    /// target's reach it.
    fn mentions_level(&self, st: &St, v: &V, l: u32) -> bool {
        let mut outside = false;
        walk(v, &mut |x| {
            if matches!(&**x, Value::Neu(n) if matches!(n.head, Head::Var(h) if h.0 == l)) {
                outside = true;
            }
            !outside
        });
        if outside {
            return false;
        }
        let mut stuck = Vec::new();
        self.collect_stuck(v, &mut stuck);
        if !stuck.iter().any(|s| matches!(s.kind, StuckKind::Scrut { .. })) {
            return false;
        }
        // (a large fact is not read back for this)
        if super::meter::value_cost(self.env, &st.ctx, v, None, true, 20_001) > 20_000 {
            return false;
        }
        let t = self.quote(st, v);
        super::abstraction::free_levels(&t, st.depth()).contains(&l)
    }

    /// Does `ty` contain a stuck match whose scrutinee converts with `s`?
    fn has_scrutinee(&mut self, st: &St, ty: &V, s: &V) -> R<bool> {
        let Some(k) = key_of(s) else { return Ok(false) };
        if !keys_in(ty).contains(&k) {
            return Ok(false);
        }
        let mut stuck = Vec::new();
        self.collect_stuck(ty, &mut stuck);
        for x in stuck {
            if matches!(x.kind, StuckKind::Scrut { .. }) && self.conv(st.depth(), &x.val, s)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// A rule `x ↦ v` that fixes a variable to a literal or a field-less
/// constructor (`true`, `None`, `3`).
fn fixes_var(r: &EqRule) -> bool {
    as_var(&r.from).is_some() && (matches!(&*r.to, Value::Lit { .. }) || matches!(&*r.to, Value::Ctor { args, .. } if args.is_empty()))
}


/// Is `rel` relevant?
pub fn is_rel(r: Rel) -> bool {
    r == Rel::Rel
}

/// Whether a value stops at an unknown: a neutral whose head is a match on
/// an unknown value or a primitive on one (the kernel's evaluator keeps a
/// recursive application folded when its body stops like this, §5.6).
fn stops_at_unknown(v: &V) -> bool {
    match &**v {
        Value::Neu(n) => matches!(n.head, Head::Prim { .. }) || n.spine.iter().any(|e| matches!(e, Elim::Match { .. })),
        _ => false,
    }
}

/// Is `v` a global application with an argument that is a constructor with
/// fields (not a literal, `true`/`false`, `None` or `[]`), of an inductive
/// other than the list type `list`?
fn ctor_arg(v: &V, list: Option<sandblaster_kernel::term::IndId>) -> bool {
    as_global_app(v).is_some_and(|(_, args)| {
        args.iter().any(|a| matches!(a, Arg::Rel(x) if matches!(&**x, Value::Ctor { ind, args, .. } if !args.is_empty() && Some(*ind) != list)))
    })
}
