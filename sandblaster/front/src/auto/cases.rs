//! Case analysis (DESIGN.md §8.1 steps 5 and 11; §7.2 dependent match
//! idiom; §7.6 refinement).
//!
//! * **Case split** on a stuck scrutinee `c : D(ps)`: the target `T` is
//!   generalized over `c` (`R[y]` with `R[c] ≡ T`, via
//!   [`super::abstraction`]), and
//!   `match c as y return Π(e :Irr Eq(D, c, y)). R[y] with | Cₖ(xs) => λe. pₖ end .refl(D, c)`
//!   is built, each arm proving `R[Cₖ(xs)]` (which computes) with the path
//!   equation `e` as a fact.
//! * **Slice refinement**: a split on the list of a slice variable `s`
//!   generalizes `s` itself — the target is rewritten to mention
//!   `(fst s, (Cₖ(xs), q))` with the `SliceOk` proof `q` as a new fact — so
//!   slice functions compute in each arm (§7.6).
//! * **Disequality splits** (step 5): a fact `eq(a, b) == false` (or
//!   `ne(a, b) == true`), unusable by linarith, becomes `a < b ∨ b < a`:
//!   split on `lt(a, b)`, then on `lt(b, a)`; the remaining arm contradicts
//!   the fact (linarith proves `eq(a, b) == true`).
//! * **`∨` facts** are destructed (no path equation: the scrutinee is
//!   irrelevant).
//! * Candidate order: stuck scrutinees of the target, scrutinees inside
//!   arithmetic atoms, then scrutinees of facts with several constructors
//!   (a split can refute arms), and single-constructor ones (struct eta)
//!   last.
//! * **Finite enumeration**: an integer variable with a proven range of at
//!   most [`AutoConfig::enum_limit`](super::AutoConfig) values (or a
//!   `Hint::Cases`) is enumerated by a chain of `lt(x, k+1)` splits; in the
//!   case `x = k` the target is rewritten with `x ↦ k` and computes.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::{One, ToPrimitive};
use sandblaster_kernel::term::{Arm, IndId, Lvl, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Elim, EnvEntry, Head, Neutral, V, VEnv, Value};

use super::arith::lit_v;
use super::rewrite::StuckKind;
use super::search::{Engine, R, apply_conts};
use super::state::{Fact, Origin, St};
use super::util::*;

impl<'a> Engine<'a> {
    /// Case splits for the target (step 11), in order: stuck scrutinees of
    /// the target, stuck scrutinees inside arithmetic atoms and undecided
    /// piecewise conditions, disequality facts, `∨` facts, scrutinees of
    /// facts, finite enumeration.
    /// A6: the target's stuck scrutinee that is a call of a recursive or
    /// opaque function (not a `bool` guard) and also a scrutinee of a fact
    /// (an induction hypothesis `match f(n - 1) { .. }` against the target
    /// `match f(n) { .. }` unfolded one step): split on it before any
    /// further unfolding, which would only move the recursion one call
    /// deeper. `None` when there is no such scrutinee or its split does not
    /// close the target.
    pub fn shared_scrutinee_split(&mut self, st: &mut St, t: &V) -> R<Option<Tm>> {
        // part of the simplifier's search (the plain search is unchanged)
        if st.depth_left == 0 || self.no_simp {
            return Ok(None);
        }
        let d = st.depth();
        let mut stuck = Vec::new();
        self.collect_stuck(t, &mut stuck);
        let facts = self.fact_scrutinees(st);
        for s in stuck {
            let StuckKind::Scrut { ind, params } = s.kind else { continue };
            // a call of a self-recursive function (`cnt(n - 1)`), of an
            // inductive with several constructors (a struct's single arm
            // splits nothing)
            let Value::Neu(n) = &*s.val else { continue };
            let Head::Global { def, .. } = &n.head else { continue };
            if ind == self.n.bool_ind || !n.spine.is_empty() || !self.self_recursive(*def) {
                continue;
            }
            if self.env.inductive_decl(ind).is_none_or(|decl| decl.ctors.len() < 2 || decl.ctors.len() > 16) {
                continue;
            }
            let mut split = false;
            for u in &st.split_vals {
                if self.conv(d, u, &s.val)? {
                    split = true;
                    break;
                }
            }
            if split {
                continue;
            }
            let mut shared = false;
            for (fv, find, _) in &facts {
                if *find == ind && self.conv(d, fv, &s.val)? {
                    shared = true;
                    break;
                }
            }
            if !shared {
                continue;
            }
            self.note(format!("case split on `{}` (a scrutinee of the target and a fact)", self.show(st, &s.val)));
            let depth = st.depth_left - 1;
            if let Some(p) = self.case_split(st, &s.val, ind, &params, t, true, depth)? {
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

    /// Whether the definition `def` calls itself (its body names it).
    fn self_recursive(&self, def: sandblaster_kernel::term::GlobalId) -> bool {
        self.env.global_body(def).is_some_and(|b| crate::elab::tm::any_node(&b, &mut |x| matches!(x, Term::Global(g) if *g == def)))
    }

    pub fn splits(&mut self, st: &mut St, t: &V) -> R<Option<Tm>> {
        let d = st.depth();
        let mut cands: Vec<(V, IndId, Vec<V>)> = Vec::new();
        let mut stuck = Vec::new();
        self.collect_stuck(t, &mut stuck);
        for s in stuck {
            if let StuckKind::Scrut { ind, params } = s.kind {
                cands.push((s.val, ind, params));
            }
        }
        cands.extend(self.atom_split_candidates(st, t)?);
        // Scrutinees of facts: multi-constructor ones first (a split can
        // refute arms); single-constructor ones (struct eta) last.
        let (single, multi): (Vec<_>, Vec<_>) =
            self.fact_scrutinees(st).into_iter().partition(|c| self.env.inductive_decl(c.1).is_some_and(|decl| decl.ctors.len() == 1));
        cands.extend(multi);
        cands.extend(single);
        // Dedup (up to conversion) and skip scrutinees split on this path.
        let mut uniq: Vec<(V, IndId, Vec<V>)> = Vec::new();
        'outer: for c in cands {
            for u in uniq.iter().chain(st.split_vals.iter().map(|v| (v.clone(), c.1, vec![])).collect::<Vec<_>>().iter()) {
                if self.conv(d, &u.0, &c.0)? {
                    continue 'outer;
                }
            }
            if let Some(decl) = self.env.inductive_decl(c.1)
                && decl.ctors.len() <= 16
            {
                uniq.push(c);
            }
        }
        for (s, ind, params) in uniq.into_iter().take(6) {
            if let Some(lvl) = self.slice_list_var(st, &s, ind)? {
                self.note("case split on a slice (refined)");
                if let Some(p) = self.slice_split(st, lvl, t)? {
                    return Ok(Some(p));
                }
                continue;
            }
            self.note(format!("case split on `{}`", self.show(st, &s)));
            let depth = st.depth_left - 1;
            if let Some(p) = self.case_split(st, &s, ind, &params, t, true, depth)? {
                return Ok(Some(p));
            }
        }
        // Disequality facts.
        for f in st.scan_facts() {
            if st.split_diseqs.contains(&f.lvl) {
                continue;
            }
            if let Some(p) = self.diseq_split(st, &f, t)? {
                return Ok(Some(p));
            }
        }
        // ∨ facts.
        for f in st.scan_facts() {
            if let Value::Ind { ind, params } = &*f.ty
                && Some(*ind) == self.n.either
                && params.len() == 2
                && !st.split_diseqs.contains(&f.lvl)
            {
                self.note("case analysis on a ∨ fact");
                let Some(fv) = self.eval(st, &st.var(f.lvl))? else { continue };
                let mut c = st.clone();
                c.split_diseqs.push(f.lvl);
                let depth = st.depth_left - 1;
                if let Some(p) = self.case_split(&c, &fv, *ind, params, t, false, depth)? {
                    return Ok(Some(p));
                }
            }
        }
        if let Some(p) = self.auto_enumerate(st, t)? {
            return Ok(Some(p));
        }
        Ok(None)
    }

    /// A case split with the default arm solver.
    #[allow(clippy::too_many_arguments)]
    pub fn case_split(&mut self, st: &St, s: &V, ind: IndId, params: &[V], t: &V, with_eq: bool, arm_depth: u32) -> R<Option<Tm>> {
        self.case_split_with(st, s, ind, params, t, with_eq, arm_depth, &mut |e: &mut Engine<'a>, arm: &mut St, tk: V, _k: u32| {
            let irr = !e.relevant;
            e.solve_in(arm, tk, irr)
        })
    }

    /// The dependent match idiom (§7.2): split on `s : ind(params)`; each
    /// arm is proved by `arm_fn(engine, arm_state, arm_target, ctor)`, which
    /// returns a proof at the arm state's depth.
    #[allow(clippy::too_many_arguments)]
    pub fn case_split_with<F>(
        &mut self,
        st: &St,
        s: &V,
        ind: IndId,
        params: &[V],
        t: &V,
        with_eq: bool,
        arm_depth: u32,
        arm_fn: &mut F,
    ) -> R<Option<Tm>>
    where
        F: FnMut(&mut Engine<'a>, &mut St, V, u32) -> R<Option<Tm>>,
    {
        // case-split bookkeeping (arm states, generalized facts) is charged
        // per fact of the branch (auto::meter)
        super::meter::spend(st.facts.len() as u64);
        self.tick()?;
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(None) };
        let dty = Rc::new(Value::Ind { ind, params: params.to_vec() });
        let p_tms: Vec<Tm> = params.iter().map(|p| self.quote(st, p)).collect();
        let s_tm = if with_eq { st.quote_at(self.env, s, &dty) } else { self.quote(st, s) };
        let d_tm = mk::ind(ind, p_tms.clone());
        // The motive: Π(e :Irr Eq(D, s, y)). R[y], or the constant target
        // (with the equation binder) if abstraction fails.
        let motive = if with_eq {
            match self.motive(st, t, &dty, s)? {
                Some(m) => m.body,
                None => mk::pi("e", Rel::Irr, mk::eq(shift(&d_tm, 1), shift(&s_tm, 1), mk::var(0)), shift(&self.quote(st, t), 2)),
            }
        } else {
            shift(&self.quote(st, t), 1)
        };
        let nbind = if with_eq { 1 } else { 0 };
        let mut arms = Vec::new();
        for (k, c) in decl.ctors.iter().enumerate() {
            let mut arm = st.child();
            arm.depth_left = arm_depth;
            arm.split_vals.push(s.clone());
            let mut fenv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
            let mut fargs = Vec::new();
            for (fname, frel, fty) in &c.fields {
                let r = self.env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(arm.depth()), fty, self.b);
                let Some(ftv) = self.ev_err(r)? else { return Ok(None) };
                let prop = self.is_prop(&ftv, arm.depth());
                let lvl = arm.depth();
                let e = arm.push_raw(self.env, fname.clone(), *frel, ftv.clone());
                if prop {
                    arm.add_ctx_fact(lvl, ftv, Origin::Split);
                }
                fargs.push(entry_arg(&e));
                fenv.push(e);
            }
            let cval = Rc::new(Value::Ctor { ind, ctor: k as u32, params: params.to_vec(), args: fargs });
            let venv = venv_push(&st.venv, EnvEntry::Rel(cval));
            let r = self.env.eval(&venv, Lvl(arm.depth()), &motive, self.b);
            let Some(mut tk) = self.ev_err(r)? else { return Ok(None) };
            // Introduce the path equation.
            for _ in 0..nbind {
                let Value::Pi { name, rel, dom, cod } = &*tk.clone() else { return Ok(None) };
                let e = arm.push_lam(self.env, name.clone(), *rel, dom.clone(), true);
                let Some(next) = self.inst(cod, vec![e], arm.depth())? else { return Ok(None) };
                tk = next;
            }
            let Some(body) = arm_fn(self, &mut arm, tk, k as u32)? else { return Ok(None) };
            arms.push(Arm { names: c.fields.iter().map(|x| x.0.clone()).collect(), body: arm.finish(body) });
        }
        let m = Rc::new(Term::Match { ind, params: p_tms, scrut: s_tm.clone(), motive, arms });
        Ok(Some(if with_eq { Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(d_tm, s_tm) }) } else { m }))
    }

    /// `a < b ∨ b < a` from a disequality fact (see the module docs).
    pub fn diseq_split(&mut self, st: &St, f: &Fact, t: &V) -> R<Option<Tm>> {
        let Some((ty, l, r)) = as_eq(&f.ty) else { return Ok(None) };
        if !matches!(&**ty, Value::Ind { ind, .. } if *ind == self.n.bool_ind) {
            return Ok(None);
        }
        let Some(b) = bool_lit(self.n.bool_ind, r) else { return Ok(None) };
        let Some((op, args)) = as_prim(l) else { return Ok(None) };
        let w = match (op, b) {
            (PrimOp::Eq(w), false) | (PrimOp::Ne(w), true) => w,
            _ => return Ok(None),
        };
        let (a, bv, c) = (args[0].clone(), args[1].clone(), l.clone());
        self.note(format!("disequality split on `{}`", self.show(st, &c)));
        let lvl = f.lvl;
        let lt_ab = self.lt_value(st, w, &a, &bv)?;
        let Some(lt_ab) = lt_ab else { return Ok(None) };
        let bi = self.n.bool_ind;
        let depth = st.depth_left.saturating_sub(1);
        let mut outer = |e: &mut Engine<'a>, arm: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
            arm.split_diseqs.push(lvl);
            if k == 1 {
                let irr = !e.relevant;
                return e.solve_in(arm, tk, irr);
            }
            let Some(lt_ba) = e.lt_value(arm, w, &bv, &a)? else { return Ok(None) };
            let c = c.clone();
            let depth2 = arm.depth_left;
            let mut inner = |e2: &mut Engine<'a>, arm2: &mut St, tk2: V, k2: u32| -> R<Option<Tm>> {
                if k2 == 1 {
                    let irr = !e2.relevant;
                    return e2.solve_in(arm2, tk2, irr);
                }
                // eq(a, b) = true (or ne(a, b) = false) by linarith, clash.
                let bt = Rc::new(Value::Ind { ind: bi, params: vec![] });
                let opp = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: e2.bool_v(!b) });
                let Some(p) = e2.lin_prove(arm2, &opp, false)? else { return Ok(None) };
                let c_tm = e2.quote(arm2, &c);
                let hv = arm2.var(lvl);
                let (pt, pf) = if b { (hv, p) } else { (p, hv) };
                let empty = e2.bool_clash(&c_tm, &pt, &pf);
                Ok(Some(e2.absurd(arm2, &tk2, empty)))
            };
            e.case_split_with(arm, &lt_ba, bi, &[], &tk, true, depth2, &mut inner)
        };
        self.case_split_with(st, &lt_ab, bi, &[], t, true, depth, &mut outer)
    }

    /// On-demand disequality splits for linear arithmetic (fact
    /// normalization, optimizer design §6.3): a fact `eq(a, b) == false` /
    /// `ne(a, b) == true` that linarith rejects is split into `a < b` and
    /// `b < a` (the case `a = b` contradicts the fact), and `goal` is proven
    /// in both arms from `hyps` plus the path equations — by a certificate,
    /// else by [`Engine::lin_cut`] with `depth − 1`. At most two such facts
    /// are tried; each is split at most once per branch. (Unsigned
    /// `a ≠ 0` never reaches here: saturation normalizes it to `0 < a`.)
    pub fn lin_diseq_cut(&mut self, st: &St, goal: &V, hyps: &[super::arith::Hyp], depth: u32) -> R<Option<Tm>> {
        let bi = self.n.bool_ind;
        let mut tried = 0;
        for f in st.scan_facts() {
            if tried >= 2 {
                break;
            }
            if st.split_diseqs.contains(&f.lvl) {
                continue;
            }
            let Some((ty, l, r)) = as_eq(&f.ty) else { continue };
            if !matches!(&**ty, Value::Ind { ind, .. } if *ind == bi) {
                continue;
            }
            let Some(b) = bool_lit(bi, r) else { continue };
            let Some((op, args)) = as_prim(l) else { continue };
            let w = match (op, b) {
                (PrimOp::Eq(w), false) | (PrimOp::Ne(w), true) => w,
                _ => continue,
            };
            tried += 1;
            let (a, bv, c) = (args[0].clone(), args[1].clone(), l.clone());
            let Some(lt_ab) = self.lt_value(st, w, &a, &bv)? else { continue };
            self.note(format!("disequality split (linarith) on `{}`", self.show(st, &c)));
            let mut base = st.clone();
            base.split_diseqs.push(f.lvl);
            let (d0, nf0, lvl) = (base.depth(), base.facts.len(), f.lvl);
            let hyps0 = hyps.to_vec();
            // hypotheses in an arm: the originals (shifted) and the path equations
            let arm_hyps = move |e: &mut Engine<'a>, arm: &St| -> Vec<super::arith::Hyp> {
                let k = (arm.depth() - d0) as i64;
                let mut hs: Vec<super::arith::Hyp> = hyps0.iter().map(|(p, s)| (shift(p, k), shift(s, k))).collect();
                for f in &arm.facts[nf0.min(arm.facts.len())..] {
                    let stated = e.quote(arm, &f.ty);
                    hs.push((arm.var(f.lvl), stated));
                }
                hs
            };
            let solve = |e: &mut Engine<'a>, arm: &mut St, tk: &V, hs: &[super::arith::Hyp]| -> R<Option<Tm>> {
                let p = match e.lin_with(arm, hs, tk)? {
                    Some(p) => Some(p),
                    None => e.lin_cut(arm, tk, hs, depth - 1)?,
                };
                Ok(p.map(|p| e.promote(arm, tk, p)))
            };
            let depth_left = base.depth_left;
            let mut outer = |e: &mut Engine<'a>, arm: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
                if k == 1 {
                    let hs = arm_hyps(e, arm);
                    return solve(e, arm, &tk, &hs);
                }
                let Some(lt_ba) = e.lt_value(arm, w, &bv, &a)? else { return Ok(None) };
                let c = c.clone();
                let mut inner = |e2: &mut Engine<'a>, arm2: &mut St, tk2: V, k2: u32| -> R<Option<Tm>> {
                    let hs = arm_hyps(e2, arm2);
                    if k2 == 1 {
                        return solve(e2, arm2, &tk2, &hs);
                    }
                    // a = b: eq(a, b) = true (or ne(a, b) = false) contradicts the fact
                    let bt = Rc::new(Value::Ind { ind: bi, params: vec![] });
                    let opp = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: e2.bool_v(!b) });
                    let Some(p) = e2.lin_with(arm2, &hs, &opp)? else { return Ok(None) };
                    let c_tm = e2.quote(arm2, &c);
                    let hv = arm2.var(lvl);
                    let (pt, pf) = if b { (hv, p) } else { (p, hv) };
                    let empty = e2.bool_clash(&c_tm, &pt, &pf);
                    Ok(Some(e2.absurd(arm2, &tk2, empty)))
                };
                let dl = arm.depth_left;
                e.case_split_with(arm, &lt_ba, bi, &[], &tk, true, dl, &mut inner)
            };
            if let Some(p) = self.case_split_with(&base, &lt_ab, bi, &[], goal, true, depth_left, &mut outer)? {
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

    /// The value `lt_w(a, b)`.
    fn lt_value(&mut self, st: &St, w: Width, a: &V, b: &V) -> R<Option<V>> {
        let t = sandblaster_kernel::prim::prim0(PrimOp::Lt(w), vec![self.quote(st, a), self.quote(st, b)]);
        self.eval(st, &t)
    }

    /// If `s` is `fst(snd(x))` for a slice variable `x`, `x`'s level.
    fn slice_list_var(&mut self, st: &St, s: &V, ind: IndId) -> R<Option<u32>> {
        if Some(ind) != self.n.list || self.n.slice_mk.is_none() {
            return Ok(None);
        }
        let Value::Neu(Neutral { head: Head::Var(l), spine }) = &**s else { return Ok(None) };
        if spine.len() != 2 || !matches!(spine[0], Elim::Snd) || !matches!(spine[1], Elim::Fst) {
            return Ok(None);
        }
        let l = l.0;
        if l >= st.depth() || st.ctx.entries[l as usize].rel != Rel::Rel || st.ctx.entries[l as usize].def.is_some() {
            return Ok(None);
        }
        let ty = st.ctx.entries[l as usize].ty.clone();
        Ok(self.slice_elem_of_ty(st, &ty)?.map(|_| l))
    }

    /// Case split on the list of the slice variable at `lvl`, refining the
    /// slice itself (§7.6).
    pub fn slice_split(&mut self, st: &St, lvl: u32, t: &V) -> R<Option<Tm>> {
        self.tick()?;
        let (Some(list), Some(slice_ok)) = (self.n.list, self.env.lookup_global("SliceOk")) else { return Ok(None) };
        let d = st.depth();
        let sty = st.ctx.entries[lvl as usize].ty.clone();
        let x_tm = st.var(lvl);
        let Some(t_elem) = self.slice_elem_of_ty(st, &sty)? else { return Ok(None) };
        let Some(xv) = self.eval(st, &x_tm)? else { return Ok(None) };
        let Some(mo) = self.motive(st, t, &sty, &xv)? else { return Ok(None) };
        let r_tm = mo.body;
        let sty_tm = self.quote(st, &sty);
        let n_tm = mk::fst(x_tm.clone());
        let l_tm = mk::fst(mk::snd(x_tm.clone()));
        let Some(nv) = self.eval(st, &n_tm)? else { return Ok(None) };
        let Some(lv) = self.eval(st, &l_tm)? else { return Ok(None) };
        let list_t = |sh: i64| mk::ind(list, vec![shift(&t_elem, sh)]);
        let ok = |sh: i64, l: Tm| apps(mk::global(slice_ok), [(Rel::Rel, shift(&t_elem, sh)), (Rel::Rel, shift(&n_tm, sh)), (Rel::Rel, l)]);
        // Motive (depth d+1, y_l = Var 0).
        let inner_sigma = |sh: i64| mk::sigma("l", Rel::Irr, list_t(sh), ok(sh + 1, mk::var(0)));
        let pair_p = mk::pair(shift(&sty_tm, 3), shift(&n_tm, 3), mk::pair(inner_sigma(3), mk::var(2), mk::var(1)));
        let motive = mk::pi(
            "q",
            Rel::Irr,
            ok(1, mk::var(0)),
            mk::pi(
                "e",
                Rel::Irr,
                mk::eq(list_t(2), shift(&l_tm, 2), mk::var(1)),
                mk::let_("y", Rel::Rel, shift(&sty_tm, 3), pair_p, shift_from(&r_tm, 3, 1)),
            ),
        );
        let Some(decl) = self.env.inductive_decl(list) else { return Ok(None) };
        let Some(tv) = self.eval(st, &t_elem)? else { return Ok(None) };
        let mut arms = Vec::new();
        for (k, c) in decl.ctors.iter().enumerate() {
            let mut arm = st.child();
            arm.depth_left = st.depth_left.saturating_sub(1);
            arm.split_vals.push(lv.clone());
            let mut fenv: Vec<EnvEntry> = vec![EnvEntry::Rel(tv.clone())];
            let mut fargs = Vec::new();
            for (fname, frel, fty) in &c.fields {
                let r = self.env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(arm.depth()), fty, self.b);
                let Some(ftv) = self.ev_err(r)? else { return Ok(None) };
                let e = arm.push_raw(self.env, fname.clone(), *frel, ftv);
                fargs.push(entry_arg(&e));
                fenv.push(e);
            }
            let cval = Rc::new(Value::Ctor { ind: list, ctor: k as u32, params: vec![tv.clone()], args: fargs });
            let c_tm = self.quote(&arm, &cval);
            let ok_tm = apps(
                mk::global(slice_ok),
                [
                    (Rel::Rel, shift(&t_elem, (arm.depth() - d) as i64)),
                    (Rel::Rel, shift(&n_tm, (arm.depth() - d) as i64)),
                    (Rel::Rel, c_tm),
                ],
            );
            let Some(ok_v) = self.eval(&arm, &ok_tm)? else { return Ok(None) };
            let qe = arm.push_lam(self.env, Rc::from("q"), Rel::Irr, ok_v, true);
            let lt = Rc::new(Value::Ind { ind: list, params: vec![tv.clone()] });
            let eq_ty = Rc::new(Value::Eq { ty: lt, lhs: lv.clone(), rhs: cval.clone() });
            arm.push_lam(self.env, Rc::from("e"), Rel::Irr, eq_ty, true);
            let pv = Rc::new(Value::Pair { fst: nv.clone(), snd: Arg::Rel(Rc::new(Value::Pair { fst: cval, snd: entry_arg(&qe) })) });
            let venv = venv_push(&st.venv, EnvEntry::Rel(pv));
            let r = self.env.eval(&venv, Lvl(arm.depth()), &r_tm, self.b);
            let Some(tk) = self.ev_err(r)? else { return Ok(None) };
            let irr = !self.relevant;
            let Some(body) = self.solve_in(&mut arm, tk, irr)? else { return Ok(None) };
            arms.push(Arm { names: c.fields.iter().map(|x| x.0.clone()).collect(), body: arm.finish(body) });
        }
        let m = Rc::new(Term::Match { ind: list, params: vec![t_elem.clone()], scrut: l_tm.clone(), motive, arms });
        let app1 = Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::snd(mk::snd(x_tm.clone())) });
        let app2: Tm = Rc::new(Term::App { rel: Rel::Irr, fun: app1, arg: mk::refl(list_t(0), l_tm) });
        Ok(Some(Rc::new(Term::App { rel: Rel::Irr, fun: app2, arg: mk::refl(sty_tm.clone(), x_tm) })))
    }

    /// Enumerate the integer variable at `lvl` over `[lo, hi)` (the range
    /// must be provable from the facts). Returns a proof at `st`'s depth.
    pub fn enumerate(&mut self, st: &St, lvl: u32, lo: &BigInt, hi: &BigInt, t: V, irr: bool) -> R<Option<Tm>> {
        let _ = irr;
        let Some(&Value::IntTy(w)) = st.ctx.entries.get(lvl as usize).map(|e| &*e.ty) else { return Ok(None) };
        if hi <= lo || (hi - lo).to_u64().is_none_or(|n| n > 256) {
            return Ok(None);
        }
        let Some(xv) = self.eval(st, &st.var(lvl))? else { return Ok(None) };
        // a frame of its own: a one-value range goes straight to the leaf,
        // which pushes the enumerated value as a fact (a `let` of this
        // frame, closed here — the proof is returned at `st`'s depth)
        let mut c = st.child();
        let r = self.enum_from(&mut c, w, &xv, lo.clone(), hi.clone(), t)?;
        Ok(r.map(|b| c.finish(b)))
    }

    fn enum_from(&mut self, st: &mut St, w: Width, x: &V, k: BigInt, hi: BigInt, t: V) -> R<Option<Tm>> {
        if &k + BigInt::one() >= hi {
            return self.enum_leaf(st, w, x, &k, &t);
        }
        let k1 = &k + BigInt::one();
        let Some(ltv) = self.lt_value(st, w, x, &lit_v(w, k1.clone()))? else { return Ok(None) };
        let bi = self.n.bool_ind;
        let depth = st.depth_left;
        let (x2, k2) = (x.clone(), k.clone());
        let mut f = |e: &mut Engine<'a>, arm: &mut St, tk: V, c: u32| -> R<Option<Tm>> {
            if c == 1 { e.enum_leaf(arm, w, &x2, &k2, &tk) } else { e.enum_from(arm, w, &x2, k2.clone() + BigInt::one(), hi.clone(), tk) }
        };
        self.case_split_with(st, &ltv, bi, &[], &t, true, depth, &mut f)
    }

    /// The case `x = k`: prove it by linarith, rewrite, solve.
    fn enum_leaf(&mut self, st: &mut St, w: Width, x: &V, k: &BigInt, t: &V) -> R<Option<Tm>> {
        let it = Rc::new(Value::IntTy(w));
        let kv = lit_v(w, k.clone());
        let g = Rc::new(Value::Eq { ty: it.clone(), lhs: x.clone(), rhs: kv.clone() });
        let Some(p) = self.lin_prove(st, &g, true)? else { return Ok(None) };
        let lvl = st.push_fact(self.env, g, p, Origin::Derived("enumerated value"));
        let e = st.var(lvl);
        match self.rewrite(st, t, &it, x, &kv, e)? {
            Some((t2, c)) => {
                let irr = !self.relevant;
                let Some(body) = self.solve(st, t2, irr)? else { return Ok(None) };
                Ok(Some(apply_conts(&[c], st.depth(), body)))
            }
            None => {
                let irr = !self.relevant;
                self.solve_in(st, t.clone(), irr)
            }
        }
    }

    /// Automatic finite enumeration of an integer variable that occurs in a
    /// stuck subterm of the target and has a proven range of at most
    /// `enum_limit` values.
    fn auto_enumerate(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        // Integer variables of the target that occur in a stuck subterm or
        // under a primitive that linarith does not linearize.
        let mut stuck = Vec::new();
        self.collect_stuck(t, &mut stuck);
        let mut roots: Vec<V> = stuck.into_iter().map(|s| s.val).collect();
        walk(t, &mut |x| {
            if let Some((op, _)) = as_prim(x)
                && !matches!(
                    op,
                    PrimOp::Add(_)
                        | PrimOp::Sub(_)
                        | PrimOp::IAdd
                        | PrimOp::ISub
                        | PrimOp::Cast { .. }
                        | PrimOp::Eq(_)
                        | PrimOp::Ne(_)
                        | PrimOp::Lt(_)
                        | PrimOp::Le(_)
                        | PrimOp::Gt(_)
                        | PrimOp::Ge(_)
                )
            {
                roots.push(x.clone());
            }
            true
        });
        let mut vars: Vec<u32> = Vec::new();
        for r in &roots {
            walk(r, &mut |x| {
                if let Some(l) = as_var(x)
                    && !vars.contains(&l)
                    && l < st.depth()
                {
                    vars.push(l);
                }
                true
            });
        }
        for l in vars {
            let Some(&Value::IntTy(w)) = st.ctx.entries.get(l as usize).map(|e| &*e.ty) else { continue };
            if w == Width::Int || st.ctx.entries[l as usize].def.is_some() {
                continue;
            }
            let x = neu_var(l);
            let Some(hi) = self.upper_bound(st, w, &x)? else { continue };
            let lo = BigInt::from(0);
            if (&hi - &lo).to_u64().is_some_and(|n| n < self.cfg.enum_limit as u64) {
                self.note(format!("finite enumeration of `{}` over [0, {hi}]", self.show(st, &x)));
                if let Some(p) = self.enumerate(st, l, &lo, &(hi + BigInt::one()), t.clone(), true)? {
                    return Ok(Some(p));
                }
            }
        }
        Ok(None)
    }

    /// The smallest literal `c` (among literals of the facts) with
    /// `x ≤ c` provable.
    fn upper_bound(&mut self, st: &St, w: Width, x: &V) -> R<Option<BigInt>> {
        let mut lits: Vec<BigInt> = Vec::new();
        for f in &st.facts {
            walk(&f.ty, &mut |v| {
                if let Some((lw, n)) = lit(v)
                    && (lw == w || lw == Width::Int)
                {
                    for c in [n.clone() - 1, n.clone(), n.clone() + 1] {
                        if c >= BigInt::from(0) && !lits.contains(&c) {
                            lits.push(c);
                        }
                    }
                }
                true
            });
        }
        lits.sort();
        let max = sandblaster_kernel::prim::max_of(w);
        lits.retain(|c| *c <= max);
        lits.truncate(64);
        // `x ≤ c` is monotone in `c`: the smallest provable candidate by
        // bisection (the literals of an eta-expanded array's lanes would
        // crowd out the bound a linear scan of the first few reaches)
        let Some(last) = lits.last().cloned() else { return Ok(None) };
        if !self.le_provable(st, w, x, &last)? {
            return Ok(None);
        }
        let (mut lo, mut hi) = (0usize, lits.len() - 1);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.le_provable(st, w, x, &lits[mid])? {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Ok(Some(lits[hi].clone()))
    }

    /// Is `x ≤ c` provable by linarith (without enrichment)?
    fn le_provable(&mut self, st: &St, w: Width, x: &V, c: &BigInt) -> R<bool> {
        let g = self.cmp_goal(st, PrimOp::Le(w), x, &lit_v(w, c.clone()))?;
        Ok(match g {
            Some(g) => self.lin_prove(st, &g, false)?.is_some(),
            None => false,
        })
    }

    /// `Eq(Bool, op(a, b), true)`.
    fn cmp_goal(&mut self, st: &St, op: PrimOp, a: &V, b: &V) -> R<Option<V>> {
        let t = mk::eq_bool(self.n.bool_ind, sandblaster_kernel::prim::prim0(op, vec![self.quote(st, a), self.quote(st, b)]), true);
        self.eval(st, &t)
    }
}
