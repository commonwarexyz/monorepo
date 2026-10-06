//! Fact saturation and contradictions (DESIGN.md §8.1 steps 4 and 5).
//!
//! Every fact of a branch is processed once ([`St::sat`] marks progress);
//! derived facts are pushed as `let` binders and processed in turn:
//!
//! * `Empty` facts and clashes (`Eq(Bool, false, true)`, `Eq(D, Cᵢ.., Cⱼ..)`
//!   with `i ≠ j`, distinct literals) end the branch with a proof of `Empty`;
//! * constructor injectivity (`Eq(D, C(as), C(bs))` ⇒ `aₖ = bₖ` for the
//!   non-dependent relevant fields) and pair components (`Eq(Σ, p, q)` with a
//!   pair side ⇒ `fst p = fst q`, and the second components when they are
//!   relevant and non-dependent);
//! * conjunctions and existentials (`Σ` propositions) are split; a negated
//!   disjunction `¬(P ∨ Q)` gives `¬P` and `¬Q`, and a negated boolean
//!   equation `¬(c == b)` gives `c == !b` (a panic contract's no-panic
//!   clause `!(p)`, DESIGN.md §16.5, in the form the rest uses);
//! * **determination** of stuck scrutinees: a fact `Eq(Bool, S, b)` whose `S`
//!   is a stuck match (in the elaborator's dependent-match shape or plain)
//!   determines the scrutinee when exactly one constructor's arm is
//!   compatible with `b` — this covers `a && b == true` ⇒ `a == true`,
//!   `a || b == false` ⇒ `a == false`, `!b == true` ⇒ `b == false`, and user
//!   enums; after `a == true` the fact is rewritten, which yields the right
//!   conjunct (`b == true`);
//! * rewriting with stuck-term equations (a new rule rewrites older facts
//!   that match on its left side; a new fact with stuck matches is rewritten
//!   with existing rules);
//! * stuck predicate applications are unfolded (`Unfold … to_body`), and
//!   so are boolean facts about recursive definitions applied to a
//!   constructor of a recursive spec type (`Delta`, §15 S5);
//! * forward rules (`eq_sound` lemmas, method facts, simp lemmas) are
//!   instantiated by matching their trigger hypothesis ([`super::ematch`]);
//! * **fact normalization** (optimizer design §6.3): an unsigned `a ≠ 0`
//!   (`ne(a, 0) == true`, `eq(a, 0) == false`) — disjunctive, so linarith
//!   rejects it — becomes the fact `0 < a` (`bits::ne_zero_pos_<w>`,
//!   `bits::eq_zero_false_pos_<w>`); other disequalities are split on demand
//!   by linear arithmetic ([`Engine::lin_diseq_cut`], `a < b` / `b < a`).

use std::rc::Rc;

use sandblaster_kernel::term::{Arm, IndId, Lvl, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Elim, EnvEntry, Head, Neutral, V, VEnv, Value};

use super::rewrite::StuckKind;
use super::search::{Engine, R};
use super::state::{Fact, Origin, St};
use super::util::*;

impl<'a> Engine<'a> {
    /// Saturate the unprocessed facts. `Some(p)` with `p : Empty` if a
    /// contradiction was found.
    pub fn saturate(&mut self, st: &mut St) -> R<Option<Tm>> {
        Ok(match self.saturate_for(st, None)? {
            Saturated::Contradiction(p) => Some(p),
            _ => None,
        })
    }

    /// [`Engine::saturate`], stopping early when a derived fact is the
    /// equation `target` itself (by conversion): the atomic loop closes the
    /// target with it at once, instead of first deriving everything the
    /// other facts give (a long saturation can use up the goal's budget
    /// after the answer is already there).
    pub fn saturate_for(&mut self, st: &mut St, target: Option<&V>) -> R<Saturated> {
        let target = target.filter(|t| matches!(&***t, Value::Eq { .. }));
        while st.sat < st.facts.len() {
            self.tick()?;
            let i = st.sat;
            st.sat += 1;
            let f = st.facts[i].clone();
            let before = st.facts.len();
            if let Some(p) = self.sat_one(st, &f, i)? {
                return Ok(Saturated::Contradiction(p));
            }
            if let Some(t) = target {
                for j in before..st.facts.len() {
                    let g = st.facts[j].clone();
                    if matches!(&*g.ty, Value::Eq { .. }) && self.conv(st.depth(), &g.ty, t)? {
                        return Ok(Saturated::Target(g.lvl));
                    }
                }
            }
        }
        Ok(Saturated::Done)
    }

    fn sat_one(&mut self, st: &mut St, f: &Fact, idx: usize) -> R<Option<Tm>> {
        // the simplifier first: a fact whose scrutinees the other facts
        // decide is replaced by its normal form, which is saturated instead
        if self.simp_fact(st, f)? {
            return Ok(None);
        }
        let d = st.depth();
        let ty = f.ty.clone();
        match &*ty {
            Value::Ind { ind, .. } if *ind == self.n.empty_ind => return Ok(Some(st.var(f.lvl))),
            Value::Eq { ty: a, lhs, rhs } => {
                let (a, lhs, rhs) = (a.clone(), lhs.clone(), rhs.clone());
                if let Some(p) = self.sat_eq(st, f, &a, &lhs, &rhs)? {
                    return Ok(Some(p));
                }
                if let Some(rule) = self.rule_of(f) {
                    self.rewrite_facts_with(st, &rule, idx)?;
                }
                if bool_lit(self.n.bool_ind, &rhs).is_some() {
                    self.either_units(st, f)?;
                    self.implication_units(st, f)?;
                }
            }
            Value::Sigma { snd_rel, fst, snd, .. } if self.is_prop(&ty, d) => {
                let (snd_rel, fst, snd) = (*snd_rel, fst.clone(), snd.clone());
                let h = st.var(f.lvl);
                let fst_t = Rc::new(Term::Fst(h.clone()));
                let Some(fv) = self.eval(st, &fst_t)? else { return Ok(None) };
                if self.is_prop(&fst, d) {
                    st.push_fact(self.env, fst.clone(), fst_t.clone(), Origin::Derived("conjunct"));
                }
                if snd_rel == Rel::Rel
                    && let Some(q) = self.inst(&snd, vec![EnvEntry::Rel(fv)], st.depth())?
                {
                    // `snd h` (with `h` shifted by the conjunct binder above).
                    let h2 = st.var(f.lvl);
                    st.push_fact(self.env, q, Rc::new(Term::Snd(h2)), Origin::Derived("conjunct"));
                }
            }
            Value::Pi { .. } => {
                self.not_fact(st, f)?;
                self.not_eq_fact(st, f)?;
                self.either_units(st, f)?;
                self.implication_units(st, f)?;
                self.forward_rule_on_facts(st, f)?;
            }
            Value::Ind { ind, params } if Some(*ind) == self.n.either && params.len() == 2 => self.either_units(st, f)?,
            Value::Neu(Neutral { head: Head::Global { def, .. }, spine }) if spine.is_empty() && self.cfg.mode.allows_delta(*def) && self.is_prop(&ty, d) => {
                let def = *def;
                if let Some((args, body)) = self.unfold_app(st, &ty, def)? {
                    let p =
                        Rc::new(Term::Unfold { def, args: args.into_iter().map(|(_, a)| a).collect(), to_body: true, val: st.var(f.lvl) });
                    st.push_fact(self.env, body, p, Origin::Derived("unfolded predicate"));
                }
            }
            _ => {}
        }
        // Stuck matches in the fact: rewrite with known rules.
        self.rewrite_fact_with_rules(st, f)?;
        // Forward rules.
        self.forward(st, f)?;
        Ok(None)
    }

    /// Equation facts: clashes, injectivity, pair components,
    /// determination.
    fn sat_eq(&mut self, st: &mut St, f: &Fact, a: &V, lhs: &V, rhs: &V) -> R<Option<Tm>> {
        let bi = self.n.bool_ind;
        // Boolean literal clash.
        if let (Some(x), Some(y)) = (bool_lit(bi, lhs), bool_lit(bi, rhs))
            && x != y
        {
            let h = st.var(f.lvl);
            let p = if !x {
                h
            } else {
                let bt = self.bool_ty();
                self.sym(&bt, &mk::bool_lit(bi, true), &mk::bool_lit(bi, false), &h)
            };
            return Ok(Some(self.false_ne_true(p)));
        }
        // two equations that give one stuck term two constructor values:
        // their values are equal (then injectivity or a clash below)
        if let Some(p) = self.join_ctor_eqs(st, f, a, lhs, rhs)? {
            return Ok(Some(p));
        }
        match (&**lhs, &**rhs) {
            (Value::Ctor { ind: i1, ctor: c1, params, args: a1 }, Value::Ctor { ind: i2, ctor: c2, args: a2, .. })
                if i1 == i2 && *i1 != bi =>
            {
                if c1 != c2 {
                    let p = self.ctor_clash(st, st.var(f.lvl), a, lhs, rhs, *i1, params, *c1)?;
                    return Ok(p);
                }
                self.injectivity(st, f, a, lhs, rhs, *i1, params, *c1, a1, a2)?;
            }
            (Value::Lit { n: x, .. }, Value::Lit { n: y, .. }) if x != y => {
                let stated = self.quote(st, &f.ty);
                let empty = Rc::new(Value::Ind { ind: self.n.empty_ind, params: vec![] });
                if let Some(p) = self.lin_with(st, &[(st.var(f.lvl), stated)], &empty)? {
                    return Ok(Some(p));
                }
            }
            _ => {}
        }
        if matches!(&**a, Value::Sigma { .. }) && (matches!(&**lhs, Value::Pair { .. }) || matches!(&**rhs, Value::Pair { .. })) {
            self.pair_components(st, f, a, lhs, rhs)?;
        }
        // Fact normalization (optimizer design §6.3): an unsigned `a ≠ 0`
        // (`ne(a, 0) == true` or `eq(a, 0) == false`), which linarith
        // rejects as disjunctive, is `0 < a` (lemmas/bits.core).
        if let Some(b) = bool_lit(bi, rhs)
            && let Some((op, args)) = as_prim(lhs)
            && let (PrimOp::Ne(w), true) | (PrimOp::Eq(w), false) = (op, b)
            && w != Width::Int
            && lit(&args[1]).is_some_and(|(_, n)| n == &num_bigint::BigInt::from(0))
        {
            let stem = if b { "ne_zero_pos" } else { "eq_zero_false_pos" };
            if let Some(g) = self.env.lookup_global(&format!("bits::{stem}_{}", sandblaster_kernel::prim::width_suffix(w))) {
                let a_tm = self.quote(st, &args[0]);
                let pf = apps(mk::global(g), [(Rel::Rel, a_tm.clone()), (Rel::Irr, st.var(f.lvl))]);
                let pos = mk::eq_bool(bi, sandblaster_kernel::prim::prim0(PrimOp::Lt(w), vec![mk::lit(w, 0u8), a_tm]), true);
                if let Some(pv) = self.eval(st, &pos)? {
                    st.push_fact(self.env, pv, pf, Origin::Derived("a ≠ 0 as 0 < a"));
                }
            }
        }
        // `seq::eq(a, b) == false` with `a` and `b` equal (by conversion or
        // an equation fact): a contradiction through `seq::eq_refl`
        if bool_lit(bi, rhs) == Some(false)
            && let Some(p) = self.seq_eq_refuted(st, f, lhs)?
        {
            return Ok(Some(p));
        }
        if let Some(b) = bool_lit(bi, rhs)
            && as_neu(lhs).is_some()
        {
            self.unfold_recursive_fact(st, f, lhs, b)?;
            return self.determine(st, f, lhs, b);
        }
        // a crate function's recursive definition applied to a constructor
        // (`groups(seq![g, ..rest], first) == Some(..)`): one step of it
        if matches!(&**rhs, Value::Ctor { .. }) && as_global_app(lhs).is_some() {
            self.unfold_recursive_ctor_fact(st, f, a, lhs, rhs)?;
        }
        // the path equation `match s { .. } == C(..)` of a match on a spec
        // function's result (`let p = e?` in a spec function, §15 S5):
        // determination as for booleans — the arm whose value can be
        // `C(..)` fixes `s`. Only path equations: a determination costs a
        // case split, and other facts of this shape (refinement facts) do
        // not need it.
        if matches!(f.origin, Origin::Goal(Some(crate::prover::FactOrigin::PathCond)))
            && matches!(&**rhs, Value::Ctor { .. })
            && as_neu(lhs).is_some_and(|n| n.spine.iter().any(|e| matches!(e, Elim::Match { .. })))
        {
            return self.determine(st, f, lhs, true);
        }
        // any other fact `match c { .. } == C(..)` whose stuck match is on a
        // value with field-less constructors (a comparison, a `bool`, a
        // test): the arm that can be `C(..)` fixes `c`, as for a path
        // equation — the facts of an unfolded definition (`if b.len() < n {
        // None } else { Some(..) } == Some((a, r))`, a `get` in range) are
        // simplified with what they already say. A field-less scrutinee
        // keeps it cheap: the determination is a two-way split whose arms
        // close by a clash.
        if matches!(&**rhs, Value::Ctor { .. })
            && let Some(n) = as_neu(lhs)
            && n.spine.iter().any(|e| matches!(e, Elim::Match { ind, .. } if self.fieldless(*ind)))
            // (not for a large fact: its motive is read back, and a read-back
            // beyond the goal's means exhausts the goal)
            && super::meter::value_cost(self.env, &st.ctx, &f.ty, None, true, 5_001) <= 5_000
        {
            return self.determine_fieldless(st, f, lhs);
        }
        if let Some(b) = bool_lit(bi, lhs)
            && as_neu(rhs).is_some()
        {
            // Orient `Eq(Bool, b, S)` as `Eq(Bool, S, b)`.
            let bt = self.bool_ty();
            let (bl, s_tm) = (mk::bool_lit(bi, b), self.quote(st, rhs));
            let p = self.sym(&bt, &bl, &s_tm, &st.var(f.lvl));
            let ty2 = Rc::new(Value::Eq { ty: a.clone(), lhs: rhs.clone(), rhs: lhs.clone() });
            st.push_fact(self.env, ty2, p, Origin::Derived("symmetric"));
        }
        Ok(None)
    }

    /// Negations in the form saturation uses (a panic contract's no-panic
    /// clause `!(p)` is the precondition `Not(P)`, DESIGN.md §16.5):
    /// * a negated disjunction `h : ¬(P ∨ Q)` gives `¬P` and `¬Q`
    ///   (`λp. h(Left(p))`, `λq. h(Right(q))`), each normalized in turn;
    /// * a negated boolean equation `h : ¬(c == b)`, `b` a literal and `c`
    ///   stuck, gives `c == !b`, by a case split on `c` whose `b` arm is
    ///   absurd (`h` applied to the path equation): the form linarith,
    ///   determination and rewriting use.
    fn not_fact(&mut self, st: &mut St, f: &Fact) -> R<()> {
        let d = st.depth();
        let Value::Pi { rel, dom, cod, .. } = &*f.ty else { return Ok(()) };
        let (rel, dom) = (*rel, dom.clone());
        let x = self.env.fresh_var(Lvl(d), rel, &dom);
        let Some(cv) = self.inst(cod, vec![x], d + 1)? else { return Ok(()) };
        if !matches!(&*cv, Value::Ind { ind, .. } if *ind == self.n.empty_ind) {
            return Ok(());
        }
        let empty = mk::ind(self.n.empty_ind, vec![]);
        // ¬(P ∨ Q): ¬P and ¬Q
        if let Some(either) = self.n.either
            && let Some((p, q)) = self.either_sides(st, &dom)?
        {
            let params = [p, q];
            for k in 0..2 {
                // (quoted at the current depth: the first side's fact is a
                // binder of the second's context)
                let d1 = st.depth();
                let sides: Vec<Tm> = params.iter().map(|p| self.quote(st, p)).collect();
                let neg_tm = mk::pi("x", rel, sides[k].clone(), empty.clone());
                let Some(neg) = self.eval(st, &neg_tm)? else { continue };
                let mut known = false;
                for g in st.scan_facts() {
                    if self.conv(d1, &g.ty, &neg)? {
                        known = true;
                        break;
                    }
                }
                if known {
                    continue;
                }
                let inj = Rc::new(Term::Ctor { ind: either, ctor: k as u32, params: sides.iter().map(|s| shift(s, 1)).collect(), args: vec![mk::var(0)] });
                let body = Rc::new(Term::App { rel, fun: shift(&st.var(f.lvl), 1), arg: inj });
                st.push_fact(self.env, neg, mk::lam("x", rel, sides[k].clone(), body), Origin::Derived("¬(p ∨ q) as ¬p and ¬q"));
            }
            return Ok(());
        }
        // ¬(c == b): c == !b
        let bi = self.n.bool_ind;
        let Some((ty, c, b)) = as_eq(&dom) else { return Ok(()) };
        if !matches!(&**ty, Value::Ind { ind, .. } if *ind == bi) {
            return Ok(());
        }
        let Some(bv) = bool_lit(bi, b) else { return Ok(()) };
        if as_neu(c).is_none() {
            return Ok(());
        }
        let c = c.clone();
        let bt = Rc::new(Value::Ind { ind: bi, params: vec![] });
        let target = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: self.bool_v(!bv) });
        for g in st.scan_facts() {
            if self.conv(d, &g.ty, &target)? {
                return Ok(());
            }
        }
        // `match c as y return (Eq(Bool, c, y) -> Eq(Bool, c, !b)) with
        // | b => λe. absurd(h e) | !b => λe. e end refl(Bool, c)`: a term, no
        // search (`Bool`'s constructor 0 is `false`)
        let c_tm = self.quote(st, &c);
        let bool_ty = mk::ind(bi, vec![]);
        let h = st.var(f.lvl);
        let motive = mk::pi("e", Rel::Rel, mk::eq(bool_ty.clone(), shift(&c_tm, 1), mk::var(0)), mk::eq(bool_ty.clone(), shift(&c_tm, 2), mk::bool_lit(bi, !bv)));
        let arm = |k: bool| -> Arm {
            let body = if k == bv {
                Rc::new(Term::Absurd { ty: mk::eq(bool_ty.clone(), shift(&c_tm, 1), mk::bool_lit(bi, !bv)), proof: Rc::new(Term::App { rel, fun: shift(&h, 1), arg: mk::var(0) }) })
            } else {
                mk::var(0)
            };
            Arm { names: vec![], body: mk::lam("e", Rel::Rel, mk::eq(bool_ty.clone(), c_tm.clone(), mk::bool_lit(bi, k)), body) }
        };
        let m = Rc::new(Term::Match { ind: bi, params: vec![], scrut: c_tm.clone(), motive, arms: vec![arm(false), arm(true)] });
        let proof = Rc::new(Term::App { rel: Rel::Rel, fun: m, arg: mk::refl(bool_ty.clone(), c_tm.clone()) });
        st.push_fact(self.env, target, proof, Origin::Derived("¬(c == b) as c == !b"));
        Ok(())
    }

    /// A negated integer equation `h : ¬(a = b)` (`requires(a != b)`, a
    /// proposition) as the boolean fact `eq(a, b) == false`, which the rest
    /// of saturation uses: the unsigned `a ≠ 0` normalization (`0 < a`),
    /// rewriting of the scrutinee `eq(a, b)` (an unfolded `if a == b`),
    /// and linarith's disequality splits. Proof: a case split on `eq(a, b)`
    /// whose `true` arm contradicts `h` (linarith gives `a = b` from the path
    /// equation).
    fn not_eq_fact(&mut self, st: &mut St, f: &Fact) -> R<()> {
        let d = st.depth();
        let Value::Pi { rel, dom, cod, .. } = &*f.ty else { return Ok(()) };
        let Some((ty, a, b)) = as_eq(dom) else { return Ok(()) };
        let Value::IntTy(w) = &**ty else { return Ok(()) };
        let (rel, w, a, b) = (*rel, *w, a.clone(), b.clone());
        let x = self.env.fresh_var(Lvl(d), rel, dom);
        let Some(cv) = self.inst(cod, vec![x], d + 1)? else { return Ok(()) };
        if !matches!(&*cv, Value::Ind { ind, .. } if *ind == self.n.empty_ind) {
            return Ok(());
        }
        let bi = self.n.bool_ind;
        let c_tm = sandblaster_kernel::prim::prim0(PrimOp::Eq(w), vec![self.quote(st, &a), self.quote(st, &b)]);
        let Some(c) = self.eval(st, &c_tm)? else { return Ok(()) };
        if as_neu(&c).is_none() {
            // decided by evaluation: nothing to add (a clash is found by
            // the equation's own saturation)
            return Ok(());
        }
        let bt = Rc::new(Value::Ind { ind: bi, params: vec![] });
        let target = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: self.bool_v(false) });
        for g in st.scan_facts() {
            if self.conv(d, &g.ty, &target)? {
                return Ok(());
            }
        }
        let (lvl, eq_goal) = (f.lvl, dom.clone());
        let mut arm_fn = |e: &mut Engine<'a>, arm: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
            if k == 0 {
                return e.close(arm, &tk);
            }
            // `eq(a, b) == true` (the path equation) gives `a = b`
            let Some(p) = e.lin_prove(arm, &eq_goal, true)? else { return Ok(None) };
            let empty = Rc::new(Term::App { rel, fun: arm.var(lvl), arg: p });
            Ok(Some(e.absurd(arm, &tk, empty)))
        };
        if let Some(p) = self.case_split_with(st, &c, bi, &[], &target, true, 0, &mut arm_fn)? {
            st.push_fact(self.env, target, p, Origin::Derived("a ≠ b as eq(a, b) == false"));
        }
        Ok(())
    }

    /// Unit propagation on `∨` facts: a fact `P ∨ Q` and a fact refuting
    /// one side (`¬Q`, or `X == !b` against `Q = (X == b)`) give the other
    /// side as a fact, by a match on the disjunction whose refuted arm is
    /// absurd. `f` is the new fact: a disjunction (checked against every
    /// fact) or a possible refutation (checked against every disjunction).
    /// Without it the disjunction waits for a case split, the last step of
    /// the search, which a large goal may never reach (§15 S5: `agree(x, y)
    /// ∨ collision(clash(x, y))` with `!collision(clash(x, y))`).
    /// A proof of `Empty` at depth `d + 1` (variable 0 : `side`) when `side`
    /// is an integer equation `a == k` (either way round, `k` a literal) and
    /// `r` is the boolean fact `eq(a, k) == false` or `ne(a, k) == true`
    /// (the path equation of a branch on `a == k`): `r` transported along
    /// the equation says `eq(k, k) == false`, which evaluates to a clash.
    fn refute_int_eq(&mut self, st: &St, side: &V, r: &Fact) -> R<Option<Tm>> {
        let d = st.depth();
        let (Some((t, a1, b1)), Some((bt2, x2, v2))) = (as_eq(side), as_eq(&r.ty)) else { return Ok(None) };
        if !matches!(&**t, Value::IntTy(_)) || !matches!(&**bt2, Value::Ind { ind, .. } if *ind == self.n.bool_ind) {
            return Ok(None);
        }
        let Some(v2) = bool_lit(self.n.bool_ind, v2) else { return Ok(None) };
        let Some((op, args)) = as_prim(x2) else { return Ok(None) };
        let ok_op = match op {
            PrimOp::Eq(_) => !v2,
            PrimOp::Ne(_) => v2,
            _ => false,
        };
        if !ok_op || args.len() != 2 {
            return Ok(None);
        }
        let (args0, args1) = (args[0].clone(), args[1].clone());
        // `forward`: the equation is `var_side == lit_side` (else reversed)
        for (forward, var_side, lit_side) in [(true, a1, b1), (false, b1, a1)] {
            if lit(lit_side).is_none() {
                continue;
            }
            // the position of `var_side` among the prim's arguments
            let pos = if self.conv(d, &args0, var_side)? && self.conv(d, &args1, lit_side)? {
                0
            } else if self.conv(d, &args1, var_side)? && self.conv(d, &args0, lit_side)? {
                1
            } else {
                continue;
            };
            let t_tm = self.quote(st, t);
            let (var_tm, lit_tm) = (st.quote_at(self.env, var_side, t), st.quote_at(self.env, lit_side, t));
            // the equation `var_side == lit_side` at depth `d + 1`
            let x = mk::var(0);
            let e = if forward { x } else { self.sym(&shift(&t_tm, 1), &shift(&lit_tm, 1), &shift(&var_tm, 1), &x) };
            // motive `y. Eq(Bool, op(.., y, ..), v2)` at depth `d + 2`
            let lit2 = shift(&lit_tm, 2);
            let prim_args = if pos == 0 { vec![mk::var(0), lit2] } else { vec![lit2, mk::var(0)] };
            let bt = self.bool_ty();
            let motive = mk::eq(shift(&bt, 2), mk::prim(op, prim_args, vec![]), mk::bool_lit(self.n.bool_ind, v2));
            let moved = Rc::new(Term::Transport {
                ty: shift(&t_tm, 1),
                lhs: shift(&var_tm, 1),
                rhs: shift(&lit_tm, 1),
                eq: e,
                motive,
                val: shift(&st.var(r.lvl), 1),
            });
            // `c` is `op(k, k)`, a closed comparison that evaluates to `!v2`
            let lit1 = shift(&lit_tm, 1);
            let c = mk::prim(op, vec![lit1.clone(), lit1], vec![]);
            let refl_c = mk::refl(shift(&bt, 1), c.clone());
            let clash = if v2 { self.bool_clash(&c, &moved, &refl_c) } else { self.bool_clash(&c, &refl_c, &moved) };
            return Ok(Some(clash));
        }
        Ok(None)
    }

    /// The operands of an ordered comparison stated as a boolean fact,
    /// `(a ⋈ b) == v` with `⋈` one of `<`, `<=`, `>`, `>=` (any width) and
    /// `v` a literal.
    fn ordered_cmp(&self, v: &V) -> Option<(V, V)> {
        let (bt, c, b) = as_eq(v)?;
        if !matches!(&**bt, Value::Ind { ind, .. } if *ind == self.n.bool_ind) || bool_lit(self.n.bool_ind, b).is_none() {
            return None;
        }
        let (op, args) = as_prim(c)?;
        match op {
            PrimOp::Lt(_) | PrimOp::Le(_) | PrimOp::Gt(_) | PrimOp::Ge(_) if args.len() == 2 => Some((args[0].clone(), args[1].clone())),
            _ => None,
        }
    }

    /// Modus ponens on an implication fact whose premise is a comparison:
    /// `h : (a ⋈ b) == v -> B` and a fact comparing the same two operands
    /// (either order, any comparison: `(a > b) == false`, a panic
    /// contract's no-panic clause, against the premise `(a <= b) == true`
    /// of a domain written `implies(a <= b, ..)`) give `B`, its premise
    /// proven by linarith, which runs only on such a pair. Without it the
    /// implication is used only by backward chaining on its conclusion as
    /// written, which an unfolded target no longer matches. `f` is the new
    /// fact: an implication (checked against every comparison fact) or a
    /// comparison (checked against every implication).
    fn implication_units(&mut self, st: &mut St, f: &Fact) -> R<()> {
        let d = st.depth();
        // an implication: its binder, its premise's operands, its conclusion
        let imp = |e: &mut Engine<'a>, g: &Fact| -> R<Option<(Rel, V, (V, V))>> {
            let Value::Pi { rel, dom, cod, .. } = &*g.ty else { return Ok(None) };
            let Some(ops) = e.ordered_cmp(dom) else { return Ok(None) };
            // (a negation `¬P` is `not_fact`'s)
            let x = e.env.fresh_var(Lvl(d), *rel, dom);
            if matches!(e.inst(cod, vec![x], d + 1)?.as_deref(), Some(Value::Ind { ind, .. }) if *ind == e.n.empty_ind) {
                return Ok(None);
            }
            Ok(Some((*rel, dom.clone(), ops)))
        };
        let facts = st.scan_facts();
        let pairs: Vec<(Fact, Fact)> = if matches!(&*f.ty, Value::Pi { .. }) {
            facts.into_iter().filter(|g| g.lvl != f.lvl && self.ordered_cmp(&g.ty).is_some()).map(|g| (f.clone(), g)).collect()
        } else if self.ordered_cmp(&f.ty).is_some() {
            facts.into_iter().filter(|g| g.lvl != f.lvl && matches!(&*g.ty, Value::Pi { .. })).map(|g| (g, f.clone())).collect()
        } else {
            return Ok(());
        };
        let mut used: Vec<u32> = Vec::new();
        for (h, c) in pairs {
            if used.contains(&h.lvl) {
                continue;
            }
            let Some((rel, dom, (a, b))) = imp(self, &h)? else { continue };
            let Some((x, y)) = self.ordered_cmp(&c.ty) else { continue };
            let same = (self.conv(d, &a, &x)? && self.conv(d, &b, &y)?) || (self.conv(d, &a, &y)? && self.conv(d, &b, &x)?);
            if !same {
                continue;
            }
            let Some(p) = self.lin_prove(st, &dom, false)? else { continue };
            let Value::Pi { cod, .. } = &*h.ty else { continue };
            let Some(concl) = self.inst(cod, vec![irr_entry(&st.venv, &p)], d)? else { continue };
            used.push(h.lvl);
            let mut known = false;
            for g in st.scan_facts() {
                if self.conv(d, &g.ty, &concl)? {
                    known = true;
                    break;
                }
            }
            if !known {
                let proof = Rc::new(Term::App { rel, fun: st.var(h.lvl), arg: p });
                st.push_fact(self.env, concl, proof, Origin::Derived("modus ponens by arithmetic"));
            }
        }
        Ok(())
    }

    fn either_units(&mut self, st: &mut St, f: &Fact) -> R<()> {
        let Some(either) = self.n.either else { return Ok(()) };
        let d = st.depth();
        let is_either = |v: &V| matches!(&**v, Value::Ind { ind, params } if *ind == either && params.len() == 2);
        let facts = st.scan_facts();
        let (ors, refs): (Vec<Fact>, Vec<Fact>) = if is_either(&f.ty) { (vec![f.clone()], facts) } else { (facts.into_iter().filter(|g| is_either(&g.ty)).collect(), vec![f.clone()]) };
        for o in &ors {
            let Value::Ind { params, .. } = &*o.ty else { continue };
            let (p, q) = (params[0].clone(), params[1].clone());
            for (k, side, other) in [(1u32, &q, &p), (0u32, &p, &q)] {
                // a proof of `Empty` from `x : side` (a term at depth `d + 1`)
                let mut refute: Option<Tm> = None;
                // a side that is a clash by itself (`false == true`, the
                // `first` of an instantiated `first || x > 0`)
                if let Some((bt, x1, y1)) = as_eq(side)
                    && matches!(&**bt, Value::Ind { ind, .. } if *ind == self.n.bool_ind)
                    && let (Some(b1), Some(b2)) = (bool_lit(self.n.bool_ind, x1), bool_lit(self.n.bool_ind, y1))
                    && b1 != b2
                {
                    let h = mk::var(0);
                    let p = if !b1 {
                        h
                    } else {
                        let bt = self.bool_ty();
                        self.sym(&bt, &mk::bool_lit(self.n.bool_ind, true), &mk::bool_lit(self.n.bool_ind, false), &h)
                    };
                    refute = Some(self.false_ne_true(p));
                }
                for r in &refs {
                    if refute.is_some() {
                        break;
                    }
                    if r.lvl == o.lvl {
                        continue;
                    }
                    if let Value::Pi { rel, dom, cod, .. } = &*r.ty
                        && self.conv(d, dom, side)?
                    {
                        let x = self.env.fresh_var(Lvl(d), *rel, dom);
                        if matches!(self.inst(cod, vec![x], d + 1)?.as_deref(), Some(Value::Ind { ind, .. }) if *ind == self.n.empty_ind) {
                            refute = Some(Rc::new(Term::App { rel: *rel, fun: shift(&st.var(r.lvl), 1), arg: mk::var(0) }));
                            break;
                        }
                    }
                    if let (Some((bt, x1, b1)), Some((_, x2, b2))) = (as_eq(side), as_eq(&r.ty))
                        && let (Some(b1), Some(b2)) = (bool_lit(self.n.bool_ind, b1), bool_lit(self.n.bool_ind, b2))
                        && b1 != b2
                        && matches!(&**bt, Value::Ind { ind, .. } if *ind == self.n.bool_ind)
                        && self.conv(d, x1, x2)?
                    {
                        let c = shift(&self.quote(st, x1), 1);
                        let hr = shift(&st.var(r.lvl), 1);
                        let (pt, pf) = if b1 { (mk::var(0), hr) } else { (hr, mk::var(0)) };
                        refute = Some(self.bool_clash(&c, &pt, &pf));
                        break;
                    }
                    // an integer equation `a == k` with a literal `k`, and the
                    // boolean fact `eq(a, k) == false` (or `ne(a, k) == true`)
                    // that a branch on `a == k` leaves: transporting the fact
                    // along the equation gives `eq(k, k) == false`, which
                    // evaluates to a clash
                    if let Some(p) = self.refute_int_eq(st, side, r)? {
                        refute = Some(p);
                        break;
                    }
                }
                let Some(empty) = refute else { continue };
                // already known?
                let mut known = false;
                for g in st.scan_facts() {
                    if self.conv(d, &g.ty, other)? {
                        known = true;
                        break;
                    }
                }
                if known {
                    break;
                }
                let (p_tm, q_tm, o_tm) = (self.quote(st, &p), self.quote(st, &q), self.quote(st, other));
                let kept = mk::var(0);
                let absurd = Rc::new(Term::Absurd { ty: shift(&o_tm, 1), proof: empty });
                let arms = if k == 1 { vec![mk::arm(&["p"], kept), mk::arm(&["q"], absurd)] } else { vec![mk::arm(&["p"], absurd), mk::arm(&["q"], kept)] };
                let proof = Rc::new(Term::Match { ind: either, params: vec![p_tm, q_tm], scrut: st.var(o.lvl), motive: shift(&o_tm, 1), arms });
                // checked in an irrelevant position (the disjunction may be
                // a derived, irrelevant fact): promoted when it is an equation
                let promoted = self.promote(st, other, proof.clone());
                let mut b = sandblaster_kernel::value::Budget { steps: self.b.steps.min(5_000_000) };
                let start = b.steps;
                let ok = self.env.check(&st.ctx, &promoted, other, &mut b).is_ok();
                self.b.steps = self.b.steps.saturating_sub(start - b.steps);
                if ok {
                    self.note("∨ fact with one side refuted");
                    st.push_fact(self.env, other.clone(), proof, Origin::Derived("∨ fact, other side refuted"));
                }
                break;
            }
        }
        Ok(())
    }

    /// `Empty` from `h : seq::eq T eq a b == false` when `a` and `b` are
    /// equal — convertible, or related by an equation fact `a = b` (`b =
    /// a`): `seq::eq_refl` says `seq::eq T eq b b == true`. Only for the
    /// element equality of machine integers (`fun u v => u == v`), whose
    /// reflexivity is `wN::eq_complete`. Spec code compares sequences with
    /// the boolean `==` while laws and facts state propositional equalities
    /// (§15 S5).
    fn seq_eq_refuted(&mut self, st: &mut St, f: &Fact, lhs: &V) -> R<Option<Tm>> {
        let Some((def, args)) = as_global_app(lhs) else { return Ok(None) };
        if self.env.global_name(def).as_deref() != Some("seq::eq") || args.len() != 4 {
            return Ok(None);
        }
        let (Arg::Rel(t), Arg::Rel(eqf), Arg::Rel(a), Arg::Rel(b)) = (&args[0], &args[1], &args[2], &args[3]) else { return Ok(None) };
        let Value::IntTy(w) = &**t else { return Ok(None) };
        let (Some(refl_g), Some(compl_g)) = (self.env.lookup_global("seq::eq_refl"), self.env.lookup_global(&format!("{}::eq_complete", sandblaster_kernel::prim::width_suffix(*w)))) else { return Ok(None) };
        let d = st.depth();
        let Some(list) = self.n.list else { return Ok(None) };
        // `e : Eq(List(T), a, b)`
        let list_ty = Rc::new(Value::Ind { ind: list, params: vec![t.clone()] });
        let e: Tm = if self.conv(d, a, b)? {
            let bt = st.quote_at(self.env, b, &list_ty);
            mk::refl(self.quote(st, &list_ty), bt)
        } else {
            let mut found = None;
            for g in st.scan_facts() {
                if let Value::Eq { lhs: x, rhs: y, .. } = &*g.ty {
                    if self.conv(d, x, a)? && self.conv(d, y, b)? {
                        found = Some(st.var(g.lvl));
                        break;
                    }
                    if self.conv(d, x, b)? && self.conv(d, y, a)? {
                        let lt = self.quote(st, &list_ty);
                        let (xt, yt) = (st.quote_at(self.env, x, &list_ty), st.quote_at(self.env, y, &list_ty));
                        found = Some(self.sym(&lt, &xt, &yt, &st.var(g.lvl)));
                        break;
                    }
                }
            }
            match found {
                Some(e) => e,
                None => return Ok(None),
            }
        };
        let (tt, eqt, at, bt, lt) = (self.quote(st, t), self.quote(st, eqf), st.quote_at(self.env, a, &list_ty), st.quote_at(self.env, b, &list_ty), self.quote(st, &list_ty));
        let bi = self.n.bool_ind;
        let seq_eq = |x: Tm, y: Tm| apps(mk::global(def), [(Rel::Rel, tt.clone()), (Rel::Rel, eqt.clone()), (Rel::Rel, x), (Rel::Rel, y)]);
        // `h' : seq::eq b b == false` (transport of `h` along `e`)
        let motive = mk::eq_bool(bi, seq_eq(mk::var(0), sandblaster_kernel::util::shift(&bt, 1)), false);
        let h2 = Rc::new(Term::Transport { ty: lt, lhs: at, rhs: bt.clone(), eq: e, motive, val: st.var(f.lvl) });
        // `seq::eq b b == true`
        let complete = mk::lam("x", Rel::Rel, tt.clone(), apps(mk::global(compl_g), [(Rel::Rel, mk::var(0)), (Rel::Rel, mk::var(0)), (Rel::Irr, mk::refl(sandblaster_kernel::util::shift(&tt, 1), mk::var(0)))]));
        let r = apps(mk::global(refl_g), [(Rel::Rel, tt.clone()), (Rel::Rel, eqt.clone()), (Rel::Rel, complete), (Rel::Rel, bt.clone())]);
        let bty = mk::bool_ty(bi);
        let sbb = seq_eq(bt.clone(), bt);
        let back = self.sym(&bty, &sbb, &mk::bool_lit(bi, false), &h2);
        let ft = self.trans(&bty, &mk::bool_lit(bi, false), &sbb, &mk::bool_lit(bi, true), &back, &r);
        let p = self.false_ne_true(ft);
        // checked here (irrelevantly, like every fact proof): a malformed
        // term only costs the branch
        let ok = self.infer_irr(st, &p)?.is_some();
        Ok(ok.then_some(p))
    }

    /// A new equation `x = C(..)` (either side) about a stuck term `x` that
    /// an older equation gives another constructor value `D(..)`: the
    /// equation `C(..) = D(..)` between the two values (`eq::trans`), whose
    /// injectivity or clash is then used like any constructor equation. The
    /// fact rewriting of [`super::rewrite`] only rewrites scrutinees, so two
    /// results of one call (`f(x) == Some(a)`, `f(x) == Some(b)`) were never
    /// related (§15 S5, QMDB). Bounded: both other sides are constructors.
    fn join_ctor_eqs(&mut self, st: &mut St, f: &Fact, a: &V, lhs: &V, rhs: &V) -> R<Option<Tm>> {
        let ctor = |v: &V| matches!(&**v, Value::Ctor { .. });
        let (key, val, key_first) = if ctor(rhs) && as_neu(lhs).is_some() {
            (lhs, rhs, true)
        } else if ctor(lhs) && as_neu(rhs).is_some() {
            (rhs, lhs, false)
        } else {
            return Ok(None);
        };
        let d = st.depth();
        let mut others: Vec<(u32, V, bool)> = Vec::new();
        for g in st.scan_facts() {
            if g.lvl == f.lvl {
                continue;
            }
            let Value::Eq { ty: t2, lhs: l2, rhs: r2 } = &*g.ty else { continue };
            if !self.conv(d, t2, a)? {
                continue;
            }
            if ctor(r2) && as_neu(l2).is_some() && self.conv(d, l2, key)? && !self.conv(d, r2, val)? {
                others.push((g.lvl, r2.clone(), true));
            } else if ctor(l2) && as_neu(r2).is_some() && self.conv(d, r2, key)? && !self.conv(d, l2, val)? {
                others.push((g.lvl, l2.clone(), false));
            }
        }
        if others.is_empty() {
            return Ok(None);
        }
        for (lvl, other, other_key_first) in others {
            // every term at the state's current depth: each round pushes the
            // joined equation (and what its saturation derives), so terms
            // quoted before the loop would point `k` binders too far out in
            // the next round (finish-B: a proof the kernel rejected, its
            // variables shifted onto the next parameters, `elems` read as
            // `sibs`)
            let at = self.quote(st, a);
            let (kt, vt) = (st.quote_at(self.env, key, a), st.quote_at(self.env, val, a));
            // `val = key`
            let p_val_key = if key_first { self.sym(&at, &kt, &vt, &st.var(f.lvl)) } else { st.var(f.lvl) };
            let ot = st.quote_at(self.env, &other, a);
            // `key = other`
            let p_key_other = if other_key_first { st.var(lvl) } else { self.sym(&at, &ot, &kt, &st.var(lvl)) };
            let p = self.trans(&at, &vt, &kt, &ot, &p_val_key, &p_key_other);
            let ty = Rc::new(Value::Eq { ty: a.clone(), lhs: val.clone(), rhs: other.clone() });
            let lvl2 = st.push_fact(self.env, ty.clone(), p, Origin::Derived("one term, two values"));
            let g = Fact { lvl: lvl2, ty: ty.clone(), origin: Origin::Derived("one term, two values") };
            if let Some(q) = self.sat_eq(st, &g, a, val, &other)? {
                return Ok(Some(q));
            }
        }
        Ok(None)
    }

    /// A boolean fact `g(.., C(..), ..) == b` about a recursive definition
    /// applied to a constructor of a recursive spec type (§15 S5,
    /// SEMANTICS.md §13.9): the kernel keeps such an application folded
    /// when its body inspects a recursive call (`agree(l1, l2) &&
    /// agree(r1, r2)`: the measure `size'` is not a literal, so the
    /// recursion is not ground), so the fact is unfolded once through the
    /// defining equation (`Delta`), which exposes the match on the
    /// recursive calls to determination. Restricted to crate inductives
    /// with recursive fields, so it never fires on sequences.
    fn unfold_recursive_fact(&mut self, st: &mut St, f: &Fact, lhs: &V, b: bool) -> R<()> {
        let Some((def, args)) = as_global_app(lhs) else { return Ok(()) };
        if !self.cfg.mode.allows_delta(def) || (self.env.global_opaque(def).unwrap_or(false) && self.cfg.mode == super::Mode::Full) {
            return Ok(());
        }
        // a crate function (a spec or exec function of the proof's crate;
        // never a prelude definition such as `seq::append`) applied to a
        // constructor of a recursive type — a tree of the crate, or a
        // sequence `Cons(head, tail)` (the facts of a `[g, rest @ ..]` case)
        let crate_fn = self.env.global_name(def).is_some_and(|n| n.starts_with("crate::"));
        let on_tree = args.iter().any(|a| match a {
            Arg::Rel(v) => matches!(&**v, Value::Ctor { ind, .. } if self.env.inductive_is_recursive(*ind) == Some(true) && (crate_fn || self.env.inductive_decl(*ind).is_some_and(|d| d.name.starts_with("crate::")))),
            Arg::Irr(_) => false,
        });
        if !on_tree {
            return Ok(());
        }
        let Some((dt, rt, l, body)) = self.delta_eq(st, lhs, def)? else { return Ok(()) };
        if matches!(as_global_app(&body), Some((g, _)) if g == def) || self.conv(st.depth(), &l, &body)? {
            return Ok(());
        }
        let bi = self.n.bool_ind;
        let bt = self.quote(st, &rt);
        let (l_tm, body_tm, bl) = (st.quote_at(self.env, &l, &rt), st.quote_at(self.env, &body, &rt), mk::bool_lit(bi, b));
        let back = self.sym(&bt, &l_tm, &body_tm, &dt);
        let p = self.trans(&bt, &body_tm, &l_tm, &bl, &back, &st.var(f.lvl));
        let ty = Rc::new(Value::Eq { ty: rt.clone(), lhs: body, rhs: self.bool_v(b) });
        st.push_fact(self.env, ty, p, Origin::Derived("unfolded recursive fact"));
        Ok(())
    }

    /// [`Engine::unfold_recursive_fact`] for an equation `g(.., C(..), ..) ==
    /// v` with a constructor value `v` (`groups(seq![g, ..rest], first) ==
    /// Some((x, r))`): the fact about the definition's body, whose matches
    /// the other facts then decide (determination, rewriting).
    fn unfold_recursive_ctor_fact(&mut self, st: &mut St, f: &Fact, a: &V, lhs: &V, rhs: &V) -> R<()> {
        let Some((def, args)) = as_global_app(lhs) else { return Ok(()) };
        if !self.cfg.mode.allows_delta(def) || self.env.global_opaque(def).unwrap_or(false) || !self.is_recursive(def) {
            return Ok(());
        }
        if !self.env.global_name(def).is_some_and(|n| n.starts_with("crate::")) {
            return Ok(());
        }
        let on_ctor = args.iter().any(|x| matches!(x, Arg::Rel(v) if matches!(&**v, Value::Ctor { ind, .. } if self.env.inductive_is_recursive(*ind) == Some(true))));
        if !on_ctor {
            return Ok(());
        }
        let Some((dt, rt, l, body)) = self.delta_eq(st, lhs, def)? else { return Ok(()) };
        if matches!(as_global_app(&body), Some((g, _)) if g == def) || self.conv(st.depth(), &l, &body)? {
            return Ok(());
        }
        let _ = a;
        let at = self.quote(st, &rt);
        let (l_tm, body_tm, v_tm) = (st.quote_at(self.env, &l, &rt), st.quote_at(self.env, &body, &rt), st.quote_at(self.env, rhs, &rt));
        if crate::elab::tm::has_erased(&body_tm) {
            return Ok(());
        }
        let back = self.sym(&at, &l_tm, &body_tm, &dt);
        let p = self.trans(&at, &body_tm, &l_tm, &v_tm, &back, &st.var(f.lvl));
        let ty = Rc::new(Value::Eq { ty: rt.clone(), lhs: body, rhs: rhs.clone() });
        st.push_fact(self.env, ty, p, Origin::Derived("unfolded recursive fact"));
        Ok(())
    }

    /// `Empty` from `e : Eq(D(ps), Cᵢ(..), Cⱼ(..))` with `i ≠ j` (`lhs` has
    /// constructor `ci`).
    #[allow(clippy::too_many_arguments)]
    pub fn ctor_clash(&mut self, st: &St, e: Tm, a: &V, lhs: &V, rhs: &V, ind: IndId, params: &[V], ci: u32) -> R<Option<Tm>> {
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(None) };
        let bi = self.n.bool_ind;
        let unit_t = mk::eq_bool(bi, mk::bool_lit(bi, true), true);
        let empty_t = mk::ind(self.n.empty_ind, vec![]);
        let arms = decl
            .ctors
            .iter()
            .enumerate()
            .map(|(k, c)| sandblaster_kernel::term::Arm {
                names: c.fields.iter().map(|x| x.0.clone()).collect(),
                body: if k as u32 == ci { unit_t.clone() } else { empty_t.clone() },
            })
            .collect();
        let p_tms: Vec<Tm> = params.iter().map(|p| shift(&self.quote(st, p), 1)).collect();
        let motive = Rc::new(Term::Match { ind, params: p_tms, scrut: mk::var(0), motive: mk::ty(), arms });
        Ok(Some(Rc::new(Term::Transport {
            ty: self.quote(st, a),
            lhs: st.quote_at(self.env, lhs, a),
            rhs: st.quote_at(self.env, rhs, a),
            eq: e,
            motive,
            val: mk::refl(mk::bool_ty(bi), mk::bool_lit(bi, true)),
        })))
    }

    /// Constructor injectivity: `aₖ = bₖ` for each relevant field whose
    /// type does not depend on earlier fields.
    #[allow(clippy::too_many_arguments)]
    fn injectivity(
        &mut self,
        st: &mut St,
        f: &Fact,
        a: &V,
        lhs: &V,
        rhs: &V,
        ind: IndId,
        params: &[V],
        ci: u32,
        a1: &[Arg],
        a2: &[Arg],
    ) -> R<()> {
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(()) };
        let c = &decl.ctors[ci as usize];
        let nf = c.fields.len() as u32;
        let penv = VEnv(Rc::new(params.iter().map(|p| EnvEntry::Rel(p.clone())).collect()));
        for (k, (_, rel, fty)) in c.fields.iter().enumerate() {
            if *rel == Rel::Irr || (0..k as u32).any(|j| occurs(fty, j)) {
                continue;
            }
            let (Some(Arg::Rel(x)), Some(Arg::Rel(y))) = (a1.get(k), a2.get(k)) else { continue };
            if self.conv(st.depth(), x, y)? {
                continue;
            }
            // Field type (non-dependent: evaluate over the parameters only;
            // shift out the field binders).
            let fty0 = shift_from(fty, -(k as i64), 0);
            let r = self.env.eval(&penv, Lvl(st.depth()), &fty0, self.b);
            let Some(tk) = self.ev_err(r)? else { continue };
            let d = st.depth();
            let tk_tm = self.quote(st, &tk);
            let x_tm = st.quote_at(self.env, x, &tk);
            let sh = (1 + nf) as i64;
            let bi = self.n.bool_ind;
            let arms = decl
                .ctors
                .iter()
                .enumerate()
                .map(|(j, cj)| sandblaster_kernel::term::Arm {
                    names: cj.fields.iter().map(|x| x.0.clone()).collect(),
                    body: if j as u32 == ci {
                        mk::eq(shift(&tk_tm, sh), shift(&x_tm, sh), mk::var(nf - 1 - k as u32))
                    } else {
                        let s = (1 + cj.fields.len()) as i64;
                        let _ = s;
                        mk::eq_bool(bi, mk::bool_lit(bi, true), true)
                    },
                })
                .collect();
            let p_tms: Vec<Tm> = params.iter().map(|p| shift(&self.quote(st, p), 1)).collect();
            let motive = Rc::new(Term::Match { ind, params: p_tms, scrut: mk::var(0), motive: mk::ty(), arms });
            let proof = Rc::new(Term::Transport {
                ty: self.quote(st, a),
                lhs: st.quote_at(self.env, lhs, a),
                rhs: st.quote_at(self.env, rhs, a),
                eq: st.var(f.lvl),
                motive,
                val: mk::refl(tk_tm.clone(), x_tm.clone()),
            });
            let _ = d;
            let fty_v = Rc::new(Value::Eq { ty: tk.clone(), lhs: x.clone(), rhs: y.clone() });
            st.push_fact(self.env, fty_v, proof, Origin::Derived("injectivity"));
        }
        Ok(())
    }

    /// `Eq(Σ, p, q)` ⇒ `Eq(A, fst p, fst q)` (and the second components if
    /// relevant and non-dependent), by `eq::cong`.
    fn pair_components(&mut self, st: &mut St, f: &Fact, a: &V, lhs: &V, rhs: &V) -> R<()> {
        let Some(cong) = self.n.eq_cong else { return Ok(()) };
        let Value::Sigma { snd_rel, fst: fa, .. } = &**a else { return Ok(()) };
        let (snd_rel, fa) = (*snd_rel, fa.clone());
        let a_tm = self.quote(st, a);
        let (l_tm, r_tm) = (st.quote_at(self.env, lhs, a), st.quote_at(self.env, rhs, a));
        let fa_tm = self.quote(st, &fa);
        // fst
        let fun = mk::lam("z", Rel::Rel, a_tm.clone(), mk::fst(mk::var(0)));
        let p = apps(
            mk::global(cong),
            [
                (Rel::Rel, a_tm.clone()),
                (Rel::Rel, fa_tm.clone()),
                (Rel::Rel, fun),
                (Rel::Rel, l_tm.clone()),
                (Rel::Rel, r_tm.clone()),
                (Rel::Rel, st.var(f.lvl)),
            ],
        );
        let fl = mk::fst(l_tm.clone());
        let fr = mk::fst(r_tm.clone());
        let ty_tm = mk::eq(fa_tm, fl, fr);
        if let Some(tyv) = self.eval(st, &ty_tm)?
            && let Some((_, x, y)) = as_eq(&tyv)
            && !self.conv(st.depth(), x, y)?
        {
            st.push_fact(self.env, tyv, p, Origin::Derived("pair component"));
        }
        // snd (relevant, non-dependent)
        if snd_rel == Rel::Rel
            && let Term::Sigma { snd, .. } = &*a_tm
            && !occurs(snd, 0)
        {
            // re-quoted at the current depth: the `fst` component above may
            // have pushed a fact (one more binder)
            let a_tm = self.quote(st, a);
            let Term::Sigma { snd, .. } = &*a_tm else { return Ok(()) };
            let sb = shift(snd, -1);
            let (l_tm, r_tm) = (st.quote_at(self.env, lhs, a), st.quote_at(self.env, rhs, a));
            let fun = mk::lam("z", Rel::Rel, a_tm.clone(), mk::snd(mk::var(0)));
            let p = apps(
                mk::global(cong),
                [
                    (Rel::Rel, a_tm.clone()),
                    (Rel::Rel, sb.clone()),
                    (Rel::Rel, fun),
                    (Rel::Rel, l_tm.clone()),
                    (Rel::Rel, r_tm.clone()),
                    (Rel::Rel, st.var(f.lvl)),
                ],
            );
            let ty_tm = mk::eq(sb, mk::snd(l_tm), mk::snd(r_tm));
            if let Some(tyv) = self.eval(st, &ty_tm)?
                && let Some((_, x, y)) = as_eq(&tyv)
                && !self.conv(st.depth(), x, y)?
            {
                st.push_fact(self.env, tyv, p, Origin::Derived("pair component"));
            }
        }
        Ok(())
    }

    /// Determination of a stuck scrutinee by a fact `Eq(Bool, S, b)` (see
    /// the module docs). May find a contradiction (no compatible arm).
    fn determine(&mut self, st: &mut St, f: &Fact, s_val: &V, b: bool) -> R<Option<Tm>> {
        if self.in_determination {
            return Ok(None);
        }
        let saved = self.in_determination;
        self.in_determination = true;
        let r = self.determine_now(st, f, s_val, b);
        self.in_determination = saved;
        r
    }

    /// [`Engine::determine`] on the matches of `s_val` on field-less
    /// values only (the innermost, then the outermost).
    fn determine_fieldless(&mut self, st: &mut St, f: &Fact, s_val: &V) -> R<Option<Tm>> {
        if self.in_determination {
            return Ok(None);
        }
        let Some(n) = as_neu(s_val) else { return Ok(None) };
        let ms: Vec<(usize, IndId, Vec<V>)> = n
            .spine
            .iter()
            .enumerate()
            .filter_map(|(i, e)| match e {
                Elim::Match { ind, params, .. } if self.fieldless(*ind) => Some((i, *ind, params.clone())),
                _ => None,
            })
            .collect();
        let mut tries = ms.first().cloned().into_iter().collect::<Vec<_>>();
        if let Some(l) = ms.last()
            && ms.len() > 1
        {
            tries.push(l.clone());
        }
        if self.trace {
            eprintln!("[auto] determination (non-path fact h{}, {:?}): {}", f.lvl, f.origin, super::search::truncate(self.show(st, &f.ty), 200));
        }
        self.in_determination = true;
        let mut out = Ok(None);
        for (i, ind, params) in tries {
            let before = st.facts.len();
            match self.determine_at(st, f, n, i, ind, params) {
                Ok(None) if st.facts.len() == before => continue,
                r => {
                    out = r;
                    break;
                }
            }
        }
        self.in_determination = false;
        out
    }

    fn determine_now(&mut self, st: &mut St, f: &Fact, s_val: &V, _b: bool) -> R<Option<Tm>> {
        let Some(n) = as_neu(s_val) else { return Ok(None) };
        let Some((i, ind, params)) = n.spine.iter().enumerate().find_map(|(i, e)| match e {
            Elim::Match { ind, params, .. } => Some((i, *ind, params.clone())),
            _ => None,
        }) else {
            return Ok(None);
        };
        self.determine_at(st, f, n, i, ind, params)
    }

    /// Whether every constructor of `ind` is field-less (`bool`, a C-like
    /// enum): a determination on it is cheap and gives an equation.
    fn fieldless(&self, ind: IndId) -> bool {
        self.env.inductive_decl(ind).is_some_and(|d| d.ctors.len() <= 8 && d.ctors.iter().all(|c| c.fields.is_empty()))
    }

    fn determine_at(&mut self, st: &mut St, f: &Fact, n: &Neutral, i: usize, ind: IndId, params: Vec<V>) -> R<Option<Tm>> {
        let sc = prefix(n, i);
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(None) };
        if decl.ctors.len() > 8 {
            return Ok(None);
        }
        let d = st.depth();
        let dty = Rc::new(Value::Ind { ind, params: params.clone() });
        let Some(mo) = self.motive(st, &f.ty, &dty, &sc)? else { return Ok(None) };
        let m = mo.body;
        let mut possible = Vec::new();
        for (k, c) in decl.ctors.iter().enumerate() {
            // Fresh (temporary) field variables above the context.
            let mut fenv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
            let mut fargs = Vec::new();
            let mut ok = true;
            for (j, (_, rel, fty)) in c.fields.iter().enumerate() {
                let r = self.env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(d + j as u32), fty, self.b);
                let Some(ftv) = self.ev_err(r)? else {
                    ok = false;
                    break;
                };
                let e = self.env.fresh_var(Lvl(d + j as u32), *rel, &ftv);
                fargs.push(entry_arg(&e));
                fenv.push(e);
            }
            if !ok {
                return Ok(None);
            }
            let cv = Rc::new(Value::Ctor { ind, ctor: k as u32, params: params.clone(), args: fargs });
            let venv = venv_push(&st.venv, EnvEntry::Rel(cv));
            let r = self.env.eval(&venv, Lvl(d + c.fields.len() as u32), &m, self.b);
            let Some(mut tk) = self.ev_err(r)? else { return Ok(None) };
            // Peel the generalized facts.
            let mut dd = d + c.fields.len() as u32;
            while let Value::Pi { rel, dom, cod, .. } = &*tk.clone() {
                let x = self.env.fresh_var(Lvl(dd), *rel, dom);
                let Some(next) = self.inst(cod, vec![x], dd + 1)? else { return Ok(None) };
                tk = next;
                dd += 1;
            }
            if !self.clashes(&tk) {
                possible.push(k);
            }
        }
        match possible.as_slice() {
            [] => {
                // Every arm contradicts the fact: split and let saturation
                // close each arm.
                self.note("determination: every arm contradicts a fact");
                let empty = Rc::new(Value::Ind { ind: self.n.empty_ind, params: vec![] });
                self.determination_split(st, &sc, ind, &params, &empty)
            }
            [k] if decl.ctors[*k].fields.is_empty() => {
                let ck = Rc::new(Value::Ctor { ind, ctor: *k as u32, params: params.clone(), args: vec![] });
                let target = Rc::new(Value::Eq { ty: dty.clone(), lhs: sc.clone(), rhs: ck });
                // Already known?
                for g in st.scan_facts() {
                    if self.conv(d, &g.ty, &target)? {
                        return Ok(None);
                    }
                }
                if let Some(p) = self.determination_split(st, &sc, ind, &params, &target)? {
                    self.note("determination of a stuck scrutinee from a fact");
                    st.push_fact(self.env, target, p, Origin::Derived("determined scrutinee"));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// The case split of a determination: each arm needs only its path
    /// equation (the determining fact, rewritten by it, clashes in every
    /// incompatible arm; the compatible arm's target holds by `refl`), so
    /// the facts still pending saturation in `st` are not saturated again
    /// in every arm — a chain `a && (b && ..)` determined conjunct by
    /// conjunct would otherwise re-saturate the rest of the branch's facts
    /// at each level.
    fn determination_split(&mut self, st: &St, sc: &V, ind: IndId, params: &[V], target: &V) -> R<Option<Tm>> {
        let pending_from = st.facts.len();
        let mut arm_fn = |e: &mut Engine<'a>, arm: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
            arm.sat = arm.sat.max(pending_from);
            let irr = !e.relevant;
            e.solve_in(arm, tk, irr)
        };
        self.case_split_with(st, sc, ind, params, target, true, 0, &mut arm_fn)
    }

    /// Is a (closed-form) proposition obviously false: a literal clash, a
    /// constructor clash, `Empty`?
    pub fn clashes(&self, t: &V) -> bool {
        match &**t {
            Value::Ind { ind, .. } => *ind == self.n.empty_ind,
            Value::Eq { lhs, rhs, .. } => match (&**lhs, &**rhs) {
                (Value::Ctor { ind: i1, ctor: c1, .. }, Value::Ctor { ind: i2, ctor: c2, .. }) => i1 == i2 && c1 != c2,
                (Value::Lit { n: x, .. }, Value::Lit { n: y, .. }) => x != y,
                _ => false,
            },
            _ => false,
        }
    }

    /// Stuck scrutinees of facts (split candidates).
    pub fn fact_scrutinees(&self, st: &St) -> Vec<(V, IndId, Vec<V>)> {
        let mut out = Vec::new();
        for f in &st.facts {
            let mut stuck = Vec::new();
            self.collect_stuck(&f.ty, &mut stuck);
            for s in stuck {
                if let StuckKind::Scrut { ind, params } = s.kind {
                    out.push((s.val, ind, params));
                }
            }
        }
        out
    }
}

/// The outcome of [`Engine::saturate_for`].
pub enum Saturated {
    /// Every fact is saturated.
    Done,
    /// A proof of `Empty` (a contradiction among the facts).
    Contradiction(Tm),
    /// The fact (by level) is the target.
    Target(u32),
}

/// Is the value a neutral whose head is an irrelevant-closure-free
/// variable?
pub fn head_var(v: &V) -> Option<u32> {
    match &**v {
        Value::Neu(Neutral { head: Head::Var(l), .. }) => Some(l.0),
        _ => None,
    }
}
