//! Term-level steps on the goal's own terms (DESIGN.md §8.1; untrusted
//! like the rest of `auto`, every step a term the kernel checks).
//!
//! `auto` reasons on values, and the evaluator unfolds every transparent
//! function: a fact `split_of(w, h) == true` whose body compares 16-byte
//! arrays eight times is, as a value, a chain of 128 element comparisons,
//! each with its index proofs; a goal equating two 64-element array
//! literals of table lookups is one of tens of thousands of nodes. Motives
//! over such values exceed the read-back bound
//! ([`super::rewrite::MAX_MOTIVE_NODES`]), so the value-level steps
//! (determination, rewriting) give up on them. The elaborator passes the
//! goal's *terms* ([`crate::elab::basic::GoalTerms`]): the statements as
//! written, the spec functions they call folded. Three steps work on those
//! terms, the first two where the value is large ([`TERM_STEP_MIN`] nodes):
//!
//! * **Conjunct facts** ([`Engine::term_conjuncts`]): a fact `P(a..) ==
//!   true` whose `P` is a transparent `bool` function whose body is a
//!   conjunction (the elaborator's `if c { rest } else { false }`) is split
//!   into its conjuncts on its term — `c == true` by a match on `c` whose
//!   `false` arm transports the fact to `false == true`, the rest by the
//!   transport to `c == true` — and a conjunct comparing two arrays of
//!   machine integers (`array::eq`) becomes the arrays' equation
//!   (`array::eq_sound_<w>`). The original fact is not saturated further.
//! * **Array literals, element by element** ([`Engine::term_array_split`]):
//!   a target `a == b` whose sides unfold (transparent functions, on the
//!   term; never an intrinsic, which the kernel unfolds only on closed
//!   arguments) to array literals of one length is the equations of their
//!   elements: each differing pair is proven on its own (a fact, a
//!   quantified fact instantiated on the terms, or the search on that
//!   element's equation), and the arrays' equation follows by list
//!   congruence (`array::ext`).
//! * **Quantified facts on the terms** ([`Engine::term_backward`]): a fact
//!   `∀x̄. H̄ → l == r` (a `using(lemma)` fact, a lemma's `forall` result)
//!   whose conclusion matches the target's term (first-order, metavariables
//!   for `x̄`, irrelevant positions ignored), its hypotheses facts on the
//!   terms (for an element of the split above, also proven by the search):
//!   an element's equation `mul_lo_byte(lut, c[0], c[32]) == ..` meets
//!   `mul_lo_byte(lut, a, b) == ..` on the terms, where the unfolded
//!   values' matching does not. Tried on the root target first (before the
//!   simplifier and saturation work on its value), cheaply: hypotheses
//!   only by facts.
//! * **Equations between applications** ([`Engine::term_rewrite`]): a fact
//!   equating two applications of transparent definitions (`row_bytes(t) ==
//!   lo_bytes(r)`, a conjunct above or a fact as stated) is no rewrite rule
//!   of the value-level steps — neither side is stuck: both unfold, to
//!   array literals of stuck bytes — so a target that writes one of them
//!   kept it, and a lemma stated over the other did not meet it. On the
//!   root target's term, an occurrence of one side is rewritten to the
//!   other when another fact names that other side and not the first
//!   (the target moves to the terms the facts are about), each equation
//!   once; the rewritten target is then closed by a fact or a quantified
//!   fact on its term, or by the search on its value (bounded).
//!
//! The proofs these steps build are checked by the kernel with the goal's
//! proof ([`super::search::prove_goal`]), not one by one: a match on the
//! terms makes an instance's conclusion the element's term up to
//! irrelevant positions, and checking each against the element's unfolded
//! value here would cost what the goal's check costs, per element.

use std::rc::Rc;

use sandblaster_kernel::term::{DefKind, Idx, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::V;

use super::search::{apply_conts, ctx_with, is_type_sort, Cont, Engine, R};
use super::state::{Origin, St};
use super::util::{shift, shift_from};

/// Values below this many nodes (read back, typed) are left to the
/// value-level steps: the term-level steps apply where those cannot build
/// their motives (the largest motive of the test suites and the verified
/// roots' builds is about 5k nodes, [`super::rewrite::MAX_MOTIVE_NODES`]).
pub const TERM_STEP_MIN: u64 = 8_000;

/// At most this many conjuncts are split off one fact.
const MAX_CONJUNCTS: usize = 256;

/// The term matcher's work limit (nodes visited) per match.
const MATCH_FUEL: u32 = 200_000;

impl Engine<'_> {
    /// The statement term of the fact at level `lvl`, at depth `d`.
    pub fn fact_term(&self, lvl: u32, d: u32) -> Option<Tm> {
        let (_, t) = self.fact_terms.iter().rev().find(|(l, _)| *l == lvl)?;
        (d >= lvl).then(|| shift(t, (d - lvl) as i64))
    }

    /// The root target's term at the state's depth, when `t` is the root
    /// target.
    fn root_term(&self, st: &St, t: &V) -> Option<Tm> {
        let (v, tm) = self.root.as_ref()?;
        if !Rc::ptr_eq(v, t) || st.depth() < self.goal_depth {
            return None;
        }
        Some(shift(tm, (st.depth() - self.goal_depth) as i64))
    }

    /// Whether a value is large: more than [`TERM_STEP_MIN`] nodes.
    fn large(&self, st: &St, v: &V) -> bool {
        super::meter::value_cost(self.env, &st.ctx, v, None, true, TERM_STEP_MIN + 1) > TERM_STEP_MIN
    }

    // ------------------------------------------------------------------
    // Conjunct facts
    // ------------------------------------------------------------------

    /// Split the goal's large `bool` facts into their conjuncts on their
    /// terms (see the module docs).
    pub fn term_conjuncts(&mut self, st: &mut St) -> R<()> {
        if self.fact_terms.is_empty() {
            return Ok(());
        }
        let goal_facts: Vec<u32> = self.fact_terms.iter().map(|(l, _)| *l).collect();
        for lvl in goal_facts {
            if self.term_split.contains(&lvl) {
                continue;
            }
            self.tick()?;
            let d = st.depth();
            let Some(ft) = self.fact_term(lvl, d) else { continue };
            let Some(fv) = st.facts.iter().find(|f| f.lvl == lvl).map(|f| f.ty.clone()) else { continue };
            let Some(chain) = self.bool_chain_fact(&ft) else { continue };
            if self.trace {
                let cost = super::meter::value_cost(self.env, &st.ctx, &fv, None, true, 10_000_000);
                eprintln!("[auto] fact h{lvl} is a conjunction on its term; its value has {cost} nodes");
            }
            if !self.large(st, &fv) {
                continue;
            }
            let n = self.split_chain(st, lvl, chain)?;
            if n > 0 {
                if self.trace {
                    eprintln!("[auto] conjuncts of fact h{lvl} on its term: {n}");
                }
                self.note("conjuncts of a fact on its term");
                self.term_split.push(lvl);
            }
        }
        Ok(())
    }

    /// `Eq(Bool, B, true)` (a term at the current depth) whose `B` is an
    /// application of a transparent definition the mode may unfold, whose
    /// body is a match on a `bool` (a conjunction): the statement with `B`
    /// unfolded (convertible with it).
    fn bool_chain_fact(&self, t: &Tm) -> Option<Tm> {
        let t = crate::elab::tm::zeta_relevant(t);
        let Term::Eq { ty, lhs, rhs } = &*t else { return None };
        let bi = self.n.bool_ind;
        if !matches!(&**ty, Term::Ind { ind, .. } if *ind == bi) || !matches!(&**rhs, Term::Ctor { ind, ctor: 1, .. } if *ind == bi) {
            return None;
        }
        let (h, _) = crate::elab::items::spine(lhs);
        let Term::Global(g) = &*h else { return None };
        if !self.cfg.mode.allows_delta(*g) {
            return None;
        }
        let body = self.unfold_head(lhs, &|x| self.bool_match_scrut(x).is_some())?;
        Some(mk::eq(ty.clone(), body, rhs.clone()))
    }

    /// The scrutinee `c` of a conjunction's term: `(match c with false =>
    /// λe. false | true => λe. rest) p` (the elaborator's `if`, its arms
    /// taking the path equation) or `match c with false => false | true =>
    /// rest`.
    fn bool_match_scrut(&self, t: &Term) -> Option<Tm> {
        let bi = self.n.bool_ind;
        let m = match t {
            Term::App { fun, .. } => &**fun,
            m => m,
        };
        let Term::Match { ind, scrut, arms, .. } = m else { return None };
        if *ind != bi || arms.len() != 2 {
            return None;
        }
        let mut f = &arms[0].body;
        if matches!(t, Term::App { .. }) {
            let Term::Lam { body, .. } = &**f else { return None };
            f = body;
        }
        matches!(&**f, Term::Ctor { ind, ctor: 0, .. } if *ind == bi).then(|| scrut.clone())
    }

    /// Push the conjuncts of the fact at level `lvl`, whose statement is
    /// `chain` (`Eq(Bool, B, true)` at the current depth, `B` a
    /// conjunction's term): for `B` a match on `c`, the fact `c == true` (a
    /// match on `c` whose `false` arm is the fact transported along its path
    /// equation to `false == true`), and the rest (the fact transported along
    /// `c == true`), a fact of its own (inert: [`Engine::term_split`]) that
    /// the next step splits — each step's proof refers to the previous fact
    /// by its variable, so the proofs stay linear in the chain. A conjunct
    /// that compares two arrays of machine integers is pushed as their
    /// equation ([`Engine::conjunct_as_equation`]). Returns the number of
    /// conjuncts pushed (0: not a conjunction).
    fn split_chain(&mut self, st: &mut St, lvl: u32, chain: Tm) -> R<usize> {
        let bi = self.n.bool_ind;
        let bool_ty = mk::ind(bi, vec![]);
        let (tt, ff) = (mk::bool_lit(bi, true), mk::bool_lit(bi, false));
        let absurd_ty = mk::eq(bool_ty.clone(), ff.clone(), tt.clone());
        let mut count = 0usize;
        // the current rest: its level and statement (at the current depth)
        let (mut cur_lvl, mut cur) = (lvl, chain);
        while count < MAX_CONJUNCTS {
            self.tick()?;
            let Term::Eq { lhs, .. } = &*cur.clone() else { break };
            let Some(c) = self.bool_match_scrut(lhs) else { break };
            // the motive `z. cur[c := z]`; its `false` instance must be
            // `false == true`
            let Some(m) = crate::elab::tm::abstract_syntactic(self.env, &cur, &c) else { break };
            let at_false = crate::elab::tm::simp_redexes(&crate::elab::tm::subst0(&m, &ff));
            if !self.env.alpha_eq_relevant(&at_false, &absurd_ty, &|a, b| a == b) {
                break;
            }
            let at_true = crate::elab::tm::simp_redexes(&crate::elab::tm::subst0(&m, &tt));
            // `c == true`: (match c as y return Π(.e : Eq(Bool, c, y)).
            // Eq(Bool, y, true) with | false => λe. transport(Bool, c,
            // false, e, z. m, h) | true => λe. refl end) .refl(Bool, c)
            let h = st.var(cur_lvl);
            let c1 = shift(&c, 1);
            let motive = mk::pi("e", Rel::Irr, mk::eq(shift(&bool_ty, 1), c1.clone(), mk::var(0)), mk::eq(shift(&bool_ty, 2), mk::var(1), shift(&tt, 2)));
            let arm = |k: bool| -> sandblaster_kernel::term::Arm {
                let lit = if k { tt.clone() } else { ff.clone() };
                let dom = mk::eq(bool_ty.clone(), c.clone(), lit);
                let body = if k {
                    mk::refl(shift(&bool_ty, 1), shift(&tt, 1))
                } else {
                    Rc::new(Term::Transport { ty: shift(&bool_ty, 1), lhs: c1.clone(), rhs: shift(&ff, 1), eq: mk::var(0), motive: shift_from(&m, 1, 1), val: shift(&h, 1) })
                };
                sandblaster_kernel::term::Arm { names: vec![], body: mk::lam("e", Rel::Irr, dom, body) }
            };
            let mt = Rc::new(Term::Match { ind: bi, params: vec![], scrut: c.clone(), motive, arms: vec![arm(false), arm(true)] });
            let pc = Rc::new(Term::App { rel: Rel::Irr, fun: mt, arg: mk::refl(bool_ty.clone(), c.clone()) });
            let c_ty = mk::eq(bool_ty.clone(), c.clone(), tt.clone());
            let Some(cv) = self.eval(st, &c_ty)? else { break };
            let at = st.depth();
            st.push_fact_tm(self.env, cv, c_ty.clone(), pc, Origin::Derived("conjunct (term)"));
            self.fact_terms.push((at, c_ty));
            count += 1;
            // an array comparison: the arrays' equation too, and the bool
            // conjunct inert
            if let Some((eq_ty, eq_p)) = self.conjunct_as_equation(&shift(&c, 1), st.var(at))
                && let Some(ev) = self.eval(st, &eq_ty)?
            {
                let at2 = st.depth();
                st.push_fact_tm(self.env, ev, eq_ty.clone(), eq_p, Origin::Derived("conjunct (term)"));
                self.fact_terms.push((at2, eq_ty));
                self.term_inert.push(at);
            }
            // the rest: `transport(Bool, c, true, c == true, z. m, h)`
            let dd = st.depth() - at;
            let (c2, m2, h2) = (shift(&c, dd as i64), shift_from(&m, dd as i64, 1), shift(&h, dd as i64));
            let rest_ty = shift(&at_true, dd as i64);
            let p = Rc::new(Term::Transport { ty: bool_ty.clone(), lhs: c2, rhs: tt.clone(), eq: st.var(at), motive: m2, val: h2 });
            let Some(rv) = self.eval(st, &rest_ty)? else { break };
            let at3 = st.depth();
            st.push_fact_tm(self.env, rv, rest_ty.clone(), p, Origin::Derived("conjunct (term)"));
            self.fact_terms.push((at3, rest_ty.clone()));
            // a rest that is a conjunction again is split next (inert
            // itself); the last one is the last conjunct
            let more = matches!(&*rest_ty, Term::Eq { lhs, .. } if self.bool_match_scrut(lhs).is_some());
            if !more {
                count += 1;
                if let Some((eq_ty, eq_p)) = self.conjunct_as_equation_eq(&shift(&rest_ty, 1), st.var(at3))
                    && let Some(ev) = self.eval(st, &eq_ty)?
                {
                    let at4 = st.depth();
                    st.push_fact_tm(self.env, ev, eq_ty.clone(), eq_p, Origin::Derived("conjunct (term)"));
                    self.fact_terms.push((at4, eq_ty));
                    self.term_inert.push(at3);
                }
                break;
            }
            self.term_inert.push(at3);
            cur_lvl = at3;
            cur = shift(&rest_ty, (st.depth() - at3) as i64);
        }
        // a rest the loop did not split after all keeps its saturation
        if cur_lvl != lvl && self.term_inert.last() == Some(&cur_lvl) && matches!(&*cur, Term::Eq { lhs, .. } if self.bool_match_scrut(lhs).is_some()) {
            self.term_inert.pop();
        }
        Ok(count)
    }

    /// A conjunct `c` = `array::eq T N (λu v. u == v) x y` over machine
    /// integers, proven by `p : c == true` (terms at the current depth): the
    /// arrays' equation `Eq(Array T N, x, y)` and its proof
    /// (`array::eq_sound_<w> N x y p`); `None` for any other conjunct.
    fn conjunct_as_equation(&self, c: &Tm, p: Tm) -> Option<(Tm, Tm)> {
        let (h, args) = crate::elab::items::spine(c);
        let Term::Global(g) = &*h else { return None };
        if self.env.global_name(*g).as_deref() != Some("array::eq") || args.len() != 5 {
            return None;
        }
        let w = prim_eq_width(&args[2])?;
        let sound = self.env.lookup_global(&format!("array::eq_sound_{}", sandblaster_kernel::prim::width_suffix(w)))?;
        let array = self.n.array?;
        let arr_ty = mk::apps(mk::global(array), [(Rel::Rel, args[0].clone()), (Rel::Rel, args[1].clone())]);
        let eq = mk::eq(arr_ty, args[3].clone(), args[4].clone());
        let pf = mk::apps(mk::global(sound), [(Rel::Rel, args[1].clone()), (Rel::Rel, args[3].clone()), (Rel::Rel, args[4].clone()), (Rel::Irr, p)]);
        Some((eq, pf))
    }

    /// [`Engine::conjunct_as_equation`] of a statement `Eq(Bool, c, true)`.
    fn conjunct_as_equation_eq(&self, ty: &Tm, p: Tm) -> Option<(Tm, Tm)> {
        let Term::Eq { lhs, rhs, .. } = &**ty else { return None };
        if !matches!(&**rhs, Term::Ctor { ind, ctor: 1, .. } if *ind == self.n.bool_ind) {
            return None;
        }
        self.conjunct_as_equation(lhs, p)
    }

    // ------------------------------------------------------------------
    // Array literals, element by element
    // ------------------------------------------------------------------

    /// Prove the root target `t` (an equation of two arrays whose sides
    /// unfold to array literals of one length, its value large) element by
    /// element (see the module docs). The proof is valid irrelevantly.
    pub fn term_array_split(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        if !self.cfg.mode.allows_splits() {
            return Ok(None);
        }
        let Some(goal) = self.root_term(st, t) else { return Ok(None) };
        let goal = crate::elab::tm::zeta_relevant(&goal);
        let Term::Eq { ty, lhs, rhs } = &*goal else { return Ok(None) };
        let (h, targs) = crate::elab::items::spine(ty);
        if !matches!(&*h, Term::Global(g) if Some(*g) == self.n.array) || targs.len() != 2 {
            return Ok(None);
        }
        let (elem_ty, len) = (targs[0].clone(), targs[1].clone());
        let (Some(la), Some(lb)) = (self.array_literal(lhs), self.array_literal(rhs)) else { return Ok(None) };
        if la.len() != lb.len() || la.len() < 2 {
            return Ok(None);
        }
        let same: Vec<bool> = la.iter().zip(&lb).map(|(a, b)| self.env.alpha_eq_relevant(a, b, &|x, y| x == y)).collect();
        if self.trace {
            let cost = super::meter::value_cost(self.env, &st.ctx, t, None, true, 10_000_000);
            eprintln!("[auto] the target is two array literals of {} elements; its value has {cost} nodes", la.len());
        }
        if same.iter().all(|s| *s) || !self.large(st, t) {
            return Ok(None);
        }
        if self.trace {
            eprintln!("[auto] array literals of {} elements, {} differing: element by element", la.len(), same.iter().filter(|s| !**s).count());
        }
        self.note("array literals, element by element");
        // on the terms first: a fact, a quantified fact
        let mut eqs: Vec<Option<Tm>> = Vec::new();
        let mut open: Vec<(usize, V)> = Vec::new();
        for i in 0..la.len() {
            if same[i] {
                eqs.push(Some(mk::refl(elem_ty.clone(), la[i].clone())));
                continue;
            }
            let eg = mk::eq(elem_ty.clone(), la[i].clone(), lb[i].clone());
            let p = match self.term_fact(st, &eg) {
                Some(p) => Some(p),
                None => self.term_backward(st, &eg, true)?,
            };
            if p.is_none() {
                let Some(ev) = self.eval(st, &eg)? else { return Ok(None) };
                open.push((i, ev));
            }
            eqs.push(p);
        }
        // then the search on each remaining element's value, in one child
        // whose facts are saturated once for all of them (each proof closed
        // by the child's derived facts, [`St::finish`])
        if !open.is_empty() {
            let mut sat = st.child();
            if let Some(c) = self.saturate(&mut sat)? {
                // contradictory facts: the target follows
                let a = self.absurd(&sat, t, c);
                return Ok(Some(sat.finish(a)));
            }
            let n = open.len() as u64;
            for (k, (i, ev)) in open.into_iter().enumerate() {
                let sref: &St = &sat;
                let p = self.bounded(n - k as u64, |e| e.solve(sref, ev, true))?;
                let Some(p) = p else {
                    if self.trace {
                        eprintln!("[auto]   element {i} not proven");
                    }
                    return Ok(None);
                };
                eqs[i] = Some(sat.finish(p));
            }
        }
        let eqs: Vec<Tm> = eqs.into_iter().map(|p| p.expect("every element proven")).collect();
        let Some(list_eq) = self.list_congruence(&elem_ty, &la, &lb, &eqs) else { return Ok(None) };
        let Some(ext) = self.env.lookup_global("array::ext") else { return Ok(None) };
        // (checked with the goal's proof, [`super::search::prove_goal`]:
        // the elements' proofs are instances whose conclusions are the
        // elements' terms, and checking each against the elements' unfolded
        // values here would cost what the goal's check costs, per element)
        Ok(Some(mk::apps(mk::global(ext), [(Rel::Rel, elem_ty), (Rel::Rel, len), (Rel::Rel, lhs.clone()), (Rel::Rel, rhs.clone()), (Rel::Irr, list_eq)])))
    }

    /// `t` unfolded at its head (transparent definitions, `let`s, redexes)
    /// until `pred` holds, as the kernel's conversion unfolds it: never
    /// through an intrinsic (a hardware model), which the kernel's evaluator
    /// unfolds only on closed arguments (DESIGN.md §5.6) — a literal reached
    /// through one on symbolic arguments is not convertible with the term.
    fn unfold_head(&self, t: &Tm, pred: &dyn Fn(&Term) -> bool) -> Option<Tm> {
        crate::elab::tm::head_unfold_if(self.env, t, pred, &|g| self.env.global_kind(g) != Some(DefKind::Intrinsic))
    }

    /// The elements of an array literal: `t` unfolded at its head
    /// ([`Engine::unfold_head`]) to `pair(Array T N, Cons(x₀, .. Nil), _)`.
    fn array_literal(&self, t: &Tm) -> Option<Vec<Tm>> {
        let list = self.n.list?;
        let lit = self.unfold_head(t, &|x| matches!(x, Term::Pair { fst, .. } if matches!(&**fst, Term::Ctor { ind, .. } if *ind == list)))?;
        let Term::Pair { fst, .. } = &*lit else { return None };
        let mut out = Vec::new();
        let mut cur = fst.clone();
        loop {
            match &*cur.clone() {
                Term::Ctor { ind, ctor: 0, .. } if *ind == list => return Some(out),
                Term::Ctor { ind, ctor: 1, args, .. } if *ind == list && args.len() == 2 => {
                    out.push(args[0].clone());
                    cur = args[1].clone();
                }
                _ => return None,
            }
        }
    }

    /// `Eq(List T, [a₀, ..], [b₀, ..])` from `eqs[i] : Eq(T, aᵢ, bᵢ)` (terms
    /// at one depth), one constructor congruence per `Cons`
    /// ([`crate::elab::tm::ctor_congruence_term`]) — under `let`s that name
    /// the tails from the last element on (`let Aᵢ = Cons(aᵢ, Aᵢ₊₁); let Bᵢ
    /// = ..; let Eᵢ : Eq(List T, Aᵢ, Bᵢ) = ..`), so each congruence's
    /// motive mentions the tails by name: the proof is linear in the
    /// number of elements, each element evaluated once by its check.
    fn list_congruence(&self, elem_ty: &Tm, la: &[Tm], lb: &[Tm], eqs: &[Tm]) -> Option<Tm> {
        let list = self.n.list?;
        let n = la.len();
        if n == 0 || lb.len() != n || eqs.len() != n {
            return None;
        }
        let list_ty = |k: u32| mk::ind(list, vec![shift(elem_ty, k as i64)]);
        let nil = |k: u32| mk::ctor(list, 0, vec![shift(elem_ty, k as i64)], vec![]);
        // the bindings, outermost first: (name, rel, type, value), each at
        // the depth of the bindings before it
        let mut binds: Vec<(&str, Rel, Tm, Tm)> = Vec::new();
        for j in 0..n {
            let i = n - 1 - j;
            let k = 3 * j as u32;
            // `Aᵢ` at depth `k`: the previous `Aᵢ₊₁` is index 2
            let (ta, tb) = if j == 0 { (nil(k), nil(k + 1)) } else { (mk::var(2), mk::var(2)) };
            let a = mk::ctor(list, 1, vec![shift(elem_ty, k as i64)], vec![shift(&la[i], k as i64), ta]);
            binds.push(("A", Rel::Rel, list_ty(k), a));
            let b = mk::ctor(list, 1, vec![shift(elem_ty, (k + 1) as i64)], vec![shift(&lb[i], (k + 1) as i64), tb]);
            binds.push(("B", Rel::Rel, list_ty(k + 1), b));
            // `Eᵢ` at depth `k + 2`: `Aᵢ` is 1, `Bᵢ` 0, `Aᵢ₊₁` 4, `Bᵢ₊₁` 3, `Eᵢ₊₁` 2
            let d2 = k + 2;
            let (ta, tb, te) = if j == 0 { (nil(d2), nil(d2), mk::refl(list_ty(d2), nil(d2))) } else { (mk::var(4), mk::var(3), mk::var(2)) };
            let e = crate::elab::tm::ctor_congruence_term(self.env, list, 1, &[shift(elem_ty, d2 as i64)], &[shift(&la[i], d2 as i64), ta], &[shift(&lb[i], d2 as i64), tb], &[], &[], &[shift(&eqs[i], d2 as i64), te])?;
            // (a relevant binding: the chain is the value of an irrelevant
            // position, where only variables bound outside it may be used
            // irrelevantly; the congruences use the element proofs only as
            // transports' equations)
            binds.push(("E", Rel::Rel, mk::eq(list_ty(d2), mk::var(1), mk::var(0)), e));
        }
        // the body: the last `E₀`
        let mut body = mk::var(0);
        for (name, rel, ty, val) in binds.into_iter().rev() {
            body = mk::let_(name, rel, ty, val, body);
        }
        Some(body)
    }

    // ------------------------------------------------------------------
    // Equations between applications
    // ------------------------------------------------------------------

    /// The equation the fact at level `lvl` states on its term, when both
    /// sides are applications of transparent definitions (`f(a..)`, the
    /// head a global the evaluator unfolds: neither recursive nor opaque,
    /// nor an intrinsic): `Eq(A, l, r)` as stated, or a comparison of
    /// arrays of machine integers `array::eq(.., l, r) == true` as the
    /// arrays' equation (`array::eq_sound_<w>`). `(A, l, r, its proof)`,
    /// terms at the state's depth.
    fn term_equation(&self, st: &St, lvl: u32) -> Option<(Tm, Tm, Tm, Tm)> {
        let ft = crate::elab::tm::zeta_relevant(&self.fact_term(lvl, st.depth())?);
        let (eq, p) = self.conjunct_as_equation_eq(&ft, st.var(lvl)).unwrap_or((ft, st.var(lvl)));
        let Term::Eq { ty, lhs, rhs } = &*eq else { return None };
        let transparent_app = |t: &Tm| {
            let (h, args) = crate::elab::items::spine(t);
            matches!(&*h, Term::Global(g) if !args.is_empty() && !self.is_unfoldable_head(*g, args.len()) && self.env.global_kind(*g) != Some(DefKind::Intrinsic) && self.env.global_arity(*g) == Some(args.len() as u32))
        };
        (transparent_app(lhs) && transparent_app(rhs)).then(|| (ty.clone(), lhs.clone(), rhs.clone(), p))
    }

    /// Whether a fact other than the one at `lvl` (and not an inert one)
    /// names `to` on its term and not `from`.
    fn names_apart(&self, st: &St, lvl: u32, to: &Tm, from: &Tm) -> bool {
        let d = st.depth();
        self.fact_terms.iter().any(|(l, _)| {
            *l != lvl
                && !self.term_inert.contains(l)
                && self.fact_term(*l, d).is_some_and(|ft| crate::elab::tm::abstract_syntactic(self.env, &ft, to).is_some() && crate::elab::tm::abstract_syntactic(self.env, &ft, from).is_none())
        })
    }

    /// Prove the root target `t` by rewriting its term with the equations
    /// between applications of [`Engine::term_equation`] (see the module
    /// docs): an occurrence of one side (`from`) is rewritten to the other
    /// (`to`) when another fact names `to` and not `from`
    /// ([`Engine::names_apart`]), `to` does not contain `from`, and the
    /// motive is well typed; each equation once, until none applies. The
    /// rewritten target is closed by a fact or a quantified fact on its
    /// term, else by the search on its value (half the budget left). The
    /// proof is valid irrelevantly.
    pub fn term_rewrite(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        if !self.cfg.mode.allows_splits() || self.fact_terms.is_empty() {
            return Ok(None);
        }
        let Some(goal) = self.root_term(st, t) else { return Ok(None) };
        let d = st.depth();
        let mut cur = goal;
        let mut conts: Vec<Cont> = Vec::new();
        let mut used: Vec<u32> = Vec::new();
        let lvls: Vec<u32> = self.fact_terms.iter().rev().map(|(l, _)| *l).collect();
        loop {
            let mut moved = false;
            for &lvl in &lvls {
                if used.contains(&lvl) || self.term_inert.contains(&lvl) {
                    continue;
                }
                self.tick()?;
                let Some((a, l, r, p)) = self.term_equation(st, lvl) else { continue };
                for (from, to, rev) in [(&l, &r, false), (&r, &l, true)] {
                    let Some(m) = crate::elab::tm::abstract_syntactic(self.env, &cur, from) else { continue };
                    if crate::elab::tm::abstract_syntactic(self.env, to, from).is_some() || !self.names_apart(st, lvl, to, from) {
                        continue;
                    }
                    let Some(av) = self.eval(st, &a)? else { continue };
                    let cy = ctx_with(&st.ctx, &av);
                    self.settle();
                    let sort = self.env.infer(&cy, &m, self.b);
                    if !matches!(self.k_err(sort)?, Some(s) if is_type_sort(&s)) {
                        continue;
                    }
                    if self.trace {
                        eprintln!("[auto] the target's term rewritten with the equation of fact h{lvl}{}", if rev { ", reversed" } else { "" });
                    }
                    // `Eq(A, to, from)`
                    let e = if rev { p.clone() } else { self.sym(&a, &l, &r, &p) };
                    conts.push(Cont { depth: d, ty: a.clone(), lhs: to.clone(), rhs: from.clone(), eq: e, motive: m.clone(), pre: vec![] });
                    cur = crate::elab::tm::simp_redexes(&crate::elab::tm::subst0(&m, to));
                    used.push(lvl);
                    moved = true;
                    break;
                }
            }
            if !moved {
                break;
            }
        }
        if conts.is_empty() {
            return Ok(None);
        }
        self.note("equations between applications on the target's term");
        let p = match self.term_fact(st, &cur) {
            Some(p) => Some(p),
            None => match self.term_backward(st, &cur, false)? {
                Some(p) => Some(p),
                None => {
                    let Some(tv) = self.eval(st, &cur)? else { return Ok(None) };
                    let mut c = st.child();
                    let r = self.bounded(2, |e| e.atomic(&mut c, tv))?;
                    r.map(|p| c.finish(p))
                }
            },
        };
        Ok(p.map(|p| apply_conts(&conts, d, p)))
    }

    /// A fact whose statement term is `eg` (α-equivalent, irrelevant
    /// positions ignored), or `eg` mirrored (then `sym`).
    fn term_fact(&self, st: &St, eg: &Tm) -> Option<Tm> {
        let d = st.depth();
        let Term::Eq { ty, lhs, rhs } = &**eg else { return None };
        let mirror = mk::eq(ty.clone(), rhs.clone(), lhs.clone());
        for (l, _) in self.fact_terms.iter().rev() {
            let Some(ft) = self.fact_term(*l, d) else { continue };
            if self.env.alpha_eq_relevant(&ft, eg, &|a, b| a == b) {
                return Some(st.var(*l));
            }
            if self.env.alpha_eq_relevant(&ft, &mirror, &|a, b| a == b) {
                return Some(self.sym(ty, rhs, lhs, &st.var(*l)));
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Quantified facts on the terms
    // ------------------------------------------------------------------

    /// Close `eg` (an equation's term at the state's depth) with a
    /// quantified fact whose conclusion matches it on the terms (see the
    /// module docs): the instance's conclusion is `eg` up to irrelevant
    /// positions, so its proof is checked with the goal's (not here, where
    /// the values may be large). Its hypotheses are facts (on the terms), or
    /// with `search`, proven by the search. The proof is valid irrelevantly.
    pub fn term_backward(&mut self, st: &St, eg: &Tm, search: bool) -> R<Option<Tm>> {
        if !self.cfg.mode.allows_forall_facts() || self.rule_depth >= 2 {
            return Ok(None);
        }
        let d = st.depth();
        let Term::Eq { ty: ety, lhs: el, rhs: er } = &**eg else { return Ok(None) };
        let mirror = mk::eq(ety.clone(), er.clone(), el.clone());
        let lvls: Vec<u32> = self.fact_terms.iter().rev().map(|(l, _)| *l).collect();
        for lvl in lvls {
            self.tick()?;
            let Some(ft) = self.fact_term(lvl, d) else { continue };
            // the telescope `Π(x̄). concl`
            let mut binders: Vec<(Rel, Tm)> = Vec::new();
            let mut cur = ft.clone();
            while let Term::Pi { rel, dom, cod, .. } = &*cur.clone() {
                binders.push((*rel, dom.clone()));
                cur = cod.clone();
            }
            if binders.is_empty() || !matches!(&*cur, Term::Eq { .. }) {
                continue;
            }
            let n = binders.len() as u32;
            for (target, mirrored) in [(eg, false), (&mirror, true)] {
                let mut sub: Vec<Option<Tm>> = vec![None; n as usize];
                let mut fuel = MATCH_FUEL;
                if !tmatch(self.env, &cur, target, 0, n, &mut sub, &mut fuel) {
                    continue;
                }
                if self.trace {
                    eprintln!("[auto] quantified fact h{lvl} matches the target's term{}", if mirrored { " (mirrored)" } else { "" });
                }
                // the arguments: matched data, proven hypotheses (a fact
                // whose statement is the hypothesis, else the search)
                let mut args: Vec<(Rel, Tm)> = Vec::new();
                let mut ok = true;
                for (j, (rel, dom)) in binders.iter().enumerate() {
                    if let Some(a) = &sub[j] {
                        args.push((*rel, a.clone()));
                        continue;
                    }
                    let vals: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
                    let hyp = crate::elab::tm::subst_n(dom, &vals);
                    let p = match self.term_fact(st, &hyp) {
                        Some(p) => Some(p),
                        None if !search => None,
                        None => {
                            let Some(hv) = self.eval(st, &hyp)? else {
                                ok = false;
                                break;
                            };
                            if !self.is_prop(&hv, d) {
                                ok = false;
                                break;
                            }
                            self.rule_depth += 1;
                            let r = self.bounded(4, |e| e.solve(st, hv, true));
                            self.rule_depth -= 1;
                            r?
                        }
                    };
                    let Some(p) = p else {
                        ok = false;
                        break;
                    };
                    args.push((*rel, p));
                }
                if !ok {
                    continue;
                }
                let p = mk::apps(st.var(lvl), args.clone());
                // (the target mirrored: `sym` of the instance)
                let p = if mirrored {
                    let vals: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
                    let concl = crate::elab::tm::subst_n(&cur, &vals);
                    let Term::Eq { ty, lhs, rhs } = &*concl else { continue };
                    self.sym(ty, lhs, rhs, &p)
                } else {
                    p
                };
                self.note(format!("quantified fact h{lvl} on the terms"));
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

}

/// The width of an element equality `λu v. #eq_w(u, v)` (the elaborator's
/// `==` on machine integers).
fn prim_eq_width(t: &Tm) -> Option<Width> {
    let Term::Lam { body, .. } = &**t else { return None };
    let Term::Lam { body, .. } = &**body else { return None };
    let Term::Prim { op: sandblaster_kernel::term::PrimOp::Eq(w), args, .. } = &**body else { return None };
    (args.len() == 2 && matches!(&*args[0], Term::Var(Idx(1))) && matches!(&*args[1], Term::Var(Idx(0))) && *w != Width::Int).then_some(*w)
}

/// Whether `t` (at depth `D + k`) mentions a variable bound inside it:
/// an index below `k`.
fn mentions_below(t: &Tm, k: u32) -> bool {
    crate::elab::tm::any_node_depth(t, &mut |n, dd| matches!(n, Term::Var(Idx(i)) if *i >= dd && *i < dd + k))
}

/// Whether `t` (at depth `k` below the pattern's `n` metavariables)
/// mentions a metavariable: an index in `k..k + n`.
fn mentions_meta(t: &Tm, k: u32, n: u32) -> bool {
    crate::elab::tm::any_node_depth(t, &mut |x, dd| matches!(x, Term::Var(Idx(i)) if *i >= dd + k && *i < dd + k + n))
}

/// First-order matching of `pat` (a term at depth `D + n + k`, its free
/// indices `k..k+n` the metavariables, binder `n - 1 - (i - k)` of the
/// telescope for index `i`) against `t` (a term at depth `D + k`): binds
/// `sub[m]` (a term at depth `D`). Irrelevant positions are not compared
/// (as [`sandblaster_kernel::api::Env::alpha_eq_relevant`]); nothing is
/// unfolded.
fn tmatch(env: &sandblaster_kernel::api::Env, pat: &Tm, t: &Tm, k: u32, n: u32, sub: &mut [Option<Tm>], fuel: &mut u32) -> bool {
    if *fuel == 0 {
        return false;
    }
    *fuel -= 1;
    // a subterm without metavariables: α-equivalence after lowering
    if !mentions_meta(pat, k, n) {
        let lowered = sandblaster_kernel::util::shift_from(pat, -(n as i64), k);
        return env.alpha_eq_relevant(&lowered, t, &|a, b| a == b);
    }
    use Term::*;
    match (&**pat, &**t) {
        (Var(Idx(i)), _) if *i >= k && *i < k + n => {
            let m = (n - 1 - (*i - k)) as usize;
            if mentions_below(t, k) {
                return false;
            }
            let v = sandblaster_kernel::util::shift(t, -(k as i64));
            match &sub[m] {
                None => {
                    sub[m] = Some(v);
                    true
                }
                Some(b) => env.alpha_eq_relevant(b, &v, &|a, c| a == c),
            }
        }
        (App { rel: r1, fun: f1, arg: a1 }, App { rel: r2, fun: f2, arg: a2 }) => r1 == r2 && tmatch(env, f1, f2, k, n, sub, fuel) && (*r1 == Rel::Irr || tmatch(env, a1, a2, k, n, sub, fuel)),
        (Pi { rel: r1, dom: d1, cod: c1, .. }, Pi { rel: r2, dom: d2, cod: c2, .. }) | (Lam { rel: r1, dom: d1, body: c1, .. }, Lam { rel: r2, dom: d2, body: c2, .. }) => {
            r1 == r2 && tmatch(env, d1, d2, k, n, sub, fuel) && tmatch(env, c1, c2, k + 1, n, sub, fuel)
        }
        (Let { rel: r1, ty: t1, val: v1, body: b1, .. }, Let { rel: r2, ty: t2, val: v2, body: b2, .. }) => {
            r1 == r2 && tmatch(env, t1, t2, k, n, sub, fuel) && (*r1 == Rel::Irr || tmatch(env, v1, v2, k, n, sub, fuel)) && tmatch(env, b1, b2, k + 1, n, sub, fuel)
        }
        (Sigma { snd_rel: r1, fst: f1, snd: s1, .. }, Sigma { snd_rel: r2, fst: f2, snd: s2, .. }) => r1 == r2 && tmatch(env, f1, f2, k, n, sub, fuel) && tmatch(env, s1, s2, k + 1, n, sub, fuel),
        (Pair { fst: f1, .. }, Pair { fst: f2, .. }) => tmatch(env, f1, f2, k, n, sub, fuel),
        (Fst(p), Fst(q)) | (Snd(p), Snd(q)) => tmatch(env, p, q, k, n, sub, fuel),
        (Eq { ty: t1, lhs: l1, rhs: r1 }, Eq { ty: t2, lhs: l2, rhs: r2 }) => tmatch(env, t1, t2, k, n, sub, fuel) && tmatch(env, l1, l2, k, n, sub, fuel) && tmatch(env, r1, r2, k, n, sub, fuel),
        (Ind { ind: i1, params: p1 }, Ind { ind: i2, params: p2 }) => i1 == i2 && p1.len() == p2.len() && p1.iter().zip(p2).all(|(a, b)| tmatch(env, a, b, k, n, sub, fuel)),
        (Ctor { ind: i1, ctor: c1, params: p1, args: a1 }, Ctor { ind: i2, ctor: c2, params: p2, args: a2 }) => {
            i1 == i2 && c1 == c2 && p1.len() == p2.len() && a1.len() == a2.len() && p1.iter().zip(p2).all(|(a, b)| tmatch(env, a, b, k, n, sub, fuel)) && a1.iter().zip(a2).all(|(a, b)| tmatch(env, a, b, k, n, sub, fuel))
        }
        (Match { ind: i1, params: p1, scrut: s1, motive: m1, arms: a1 }, Match { ind: i2, params: p2, scrut: s2, motive: m2, arms: a2 }) => {
            i1 == i2
                && p1.len() == p2.len()
                && a1.len() == a2.len()
                && p1.iter().zip(p2).all(|(a, b)| tmatch(env, a, b, k, n, sub, fuel))
                && tmatch(env, s1, s2, k, n, sub, fuel)
                && tmatch(env, m1, m2, k + 1, n, sub, fuel)
                && a1.iter().zip(a2).all(|(x, y)| x.names.len() == y.names.len() && tmatch(env, &x.body, &y.body, k + x.names.len() as u32, n, sub, fuel))
        }
        (Prim { op: o1, args: a1, proofs: q1 }, Prim { op: o2, args: a2, proofs: q2 }) => o1 == o2 && q1.len() == q2.len() && a1.len() == a2.len() && a1.iter().zip(a2).all(|(a, b)| tmatch(env, a, b, k, n, sub, fuel)),
        _ => false,
    }
}
