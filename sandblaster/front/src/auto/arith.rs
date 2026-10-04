//! Linear arithmetic (DESIGN.md §5.8; §8.1 steps 7 and 13).
//!
//! `lin_prove` collects the arithmetic facts of the state (the §5.8
//! hypothesis forms: `Eq(Bool, cmp(a, b), true|false)` except the
//! disjunctive `eq … false` / `ne … true`, and `Eq(IntTy, a, b)`), asks the
//! kernel for the canonical linear system (`Env::linearize`, so both sides
//! agree on atoms and constraint order), and searches a certificate with the
//! simplex ([`super::simplex`]). If there is none, the system's **atoms**
//! drive an enrichment round (step 7):
//!
//! * atoms headed by `min`, `max`, `sat_sub`, `sat_add`, `int_to_sat` get
//!   their piecewise defining axiom when the condition is decidable by a
//!   nested linarith call (otherwise the condition is reported as a case-split
//!   candidate, [`Engine::atom_split_candidates`]);
//! * `and`, `or`, `xor`, `wshr`/`shr` by a non-literal amount and `rem` by
//!   a non-literal divisor get their unconditional axioms (`and_le_*`,
//!   `or_ge_*`, `or_le_add`, `xor_le_or`, `shr_le`, `rem_lt`); literal
//!   masks, shifts, divisions and truncating casts are already linearized
//!   definitionally by the kernel; a complement `!x` gets its value
//!   `MAX − x` (`bits::not_val_<w>`);
//! * `count_ones`, `leading_zeros` and `trailing_zeros` get the bound
//!   lemmas of `lemmas/bits.core` (`bits::count_ones_le_<w>`,
//!   `bits::{leading,trailing}_zeros_le_<w>`, and the strict `_lt_<w>` when
//!   `a ≠ 0` is decidable) — checked lemmas derived from the kernel's K1
//!   definitions, which replaced the phase-3 bound axioms;
//! * wrapping `wadd`, `wsub`, `wmul` by a literal and `wshl` by a literal
//!   whose exact result is provably in range get the exactness lemmas
//!   (`bits::w{add,sub,mul}_exact_<w>`, `bits::wshl_exact_<w>_<k>` when
//!   loaded): the wrapping operation equals the checked one, which the
//!   kernel linearizes without a carry atom;
//! * `fst s` of a slice gets `slice::ok_bound` (`≤ ISIZE_MAX`), and
//!   `seq::len` of a slice's or array's list gets `slice::ok_len` /
//!   `array::ok_len` (the link between list length and `usize` length);
//! * `T::size'` of a recursive spec type gets `T::size'_pos` (`1 ≤ size'`,
//!   `elab::recursive`), and the ghost `Nat` functions their bounds
//!   (`lemmas/nat.core`: `pow2 ≥ 1`, `log2 ≥ 0`, `0 ≤ popcount(x) ≤ x`,
//!   `pow2(log2 x) ≤ x < 2·pow2(log2 x)`);
//! * registered linarith lemmas (length lemmas, method facts) are instantiated
//!   by matching their trigger against atoms ([`super::ematch`]).
//!
//! A successful certificate is pruned: hypotheses with a zero multiplier are
//! dropped and the (smaller) system is solved again, so proof terms stay
//! small.
//!
//! **Integer cuts** (optimizer design §7.5). linarith is rational: a bit
//! atom `(x >> k) & 1` may take the value `1/2`, a quotient `t >> j` may lie
//! strictly between two integers. When the enriched system still has no
//! certificate, [`Engine::lin_cut`] reads a rational point of the failing
//! problem off the simplex ([`super::simplex::farkas_staged_point`]), picks
//! an atom with a fractional value `v`, and splits on `lt(atom, ⌈v⌉)` (a
//! dependent `Bool` match): one arm gets `atom ≤ ⌈v⌉ − 1`, the other
//! `atom ≥ ⌈v⌉`, and each is closed by its own certificate (recursively,
//! up to [`AutoConfig::int_cuts`](super::AutoConfig) nested cuts).
//! Quotient and remainder atoms of the kernel's linearization are split
//! through the word operation they come from (`wshr`/`and` by powers of
//! two, `div`/`rem` by other literals), so the cut constrains the same atom;
//! a ghost `Int` division of a cast, which the kernel linearizes into its
//! own pair with the same printed atom, is cut as the `Int` atom itself when
//! it occurs in the goal or a hypothesis, and a division by a literal
//! `k ≤ 0` is an ordinary atom ([`Engine::cut_terms`]).
//! Disequality facts (`ne … true`, `eq … false`), which linarith rejects,
//! are split on demand the same way (`a < b`, `b < a`, and `a = b` refuted
//! by the fact) — see [`Engine::lin_diseq_cut`].

use std::rc::Rc;

use num_bigint::BigInt;
use sandblaster_kernel::axioms::{self, Schema};
use sandblaster_kernel::linarith::{ConstraintOrigin, LinSystem};
use sandblaster_kernel::term::{PrimOp, Rat, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Elim, EnvEntry, Head, Neutral, V, VEnv, Value};

use super::search::{Engine, R};
use super::simplex;
use super::state::St;
use super::util::*;

/// The bit-level primitive subterms nested under the arguments of `t`
/// (`|`, `&`, `^`, shifts, casts, wrapping arithmetic), innermost first,
/// without `t` itself; at most `cap` of them.
fn nested_bit_prims(t: &Tm, out: &mut Vec<Tm>, cap: usize) {
    use PrimOp::*;
    fn go(t: &Tm, out: &mut Vec<Tm>, cap: usize, top: bool) {
        if out.len() >= cap {
            return;
        }
        let Term::Prim { op, args, .. } = &**t else { return };
        // (saturating operations and min/max are descended through: their
        // enrichment needs their operands' exactness, plan O6)
        if !matches!(op, Or(_) | And(_) | Xor(_) | Shl(_) | WShl(_) | Shr(_) | WShr(_) | Cast { .. } | WAdd(_) | WSub(_) | WMul(_) | Add(_) | Mul(_) | SatSub(_) | SatAdd(_) | Min(_) | Max(_)) {
            return;
        }
        for a in args {
            go(a, out, cap, false);
        }
        if !top && !out.iter().any(|x| Rc::ptr_eq(x, t)) {
            out.push(t.clone());
        }
    }
    go(t, out, cap, true);
}

thread_local! {
    /// Inside [`Engine::lin_equiv`]: equivalences are not split again in its
    /// arms (kept out of `Engine`, whose fields belong to `auto::search`).
    static IN_LIN_EQUIV: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A linarith hypothesis: proof term and stated proposition (both at the
/// state's depth).
pub type Hyp = (Tm, Tm);

/// Integer cuts are not tried on systems with more atoms (each cut solves
/// the system again per arm).
const CUT_MAX_ATOMS: usize = 200;

impl<'a> Engine<'a> {
    /// Is `t` a linarith goal form (§5.8 item 2)? Also a boolean
    /// equivalence of two comparisons (`Eq(Bool, c1, c2)`), proved by a
    /// split on `c1` ([`Self::lin_equiv`]).
    pub fn lin_goal_form(&self, t: &V) -> bool {
        if self.lin_equiv_sides(t).is_some() {
            return true;
        }
        match &**t {
            Value::Ind { ind, .. } => *ind == self.n.empty_ind,
            Value::Eq { ty, lhs, rhs } => match &**ty {
                Value::IntTy(_) => true,
                Value::Ind { ind, .. } if *ind == self.n.bool_ind => {
                    bool_lit(self.n.bool_ind, rhs).is_some() && as_prim(lhs).is_some_and(|(op, _)| cmp_width(op).is_some())
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// `Eq(Bool, c1, c2)` for two comparisons (neither a literal): the two
    /// sides of a boolean equivalence (pe P3/C3: `(b >> s) & 1 != 0` against
    /// `(b / pow2(s)) % 2 == 1`).
    pub fn lin_equiv_sides(&self, t: &V) -> Option<(V, V)> {
        let Value::Eq { ty, lhs, rhs } = &**t else { return None };
        if !matches!(&**ty, Value::Ind { ind, .. } if *ind == self.n.bool_ind) {
            return None;
        }
        let cmp = |v: &V| as_prim(v).is_some_and(|(op, _)| cmp_width(op).is_some());
        (cmp(lhs) && cmp(rhs)).then(|| (lhs.clone(), rhs.clone()))
    }

    /// A boolean equivalence `c1 == c2` of comparisons, by a split on `c1`.
    /// Where `c1` holds, `c2 == true` by linarith (with enrichment). Where
    /// it fails, a split on `c2`: if `c2` held, `c1 == true` would follow by
    /// linarith, contradicting the arm. Every linarith call therefore has a
    /// positive fact (`c == true`), never a disequality (which linarith
    /// cannot use directly).
    fn lin_equiv(&mut self, st: &St, goal: &V, c1: &V) -> R<Option<Tm>> {
        if IN_LIN_EQUIV.with(|c| c.replace(true)) {
            return Ok(None);
        }
        let r = self.lin_equiv_in(st, goal, c1);
        IN_LIN_EQUIV.with(|c| c.set(false));
        let p = r?;
        if p.is_some() {
            self.note("boolean equivalence of comparisons (split on both sides)");
        }
        Ok(p)
    }

    fn lin_equiv_in(&mut self, st: &St, goal: &V, c1: &V) -> R<Option<Tm>> {
        let bi = self.n.bool_ind;
        let d0 = st.depth();
        let c1_tm = self.quote(st, c1);
        // `c == b` is a linarith hypothesis (not a disjunction `≠`)
        let usable = |c: &V, b: bool| match as_prim(c) {
            Some((PrimOp::Eq(_), _)) => b,
            Some((PrimOp::Ne(_), _)) => !b,
            _ => true,
        };
        let c1v0 = c1.clone();
        let mut arm_fn = |e: &mut Engine<'a>, arm: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
            let Some((ty, l, r)) = as_eq(&tk).map(|(a, b, c)| (a.clone(), b.clone(), c.clone())) else { return Ok(None) };
            // `c1` was on either side: `(v1, c2)` and whether the goal is `v1 == c2`
            let (v1, c2, lit_left) = match (bool_lit(e.n.bool_ind, &l), bool_lit(e.n.bool_ind, &r)) {
                (Some(v), None) => (v, r.clone(), true),
                (None, Some(v)) => (v, l.clone(), false),
                _ => return Ok(None),
            };
            let bt = e.bool_ty();
            let lit = |v: bool| mk::bool_lit(bi, v);
            if usable(&c1v0, v1) {
                // `c1 == v1` is a fact here: prove `c2 == v1` (turned around if needed)
                let want: V = Rc::new(Value::Eq { ty: ty.clone(), lhs: c2.clone(), rhs: if lit_left { l.clone() } else { r.clone() } });
                if !e.lin_goal_form(&want) {
                    return Ok(None);
                }
                let Some(p) = e.lin_prove(arm, &want, true)? else { return Ok(None) };
                let p = e.promote(arm, &want, p);
                return Ok(Some(if lit_left { e.sym(&bt, &arm.quote_at(e.env, &c2, &ty), &lit(v1), &p) } else { p }));
            }
            // `c1 == v1` is a disequality: split on `c2`; where `c2` is the
            // other value, `c1` would be too (by linarith from `c2`)
            let Some(neg) = arm.facts.last().cloned() else { return Ok(None) };
            let k1 = (arm.depth() - d0) as i64;
            let c1_arm = shift(&c1_tm, k1);
            let d1 = arm.depth();
            let mut inner = |e: &mut Engine<'a>, arm2: &mut St, tk2: V, _k: u32| -> R<Option<Tm>> {
                let Some((ty2, l2, r2)) = as_eq(&tk2).map(|(a, b, c)| (a.clone(), b.clone(), c.clone())) else { return Ok(None) };
                if e.conv(arm2.depth(), &l2, &r2)? {
                    return Ok(Some(mk::refl(e.quote(arm2, &ty2), arm2.quote_at(e.env, &l2, &ty2))));
                }
                let (Some(x), Some(y)) = (bool_lit(e.n.bool_ind, &l2), bool_lit(e.n.bool_ind, &r2)) else { return Ok(None) };
                let v2 = if lit_left { y } else { x };
                if v2 == v1 {
                    return Ok(None);
                }
                // (a disequality fact `c2 == v2` is split on demand by the cuts)
                let k2 = (arm2.depth() - d1) as i64;
                let c1t = shift(&c1_arm, k2);
                let Some(c1_val) = e.eval(arm2, &c1t)? else { return Ok(None) };
                let want: V = Rc::new(Value::Eq { ty: ty2.clone(), lhs: c1_val, rhs: Rc::new(Value::Ctor { ind: bi, ctor: v2 as u32, params: vec![], args: vec![] }) });
                if !e.lin_goal_form(&want) {
                    return Ok(None);
                }
                let Some(p) = e.lin_prove(arm2, &want, true)? else { return Ok(None) };
                let p = e.promote(arm2, &want, p);
                // `v1 == v2`: `v1 = c1` (the outer arm), `c1 = v2` (no `absurd`:
                // a linarith proof may carry erased proofs, which it rejects)
                let bt = e.bool_ty();
                let negp = e.promote(arm2, &neg.ty, arm2.var(neg.lvl));
                let s = e.sym(&bt, &c1t, &lit(v1), &negp);
                let e12 = e.trans(&bt, &lit(v1), &c1t, &lit(v2), &s, &p);
                Ok(Some(if lit_left { e12 } else { e.sym(&bt, &lit(v1), &lit(v2), &e12) }))
            };
            let depth_left = arm.depth_left;
            e.case_split_with(arm, &c2, e.n.bool_ind, &[], &tk, true, depth_left, &mut inner)
        };
        let depth_left = st.depth_left;
        self.case_split_with(st, c1, bi, &[], goal, true, depth_left, &mut arm_fn)
    }

    /// Is `t` a (non-trivial, non-disjunctive) linarith hypothesis form?
    pub fn lin_hyp_form(&self, t: &V) -> bool {
        match &**t {
            Value::Eq { ty, lhs, rhs } => match &**ty {
                Value::IntTy(_) => true,
                Value::Ind { ind, .. } if *ind == self.n.bool_ind => {
                    let Some(b) = bool_lit(self.n.bool_ind, rhs) else { return false };
                    match as_prim(lhs) {
                        Some((PrimOp::Eq(_), _)) => b,
                        Some((PrimOp::Ne(_), _)) => !b,
                        Some((op, _)) => cmp_width(op).is_some(),
                        None => false,
                    }
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// The arithmetic facts of the state as linarith hypotheses.
    pub fn lin_hyps(&mut self, st: &St) -> Vec<Hyp> {
        let mut out = Vec::new();
        for f in &st.facts {
            if self.lin_hyp_form(&f.ty) {
                out.push((st.var(f.lvl), self.quote(st, &f.ty)));
            }
        }
        out
    }

    /// [`Self::lin_prove`] (enriched) of several goals over the same facts
    /// and atoms — a probe deciding a comparison both ways,
    /// `Eq(Bool, c, true)` and `Eq(Bool, c, false)`
    /// ([`Engine::decide_bool`]): the enrichment rounds are shared (they
    /// depend on the facts and the atoms only, the same for every goal) and
    /// each round tries every goal's certificate, then the integer cuts try
    /// the goals in order. `Some((i, proof))` for the first goal `i` found.
    /// Goals that are not plain linarith forms (or sides of an
    /// equivalence) are proved one by one by [`Self::lin_prove`].
    pub fn lin_prove_any(&mut self, st: &St, goals: &[V]) -> R<Option<(usize, Tm)>> {
        if goals.iter().any(|g| !self.lin_goal_form(g) || self.lin_equiv_sides(g).is_some()) {
            for (i, g) in goals.iter().enumerate() {
                if let Some(p) = self.lin_prove(st, g, true)? {
                    return Ok(Some((i, p)));
                }
            }
            return Ok(None);
        }
        let goal_tms: Vec<Tm> = goals.iter().map(|g| self.quote(st, g)).collect();
        let mut live = vec![true; goals.len()];
        let mut hyps = self.lin_hyps(st);
        let rounds = self.cfg.lin_rounds;
        let mut seen: Vec<Tm> = Vec::new();
        let skip = std::mem::replace(&mut self.lin_skip_rounds, 0);
        // the goals' atoms (one comparison's, whichever its value)
        let mut goal_atoms: Vec<Tm> = Vec::new();
        for t in &goal_tms {
            for a in self.linearize(st, &[], t)?.map(|s| s.atoms).unwrap_or_default() {
                if !goal_atoms.iter().any(|b| self.env.alpha_eq_relevant(&a, b, &|x, y| x == y)) {
                    goal_atoms.push(a);
                }
            }
        }
        for round in 0..rounds {
            // the first live goal's system and feasible points feed the
            // enrichment (the atoms are the same for all)
            let mut base: Option<(LinSystem, Option<Vec<Vec<Option<super::rat::Q>>>>)> = None;
            for i in 0..goals.len() {
                if !live[i] {
                    continue;
                }
                let Some(sys) = self.linearize(st, &hyps, &goal_tms[i])? else {
                    // (as in `lin_prove`: a goal that does not linearize fails)
                    live[i] = false;
                    continue;
                };
                let mut points: Option<Vec<Vec<Option<super::rat::Q>>>> = None;
                let cert = if round < skip && round + 1 < rounds { None } else { certificate_or_point(&sys).map_err(|p| points = Some(p.into_iter().collect())).ok() };
                if let Some(cert) = cert {
                    self.lin_round = Some(round);
                    let t = goal_tms[i].clone();
                    return Ok(Some((i, self.lin_term(st, hyps, t, &sys, cert)?)));
                }
                if self.trace {
                    eprintln!("[auto] linarith failed (round {round}, {} hyps, {} atoms): {}", hyps.len(), sys.atoms.len(), self.show(st, &goals[i]));
                }
                if base.is_none() {
                    base = Some((sys, points));
                }
            }
            let Some((sys, points)) = base else { return Ok(None) };
            if round + 1 == rounds {
                break;
            }
            let before = hyps.len();
            let atoms = self.enrich_atoms(st, &sys, &mut hyps, &mut seen)?;
            self.enrich_pairs(st, &sys, points.as_deref(), &goal_atoms, &atoms, &mut hyps, &mut seen, None)?;
            if hyps.len() == before {
                break;
            }
        }
        if self.cfg.int_cuts > 0 && !self.lin_no_cuts {
            for i in 0..goals.len() {
                if !live[i] {
                    continue;
                }
                if let Some(p) = self.lin_cut(st, &goals[i], &hyps, self.cfg.int_cuts)? {
                    self.lin_round = Some(u32::MAX);
                    return Ok(Some((i, p)));
                }
            }
        }
        Ok(None)
    }

    /// Prove an arithmetic goal (a §5.8 goal form) by linarith over the
    /// state's facts, with enrichment rounds if `enrich`.
    pub fn lin_prove(&mut self, st: &St, goal: &V, enrich: bool) -> R<Option<Tm>> {
        if !self.lin_goal_form(goal) {
            return Ok(None);
        }
        if let Some((c1, c2)) = self.lin_equiv_sides(goal) {
            if !enrich {
                return Ok(None);
            }
            // split on a side whose term carries no erased proof (a checked
            // word operation read back from its value does): the refutation
            // names it in relevant positions
            let (a, b) = (self.quote(st, &c1), self.quote(st, &c2));
            let first = if crate::elab::tm::has_erased(&a) && !crate::elab::tm::has_erased(&b) { c2 } else { c1 };
            let _ = (a, b);
            return self.lin_equiv(st, goal, &first);
        }
        let goal_tm = self.quote(st, goal);
        let mut hyps = self.lin_hyps(st);
        let rounds = if enrich { self.cfg.lin_rounds } else { 1 };
        let mut seen: Vec<Tm> = Vec::new();
        // (this call's own: a nested call, e.g. from the enrichment, starts
        // from round 0)
        let skip = std::mem::replace(&mut self.lin_skip_rounds, 0);
        // the goal's own atoms (the pairwise enrichments look at those only)
        let goal_atoms = match enrich {
            true => self.linearize(st, &[], &goal_tm)?.map(|s| s.atoms).unwrap_or_default(),
            false => Vec::new(),
        };
        // the last failed search over the current `hyps`: its system and the
        // point the integer cuts start from (`certificate_or_point`'s
        // failure is the first infeasible problem's point, as `lin_cut`
        // computes it)
        let mut last: Option<(usize, LinSystem, Option<Vec<Option<super::rat::Q>>>)> = None;
        // a failed per-atom search whose hypotheses the pairwise enrichment
        // left unchanged: the next round's system is that same system
        let mut carried: Option<(LinSystem, Option<Vec<Option<super::rat::Q>>>)> = None;
        for round in 0..rounds {
            let mut points: Option<Vec<Vec<Option<super::rat::Q>>>> = None;
            let (sys, cert) = match carried.take() {
                // (the same system fails the same way: no second search)
                Some((sys, pt)) => {
                    points = Some(pt.clone().into_iter().collect());
                    last = Some((hyps.len(), sys.clone(), pt));
                    (sys, None)
                }
                None => {
                    let Some(sys) = self.linearize(st, &hyps, &goal_tm)? else { return Ok(None) };
                    // (a round the caller knows fails for this class: no
                    // search; a failed search leaves its feasible points to
                    // the enrichment)
                    let cert = if round < skip && round + 1 < rounds {
                        None
                    } else {
                        match certificate_or_point(&sys) {
                            Ok(c) => Some(c),
                            Err(p) => {
                                last = Some((hyps.len(), sys.clone(), p.clone()));
                                points = Some(p.into_iter().collect());
                                None
                            }
                        }
                    };
                    (sys, cert)
                }
            };
            if let Some(cert) = cert {
                self.lin_round = Some(round);
                return Ok(Some(self.lin_term(st, hyps, goal_tm, &sys, cert)?));
            }
            if self.trace {
                eprintln!(
                    "[auto] linarith failed (round {round}, {} hyps, {} atoms): {}",
                    hyps.len(),
                    sys.atoms.len(),
                    self.show(st, goal)
                );
            }
            if round + 1 == rounds {
                break;
            }
            let before = hyps.len();
            let atoms = self.enrich_atoms(st, &sys, &mut hyps, &mut seen)?;
            // The per-atom facts alone first: the pairwise enrichments prove
            // side conditions by linarith over every hypothesis, per
            // candidate, which costs far more than one more certificate
            // search; they run only when the cheap facts do not close the
            // goal. (As a round: skipped below `skip`, reported as the next
            // round; its linear system is a subsystem of the next round's.)
            // Not in a probe, whose usual outcome is failure
            // ([`Engine::lin_probe`]): there the extra search is pure cost.
            let mut atoms_failed: Option<(usize, LinSystem, Option<Vec<Option<super::rat::Q>>>)> = None;
            if hyps.len() > before && round + 1 >= skip && !self.lin_probe {
                if let Some(sys1) = self.linearize(st, &hyps, &goal_tm)? {
                    match certificate_or_point(&sys1) {
                        Ok(cert) => {
                            self.lin_round = Some(round + 1);
                            return Ok(Some(self.lin_term(st, hyps, goal_tm, &sys1, cert)?));
                        }
                        Err(p) => atoms_failed = Some((hyps.len(), sys1, p)),
                    }
                }
            }
            let model = atoms_failed.as_ref().and_then(|(n, s1, p)| p.as_ref().map(|p| (*n, s1, p.as_slice())));
            self.enrich_pairs(st, &sys, points.as_deref(), &goal_atoms, &atoms, &mut hyps, &mut seen, model)?;
            if let Some((n, sys1, p)) = atoms_failed
                && n == hyps.len()
            {
                last = Some((n, sys1.clone(), p.clone()));
                carried = Some((sys1, p));
            }
            if hyps.len() == before {
                break;
            }
        }
        if enrich && self.cfg.int_cuts > 0 && !self.lin_no_cuts {
            let r = match last {
                // the cuts start from the last failed search of these very
                // hypotheses (its system and point), not from a new one
                Some((n, sys, point)) if n == hyps.len() => self.lin_cut_from(st, goal, goal_tm, &hyps, self.cfg.int_cuts, sys, point),
                _ => self.lin_cut(st, goal, &hyps, self.cfg.int_cuts),
            };
            if matches!(r, Ok(Some(_))) {
                self.lin_round = Some(u32::MAX);
            }
            return r;
        }
        Ok(None)
    }

    /// Integer cuts and on-demand disequality splits (see the module docs):
    /// prove `goal` from `hyps` (terms at `st`'s depth) with at most `depth`
    /// nested splits. The result is an (irrelevant) proof at `st`'s depth.
    pub fn lin_cut(&mut self, st: &St, goal: &V, hyps: &[Hyp], depth: u32) -> R<Option<Tm>> {
        if depth == 0 {
            return Ok(None);
        }
        let goal_tm = self.quote(st, goal);
        let Some(sys) = self.linearize(st, hyps, &goal_tm)? else { return Ok(None) };
        if sys.atoms.len() > CUT_MAX_ATOMS {
            return Ok(None);
        }
        let mut point = None;
        for p in &sys.problems {
            match simplex::farkas_staged_point(p, sys.atoms.len()) {
                Ok(_) => continue,
                Err(Some(pt)) => {
                    point = Some(pt);
                    break;
                }
                Err(None) => return Ok(None),
            }
        }
        let Some(point) = point else {
            // every problem has a certificate after all
            let Some(cert) = simplex::certificate(&sys) else { return Ok(None) };
            return Ok(Some(self.lin_term(st, hyps.to_vec(), goal_tm, &sys, cert)?));
        };
        self.lin_cut_at(st, goal, &goal_tm, hyps, depth, &sys, point)
    }

    /// [`Self::lin_cut`] from a search of `hyps` that already failed:
    /// `sys` is their system and `point` the first infeasible problem's
    /// point (`None`: no point, as `lin_cut` gives up then), the same
    /// [`simplex::farkas_staged_point`] search `lin_cut` would run again.
    #[allow(clippy::too_many_arguments)]
    fn lin_cut_from(&mut self, st: &St, goal: &V, goal_tm: Tm, hyps: &[Hyp], depth: u32, sys: LinSystem, point: Option<Vec<Option<super::rat::Q>>>) -> R<Option<Tm>> {
        if depth == 0 || sys.atoms.len() > CUT_MAX_ATOMS {
            return Ok(None);
        }
        let Some(point) = point else { return Ok(None) };
        self.lin_cut_at(st, goal, &goal_tm, hyps, depth, &sys, point)
    }

    /// The cuts of [`Self::lin_cut`] at the infeasible `point` of `sys`.
    #[allow(clippy::too_many_arguments)]
    fn lin_cut_at(&mut self, st: &St, goal: &V, goal_tm: &Tm, hyps: &[Hyp], depth: u32, sys: &LinSystem, point: Vec<Option<super::rat::Q>>) -> R<Option<Tm>> {
        let goal_tm = goal_tm.clone();
        // Disequality facts first: they are the usual reason (`h < 2 ∧ h ≠ 0 ⊢ h = 1`).
        if let Some(p) = self.lin_diseq_cut(st, goal, hyps, depth)? {
            return Ok(Some(p));
        }
        // Candidates: atoms with a fractional value, smallest range first (a
        // bit `x & 1` before a quotient `x >> j` before a plain word).
        let mut cands: Vec<(BigInt, Width, Tm, BigInt)> = Vec::new();
        for (i, v) in point.iter().enumerate() {
            let Some(v) = v else { continue };
            if v.den() == BigInt::from(1) {
                continue;
            }
            // ⌈v⌉ = ⌊v⌋ + 1 (v is not an integer; the denominator is positive)
            let (q, r) = (v.num() / v.den(), v.num() % v.den());
            let c = if r < BigInt::from(0) { q } else { q + 1 };
            for (w, t, range) in self.cut_terms(st, &sys.atoms[i], hyps, &goal_tm)? {
                if w != Width::Int && (c < BigInt::from(0) || c > sandblaster_kernel::prim::max_of(w)) {
                    continue;
                }
                if cands.iter().any(|(_, _, t2, c2)| c2 == &c && self.env.alpha_eq_relevant(t2, &t, &|x, y| x == y)) {
                    continue;
                }
                cands.push((range, w, t, c.clone()));
            }
        }
        cands.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, w, t, c) in cands.into_iter().take(self.cfg.cut_width as usize) {
            let cond = sandblaster_kernel::prim::prim0(PrimOp::Lt(w), vec![t, mk::lit(w, c)]);
            let Some(cv) = self.eval(st, &cond)? else { continue };
            if bool_lit(self.n.bool_ind, &cv).is_some() {
                continue;
            }
            self.note(format!("integer cut on `{}`", self.show(st, &cv)));
            if let Some(p) = self.lin_split(st, &cv, goal, hyps, depth)? {
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

    /// Split on the boolean `c` and prove `goal` in each arm from `hyps` plus
    /// the arm's path equation (by a certificate, else by further cuts).
    pub fn lin_split(&mut self, st: &St, c: &V, goal: &V, hyps: &[Hyp], depth: u32) -> R<Option<Tm>> {
        let bi = self.n.bool_ind;
        let d0 = st.depth();
        let hyps = hyps.to_vec();
        let mut arm_fn = |e: &mut Engine<'a>, arm: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
            let k = (arm.depth() - d0) as i64;
            let mut hs: Vec<Hyp> = hyps.iter().map(|(p, s)| (shift(p, k), shift(s, k))).collect();
            if let Some(f) = arm.facts.last().cloned() {
                let stated = e.quote(arm, &f.ty);
                hs.push((arm.var(f.lvl), stated));
            }
            let p = match e.lin_with(arm, &hs, &tk)? {
                Some(p) => Some(p),
                None => e.lin_cut(arm, &tk, &hs, depth - 1)?,
            };
            Ok(p.map(|p| e.promote(arm, &tk, p)))
        };
        let depth_left = st.depth_left;
        self.case_split_with(st, c, bi, &[], goal, true, depth_left, &mut arm_fn)
    }

    /// The terms to split on for an atom of a linear system, most likely
    /// first: machine and `Int` atoms themselves; the kernel's quotient /
    /// remainder atoms `idiv/imod(to_int a, k)` (`k > 0`) through the word
    /// operation on `a` whose linearization they are (`wshr`/`and` for
    /// `k = 2^j`, checked `div`/`rem` otherwise), so a cut constrains the
    /// same atom. The kernel keeps a separate pair for a ghost `Int`
    /// division of the same value (`idiv(cast a, k)` written in the goal or
    /// a hypothesis), which quotes to the same term: when the atom occurs
    /// literally in `hyps` or `goal`, the atom itself (an `Int` cut) comes
    /// first, and it is the only term when no word operation has that
    /// divisor (`k` beyond the word's range). A division by a literal
    /// `k ≤ 0` is a plain `Int` atom of the kernel (no pair) and is cut as
    /// itself. Carry atoms are not split (their `idiv` term is a different
    /// atom).
    fn cut_terms(&mut self, st: &St, atom: &Tm, hyps: &[Hyp], goal: &Tm) -> R<Vec<(Width, Tm, BigInt)>> {
        use PrimOp::*;
        let wide = || BigInt::from(1) << 128u32;
        if let Term::Prim { op: op @ (IDiv | IMod), args, .. } = &**atom
            && args.len() == 2
            && let Term::Lit { n: k, .. } = &*args[1]
        {
            if let Term::Prim { op: Cast { from, to: Width::Int }, args: inner, .. } = &*args[0]
                && from.bits().is_some()
            {
                let zero = BigInt::from(0);
                if k <= &zero {
                    // not a quotient/remainder pair of the kernel: a plain atom
                    return Ok(vec![(Width::Int, atom.clone(), wide())]);
                }
                let w = *from;
                let a = inner[0].clone();
                let one = BigInt::from(1);
                let j = (k.bits() - 1) as u32;
                let pow2 = (k & (k - &one)) == zero;
                let range = match op {
                    IDiv => (sandblaster_kernel::prim::max_of(w) + 1u8) / k,
                    _ => k.clone(),
                };
                let word = if pow2 && j < w.bits().unwrap_or(0) {
                    Some(match op {
                        IDiv => (w, sandblaster_kernel::prim::prim0(WShr(w), vec![a, mk::lit(Width::U32, j)]), range.clone()),
                        _ => (w, sandblaster_kernel::prim::prim0(And(w), vec![a, mk::lit(w, k - &one)]), range.clone()),
                    })
                } else if k <= &sandblaster_kernel::prim::max_of(w) {
                    let bt = mk::bool_ty(self.n.bool_ind);
                    let nz = mk::refl(bt, mk::bool_lit(self.n.bool_ind, true));
                    let op = if matches!(op, IDiv) { Div(w) } else { Rem(w) };
                    Some((w, mk::prim(op, vec![a, mk::lit(w, k.clone())], vec![nz]), range.clone()))
                } else {
                    None
                };
                let int_cut = (Width::Int, atom.clone(), range);
                return Ok(match word {
                    // no word operation divides by `k`: only a ghost `Int`
                    // division has this atom
                    None => vec![int_cut],
                    Some(word) if self.occurs_literally(atom, hyps, goal) => vec![int_cut, word],
                    Some(word) => vec![word],
                });
            }
            // an `Int` division: the atom is its own term — unless it is a
            // carry (a sum/difference/product of casts)
            if matches!(&*args[0], Term::Prim { op: IAdd | ISub | IMul, .. }) {
                return Ok(vec![]);
            }
            let range = if matches!(op, IMod) && k != &BigInt::from(0) { k.magnitude().clone().into() } else { wide() };
            return Ok(vec![(Width::Int, atom.clone(), range)]);
        }
        if matches!(&**atom, Term::Prim { op: INeg, .. }) {
            return Ok(vec![]);
        }
        let Some(ty) = self.infer_irr(st, atom)? else { return Ok(vec![]) };
        match &*ty {
            Value::IntTy(w) => {
                Ok(vec![(*w, atom.clone(), if *w == Width::Int { wide() } else { sandblaster_kernel::prim::max_of(*w) + 1u8 })])
            }
            _ => Ok(vec![]),
        }
    }

    /// Does the (quotient/remainder) atom occur as a subterm of a stated
    /// hypothesis or of the goal, outside binders?
    fn occurs_literally(&self, atom: &Tm, hyps: &[Hyp], goal: &Tm) -> bool {
        let env = &self.env;
        let mut found = false;
        for t in hyps.iter().map(|(_, stated)| stated).chain([goal]) {
            map_term(t, 0, &mut |s, k| {
                if found {
                    return Some(s.clone());
                }
                if k == 0 && matches!(&**s, Term::Prim { op: PrimOp::IDiv | PrimOp::IMod, .. }) && env.alpha_eq_relevant(s, atom, &|x, y| x == y) {
                    found = true;
                    return Some(s.clone());
                }
                None
            });
            if found {
                return true;
            }
        }
        false
    }

    /// Linarith with exactly these hypotheses (no enrichment).
    pub fn lin_with(&mut self, st: &St, hyps: &[Hyp], goal: &V) -> R<Option<Tm>> {
        if !self.lin_goal_form(goal) || self.lin_equiv_sides(goal).is_some() {
            return Ok(None);
        }
        let goal_tm = self.quote(st, goal);
        let Some(sys) = self.linearize(st, hyps, &goal_tm)? else { return Ok(None) };
        match simplex::certificate(&sys) {
            Some(cert) => Ok(Some(self.lin_term(st, hyps.to_vec(), goal_tm, &sys, cert)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn linearize(&mut self, st: &St, hyps: &[Hyp], goal: &Tm) -> R<Option<LinSystem>> {
        // every linarith use goes through here ([`super::AutoConfig::arith`])
        if !self.cfg.arith {
            return Ok(None);
        }
        let r = self.env.linearize(&st.ctx, hyps, goal, self.b);
        self.k_err(r)
    }

    /// Fill the `Erased` proof slots of checked word operations in a quoted
    /// statement (a value read back loses them: `x >> s` whose `s < w` proof
    /// was irrelevant), outside binders, by linarith over `hyps`; the kernel
    /// re-checks statements, so a `Linarith` term must not carry `Erased`.
    /// Slots that cannot be re-proved stay (the kernel then rejects the
    /// proof, as before).
    pub(crate) fn refill_erased(&mut self, st: &St, t: &Tm, hyps: &[Hyp]) -> R<Tm> {
        if !crate::elab::tm::has_erased(t) {
            return Ok(t.clone());
        }
        // obligations are proved from the statements without placeholders
        let clean: Vec<Hyp> = hyps.iter().filter(|(_, s)| !crate::elab::tm::has_erased(s)).cloned().collect();
        let hyps = &clean[..];
        let mut cur = t.clone();
        for _ in 0..16 {
            // an innermost operation with an erased slot and clean arguments
            let mut target: Option<Tm> = None;
            map_term(&cur, 0, &mut |x, k| {
                if target.is_some() {
                    return Some(x.clone());
                }
                if let Term::Prim { proofs, args, .. } = &**x
                    && k == 0
                    && proofs.iter().any(crate::elab::tm::has_erased)
                    && !args.iter().any(crate::elab::tm::has_erased)
                {
                    target = Some(x.clone());
                    return Some(x.clone());
                }
                None
            });
            // … or an irrelevant argument slot of an application (the
            // `requires` proof of an exec call read back from a value): its
            // proposition is the function's Π domain
            if target.is_none() {
                let mut app: Option<Tm> = None;
                map_term(&cur, 0, &mut |x, k| {
                    if app.is_some() {
                        return Some(x.clone());
                    }
                    if let Term::App { rel: Rel::Irr, fun, arg } = &**x
                        && k == 0
                        && crate::elab::tm::has_erased(arg)
                        && !crate::elab::tm::has_erased(fun)
                    {
                        app = Some(x.clone());
                        return Some(x.clone());
                    }
                    None
                });
                if let Some(ap) = app {
                    let Term::App { fun, .. } = &*ap else { break };
                    let slot = self.env.infer(&st.ctx, fun, self.b).ok();
                    let q = match slot.as_deref() {
                        Some(Value::Pi { rel: Rel::Irr, dom, .. }) => match as_eq(dom) {
                            Some((_, l, r)) if self.conv(st.depth(), l, r)? => Some(mk::refl(mk::bool_ty(self.n.bool_ind), mk::bool_lit(self.n.bool_ind, true))),
                            _ => self.lin_with(st, hyps, dom)?,
                        },
                        _ => None,
                    };
                    let Some(q) = q else { return Ok(cur) };
                    let rep: Tm = Rc::new(Term::App { rel: Rel::Irr, fun: fun.clone(), arg: q });
                    cur = map_term(&cur, 0, &mut |x, _| Rc::ptr_eq(x, &ap).then(|| rep.clone()));
                    continue;
                }
            }
            let Some(tg) = target else { break };
            let Term::Prim { op, args, proofs } = &*tg else { break };
            let obligations = sandblaster_kernel::prim::prim_obligations(*op, args, self.n.bool_ind);
            let mut fresh = Vec::with_capacity(proofs.len());
            for (i, p) in proofs.iter().enumerate() {
                if !crate::elab::tm::has_erased(p) {
                    fresh.push(p.clone());
                    continue;
                }
                let Some(ob) = obligations.get(i) else { return Ok(cur) };
                let Some(obv) = self.eval(st, ob)? else { return Ok(cur) };
                let q = match as_eq(&obv) {
                    Some((_, l, r)) if self.conv(st.depth(), l, r)? => Some(mk::refl(mk::bool_ty(self.n.bool_ind), mk::bool_lit(self.n.bool_ind, true))),
                    _ => self.lin_with(st, hyps, &obv)?,
                };
                let Some(q) = q else { return Ok(cur) };
                fresh.push(q);
            }
            let rep: Tm = Rc::new(Term::Prim { op: *op, args: args.clone(), proofs: fresh });
            cur = map_term(&cur, 0, &mut |x, _| Rc::ptr_eq(x, &tg).then(|| rep.clone()));
        }
        Ok(cur)
    }

    /// Build the `Linarith` term, pruning unused hypotheses.
    fn lin_term(&mut self, st: &St, hyps: Vec<Hyp>, goal: Tm, sys: &LinSystem, cert: Vec<Rat>) -> R<Tm> {
        // statements read back from values may have lost proof slots
        let goal = self.refill_erased(st, &goal, &hyps)?;
        let mut hyps = hyps;
        for i in 0..hyps.len() {
            if crate::elab::tm::has_erased(&hyps[i].1) {
                let stated = hyps[i].1.clone();
                hyps[i].1 = self.refill_erased(st, &stated, &hyps)?;
            }
        }
        // Which hypotheses have a nonzero multiplier in some problem?
        let mut used = vec![false; hyps.len()];
        let mut off = 0;
        for p in &sys.problems {
            for (c, m) in p.iter().zip(&cert[off..off + p.len()]) {
                if let ConstraintOrigin::Hyp(i) = c.origin
                    && m.num != BigInt::from(0)
                {
                    used[i] = true;
                }
            }
            off += p.len();
        }
        if used.iter().all(|u| *u) {
            return Ok(Rc::new(Term::Linarith { hyps, goal, cert }));
        }
        let small: Vec<Hyp> = hyps.iter().zip(&used).filter(|(_, u)| **u).map(|(h, _)| h.clone()).collect();
        let small_to_orig: Vec<usize> = used.iter().enumerate().filter(|(_, u)| **u).map(|(i, _)| i).collect();
        if let Some(sys2) = self.linearize(st, &small, &goal)? {
            // the certificate carried over (its used constraints are in the
            // smaller system too), checked exactly; else searched again
            if let Some(cert2) = self.carry_certificate(sys, &cert, &sys2, &small_to_orig) {
                return Ok(Rc::new(Term::Linarith { hyps: small, goal, cert: cert2 }));
            }
            if let Some(cert2) = simplex::certificate(&sys2) {
                return Ok(Rc::new(Term::Linarith { hyps: small, goal, cert: cert2 }));
            }
        }
        Ok(Rc::new(Term::Linarith { hyps, goal, cert }))
    }

    /// The certificate `cert` of `sys` for `sys2`, the linearization of a
    /// subset of its hypotheses (`small_to_orig`: their indices in `sys`):
    /// every constraint with a nonzero multiplier is found in `sys2` (same
    /// kind, constant and coefficients over the same atom terms, a
    /// hypothesis' constraint from the same hypothesis) and takes its
    /// multiplier there; `None` unless the result is a certificate of every
    /// problem of `sys2` ([`simplex::verify`], the kernel's condition).
    fn carry_certificate(&self, sys: &LinSystem, cert: &[Rat], sys2: &LinSystem, small_to_orig: &[usize]) -> Option<Vec<Rat>> {
        use sandblaster_kernel::linarith::Constraint;
        if sys.problems.len() != sys2.problems.len() {
            return None;
        }
        // atoms of `sys2` → atoms of `sys` (the same canonical terms)
        let mut amap: Vec<Option<usize>> = Vec::with_capacity(sys2.atoms.len());
        for a2 in &sys2.atoms {
            amap.push(sys.atoms.iter().position(|a| Rc::ptr_eq(a, a2) || self.env.alpha_eq_relevant(a, a2, &|x, y| x == y)));
        }
        let same = |c: &Constraint, c2: &Constraint| -> bool {
            if c.kind != c2.kind || c.constant != c2.constant || c.coeffs.len() != c2.coeffs.len() {
                return false;
            }
            let origin_ok = match (&c.origin, &c2.origin) {
                (ConstraintOrigin::Hyp(i), ConstraintOrigin::Hyp(k)) => small_to_orig.get(*k) == Some(i),
                (ConstraintOrigin::Hyp(_), _) | (_, ConstraintOrigin::Hyp(_)) => false,
                _ => true,
            };
            origin_ok && c2.coeffs.iter().all(|(a2, k2)| amap.get(*a2).copied().flatten().is_some_and(|a| c.coeffs.iter().any(|(x, k)| *x == a && k == k2)))
        };
        let mut out: Vec<Rat> = Vec::new();
        let mut off = 0;
        for (p, p2) in sys.problems.iter().zip(&sys2.problems) {
            let mut c2m: Vec<super::rat::Q> = vec![super::rat::Q::zero(); p2.len()];
            let mut taken = vec![false; p2.len()];
            for (c, m) in p.iter().zip(cert.get(off..off + p.len())?) {
                if m.num == BigInt::from(0) {
                    continue;
                }
                let j = (0..p2.len()).find(|&j| !taken[j] && same(c, &p2[j]))?;
                taken[j] = true;
                c2m[j] = super::rat::Q::new(m.num.clone(), m.den.clone());
            }
            if !simplex::verify(p2, &c2m) {
                return None;
            }
            out.extend(c2m.iter().map(super::rat::Q::to_rat));
            off += p.len();
        }
        Some(out)
    }

    /// The per-atom part of an enrichment round: axiom instances, type
    /// bounds and lemma instances for the atoms of `sys` (see the module
    /// docs). Returns the atoms looked at, for [`Self::enrich_pairs`].
    fn enrich_atoms(&mut self, st: &St, sys: &LinSystem, hyps: &mut Vec<Hyp>, seen: &mut Vec<Tm>) -> R<Vec<Tm>> {
        let mut atoms = sys.atoms.clone();
        // the atoms of disequality facts (`a ≠ b`, not linarith hypotheses,
        // split on demand by the cuts) are enriched too, so the cut arms have
        // their facts (pe P3/C3: `(b >> s) & 1 ≠ 0` against `x / pow2(s)`)
        self.diseq_atoms(st, hyps, &mut atoms)?;
        if self.cfg.deep_enrich {
            // the nested bit-level subterms, innermost first, then the atoms
            let mut nested: Vec<Tm> = Vec::new();
            for a in &atoms {
                nested_bit_prims(a, &mut nested, 512);
            }
            nested.extend(atoms);
            atoms = nested;
        }
        // the lengths of nested concatenations: `len(a ++ (b ++ c))` gets
        // `len a + len(b ++ c)` from its rule, and `len(b ++ c)` in the same
        // round (a chain of `k` parts needs no `k` rounds)
        let mut nested_lens: Vec<Tm> = Vec::new();
        for a in &atoms {
            self.len_append_parts(a, &mut nested_lens, 0);
        }
        for t in nested_lens {
            if !atoms.iter().any(|a| self.env.alpha_eq_relevant(a, &t, &|x, y| x == y)) {
                atoms.push(t);
            }
        }
        for a in &atoms {
            if seen.iter().any(|s| self.env.alpha_eq_relevant(s, a, &|x, y| x == y)) {
                continue;
            }
            seen.push(a.clone());
            if let Term::Prim { op, args, proofs } = &**a {
                self.enrich_prim(st, *op, args, proofs, hyps)?;
                self.enrich_divmod_link(st, *op, args, hyps)?;
            }
            let Some(av) = self.eval(st, a)? else { continue };
            self.enrich_bounds(st, a, &av, &atoms, hyps)?;
            self.enrich_rules(st, &av, hyps)?;
        }
        Ok(atoms)
    }

    /// The pairwise part of an enrichment round, after [`Self::enrich_atoms`]
    /// (`atoms`: the atoms it looked at). `model`: a failed search over the
    /// first `n` of `hyps` — its system and the rational point it ends at, a
    /// model of those hypotheses (and of the implicit bounds of the atoms it
    /// assigns).
    #[allow(clippy::too_many_arguments)]
    fn enrich_pairs(&mut self, st: &St, sys: &LinSystem, points: Option<&[Vec<Option<super::rat::Q>>]>, goal_atoms: &[Tm], atoms: &[Tm], hyps: &mut Vec<Hyp>, seen: &mut Vec<Tm>, model: Option<(usize, &LinSystem, &[Option<super::rat::Q>])>) -> R<()> {
        // The pairwise enrichments (unique quotients, `pow2` pairs, quotient
        // congruence) prove side conditions by linarith over every
        // hypothesis, per candidate and on every enriched linarith call:
        // they look at the goal's atoms (and run for a goal that has one),
        // not at every atom of the facts (pe integration: QMDB geometry
        // goals with a dozen `/ 2` and `pow2` atoms ran out of budget). Not
        // at all inside an atom congruence, whose linarith calls prove the
        // equations of two atoms' arguments.
        let in_goal: Vec<Tm> = match self.in_atom_congr {
            true => Vec::new(),
            false => atoms.iter().filter(|a| goal_atoms.iter().any(|g| self.env.alpha_eq_relevant(g, a, &|x, y| x == y))).cloned().collect(),
        };
        let goal_divides = in_goal.iter().any(|a| matches!(&**a, Term::Prim { op: PrimOp::IDiv | PrimOp::IMod, args, .. } if matches!(&*args[1], Term::Lit { .. })));
        self.enrich_quotients(st, &in_goal, hyps, seen, model)?;
        self.enrich_pow2_pairs(st, &in_goal, hyps, seen)?;
        if !self.in_atom_congr {
            self.enrich_pow2_exponents(st, sys, points, goal_atoms, hyps, seen)?;
            // the argument equations of two atoms are linear facts or not at
            // all: no integer cuts for them (each costs a search per pair)
            self.in_atom_congr = true;
            let saved = std::mem::replace(&mut self.lin_no_cuts, true);
            let r = self.enrich_atom_congruence(st, &atoms, hyps);
            self.lin_no_cuts = saved;
            self.in_atom_congr = false;
            r?;
        }
        // after the atom congruences (the operands' equations may use them),
        // then the quotients of equal dividends (which may use both)
        self.enrich_div_congruence(st, &atoms, hyps, seen)?;
        if self.rule_depth < 3 && goal_divides {
            self.enrich_quotient_congruence(st, &atoms, hyps, seen)?;
        }
        Ok(())
    }

    /// Atom congruence: two atoms that apply the same stuck global to
    /// arguments that are equal — integers by linarith, the others by
    /// conversion or a fact ([`Engine::arg_congruence`]) — are linked by
    /// their equation, proven by one transport per differing position. The
    /// loop elaboration states an invariant at `i + 1` as
    /// `s(xs, (i +ᵤ 1) as Int)` while an unfolding fact about the spec reads
    /// `s(xs, (i as Int) + 1)`: two atoms for linarith until this equation
    /// joins them.
    fn enrich_atom_congruence(&mut self, st: &St, atoms: &[Tm], hyps: &mut Vec<Hyp>) -> R<()> {
        let head = |t: &Tm| -> Option<(sandblaster_kernel::term::GlobalId, usize)> {
            let mut h = t;
            let mut n = 0;
            while let Term::App { fun, .. } = &**h {
                h = fun;
                n += 1;
            }
            match &**h {
                Term::Global(g) if n > 0 => Some((*g, n)),
                _ => None,
            }
        };
        let mut tries = 0u32;
        for i in 0..atoms.len() {
            let Some(hi) = head(&atoms[i]) else { continue };
            for j in (i + 1)..atoms.len() {
                if head(&atoms[j]) != Some(hi) || self.env.alpha_eq_relevant(&atoms[i], &atoms[j], &|x, y| x == y) {
                    continue;
                }
                // a pair with an integer argument pair that is never equal
                // (`pow2(e)` against `pow2(e - 1)`) costs no try
                if self.atoms_arith_distinct(st, &atoms[i], &atoms[j])? {
                    continue;
                }
                tries += 1;
                if tries > 16 {
                    return Ok(());
                }
                let (Some(av), Some(bv)) = (self.eval(st, &atoms[i])?, self.eval(st, &atoms[j])?) else { continue };
                let Some(ty) = self.infer_irr(st, &atoms[i])? else { continue };
                if !matches!(&*ty, Value::IntTy(_)) {
                    continue;
                }
                let goal: V = Rc::new(Value::Eq { ty, lhs: av, rhs: bv });
                let stmt = self.quote(st, &goal);
                if hyps.iter().any(|(_, s)| self.env.alpha_eq_relevant(s, &stmt, &|x, y| x == y)) {
                    continue;
                }
                let mut p = self.arg_congruence(st, &goal)?;
                // the index positions of `l[a]`, `l[b]` differ only by
                // arithmetic, and their bound proofs make the transport's
                // motive ill-typed: the gated backward rule `seq::index_eq`
                // (pe P3/C2)
                // Only when the two indices are equal by linear arithmetic
                // over `hyps` (then the motive was the obstacle): otherwise
                // the rule's `i == j` hypothesis cannot be proved either, and
                // trying it costs a hypothesis search per atom pair on every
                // linarith call (`l[0]` against `l[1]`, …).
                if p.is_none() && Some(hi.0) == self.n.seq_index && self.index_args_equal(st, &atoms[i], &atoms[j], hyps)? {
                    let mut c = st.child();
                    p = self.backward(&mut c, &goal)?.map(|b| c.finish(b));
                }
                if let Some(p) = p {
                    if self.trace {
                        eprintln!("[auto] atom congruence: {}", self.show(st, &goal));
                    }
                    hyps.push((p, stmt));
                }
            }
        }
        Ok(())
    }

    /// Whether two applications of one global have, at some position, two
    /// integer arguments whose linear forms differ by a nonzero constant
    /// ([`Engine::arith_distinct`]): their argument congruence cannot hold.
    fn atoms_arith_distinct(&mut self, st: &St, a: &Tm, b: &Tm) -> R<bool> {
        let (_, xa) = crate::elab::items::spine(a);
        let (_, xb) = crate::elab::items::spine(b);
        if xa.len() != xb.len() {
            return Ok(false);
        }
        for (x, y) in xa.iter().zip(xb.iter()) {
            if self.env.alpha_eq_relevant(x, y, &|p, q| p == q) {
                continue;
            }
            let Some(ty) = self.infer_irr(st, x)? else { continue };
            if !matches!(&*ty, Value::IntTy(_)) {
                continue;
            }
            let (Some(xv), Some(yv)) = (self.eval(st, x)?, self.eval(st, y)?) else { continue };
            let goal: V = Rc::new(Value::Eq { ty, lhs: xv, rhs: yv });
            if self.arith_distinct(st, &goal)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// For two `seq::index T l i _ _` atoms: the same list, and `i == j` by
    /// one linarith round over `hyps` (no enrichment).
    fn index_args_equal(&mut self, st: &St, a: &Tm, b: &Tm, hyps: &[Hyp]) -> R<bool> {
        let (_, xa) = crate::elab::items::spine(a);
        let (_, xb) = crate::elab::items::spine(b);
        if xa.len() < 3 || xb.len() < 3 || !self.env.alpha_eq_relevant(&xa[1], &xb[1], &|x, y| x == y) {
            return Ok(false);
        }
        let Some(ty) = self.infer_irr(st, &xa[2])? else { return Ok(false) };
        let goal = mk::eq(self.quote(st, &ty), xa[2].clone(), xb[2].clone());
        let Some(sys) = self.linearize(st, hyps, &goal)? else { return Ok(false) };
        Ok(simplex::certificate(&sys).is_some())
    }

    /// Add the atoms of the state's disequality facts (`Eq(Bool, eq(a, b),
    /// false)`, `Eq(Bool, ne(a, b), true)`) to `atoms` (at most four facts).
    fn diseq_atoms(&mut self, st: &St, hyps: &[Hyp], atoms: &mut Vec<Tm>) -> R<()> {
        let mut n = 0;
        for f in st.facts.clone().iter().rev() {
            let Some((ty, l, r)) = as_eq(&f.ty) else { continue };
            if !matches!(&**ty, Value::Ind { ind, .. } if *ind == self.n.bool_ind) || self.lin_hyp_form(&f.ty) {
                continue;
            }
            let (Some(b), Some((op, args))) = (bool_lit(self.n.bool_ind, r), as_prim(l)) else { continue };
            let w = match (op, b) {
                (PrimOp::Eq(w), false) | (PrimOp::Ne(w), true) => w,
                _ => continue,
            };
            n += 1;
            if n > 4 {
                break;
            }
            let (a0, a1) = (self.quote(st, &args[0]), self.quote(st, &args[1]));
            let le = sandblaster_kernel::prim::prim0(PrimOp::Le(w), vec![a0, a1]);
            let g = mk::eq(mk::bool_ty(self.n.bool_ind), le, mk::bool_lit(self.n.bool_ind, true));
            let Some(sys) = self.linearize(st, hyps, &g)? else { continue };
            for a in sys.atoms {
                if !atoms.iter().any(|x| self.env.alpha_eq_relevant(x, &a, &|p, q| p == q)) {
                    atoms.push(a);
                }
            }
        }
        Ok(())
    }

    /// Unique quotient (integer division by a literal, pe P3/C4). The
    /// kernel linearizes `x / k` and `x % k` (`k > 1` a literal) through one
    /// pair `x = k·q + r`, `0 ≤ r < k`; linarith is rational, so from
    /// `x = k·m + c` with `0 ≤ c < k` it cannot conclude `q = m` (that needs
    /// `q − m` to be an integer strictly between −1 and 1). For every such
    /// atom whose dividend decomposes as `k·m + c` — syntactically (the
    /// summands whose coefficients are multiples of `k` form `m`), or
    /// through a hypothesis `x = e` — with `0 ≤ c` and `c < k` provable,
    /// the equation `x / k = m` is proved by two splits (`q < m` and
    /// `m < q` are each refuted by linarith) and added; `x % k = c` then
    /// follows linearly. Each proof is checked by the kernel like any other.
    fn enrich_quotients(&mut self, st: &St, atoms: &[Tm], hyps: &mut Vec<Hyp>, seen: &mut Vec<Tm>, model: Option<(usize, &LinSystem, &[Option<super::rat::Q>])>) -> R<()> {
        // (also for rule hypotheses: `bool::eq_sound` states a boolean
        // equation as one; the splits below instantiate no rules)
        if self.rule_depth >= 3 {
            return Ok(());
        }
        let mut tries = 0u32;
        for a in atoms {
            let Term::Prim { op: PrimOp::IDiv | PrimOp::IMod, args, .. } = &**a else { continue };
            let (x, Term::Lit { n: k, .. }) = (&args[0], &*args[1]) else { continue };
            if k <= &BigInt::from(1) {
                continue;
            }
            let q = sandblaster_kernel::prim::prim0(PrimOp::IDiv, vec![x.clone(), mk::lit(Width::Int, k.clone())]);
            // a marker (never an atom: linear forms have no negation node),
            // so a later round does not redo the atom
            let key = sandblaster_kernel::prim::prim0(PrimOp::INeg, vec![q.clone()]);
            if seen.iter().any(|s| self.env.alpha_eq_relevant(s, &key, &|a, b| a == b)) {
                continue;
            }
            seen.push(key);
            // candidate readings of the dividend: itself, and the other sides
            // of the hypotheses `x = e` / `e = x`
            let mut sources = vec![x.clone()];
            for (_, stated) in hyps.iter() {
                if let Term::Eq { ty, lhs, rhs } = &**stated
                    && matches!(&**ty, Term::IntTy(Width::Int))
                {
                    if self.env.alpha_eq_relevant(lhs, x, &|a, b| a == b) {
                        sources.push(rhs.clone());
                    } else if self.env.alpha_eq_relevant(rhs, x, &|a, b| a == b) {
                        sources.push(lhs.clone());
                    }
                }
            }
            // each reading as `k·m + c`, with `c` also moved by one `k`
            // either way (`g - 128 + 128·y` is `128·y + (g - 128)` when `g ≥
            // 128`, not `128·(y - 1) + g`)
            let cands: Vec<(Tm, Tm)> = sources.into_iter().take(4).flat_map(|src| split_multiple_shifts(&src, k)).collect();
            for (m, c) in cands {
                // `x = k·(x / k) + x % k` (the division's own equation, a
                // fact after `halves(x)`) only gives `x / k = x / k`
                if self.env.alpha_eq_relevant(&m, &q, &|a, b| a == b) {
                    continue;
                }
                if self.trace {
                    eprintln!("[auto] quotient candidate: {} / {k} = {} (+ {})", self.env.print_term(&[], x), self.env.print_term(&[], &m), self.env.print_term(&[], &c));
                }
                tries += 1;
                if tries > 8 {
                    return Ok(());
                }
                let int = Width::Int;
                let le0 = sandblaster_kernel::prim::prim0(PrimOp::Le(int), vec![mk::lit(int, 0u8), c.clone()]);
                let ltk = sandblaster_kernel::prim::prim0(PrimOp::Lt(int), vec![c.clone(), mk::lit(int, k.clone())]);
                let hs = hyps.clone();
                let (Some(g0), Some(g1)) = (self.cond(st, le0, true)?, self.cond(st, ltk, true)?) else { continue };
                // a side condition false at a rational model of these very
                // hypotheses has no linarith proof: no search for it
                if let Some((n, s1, pt)) = model
                    && n == hs.len()
                    && (self.false_at(st, &g1, s1, pt)? || self.false_at(st, &g0, s1, pt)?)
                {
                    continue;
                }
                if self.lin_with(st, &hs, &g0)?.is_none() || self.lin_with(st, &hs, &g1)?.is_none() {
                    continue;
                }
                let Some(p) = self.quotient_eq(st, &q, &m, &hs)? else { continue };
                let stmt = mk::eq(mk::int_ty(int), q.clone(), m.clone());
                if self.trace {
                    eprintln!("[auto] unique quotient: {}", self.env.print_term(&[], &stmt));
                }
                self.note("unique quotient of a division by a literal");
                hyps.push((p, stmt));
                break;
            }
        }
        Ok(())
    }

    /// Division congruence (pe P3/C3, C4): two quotient/remainder atoms by
    /// the same literal `k` whose dividends are equal by linarith (a machine
    /// word `x >> s` and the ghost `x / pow2(s)` it equals, the two readings
    /// of one value) have equal quotients, proved as [`Self::quotient_eq`]
    /// does; their remainders are then linearly equal. At most eight such
    /// atoms are paired.
    fn enrich_quotient_congruence(&mut self, st: &St, atoms: &[Tm], hyps: &mut Vec<Hyp>, seen: &mut Vec<Tm>) -> R<()> {
        let mut divs: Vec<(Tm, BigInt)> = Vec::new();
        for a in atoms {
            let Term::Prim { op: PrimOp::IDiv | PrimOp::IMod, args, .. } = &**a else { continue };
            let Term::Lit { n: k, .. } = &*args[1] else { continue };
            if k <= &BigInt::from(1) || divs.iter().any(|(x, j)| j == k && self.env.alpha_eq_relevant(x, &args[0], &|p, q| p == q)) {
                continue;
            }
            divs.push((args[0].clone(), k.clone()));
        }
        if divs.len() < 2 || divs.len() > 8 {
            return Ok(());
        }
        let int = Width::Int;
        for i in 0..divs.len() {
            for j in (i + 1)..divs.len() {
                let ((x1, k), (x2, k2)) = (divs[i].clone(), divs[j].clone());
                if k != k2 {
                    continue;
                }
                let q1 = sandblaster_kernel::prim::prim0(PrimOp::IDiv, vec![x1.clone(), mk::lit(int, k.clone())]);
                let q2 = sandblaster_kernel::prim::prim0(PrimOp::IDiv, vec![x2.clone(), mk::lit(int, k.clone())]);
                let key = sandblaster_kernel::prim::prim0(PrimOp::INeg, vec![sandblaster_kernel::prim::prim0(PrimOp::ISub, vec![q1.clone(), q2.clone()])]);
                if seen.iter().any(|s| self.env.alpha_eq_relevant(s, &key, &|p, q| p == q)) {
                    continue;
                }
                // (marked done only once proved: a later round may have the
                // dividends' equation; a failure is marked with the number
                // of hypotheses it saw — the list only grows — so the same
                // search is not run again until they grow)
                let tried = sandblaster_kernel::prim::prim0(PrimOp::IAdd, vec![key.clone(), mk::lit(int, hyps.len() as u64)]);
                if seen.iter().any(|s| self.env.alpha_eq_relevant(s, &tried, &|p, q| p == q)) {
                    continue;
                }
                let hs = hyps.clone();
                let Some(e) = self.eval(st, &mk::eq(mk::int_ty(int), x1.clone(), x2.clone()))? else {
                    seen.push(tried);
                    continue;
                };
                let Some(pe) = self.lin_with(st, &hs, &e)? else {
                    seen.push(tried);
                    continue;
                };
                // one transport along the dividends' equation (as in
                // `enrich_div_congruence`), not the two splits of
                // `quotient_eq`: those cost a linarith run per arm
                let pe = self.promote(st, &e, pe);
                let motive = mk::eq(mk::int_ty(int), shift(&q1, 1), sandblaster_kernel::prim::prim0(PrimOp::IDiv, vec![mk::var(0), mk::lit(int, k.clone())]));
                let p = Rc::new(Term::Transport { ty: mk::int_ty(int), lhs: x1.clone(), rhs: x2.clone(), eq: pe, motive, val: mk::refl(mk::int_ty(int), q1.clone()) });
                seen.push(key);
                let stmt = mk::eq(mk::int_ty(int), q1, q2);
                if self.trace {
                    eprintln!("[auto] quotient congruence: {}", self.env.print_term(&[], &stmt));
                }
                self.note("equal dividends have equal quotients");
                hyps.push((p, stmt));
            }
        }
        Ok(())
    }

    /// `pow2` atom pairs (pe P3/C5): for two atoms `pow2(a)`, `pow2(b)`
    /// whose arguments differ by the literal 1 (`b = a + 1` as linear
    /// forms) and `0 ≤ a`, the step `pow2(b) = 2·pow2(a)`
    /// (`nat::pow2_step`); for arguments with `a ≤ b` provable, the
    /// monotonicity `pow2(a) ≤ pow2(b)` (`nat::pow2_mono`). At most six
    /// `pow2` atoms are paired.
    fn enrich_pow2_pairs(&mut self, st: &St, atoms: &[Tm], hyps: &mut Vec<Hyp>, seen: &mut Vec<Tm>) -> R<()> {
        if self.rule_depth >= 1 {
            return Ok(());
        }
        let mut args: Vec<Tm> = Vec::new();
        for a in atoms {
            if let Some(("ghost::pow2", x)) = self.nat_fn_app(a)
                && !args.iter().any(|y| self.env.alpha_eq_relevant(y, &x, &|p, q| p == q))
            {
                args.push(x);
            }
        }
        if args.len() < 2 || args.len() > 6 {
            return Ok(());
        }
        let int = Width::Int;
        let (Some(step), Some(mono)) = (self.env.lookup_global("nat::pow2_step"), self.env.lookup_global("nat::pow2_mono")) else { return Ok(()) };
        for i in 0..args.len() {
            for j in 0..args.len() {
                if i == j {
                    continue;
                }
                let (a, b) = (args[i].clone(), args[j].clone());
                // a marker per ordered pair, so a later round does not redo it
                let key = sandblaster_kernel::prim::prim0(PrimOp::ISub, vec![b.clone(), a.clone()]);
                if seen.iter().any(|s| self.env.alpha_eq_relevant(s, &key, &|p, q| p == q)) {
                    continue;
                }
                seen.push(key);
                let hs = hyps.clone();
                if lin_diff(&self.env, &b, &a) == Some(BigInt::from(1)) {
                    let g0 = sandblaster_kernel::prim::prim0(PrimOp::Le(int), vec![mk::lit(int, 0u8), a.clone()]);
                    let Some(g0v) = self.cond(st, g0, true)? else { continue };
                    let Some(p0) = self.lin_with(st, &hs, &g0v)? else { continue };
                    let e = mk::eq(mk::int_ty(int), b.clone(), sandblaster_kernel::prim::prim0(PrimOp::IAdd, vec![a.clone(), mk::lit(int, 1u8)]));
                    let Some(ev) = self.eval(st, &e)? else { continue };
                    let Some(p1) = self.lin_with(st, &hs, &ev)? else { continue };
                    let pf = self.pow2_lemma(st, step, &a, &b, vec![p0, p1])?;
                    if let Some((pf, stmt)) = pf {
                        hyps.push((pf, stmt));
                    }
                } else {
                    let g = sandblaster_kernel::prim::prim0(PrimOp::Le(int), vec![a.clone(), b.clone()]);
                    let Some(gv) = self.cond(st, g, true)? else { continue };
                    // (an integer cut for arguments read through truncating
                    // casts: `pow2(s as u32 as Int)` against `pow2(s as Int)`)
                    let cast = |t: &Tm| crate::elab::tm::any_node(t, &mut |n| matches!(n, Term::Prim { op: PrimOp::Cast { .. }, .. }));
                    let p = match self.lin_with(st, &hs, &gv)? {
                        Some(p) => Some(p),
                        // (only there: a cut search per unordered pair of
                        // `pow2` atoms on every enriched linarith call costs
                        // more than the goals it helps)
                        None if cast(&a) || cast(&b) => self.lin_cut(st, &gv, &hs, 2)?,
                        None => None,
                    };
                    let Some(p) = p else { continue };
                    if let Some((pf, stmt)) = self.pow2_lemma(st, mono, &a, &b, vec![p])? {
                        hyps.push((pf, stmt));
                    }
                }
            }
        }
        Ok(())
    }

    /// The exponent of a power, bounded through the power (pe P3/C5 read
    /// backwards), for a goal about exponents: each goal atom occurs in the
    /// exponent of a `pow2` atom of the round (`g ≤ 62`, `t + 1 < 64`), and
    /// the negated goal pushes an exponent up. For such an atom `pow2(x)`
    /// (at most four) and the smallest literal `U` among the hypotheses'
    /// with `pow2(x) ≤ U` following from the round's facts, the bound
    /// `x < k + 1` for `k = ⌊log₂ U⌋` (`nat::pow2_lt_rev`, from
    /// `pow2(x) ≤ U < 2^(k+1)`). So `(c + 1)·2^g ≤ 2^62` gives `g ≤ 62` once
    /// the product's monotonicity (`2^g ≤ (c + 1)·2^g`) has put `pow2(g)`
    /// among the atoms.
    ///
    /// Cost: the search tries goals that do not hold on every enriched
    /// linarith call, and a proof search per candidate ran the verifier's
    /// subtree lemma out of budget. So the rule does not run inside a probe
    /// ([`Engine::lin_probe`]); it decides on the round's linear system
    /// (rows swapped in, no kernel calls); the round's feasible point ends
    /// it when no bound could cut that point off (a point with
    /// `x ≤ bits(⌊pow2(x)⌋) − 1` satisfies every such bound, as a provable
    /// `pow2(x) ≤ U` holds there); the candidates are bisected (refutation is
    /// monotone in `U`); and the bounds are proved only when they refute the
    /// round's negated goal.
    fn enrich_pow2_exponents(&mut self, st: &St, sys: &LinSystem, points: Option<&[Vec<Option<super::rat::Q>>]>, goal_atoms: &[Tm], hyps: &mut Vec<Hyp>, seen: &mut Vec<Tm>) -> R<()> {
        use super::rat::Q;
        use sandblaster_kernel::linarith::{Constraint, ConstraintKind};
        if self.rule_depth >= 1 || self.lin_probe || goal_atoms.is_empty() || sys.problems.is_empty() {
            return Ok(());
        }
        let (Some(rev), Some(pow2)) = (self.env.lookup_global("nat::pow2_lt_rev"), self.env.lookup_global("ghost::pow2")) else { return Ok(()) };
        let int = Width::Int;
        let n = sys.atoms.len();
        // the round's `pow2` atoms with a non-literal exponent that mentions
        // a goal atom, every goal atom in one of them
        let mut exps: Vec<(usize, Tm)> = Vec::new();
        for (i, a) in sys.atoms.iter().enumerate() {
            let Some(("ghost::pow2", x)) = self.nat_fn_app(a) else { continue };
            if matches!(&*x, Term::Lit { .. }) || exps.iter().any(|(_, y)| self.env.alpha_eq_relevant(y, &x, &|p, q| p == q)) {
                continue;
            }
            exps.push((i, x));
        }
        if !goal_atoms.iter().all(|g| exps.iter().any(|(_, x)| self.mentions_atom(x, std::slice::from_ref(g), 0))) {
            return Ok(());
        }
        let mut powers: Vec<(usize, Tm, Constraint)> = Vec::new();
        for (ai, x) in exps {
            if powers.len() == 4 || !self.mentions_atom(&x, goal_atoms, 0) {
                continue;
            }
            // a marker per exponent, so a later round does not redo it
            let key = sandblaster_kernel::prim::prim0(PrimOp::INeg, vec![x.clone()]);
            if seen.iter().any(|s| self.env.alpha_eq_relevant(s, &key, &|p, q| p == q)) {
                continue;
            }
            seen.push(key);
            // the row `x ≤ 0` over the round's atoms: the negated goal of
            // `(x ≤ 0) = false`, linearized alone, its atoms found among the
            // round's (or the power is not used)
            let Some(g) = self.cond(st, sandblaster_kernel::prim::prim0(PrimOp::Le(int), vec![x.clone(), mk::lit(int, 0u8)]), false)? else { continue };
            let g = self.quote(st, &g);
            let Some(small) = self.linearize(st, &[], &g)? else { continue };
            let Some(row) = small.problems.first().and_then(|p| p.iter().find(|c| c.origin == ConstraintOrigin::NegatedGoal)) else { continue };
            let mut coeffs = Vec::new();
            for (j, c) in &row.coeffs {
                let Some(i) = sys.atoms.iter().position(|a| self.env.alpha_eq_relevant(a, &small.atoms[*j], &|p, q| p == q)) else { break };
                coeffs.push((i, c.clone()));
            }
            if coeffs.len() == row.coeffs.len() && row.kind == ConstraintKind::Le0 {
                powers.push((ai, x, Constraint { coeffs, constant: row.constant.clone(), kind: ConstraintKind::Le0, origin: ConstraintOrigin::Hyp(usize::MAX) }));
            }
        }
        // the negated goal must push an exponent up: a coefficient of the
        // opposite sign to the exponent's in some atom (`h ≤ 1` negated is
        // `h ≥ 2`, which an upper bound can cut off; `h > 1` negated is
        // `h ≤ 1`, which none can)
        let negs: Vec<&Constraint> = sys.problems.iter().filter_map(|p| p.iter().find(|c| c.origin == ConstraintOrigin::NegatedGoal)).collect();
        powers.retain(|(_, _, row)| {
            negs.iter().any(|ng| {
                row.coeffs.iter().any(|(i, b)| ng.coeffs.iter().any(|(j, g)| i == j && b * g < BigInt::from(0)))
            })
        });
        if powers.is_empty() {
            return Ok(());
        }
        // the round's feasible points: those of its certificate search, or
        // a search here (a round the caller skipped); none (it gave up): no
        // bounds
        let mut own: Vec<Vec<Option<Q>>> = Vec::new();
        let points: &[Vec<Option<Q>>] = match points {
            Some(p) => p,
            None => {
                for p in &sys.problems {
                    match simplex::farkas_staged_point(p, n) {
                        Ok(_) => continue,
                        Err(Some(pt)) => own.push(pt),
                        Err(None) => return Ok(()),
                    }
                }
                &own
            }
        };
        if points.is_empty() {
            return Ok(());
        }
        // at a point: `x`'s value, and `bits(⌊pow2(x)⌋) − 1`
        let at = |pt: &[Option<Q>], ai: usize, row: &Constraint| -> Option<(Q, BigInt)> {
            let mut xv = Q::int(row.constant.clone());
            for (i, c) in &row.coeffs {
                xv = xv.add(&Q::int(c.clone()).mul(pt.get(*i)?.as_ref()?));
            }
            let pw = pt.get(ai)?.as_ref()?;
            let fl = if pw.is_neg() { BigInt::from(0) } else { pw.num() / pw.den() };
            Some((xv, BigInt::from(fl.bits()) - 1))
        };
        // per power: whether its bound may cut a point off, and the largest
        // exponent value to cut off (`None`: a value is unknown — outside
        // the point's neighbourhood)
        let mut useful = vec![false; powers.len()];
        let mut need: Vec<Option<Q>> = vec![None; powers.len()];
        let mut unknown = vec![false; powers.len()];
        for pt in points {
            let mut cut = false;
            for (k, (ai, _, row)) in powers.iter().enumerate() {
                match at(pt, *ai, row) {
                    Some((xv, thr)) if !xv.sub(&Q::int(thr.clone())).is_pos() => {}
                    Some((xv, _)) => {
                        cut = true;
                        useful[k] = true;
                        if need[k].as_ref().is_none_or(|m| xv.sub(m).is_pos()) {
                            need[k] = Some(xv);
                        }
                    }
                    None => {
                        cut = true;
                        useful[k] = true;
                        unknown[k] = true;
                    }
                }
            }
            if !cut {
                return Ok(());
            }
        }
        let mut cands: Vec<BigInt> = Vec::new();
        for (_, stated) in hyps.iter() {
            visit_lits(stated, &mut |v| {
                if v >= &BigInt::from(1) && !cands.contains(v) {
                    cands.push(v.clone());
                }
            });
        }
        cands.sort();
        // the round's facts and implicit constraints, without its negated goal
        let base: Vec<Constraint> = sys.problems[0].iter().filter(|c| c.origin != ConstraintOrigin::NegatedGoal).cloned().collect();
        // (exponent, k + 1 = the bit length of U, the row `x − k ≤ 0`)
        let mut found: Vec<(Tm, BigInt, Constraint)> = Vec::new();
        for (k, (ai, x, row)) in powers.into_iter().enumerate() {
            if !useful[k] {
                continue;
            }
            // the smallest `U` refuting `pow2(x) ≥ U + 1` (refutation is
            // monotone in `U`: the largest first, then a bisection), among
            // those whose bound `bits(U) − 1` is below a value to cut off
            let refutes = |u: &BigInt| {
                let mut p = base.clone();
                p.push(Constraint { coeffs: vec![(ai, BigInt::from(-1))], constant: u + 1, kind: ConstraintKind::Le0, origin: ConstraintOrigin::NegatedGoal });
                simplex::farkas_staged(&p, n).is_some()
            };
            let el: Vec<&BigInt> = cands
                .iter()
                .filter(|u| unknown[k] || need[k].as_ref().is_none_or(|m| m.sub(&Q::int(BigInt::from(u.bits()) - 1)).is_pos()))
                .collect();
            let Some(last) = el.last() else { continue };
            if !refutes(last) {
                continue;
            }
            let (mut lo, mut hi) = (0, el.len() - 1);
            while lo < hi {
                let mid = (lo + hi) / 2;
                if refutes(el[mid]) {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            let u = el[lo].clone();
            let k1 = BigInt::from(u.bits());
            let mut row = row;
            row.constant -= &k1 - 1;
            found.push((x, k1, row));
        }
        if found.is_empty() {
            return Ok(());
        }
        // the bounds close the goal with the round's facts, or none is added
        for p in &sys.problems {
            let mut p = p.clone();
            p.extend(found.iter().map(|(_, _, r)| r.clone()));
            if simplex::farkas_staged(&p, n).is_none() {
                return Ok(());
            }
        }
        let hs = hyps.clone();
        for (x, k1, _) in found {
            let pk1 = mk::app(mk::global(pow2), mk::lit(int, k1.clone()));
            let c = sandblaster_kernel::prim::prim0(PrimOp::Lt(int), vec![mk::app(mk::global(pow2), x.clone()), pk1]);
            let Some(pf) = self.prove_cond(st, &c, &hs)? else { continue };
            if let Some(h) = self.pow2_lemma(st, rev, &x, &mk::lit(int, k1), vec![pf])? {
                hyps.push(h);
            }
        }
        Ok(())
    }

    /// Whether one of `atoms` occurs in `t` (outside binders, at most eight
    /// levels deep).
    fn mentions_atom(&self, t: &Tm, atoms: &[Tm], depth: u32) -> bool {
        if depth > 8 {
            return false;
        }
        if atoms.iter().any(|a| self.env.alpha_eq_relevant(a, t, &|p, q| p == q)) {
            return true;
        }
        if matches!(&**t, Term::Lam { .. } | Term::Pi { .. } | Term::Let { .. } | Term::Sigma { .. } | Term::Match { .. }) {
            return false;
        }
        let mut found = false;
        crate::elab::tm::children(t, &mut |c| {
            if !found && self.mentions_atom(c, atoms, depth + 1) {
                found = true;
            }
        });
        found
    }

    /// `lemma a b h…` for a `nat::pow2_*` lemma whose binders after the two
    /// `Int` arguments are the hypotheses proved by `proofs`, with its
    /// statement.
    fn pow2_lemma(&mut self, st: &St, g: sandblaster_kernel::term::GlobalId, a: &Tm, b: &Tm, proofs: Vec<Tm>) -> R<Option<Hyp>> {
        let Some(rels) = self.env.global_param_rels(g) else { return Ok(None) };
        if rels.len() != 2 + proofs.len() {
            return Ok(None);
        }
        let mut args: Vec<(Rel, Tm)> = vec![(rels[0], a.clone()), (rels[1], b.clone())];
        args.extend(rels[2..].iter().copied().zip(proofs));
        let pf = apps(mk::global(g), args);
        let Some(ty) = self.infer_irr(st, &pf)? else { return Ok(None) };
        let stmt = self.quote(st, &ty);
        Ok(Some((pf, stmt)))
    }

    /// Whether the linarith goal `goal` is false at `pt`, the point of a
    /// failed search `s1` over some hypotheses (a rational model of them
    /// and of the implicit bounds of the atoms it assigns): some refutation
    /// problem of `goal` — the negated goal and the implicit constraints of
    /// its atoms — holds at `pt` with every atom of it assigned. Then
    /// `lin_with` over those hypotheses finds no certificate (the
    /// constraints of the unassigned atoms share none of them and are
    /// satisfiable on their own). Conservative: `false` when unsure.
    fn false_at(&mut self, st: &St, goal: &V, s1: &LinSystem, pt: &[Option<super::rat::Q>]) -> R<bool> {
        use super::rat::Q;
        use sandblaster_kernel::linarith::ConstraintKind;
        if !self.lin_goal_form(goal) || self.lin_equiv_sides(goal).is_some() {
            return Ok(false);
        }
        let goal_tm = self.quote(st, goal);
        let Some(gs) = self.linearize(st, &[], &goal_tm)? else { return Ok(false) };
        let mut map: Vec<usize> = Vec::with_capacity(gs.atoms.len());
        for a in &gs.atoms {
            match s1.atoms.iter().position(|b| self.env.alpha_eq_relevant(a, b, &|x, y| x == y)) {
                Some(i) if pt.get(i).is_some_and(|v| v.is_some()) => map.push(i),
                _ => return Ok(false),
            }
        }
        'p: for p in &gs.problems {
            for c in p {
                let mut v = Q::int(c.constant.clone());
                for (a, k) in &c.coeffs {
                    let Some(&i) = map.get(*a) else { continue 'p };
                    let Some(x) = &pt[i] else { continue 'p };
                    v = v.add(&Q::int(k.clone()).mul(x));
                }
                let holds = match c.kind {
                    ConstraintKind::Le0 => !v.is_pos(),
                    ConstraintKind::Eq0 => v.is_zero(),
                };
                if !holds {
                    continue 'p;
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// A proof of `q = m` (terms at `st`'s depth) from `hyps`: split on
    /// `q < m`, then on `m < q`; the two strict arms are refuted and the
    /// last one is linear.
    fn quotient_eq(&mut self, st: &St, q: &Tm, m: &Tm, hyps: &[Hyp]) -> R<Option<Tm>> {
        let int = Width::Int;
        let goal_tm = mk::eq(mk::int_ty(int), q.clone(), m.clone());
        let Some(goal) = self.eval(st, &goal_tm)? else { return Ok(None) };
        let Some(c1) = self.eval(st, &sandblaster_kernel::prim::prim0(PrimOp::Lt(int), vec![q.clone(), m.clone()]))? else { return Ok(None) };
        if bool_lit(self.n.bool_ind, &c1).is_some() {
            return Ok(None);
        }
        let c2_tm = sandblaster_kernel::prim::prim0(PrimOp::Lt(int), vec![m.clone(), q.clone()]);
        let bi = self.n.bool_ind;
        let d0 = st.depth();
        let hyps = hyps.to_vec();
        let mut arm_fn = |e: &mut Engine<'a>, arm: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
            let k = (arm.depth() - d0) as i64;
            let mut hs: Vec<Hyp> = hyps.iter().map(|(p, s)| (shift(p, k), shift(s, k))).collect();
            if let Some(f) = arm.facts.last().cloned() {
                let stated = e.quote(arm, &f.ty);
                hs.push((arm.var(f.lvl), stated));
            }
            let p = match e.lin_with(arm, &hs, &tk)? {
                Some(p) => Some(p),
                None => {
                    let Some(c2) = e.eval(arm, &shift(&c2_tm, k))? else { return Ok(None) };
                    if bool_lit(e.n.bool_ind, &c2).is_some() {
                        return Ok(None);
                    }
                    e.lin_split(arm, &c2, &tk, &hs, 1)?
                }
            };
            Ok(p.map(|p| e.promote(arm, &tk, p)))
        };
        let depth_left = st.depth_left;
        self.case_split_with(st, &c1, bi, &[], &goal, true, depth_left, &mut arm_fn)
    }

    /// The lengths of the parts of a concatenation under `seq::len`, nested.
    fn len_append_parts(&self, a: &Tm, out: &mut Vec<Tm>, depth: u32) {
        if depth > 8 || out.len() > 32 {
            return;
        }
        let (Some(len_g), Some(app_g)) = (self.n.seq_len, self.env.lookup_global("seq::append")) else { return };
        let Term::App { fun, arg: l, .. } = &**a else { return };
        let Term::App { fun: g, arg: elem, .. } = &**fun else { return };
        if !matches!(&**g, Term::Global(h) if *h == len_g) {
            return;
        }
        let (h, args) = crate::elab::items::spine(l);
        if !matches!(&*h, Term::Global(x) if *x == app_g) || args.len() != 3 {
            return;
        }
        for part in [&args[1], &args[2]] {
            let t = apps(mk::global(len_g), [(Rel::Rel, elem.clone()), (Rel::Rel, part.clone())]);
            self.len_append_parts(&t, out, depth + 1);
            out.push(t);
        }
    }

    /// Congruence of divisions by a non-literal divisor (pe P3/C3, C5):
    /// two atoms `a / d` and `b / e` (or `%`) with `a = b` and `d = e` by
    /// linarith are equal (`x >> s` read as `x / pow2(s)` next to the
    /// spec's own `/ pow2(..)` of the same value). Proved by one transport
    /// per differing operand (`Int` division carries no proof). At most
    /// eight such atoms are paired.
    fn enrich_div_congruence(&mut self, st: &St, atoms: &[Tm], hyps: &mut Vec<Hyp>, seen: &mut Vec<Tm>) -> R<()> {
        let divs: Vec<(PrimOp, Tm, Tm, Tm)> = atoms
            .iter()
            .filter_map(|a| match &**a {
                Term::Prim { op: op @ (PrimOp::IDiv | PrimOp::IMod), args, .. } if !matches!(&*args[1], Term::Lit { .. }) => {
                    Some((*op, a.clone(), args[0].clone(), args[1].clone()))
                }
                _ => None,
            })
            .collect();
        if divs.len() < 2 || divs.len() > 8 {
            return Ok(());
        }
        let int = Width::Int;
        let it = mk::int_ty(int);
        for i in 0..divs.len() {
            for j in (i + 1)..divs.len() {
                let ((o1, t1, a1, d1), (o2, t2, a2, d2)) = (divs[i].clone(), divs[j].clone());
                if o1 != o2 || self.env.alpha_eq_relevant(&t1, &t2, &|p, q| p == q) {
                    continue;
                }
                let key = sandblaster_kernel::prim::prim0(PrimOp::INeg, vec![sandblaster_kernel::prim::prim0(PrimOp::ISub, vec![t1.clone(), t2.clone()])]);
                if seen.iter().any(|s| self.env.alpha_eq_relevant(s, &key, &|p, q| p == q)) {
                    continue;
                }
                // (a failure over these very hypotheses is not retried until
                // they grow, as in `enrich_quotient_congruence`)
                let tried = sandblaster_kernel::prim::prim0(PrimOp::IAdd, vec![key.clone(), mk::lit(int, hyps.len() as u64)]);
                if seen.iter().any(|s| self.env.alpha_eq_relevant(s, &tried, &|p, q| p == q)) {
                    continue;
                }
                let hs = hyps.clone();
                // an equation of the operands, by linarith (`None`: equal already)
                let operand_eq = |e: &mut Self, x: &Tm, y: &Tm| -> R<Option<Option<Tm>>> {
                    if e.env.alpha_eq_relevant(x, y, &|p, q| p == q) {
                        return Ok(Some(None));
                    }
                    let Some(g) = e.eval(st, &mk::eq(it.clone(), x.clone(), y.clone()))? else { return Ok(None) };
                    if let Some(p) = e.lin_with(st, &hs, &g)? {
                        return Ok(Some(Some(e.promote(st, &g, p))));
                    }
                    // `f(u) == f(v)` for one `Int -> Int` global (`pow2`): the
                    // arguments' equation (an integer cut for truncating casts),
                    // then congruence
                    if let (Term::App { rel: Rel::Rel, fun: f1, arg: u }, Term::App { rel: Rel::Rel, fun: f2, arg: v }) = (&**x, &**y)
                        && let (Term::Global(g1), Term::Global(g2)) = (&**f1, &**f2)
                        && g1 == g2
                        && let Some(gu) = e.eval(st, &mk::eq(it.clone(), u.clone(), v.clone()))?
                    {
                        let q = match e.lin_with(st, &hs, &gu)? {
                            Some(q) => Some(q),
                            None => e.lin_cut(st, &gu, &hs, 2)?,
                        };
                        if let Some(q) = q {
                            let q = e.promote(st, &gu, q);
                            let motive = mk::eq(it.clone(), shift(x, 1), Rc::new(Term::App { rel: Rel::Rel, fun: f1.clone(), arg: mk::var(0) }));
                            let proof = Rc::new(Term::Transport { ty: it.clone(), lhs: u.clone(), rhs: v.clone(), eq: q, motive, val: mk::refl(it.clone(), x.clone()) });
                            return Ok(Some(Some(proof)));
                        }
                    }
                    Ok(None)
                };
                let (Some(ea), Some(ed)) = (operand_eq(self, &a1, &a2)?, operand_eq(self, &d1, &d2)?) else {
                    seen.push(tried);
                    continue;
                };
                let prim = |x: Tm, y: Tm| sandblaster_kernel::prim::prim0(o1, vec![x, y]);
                // refl(t1), then along the dividend, then along the divisor
                let mut proof = mk::refl(it.clone(), t1.clone());
                if let Some(e) = ea {
                    let motive = mk::eq(it.clone(), shift(&t1, 1), prim(mk::var(0), shift(&d1, 1)));
                    proof = Rc::new(Term::Transport { ty: it.clone(), lhs: a1.clone(), rhs: a2.clone(), eq: e, motive, val: proof });
                }
                if let Some(e) = ed {
                    let motive = mk::eq(it.clone(), shift(&t1, 1), prim(shift(&a2, 1), mk::var(0)));
                    proof = Rc::new(Term::Transport { ty: it.clone(), lhs: d1.clone(), rhs: d2.clone(), eq: e, motive, val: proof });
                }
                seen.push(key);
                let stmt = mk::eq(it.clone(), t1.clone(), t2.clone());
                if self.trace {
                    eprintln!("[auto] division congruence: {}", self.env.print_term(&[], &stmt));
                }
                hyps.push((proof, stmt));
            }
        }
        Ok(())
    }

    /// The statement of an axiom instance (a term at the state's depth).
    fn axiom_stmt(&mut self, st: &St, ax: sandblaster_kernel::term::AxiomId, args: &[Tm]) -> R<Option<Tm>> {
        let Some((params, stmt)) = axioms::telescope(ax, self.n.bool_ind) else { return Ok(None) };
        if params.len() != args.len() {
            return Ok(None);
        }
        let mut es = Vec::new();
        for ((_, rel, _), a) in params.iter().zip(args) {
            match rel {
                Rel::Rel => {
                    let Some(v) = self.eval(st, a)? else { return Ok(None) };
                    es.push(EnvEntry::Rel(v));
                }
                Rel::Irr => es.push(irr_entry(&st.venv, a)),
            }
        }
        let r = self.env.eval(&VEnv(Rc::new(es)), sandblaster_kernel::term::Lvl(st.depth()), &stmt, self.b);
        let Some(v) = self.ev_err(r)? else { return Ok(None) };
        Ok(Some(self.quote(st, &v)))
    }

    fn push_axiom(&mut self, st: &St, s: Schema, w: Width, args: Vec<Tm>, hyps: &mut Vec<Hyp>) -> R<()> {
        let Some(ax) = axioms::axiom_id(s, w) else { return Ok(()) };
        let Some(stmt) = self.axiom_stmt(st, ax, &args)? else { return Ok(()) };
        hyps.push((Rc::new(Term::Axiom { ax, args }), stmt));
        Ok(())
    }

    /// A lemma instance `g args` (by name) as a linarith hypothesis, if the
    /// lemma is loaded and the instance type-checks.
    fn push_lemma(&mut self, st: &St, name: &str, args: Vec<(Rel, Tm)>, hyps: &mut Vec<Hyp>) -> R<()> {
        let Some(g) = self.env.lookup_global(name) else { return Ok(()) };
        let pf = apps(mk::global(g), args);
        if let Some(ty) = self.infer_irr(st, &pf)? {
            let stmt = self.quote(st, &ty);
            hyps.push((pf, stmt));
        }
        Ok(())
    }

    /// A proof of `Eq(Bool, c, true)` by linarith with the current
    /// hypotheses (or by evaluation).
    fn prove_cond(&mut self, st: &St, c: &Tm, hyps: &[Hyp]) -> R<Option<Tm>> {
        let Some(g) = self.cond(st, c.clone(), true)? else { return Ok(None) };
        if let Some((_, l, r)) = as_eq(&g)
            && let (Some(x), Some(y)) = (bool_lit(self.n.bool_ind, l), bool_lit(self.n.bool_ind, r))
        {
            return Ok((x == y).then(|| mk::refl(mk::bool_ty(self.n.bool_ind), mk::bool_lit(self.n.bool_ind, true))));
        }
        self.lin_with_directed(st, hyps, &g)
    }

    /// [`Self::lin_with`] for the side condition of an enrichment fact (a
    /// no-wrap or decided comparison of one atom): the certificate is
    /// searched from the condition outwards
    /// ([`simplex::certificate_directed`]), as the condition usually needs
    /// a few of the round's many hypotheses. It misses only a refutation by
    /// hypotheses contradictory among themselves and unrelated to the
    /// condition, which the round's own search finds.
    fn lin_with_directed(&mut self, st: &St, hyps: &[Hyp], goal: &V) -> R<Option<Tm>> {
        if !self.lin_goal_form(goal) || self.lin_equiv_sides(goal).is_some() {
            return Ok(None);
        }
        let goal_tm = self.quote(st, goal);
        let Some(sys) = self.linearize(st, hyps, &goal_tm)? else { return Ok(None) };
        match simplex::certificate_directed(&sys) {
            Some(cert) => Ok(Some(self.lin_term(st, hyps.to_vec(), goal_tm, &sys, cert)?)),
            None => Ok(None),
        }
    }

    /// `Eq(Bool, c, b)` for a comparison term `c`.
    fn cond(&mut self, st: &St, c: Tm, b: bool) -> R<Option<V>> {
        let bt = mk::bool_ty(self.n.bool_ind);
        let t = mk::eq(bt, c, mk::bool_lit(self.n.bool_ind, b));
        self.eval(st, &t)
    }

    /// Decide a condition with the current hypotheses: `Some((b, proof))`.
    fn decide_cond(&mut self, st: &St, c: &Tm, hyps: &[Hyp]) -> R<Option<(bool, Tm)>> {
        for b in [true, false] {
            let Some(g) = self.cond(st, c.clone(), b)? else { continue };
            // Closed conditions evaluate to a literal equation.
            if let Some((_, l, r)) = as_eq(&g)
                && let (Some(x), Some(y)) = (bool_lit(self.n.bool_ind, l), bool_lit(self.n.bool_ind, r))
            {
                if x == y {
                    return Ok(Some((b, mk::refl(mk::bool_ty(self.n.bool_ind), mk::bool_lit(self.n.bool_ind, b)))));
                }
                continue;
            }
            if let Some(p) = self.lin_with_directed(st, hyps, &g)? {
                return Ok(Some((b, p)));
            }
        }
        Ok(None)
    }

    /// Machine and `Int` division by a literal (see the module docs): the
    /// kernel linearizes `x % k`, `x / k`, `x & (2^j − 1)`, `x >> j` and a
    /// truncating cast of a machine word `x` through one quotient/remainder
    /// pair of `x`, and `(x as Int) % k`, `(x as Int) / k` through another
    /// pair of the `Int` value — equal remainders that linarith (rational)
    /// cannot identify. An atom `imod | idiv(cast_w(x), k)` (the printed
    /// form of either pair) gets the `rem_def` and `div_def` axiom instances
    /// at `x`'s width, `cast(x % k) = (x as Int) % k` and
    /// `cast(x / k) = (x as Int) / k`, whose sides are exactly the two
    /// pairs: so `(x % 10) as Int == (x as Int) % 10` and
    /// `(x & 0xff) as u8 as Nat == x as Nat % 256` are linear consequences.
    fn enrich_divmod_link(&mut self, st: &St, op: PrimOp, args: &[Tm], hyps: &mut Vec<Hyp>) -> R<()> {
        if !matches!(op, PrimOp::IMod | PrimOp::IDiv) || args.len() != 2 {
            return Ok(());
        }
        let Term::Prim { op: PrimOp::Cast { from: w, to: Width::Int }, args: xs, .. } = &*args[0] else { return Ok(()) };
        let Term::Lit { n: k, .. } = &*args[1] else { return Ok(()) };
        if *w == Width::Int || xs.len() != 1 || k <= &BigInt::from(0) || k > &sandblaster_kernel::prim::max_of(*w) {
            return Ok(());
        }
        let bool_ind = self.n.bool_ind;
        let ne = sandblaster_kernel::prim::prim0(PrimOp::Ne(*w), vec![mk::lit(*w, k.clone()), mk::lit(*w, 0u8)]);
        // `k ≠ 0` computes: `refl(Bool, k ≠ 0)` proves it by conversion
        let p = mk::refl(mk::bool_ty(bool_ind), ne);
        for s in [Schema::RemDef, Schema::DivDef] {
            let args = vec![xs[0].clone(), mk::lit(*w, k.clone()), p.clone()];
            let Some(ax) = axioms::axiom_id(s, *w) else { continue };
            let Some(stmt) = self.axiom_stmt(st, ax, &args)? else { continue };
            if hyps.iter().any(|(_, h)| self.env.alpha_eq_relevant(h, &stmt, &|x, y| x == y)) {
                continue;
            }
            hyps.push((Rc::new(Term::Axiom { ax, args }), stmt));
        }
        Ok(())
    }

    fn enrich_prim(&mut self, st: &St, op: PrimOp, args: &[Tm], proofs: &[Tm], hyps: &mut Vec<Hyp>) -> R<()> {
        use PrimOp::*;
        let prim = |op: PrimOp, a: Vec<Tm>| sandblaster_kernel::prim::prim0(op, a);
        let to_int = |w: Width, t: Tm| sandblaster_kernel::prim::prim0(Cast { from: w, to: Width::Int }, vec![t]);
        match op {
            Min(w) | Max(w) => {
                let c = prim(Le(w), vec![args[0].clone(), args[1].clone()]);
                if let Some((b, p)) = self.decide_cond(st, &c, &hyps.clone())? {
                    let s = match (op, b) {
                        (Min(_), true) => Schema::MinDefLe,
                        (Min(_), false) => Schema::MinDefGt,
                        (_, true) => Schema::MaxDefLe,
                        (_, false) => Schema::MaxDefGt,
                    };
                    self.push_axiom(st, s, w, vec![args[0].clone(), args[1].clone(), p], hyps)?;
                }
            }
            SatSub(w) => {
                let c = prim(Le(w), vec![args[1].clone(), args[0].clone()]);
                if let Some((b, p)) = self.decide_cond(st, &c, &hyps.clone())? {
                    let s = if b { Schema::SatSubDefLe } else { Schema::SatSubDefGt };
                    self.push_axiom(st, s, w, vec![args[0].clone(), args[1].clone(), p], hyps)?;
                }
            }
            SatAdd(w) => {
                let sum = prim(IAdd, vec![to_int(w, args[0].clone()), to_int(w, args[1].clone())]);
                let c = prim(Le(Width::Int), vec![sum, mk::lit(Width::Int, sandblaster_kernel::prim::max_of(w))]);
                if let Some((b, p)) = self.decide_cond(st, &c, &hyps.clone())? {
                    let s = if b { Schema::SatAddDefLe } else { Schema::SatAddDefGt };
                    self.push_axiom(st, s, w, vec![args[0].clone(), args[1].clone(), p], hyps)?;
                }
            }
            IntToSat(w) => {
                let lo = prim(Le(Width::Int), vec![mk::lit(Width::Int, 0u8), args[0].clone()]);
                let hi = prim(Le(Width::Int), vec![args[0].clone(), mk::lit(Width::Int, sandblaster_kernel::prim::max_of(w))]);
                let hs = hyps.clone();
                match (self.decide_cond(st, &lo, &hs)?, self.decide_cond(st, &hi, &hs)?) {
                    (Some((true, p0)), Some((true, p1))) => {
                        self.push_axiom(st, Schema::IntToSatDefIn, w, vec![args[0].clone(), p0, p1], hyps)?
                    }
                    (Some((false, _)), _) => {
                        let c = prim(Lt(Width::Int), vec![args[0].clone(), mk::lit(Width::Int, 0u8)]);
                        if let Some((true, p)) = self.decide_cond(st, &c, &hs)? {
                            self.push_axiom(st, Schema::IntToSatDefLo, w, vec![args[0].clone(), p], hyps)?;
                        }
                    }
                    (_, Some((false, _))) => {
                        let c = prim(Lt(Width::Int), vec![mk::lit(Width::Int, sandblaster_kernel::prim::max_of(w)), args[0].clone()]);
                        if let Some((true, p)) = self.decide_cond(st, &c, &hs)? {
                            self.push_axiom(st, Schema::IntToSatDefHi, w, vec![args[0].clone(), p], hyps)?;
                        }
                    }
                    _ => {}
                }
            }
            And(w) => {
                self.push_axiom(st, Schema::AndLeLeft, w, args.to_vec(), hyps)?;
                self.push_axiom(st, Schema::AndLeRight, w, args.to_vec(), hyps)?;
            }
            Or(w) => {
                self.push_axiom(st, Schema::OrGeLeft, w, args.to_vec(), hyps)?;
                self.push_axiom(st, Schema::OrGeRight, w, args.to_vec(), hyps)?;
                self.push_axiom(st, Schema::OrLeAdd, w, args.to_vec(), hyps)?;
            }
            Xor(w) => self.push_axiom(st, Schema::XorLeOr, w, args.to_vec(), hyps)?,
            // a complement is exact: `!x = MAX − x` (`bits::not_val_<w>`,
            // a checked lemma of `lemmas/bits.core`)
            Not(w) if args.len() == 1 && w.bits().is_some() => {
                self.push_lemma(st, &format!("bits::not_val_{}", sfx(w)), vec![(Rel::Rel, args[0].clone())], hyps)?
            }
            WShr(w) | Shr(w) => {
                self.push_axiom(st, Schema::ShrLe, w, args.to_vec(), hyps)?;
                // a non-literal amount below the width: `x >> s = x / pow2(s)`
                // (`bits::shr_is_div_pow2_<w>`, pe P3/C3); a checked shift
                // carries the proof, a wrapping one needs `s < w` by linarith
                if args.len() == 2 && !matches!(&*args[1], Term::Lit { .. }) && w.bits().is_some() {
                    let name = format!("bits::shr_is_div_pow2_{}", sfx(w));
                    // `s < w` by linarith (a checked shift's own proof, read back
                    // from its value, can be a bare `refl`: kept only as a
                    // fallback when it is a proof term of its own)
                    let c = prim(Lt(Width::U32), vec![args[1].clone(), mk::lit(Width::U32, w.bits().unwrap_or(0))]);
                    let p = match self.prove_cond(st, &c, &hyps.clone())? {
                        // promoted: the lemma's statement passes the proof to the
                        // shift's proof slot, and a bare certificate would read
                        // back from its value as `refl`
                        Some(p) => match self.cond(st, c.clone(), true)? {
                            Some(cv) => Some(self.promote(st, &cv, p)),
                            None => None,
                        },
                        None => match (op, proofs.first()) {
                            (Shr(_), Some(p)) if !matches!(&**p, Term::Refl { .. } | Term::Erased) => Some(p.clone()),
                            _ => None,
                        },
                    };
                    if let Some(p) = p {
                        self.push_lemma(st, &name, vec![(Rel::Rel, args[0].clone()), (Rel::Rel, args[1].clone()), (Rel::Rel, p)], hyps)?;
                    }
                }
            }
            // The bit-count bounds are lemmas of `lemmas/bits.core` (derived
            // from the K1 definitions).
            CountOnes(w) => self.push_lemma(st, &format!("bits::count_ones_le_{}", sfx(w)), vec![(Rel::Rel, args[0].clone())], hyps)?,
            LeadingZeros(w) | TrailingZeros(w) => {
                let stem = if matches!(op, LeadingZeros(_)) { "leading_zeros" } else { "trailing_zeros" };
                self.push_lemma(st, &format!("bits::{stem}_le_{}", sfx(w)), vec![(Rel::Rel, args[0].clone())], hyps)?;
                // the count of a complement `!y` (trailing ones): its value
                // first, so `!y ≠ 0` follows from `y ≠ MAX`
                if let Term::Prim { op: Not(w2), args: ys, .. } = &*args[0]
                    && ys.len() == 1
                {
                    self.push_lemma(st, &format!("bits::not_val_{}", sfx(*w2)), vec![(Rel::Rel, ys[0].clone())], hyps)?;
                }
                let c = prim(Ne(w), vec![args[0].clone(), mk::lit(w, 0u8)]);
                if let Some(p) = self.prove_cond(st, &c, &hyps.clone())? {
                    self.push_lemma(st, &format!("bits::{stem}_lt_{}", sfx(w)), vec![(Rel::Rel, args[0].clone()), (Rel::Irr, p)], hyps)?;
                }
            }
            // Wrapping operations that provably do not wrap equal the checked
            // ones (exact linearization, no carry atom).
            WAdd(w) | WMul(w) if args.len() == 2 => {
                if matches!(op, WMul(_)) && !args.iter().any(|a| matches!(&**a, Term::Lit { .. })) {
                    return Ok(());
                }
                let iop = if matches!(op, WAdd(_)) { IAdd } else { IMul };
                let c = prim(
                    Le(Width::Int),
                    vec![
                        prim(iop, vec![to_int(w, args[0].clone()), to_int(w, args[1].clone())]),
                        mk::lit(Width::Int, sandblaster_kernel::prim::max_of(w)),
                    ],
                );
                if let Some(p) = self.prove_cond(st, &c, &hyps.clone())? {
                    let stem = if matches!(op, WAdd(_)) { "wadd_exact" } else { "wmul_exact" };
                    self.push_lemma(
                        st,
                        &format!("bits::{stem}_{}", sfx(w)),
                        vec![(Rel::Rel, args[0].clone()), (Rel::Rel, args[1].clone()), (Rel::Irr, p)],
                        hyps,
                    )?;
                }
            }
            WSub(w) if args.len() == 2 => {
                let c = prim(Le(w), vec![args[1].clone(), args[0].clone()]);
                if let Some(p) = self.prove_cond(st, &c, &hyps.clone())? {
                    self.push_lemma(
                        st,
                        &format!("bits::wsub_exact_{}", sfx(w)),
                        vec![(Rel::Rel, args[0].clone()), (Rel::Rel, args[1].clone()), (Rel::Irr, p)],
                        hyps,
                    )?;
                }
            }
            // (a checked `<<` too: its width obligation is irrelevant, so the
            // lemma's own proof of it converts with the atom's)
            WShl(w) | Shl(w) if args.len() == 2 => {
                let stem = if matches!(op, WShl(_)) { "wshl_exact" } else { "shl_exact" };
                if let Term::Lit { n: k, .. } = &*args[1]
                    && let Some(k) = num_traits::ToPrimitive::to_u32(k)
                    && k >= 1
                    && k < w.bits().unwrap_or(0)
                    && self.env.lookup_global(&format!("bits::{stem}_{}_{k}", sfx(w))).is_some()
                {
                    let c = prim(Le(w), vec![args[0].clone(), mk::lit(w, sandblaster_kernel::prim::max_of(w) >> k)]);
                    if let Some(p) = self.prove_cond(st, &c, &hyps.clone())? {
                        self.push_lemma(
                            st,
                            &format!("bits::{stem}_{}_{k}", sfx(w)),
                            vec![(Rel::Rel, args[0].clone()), (Rel::Irr, p)],
                            hyps,
                        )?;
                    }
                }
            }
            Rem(w) if proofs.len() == 1 => {
                self.push_axiom(st, Schema::RemLt, w, vec![args[0].clone(), args[1].clone(), proofs[0].clone()], hyps)?;
            }
            // A product of two non-literal factors (a non-linear atom),
            // bounded by `mul_mono` (`0 ≤ a ≤ A ∧ 0 ≤ b ≤ B → a·b ≤ A·B`,
            // the kernel's one axiom about such products) for nonnegative
            // factors: `0 ≤ a·b`; `b ≤ a·b` when `1 ≤ a` (and `a ≤ a·b`
            // when `1 ≤ b`): a factor of at least 1 does not decrease the
            // other; `a·b ≤ U·b` for a literal bound `a ≤ U` (and `a·b ≤
            // a·V` for `b ≤ V`), and `a·b ≤ U·V` when both have one. Every
            // instance is linear in the atom and its factors.
            IMul if args.len() == 2 && !args.iter().any(|a| matches!(&**a, Term::Lit { .. })) => {
                let (a, b) = (args[0].clone(), args[1].clone());
                // the facts of the `Nat` functions in the factors (`1 ≤
                // pow2(x)`): a power inside a product is not an atom yet
                self.nat_inner_facts(st, &a, hyps, 0)?;
                self.nat_inner_facts(st, &b, hyps, 0)?;
                let hs = hyps.clone();
                let int = Width::Int;
                let le = |x: &Tm, y: &Tm| prim(Le(int), vec![x.clone(), y.clone()]);
                let (zero, one) = (mk::lit(int, 0u8), mk::lit(int, 1u8));
                let (Some(pa0), Some(pb0)) = (self.prove_cond(st, &le(&zero, &a), &hs)?, self.prove_cond(st, &le(&zero, &b), &hs)?) else {
                    return Ok(());
                };
                let (Some(p00), Some(p01)) = (self.prove_cond(st, &le(&zero, &zero), &hs)?, self.prove_cond(st, &le(&zero, &one), &hs)?) else {
                    return Ok(());
                };
                // (`a ≤ a` needs no hypothesis)
                let (Some(paa), Some(pbb)) = (self.prove_cond(st, &le(&a, &a), &[])?, self.prove_cond(st, &le(&b, &b), &[])?) else {
                    return Ok(());
                };
                // 0·0 ≤ a·b
                self.push_axiom(st, Schema::MulMono, int, vec![zero.clone(), a.clone(), zero.clone(), b.clone(), p00.clone(), pa0.clone(), p00.clone(), pb0.clone()], hyps)?;
                // 1·b ≤ a·b and a·1 ≤ a·b
                if let Some(pa1) = self.prove_cond(st, &le(&one, &a), &hs)? {
                    self.push_axiom(st, Schema::MulMono, int, vec![one.clone(), a.clone(), b.clone(), b.clone(), p01.clone(), pa1, pb0.clone(), pbb.clone()], hyps)?;
                }
                if let Some(pb1) = self.prove_cond(st, &le(&one, &b), &hs)? {
                    self.push_axiom(st, Schema::MulMono, int, vec![a.clone(), a.clone(), one.clone(), b.clone(), pa0.clone(), paa.clone(), p01.clone(), pb1], hyps)?;
                }
                // a·b ≤ U·b, a·b ≤ a·V, a·b ≤ U·V
                let ua = self.int_upper(st, &a, &hs)?;
                let ub = self.int_upper(st, &b, &hs)?;
                if let Some((u, pu)) = &ua {
                    self.push_axiom(st, Schema::MulMono, int, vec![a.clone(), mk::lit(int, u.clone()), b.clone(), b.clone(), pa0.clone(), pu.clone(), pb0.clone(), pbb.clone()], hyps)?;
                }
                if let Some((v, pv)) = &ub {
                    self.push_axiom(st, Schema::MulMono, int, vec![a.clone(), a.clone(), b.clone(), mk::lit(int, v.clone()), pa0.clone(), paa.clone(), pb0.clone(), pv.clone()], hyps)?;
                }
                if let (Some((u, pu)), Some((v, pv))) = (ua, ub) {
                    self.push_axiom(st, Schema::MulMono, int, vec![a, mk::lit(int, u), b, mk::lit(int, v), pa0, pu, pb0, pv], hyps)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// A literal upper bound `a ≤ U` of an `Int` term by linarith: the
    /// smallest provable among the literals of the hypotheses and the range
    /// of a machine-integer cast, with its proof.
    fn int_upper(&mut self, st: &St, a: &Tm, hyps: &[Hyp]) -> R<Option<(BigInt, Tm)>> {
        use PrimOp::*;
        let prim = |op: PrimOp, x: Vec<Tm>| sandblaster_kernel::prim::prim0(op, x);
        let mut cands: Vec<BigInt> = Vec::new();
        for (_, stated) in hyps {
            visit_lits(stated, &mut |n| {
                if n >= &BigInt::from(0) && !cands.contains(n) {
                    cands.push(n.clone());
                }
            });
        }
        if let Term::Prim { op: Cast { from, .. }, .. } = &**a
            && from.bits().is_some()
        {
            cands.push(sandblaster_kernel::prim::max_of(*from));
        }
        cands.sort();
        for c in cands.into_iter().take(16) {
            let Some(g) = self.cond(st, prim(Le(Width::Int), vec![a.clone(), mk::lit(Width::Int, c.clone())]), true)? else { continue };
            if let Some(p) = self.lin_with(st, hyps, &g)? {
                return Ok(Some((c, p)));
            }
        }
        Ok(None)
    }

    /// Slice / array length facts for `fst s` and `seq::len` atoms.
    fn enrich_bounds(&mut self, st: &St, a: &Tm, av: &V, atoms: &[Tm], hyps: &mut Vec<Hyp>) -> R<()> {
        self.enrich_nat_fns(st, a, atoms, hyps)?;
        // the structural size of a recursive spec type is positive
        // (`T::size'_pos`, `elab::recursive`)
        if let Some((def, _)) = as_global_app(av)
            && let Some(name) = self.env.global_name(def)
            && name.ends_with(crate::elab::recursive::SIZE_SUFFIX)
            && let Some(pos) = self.env.lookup_global(&format!("{name}_pos"))
        {
            let (h, args) = crate::elab::items::spine(a);
            if matches!(&*h, Term::Global(g) if *g == def) {
                let pf = apps(mk::global(pos), args.into_iter().map(|x| (Rel::Rel, x)));
                if let Some(ty) = self.infer_irr(st, &pf)? {
                    hyps.push((pf, self.quote(st, &ty)));
                }
            }
        }
        // fst(s) with s : Slice T  ⇒  slice::ok_bound T s
        if let Term::Fst(s) = &**a
            && let Some(g) = self.n.slice_ok_bound
            && let Some(t_elem) = self.slice_elem(st, s)?
        {
            let pf = apps(mk::global(g), [(Rel::Rel, t_elem), (Rel::Rel, s.clone())]);
            if let Some(ty) = self.infer_irr(st, &pf)? {
                hyps.push((pf, self.quote(st, &ty)));
            }
        }
        // seq::len T l with l = fst(snd s) / fst(a)
        if let Some((def, args)) = as_global_app(av)
            && Some(def) == self.n.seq_len
            && args.len() == 2
            && let Arg::Rel(l) = &args[1]
            && let Value::Neu(Neutral { head, spine }) = &**l
            && matches!(spine.last(), Some(Elim::Fst))
        {
            let n = Neutral { head: super::util::clone_head(head), spine: spine.iter().map(super::util::clone_elim).collect() };
            let len = spine.len();
            if len >= 2 && matches!(spine[len - 2], Elim::Snd) {
                let s = prefix(&n, len - 2);
                let s_tm = self.quote(st, &s);
                if let Some(g) = self.n.slice_ok_len
                    && let Some(t_elem) = self.slice_elem(st, &s_tm)?
                {
                    let pf = apps(mk::global(g), [(Rel::Rel, t_elem), (Rel::Rel, s_tm)]);
                    if let Some(ty) = self.infer_irr(st, &pf)? {
                        hyps.push((pf, self.quote(st, &ty)));
                    }
                }
            } else {
                let arr = prefix(&n, len - 1);
                let arr_tm = self.quote(st, &arr);
                if let Some(g) = self.n.array_ok_len
                    && let Some((t_elem, n_len)) = self.array_shape(st, &arr_tm)?
                {
                    let pf = apps(mk::global(g), [(Rel::Rel, t_elem), (Rel::Rel, n_len), (Rel::Rel, arr_tm)]);
                    if let Some(ty) = self.infer_irr(st, &pf)? {
                        hyps.push((pf, self.quote(st, &ty)));
                    }
                }
            }
        }
        Ok(())
    }

    /// The ghost `Nat` functions (`lemmas/nat.core`, §15 S5): for an atom
    /// `pow2(x)`, `log2(x)` or `popcount(x)` the facts `1 ≤ pow2(x)`,
    /// `0 ≤ log2(x)`, `0 ≤ popcount(x)` (true of every `Int`), `popcount(x)
    /// ≤ x` when `0 ≤ x` follows, and for `pow2(log2(y))` the bounds
    /// `pow2(log2(y)) ≤ y < 2·pow2(log2(y))` when `1 ≤ y` follows. A
    /// condition is decided by linear arithmetic over the hypotheses and
    /// the facts of the `Nat` functions inside it.
    fn enrich_nat_fns(&mut self, st: &St, a: &Tm, atoms: &[Tm], hyps: &mut Vec<Hyp>) -> R<()> {
        let Some((f, x)) = self.nat_fn_app(a) else { return Ok(()) };
        self.push_nat_lemma(st, nat_fact(f), &x, None, hyps)?;
        // one step of `popcount` (pe P3/C5): `popcount(x) = x % 2 + popcount(x / 2)`,
        // only when `x % 2` or `popcount(x / 2)` is already an atom: the step
        // relates existing atoms and never creates the next one to step
        // (`popcount(x / 2 / 2)`, …, each with its cuts)
        if f == "ghost::popcount" && !matches!(&*x, Term::Lit { .. }) && self.popcount_step_triggered(&x, atoms) {
            let mut local = hyps.clone();
            self.nat_inner_facts(st, &x, &mut local, 0)?;
            if let Some(g) = self.cond(st, sandblaster_kernel::prim::prim0(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 0u8), x.clone()]), true)?
                && let Some(h) = self.lin_with(st, &local, &g)?
            {
                self.push_nat_lemma(st, "nat::popcount_step", &x, Some(h), hyps)?;
            }
        }
        let (lemma, y, lo) = match f {
            "ghost::popcount" => ("nat::popcount_le", x.clone(), 0u8),
            "ghost::pow2" => match self.nat_fn_app(&x) {
                Some(("ghost::log2", y)) => ("nat::log2_bounds", y, 1u8),
                _ => return Ok(()),
            },
            _ => return Ok(()),
        };
        let mut local = hyps.clone();
        self.nat_inner_facts(st, &y, &mut local, 0)?;
        let Some(g) = self.cond(st, sandblaster_kernel::prim::prim0(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, lo), y.clone()]), true)? else { return Ok(()) };
        if let Some(h) = self.lin_with(st, &local, &g)? {
            self.push_nat_lemma(st, lemma, &y, Some(h), hyps)?;
        }
        Ok(())
    }

    /// Whether `x % 2`, or `popcount(x / 2)`, is among `atoms`.
    fn popcount_step_triggered(&self, x: &Tm, atoms: &[Tm]) -> bool {
        let halves = |t: &Tm, op: PrimOp| matches!(&**t, Term::Prim { op: o, args, .. } if *o == op && args.len() == 2
            && matches!(&*args[1], Term::Lit { n, .. } if *n == BigInt::from(2))
            && self.env.alpha_eq_relevant(&args[0], x, &|p, q| p == q));
        atoms.iter().any(|t| {
            halves(t, PrimOp::IMod) || matches!(self.nat_fn_app(t), Some(("ghost::popcount", y)) if halves(&y, PrimOp::IDiv))
        })
    }

    /// The unconditional facts of the ghost `Nat` function calls inside `t`
    /// (for deciding a condition over them).
    fn nat_inner_facts(&mut self, st: &St, t: &Tm, hyps: &mut Vec<Hyp>, depth: u32) -> R<()> {
        if depth > 8 {
            return Ok(());
        }
        if let Some((f, x)) = self.nat_fn_app(t) {
            self.push_nat_lemma(st, nat_fact(f), &x, None, hyps)?;
            return self.nat_inner_facts(st, &x, hyps, depth + 1);
        }
        let kids: Vec<Tm> = match &**t {
            Term::Prim { args, .. } => args.clone(),
            Term::App { fun, arg, .. } => vec![fun.clone(), arg.clone()],
            _ => vec![],
        };
        for k in kids {
            self.nat_inner_facts(st, &k, hyps, depth + 1)?;
        }
        Ok(())
    }

    /// `(f, x)` if `t` is `f x` for a ghost `Nat` function `f`.
    fn nat_fn_app(&self, t: &Tm) -> Option<(&'static str, Tm)> {
        let Term::App { fun, arg, .. } = &**t else { return None };
        let Term::Global(g) = &**fun else { return None };
        let name = self.env.global_name(*g)?;
        let f = ["ghost::pow2", "ghost::log2", "ghost::popcount"].into_iter().find(|n| **n == *name)?;
        Some((f, arg.clone()))
    }

    /// Adds `lemma x [h]` (a `lemmas/nat.core` lemma) to `hyps`, both
    /// components of a conjunction.
    fn push_nat_lemma(&mut self, st: &St, lemma: &str, x: &Tm, h: Option<Tm>, hyps: &mut Vec<Hyp>) -> R<()> {
        let Some(g) = self.env.lookup_global(lemma) else { return Ok(()) };
        let mut args = vec![(Rel::Rel, x.clone())];
        args.extend(h.map(|h| (Rel::Rel, h)));
        let pf = apps(mk::global(g), args);
        if let Some(ty) = self.infer_irr(st, &pf)? {
            self.push_lin_conclusion_pub(st, pf, &ty, hyps)?;
        }
        Ok(())
    }

    /// If `s` (a term) has type `Slice T`, the term `T`.
    pub fn slice_elem(&mut self, st: &St, s: &Tm) -> R<Option<Tm>> {
        let Some(ty) = self.infer_irr(st, s)? else { return Ok(None) };
        self.slice_elem_of_ty(st, &ty)
    }

    /// `T` if `ty` is (the unfolding of) `Slice T`.
    pub fn slice_elem_of_ty(&mut self, st: &St, ty: &V) -> R<Option<Tm>> {
        let Value::Sigma { snd_rel: Rel::Rel, fst, snd, .. } = &**ty else { return Ok(None) };
        if !matches!(&**fst, Value::IntTy(Width::Usize)) {
            return Ok(None);
        }
        let x = self.env.fresh_var(sandblaster_kernel::term::Lvl(st.depth()), Rel::Rel, fst);
        let Some(inner) = self.inst(snd, vec![x], st.depth() + 1)? else { return Ok(None) };
        let Value::Sigma { snd_rel: Rel::Irr, fst: lt, .. } = &*inner else { return Ok(None) };
        match &**lt {
            Value::Ind { ind, params } if Some(*ind) == self.n.list && params.len() == 1 => Ok(Some(self.quote(st, &params[0]))),
            _ => Ok(None),
        }
    }

    /// If `a` (a term) has type `Array T N`, the terms `(T, N)`.
    fn array_shape(&mut self, st: &St, a: &Tm) -> R<Option<(Tm, Tm)>> {
        let Some(ty) = self.infer_irr(st, a)? else { return Ok(None) };
        // `Array T N` itself (a type left folded, e.g. a spec function's
        // `[u8; 32]` result): its arguments
        if let Some((def, args)) = as_global_app(&ty)
            && self.env.lookup_global("Array") == Some(def)
            && let [Arg::Rel(t), Arg::Rel(n)] = args
        {
            return Ok(Some((self.quote(st, t), self.quote(st, n))));
        }
        let Value::Sigma { snd_rel: Rel::Irr, fst, snd, .. } = &*ty else { return Ok(None) };
        let Value::Ind { ind, params } = &**fst else { return Ok(None) };
        if Some(*ind) != self.n.list || params.len() != 1 {
            return Ok(None);
        }
        let x = self.env.fresh_var(sandblaster_kernel::term::Lvl(st.depth()), Rel::Rel, fst);
        let Some(p) = self.inst(snd, vec![x], st.depth() + 1)? else { return Ok(None) };
        let Some((_, _, rhs)) = as_eq(&p) else { return Ok(None) };
        // rhs = to_int(N)
        let n = match as_prim(rhs) {
            Some((PrimOp::Cast { from: Width::Usize, to: Width::Int }, a)) => a[0].clone(),
            // a literal length (`[u8; 32]`): the cast already evaluated
            _ => match &**rhs {
                Value::Lit { w: Width::Int, n } => return Ok(Some((self.quote(st, &params[0]), mk::lit(Width::Usize, n.clone())))),
                _ => return Ok(None),
            },
        };
        Ok(Some((self.quote(st, &params[0]), self.quote(st, &n))))
    }

    /// Scrutinees that a case split could decide to make linarith succeed:
    /// stuck matches inside atoms and undecided piecewise-axiom conditions.
    pub fn atom_split_candidates(&mut self, st: &St, goal: &V) -> R<Vec<(V, sandblaster_kernel::term::IndId, Vec<V>)>> {
        let mut out = Vec::new();
        let g = if self.lin_goal_form(goal) && self.lin_equiv_sides(goal).is_none() { goal.clone() } else { Rc::new(Value::Ind { ind: self.n.empty_ind, params: vec![] }) };
        let goal_tm = self.quote(st, &g);
        let hyps = self.lin_hyps(st);
        let Some(sys) = self.linearize(st, &hyps, &goal_tm)? else { return Ok(out) };
        for a in &sys.atoms {
            let Some(av) = self.eval(st, a)? else { continue };
            // stuck matches in the atom
            let mut stuck = Vec::new();
            self.collect_stuck(&av, &mut stuck);
            for s in stuck {
                if let super::rewrite::StuckKind::Scrut { ind, params } = s.kind {
                    out.push((s.val, ind, params));
                }
            }
            // piecewise conditions
            if let Term::Prim { op, args, .. } = &**a {
                use PrimOp::*;
                let c = match op {
                    Min(w) | Max(w) => Some(sandblaster_kernel::prim::prim0(Le(*w), vec![args[0].clone(), args[1].clone()])),
                    SatSub(w) => Some(sandblaster_kernel::prim::prim0(Le(*w), vec![args[1].clone(), args[0].clone()])),
                    SatAdd(w) => {
                        let ti = |t: Tm| sandblaster_kernel::prim::prim0(Cast { from: *w, to: Width::Int }, vec![t]);
                        Some(sandblaster_kernel::prim::prim0(
                            Le(Width::Int),
                            vec![
                                sandblaster_kernel::prim::prim0(IAdd, vec![ti(args[0].clone()), ti(args[1].clone())]),
                                mk::lit(Width::Int, sandblaster_kernel::prim::max_of(*w)),
                            ],
                        ))
                    }
                    _ => None,
                };
                if let Some(c) = c
                    && let Some(cv) = self.eval(st, &c)?
                    && as_neu(&cv).is_some()
                {
                    out.push((cv, self.n.bool_ind, vec![]));
                }
            }
        }
        Ok(out)
    }
}

/// The summands of an `Int` sum (`iadd`/`isub`/`ineg`, products with a
/// literal), with their coefficients; literals as `(n, None)`.
fn summands(t: &Tm, coef: &BigInt, out: &mut Vec<(BigInt, Option<Tm>)>, depth: u32) {
    use PrimOp::*;
    if depth > 16 || out.len() > 32 {
        out.push((coef.clone(), Some(t.clone())));
        return;
    }
    match &**t {
        Term::Lit { n, .. } => out.push((coef * n, None)),
        Term::Let { rel: Rel::Irr, body, .. } if !mentions_var0(body) => summands(&shift(body, -1), coef, out, depth + 1),
        Term::Prim { op: IAdd, args, .. } => {
            summands(&args[0], coef, out, depth + 1);
            summands(&args[1], coef, out, depth + 1);
        }
        Term::Prim { op: ISub, args, .. } => {
            summands(&args[0], coef, out, depth + 1);
            summands(&args[1], &-coef, out, depth + 1);
        }
        Term::Prim { op: INeg, args, .. } => summands(&args[0], &-coef, out, depth + 1),
        Term::Prim { op: IMul, args, .. } if matches!(&*args[0], Term::Lit { .. }) => {
            let Term::Lit { n, .. } = &*args[0] else { unreachable!() };
            summands(&args[1], &(coef * n), out, depth + 1)
        }
        Term::Prim { op: IMul, args, .. } if matches!(&*args[1], Term::Lit { .. }) => {
            let Term::Lit { n, .. } = &*args[1] else { unreachable!() };
            summands(&args[0], &(coef * n), out, depth + 1)
        }
        _ => out.push((coef.clone(), Some(t.clone()))),
    }
}

/// `a − b` when the two `Int` terms differ by a literal as linear forms.
fn lin_diff(env: &sandblaster_kernel::api::Env, a: &Tm, b: &Tm) -> Option<BigInt> {
    let (mut pa, mut pb) = (Vec::new(), Vec::new());
    summands(a, &BigInt::from(1), &mut pa, 0);
    summands(b, &BigInt::from(-1), &mut pb, 0);
    let mut konst = BigInt::from(0);
    let mut terms: Vec<(BigInt, Tm)> = Vec::new();
    for (n, x) in pa.into_iter().chain(pb) {
        match x {
            None => konst += n,
            Some(x) => match terms.iter_mut().find(|(_, y)| env.alpha_eq_relevant(y, &x, &|p, q| p == q)) {
                Some((m, _)) => *m += n,
                None => terms.push((n, x)),
            },
        }
    }
    terms.iter().all(|(n, _)| n == &BigInt::from(0)).then_some(konst)
}

/// Does `t` mention the innermost variable (`Idx(0)`)?
fn mentions_var0(t: &Tm) -> bool {
    let mut found = false;
    map_term(t, 0, &mut |x, k| {
        if let Term::Var(i) = &**x
            && i.0 == k
        {
            found = true;
        }
        None
    });
    found
}

/// `t = k·m + c` with `m` the summands whose coefficients are multiples of
/// `k` (divided by `k`, the literal's quotient included) and `c` the rest
/// (the literal's remainder included).
fn split_multiple(t: &Tm, k: &BigInt) -> Option<(Tm, Tm)> {
    let mut parts = Vec::new();
    summands(t, &BigInt::from(1), &mut parts, 0);
    let int = Width::Int;
    let (mut m, mut c): (Vec<Tm>, Vec<Tm>) = (Vec::new(), Vec::new());
    let (mut mq, mut cr) = (BigInt::from(0), BigInt::from(0));
    let term = |n: &BigInt, x: &Tm| if n == &BigInt::from(1) { x.clone() } else { sandblaster_kernel::prim::prim0(PrimOp::IMul, vec![mk::lit(int, n.clone()), x.clone()]) };
    let mut informative = false;
    for (n, x) in &parts {
        match x {
            None => {
                // floor division (`k > 0`)
                let mut r = n % k;
                if r < BigInt::from(0) {
                    r += k;
                }
                let q = (n - &r) / k;
                mq += q;
                cr += r;
            }
            Some(x) if (n % k) == BigInt::from(0) => {
                informative = true;
                m.push(term(&(n / k), x));
            }
            Some(x) => c.push(term(n, x)),
        }
    }
    // (nothing multiple of `k`: the reading `x = k·0 + x`, useful when
    // `0 ≤ x < k`, e.g. the carry of a shift that does not overflow)
    let _ = informative;
    let sum = |mut xs: Vec<Tm>, lit: BigInt| -> Tm {
        if lit != BigInt::from(0) || xs.is_empty() {
            xs.push(mk::lit(int, lit));
        }
        let mut it = xs.into_iter();
        let first = it.next().unwrap();
        it.fold(first, |a, b| sandblaster_kernel::prim::prim0(PrimOp::IAdd, vec![a, b]))
    };
    Some((sum(m, mq), sum(c, cr)))
}

/// [`split_multiple`], and — when the remainder part has a non-constant
/// summand — the same with the remainder moved by `k` either way.
fn split_multiple_shifts(t: &Tm, k: &BigInt) -> Vec<(Tm, Tm)> {
    let Some((m, c)) = split_multiple(t, k) else { return vec![] };
    let int = Width::Int;
    let mut out = vec![(m.clone(), c.clone())];
    // (only a dividend with a constant summand: its constant was folded
    // into the quotient, which may be off by one `k` for the remainder's
    // bounds; a sum of atoms alone gives no other reading)
    let mut parts = Vec::new();
    summands(t, &BigInt::from(1), &mut parts, 0);
    let has_const = parts.iter().any(|(n, x)| x.is_none() && n != &BigInt::from(0));
    if has_const && !matches!(&*c, Term::Lit { .. }) {
        let add = |x: &Tm, n: BigInt| sandblaster_kernel::prim::prim0(PrimOp::IAdd, vec![x.clone(), mk::lit(int, n)]);
        out.push((add(&m, BigInt::from(1)), add(&c, -k.clone())));
        out.push((add(&m, BigInt::from(-1)), add(&c, k.clone())));
    }
    out
}

/// The unconditional fact of a ghost `Nat` function (`lemmas/nat.core`).
fn nat_fact(f: &str) -> &'static str {
    match f {
        "ghost::pow2" => "nat::pow2_pos",
        "ghost::log2" => "nat::log2_nonneg",
        _ => "nat::popcount_nonneg",
    }
}

/// The width suffix of lemma names (`u64`).
fn sfx(w: Width) -> &'static str {
    sandblaster_kernel::prim::width_suffix(w)
}

/// `Value::Lit` helper.
pub fn lit_v(w: Width, n: impl Into<BigInt>) -> V {
    Rc::new(Value::Lit { w, n: n.into() })
}

/// A bare `Head::Var` value at level `l` with an empty spine?
pub fn is_var_level(v: &V, l: u32) -> bool {
    matches!(&**v, Value::Neu(Neutral { head: Head::Var(x), spine }) if x.0 == l && spine.is_empty())
}

/// [`simplex::certificate`], or the feasible point of the first problem
/// without one (`None`: the search gave up).
fn certificate_or_point(sys: &LinSystem) -> Result<Vec<sandblaster_kernel::term::Rat>, Option<Vec<Option<super::rat::Q>>>> {
    let mut out = Vec::new();
    for p in &sys.problems {
        let c = simplex::farkas_staged_point(p, sys.atoms.len())?;
        out.extend(c.iter().map(super::rat::Q::to_rat));
    }
    Ok(out)
}

/// Visit the integer literals of a term.
fn visit_lits(t: &Tm, f: &mut dyn FnMut(&BigInt)) {
    map_term(t, 0, &mut |x, _| {
        if let Term::Lit { n, .. } = &**x {
            f(n);
        }
        None
    });
}

