//! Lanes of the hardware models (DESIGN.md §9.2, §16.4).
//!
//! A vector value is its model's `Array(lane, n)`, lane 0 first, and every
//! intrinsic model is a `def[intrinsic]` global, which the evaluator
//! unfolds only on closed data (§5.6): on symbolic vectors
//! `vaddq_u32(a, b)` stays folded, and so does its lane `k`, `seq::index
//! T (fst (vaddq_u32 a b)) k _ _` (what `array::index` of a vector
//! evaluates to). Only `BvRefl` unfolded it, so a lane fact that needs
//! arithmetic or a hypothesis (`(x & 15)[k] < 16`, a lane sum exact under
//! a bound on the lanes) had no proof.
//!
//! **Lane step.** A model application read at a literal lane is unfolded
//! once (`Delta(m; args) : Eq(Array T n, m args, body)`, the kernel's
//! unfolding equation of any definition, [`Engine::delta_eq`]) and the
//! target or fact is rewritten with that equation. The models are
//! lane-wise maps (`aarch64::map2_u32x4 f a b`, `u8x16(..)` of per-lane
//! expressions), so the unfolded body is the vector of its lanes and the
//! evaluator's direct indexing reads lane `k`: `vaddq_u32(a, b)[2]` becomes
//! `a[2] +w b[2]`, a scalar term for linarith, the bit lemmas and the
//! rest of `auto`. A model nested in a lane (`vandq_u8(vaddq_u8(a, b),
//! c)[k]`) is reached by the next step. A lane read at a symbolic index
//! `i < n` is split by the finite enumeration of `i` ([`super::cases`]),
//! each case a literal lane.
//!
//! Only reads at a literal lane trigger a step (an unfolded model whose
//! lanes are all compared by `==` is `BvRefl`'s case, which needs no
//! unfolding), and a step must expose the lanes (the body evaluates to a
//! pair); everything is a `transport` along a `Delta` equation, checked
//! by the kernel as any rewrite. A step whose result reads back with a
//! hidden proof is not taken ([`Engine::lane_result_stated`]).
//!
//! **The lane closer** ([`Engine::lane_split`], C8's second slice). An
//! equation between two vectors of which one is made by a hardware model
//! (`vqtbl1q_u8(t, idx) == tbl_lanes(t, idx)`, a whole `mul_128`) is proven
//! lane by lane, without searching:
//!
//! 1. every model of both sides is unfolded at once (its global replaced by
//!    its body, which `BvRefl` equates with the folded side), so each side
//!    is the vector of its lanes;
//! 2. an array the sides read that is not a variable (a table row
//!    `lut.lo[0]`) is generalized to one, which the kernel introduces as
//!    the array of its lanes (§5.9), so a lane a model reads from the row
//!    and the same lane read directly are one term;
//! 3. each lane's reads of vector lanes (`x[k]`) are abstracted: the lanes
//!    of a lane-wise computation then have one shape, proven once
//!    (`λ x.. . p`) and applied to each lane's reads;
//! 4. a shape is decided by a case analysis on its conditions — a table
//!    lookup's index test `k < 16` (TBL) or `m & 128 != 0` (PSHUFB): one
//!    that linear arithmetic decides (`(x & 15) < 16`) is rewritten to its
//!    value, an undecided one is split; the condition is generalized where
//!    the lane tests it, the dependent match's path equation becoming the
//!    motive's equation binder, so the arm's index proof keeps its type
//!    ([`Engine::lane_decide`]); a lane with no condition left closes by
//!    conversion or `BvRefl`;
//! 5. the lanes are joined into the vectors' equation by one congruence
//!    step per lane and `array::ext`.
//!
//! The proof is checked by the kernel like any other, and each lane shape's
//! proof as soon as it is built (a proof slot left ill-typed is first
//! re-proved from the context, [`super::repair`]); a lane that does not
//! close leaves the target to the rest of the search.

use std::rc::Rc;

use sandblaster_kernel::term::{DefKind, GlobalId, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Elim, Head, Neutral, V, Value};

use super::rewrite::{Stuck, StuckKind};
use super::search::{Cont, Engine, R};
use super::state::{Origin, St};
use super::util::*;

/// Lane steps on one search path (a lane step unfolds one model
/// application, all its occurrences).
pub const MAX_LANE_STEPS: u32 = 32;

/// The most lanes the lane closer splits an equation into (64 byte lanes:
/// an AVX-512 vector, a 64-byte chunk).
pub const MAX_SPLIT_LANES: u64 = 64;

/// Undecided conditions split per lane by the lane closer (at most `2^k`
/// cases per lane).
pub const MAX_LANE_SPLITS: u32 = 4;

impl Engine<'_> {
    /// The model applications read at a literal lane in a value
    /// (`seq::index T (fst (m args)) k _ _`, `m` a fully applied
    /// `def[intrinsic]` global), outermost first.
    pub fn lane_models(&self, v: &V) -> Vec<(V, GlobalId)> {
        let mut stuck = Vec::new();
        self.collect_stuck(v, &mut stuck);
        self.lane_models_of(&stuck)
    }

    /// [`Engine::lane_models`] among a value's stuck subterms
    /// ([`Engine::collect_stuck`]: a lane read is a folded `seq::index`).
    pub fn lane_models_of(&self, stuck: &[Stuck]) -> Vec<(V, GlobalId)> {
        let Some(index) = self.n.seq_index else { return Vec::new() };
        let mut out: Vec<(V, GlobalId)> = Vec::new();
        let mut lists: Vec<*const Value> = Vec::new();
        // one entry per model application (a step rewrites all its
        // occurrences): the lanes of one vector are separate reads of the
        // same application, its relevant arguments shared
        let mut apps: Vec<(GlobalId, Vec<*const Value>)> = Vec::new();
        for s in stuck {
            if let StuckKind::App { def } = s.kind
                && def == index
                && let Value::Neu(Neutral { head: Head::Global { args, .. }, spine }) = &*s.val
                && spine.is_empty()
                && args.len() == 5
                && let (Arg::Rel(l), Arg::Rel(i)) = (&args[1], &args[2])
                && lit(i).is_some()
                && let Value::Neu(n @ Neutral { head: Head::Global { def: m, args: margs }, spine: ms }) = &**l
                && matches!(ms.as_slice(), [Elim::Fst])
                && self.env.global_kind(*m) == Some(DefKind::Intrinsic)
                && self.env.global_arity(*m) == Some(margs.len() as u32)
                && !lists.contains(&std::rc::Rc::as_ptr(l))
            {
                lists.push(std::rc::Rc::as_ptr(l));
                let rel: Vec<*const Value> = margs.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(std::rc::Rc::as_ptr(v)) } else { None }).collect();
                if apps.iter().any(|(d, r)| d == m && *r == rel) {
                    continue;
                }
                apps.push((*m, rel));
                out.push((prefix(n, 0), *m));
            }
        }
        out
    }

    /// The unfolding equation of a model application, when its body is the
    /// vector of its lanes: `(proof, type, lhs, rhs)` of
    /// [`Engine::delta_eq`].
    fn lane_unfolding(&mut self, st: &St, app: &V, def: GlobalId) -> R<Option<(sandblaster_kernel::term::Tm, V, V, V)>> {
        if !self.cfg.mode.allows_delta(def) {
            return Ok(None);
        }
        let Some((dt, rt, l, rhs)) = self.delta_eq(st, app, def)? else { return Ok(None) };
        if !matches!(&*rhs, Value::Pair { .. }) {
            return Ok(None);
        }
        // a body whose read-back hides proofs cannot be stated
        if crate::elab::tm::has_erased(&st.quote_at(self.env, &rhs, &rt)) {
            return Ok(None);
        }
        Ok(Some((dt, rt, l, rhs)))
    }

    /// One lane step on the target: unfold a model application read at a
    /// literal lane.
    pub fn lane_step(&mut self, st: &mut St, t: &V) -> R<Option<(V, Cont)>> {
        if st.lanes >= MAX_LANE_STEPS {
            return Ok(None);
        }
        for (app, def) in self.lane_models(t) {
            let Some((dt, rt, l, rhs)) = self.lane_unfolding(st, &app, def)? else { continue };
            if let Some(res) = self.rewrite(st, t, &rt, &l, &rhs, dt)? {
                if !self.lane_result_stated(st, &res.0, def) {
                    continue;
                }
                st.lanes += 1;
                self.note("unfold a hardware model at a lane");
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    /// One lane step on a fact `h : ty` whose lane reads are `lanes`
    /// ([`Engine::lane_models_of`] its stuck subterms): the rewritten fact
    /// and its proof.
    pub fn lane_step_prop(&mut self, st: &St, ty: &V, h: &sandblaster_kernel::term::Tm, lanes: Vec<(V, GlobalId)>) -> R<Option<(V, sandblaster_kernel::term::Tm)>> {
        for (app, def) in lanes {
            let Some((dt, rt, l, rhs)) = self.lane_unfolding(st, &app, def)? else { continue };
            if let Some(res) = self.rewrite_prop(st, ty, h, &rt, &l, &rhs, dt)? {
                if !self.lane_result_stated(st, &res.0, def) {
                    continue;
                }
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    /// Whether the proposition a lane step produced can be stated: its
    /// read-back holds no `Erased` placeholder; any proof of one that does
    /// carries the placeholder, which the kernel refuses, so the step is
    /// not taken and the search goes on without it. (A lane fed to a
    /// dependent match — a table lookup's `if k < 16 as .h`, PSHUFB's
    /// reference — read back with one: the index proof of the match's arm
    /// is carried along the step's equation, and the proof closure read
    /// the unfolded vector back as an untyped pair. The read-back now types
    /// it from the transport, `super::util::kernel_friendly`.)
    fn lane_result_stated(&mut self, st: &St, p: &V, def: GlobalId) -> bool {
        let q = self.quote(st, p);
        if crate::elab::tm::has_erased(&q) {
            if self.trace {
                eprintln!("[auto] no lane step on `{}`: the result's read-back hides a proof", self.env.global_name(def).as_deref().unwrap_or("?"));
            }
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// The lane closer.
// ---------------------------------------------------------------------------

impl Engine<'_> {
    /// The lane closer (see the module docs; DESIGN.md §16.4, C8's second
    /// slice): an equation `Eq(Array T N, a, b)` between word vectors (`2 ≤
    /// N ≤` [`MAX_SPLIT_LANES`]) of which a side is made by a hardware model,
    /// proven lane by lane. The proof is
    ///
    /// ```text
    /// let lane_j : Π(x.. : T..). Eq(T, l_j[x..], r_j[x..]) = λ x... p_j;   (each lane shape)
    /// let a' : Array T N = a';  let b' : Array T N = b';                    (the unfolded sides)
    /// a = a' (BvRefl) = b' (array::ext, one Cons congruence per lane: lane_j reads..) = b (BvRefl)
    /// ```
    ///
    /// under `let rows : Π(row..). .. = λ row... ..; rows lut.lo[0] ..` when
    /// arrays read by the sides were generalized. Everything is checked by
    /// the kernel (the goal's proof); a lane that does not close leaves the
    /// target to the rest of the search. Full reasoning only (no restricted
    /// closing statement unfolds a model or splits), and only where the
    /// search uses `BvRefl` by itself ([`super::AutoConfig::auto_bvrefl`]):
    /// the bridges and the lanes' last step are `BvRefl`, which the law
    /// rules' echo prover (LR6 (a), "no `BvRefl`") and the completeness
    /// discharges do without.
    pub fn lane_split(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        if self.cfg.mode != super::Mode::Full || !self.cfg.auto_bvrefl {
            return Ok(None);
        }
        self.settle();
        let steps0 = self.b.steps;
        let p = self.lane_split_sides(st, t)?;
        if self.trace
            && let Some(p) = &p
        {
            self.settle();
            let used = steps0.saturating_sub(self.b.steps);
            // (tracing only: the kernel's verdict on the proof as built, and
            // its cost; the goal's own check comes later)
            let mut b = sandblaster_kernel::value::Budget { steps: 2_000_000_000 };
            let r = self.env.check(&st.ctx, p, t, &mut b);
            eprintln!(
                "[auto] lane split: proven in {used} steps (proof {} nodes; the kernel's check {} steps: {})",
                crate::elab::tm::size_capped(p, 100_000_000),
                2_000_000_000 - b.steps,
                r.map_or_else(|e| e.to_string().chars().take(300).collect::<String>(), |_| "accepted".into())
            );
        }
        Ok(p)
    }

    /// [`Engine::lane_split`] after its mode checks.
    fn lane_split_sides(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        let Some((aty, l, r)) = as_eq(t) else { return Ok(None) };
        let (aty, l, r) = (aty.clone(), l.clone(), r.clone());
        // a side made by a hardware model (its value is a model application,
        // or the vector of lanes read from one); every other array equation
        // (a digest, a buffer) is left to the rest of the search untouched
        if !self.model_made(&l) && !self.model_made(&r) {
            return Ok(None);
        }
        let Some((elem, n)) = self.word_vector_shape(st, &aty)? else { return Ok(None) };
        let ty_tm = self.quote(st, &aty);
        let (l_tm, r_tm) = (self.quote_typed(st, &l, &aty), self.quote_typed(st, &r, &aty));
        if [&ty_tm, &l_tm, &r_tm].iter().any(|x| crate::elab::tm::has_erased(x)) {
            return Ok(None);
        }
        // the arrays the sides read that are not variables (a row of a
        // table, `lut.lo[0]`, `rows[1]`): generalized to variables, which
        // the kernel introduces as the arrays of their lanes (§5.9), so a
        // lane a model reads from the row and the same lane read directly
        // are one term; the proof is `(λ row.. . p) lut.lo[0] ..`
        let atoms = self.array_atoms(st, &[&l_tm, &r_tm])?;
        if !atoms.is_empty() {
            let m = atoms.len() as u32;
            let mut c = st.child();
            for (j, (_, aty_j)) in atoms.iter().enumerate() {
                c.push_lam(self.env, Rc::from(format!("row{j}")), Rel::Rel, aty_j.clone(), false);
            }
            let terms: Vec<Tm> = atoms.iter().map(|(a, _)| a.clone()).collect();
            let (lg, rg) = (self.abstract_terms(&l_tm, &terms), self.abstract_terms(&r_tm, &terms));
            let tyg = shift(&ty_tm, m as i64);
            let (Some(lv), Some(rv)) = (self.eval(&c, &lg)?, self.eval(&c, &rg)?) else { return Ok(None) };
            self.note(format!("lane split: {m} array(s) read by the sides generalized to variables"));
            let Some(p) = self.lane_split_terms(&c, &elem, n, &tyg, &lg, &rg, &lv, &rv)? else { return Ok(None) };
            // `let rows : Π(row..). Eq(ty, l[row..], r[row..]) = λ row... p;
            // rows lut.lo[0] ..`: the statement as written here, not as the
            // kernel would infer it (inside the λ a row is eta-expanded, and
            // `fst(row)` read back as its lanes no longer converts with
            // `fst(lut.lo[0])` once a row that is not a variable is put in)
            let f = c.finish(p);
            let mut stmt = mk::eq(tyg, lg, rg);
            for (j, (_, aty_j)) in atoms.iter().enumerate().rev() {
                stmt = mk::pi(&format!("row{j}"), Rel::Rel, shift(&self.quote(st, aty_j), j as i64), stmt);
            }
            let res = mk::let_("rows", Rel::Rel, stmt, f, mk::apps(mk::var(0), terms.iter().map(|a| (Rel::Rel, shift(a, 1)))));
            return Ok(Some(res));
        }
        self.lane_split_terms(st, &elem, n, &ty_tm, &l_tm, &r_tm, &l, &r)
    }

    /// [`Engine::lane_split`] on the sides `l_tm`, `r_tm` (terms at `st`'s
    /// depth, of type `ty_tm` = `Array elem n`) with their values `l`, `r`.
    #[allow(clippy::too_many_arguments)]
    fn lane_split_terms(&mut self, st: &St, elem: &V, n: u64, ty_tm: &Tm, l_tm: &Tm, r_tm: &Tm, l: &V, r: &V) -> R<Option<Tm>> {
        let (Some(list), Some(index), Some(drop_g), Some(ext)) =
            (self.n.list, self.env.lookup_global("array::index"), self.env.lookup_global("seq::drop"), self.env.lookup_global("array::ext"))
        else {
            return Ok(None);
        };
        let (lu, l_models) = self.unfold_models(l_tm);
        let (ru, r_models) = self.unfold_models(r_tm);
        if !l_models && !r_models {
            return Ok(None);
        }
        // the unfolded sides: the vectors of their lanes
        let lv = if l_models { self.eval(st, &lu)? } else { Some(l.clone()) };
        let rv = if r_models { self.eval(st, &ru)? } else { Some(r.clone()) };
        let (Some(lv), Some(rv)) = (lv, rv) else { return Ok(None) };
        let (Some(ls), Some(rs)) = (self.explicit_lanes(&lv, list, n), self.explicit_lanes(&rv, list, n)) else {
            self.note("lane split: a side does not unfold to the vector of its lanes");
            self.lane_side_folded = true;
            return Ok(None);
        };
        self.note(format!("split a vector equation into its {n} lanes"));
        // the lanes' terms, each lane's reads of the lanes of vectors (`x[k]`)
        // abstracted: lanes of one shape (a lane-wise computation's lanes are
        // one scalar function of their own inputs) are proven once
        let elem_tm = self.quote(st, elem);
        let mut shapes: Vec<LaneShape> = Vec::new();
        let mut lanes: Vec<(usize, Vec<Tm>)> = Vec::with_capacity(n as usize);
        for k in 0..n as usize {
            let (lk, rk) = (st.quote_at(self.env, &ls[k], elem), st.quote_at(self.env, &rs[k], elem));
            if crate::elab::tm::has_erased(&lk) || crate::elab::tm::has_erased(&rk) {
                return Ok(None);
            }
            let reads = self.lane_reads(&[&lk, &rk]);
            let read_tms: Vec<Tm> = reads.iter().map(|(t, _)| t.clone()).collect();
            let (la, ra) = (self.abstract_terms(&lk, &read_tms), self.abstract_terms(&rk, &read_tms));
            let same = |sh: &LaneShape| {
                sh.types.len() == reads.len()
                    && sh.types.iter().zip(&reads).all(|(a, (_, b))| self.env.alpha_eq_relevant(a, b, &|x, y| x == y))
                    && self.env.alpha_eq_relevant(&sh.l, &la, &|x, y| x == y)
                    && self.env.alpha_eq_relevant(&sh.r, &ra, &|x, y| x == y)
            };
            let j = match shapes.iter().position(same) {
                Some(j) => j,
                None => {
                    shapes.push(LaneShape { types: reads.iter().map(|(_, t)| t.clone()).collect(), l: la, r: ra, proof: None });
                    shapes.len() - 1
                }
            };
            lanes.push((j, read_tms));
        }
        // each shape: `λ(x.. : T..). p` with `p : Eq(T, l[x..], r[x..])`
        for (j, sh) in shapes.iter_mut().enumerate() {
            let m = sh.types.len() as u32;
            let mut c = st.child();
            for (i, ty) in sh.types.iter().enumerate() {
                let Some(tyv) = self.eval(&c, &shift(ty, i as i64))? else { return Ok(None) };
                c.push_lam(self.env, Rc::from(format!("x{i}")), Rel::Rel, tyv, false);
            }
            let Some(lane) = self.eval(&c, &mk::eq(shift(&elem_tm, m as i64), sh.l.clone(), sh.r.clone()))? else { return Ok(None) };
            let first = lanes.iter().position(|(s, _)| *s == j).unwrap_or(0);
            let Some(p) = self.lane_decide(&mut c, &lane, MAX_LANE_SPLITS)? else {
                self.note(format!("lane split: lane {first} not decided"));
                return Ok(None);
            };
            let p = c.finish(p);
            // checked here: a shape whose proof the kernel refuses leaves the
            // target to the rest of the search, rather than failing the
            // check of the goal's whole proof
            let Some(stmt) = self.eval(st, &shape_statement(&elem_tm, sh))? else { return Ok(None) };
            self.settle();
            let mut r = self.env.check(&st.ctx, &p, &stmt, self.b);
            let mut p = p;
            if let Err(e) = &r {
                if self.trace {
                    eprintln!("[auto] lane split: lane {first}'s shape proof: {}", e.to_string().chars().take(1000).collect::<String>());
                }
                // a proof slot left ill-typed (a form of a read the shape's
                // abstraction did not see): re-proved from the context, as
                // the goal's own check would ([`super::repair`])
                let mut rb = sandblaster_kernel::value::Budget { steps: self.b.steps.min(20_000_000) };
                let start = rb.steps;
                let (p2, n) = super::repair::repair_validated(self.env, &st.ctx, &p, &mut rb);
                self.b.steps = self.b.steps.saturating_sub(start - rb.steps);
                if n > 0 {
                    self.settle();
                    r = self.env.check(&st.ctx, &p2, &stmt, self.b);
                    p = p2;
                }
            }
            if self.k_err(r)?.is_none() {
                self.note(format!("lane split: the proof of lane {first} does not check"));
                return Ok(None);
            }
            sh.proof = Some(p);
        }
        if shapes.len() > 1 {
            self.note(format!("lane split: {} lane shapes", shapes.len()));
        }
        // under `let s_j : Π(x..). Eq(T, l_j, r_j) = λ x... p_j; .. let a' : ty =
        // lu; let b' : ty = ru;` (`s` shapes, then the two sides)
        let ns = shapes.len() as i64;
        let dd = |x: &Tm| shift(x, ns + 2);
        let (ty2, l2, r2) = (dd(ty_tm), dd(l_tm), dd(r_tm));
        let elem_tm = dd(&elem_tm);
        let n_tm = mk::lit(Width::Usize, n);
        let (a, b) = (mk::var(1), mk::var(0));
        let list_ty = mk::ind(list, vec![elem_tm.clone()]);
        let lane_of = |v: &Tm, k: u64| {
            mk::apps(mk::global(index), [(Rel::Rel, elem_tm.clone()), (Rel::Rel, n_tm.clone()), (Rel::Rel, v.clone()), (Rel::Rel, mk::lit(Width::Usize, k)), (Rel::Irr, mk::refl(self.bool_ty(), mk::bool_lit(self.n.bool_ind, true)))])
        };
        let tail_of = |v: &Tm, k: u64| mk::apps(mk::global(drop_g), [(Rel::Rel, elem_tm.clone()), (Rel::Rel, mk::fst(v.clone())), (Rel::Rel, mk::lit(Width::Int, k))]);
        let cons = |x: Tm, xs: Tm| mk::ctor(list, 1, vec![elem_tm.clone()], vec![x, xs]);
        // lane `k`'s proof: its shape applied to its reads
        let lane_proof = |k: usize| {
            let (j, reads) = &lanes[k];
            mk::apps(mk::var((ns - 1 - *j as i64 + 2) as u32), reads.iter().map(|t| (Rel::Rel, dd(t))))
        };
        // `Eq(List T, drop(fst a', k), drop(fst b', k))` from lane `k` on
        let mut chain = mk::refl(list_ty.clone(), mk::ctor(list, 0, vec![elem_tm.clone()], vec![]));
        for k in (0..n).rev() {
            let (x, y, xs, ys) = (lane_of(&a, k), lane_of(&b, k), tail_of(&a, k + 1), tail_of(&b, k + 1));
            let s1 = |t: &Tm| shift(t, 1);
            // Cons(x, xs) = Cons(x, ys), along the tails' equation
            let tails = Rc::new(Term::Transport {
                ty: list_ty.clone(),
                lhs: xs.clone(),
                rhs: ys.clone(),
                eq: chain,
                motive: mk::eq(s1(&list_ty), cons(s1(&x), s1(&xs)), cons(s1(&x), mk::var(0))),
                val: mk::refl(list_ty.clone(), cons(x.clone(), xs.clone())),
            });
            // Cons(x, xs) = Cons(y, ys), along the lane's equation
            chain = Rc::new(Term::Transport {
                ty: elem_tm.clone(),
                lhs: x.clone(),
                rhs: y,
                eq: lane_proof(k as usize),
                motive: mk::eq(s1(&list_ty), cons(s1(&x), s1(&xs)), cons(mk::var(0), s1(&ys))),
                val: tails,
            });
        }
        let ext_p = mk::apps(mk::global(ext), [(Rel::Rel, elem_tm.clone()), (Rel::Rel, n_tm), (Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Irr, chain)]);
        // the bridges: `l = a'` and `r = b'` (`BvRefl` where a side's models
        // were unfolded, the let's own value otherwise)
        let bridge = |side: &Tm, v: &Tm, models: bool| if models { Rc::new(Term::BvRefl { ty: ty2.clone(), lhs: side.clone(), rhs: v.clone() }) } else { mk::refl(ty2.clone(), v.clone()) };
        let (bl, br) = (bridge(&l2, &a, l_models), bridge(&r2, &b, r_models));
        let towards = |eq: Tm, from: &Tm, to: &Tm, val: Tm| {
            Rc::new(Term::Transport { ty: ty2.clone(), lhs: from.clone(), rhs: to.clone(), eq, motive: mk::eq(shift(&ty2, 1), shift(&l2, 1), mk::var(0)), val })
        };
        // l = a' = b' = r
        let step = towards(ext_p, &a, &b, bl);
        let br_sym = self.sym(&ty2, &r2, &b, &br);
        let mut res = towards(br_sym, &b, &r2, step);
        res = mk::let_("a'", Rel::Rel, shift(ty_tm, ns), shift(&lu, ns), mk::let_("b'", Rel::Rel, shift(ty_tm, ns + 1), shift(&ru, ns + 1), res));
        let elem0 = self.quote(st, elem);
        for (j, sh) in shapes.iter().enumerate().rev() {
            let Some(p) = &sh.proof else { return Ok(None) };
            res = mk::let_(&format!("lane{j}"), Rel::Rel, shift(&shape_statement(&elem0, sh), j as i64), shift(p, j as i64), res);
        }
        Ok(Some(res))
    }

    /// The reads of a lane of a vector variable at a literal lane
    /// (`seq::index T (fst x) k _ _`, `x` a variable of the context) in the
    /// terms, each once, with their element types `T` (terms at the depth of
    /// the terms' context).
    fn lane_reads(&self, terms: &[&Tm]) -> Vec<(Tm, Tm)> {
        let Some(index) = self.n.seq_index else { return Vec::new() };
        let mut out: Vec<(Tm, Tm)> = Vec::new();
        let mut seen: FxSet<(*const Term, u32)> = FxSet::default();
        fn go(t: &Tm, k: u32, index: GlobalId, env: &sandblaster_kernel::api::Env, out: &mut Vec<(Tm, Tm)>, seen: &mut FxSet<(*const Term, u32)>) {
            if !seen.insert((Rc::as_ptr(t), k)) {
                return;
            }
            super::meter::spend(1);
            if let Term::App { .. } = &**t {
                let (h, args) = crate::elab::items::spine(t);
                if matches!(&*h, Term::Global(g) if *g == index)
                    && args.len() == 5
                    && matches!(&*args[1], Term::Fst(x) if matches!(&**x, Term::Var(i) if i.0 >= k))
                    && matches!(&*args[2], Term::Lit { .. })
                    && !crate::elab::tm::any_node_depth(&args[0], &mut |n, depth| matches!(n, Term::Var(i) if i.0 >= depth && i.0 - depth < k))
                {
                    let read = shift(t, -(k as i64));
                    if !out.iter().any(|(r, _)| env.alpha_eq_relevant(r, &read, &|x, y| x == y)) {
                        out.push((read, shift(&args[0], -(k as i64))));
                    }
                    return;
                }
            }
            crate::elab::tm::children_depth(t, &mut |c, b| go(c, k + b, index, env, out, seen));
        }
        for t in terms {
            go(t, 0, index, self.env, &mut out, &mut seen);
        }
        out
    }

    /// The arrays the terms read (as a model's argument, or through `fst`)
    /// that are not variables, not explicit arrays and not model
    /// applications, with their types `Array T N` (literal `N`, at most the
    /// kernel's eta bound): outermost ones only, each once, at `st`'s depth
    /// (none under a binder of the terms).
    fn array_atoms(&mut self, st: &St, terms: &[&Tm]) -> R<Vec<(Tm, V)>> {
        let mut cands: Vec<Tm> = Vec::new();
        let mut seen: FxSet<(*const Term, u32)> = FxSet::default();
        for t in terms {
            self.atom_candidates(t, 0, false, &mut cands, &mut seen);
        }
        let mut out: Vec<(Tm, V)> = Vec::new();
        for c in cands {
            if out.iter().any(|(a, _)| self.env.alpha_eq_relevant(a, &c, &|x, y| x == y)) {
                continue;
            }
            let Some(ty) = self.infer_irr(st, &c)? else { continue };
            if self.array_len(st, &ty)?.is_none_or(|n| n > 256) {
                continue;
            }
            out.push((c, ty));
            if out.len() >= 16 {
                break;
            }
        }
        Ok(out)
    }

    /// Candidates of [`Engine::array_atoms`] in `t` at local depth `k`
    /// (`arg`: `t` is read as an array, a model's argument or under `fst`).
    fn atom_candidates(&self, t: &Tm, k: u32, arg: bool, out: &mut Vec<Tm>, seen: &mut FxSet<(*const Term, u32)>) {
        if !seen.insert((Rc::as_ptr(t), k)) {
            return;
        }
        super::meter::spend(1);
        let model_app = |x: &Tm| {
            let (h, _) = crate::elab::items::spine(x);
            matches!(&*h, Term::Global(g) if self.env.global_kind(*g) == Some(DefKind::Intrinsic))
        };
        if arg && !matches!(&**t, Term::Var(_) | Term::Pair { .. } | Term::Ctor { .. } | Term::Lit { .. }) && !model_app(t) {
            // closed under the terms' own binders
            if !crate::elab::tm::any_node_depth(t, &mut |n, depth| matches!(n, Term::Var(i) if i.0 >= depth && i.0 - depth < k)) {
                out.push(shift(t, -(k as i64)));
                return;
            }
        }
        match &**t {
            Term::Fst(p) => self.atom_candidates(p, k, true, out, seen),
            Term::App { .. } if model_app(t) => {
                let (_, args) = crate::elab::items::spine(t);
                for a in &args {
                    self.atom_candidates(a, k, true, out, seen);
                }
            }
            _ => crate::elab::tm::children_depth(t, &mut |c, b| self.atom_candidates(c, k + b, false, out, seen)),
        }
    }

    /// `t` with each occurrence of `atoms[j]` (terms of `t`'s context,
    /// compared up to proofs) replaced by the variable of the `j`-th of
    /// `atoms.len()` binders pushed after that context (`t` shifted under
    /// them).
    ///
    /// An atom that reads an element at a literal index (`seq::index T (fst
    /// x) k _ _`, how a value reads back) also matches the elaborated form
    /// of the same read (`array::index T N x k _`), which proofs quoted by
    /// substitution keep (the bound proof of a reference's `t[x[0] & 15]`
    /// states `x[0]` so): a proof left mentioning the read would no longer
    /// have the type its position expects.
    fn abstract_terms(&self, t: &Tm, atoms: &[Tm]) -> Tm {
        let env = self.env;
        let m = atoms.len() as u32;
        let parts: Vec<Option<(Tm, num_bigint::BigInt)>> = atoms.iter().map(|a| self.read_parts(a)).collect();
        let mut at: Vec<Vec<Tm>> = vec![Vec::new(); atoms.len()];
        let mut arr: Vec<Vec<Option<Tm>>> = vec![Vec::new(); atoms.len()];
        map_term(&shift(t, m as i64), 0, &mut |x, k| {
            let xp = self.read_parts(x);
            for (j, a) in atoms.iter().enumerate() {
                while at[j].len() <= k as usize {
                    let n = at[j].len() as i64;
                    at[j].push(shift(a, m as i64 + n));
                    arr[j].push(parts[j].as_ref().map(|(x, _)| shift(x, m as i64 + n)));
                }
                if env.alpha_eq_relevant(x, &at[j][k as usize], &|p, q| p == q) {
                    return Some(mk::var(m - 1 - j as u32 + k));
                }
                // the same read, written the other way
                if let (Some((xa, ka)), Some((_, kj)), Some(xj)) = (&xp, &parts[j], &arr[j][k as usize])
                    && ka == kj
                    && env.alpha_eq_relevant(xa, xj, &|p, q| p == q)
                {
                    return Some(mk::var(m - 1 - j as u32 + k));
                }
            }
            None
        })
    }

    /// `(x, k)` of a read of element `k` (a literal) of the array `x`:
    /// `seq::index T (fst x) k _ _` or `array::index T N x k _`.
    fn read_parts(&self, t: &Tm) -> Option<(Tm, num_bigint::BigInt)> {
        if !matches!(&**t, Term::App { .. }) {
            return None;
        }
        let (h, args) = crate::elab::items::spine(t);
        let Term::Global(g) = &*h else { return None };
        if args.len() != 5 {
            return None;
        }
        if Some(*g) == self.n.seq_index {
            let (Term::Fst(x), Term::Lit { n, .. }) = (&*args[1], &*args[2]) else { return None };
            return Some((x.clone(), n.clone()));
        }
        if self.env.global_name(*g).as_deref() == Some("array::index") {
            let Term::Lit { n, .. } = &*args[3] else { return None };
            return Some((args[2].clone(), n.clone()));
        }
        None
    }

    /// Whether a vector value is made by a hardware model: an application of
    /// a `def[intrinsic]` global, or an explicit vector one of whose lanes
    /// is read from one (`seq::index T (fst (m args)) k _ _`). Only the top
    /// of the value is looked at (no walk, nothing charged).
    fn model_made(&self, v: &V) -> bool {
        let is_model = |x: &V| matches!(&**x, Value::Neu(Neutral { head: Head::Global { def, .. }, spine }) if spine.is_empty() && self.env.global_kind(*def) == Some(DefKind::Intrinsic));
        if is_model(v) {
            return true;
        }
        let (Value::Pair { fst, .. }, Some(list), Some(index)) = (&**v, self.n.list, self.n.seq_index) else { return false };
        let mut cur = fst.clone();
        for _ in 0..MAX_SPLIT_LANES {
            let next = match &*cur {
                Value::Ctor { ind, ctor: 1, args, .. } if *ind == list && args.len() == 2 => {
                    let (Arg::Rel(h), Arg::Rel(tl)) = (&args[0], &args[1]) else { return false };
                    if let Value::Neu(Neutral { head: Head::Global { def, args: ia }, spine }) = &**h
                        && *def == index
                        && spine.is_empty()
                        && let Some(Arg::Rel(lst)) = ia.get(1)
                        && let Value::Neu(Neutral { head: Head::Global { def: m, .. }, spine: ms }) = &**lst
                        && matches!(ms.as_slice(), [Elim::Fst])
                        && self.env.global_kind(*m) == Some(DefKind::Intrinsic)
                    {
                        return true;
                    }
                    tl.clone()
                }
                _ => return false,
            };
            cur = next;
        }
        false
    }

    /// `(T, N)` of a vector type `Array T N` with machine-word lanes `T`
    /// and a literal `N` in `2..=`[`MAX_SPLIT_LANES`].
    fn word_vector_shape(&mut self, st: &St, ty: &V) -> R<Option<(V, u64)>> {
        let Value::Sigma { fst, .. } = &**ty else { return Ok(None) };
        let Value::Ind { params, .. } = &**fst else { return Ok(None) };
        if params.len() != 1 || !matches!(&*params[0], Value::IntTy(w) if *w != Width::Int) {
            return Ok(None);
        }
        Ok(self.array_len(st, ty)?.filter(|n| (2..=MAX_SPLIT_LANES).contains(n)).map(|n| (params[0].clone(), n)))
    }

    /// `N` of an array type `Array T N` (`Σ(l : List T). .Eq(Int, len T l,
    /// N)`) with a literal `N`.
    fn array_len(&mut self, st: &St, ty: &V) -> R<Option<u64>> {
        let Value::Sigma { snd_rel: Rel::Irr, fst, snd, .. } = &**ty else { return Ok(None) };
        let Value::Ind { ind, params } = &**fst else { return Ok(None) };
        if Some(*ind) != self.n.list || params.len() != 1 {
            return Ok(None);
        }
        let x = self.env.fresh_var(sandblaster_kernel::term::Lvl(st.depth()), Rel::Rel, fst);
        let Some(p) = self.inst(snd, vec![x], st.depth() + 1)? else { return Ok(None) };
        let Some((_, _, rhs)) = as_eq(&p) else { return Ok(None) };
        let n = match &**rhs {
            Value::Lit { n, .. } => n,
            _ => match as_prim(rhs) {
                Some((sandblaster_kernel::term::PrimOp::Cast { .. }, [a])) => match &**a {
                    Value::Lit { n, .. } => n,
                    _ => return Ok(None),
                },
                _ => return Ok(None),
            },
        };
        use num_traits::ToPrimitive;
        Ok(n.to_u64())
    }

    /// `t` with every hardware model (`def[intrinsic]` global) replaced by
    /// its body (a closed λ term), and whether there was one.
    fn unfold_models(&self, t: &Tm) -> (Tm, bool) {
        let mut any = false;
        let env = self.env;
        let out = map_term(t, 0, &mut |x, _| match &**x {
            Term::Global(g) if env.global_kind(*g) == Some(DefKind::Intrinsic) => {
                let body = env.global_body(*g)?;
                any = true;
                Some(body)
            }
            _ => None,
        });
        (out, any)
    }

    /// The `n` lanes of an explicit vector value `pair(Cons(x0, .. Nil), _)`.
    fn explicit_lanes(&self, v: &V, list: sandblaster_kernel::term::IndId, n: u64) -> Option<Vec<V>> {
        let Value::Pair { fst, .. } = &**v else { return None };
        let mut out = Vec::with_capacity(n as usize);
        let mut cur = fst.clone();
        loop {
            let next = match &*cur {
                Value::Ctor { ind, ctor: 1, args, .. } if *ind == list && args.len() == 2 => {
                    let (Arg::Rel(h), Arg::Rel(tl)) = (&args[0], &args[1]) else { return None };
                    out.push(h.clone());
                    tl.clone()
                }
                Value::Ctor { ind, ctor: 0, .. } if *ind == list => break,
                _ => return None,
            };
            cur = next;
        }
        (out.len() as u64 == n).then_some(out)
    }

    /// Decide one lane equation `t = Eq(T, l, r)` (values in `st`, with
    /// the models unfolded): conversion, else its first stuck condition (a
    /// `bool` scrutinee, outermost first) is decided by linear arithmetic
    /// and rewritten to its value, or split when undecided (at most
    /// `splits` nested splits), else `BvRefl`, else the search on the lane
    /// (bounded). A proof at `st`'s depth (its wrappers are the caller's to
    /// close).
    ///
    /// **The condition's motive** ([`Engine::lane_motive`]) generalizes the
    /// condition `c` where the lane *tests* it and nowhere else: the
    /// scrutinee of a match on `c` becomes the motive variable `z`, and the
    /// path equation a dependent match (`if c as .h`) is applied to becomes
    /// the motive's equation binder `e : Eq(Bool, c, z)`. The match's own
    /// motive `(.h : Eq(Bool, c, y)) -> T` and every proof keep `c`, so the
    /// arm's index proof (`t[k]` needs `k < 16`, from `h`) keeps its type,
    /// and `z := c, e := refl(Bool, c)` gives back the lane. Read straight
    /// from the lane's terms, it needs no abstraction search and no check
    /// of its own (the kernel checks the goal's proof).
    pub fn lane_decide(&mut self, st: &mut St, t: &V, splits: u32) -> R<Option<Tm>> {
        self.tick()?;
        // a condition's path equation: `Π(.e : Eq(Bool, c, b)). T`
        if let Value::Pi { name, rel, dom, cod } = &**t {
            let mut c = st.child();
            let is_prop = self.is_prop(dom, c.depth());
            let e = c.push_lam(self.env, name.clone(), *rel, dom.clone(), is_prop);
            let Some(body) = self.inst(cod, vec![e], c.depth())? else { return Ok(None) };
            let p = self.lane_decide(&mut c, &body, splits)?;
            return Ok(p.map(|p| c.finish(p)));
        }
        let Some((ty, l, r)) = as_eq(t) else { return Ok(None) };
        let (ty, l, r) = (ty.clone(), l.clone(), r.clone());
        let d = st.depth();
        if self.conv(d, &l, &r)? {
            return Ok(Some(mk::refl(self.quote(st, &ty), st.quote_at(self.env, &l, &ty))));
        }
        let bi = self.n.bool_ind;
        let bt = Rc::new(Value::Ind { ind: bi, params: vec![] });
        let mut stuck = Vec::new();
        self.collect_stuck(t, &mut stuck);
        let mut tried: Vec<V> = Vec::new();
        for s in stuck {
            let StuckKind::Scrut { ind, .. } = s.kind else { continue };
            if ind != bi {
                continue;
            }
            // each condition once (a lane tests one index on both sides)
            let mut seen = false;
            for u in tried.iter().chain(st.split_vals.iter()) {
                if self.conv(d, u, &s.val)? {
                    seen = true;
                    break;
                }
            }
            if seen {
                continue;
            }
            tried.push(s.val.clone());
            let ty_tm = self.quote(st, &ty);
            let (l_tm, r_tm, c_tm) = (st.quote_at(self.env, &l, &ty), st.quote_at(self.env, &r, &ty), st.quote_at(self.env, &s.val, &bt));
            if [&ty_tm, &l_tm, &r_tm, &c_tm].iter().any(|x| crate::elab::tm::has_erased(x)) {
                continue;
            }
            let Some(motive) = self.lane_motive(&ty_tm, &l_tm, &r_tm, &c_tm) else { continue };
            let refl_c = mk::refl(self.bool_ty(), c_tm.clone());
            if let Some((b, p)) = self.decide_bool(st, &s.val)? {
                // `transport(Bool, b, c, sym(p), z. motive, λe. q) .refl(Bool, c)`
                self.note("decide a lane's condition by linarith");
                let lit = self.bool_v(b);
                let fty = Rc::new(Value::Eq { ty: bt.clone(), lhs: s.val.clone(), rhs: lit.clone() });
                let lvl = st.push_fact(self.env, fty, p, Origin::Derived("decided lane condition"));
                let k = st.depth() - d;
                let (motive, c_tm, refl_c) = (shift_from(&motive, k as i64, 1), shift(&c_tm, k as i64), shift(&refl_c, k as i64));
                let lit_tm = mk::bool_lit(bi, b);
                let Some(t2) = self.motive_at(st, &motive, &lit)? else { return Ok(None) };
                let eq = self.sym(&self.bool_ty(), &c_tm, &lit_tm, &st.var(lvl));
                let cont = Cont { depth: st.depth(), ty: self.bool_ty(), lhs: lit_tm, rhs: c_tm, eq, motive, pre: vec![refl_c] };
                let Some(q) = self.lane_decide(st, &t2, splits)? else { return Ok(None) };
                return Ok(Some(cont.apply(st.depth(), q)));
            }
            if splits == 0 {
                continue;
            }
            // `match c as z return motive with | false => λe. q0 | true => λe. q1 end .refl(Bool, c)`
            self.note(format!("split a lane on `{}`", self.show(st, &s.val)));
            let mut arms = Vec::with_capacity(2);
            for b in [false, true] {
                let mut arm = st.child();
                arm.split_vals.push(s.val.clone());
                let Some(tk) = self.motive_at(&arm, &motive, &self.bool_v(b))? else { return Ok(None) };
                let Some(q) = self.lane_decide(&mut arm, &tk, splits - 1)? else { return Ok(None) };
                arms.push(sandblaster_kernel::term::Arm { names: vec![], body: arm.finish(q) });
            }
            let m = Rc::new(Term::Match { ind: bi, params: vec![], scrut: c_tm, motive, arms });
            return Ok(Some(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: refl_c })));
        }
        // a lane without conditions left: word algebra, else the search on
        // the lane (its hypotheses: a table's relation to another), on a
        // quarter of what is left of the budget
        if let Some(p) = self.try_bvrefl(st, t, true)? {
            return Ok(Some(p));
        }
        let mut c = st.child();
        let t = t.clone();
        let p = self.bounded(4, |e| e.atomic(&mut c, t))?;
        Ok(p.map(|p| c.finish(p)))
    }

    /// The motive of a lane's condition `c` (see [`Engine::lane_decide`]):
    /// `z. Π(.e : Eq(Bool, c, z)). Eq(T, l[z, e], r[z, e])` (a term at the
    /// depth of the inputs plus one, `z` its variable), where the matches on
    /// `c` of the lane's sides test `z` and the dependent ones are applied to
    /// `e`. `None` if no match tests `c`.
    fn lane_motive(&self, ty_tm: &Tm, l_tm: &Tm, r_tm: &Tm, c_tm: &Tm) -> Option<Tm> {
        let bi = self.n.bool_ind;
        let env = self.env;
        let mut count = 0usize;
        // `c` at local depth `k` under `z` and `e`
        let mut cs: Vec<Tm> = Vec::new();
        let mut generalize = |n: Tm, k: u32| -> Option<Tm> {
            let z = |k: u32| mk::var(k + 1);
            match &*n {
                Term::Match { ind, params, scrut, motive, arms } if *ind == bi && !matches!(&**scrut, Term::Var(i) if i.0 == k + 1) => {
                    // a match on `c` whose type does not depend on `c`: the
                    // `if c` of the lane (its motive constant, or the path
                    // equation's `Π(.h : Eq(Bool, c, y)). R`)
                    if !(path_form(motive) || !occurs(motive, 0)) {
                        return Some(n);
                    }
                    while cs.len() <= k as usize {
                        cs.push(shift(c_tm, 2 + cs.len() as i64));
                    }
                    if !env.alpha_eq_relevant(scrut, &cs[k as usize], &|a, b| a == b) {
                        return Some(n);
                    }
                    count += 1;
                    Some(Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: z(k), motive: motive.clone(), arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect() }))
                }
                // the path equation a dependent `if c as .h` is applied to
                Term::App { rel: Rel::Irr, fun, .. } => match &**fun {
                    Term::Match { ind, scrut, motive, .. } if *ind == bi && matches!(&**scrut, Term::Var(i) if i.0 == k + 1) && path_form(motive) => {
                        Some(Rc::new(Term::App { rel: Rel::Irr, fun: fun.clone(), arg: mk::var(k) }))
                    }
                    _ => Some(n),
                },
                _ => Some(n),
            }
        };
        let l2 = crate::elab::tm::map_post(&shift(l_tm, 2), 0, &mut generalize)?;
        let r2 = crate::elab::tm::map_post(&shift(r_tm, 2), 0, &mut generalize)?;
        if count == 0 {
            return None;
        }
        Some(mk::pi("e", Rel::Irr, mk::eq(self.bool_ty(), shift(c_tm, 1), mk::var(0)), mk::eq(shift(ty_tm, 2), l2, r2)))
    }
}

/// One shape of the lanes of a vector equation ([`Engine::lane_split`]):
/// the lane's sides with its reads of vector lanes abstracted (terms under
/// one binder per read, of the given types), and its proof.
struct LaneShape {
    types: Vec<Tm>,
    l: Tm,
    r: Tm,
    proof: Option<Tm>,
}

/// A lane shape's statement `Π(x.. : T..). Eq(elem, l, r)` (a term in the
/// context of the shape's lanes; `elem` its lane type there): the lane's
/// terms with its reads abstracted, as written here.
fn shape_statement(elem: &Tm, sh: &LaneShape) -> Tm {
    let m = sh.types.len();
    let mut stmt = mk::eq(shift(elem, m as i64), sh.l.clone(), sh.r.clone());
    for (i, ty) in sh.types.iter().enumerate().rev() {
        stmt = mk::pi(&format!("x{i}"), Rel::Rel, shift(ty, i as i64), stmt);
    }
    stmt
}

/// A match motive `y. Π(.h : Eq(Bool, _, y)). R` with `R` independent of
/// `y` (the dependent `if c as .h return R`).
fn path_form(motive: &Tm) -> bool {
    match &**motive {
        Term::Pi { rel: Rel::Irr, dom, cod, .. } => matches!(&**dom, Term::Eq { rhs, .. } if matches!(&**rhs, Term::Var(i) if i.0 == 0)) && !occurs(cod, 1),
        _ => false,
    }
}
