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
//! hidden proof (a lane fed to a dependent match) is not taken
//! ([`Engine::lane_result_stated`]).

use sandblaster_kernel::term::{DefKind, GlobalId};
use sandblaster_kernel::value::{Arg, Elim, Head, Neutral, V, Value};

use super::rewrite::{Stuck, StuckKind};
use super::search::{Cont, Engine, R};
use super::state::St;
use super::util::*;

/// Lane steps on one search path (a lane step unfolds one model
/// application, all its occurrences).
pub const MAX_LANE_STEPS: u32 = 32;

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
    /// read-back holds no `Erased` placeholder. A lane fed to a dependent
    /// match (PSHUFB's reference `if` and its path equation, a table
    /// lookup's `if k < 16 as .h`) can unfold to a proposition whose
    /// read-back hides a proof; any proof of it carries the placeholder,
    /// which the kernel refuses. Such a step is not taken, and the search
    /// goes on without it (`bv()`, the other steps), as it did before lane
    /// steps existed.
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
