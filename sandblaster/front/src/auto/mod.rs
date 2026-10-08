//! `auto`: untrusted, proof-producing automation implementing
//! [`crate::prover::Prover`] (DESIGN.md §8.1).
//!
//! `auto` receives a [`Goal`](crate::prover::Goal) (a kernel context whose
//! proposition-typed binders are the facts, a target proposition, hints) and
//! a budget, and returns a kernel term proving the target in the goal's
//! context — or an [`AutoFailure`](crate::prover::AutoFailure) describing the
//! normalized goal, the facts, the stuck subterms and what was tried. The
//! kernel checks every term later; by default `auto` also checks its own
//! result before returning it ([`AutoConfig::self_check`]), so a failure is
//! reported as a failure of `auto`, never as a mysterious kernel error.
//!
//! # The steps of §8.1 and where they live
//!
//! | §8.1 step | implementation |
//! | --- | --- |
//! | 1. normalize target and facts | values come from the kernel evaluator (unfolding policy of §5.6); every transformation re-evaluates ([`search`]) |
//! | 2. `refl` by conversion, a fact, `Unit` | [`search`] (`close`) |
//! | 3. goal connectives: dependent ∧, →/∀ intro, ∨, `exists` by unification against facts or `Witness` hints | [`search`] (`solve`), [`ematch`] (witnesses) |
//! | 4. fact saturation: ∧ facts, short-circuit `&&` (dependent-match shape), `!b`, injectivity, `eq_sound`, method facts, simp lemmas | [`facts`], [`ematch`] (forward rules) |
//! | 5. contradictions: constructor clash (incl. `true == false`), `Empty`, linarith infeasibility, `¬P` facts, `¬(a = b)` as `a < b ∨ a > b` | [`facts`], [`search`] (`contradiction`), [`cases`] (disequality splits) |
//! | 6. rewriting with stuck-term equations (`Transport` + term-level abstraction, [`abstraction`]; variable equations substitute, induction-hypothesis-shaped equations between stuck terms rewrite once) | [`rewrite`] |
//! | 7. axiom instantiation for `min max sat_sub sat_add div rem wshr wshl and or cast` atoms (piecewise ones decided or split), `mul_mono` for products of bounded factors; the bit-count bounds and wrapping-exactness lemmas of `lemmas/bits.core` ([`bitlib`]) for `count_ones leading_zeros trailing_zeros wadd wsub wmul wshl` atoms; the variable-shift lemmas of `lemmas/bits_shift.core` for shifts by a non-literal amount (`x · 2^s`, masks, ordered shifts) and products with a power of two | [`arith`] (`enrich`) |
//! | 8. arithmetic decision of stuck comparisons | [`rewrite`] (`decide_scrutinee`) |
//! | 9. arithmetic congruence | [`rewrite`] (`congruence`) |
//! | 10. `Delta` unfolding that unblocks a match (recursive definitions; opaque ones only on an `Unfold` hint, §5.6); a hardware model read at a literal lane, in the target and in facts (§16.4) | [`rewrite`] (`delta_step`), [`lanes`] |
//! | 11. bounded case splits (dependent match idiom with equations), finite enumeration (≤ 64 values) | [`cases`] |
//! | 12. `BvRefl` | [`search`] (`try_bvrefl`) |
//! | 13. linarith certificate search (simplex over exact rationals) on `Env::linearize` systems, then integer cuts and on-demand disequality splits | [`arith`], [`simplex`], [`rat`]; certificates of quoted proofs are re-derived by [`repair`] |
//! | §13.9 E-matching of ∀-facts, conditional simp sets | [`ematch`] |
//! | steps on the goal's terms where its values are too large for motives: a `bool` spec's conjuncts as facts (arrays compared become equations), array literals equal element by element, ∀-facts matched on the terms | [`terms`] |
//!
//! Prelude lemmas (DESIGN.md §6, §3.4 method facts) are core text in
//! `sandblaster/front/lemmas/*.core`, loaded by [`lemmas::load`] and
//! used by the rule engine ([`ematch`]); [`lemmas::method_facts`] is the
//! table the elaborator uses to attach method facts at call sites.
//!
//! # Relevance
//!
//! Proof slots are irrelevant positions, but a goal's term may also be used
//! relevantly (lemma bodies, `ensures` proofs). `auto` builds the connective
//! structure of the target relevantly (λ, pairs, `Either` injections,
//! witnesses) and proves each *atomic* target (an equation or `Empty`)
//! irrelevantly, then promotes it (`eq::promote A a b .p`, `absurd(Empty,
//! p)`), so the result is valid in any position (§5.3,
//! `INTERFACE_CHANGES.md`). When a non-promotable target (`∃`, `∨`) needs a
//! case split first, the split's arms are solved in relevant mode
//! ([`search::Engine::relevant`]).
//!
//! # Quoting
//!
//! Terms are read back from kernel values with typed quoting; the
//! eta-expanded list of an array variable (§5.9) is folded back to `fst(x)`
//! ([`util::fold_array_eta`]), which keeps motives small and makes them
//! independent of whether conversion eta-expands the binder.
//!
//! # Determinism and budget
//!
//! The search is deterministic: decisions only use ordered data structures;
//! hash maps serve as memo tables (quoting, opened rules) whose contents do
//! not depend on iteration order. All kernel work is charged to the caller's
//! [`Budget`], and so is the front-end work (quoting, shifting, abstraction,
//! fact scans, E-matching, splits, pivots, instantiation; [`meter`]); every
//! call also has a wall-clock deadline ([`AutoConfig::goal_timeout`]) and
//! stops at the memory soft limit. The search additionally bounds its own
//! node count, case-split depth, rewrites and unfoldings ([`AutoConfig`]).
//! Exhaustion is a failure with "budget exhausted" (or the deadline or
//! memory limit that was hit) in `tried`, never a panic or a success.

pub mod abstraction;
pub mod arith;
pub mod bitlib;
pub mod cases;
pub mod complete;
pub mod congr;
pub mod ematch;
pub mod facts;
pub mod lanes;
pub mod lemmas;
pub mod meter;
pub mod names;
pub mod rat;
pub mod repair;
pub mod report;
pub mod rewrite;
pub mod search;
pub mod simplex;
pub mod state;
pub mod surface;
pub mod terms;
pub mod util;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::Tm;
use sandblaster_kernel::value::Budget;

use sandblaster_kernel::term::GlobalId;

use crate::prover::{AutoFailure, Goal, Prover, Reasoning};

/// Which reasoning one call may use (DESIGN.md §4.4 closing statements).
///
/// | step of §8.1 | `Full` | `Arith` | `Unfold(gs)` |
/// | --- | --- | --- | --- |
/// | 1–5, 8, 9, 12, 13 (evaluation, connectives, facts, clashes, contradictions, rewriting with fact equations, arithmetic decisions, congruence, `BvRefl`, linarith) | yes | yes | yes |
/// | 7 (axioms of `min max sat_* div rem shifts and or cast count_ones`, `mul_mono`) | yes | yes | yes |
/// | 10 (`Delta`), predicate unfolding | yes | no | exactly `gs` (a named user definition through its view variable, [`crate::prover::Hint::ViewFunction`]) |
/// | 11 (case splits, enumeration) | yes | no | no |
/// | §13.9 rules of the built-in theory (the prelude lemmas about built-in operations — sequence lengths, `drop(l, 0) = l`, method facts, `eq_sound`, extensionality) | yes | yes | yes |
/// | §13.9 ∀-facts of the context (quantified hypotheses and lemma results, instantiated by E-matching) | yes | no | no |
///
/// The elaborator additionally hides what the restricted modes must not
/// see (user functions become variables, `elab::closers`), so a restricted
/// call cannot unfold them through evaluation either.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// `follows()`, the end of a block, and every obligation that is not a
    /// restricted closing statement.
    #[default]
    Full,
    /// `by_arithmetic()`.
    Arith,
    /// `by_unfolding(g, ..)`.
    Unfold(Vec<GlobalId>),
}

impl Mode {
    /// The mode of a goal's restriction ([`crate::prover::Hint::Only`]).
    pub fn of(r: Option<&Reasoning>) -> Mode {
        match r {
            None => Mode::Full,
            Some(Reasoning::Arithmetic) => Mode::Arith,
            Some(Reasoning::Unfolding(gs)) => Mode::Unfold(gs.clone()),
        }
    }
    /// Case splits and enumeration (step 11).
    pub fn allows_splits(&self) -> bool {
        *self == Mode::Full
    }
    /// Instantiation of the context's ∀-facts (§13.9); the rules of the
    /// built-in theory ([`lemmas::LEMMA_ROLES`]) are always available.
    pub fn allows_forall_facts(&self) -> bool {
        *self == Mode::Full
    }
    /// `Delta` / predicate unfolding of `g` (step 10).
    pub fn allows_delta(&self, g: GlobalId) -> bool {
        match self {
            Mode::Full => true,
            Mode::Arith => false,
            Mode::Unfold(gs) => gs.contains(&g),
        }
    }
}

/// Search limits of [`Auto`].
#[derive(Clone, Debug)]
pub struct AutoConfig {
    /// The reasoning allowed ([`Mode`]); per goal, a closing statement's
    /// restriction ([`crate::prover::Hint::Only`]) overrides it.
    pub mode: Mode,
    /// Maximal nesting of case splits (§8.1 step 11).
    pub max_split_depth: u32,
    /// Maximal number of rewrites on one search path (§8.1 step 6).
    pub max_rewrites: u32,
    /// Maximal number of `Delta` unfoldings on one search path (step 10).
    pub max_deltas: u32,
    /// Maximal number of search nodes per goal.
    pub max_nodes: u64,
    /// Largest integer range enumerated automatically (step 11).
    pub enum_limit: u32,
    /// Enrichment rounds of a linarith attempt (step 7).
    pub lin_rounds: u32,
    /// Nesting of integer cuts and on-demand disequality splits after a
    /// failed linarith attempt ([`arith`], optimizer design §7.5); 0
    /// disables them.
    pub int_cuts: u32,
    /// Candidate atoms tried per integer cut.
    pub cut_width: u32,
    /// Maximal number of facts derived by rewriting per branch (step 4/6).
    pub max_fact_rewrites: u32,
    /// Maximal number of rule instances per E-matching round (§13.9).
    pub max_instances: usize,
    /// Check every produced term with the kernel before returning it.
    pub self_check: bool,
    /// Wall-clock limit of one call (`None`: [`meter::goal_timeout`]); an
    /// enclosing scope (the prover chain's per-goal deadline) may be
    /// shorter.
    pub goal_timeout: Option<std::time::Duration>,
    /// Enrich the nested bit-level subterms of the atoms (`|`, `&`, `^`,
    /// shifts, casts, wrapping operations) in the same round as the atoms,
    /// innermost first, instead of one nesting level per round: the
    /// optimizer's decisions on accumulated values (a varint's
    /// `acc | (h & 0x7f) << 7k`, ten levels deep) need every level, and a
    /// round per level re-linearizes the whole system each time.
    pub deep_enrich: bool,
    /// Try `BvRefl` on word equations by itself (§8.1 step 12; a `bv()`
    /// hint always does). Off for the completeness discharges
    /// ([`complete`]): their goals equate a hypothetical `F' x̄` with the real
    /// function, whose word normal form (the whole body unfolded) is useless
    /// there and can be huge.
    pub auto_bvrefl: bool,
    /// Linear arithmetic (§8.1 steps 7, 8 and 13: linarith, its axiom
    /// enrichment, arithmetic decisions of stuck comparisons, integer cuts).
    /// Off for the echo check of the law rules (DESIGN.md §15.1 LR6,
    /// `crate::elab::law_rules`): "no arithmetic beyond evaluation".
    pub arith: bool,
}

impl Default for AutoConfig {
    fn default() -> Self {
        AutoConfig {
            mode: Mode::Full,
            max_split_depth: 4,
            max_rewrites: 64,
            max_deltas: 6,
            max_nodes: 4_000,
            enum_limit: 64,
            lin_rounds: 3,
            int_cuts: 2,
            cut_width: 2,
            max_fact_rewrites: 48,
            max_instances: 24,
            self_check: true,
            goal_timeout: None,
            deep_enrich: false,
            auto_bvrefl: true,
            arith: true,
        }
    }
}

/// The automation ([`Prover`] implementation).
#[derive(Default)]
pub struct Auto {
    pub config: AutoConfig,
    db: lemmas::LemmaDb,
}

impl Auto {
    pub fn new() -> Auto {
        Auto::default()
    }

    pub fn with_config(config: AutoConfig) -> Auto {
        Auto { config, db: lemmas::LemmaDb::default() }
    }
}

impl AutoConfig {
    /// This configuration restricted to `mode` (no case splits outside
    /// [`Mode::Full`]).
    pub fn restricted(&self, mode: Mode) -> AutoConfig {
        let mut c = self.clone();
        if !mode.allows_splits() {
            c.max_split_depth = 0;
        }
        c.mode = mode;
        c
    }
}

impl Prover for Auto {
    fn prove(&mut self, env: &Env, g: &Goal, b: &mut Budget) -> Result<Tm, AutoFailure> {
        let _scope = meter::Scope::enter(self.config.goal_timeout, b);
        self.db.refresh(env);
        match g.reasoning() {
            Some(r) => {
                let cfg = self.config.restricted(Mode::of(Some(r)));
                search::prove_goal(env, g, b, &cfg, &self.db)
            }
            None if self.config.mode != Mode::Full => {
                let cfg = self.config.restricted(self.config.mode.clone());
                search::prove_goal(env, g, b, &cfg, &self.db)
            }
            None => search::prove_goal(env, g, b, &self.config, &self.db),
        }
    }
}
