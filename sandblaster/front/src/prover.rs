//! The contract between the elaborator and the automation (FROZEN INTERFACE —
//! DESIGN.md §7.2, §8.1). Changes are additive and recorded in
//! `sandblaster/front/INTERFACE_CHANGES.md` (§15: six new
//! [`ObligationKind`]s).
//!
//! The elaborator turns every proof obligation (overflow, bounds, callee
//! `requires`, termination, `ensures`, law goals, `assert`s, …) into a
//! [`Goal`] and calls a [`Prover`] synchronously. The prover returns a kernel
//! term that proves `goal.target` in `goal.ctx`, or an [`AutoFailure`] that the
//! elaborator turns into a diagnostic. The prover is untrusted: whatever it
//! returns is checked by the kernel when the enclosing definition is added.
//!
//! Conventions:
//! * **Facts are context entries.** Every hypothesis (a `requires`, a path
//!   condition from a dependent match, an earlier `assert`, a callee's
//!   `ensures`, a loop invariant, a type bound, an induction hypothesis) is a
//!   binder of `goal.ctx` (usually `Rel::Irr`). [`Goal::facts`] lists which
//!   binders are facts (by de Bruijn *level*) and where they came from; it is
//!   metadata for search and diagnostics — the prover may use any binder of
//!   the context whose type is a proposition.
//! * **The target is a value** (a `Type`-sorted proposition) in `goal.ctx`.
//! * **The result is a term closed in `goal.ctx`** (de Bruijn indices relative
//!   to the end of the context). It is usually placed in an irrelevant
//!   position (proof slot), but may be relevant (lemma bodies, `ensures`
//!   proofs); if the prover uses an irrelevant binder in a relevant position,
//!   it must go through `eq::promote` (see the kernel's INTERFACE_CHANGES.md)
//!   or return an error.
//! * **Budgets.** Every call receives a kernel [`Budget`]; the prover must stay
//!   within it (the kernel enforces it anyway) and should fail gracefully.
//! * **Determinism.** Given the same environment, goal and budget, the prover
//!   must return the same result (builds must be reproducible).
//! * **Restrictions.** A goal with a [`Hint::Only`] comes from a closing
//!   statement that names its reasoning (`by_arithmetic()`,
//!   `by_unfolding(..)`); the prover must stay within that reasoning (or
//!   fail), because the elaborator uses the result to check the claim.

use num_bigint::BigInt;
use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{GlobalId, Lvl, Tm};
use sandblaster_kernel::value::{Budget, V};

use crate::builtins::Builtin;
use crate::span::Span;

/// Identifies an obligation within one build (stable across runs of the same
/// input, for reports and caching).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObligationId(pub u32);

/// What kind of obligation a goal is (for diagnostics and reports).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObligationKind {
    Overflow,
    Underflow,
    DivZero,
    ShiftWidth,
    IndexBounds,
    SliceRange,
    /// The `requires` of a callee (user function, builtin method, lemma).
    CalleeRequires(GlobalId),
    Unreachable,
    InvariantEntry,
    InvariantPreserve,
    /// Measure decrease at a recursive call.
    Termination,
    /// `e ≤ C` for `#[decreases(e, max = C)]` at a call from outside.
    StackDepth,
    Ensures,
    LawGoal,
    Assert,
    /// `variant(x) == portable(x)` for `#[implements]` (§9.3).
    VariantEquiv,
    /// Any other side condition produced by elaboration (e.g. the length proof
    /// of an array literal, a Slice bound for a ghost sequence).
    WellFormed,
    // ---- additive (DESIGN.md §15; sandblaster/front/INTERFACE_CHANGES.md) ----
    /// `f::refines`: the function refines its spec through the views of
    /// its types (`#[refines]`, §15.2).
    Refines,
    /// The invariant of a struct at a construction site: literal, tuple
    /// struct call, `..base` update, field assignment, pattern rebuild
    /// (`#[invariant]`, §15.3).
    TypeInvariant,
    /// A loop invariant at the exit of the loop helper, proving
    /// `f::loop#k::ensures` (the post-loop facts, §7.4).
    InvariantExit,
    /// `view_inj_T`: a lossy-looking view is injective (§15.2, §15.3).
    ViewInjective,
    /// `s::example#k`: a known-answer example holds (`#[example]`,
    /// `#[examples(file)]`, §15.7).
    Example,
    /// `complete_p(R)`: every implementation satisfying the section's
    /// specification agrees with this one (§15.5).
    Completeness,
}

/// Where a fact came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactOrigin {
    Requires,
    PathCond,
    LetDef,
    Invariant,
    CalleeEnsures(GlobalId),
    MethodFact(Builtin),
    Assert,
    TypeBound,
    InductionHyp,
    /// Hypothesis of a lemma/law being proven.
    LemmaHyp,
}

/// A fact available to the prover: a context binder (by level) whose type is
/// a proposition.
#[derive(Clone, Debug)]
pub struct FactRef {
    pub lvl: Lvl,
    pub origin: FactOrigin,
    pub span: Span,
}

/// User-supplied guidance from script statements (§4.4). Terms are in
/// `goal.ctx`.
#[derive(Clone, Debug)]
pub enum Hint {
    /// Apply this lemma instance (its type is a proposition in `goal.ctx`);
    /// the prover may use it as a fact.
    Lemma(Tm),
    /// Rewrite the target with an equation proof `eq : Eq(A, l, r)` (left to
    /// right, or right to left when `rev`), optionally with an explicit motive
    /// body (a term in `goal.ctx` extended with one variable).
    Rewrite { eq: Tm, rev: bool, motive: Option<Tm> },
    /// Witnesses for an existential target (outermost first).
    Witness(Vec<Tm>),
    /// Unfold applications of this (recursive or opaque) global in the target.
    Unfold(GlobalId),
    /// Enumerate the integer binder at `var` over `[lo, hi)`.
    Cases { var: Lvl, lo: BigInt, hi: BigInt },
    /// Close the target with exactly this term.
    Exact(Tm),
    /// Close an equality target with `BvRefl` (word algebra).
    Bv,
    /// Use only the reasoning a closing statement claims (`by_arithmetic()`,
    /// `by_unfolding(..)`, DESIGN.md §4.4). Every prover of a chain must
    /// honor it or fail: the elaborator relies on it to check the claim.
    Only(Reasoning),
    /// A function of the crate in a restricted view (`elab::closers`,
    /// `by_arithmetic()`, `by_unfolding(..)`): the context variable at `var`
    /// stands for the global `def` (of `arity` parameters; its type is
    /// `def`'s, with the view's variables for the crate's functions). With
    /// `eq`, `def` is a named recursive or opaque definition and the fact
    /// at `eq` is its defining equation `Π(x..). Eq(R, var x.., body[x..])`,
    /// whose body calls the view's variables: a prover may replace a full
    /// application `var a..` by `body[a..]` with it (like `Delta` for a
    /// global). Without `eq` the function is unknown.
    ViewFunction { def: GlobalId, var: Lvl, eq: Option<Lvl>, arity: u32 },
}

/// The reasoning a restricted closing statement allows ([`Hint::Only`]).
///
/// Both allow linear arithmetic (certificates), the §8.1 step-7 axioms
/// (`min`, `max`, saturating operations, shifts, masks, casts,
/// `count_ones`) and the rest of the built-in theory of built-in operations
/// (the prelude lemma rules: sequence lengths, `drop(l, 0) = l`, method
/// facts, `eq_sound`, extensionality), evaluation of the goal as given,
/// rewriting with equations among the facts, splitting boolean facts
/// (`a && b`), deciding a stuck comparison by arithmetic, congruence,
/// constructor clashes and contradictory facts. Neither allows case splits,
/// instantiating the context's quantified facts, or unfolding any
/// definition beyond the listed ones (a named user definition is unfolded
/// through its view variable, [`Hint::ViewFunction`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reasoning {
    /// `by_arithmetic()`: no definition is unfolded (`Delta`, predicate
    /// unfolding).
    Arithmetic,
    /// `by_unfolding(f, ..)`: `Delta` / predicate unfolding of exactly these
    /// globals (opaque ones included).
    Unfolding(Vec<GlobalId>),
}

impl Reasoning {
    /// Whether the definition `g` may be unfolded (`Delta`, `Unfold`).
    pub fn may_unfold(&self, g: GlobalId) -> bool {
        match self {
            Reasoning::Arithmetic => false,
            Reasoning::Unfolding(gs) => gs.contains(&g),
        }
    }
}

impl Goal {
    /// The restriction of a closing statement, if the goal carries one
    /// ([`Hint::Only`]).
    pub fn reasoning(&self) -> Option<&Reasoning> {
        self.hints.iter().find_map(|h| match h {
            Hint::Only(r) => Some(r),
            _ => None,
        })
    }
}

/// One proof obligation.
#[derive(Clone, Debug)]
pub struct Goal {
    pub id: ObligationId,
    pub kind: ObligationKind,
    pub span: Span,
    pub ctx: Ctx,
    pub facts: Vec<FactRef>,
    /// The proposition to prove (a value of sort `Type` in `ctx`).
    pub target: V,
    pub hints: Vec<Hint>,
}

/// Why the prover failed (rendered as the diagnostic's notes). Strings are
/// pretty-printed in Rust-like syntax where possible.
#[derive(Clone, Debug, Default)]
pub struct AutoFailure {
    /// The goal after normalization.
    pub goal: String,
    /// The facts that were considered.
    pub facts: Vec<String>,
    /// Stuck subterms that blocked progress (unfold/case-split candidates).
    pub stuck: Vec<String>,
    /// What was tried, in order.
    pub tried: Vec<String>,
}

/// A proof search procedure.
pub trait Prover {
    /// Prove `g.target` in `g.ctx`; the returned term is checked later by the
    /// kernel.
    fn prove(&mut self, env: &Env, g: &Goal, b: &mut Budget) -> Result<Tm, AutoFailure>;
}
