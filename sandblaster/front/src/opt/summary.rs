//! Compositional summaries (optimizer design §1, §4 step 3, §5 `Summary`,
//! §6.4): what the summary pass records about a function once it is
//! optimized, so that its callers use the summary instead of re-driving the
//! function's source.
//!
//! A [`FnSummary`] holds
//!
//! * the admitted **residual** (its kernel global and item) and its
//!   **link** to the source: conversion (tier 0) or the kernel-checked
//!   equality lemma `Π x̄ h̄. Eq(R, res x̄ h̄, f x̄ h̄)` (`Link::Lemma`);
//! * the residual's shape as the cost model sees it: its node count and the
//!   number of result leaves of its process tree (how many copies a
//!   continuation pushed into it would get, case-of-case);
//! * the **fact lemmas** exported for callers (`Π x̄ h̄. P(x̄, f x̄ h̄)`,
//!   kernel-checked; [`FactLemma`]).
//!
//! At a call site the driver picks one of the three forms of design §6.4
//! from the summary ([`CallForm`]): keep the call (with the fact lemmas as
//! facts of the caller's path), inline the residual through its link as a
//! value (a join point, when the continuation is large), or instantiate its
//! tree (continue driving the caller through the callee's residual:
//! case-of-case, when the continuation is small). Every form is justified
//! by the link; nothing here is trusted.

use std::collections::{BTreeMap, BTreeSet};

use sandblaster_kernel::term::GlobalId;

use crate::hir::ItemId;
use crate::opt::drive::tree::SpecKey;

/// How a summary's residual is justified against its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SumLink {
    /// Convertible with the source (tier 0): the caller may unfold the
    /// source itself.
    Conversion,
    /// The kernel-checked equality lemma (`Link::Lemma`).
    Lemma(GlobalId),
}

/// A kernel-checked fact about a function's result (design §6.4 "output
/// facts"): `lemma : Π x̄ (h̄ :Irr Req). P(x̄, f x̄ h̄)`.
#[derive(Clone, Debug)]
pub struct FactLemma {
    /// The lemma's global.
    pub lemma: GlobalId,
    /// Its name (reported).
    pub name: String,
    /// What it states, for the report (`value <= 4611686018427387904`).
    pub states: String,
}

/// The summary of one exec function (see the module docs).
#[derive(Clone, Debug)]
pub struct FnSummary {
    pub item: ItemId,
    pub source: GlobalId,
    /// The admitted residual (for a conversion link, the tier-0 residual).
    pub residual: GlobalId,
    pub residual_item: ItemId,
    pub link: SumLink,
    /// Distinct residual nodes.
    pub nodes: usize,
    /// Result leaves of the residual's process tree (1 for straight-line).
    pub result_leaves: usize,
    /// The same with the result leaves of the specialization helpers the
    /// residual calls (what instantiating it all the way would produce).
    pub expanded_leaves: usize,
    /// The residual calls a recursive function (a loop stays a call).
    pub calls_recursion: bool,
    /// Estimated size of its result (bytes; `None`: unknown).
    pub result_bytes: Option<u64>,
    /// The residual keeps calls of user functions (other than
    /// specialization helpers): inlining it would expose further calls.
    pub calls_user: bool,
    /// Exported fact lemmas.
    pub facts: Vec<FactLemma>,
}

/// A committed specialization helper as the cost model sees it (design
/// §6.5): its residual size and expanded result leaves. A helper's body is
/// unfolded directly at a call site (it is a definition of this crate; its
/// own lemma links it to the specialized function).
#[derive(Clone, Copy, Debug)]
pub struct HelperShape {
    pub nodes: usize,
    pub result_leaves: usize,
    pub result_bytes: Option<u64>,
    pub calls_user: bool,
}

/// Polyvariant call-site specializations of one callee (design §6.5).
pub const MAX_SPECS_PER_CALLEE: usize = 8;
/// Polyvariant call-site specializations of the crate.
pub const MAX_SPECS_PER_CRATE: usize = 64;

/// The summaries of the functions optimized so far, by source global.
#[derive(Default)]
pub struct Summaries {
    pub by_global: BTreeMap<GlobalId, FnSummary>,
    /// Specialization helpers, by their global.
    pub helpers: BTreeMap<GlobalId, HelperShape>,
    /// The polyvariant call-site specializations committed (their keys;
    /// the caps count these).
    pub spec_keys: BTreeSet<SpecKey>,
    /// Polyvariant specializations that failed (not proposed again).
    pub spec_failed: BTreeSet<SpecKey>,
    /// Fold helpers (loop helpers with a carried bound invariant, design
    /// §6.6), by the recursion they fold.
    pub folds: BTreeMap<GlobalId, FoldHelper>,
    /// Recursions whose fold helper failed (not proposed again).
    pub fold_failed: BTreeSet<GlobalId>,
    /// Σ3 segment specializations (design §8.2, `opt::seqsum`).
    pub seg: crate::opt::seqsum::drive::Registry,
}

/// A committed fold helper `H` of a user recursion `f` (design §6.6): `H`
/// has `f`'s parameters, `f`'s `requires` and a bound invariant over them,
/// and calls itself where `f` does; `lemma : Π x̄ (h :Irr Req_H). Eq(R, H x̄
/// h, E x̄ h)` (measure recursion: the back-edges are its induction
/// hypothesis), where the entry `E x̄ h` is `f x̄ …` by definition.
#[derive(Clone, Copy, Debug)]
pub struct FoldHelper {
    pub item: ItemId,
    pub global: GlobalId,
    pub lemma: GlobalId,
    pub entry: GlobalId,
}

impl Summaries {
    pub fn get(&self, g: GlobalId) -> Option<&FnSummary> {
        self.by_global.get(&g)
    }

    pub fn insert(&mut self, s: FnSummary) {
        self.by_global.insert(s.source, s);
    }

    /// The summary of `g` when it is admitted through an equality lemma
    /// (a driven residual): `(residual, lemma)`.
    pub fn lemma_link(&self, g: GlobalId) -> Option<(GlobalId, GlobalId)> {
        match self.get(g)?.link {
            SumLink::Lemma(l) => Some((self.get(g)?.residual, l)),
            SumLink::Conversion => None,
        }
    }
}

/// What the driver does with a call of a summarized function (design §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallForm {
    /// Keep the call (its fact lemmas enter the caller's facts).
    Keep,
    /// Inline the residual through the link as a value bound to a new
    /// variable (a join point): the caller's continuation is not
    /// duplicated.
    Inline,
    /// Instantiate the residual's tree: the caller continues through it,
    /// its continuation pushed into every leaf (case-of-case).
    Instantiate,
}

/// The cost model's thresholds for the call-site forms.
#[derive(Clone, Copy, Debug)]
pub struct CallCosts {
    /// Residuals larger than this (nodes) stay calls.
    pub max_inline_nodes: usize,
    /// Case-of-case duplicates the continuation into every result leaf of
    /// the callee: allowed while `leaves × continuation nodes` is at most
    /// this; beyond it the residual is inlined as a value.
    pub max_duplicated_nodes: usize,
}

/// Results larger than this many bytes are returned through memory (two
/// registers on aarch64 and x86-64): the call's ABI dominates a small
/// callee (design §6.4).
pub const ABI_REGISTER_BYTES: u64 = 16;

/// The call-site form (design §6.4) for a callee whose residual has
/// `nodes` nodes, `leaves` result leaves and a result of `result_bytes`,
/// its result eliminated by a continuation of `cont_nodes` relevant term
/// nodes (`None`: the call is in tail position, the whole value), `nested`
/// when the continuation calls another callee that expands into several
/// leaves:
///
/// * **instantiate** (case-of-case) when a continuation exists and
///   `leaves × continuation` stays within the duplication budget (each
///   leaf specializes the continuation: facts of the leaf reach it) — for
///   a callee with several leaves only when the continuation is not
///   `nested` (the copies would multiply along a chain of calls: only the
///   chain's last call is instantiated);
/// * **inline** as a value when the call's ABI dominates (a small callee
///   whose result is an aggregate returned through memory) — in tail
///   position the same as instantiating;
/// * **keep** the call otherwise (inlining would only enlarge the caller
///   and its proof), and always for a callee whose residual calls other
///   user functions.
pub fn call_form(costs: &CallCosts, nodes: usize, leaves: usize, result_bytes: Option<u64>, calls_user: bool, cont_nodes: Option<usize>, nested: bool) -> CallForm {
    // only leaf-level callees (their residual calls no other user
    // function): inlining one that does would cascade into its callees
    if nodes > costs.max_inline_nodes || calls_user {
        return CallForm::Keep;
    }
    if let Some(c) = cont_nodes
        && (leaves <= 1 || !nested)
        && leaves.saturating_mul(c) <= costs.max_duplicated_nodes
    {
        return CallForm::Instantiate;
    }
    let abi = result_bytes.is_some_and(|b| b > ABI_REGISTER_BYTES);
    match (abi, cont_nodes) {
        (true, None) => CallForm::Instantiate,
        (true, Some(_)) => CallForm::Inline,
        (false, _) => CallForm::Keep,
    }
}
