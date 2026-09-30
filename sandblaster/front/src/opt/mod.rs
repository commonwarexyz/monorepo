//! The optimizer (DESIGN.md §8.2, §9.3, §9.5). It always runs; it is
//! untrusted: every result it keeps is checked by the kernel, and a
//! failure falls back to the proven unspecialized definition with a warning
//! (an error under `SANDBLASTER_STRICT_OPT=1`; `#[specialize]` functions must
//! specialize).
//!
//! [`optimize`] runs after the crate is verified (every definition checked,
//! every obligation and law proven), on the elaboration's environment:
//!
//! 1. **Variants** ([`variant`], [`multiversion`]): every
//!    `#[implements(p)]` function whose definition checked gets its
//!    `VariantEquiv` lemma proven by `BvRefl` (kernel-checked); variants
//!    with a proof and hardware evidence for every intrinsic they call form
//!    the dispatchable **variant sets**.
//! 2. **Multiversioning** ([`multiversion`]): the call tree of every set is
//!    cloned (`f__<set>`), the clones are elaborated and kernel-checked like
//!    source functions, each clone is checked α-equivalent in all relevant
//!    positions to its original modulo the renaming, and its equality with
//!    the original is proven as a kernel-checked lemma `f__<set>::clone_equiv
//!    : Π x̄. f__<set> x̄ = f x̄` ([`mirror`], by induction for recursive
//!    clones, on top of the `VariantEquiv` lemmas).
//! 3. **Specialization** ([`symex`], [`residual`]): every exec function
//!    (originals and clones, callees first) is symbolically executed in the
//!    kernel evaluator; a stuck-free result within the cost model becomes a
//!    straight-line residual function (HIR), which is elaborated (every
//!    proof slot re-proven) and admitted with `Env::check_residual_equal`
//!    against the function (`Specialized`); otherwise the function is
//!    `Unspecialized(reason)`.
//! 4. The **print view** ([`Optimized::print`]): the crate as it is printed —
//!    specialized functions with their residual bodies, clones, portable
//!    functions of the tree renamed `f__portable` where a dispatcher takes
//!    the boundary name — and the round-trip targets: for every printed
//!    definition, the kernel global it denotes and the one whose body it
//!    must equal (DESIGN.md §8.3).
//!
//! 5. The **evidence gate** ([`evidence_gate`], §9.2): no printed function
//!    may call an intrinsic whose model lacks hardware evidence for the
//!    target — non-dispatched variants that would are left out of the
//!    emitted code, anything else fails the build.
//!
//! Bounds-check elimination (§8.2.3) needs no equivalence proof: every
//! index operation of the optimized core carries its kernel-checked proof,
//! and the printer emits `get_unchecked` forms (see `canon`).

pub mod cost;
pub mod derive;
pub mod drive;
pub mod egraph;
pub mod facts;
pub mod guardspec;
pub mod loopsum;
#[cfg(any(test, feature = "opt-test-hooks"))]
pub mod hooks;
pub mod mirror;
pub mod proof;
pub mod multiversion;
pub mod refute;
pub mod outline;
pub mod par;
pub mod cache;
pub mod residual;
pub mod seqsum;
pub mod summary;
pub mod symex;
pub mod variant;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use sandblaster_kernel::term::GlobalId;
use sandblaster_kernel::value::Budget;

/// Production builds have no test hooks (see [`hooks`], compiled only under
/// `cfg(test)` or the `opt-test-hooks` feature): this stand-in is
/// uninhabited, so [`OptOptions::hooks`] is always `None` and every hook
/// site is statically dead.
#[cfg(not(any(test, feature = "opt-test-hooks")))]
mod hooks {
    use sandblaster_kernel::api::Env;
    use sandblaster_kernel::term::{GlobalId, Tm};

    pub type ProofSkeleton = std::sync::Arc<dyn Fn(&Env, GlobalId, GlobalId) -> Result<Tm, String> + Send + Sync>;

    pub enum OptTestHooks {}

    /// Uninhabited in production: no simulated CPU exists.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KatFault {}

    impl OptTestHooks {
        pub(crate) fn candidate(&self, _: &str) -> Option<String> {
            match *self {}
        }
        pub(crate) fn cache_proof(&self, _: &str) -> Option<ProofSkeleton> {
            match *self {}
        }
        pub(crate) fn proof(&self, _: &str) -> Option<ProofSkeleton> {
            match *self {}
        }
        pub(crate) fn forces_dispatch(&self, _: &str) -> bool {
            match *self {}
        }
        pub(crate) fn forges_clone_lemma(&self, _: &str) -> bool {
            match *self {}
        }
        pub(crate) fn drive_fault(&self, _: &str) -> Option<super::DriveFault> {
            match *self {}
        }
        pub(crate) fn loop_fault(&self, _: &str) -> Option<super::loopsum::LoopFault> {
            match *self {}
        }
        pub(crate) fn kat_fault(&self, _: &str) -> Option<KatFault> {
            match *self {}
        }
        pub(crate) fn rule_files(&self) -> Option<Vec<(String, String)>> {
            match *self {}
        }
        pub(crate) fn grants_set_evidence(&self, _: &str) -> bool {
            match *self {}
        }
        pub(crate) fn lane_fault(&self, _: &str) -> Option<super::par::lift::LaneFault> {
            match *self {}
        }
    }
}

/// A simulated fault of the driven route (design §20, R1–R15): the driver,
/// the residual printer or the proof builder proposes something wrong, and
/// the proof builder *trusts* the proposal (closes leaves by `refl`, emits
/// the claimed decisions), so what rejects it is the kernel or elaboration,
/// never the builder's own checks. Injected only by the must-reject suite
/// (`OptTestHooks::drive_faults`, which a production build does not have).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveFault {
    /// R1: every `Prune` decides its condition the other way (the live arm
    /// is pruned); its proof is a certificate-free `linarith` claim.
    FlipPrune,
    /// R3: partial operations (unchecked reads, divisions, checked
    /// arithmetic) over the parameters are emitted at the top of the
    /// residual, above the splits that guard them.
    HoistPartial,
    /// R4: the arms of the residual's first boolean split are swapped.
    SwapArms,
    /// R11: a specialization helper calls itself where it calls the next
    /// helper (recursion between helpers).
    SelfHelper,
    /// R12: a specialization helper keeps a `requires` over a dynamic
    /// parameter (`p == 0`) that its call sites do not establish.
    HelperRequires,
    /// R13: a `Reuse` takes the sibling arm's decision (the other boolean
    /// constructor) and proves it with this arm's path equation.
    CrossArmReuse,
    /// R14: in-place boolean selects are printed with both arms evaluated
    /// before the `if` (a select conversion of arms with partial
    /// operations).
    SelectPartial,
    /// R15: saturating additions are printed as wrapping ones.
    WrapOps,
    /// R2: a range check the facts cannot decide (an undecided boolean
    /// split on a comparison of a `u64` value with a literal, the varint's
    /// `value <= MAX_LEAVES` after the ninth byte) is claimed dead: pruned
    /// to its `true` arm, with a certificate-free `linarith` claim.
    RangeCheckDead,
    /// R10: a fold helper's lemma declared with a measure that does not
    /// decrease (its accumulator), the decrease at each back-edge claimed
    /// with a certificate-free `linarith`.
    FoldBadMeasure,
    /// Not a must-reject fault: a safety net stops the driver's run (its
    /// wall-clock deadline, recorded as the meter records a real one), so
    /// the function falls back to a weaker candidate — output that would
    /// depend on the clock. `driver::resource_gate` must then fail the
    /// build (`error[resource]`, DESIGN.md §15.8, §8.2 item 10).
    DeadlineTrip,
    /// R5 (Σ3): the segment normal form claims that a `take` ends before a
    /// replicated piece it reaches into (`take(C, nb+2+na) = B ++ d::A`),
    /// the side condition `k ≤ 0` claimed with a certificate-free
    /// `linarith`.
    SegTakeShort,
    /// R9 (Σ3): a segment helper's back-edge folds its pieces in the wrong
    /// order (the first and last segments swapped: `fold(X ++ Y)` continued
    /// as `fold(Y ++ X)`), its induction step claimed by `refl`.
    SegFoldSwap,
    /// R16: the proof builder's abstraction transports an irrelevant proof
    /// whose expected type did not change (a checked constructor's
    /// invariant proof, stated over the abstracted scrutinee) — the bug the
    /// abstraction had before `auto::abstraction::Abs::irr_after`. The
    /// kernel's type check of the builder's motive rejects it; being an
    /// ill-typed term of the builder (not a search that ran out), it is an
    /// optimizer fault ([`PROOF_ILL_TYPED`]).
    TransportKeptProof,
}

use crate::elab::{self, DefStatus, Output, ProverChain};
use crate::hir::*;
use multiversion::VariantSet;

/// Optimizer settings (cost model and budgets, §8.2.1).
#[derive(Clone, Debug)]
pub struct OptOptions {
    /// Largest residual (distinct nodes) of one function.
    pub node_budget: usize,
    /// Callee residuals at most this large are inlined when specializing a
    /// caller; larger ones stay opaque calls.
    pub inline_threshold: usize,
    /// Crate-wide cap on the residual nodes of all specialized functions.
    pub growth_cap: usize,
    /// Kernel step budget of one symbolic execution.
    pub symex_budget: u64,
    /// Kernel step budget of one `VariantEquiv` check / residual check.
    pub check_budget: u64,
    /// Turn optimizer failures into errors (`SANDBLASTER_STRICT_OPT=1`).
    pub strict: bool,
    /// Multiversion call trees (§9.3).
    pub multiversion: bool,
    /// Kernel step budget of one clone-equality lemma.
    pub clone_budget: u64,
    /// Clone-equality lemmas are attempted for bodies up to this size
    /// (term nodes, shared nodes counted once).
    pub clone_lemma_max_nodes: usize,
    /// The hints-only proof cache's directory ([`cache`]; `None`: no
    /// cache). Every hit is re-checked by the kernel.
    pub cache_dir: Option<std::path::PathBuf>,
    /// Σ2 loop summaries: synthesis switch (a test hook), budgets, the
    /// crate's profile inputs ([`loopsum::LoopConfig`]).
    pub loops: loopsum::LoopConfig,
    /// The tuning evidence of the cost model (plan O8; by default the
    /// committed files). With `PROFILE.json` the only input that changes
    /// choices (its hash keys the proof cache and is reported).
    pub tuning: std::sync::Arc<cost::tuning::Tuning>,
    /// Test hooks ([`hooks`]; never present in a production build).
    #[cfg(any(test, feature = "opt-test-hooks"))]
    pub hooks: Option<std::sync::Arc<hooks::OptTestHooks>>,
}

impl Default for OptOptions {
    fn default() -> OptOptions {
        OptOptions {
            node_budget: 20_000,
            inline_threshold: 2_048,
            growth_cap: 400_000,
            symex_budget: 200_000_000,
            check_budget: 2_000_000_000,
            strict: false,
            multiversion: true,
            clone_budget: 50_000_000,
            clone_lemma_max_nodes: 1 << 20,
            cache_dir: None,
            loops: loopsum::LoopConfig::default(),
            tuning: cost::tuning::Tuning::shared(),
            #[cfg(any(test, feature = "opt-test-hooks"))]
            hooks: None,
        }
    }
}

impl OptOptions {
    /// The defaults, with `strict` from `SANDBLASTER_STRICT_OPT=1`.
    pub fn from_env() -> OptOptions {
        OptOptions { strict: std::env::var("SANDBLASTER_STRICT_OPT").as_deref() == Ok("1"), cache_dir: cache::Cache::default_dir(), ..Default::default() }
    }

    /// The installed test hooks (always `None` in a production build).
    #[inline]
    fn hooks(&self) -> Option<&hooks::OptTestHooks> {
        #[cfg(any(test, feature = "opt-test-hooks"))]
        {
            self.hooks.as_deref()
        }
        #[cfg(not(any(test, feature = "opt-test-hooks")))]
        {
            None
        }
    }
}

/// How an emitted function is justified against its source (design §3.1,
/// the emission chain). Today every specialization is admitted by
/// conversion (`Env::check_residual_equal`, tier 0); `Lemma` (a
/// kernel-checked `Π x̄. Eq(R, residual x̄, f x̄)` admitted by `add_def`)
/// arrives with the driver (plan O4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    Conversion,
    Lemma(String),
}

/// The rungs of the fallback ladder (design §3.2), strongest first. The
/// source itself is below the last rung (no rung).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rung {
    ClosedForm,
    EarlyExit,
    SkipIdle,
    SetBits,
    Fused,
    Driven,
    /// A straight-line residual rewritten by the aegraph (plan O8): a
    /// cheaper alternative of the straight-line rung, linked by its lemma.
    Rewritten,
    StraightLine,
}

impl Rung {
    pub fn name(self) -> &'static str {
        match self {
            Rung::ClosedForm => "ClosedForm",
            Rung::EarlyExit => "EarlyExit",
            Rung::SkipIdle => "SkipIdle",
            Rung::SetBits => "SetBits",
            Rung::Fused => "Fused",
            Rung::Driven => "Driven",
            Rung::Rewritten => "Rewritten",
            Rung::StraightLine => "StraightLine",
        }
    }
}

/// One candidate the optimizer considered for a function (a rung or an
/// alternative), and what became of it.
#[derive(Clone, Debug)]
pub struct CandidateReport {
    pub rung: Rung,
    /// Cost per variant set (today: residual nodes, the only cost term; the
    /// set is the function's own: `portable`, or the clone's set).
    pub cost: BTreeMap<String, u64>,
    pub chosen: bool,
    pub reason: String,
    /// The checker that refused the candidate, when one did (e.g.
    /// `check_residual_equal: TypeMismatch`, `add_def: TypeMismatch`,
    /// `elaboration`).
    pub rejected_by: Option<String>,
    /// Proposed through a test hook ([`hooks`]).
    pub injected: bool,
}

/// Deterministic resource use of one function's optimization (step and node
/// counts only, never wall-clock time: they are part of the byte-identical
/// report, gate G1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetsUsed {
    /// Kernel steps of the symbolic execution.
    pub symex_steps: u64,
    /// Kernel steps of the admission check.
    pub check_steps: u64,
    /// Distinct residual nodes.
    pub residual_nodes: u64,
    /// Kernel steps of the Σ2 loop summaries built while driving the
    /// function (analysis, lemma chain, links, facts, fallback rungs;
    /// `loopsum::meter`, each within `LoopConfig::steps_per_loop`).
    pub loopsum_steps: u64,
}

/// The optimizer's result for one exec function.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// A straight-line residual, kernel-checked equal to the function.
    Specialized {
        /// Distinct residual nodes.
        nodes: usize,
        /// The residual's kernel definition.
        residual: GlobalId,
        /// Globals kept as opaque calls in the residual.
        calls: Vec<String>,
    },
    /// Not specialized; `failure` marks an optimizer failure (a warning,
    /// or an error in strict mode) as opposed to a cost-model or
    /// stuck-evaluation decision.
    Unspecialized { reason: String, failure: bool },
}

/// One exec function's report entry.
#[derive(Clone, Debug)]
pub struct FnReport {
    pub item: ItemId,
    /// Source (or clone) path.
    pub name: String,
    /// The variant set of a clone.
    pub set: Option<String>,
    pub outcome: Outcome,
    /// How the emitted function is justified (`None`: the source is printed).
    pub link: Option<Link>,
    /// The rung of the emitted candidate (`None`: the source is printed).
    pub rung: Option<Rung>,
    /// Every candidate considered, the chosen one marked.
    pub candidates: Vec<CandidateReport>,
    pub budgets_used: BudgetsUsed,
    /// Names of the kernel-checked fact lemmas exported for callers (none
    /// before compositional summaries, plan O5).
    pub facts_exported: Vec<String>,
    /// Wall-clock milliseconds (reported in `sandblaster-timing.json`, never in
    /// the deterministic report).
    pub millis: u128,
}

/// A hardware variant and what became of it.
#[derive(Clone, Debug)]
pub struct VariantReport {
    pub variant: String,
    pub implements: String,
    pub features: Vec<String>,
    /// `Ok((lemma, right-hand side, milliseconds))` when proven.
    pub equivalence: Result<(String, String, u128), String>,
    /// `(model, status)` for every intrinsic the variant calls.
    pub evidence: Vec<(String, String)>,
    pub dispatched: bool,
    pub note: String,
}

/// A multiversioned clone and its relation check.
#[derive(Clone, Debug)]
pub struct CloneReport {
    pub clone: String,
    pub original: String,
    pub set: String,
    /// Kernel-checked α-equivalence modulo the renaming.
    pub related: Result<(), String>,
    /// The kernel-checked equality lemma `Π x. clone x = original x`
    /// ([`mirror`]); a clone without one is not admitted (plan O4): its
    /// variant set is not dispatched.
    pub lemma: Option<String>,
}

/// A trusted boundary dispatcher (§9.3).
#[derive(Clone, Debug)]
pub struct Dispatcher {
    /// The module and boundary name the dispatcher takes.
    pub module: ModId,
    pub name: String,
    /// The portable function (renamed `f__portable`).
    pub portable: ItemId,
    /// `(set, function)` in preference order.
    pub variants: Vec<(VariantSet, ItemId)>,
}

/// Everything the optimizer produced.
pub struct Optimized {
    /// The print view (see the module docs). Residual items are kept (as
    /// ghost items, never printed) so item ids match the elaboration.
    pub print: Crate,
    /// Printed item → (kernel global it denotes, kernel global its body
    /// must equal).
    pub targets: HashMap<ItemId, (GlobalId, GlobalId)>,
    pub fns: Vec<FnReport>,
    pub variants: Vec<VariantReport>,
    pub clones: Vec<CloneReport>,
    pub sets: Vec<VariantSet>,
    pub dispatchers: Vec<Dispatcher>,
    /// Functions of a call tree left portable, `(function, set, reason)`
    /// (methods and generic functions, red team R2/R2b).
    pub not_cloned: Vec<(String, String, String)>,
    /// Functions left out of the emitted code, `(function, reason)`: hardware
    /// variants (and helpers only they use) whose intrinsic models lack
    /// hardware evidence for the target (§9.2, red team E1).
    pub not_emitted: Vec<(String, String)>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub millis: u128,
    /// Lane kernels considered at lane sites (plan O10, the lane functor);
    /// empty for programs without a lane site.
    pub lanes: Vec<par::LaneReport>,
    /// The SIMD `seq::eq` candidates (plan O10), one per compared length.
    pub seq_eq: Vec<par::seqeq::SeqEqReport>,
}

/// Development tracing (`SANDBLASTER_OPT_TRACE=1`).
fn trace(msg: impl FnOnce() -> String) {
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
        eprintln!("opt: {}", msg());
    }
}

/// Model names (evidence records) of every intrinsic and load/store helper
/// `id` calls, transitively through user functions.
fn used_models(krate: &Crate, id: ItemId) -> Vec<String> {
    struct V(Vec<String>, Vec<ItemId>);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            match &e.kind {
                ExprKind::Call { callee: Callee::Intrinsic(i, _), .. } => self.0.push(crate::intrinsics::get(*i).name.to_string()),
                ExprKind::Call { callee: Callee::Helper(h), .. } => self.0.push(helper_model(*h)),
                ExprKind::Call { callee: Callee::Item(c, _), .. } => self.1.push(*c),
                _ => {}
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut seen = HashSet::new();
    let mut work = vec![id];
    let mut out: Vec<String> = Vec::new();
    while let Some(i) = work.pop() {
        if !seen.insert(i) {
            continue;
        }
        let Some(f) = krate.fn_def(i) else { continue };
        let mut v = V(vec![], vec![]);
        crate::visit::walk_fn(&mut v, f);
        out.extend(v.0);
        work.extend(v.1);
    }
    out.sort();
    out.dedup();
    out
}

/// Model names of the intrinsics and load/store helpers a function body
/// calls directly (what it emits).
fn direct_models(f: &FnDef) -> Vec<String> {
    struct V(Vec<String>);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            match &e.kind {
                ExprKind::Call { callee: Callee::Intrinsic(i, _), .. } => self.0.push(crate::intrinsics::get(*i).name.to_string()),
                ExprKind::Call { callee: Callee::Helper(h), .. } => self.0.push(helper_model(*h)),
                _ => {}
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(vec![]);
    if let FnBody::Exec(b) = &f.body {
        crate::visit::Visitor::expr(&mut v, b);
    }
    v.0.sort();
    v.0.dedup();
    v.0
}

/// The evidence record of a load/store helper: the intrinsic its fixed
/// template calls.
fn helper_model(h: crate::intrinsics::HelperId) -> String {
    let info = crate::intrinsics::helper(h);
    let arch = info.arch.name();
    let via = info.template.split(&format!("::core::arch::{arch}::")).nth(1).map(|r| r.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<String>());
    via.unwrap_or_else(|| info.name.to_string())
}

/// `Err(status)` unless the model `m` has hardware evidence for `arch`.
fn evidence_status(arch: &crate::target::Arch, m: &str) -> Result<String, String> {
    match targets_arch(arch) {
        Some(a) => match sandblaster_targets::evidence::validation(a, m) {
            sandblaster_targets::evidence::Validation::Validated { executor } => Ok(format!("validated ({executor})")),
            sandblaster_targets::evidence::Validation::PendingHardware => Err("pending hardware".to_string()),
            sandblaster_targets::evidence::Validation::Missing(r) => Err(format!("missing: {r}")),
        },
        None => Err("unknown architecture".into()),
    }
}

/// The hardware-evidence gate of the emitted code (DESIGN.md §9.2: only
/// instructions that remain in emitted code need evidence, and the gate
/// fails closed; red team E1). Every printed function's own intrinsic and
/// helper calls are checked:
///
/// * a hardware variant that is not dispatched, is not a boundary export
///   of its own, and whose code uses an unvalidated model is left out of
///   the emitted code, with the private helpers that only such variants
///   call (or nothing calls: a specialized variant inlines its helpers);
/// * any other printed function calling an unvalidated model is an error
///   (the build fails; the model's evidence must be recorded first).
#[allow(clippy::too_many_arguments)]
fn evidence_gate(print: &mut Crate, targets: &mut HashMap<ItemId, (GlobalId, GlobalId)>, dispatchers: &[Dispatcher], variants: &mut [VariantReport], not_emitted: &mut Vec<(String, String)>, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
    let arch = print.target.arch.clone();
    let printed: Vec<ItemId> = print.items.iter().filter(|it| !it.ghost && matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Exec)).map(|it| it.id).collect();
    let mut bad: HashMap<ItemId, Vec<(String, String)>> = HashMap::new();
    for &id in &printed {
        let f = print.fn_def(id).unwrap();
        let v: Vec<(String, String)> = direct_models(f).into_iter().filter_map(|m| evidence_status(&arch, &m).err().map(|st| (m, st))).collect();
        if !v.is_empty() {
            bad.insert(id, v);
        }
    }
    if bad.is_empty() {
        return;
    }
    let mut calls: HashMap<ItemId, BTreeSetIds> = HashMap::new();
    let mut callers: HashMap<ItemId, HashSet<ItemId>> = HashMap::new();
    for &id in &printed {
        let cs = multiversion::callees(print.fn_def(id).unwrap());
        for c in &cs {
            callers.entry(*c).or_default().insert(id);
        }
        calls.insert(id, cs);
    }
    // printed functions whose code (transitively) emits an unvalidated model
    let mut tainted: HashSet<ItemId> = bad.keys().copied().collect();
    loop {
        let before = tainted.len();
        for &id in &printed {
            if !tainted.contains(&id) && calls[&id].iter().any(|c| tainted.contains(c)) {
                tainted.insert(id);
            }
        }
        if tainted.len() == before {
            break;
        }
    }
    let dispatched: HashSet<ItemId> = dispatchers.iter().flat_map(|d| d.variants.iter().map(|(_, t)| *t).chain([d.portable])).collect();
    let direct_exports: HashSet<ItemId> = print.boundary.iter().filter_map(|e| match e.target {
        ExportTarget::Item(i) => Some(i),
        _ => None,
    }).collect();
    let api = crate::canon::exported_items(print);
    let movable = |id: &ItemId| !dispatched.contains(id) && !direct_exports.contains(id) && tainted.contains(id);
    let mut excluded: HashSet<ItemId> = printed.iter().copied().filter(|id| print.fn_def(*id).is_some_and(|f| f.implements.is_some()) && movable(id)).collect();
    // private helpers that only excluded functions call (or none: a
    // specialized variant inlines its helpers) go with them; exported
    // functions stay (and fail below)
    loop {
        let before = excluded.len();
        for &id in &printed {
            if excluded.contains(&id) || !movable(&id) || api.contains(&id) {
                continue;
            }
            if callers.get(&id).is_none_or(|cs| cs.iter().all(|c| excluded.contains(c))) {
                excluded.insert(id);
            }
        }
        if excluded.len() == before {
            break;
        }
    }
    let mut ex: Vec<ItemId> = excluded.into_iter().collect();
    ex.sort();
    for id in &ex {
        let path = print.item(*id).path.to_string();
        let models: Vec<String> = bad.get(id).map(|v| v.iter().map(|(m, st)| format!("{m} ({st})")).collect()).unwrap_or_default();
        let why = if models.is_empty() { "only used by variants left out of the emitted code".to_string() } else { format!("its intrinsic models lack hardware evidence for {}: {}", arch.name(), models.join(", ")) };
        warnings.push(format!("`{path}` is not emitted: {why} (DESIGN.md §9.2)"));
        not_emitted.push((path.clone(), why));
        if let Some(v) = variants.iter_mut().find(|v| v.variant == path) {
            v.note = format!("{}; not emitted (no hardware evidence for this target)", v.note);
        }
        print.items[id.0 as usize].ghost = true;
        targets.remove(id);
    }
    for (id, v) in bad.iter().filter(|(id, _)| !ex.contains(id)) {
        let models: Vec<String> = v.iter().map(|(m, st)| format!("`{m}` ({st})")).collect();
        errors.push(format!(
            "`{}` would emit {} without hardware evidence for {}: no unvalidated instruction may reach emitted code (DESIGN.md §9.2); validate the model(s) on real hardware and record the evidence, or do not call them from exported or dispatched code",
            print.item(*id).path,
            models.join(", "),
            arch.name()
        ));
    }
    errors.sort();
}

type BTreeSetIds = std::collections::BTreeSet<ItemId>;

fn targets_arch(a: &crate::target::Arch) -> Option<sandblaster_targets::registry::Arch> {
    match a.name() {
        "aarch64" => Some(sandblaster_targets::registry::Arch::Aarch64),
        "x86_64" => Some(sandblaster_targets::registry::Arch::X86_64),
        _ => None,
    }
}

/// The feature-implication closure of `features` (sorted).
fn closure(arch: &crate::target::Arch, features: &[String]) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut work: Vec<String> = features.to_vec();
    while let Some(f) = work.pop() {
        if set.insert(f.clone()) {
            work.extend(crate::target::implied(arch, &f).iter().map(|s| s.to_string()));
        }
    }
    set.into_iter().collect()
}

/// Kernel names of the definitions a function contributes (itself, its
/// loop helpers, its `ensures`), for correspondences.
fn defs_of(out: &Output, name: &str) -> Vec<(String, GlobalId)> {
    let mut v = Vec::new();
    for d in &out.defs {
        let Some(g) = d.global else { continue };
        if d.name == name || d.name.starts_with(&format!("{name}::loop#")) || d.name == format!("{name}::ensures") {
            v.push((d.name.clone(), g));
        }
    }
    v
}

struct Ctx<'o> {
    out: &'o mut Output,
    opts: OptOptions,
    warnings: Vec<String>,
    errors: Vec<String>,
    /// Specialization helpers committed so far (crate-wide, design §6.5).
    helpers: BTreeMap<drive::tree::SpecKey, Helper>,
    /// Keys whose helper failed (not retried).
    helper_failed: BTreeMap<drive::tree::SpecKey, String>,
    /// Functions whose chosen residual is driven (`Link::Lemma`): callers
    /// keep calling them (their residual already is the specialization; a
    /// caller unfolding the source would redo its driving and its proof).
    driven: HashSet<ItemId>,
    /// Functions whose driving failed, with the reason (a multiversioned
    /// clone of one is not driven: it fails the same way).
    drive_failed: HashMap<ItemId, String>,
    /// Driven functions whose process tree was trivial (a clone of one is
    /// not driven: its residual would be its source up to evaluation too).
    drive_trivial: HashSet<ItemId>,
    /// Tier-0 outcomes: the functions tier 0 specialized and their residual
    /// sizes (tier 0 inlines these callees, as before the driver, whichever
    /// residual was chosen for them).
    tier0_nodes: HashMap<ItemId, usize>,
    /// Tier-0 residuals that call a recursive function (the driver keeps
    /// such a callee a call: unfolding it only exposes a recursion it keeps).
    tier0_recursive: HashSet<ItemId>,
    /// The global of every tier-0 residual (not proposed by a test hook) by
    /// its function's global: tier 0 unfolds an inlined callee through it
    /// (`symex::symex_via`), so the callee is not evaluated again.
    tier0_residual: HashMap<GlobalId, GlobalId>,
    /// The admitted driven residual and link of every driven function
    /// (`derive`: a multiversioned clone's link may go through them).
    driven_info: HashMap<ItemId, derive::DrivenInfo>,
    /// Clone or variant global → (its original, the kernel-checked lemma
    /// `Π x̄. Eq(R, clone x̄, original x̄)`), for every admitted variant set.
    clone_lemmas: HashMap<GlobalId, (GlobalId, GlobalId)>,
    /// Admitted clone → (its original, its variant set).
    clone_of: HashMap<ItemId, (ItemId, String)>,
    /// Derived segment helper (of a clone consumer) → (the original's
    /// helper, the kernel-checked lemma `Π ā. Eq(R, derived ā, original ā)`)
    /// (`derive`).
    helper_pairs: HashMap<GlobalId, (GlobalId, GlobalId)>,
    /// The obligations of committed driven residuals and helpers, set aside
    /// until the end of specialization: obligation numbers are the count of
    /// obligations at their creation, so every other function keeps the
    /// numbering (printed in `SAFETY:` comments) it has without the driver
    /// (gate G10).
    late_obligations: Vec<elab::ObligationRecord>,
    /// Per driven residual or helper being committed: the number of
    /// obligations and definition records before its elaboration (what it
    /// added is everything after; names do not identify it: a tier-0
    /// residual has the same name).
    marks: HashMap<ItemId, (usize, usize)>,
    /// The summaries of the functions optimized so far (design §4 step 3,
    /// §6.4): callers use them at their call sites.
    summaries: summary::Summaries,
    /// Outlined definitions (their `linarith` proofs as lemmas) for the
    /// equality lemmas' proofs (`outline`).
    outlines: outline::Outlines,
    /// The hints-only proof cache (`cache`).
    cache: Option<cache::Cache>,
    /// The aegraph's rule library: `None` until a rule trigger first
    /// fires, then the result of loading it (the kernel checks every
    /// lemma). A library that failed is never used for the rest of the
    /// build (lemmas loaded before the failing one included).
    rules: Option<Result<(), String>>,
    /// The functions on whose region the aegraph matched at least one rule
    /// instance, whatever its saving under the function's own cost model
    /// (`egraph::improve`). Matching does not depend on the cost model;
    /// which match is kept does. So a clone of any other function gets the
    /// same aegraph outcome as its original, and the pre-pricing of the
    /// feature-only sets may price such a clone on its original's residual;
    /// a function in this set must be cloned to be priced.
    aegraph_matched: HashSet<ItemId>,
}

impl Ctx<'_> {
    /// Sets the obligations of the committed item `rid` aside (see
    /// `late_obligations`).
    fn set_aside_obligations(&mut self, rid: ItemId) {
        if let Some((om, _)) = self.marks.remove(&rid) {
            let late: Vec<_> = self.out.obligations.drain(om.min(self.out.obligations.len())..).collect();
            self.late_obligations.extend(late);
        }
    }
}

/// A committed specialization helper: its item, global and lemma.
#[derive(Clone, Copy, Debug)]
struct Helper {
    item: ItemId,
    global: GlobalId,
    lemma: GlobalId,
}

impl Ctx<'_> {
    fn failure(&mut self, msg: String) {
        if self.opts.strict {
            self.errors.push(msg);
        } else {
            self.warnings.push(msg);
        }
    }

    fn global_name(&self, g: GlobalId) -> String {
        self.out.env.global_name(g).map(|s| s.to_string()).unwrap_or_default()
    }

    fn checked(&self, id: ItemId) -> Option<GlobalId> {
        let g = *self.out.fn_globals.get(&id)?;
        self.out.defs.iter().any(|d| d.global == Some(g) && d.status == DefStatus::Checked).then_some(g)
    }

    /// Kernel-checked α-equivalence of two definitions' committed bodies
    /// (and types) modulo `corr`.
    fn related(&self, a: GlobalId, b: GlobalId, corr: &HashMap<GlobalId, GlobalId>) -> Result<(), String> {
        let env = &self.out.env;
        let c = |x: GlobalId, y: GlobalId| x == y || corr.get(&x) == Some(&y);
        let (ta, tb) = (env.global_type(a).ok_or("no type")?, env.global_type(b).ok_or("no type")?);
        if !env.alpha_eq_relevant(&ta, &tb, &c) {
            return Err(format!("the types of `{}` and `{}` differ", self.global_name(a), self.global_name(b)));
        }
        let (ba, bb) = (env.global_body(a).ok_or("no body")?, env.global_body(b).ok_or("no body")?);
        if !env.alpha_eq_relevant(&ba, &bb, &c) {
            return Err(format!("the bodies of `{}` and `{}` differ beyond the renaming", self.global_name(a), self.global_name(b)));
        }
        Ok(())
    }

    /// Checks every definition of `copy` (function, loop helpers, ensures)
    /// against the same-suffix definition of `orig`, with `corr` extended by
    /// those pairs.
    fn related_fn(&self, copy: &str, orig: &str, corr: &mut HashMap<GlobalId, GlobalId>) -> Result<(), String> {
        let cd = defs_of(self.out, copy);
        let od: HashMap<String, GlobalId> = defs_of(self.out, orig).into_iter().collect();
        let mut pairs = Vec::new();
        for (n, g) in &cd {
            let suffix = &n[copy.len()..];
            let Some(o) = od.get(&format!("{orig}{suffix}")) else { return Err(format!("`{n}` has no counterpart `{orig}{suffix}`")) };
            corr.insert(*g, *o);
            pairs.push((*g, *o));
        }
        if cd.len() != od.len() {
            return Err(format!("`{copy}` and `{orig}` have different helper definitions"));
        }
        for (g, o) in pairs {
            self.related(g, o, corr)?;
        }
        Ok(())
    }
}

/// Empties the per-crate thread-local registries (loop summaries, exported
/// facts, guard specializations) when dropped.
struct ResetRegistries;

impl Drop for ResetRegistries {
    fn drop(&mut self) {
        loopsum::reset(loopsum::LoopConfig::default());
        facts::reset();
        guardspec::reset();
        crate::auto::ematch::reset_lin_rules();
        symex::reset_memo();
    }
}

/// Runs the optimizer (see the module docs) on a verified elaboration of
/// `krate`. `out` gains the optimizer's kernel definitions (lemmas,
/// clones, residuals).
pub fn optimize(out: &mut Output, krate: &Crate, opts: &OptOptions) -> Optimized {
    let t0 = Instant::now();
    let mut cx = Ctx { out, opts: opts.clone(), warnings: vec![], errors: vec![], helpers: BTreeMap::new(), helper_failed: BTreeMap::new(), driven: HashSet::new(), drive_failed: HashMap::new(), drive_trivial: HashSet::new(), tier0_nodes: HashMap::new(), tier0_recursive: HashSet::new(), tier0_residual: HashMap::new(), driven_info: HashMap::new(), clone_lemmas: HashMap::new(), clone_of: HashMap::new(), helper_pairs: HashMap::new(), late_obligations: Vec::new(), marks: HashMap::new(), summaries: summary::Summaries::default(), outlines: outline::Outlines::default(), cache: opts.cache_dir.as_deref().map(|d| cache::Cache::new(d).with_inputs(choice_inputs_hash(opts))), rules: None, aegraph_matched: HashSet::new() };
    // Σ2 loop summaries (plan O6): one registry per crate; so are the
    // exported facts and the guard specializations
    loopsum::reset(opts.loops.clone());
    facts::reset();
    guardspec::reset();
    crate::auto::ematch::reset_lin_rules();
    symex::reset_memo();
    // ... and emptied again when the run ends, however it ends: an
    // elaboration after it on the same thread (another crate) must not see
    // this crate's facts in the `dep_match` hook (`elab/exec.rs`), keyed by
    // this environment's globals
    let _registries = ResetRegistries;
    let mut ext = krate.clone();
    let mut chain = ProverChain::standard();
    let eopts = elab::Options::default();
    let arch = krate.target.arch.clone();

    // ------------------------------------------------------------------
    // 1. variants
    // ------------------------------------------------------------------
    let mut variants: Vec<VariantReport> = Vec::new();
    let mut dispatchable: Vec<(ItemId, ItemId)> = Vec::new(); // (variant, portable)
    let variant_items: Vec<(ItemId, ItemId)> = krate.items.iter().filter_map(|it| match &it.kind {
        ItemKind::Fn(f) if f.kind == FnKind::Exec && !it.ghost => f.implements.map(|p| (it.id, p)),
        _ => None,
    }).collect();
    for (v, p) in variant_items {
        let f = krate.fn_def(v).unwrap();
        let mut rep = VariantReport { variant: krate.item(v).path.to_string(), implements: krate.item(p).path.to_string(), features: f.feature_set.clone(), equivalence: Err("not attempted".into()), evidence: vec![], dispatched: false, note: String::new() };
        let (Some(gv), Some(gp)) = (cx.checked(v), cx.checked(p)) else {
            rep.equivalence = Err("the variant or the portable function is not kernel-checked".into());
            cx.failure(format!("variant `{}`: not kernel-checked; not dispatched", rep.variant));
            variants.push(rep);
            continue;
        };
        // hardware evidence (fail closed)
        let tarch = targets_arch(&arch);
        let mut evidence_ok = true;
        for m in used_models(krate, v) {
            let status = match tarch {
                Some(a) => match sandblaster_targets::evidence::validation(a, &m) {
                    sandblaster_targets::evidence::Validation::Validated { executor } => format!("validated ({executor})"),
                    sandblaster_targets::evidence::Validation::PendingHardware => {
                        evidence_ok = false;
                        "pending hardware".to_string()
                    }
                    sandblaster_targets::evidence::Validation::Missing(r) => {
                        evidence_ok = false;
                        format!("missing: {r}")
                    }
                },
                None => {
                    evidence_ok = false;
                    "unknown architecture".into()
                }
            };
            rep.evidence.push((m, status));
        }
        // VariantEquiv: directly, or against a transparent copy
        let t = Instant::now();
        trace(|| format!("VariantEquiv {} (direct)", rep.variant));
        let mut equiv = variant::prove(&mut cx.out.env, gv, gp, opts.check_budget);
        trace(|| format!("  -> {:?} in {:?}", equiv.as_ref().map(|_| ()).map_err(|e| e.chars().take(300).collect::<String>()), t.elapsed()));
        if let Err(direct) = &equiv {
            let direct = direct.clone();
            equiv = transparent_equiv(&mut cx, &mut ext, &mut chain, &eopts, v, p, gv, gp).map_err(|e| format!("direct: {direct}; via a transparent copy: {e}"));
        }
        // a test hook may force the dispatch of a variant without evidence
        // (a simulated optimizer bug, R26: the evidence gate must refuse it)
        let forced = !evidence_ok && cx.opts.hooks().is_some_and(|h| h.forces_dispatch(&rep.variant));
        match equiv {
            Ok(e) => {
                rep.equivalence = Ok((cx.global_name(e.lemma), cx.global_name(e.rhs), t.elapsed().as_millis()));
                if evidence_ok || forced {
                    rep.dispatched = true;
                    rep.note = if forced { "dispatched WITHOUT hardware evidence (forced by a test hook)".into() } else { "dispatched".into() };
                    dispatchable.push((v, p));
                } else {
                    rep.note = "not dispatched: some intrinsic models lack hardware evidence for this target (§9.2)".into();
                }
            }
            Err(e) => {
                rep.equivalence = Err(e.clone());
                if evidence_ok {
                    rep.note = "not dispatched: VariantEquiv not proven".into();
                    cx.failure(format!("variant `{}`: VariantEquiv not proven: {e}", rep.variant));
                } else {
                    // not dispatchable anyway (no hardware evidence): a note
                    rep.note = "not dispatched: some intrinsic models lack hardware evidence for this target (§9.2); VariantEquiv not proven either".into();
                }
            }
        }
        variants.push(rep);
    }

    // ------------------------------------------------------------------
    // 1b. lane kernels (plan O10): lane sites lifted by the lane functor
    // are variants of their site (the `VariantEquiv` lemma is the lane
    // functor's `lane_equiv`), dispatched only when the cost model picks
    // them and a host has run them (fail closed)
    // ------------------------------------------------------------------
    let mut lanes: Vec<par::LaneReport> = Vec::new();
    if opts.multiversion {
        let cands = par::sites::candidates(&ext);
        if !cands.is_empty() {
            lane_variants(&mut cx, &mut ext, &mut chain, &eopts, &arch, &cands, &mut variants, &mut dispatchable, &mut lanes);
        }
    }
    // ------------------------------------------------------------------
    // 1c. SIMD search variants (plan O10, P12): a byte search with an early
    // exit gets a NEON variant testing 16 bytes per step, linked by its
    // `search_equiv` (an instance of the kernel-checked search library)
    // ------------------------------------------------------------------
    let mut search_items: HashSet<String> = HashSet::new();
    if opts.multiversion && arch.name() == "aarch64" {
        let sites = par::search::candidates(&ext);
        if !sites.is_empty() {
            search_variants(&mut cx, &mut ext, &mut chain, &eopts, &arch, &sites, &mut variants, &mut dispatchable, &mut search_items);
        }
    }
    // the SIMD `seq::eq` candidates (plan O10, design §12.4): proven equal to
    // the word form and priced against it (reported; the word form stays)
    let mut seq_eq: Vec<par::seqeq::SeqEqReport> = Vec::new();
    if opts.multiversion && arch.name() == "aarch64" {
        let cmps = par::seqeq::comparisons(&ext);
        if !cmps.is_empty() {
            let features = closure(&arch, &["neon".to_string()]);
            let model = cost::model::SetModel::new("neon", arch.name(), &features, &cx.opts.tuning.clone());
            for (n, fs) in cmps {
                let r = par::seqeq::candidate(&mut cx.out.env, &model, n, fs);
                trace(|| r.note.clone());
                seq_eq.push(r);
            }
        }
    }

    if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
        eprintln!("opt: timing phase variants done at {:?}", t0.elapsed());
    }
    // ------------------------------------------------------------------
    // 2. multiversioning
    // ------------------------------------------------------------------
    let mut sets: Vec<VariantSet> = Vec::new();
    for (v, p) in &dispatchable {
        let f = ext.fn_def(*v).unwrap();
        let features = f.target_features.clone();
        match sets.iter_mut().find(|s| s.features == features) {
            Some(s) => {
                s.map.insert(*p, *v);
            }
            None => {
                let name = features.join("_").replace(['.', '-'], "_");
                sets.push(VariantSet::of_variants(name, features.clone(), closure(&arch, &features), HashMap::from([(*p, *v)])));
            }
        }
    }
    // the feature-only sets (plan O8), in dispatch preference order: `v4`
    // and each variant set combined with `v3_scalar` before the variant
    // sets, `v3_scalar` last; at most four sets
    let feature_only: HashSet<String> = if opts.multiversion {
        let fo = multiversion::feature_only_sets(&ext, &arch, &sets);
        let names: HashSet<String> = fo.iter().map(|s| s.name.clone()).collect();
        let (mut first, last): (Vec<VariantSet>, Vec<VariantSet>) = fo.into_iter().partition(|s| s.name != "v3_scalar");
        first.append(&mut sets);
        first.extend(last);
        // over the limit: drop the combined sets (last first), then `v4`;
        // the variant sets and `v3_scalar` stay
        while first.len() > multiversion::MAX_SETS {
            match first.iter().rposition(|s| s.name.ends_with("_v3")).or_else(|| first.iter().position(|s| s.name == "v4")) {
                Some(i) => {
                    first.remove(i);
                }
                None => break,
            }
        }
        sets = first;
        names
    } else {
        HashSet::new()
    };
    // a simulated CPU per set (test hooks only, R21)
    for set in sets.iter_mut() {
        set.kat_fault = cx.opts.hooks().and_then(|h| h.kat_fault(&set.name));
    }
    let mut clones: Vec<CloneReport> = Vec::new();
    let mut not_cloned: Vec<(String, String, String)> = Vec::new();
    let mut not_emitted: Vec<(String, String)> = Vec::new();
    let mut clone_of: HashMap<ItemId, (ItemId, String)> = HashMap::new(); // clone -> (original, set)
    let mut tree_of: HashMap<String, HashMap<ItemId, ItemId>> = HashMap::new();
    // the feature-only sets (plan O8) are generated only for sets a host
    // has run (host evidence, `sandblaster_targets::evidence::SetRecord`),
    // and only after the originals are specialized, where the cost model
    // says they pay (below: `deferred`)
    let set_order: Vec<String> = sets.iter().map(|s| s.name.clone()).collect();
    let mut deferred: Vec<VariantSet> = Vec::new();
    if opts.multiversion {
        let mut kept_sets = Vec::new();
        for set in sets {
            if feature_only.contains(&set.name) {
                match set_evidence(&cx, &arch, &set) {
                    Ok(()) => deferred.push(set),
                    Err(why) => {
                        trace(|| format!("feature-only set {{{}}} not generated: {why}", set.name));
                        not_cloned.push(("*".into(), set.name.clone(), format!("the set is not generated: no host evidence for its clones ({why}); the dispatch never selects it")));
                    }
                }
                continue;
            }
            if let Some(s) = admit_set(&mut cx, &mut ext, &mut chain, &eopts, set, false, &variants, &mut clones, &mut not_cloned, &mut clone_of, &mut tree_of) {
                kept_sets.push(s);
            }
        }
        sets = kept_sets;
    }

    if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
        eprintln!("opt: timing phase multiversioning done at {:?}", t0.elapsed());
    }
    // ------------------------------------------------------------------
    // 3. specialization
    // ------------------------------------------------------------------
    let mut fns: Vec<FnReport> = Vec::new();
    let mut specialized: HashMap<ItemId, (usize, GlobalId, ItemId)> = HashMap::new(); // item -> (nodes, residual global, residual item)
    let mut growth = 0usize;
    // (a lane kernel is already a straight-line residual — the lane
    // functor printed it through the residual printer — and is linked by
    // its `lane_equiv`: it is not specialized again)
    let lane_items: HashSet<String> = lanes.iter().map(|l| l.kernel.clone()).collect();
    let exec_order: Vec<ItemId> = elab::order::dependency_order(&ext)
        .into_iter()
        .filter(|i| !ext.item(*i).ghost && matches!(&ext.item(*i).kind, ItemKind::Fn(f) if f.kind == FnKind::Exec))
        .filter(|i| !lane_items.contains(&ext.item(*i).path.to_string()) && !search_items.contains(&ext.item(*i).path.to_string()))
        .collect();
    let user_globals: HashMap<GlobalId, ItemId> = ext.items.iter().filter(|it| matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Exec)).filter_map(|it| cx.out.fn_globals.get(&it.id).map(|g| (*g, it.id))).collect();
    // the per-literal shift lemmas the driver's decisions need (a shift by a
    // literal is exact when its operand is small: `bits::{w,}shl_exact`)
    ensure_shift_lemmas(&mut cx.out.env, &user_globals);
    specialize_items(&mut cx, &mut ext, &mut chain, &eopts, &exec_order, &clone_of, &user_globals, &mut specialized, &mut growth, &mut fns);

    // the feature-only sets with host evidence (plan O8; design §13.1 "the
    // generated sets are the ones the residuals can actually use"), priced
    // before any clone is built: a set none of whose tree functions is ≥ 3%
    // cheaper under the set's tables than under the portable tables, both
    // on the originals' residuals (callees at their printed cost), is not
    // generated. The others are cloned, admitted and specialized like the
    // variant sets' clones (nothing before depends on them: dispatch is at
    // the boundary), and checked again on their own residuals below.
    //
    // The pre-pricing may only drop a set that the check on the clones
    // would drop too. That holds because the only choice of specialization
    // that depends on the cost model is the aegraph's (loop rungs are
    // priced on the portable tables), and its matching does not: a clone of
    // a function whose region matched no rule has its original's residual.
    // A function whose region matched some rule (`Ctx::aegraph_matched`)
    // may get a rewrite under the set's model that the portable model
    // rejected, so it counts as paying here, and the check on its clone
    // decides.
    if !deferred.is_empty() {
        let tuning = cx.opts.tuning.clone();
        let arch_name = arch.name().to_string();
        let portable = cost::model::SetModel::portable(&arch_name, &tuning);
        for set in deferred {
            let model = cost::model::SetModel::new(&set.name, &arch_name, &set.feature_set, &tuning);
            let (tree, _) = multiversion::call_tree_excluding(&ext, &set);
            let mut pc = PrintedCost::default();
            let mut sc = PrintedCost::default();
            let pays = tree.iter().any(|o| {
                if cx.aegraph_matched.contains(o) {
                    trace(|| format!("variant set {{{}}} (before cloning): `{}` has aegraph matches; its clone is priced after cloning", set.name, ext.item(*o).path));
                    return true;
                }
                let (a, b) = (sc.of(&ext, &specialized, &model, *o), pc.of(&ext, &specialized, &portable, *o));
                trace(|| format!("variant set {{{}}} (before cloning): `{}` {} (portable {})", set.name, ext.item(*o).path, cost::model::fmt_mc(a), cost::model::fmt_mc(b)));
                cost::model::beats(a, b)
            });
            if !pays {
                trace(|| format!("variant set {{{}}}: no function of its tree is 3% cheaper under its tables; not generated", set.name));
                not_cloned.push(("*".into(), set.name.clone(), "the set is not generated: no function of its tree is 3% cheaper under the set's cost tables than under the portable ones (priced on the originals' residuals, before any clone is built; no function of the tree has an aegraph match)".into()));
                continue;
            }
            let name = set.name.clone();
            if let Some(s) = admit_set(&mut cx, &mut ext, &mut chain, &eopts, set, true, &variants, &mut clones, &mut not_cloned, &mut clone_of, &mut tree_of) {
                let new: HashSet<ItemId> = tree_of.get(&name).map(|m| m.values().copied().collect()).unwrap_or_default();
                // the user functions: the ones of the main phase and the new
                // clones (never the optimizer's residuals and helpers, which
                // exist by now: a residual is unfolded, not called)
                let mut clone_globals: HashMap<GlobalId, ItemId> = new.iter().filter_map(|c| cx.out.fn_globals.get(c).map(|g| (*g, *c))).collect();
                ensure_shift_lemmas(&mut cx.out.env, &clone_globals);
                clone_globals.extend(user_globals.iter().map(|(g, i)| (*g, *i)));
                let user_globals = clone_globals;
                let order: Vec<ItemId> = elab::order::dependency_order(&ext).into_iter().filter(|i| new.contains(i)).collect();
                specialize_items(&mut cx, &mut ext, &mut chain, &eopts, &order, &clone_of, &user_globals, &mut specialized, &mut growth, &mut fns);
                sets.push(s);
            }
        }
        // (dispatch preference order)
        sets.sort_by_key(|s| set_order.iter().position(|n| *n == s.name).unwrap_or(usize::MAX));
    }

    // rejected cache hits outside any function's summary (none today)
    for r in cx.cache.as_ref().map(|c| c.take_rejected()).unwrap_or_default() {
        cx.failure(format!("proof cache entry rejected by the kernel (add_def: {}) for `{}`: a forged or corrupt entry (R25); removed, the proof rebuilt", r.kind, r.lemma));
    }

    // the obligations of the driven residuals and helpers, set aside while
    // specializing, after all others (numbered from the largest)
    {
        let mut next = cx.out.obligations.iter().map(|o| o.id + 1).max().unwrap_or(0);
        for mut o in std::mem::take(&mut cx.late_obligations) {
            o.id = next;
            next += 1;
            cx.out.obligations.push(o);
        }
    }

    // the feature-only sets pay only where the cost model says so (plan O8,
    // design §13.1 "the generated sets are the ones the residuals can
    // actually use"): a set none of whose clones is ≥ 3% cheaper under the
    // set's tables than its original under the portable tables is dropped
    // (its clones are not printed and nothing dispatches to it)
    if !feature_only.is_empty() {
        let tuning = cx.opts.tuning.clone();
        let arch_name = arch.name().to_string();
        let portable = cost::model::SetModel::portable(&arch_name, &tuning);
        let mut dropped: Vec<String> = Vec::new();
        for set in sets.iter().filter(|s| feature_only.contains(&s.name)) {
            let model = cost::model::SetModel::new(&set.name, &arch_name, &set.feature_set, &tuning);
            let Some(map) = tree_of.get(&set.name) else { continue };
            let mut pairs: Vec<(ItemId, ItemId)> = map.iter().map(|(o, c)| (*o, *c)).collect();
            pairs.sort();
            let mut pc = PrintedCost::default();
            let mut sc = PrintedCost::default();
            let pays = pairs.iter().any(|(o, c)| {
                let (a, b) = (sc.of(&ext, &specialized, &model, *c), pc.of(&ext, &specialized, &portable, *o));
                trace(|| format!("variant set {{{}}}: `{}` {} (portable {})", set.name, ext.item(*c).path, cost::model::fmt_mc(a), cost::model::fmt_mc(b)));
                cost::model::beats(a, b)
            });
            if !pays {
                dropped.push(set.name.clone());
            }
        }
        for name in dropped {
            trace(|| format!("variant set {{{name}}}: no clone is 3% cheaper than its original; not generated"));
            if let Some(map) = tree_of.remove(&name) {
                for c in map.values() {
                    ext.items[c.0 as usize].ghost = true;
                    clone_of.remove(c);
                }
            }
            clones.retain(|r| r.set != name);
            sets.retain(|s| s.name != name);
        }
    }
    if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
        eprintln!("opt: timing phase specialization done at {:?}", t0.elapsed());
    }
    // ------------------------------------------------------------------
    // 4. print view
    // ------------------------------------------------------------------
    let mut print = ext.clone();
    let mut targets: HashMap<ItemId, (GlobalId, GlobalId)> = HashMap::new();
    let residual_items: HashSet<ItemId> = specialized.values().map(|x| x.2).collect();
    for r in &residual_items {
        print.items[r.0 as usize].ghost = true;
    }
    for it in &ext.items {
        if it.ghost || residual_items.contains(&it.id) {
            continue;
        }
        let Some(g) = cx.out.fn_globals.get(&it.id).copied() else { continue };
        match &it.kind {
            ItemKind::Fn(f) if f.kind == FnKind::Exec => {
                let compare = match specialized.get(&it.id) {
                    Some((nodes, rg, ritem)) => {
                        // print the residual body under the function's name
                        let rf = ext.fn_def(*ritem).unwrap().clone();
                        let abi = cx.driven.contains(&it.id) && abi_inlined(&ext, f, *nodes, cx.summaries.get(g).is_some_and(|s| s.calls_recursion));
                        if let ItemKind::Fn(pf) = &mut print.items[it.id.0 as usize].kind {
                            pf.body = rf.body;
                            pf.locals = rf.locals;
                            if abi && pf.inline.is_none() {
                                pf.inline = Some(Inline::Always);
                            }
                        }
                        *rg
                    }
                    None => g,
                };
                targets.insert(it.id, (g, compare));
            }
            ItemKind::Const(_) => {
                targets.insert(it.id, (g, g));
            }
            _ => {}
        }
    }
    // dispatchers for exported functions of the trees (and exported
    // portable functions with variants)
    let exported = crate::canon::exported_items(krate);
    let mut dispatchers = Vec::new();
    if !sets.is_empty() {
        let mut roots: Vec<ItemId> = Vec::new();
        for set in &sets {
            for p in set.map.keys() {
                roots.push(*p);
            }
            if let Some(m) = tree_of.get(&set.name) {
                roots.extend(m.keys().copied());
            }
        }
        roots.sort();
        roots.dedup();
        for p in roots {
            if !exported.contains(&p) {
                continue;
            }
            if let Some(why) = krate.fn_def(p).and_then(multiversion::not_clonable) {
                // (never a tree member; a portable method with variants)
                not_cloned.push((krate.item(p).path.to_string(), "-".into(), format!("no boundary dispatcher: {why}")));
                continue;
            }
            let mut vs = Vec::new();
            for set in &sets {
                let target = set.map.get(&p).copied().or_else(|| tree_of.get(&set.name).and_then(|m| m.get(&p).copied()));
                if let Some(t) = target {
                    vs.push((set.clone(), t));
                }
            }
            if vs.is_empty() {
                continue;
            }
            let orig = krate.item(p).clone();
            let it = &mut print.items[p.0 as usize];
            it.name = format!("{}__{}", orig.name, multiversion::PORTABLE_SUFFIX);
            if let Some(l) = it.path.0.last_mut() {
                *l = it.name.clone();
            }
            it.vis = Vis::Crate;
            dispatchers.push(Dispatcher { module: orig.module, name: orig.name.clone(), portable: p, variants: vs });
        }
    }
    // dead-helper elimination: optimizer helpers no printed function calls
    {
        let mut helpers: Vec<ItemId> = cx.helpers.values().map(|h| h.item).collect();
        helpers.extend(cx.summaries.folds.values().map(|h| h.item));
        helpers.extend(cx.summaries.seg.items().into_iter().map(|(_, i)| i));
        let dropped = seqsum::eliminate_dead_helpers(&mut print, &mut targets, &helpers, &dispatchers.iter().flat_map(|d| std::iter::once(d.portable).chain(d.variants.iter().map(|(_, i)| *i))).collect::<Vec<_>>());
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() && !dropped.is_empty() {
            eprintln!("opt: dead helpers not printed: {dropped:?}");
        }
    }
    if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
        eprintln!("opt: timing phase print view done at {:?}", t0.elapsed());
        if let Some(c) = &cx.cache {
            eprintln!("opt: cache {:?}", *c.stats.borrow());
        }
    }
    // ------------------------------------------------------------------
    // 5. hardware evidence of everything emitted (§9.2)
    // ------------------------------------------------------------------
    evidence_gate(&mut print, &mut targets, &dispatchers, &mut variants, &mut not_emitted, &mut cx.warnings, &mut cx.errors);
    // a dispatched lane kernel needs a host run of the kernel itself (its
    // models are validated one by one; their composition is not): fail
    // closed (R26)
    for l in lanes.iter().filter(|l| l.dispatched && l.host_evidence.is_err()) {
        cx.errors.push(format!("lane kernel `{}` is dispatched without host evidence of the kernel ({}: {}); nothing is emitted (§9.2, plan O10)", l.kernel, l.lane_set, l.host_evidence.as_ref().err().map(String::as_str).unwrap_or("")));
    }
    let warnings = std::mem::take(&mut cx.warnings);
    let errors = std::mem::take(&mut cx.errors);
    Optimized { print, targets, fns, variants, clones, sets, dispatchers, not_cloned, not_emitted, warnings, errors, millis: t0.elapsed().as_millis(), lanes, seq_eq }
}

/// Phase 1b (plan O10): every lane site on every lane target of the
/// architecture with the site's lane count is lifted by the lane functor
/// ([`par::lift::lift_site`]: the kernel `s__<target>` and its
/// kernel-checked `lane_equiv`), priced against the site's best existing
/// code (the portable code, or the site under each ISA variant set: on the
/// M5 the SHA2 instructions), and becomes a dispatchable variant of the
/// site when it is ≥ 3% cheaper and has hardware evidence: its models
/// (as every variant) and a host run of the kernel (`lanes:` set records).
/// Otherwise the kernel is kept out of the emitted code (a ghost item),
/// unless `SANDBLASTER_LANES_COMPILE_ONLY=1` asks to print it (never called)
/// so G7 compiles it.
#[allow(clippy::too_many_arguments)]
fn lane_variants(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, arch: &crate::target::Arch, cands: &[par::sites::Candidate], variants: &mut Vec<VariantReport>, dispatchable: &mut Vec<(ItemId, ItemId)>, lanes: &mut Vec<par::LaneReport>) {
    let compile_only = std::env::var("SANDBLASTER_LANES_COMPILE_ONLY").as_deref() == Ok("1");
    let tuning = cx.opts.tuning.clone();
    let isa_variants: Vec<(ItemId, ItemId)> = dispatchable.clone();
    for c in cands {
        for target in par::tiles::targets_for(arch.name()) {
            if target.lanes != c.lanes {
                continue;
            }
            let site = ext.item(c.site).path.to_string();
            let callee = ext.item(c.callee).path.to_string();
            let kernel = format!("{site}__{}", target.name);
            let users: HashSet<GlobalId> = cx.out.fn_globals.values().copied().collect();
            let t = Instant::now();
            let fault = cx.opts.hooks().and_then(|h| h.lane_fault(&kernel));
            let lifted = par::lift::lift_site_with(cx.out, ext, chain, eopts, c.site, target, &|g| users.contains(&g), fault);
            let mut rep = par::LaneReport { site: site.clone(), callee: callee.clone(), target: target.name.to_string(), lanes: target.lanes, kernel: kernel.clone(), ..Default::default() };
            let l = match lifted {
                Ok(l) => l,
                Err(e) => {
                    trace(|| format!("lane kernel {kernel}: {e}"));
                    // a lane_equiv the kernel rejects is an optimizer fault;
                    // anything else (a callee the functor cannot lift) a note
                    if e.contains("rejected by the kernel") {
                        cx.failure(format!("lane kernel `{kernel}`: {e}"));
                    }
                    rep.proof = Err(e.clone());
                    rep.note = format!("not built: {}", e.chars().take(300).collect::<String>());
                    lanes.push(rep);
                    continue;
                }
            };
            let fdef = ext.fn_def(l.item).cloned().expect("the lane kernel is a function");
            // cost: the kernel against the site's best existing code
            let features = closure(arch, &target.features.iter().map(|f| f.to_string()).collect::<Vec<_>>());
            let lane_model = cost::model::SetModel::new(target.name, arch.name(), &features, &tuning);
            let lifted_cost = lane_model.fn_cost(ext, &fdef, &|_| None);
            let portable = cost::model::SetModel::portable(arch.name(), &tuning);
            let mut best = (par::sites::source_cost(&portable, ext, c.site, &HashMap::new(), &mut HashMap::new()), "portable".to_string());
            for (v, p) in &isa_variants {
                let vf = ext.fn_def(*v).map(|f| f.feature_set.clone()).unwrap_or_default();
                let m = cost::model::SetModel::new("isa", arch.name(), &vf, &tuning);
                let cst = par::sites::source_cost(&m, ext, c.site, &HashMap::from([(*p, *v)]), &mut HashMap::new());
                if cst < best.0 {
                    best = (cst, format!("the site under {{{}}} (`{}` for `{}`)", vf.join(","), ext.item(*v).path, ext.item(*p).path));
                }
            }
            let chosen = cost::model::beats(lifted_cost, best.0);
            // evidence: the models, and a host run of the kernel
            let tarch = targets_arch(arch);
            let mut evidence: Vec<(String, String)> = Vec::new();
            let mut models_ok = true;
            for m in used_models(ext, l.item) {
                match evidence_status(arch, &m) {
                    Ok(s) => evidence.push((m, s)),
                    Err(s) => {
                        models_ok = false;
                        evidence.push((m, s));
                    }
                }
            }
            // the kernel's core text (reports only) and the code a host
            // compiles when it runs the kernel, which names its evidence
            let core_hash = {
                let (_, ret) = par::lift::site_binders(&cx.out.env, cx.out.fn_globals[&c.site]).unwrap_or_default();
                sandblaster_targets::fips::hex(&sandblaster_targets::fips::sha256(l.plan.kernel_body(&l.site, &ret).as_bytes()))
            };
            let fingerprint = par::lane_fingerprint(ext, l.item, target.name);
            let lane_set = match &fingerprint {
                Ok(f) => f.set.clone(),
                Err(_) => format!("{}{}:unprintable", sandblaster_targets::evidence::LANE_SET_PREFIX, target.name),
            };
            rep.core_hash = core_hash;
            rep.kernel_tokens = fingerprint.as_ref().map(|f| f.kernel_tokens.clone()).unwrap_or_default();
            let granted = fingerprint.is_ok() && cx.opts.hooks().is_some_and(|h| h.grants_set_evidence(&lane_set) || h.grants_set_evidence(&format!("{}{}", sandblaster_targets::evidence::LANE_SET_PREFIX, target.name)));
            let host = if let Err(e) = &fingerprint {
                Err(format!("the kernel's emitted text has no fingerprint: {e}"))
            } else if granted {
                Ok("granted by a test hook".to_string())
            } else {
                match tarch.map(|a| sandblaster_targets::evidence::set_validation(a, &lane_set, &features)) {
                    Some(sandblaster_targets::evidence::SetVerdict::Validated { cpus }) => Ok(format!("validated on {}", cpus.join(", "))),
                    Some(sandblaster_targets::evidence::SetVerdict::Missing(why)) => Err(why),
                    None => Err("unknown architecture".into()),
                }
            };
            evidence.push((lane_set.clone(), host.clone().unwrap_or_else(|e| format!("missing: {e}"))));
            let forced = cx.opts.hooks().is_some_and(|h| h.forces_dispatch(&kernel));
            let dispatched = (chosen && models_ok && host.is_ok()) || forced;
            let st = &l.stats;
            let why = if forced && !(chosen && models_ok && host.is_ok()) {
                "dispatched WITHOUT the evidence or the cost model's choice (forced by a test hook)".to_string()
            } else if dispatched {
                "dispatched".to_string()
            } else if !chosen {
                format!("rejected by the cost model: {} per call vs {} for {}", cost::model::fmt_mc(lifted_cost), cost::model::fmt_mc(best.0), best.1)
            } else if !models_ok {
                "not dispatched: some intrinsic models lack hardware evidence for this target (§9.2)".to_string()
            } else {
                format!("not dispatched: no host has run the kernel ({})", host.as_ref().err().map(String::as_str).unwrap_or(""))
            };
            rep.note = format!(
                "lane kernel (plan O10, the lane functor; `lane_equiv` is a kernel-checked congruence chain, not BvRefl): {} scalar operations of `{callee}` → {} vector operations on {} ({} tiles, {} lane inputs, {} constants); lane_equiv {} steps, {} ms (whole lift {} ms); cost {} per call vs {} for {}; evidence record `{lane_set}` (the emitted kernel and its helpers under {}; core text {}); {why}",
                st.scalar_ops,
                st.vector_ops,
                target.name,
                st.tiles,
                st.leaves,
                st.consts,
                st.steps,
                st.millis,
                st.lift_millis,
                cost::model::fmt_mc(lifted_cost),
                cost::model::fmt_mc(best.0),
                best.1,
                sandblaster_targets::evidence::BUILD_RUSTC,
                &rep.core_hash[..16.min(rep.core_hash.len())]
            );
            rep.proof = Ok(l.stats.clone());
            rep.lifted_cost = lifted_cost;
            rep.site_cost = best.0;
            rep.site_best = best.1.clone();
            rep.chosen = chosen;
            rep.dispatched = dispatched;
            rep.host_evidence = host.clone();
            rep.lane_set = lane_set.clone();
            let lemma = cx.global_name(l.lemma);
            variants.push(VariantReport { variant: kernel.clone(), implements: site.clone(), features: features.clone(), equivalence: Ok((lemma, site.clone(), t.elapsed().as_millis())), evidence, dispatched, note: rep.note.clone() });
            if dispatched {
                dispatchable.push((l.item, c.site));
            } else if !compile_only {
                // proven, not used: kept out of the emitted code
                ext.items[l.item.0 as usize].ghost = true;
            } else {
                // public, so rustc generates its code (G7 inspects it)
                ext.items[l.item.0 as usize].vis = Vis::Public;
                rep.note.push_str("; printed for compile-only checks (SANDBLASTER_LANES_COMPILE_ONLY=1), never called");
                if let Some(v) = variants.last_mut() {
                    v.note = rep.note.clone();
                }
            }
            lanes.push(rep);
        }
    }
}

/// The SIMD search variants of `sites` (plan O10, P12; `par::search`):
/// each is dispatched on aarch64 when its per-byte cost beats the
/// source's under the `{neon}` tables and its models have hardware
/// evidence; otherwise it is kept out of the emitted code.
#[allow(clippy::too_many_arguments)]
fn search_variants(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, arch: &crate::target::Arch, sites: &[par::search::Site], variants: &mut Vec<VariantReport>, dispatchable: &mut Vec<(ItemId, ItemId)>, search_items: &mut HashSet<String>) {
    let tuning = cx.opts.tuning.clone();
    let ropts = elab::Options { check_proofs: false, ..eopts.clone() };
    for site in sites {
        let source = ext.item(site.item).path.to_string();
        let t = Instant::now();
        let l = match par::search::lower(cx.out, ext, chain, &ropts, site) {
            Ok(l) => l,
            Err(e) => {
                trace(|| format!("search variant of {source}: {e}"));
                if e.contains("rejected by the kernel") {
                    cx.failure(format!("search variant of `{source}`: {e}"));
                }
                continue;
            }
        };
        let name = ext.item(l.item).path.to_string();
        search_items.insert(name.clone());
        let features = closure(arch, &["neon".to_string()]);
        let model = cost::model::SetModel::new("neon", arch.name(), &features, &tuning);
        let (v_step, s_step) = par::search::step_costs(&model, ext, l.item, site.item);
        let per16 = s_step.saturating_mul(par::search::CHUNK);
        let chosen = cost::model::beats(v_step, per16);
        let mut evidence: Vec<(String, String)> = Vec::new();
        let mut models_ok = true;
        for m in used_models(ext, l.item) {
            match evidence_status(arch, &m) {
                Ok(s) => evidence.push((m, s)),
                Err(s) => {
                    models_ok = false;
                    evidence.push((m, s));
                }
            }
        }
        let dispatched = chosen && models_ok;
        let why = if dispatched {
            "dispatched".to_string()
        } else if !chosen {
            format!("rejected by the cost model: {} per 16 bytes vs {} for the source", cost::model::fmt_mc(v_step), cost::model::fmt_mc(per16))
        } else {
            "not dispatched: some intrinsic models lack hardware evidence for this target (§9.2)".to_string()
        };
        let note = format!(
            "SIMD search (plan O10, P12): 16 bytes per step, test `{}` against {}; search_equiv by the search library ({} instance steps, {} library steps, {} ms); cost {} per 16 bytes vs {} for the source ({} per byte); {why}",
            l.kind.name(),
            l.literal,
            l.instance_steps,
            l.library_steps,
            l.millis,
            cost::model::fmt_mc(v_step),
            cost::model::fmt_mc(per16),
            cost::model::fmt_mc(s_step)
        );
        let lemma = cx.global_name(l.lemma);
        variants.push(VariantReport { variant: name, implements: source.clone(), features: features.clone(), equivalence: Ok((lemma, source, t.elapsed().as_millis())), evidence, dispatched, note });
        if dispatched {
            dispatchable.push((l.item, site.item));
        } else {
            ext.items[l.item.0 as usize].ghost = true;
        }
    }
}

/// Specializes `items` in order (see [`summarize_one`]), recording each
/// outcome in `specialized` (and the summaries callers use) and its report
/// entry in `fns`.
#[allow(clippy::too_many_arguments)]
fn specialize_items(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, items: &[ItemId], clone_of: &HashMap<ItemId, (ItemId, String)>, user_globals: &HashMap<GlobalId, ItemId>, specialized: &mut HashMap<ItemId, (usize, GlobalId, ItemId)>, growth: &mut usize, fns: &mut Vec<FnReport>) {
    for &id in items {
        let t = Instant::now();
        let name = ext.item(id).path.to_string();
        let set = clone_of.get(&id).map(|(_, s)| s.clone());
        trace(|| format!("specialize {name}"));
        let sm = summarize_one(cx, ext, chain, eopts, id, clone_of.get(&id).map(|(o, _)| *o), user_globals, specialized, growth);
        let sp = sm.tier0;
        let driven = sm.driven;
        // proof-cache hits the kernel rejected while summarizing it (its
        // lemma's, or a helper's): forged or corrupt entries (R25), removed
        // and rebuilt, so the outcome is the cold build's; an optimizer
        // fault all the same, whatever the outcome
        let cache_rejected = cx.cache.as_ref().map(|c| c.take_rejected()).unwrap_or_default();
        for r in &cache_rejected {
            cx.failure(format!("`{name}`: proof cache entry rejected by the kernel (add_def: {}) for `{}`: a forged or corrupt entry (R25); removed, the proof rebuilt ({})", r.kind, r.lemma, r.error.chars().take(160).collect::<String>()));
        }
        if let Outcome::Specialized { nodes, residual, .. } = &sp.outcome {
            cx.tier0_nodes.insert(id, *nodes);
            if !sp.injected
                && let Some(g) = cx.out.fn_globals.get(&id).copied()
            {
                cx.tier0_residual.insert(g, *residual);
            }
            if sp.recursive_calls {
                cx.tier0_recursive.insert(id);
            }
        }
        match &driven {
            Some(DriveOut { outcome: Some(_), trivial, .. }) => {
                cx.driven.insert(id);
                if *trivial {
                    cx.drive_trivial.insert(id);
                }
            }
            Some(d) if !d.trivial => {
                cx.drive_failed.insert(id, d.reason.clone());
            }
            Some(_) => {}
            None => {}
        }
        let outcome = match &driven {
            Some(d) if d.outcome.is_some() => d.outcome.clone().unwrap(),
            // a driven candidate rejected by the kernel or elaboration: an
            // optimizer fault, the source stays (the proven fallback)
            Some(d) if d.failure && matches!(sp.outcome, Outcome::Unspecialized { .. }) => Outcome::Unspecialized { reason: d.reason.clone(), failure: true },
            // the same fault next to an admitted straight-line residual: that
            // residual stays (kernel-checked by conversion), and the fault is
            // reported all the same (a build error under strict options)
            Some(d) if d.failure => {
                cx.failure(format!("`{name}`: the driven candidate was rejected ({}): {}; the straight-line residual is kept", d.rejected_by.as_deref().unwrap_or("kernel"), d.reason.chars().take(600).collect::<String>()));
                sp.outcome.clone()
            }
            _ => sp.outcome.clone(),
        };
        if let Outcome::Specialized { nodes, residual, calls } = &outcome {
            let ritem = match &driven {
                Some(DriveOut { ritem: Some(r), outcome: Some(_), .. }) => *r,
                _ => ItemId(sp.ritem.expect("a tier-0 residual item").0),
            };
            specialized.insert(id, (*nodes, *residual, ritem));
            // the summary its callers use (design §6.4)
            if let Some(g) = cx.out.fn_globals.get(&id).copied() {
                let (link, leaves, expanded_leaves) = match &driven {
                    Some(DriveOut { outcome: Some(_), lemma: Some(l), leaves, expanded_leaves, .. }) => (cx.out.env.lookup_global(l).map(summary::SumLink::Lemma), *leaves, *expanded_leaves),
                    _ => (Some(summary::SumLink::Conversion), 1, 1),
                };
                if let Some(link) = link {
                    let calls_recursion = calls.iter().any(|c| cx.out.env.lookup_global(c).is_some_and(|h| symex::is_recursive(&cx.out.env, h)));
                    let result_bytes = ty_bytes(ext, &ext.fn_def(id).unwrap().ret, 0);
                    let helper_items: HashSet<String> = cx.helpers.values().map(|h| ext.item(h.item).path.to_string()).collect();
                    let calls_user = calls.iter().any(|c| !helper_items.contains(c) && ext.items.iter().any(|it| it.path.to_string() == *c && matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Exec)));
                    let fl: Vec<summary::FactLemma> = facts::of(g).into_iter().map(|f| summary::FactLemma { lemma: f.lemma, name: f.name, states: f.states }).collect();
                    cx.summaries.insert(summary::FnSummary { item: id, source: g, residual: *residual, residual_item: ritem, link, nodes: *nodes, result_leaves: leaves, expanded_leaves, calls_recursion, result_bytes, calls_user, facts: fl });
                }
            }
        }
        let f = ext.fn_def(id).unwrap();
        if let Outcome::Unspecialized { reason, failure } = &outcome {
            if f.specialize {
                cx.errors.push(format!("`{name}` is marked #[specialize] but was not specialized: {reason}"));
            } else if *failure {
                cx.failure(format!("`{name}`: specialization failed: {reason}"));
            }
        }
        // the straight-line residual (tier 0) is linked by conversion, a
        // driven residual by its equality lemma; any other outcome prints
        // the source
        let (link, rung) = match (&outcome, &driven) {
            (Outcome::Specialized { .. }, Some(DriveOut { outcome: Some(_), lemma: Some(l), loop_rung, .. })) => (Some(Link::Lemma(l.clone())), Some(loop_rung.unwrap_or(Rung::Driven))),
            (Outcome::Specialized { .. }, _) => (Some(Link::Conversion), Some(Rung::StraightLine)),
            (Outcome::Unspecialized { .. }, _) => (None, None),
        };
        let mut candidates = Vec::new();
        let driven_chosen = matches!(&driven, Some(DriveOut { outcome: Some(_), .. }));
        if sp.attempted {
            let (cost, chosen, reason) = match &sp.outcome {
                Outcome::Specialized { nodes, .. } => (BTreeMap::from([(set.clone().unwrap_or_else(|| "portable".into()), *nodes as u64)]), !driven_chosen, if driven_chosen { "admitted: kernel-checked conversion (check_residual_equal); superseded by the driven residual".to_string() } else { "admitted: kernel-checked conversion (check_residual_equal)".to_string() }),
                Outcome::Unspecialized { reason, .. } => (BTreeMap::new(), false, reason.clone()),
            };
            candidates.push(CandidateReport { rung: Rung::StraightLine, cost, chosen, reason, rejected_by: sp.rejected_by.clone(), injected: sp.injected });
        }
        let mut budgets = sp.budgets.clone();
        if let Some(d) = &driven {
            let cost = match &d.outcome {
                Some(Outcome::Specialized { nodes, .. }) => BTreeMap::from([(set.clone().unwrap_or_else(|| "portable".into()), *nodes as u64)]),
                _ => BTreeMap::new(),
            };
            let mut reason = d.reason.clone();
            if !cache_rejected.is_empty() {
                let what: Vec<String> = cache_rejected.iter().map(|r| format!("`{}` (add_def: {})", r.lemma, r.kind)).collect();
                reason.push_str(&format!("; proof cache: rejected entries removed and rebuilt: {}", what.join(", ")));
            }
            candidates.push(CandidateReport { rung: d.loop_rung.unwrap_or(Rung::Driven), cost, chosen: d.outcome.is_some(), reason, rejected_by: d.rejected_by.clone(), injected: false });
            if d.outcome.is_some() {
                budgets = d.budgets.clone();
            }
            // (a loop summary is spent whether or not the driven candidate
            // was admitted)
            budgets.loopsum_steps = d.budgets.loopsum_steps;
        }
        if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
            eprintln!("opt: timing fn {name}: {:?}", t.elapsed());
        }
        let facts_exported: Vec<String> = cx.out.fn_globals.get(&id).map(|g| facts::of(*g).iter().map(|f| format!("{}: {}", f.name, f.states)).collect()).unwrap_or_default();
        fns.push(FnReport { item: id, name, set, outcome, link, rung, candidates, budgets_used: budgets, facts_exported, millis: t.elapsed().as_millis() });
    }
}

/// `Ok` when a host has run the feature-only set's clones
/// (`sandblaster_targets::evidence::set_validation`: a passing run of the set
/// as defined now, on a CPU that reports every feature of the set, under a
/// validating executor, and no current failure anywhere; fail closed), or
/// a test hook grants it; `Err(why)` otherwise.
fn set_evidence(cx: &Ctx<'_>, arch: &crate::target::Arch, set: &VariantSet) -> Result<(), String> {
    if cx.opts.hooks().is_some_and(|h| h.grants_set_evidence(&set.name)) {
        return Ok(());
    }
    let Some(a) = targets_arch(arch) else { return Err("unknown architecture".into()) };
    match sandblaster_targets::evidence::set_validation(a, &set.name, &set.feature_set) {
        sandblaster_targets::evidence::SetVerdict::Validated { cpus } => {
            trace(|| format!("feature-only set {{{}}}: host evidence on {}", set.name, cpus.join(", ")));
            Ok(())
        }
        sandblaster_targets::evidence::SetVerdict::Missing(why) => Err(why),
    }
}

/// Clones the call tree of `set`, elaborates the clones, relates each to
/// its original (kernel α-equivalence modulo the renaming) and proves its
/// equality lemma (`mirror`, callees first); `Some(set)` when every clone
/// is admitted. A feature-only set (`is_fo`) is optional: its functions
/// whose clone is not admitted leave its tree and it is tried again (at
/// most three times), and its failures are notes, not optimizer faults.
#[allow(clippy::too_many_arguments)]
fn admit_set(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, mut set: VariantSet, is_fo: bool, variants: &[VariantReport], clones: &mut Vec<CloneReport>, not_cloned: &mut Vec<(String, String, String)>, clone_of: &mut HashMap<ItemId, (ItemId, String)>, tree_of: &mut HashMap<String, HashMap<ItemId, ItemId>>) -> Option<VariantSet> {
    // failures of a feature-only set are notes (see below); of a
    // variant set, optimizer faults
    let set_failure = |cx: &mut Ctx<'_>, notes: &mut Vec<String>, msg: String| if is_fo { notes.push(msg) } else { cx.failure(msg) };
    'attempt: for attempt in 0..=3 {
        let mut failing: Vec<ItemId> = Vec::new();
        let mut fo_notes: Vec<String> = Vec::new();
        // what this attempt adds to the elaboration's records (a
        // retry takes them back: its clones reuse the names)
        let marks = (cx.out.obligations.len(), cx.out.defs.len(), cx.out.diags.list.len());
        let (tree, excluded) = multiversion::call_tree_excluding(ext, &set);
        for (id, why) in excluded {
            not_cloned.push((ext.item(id).path.to_string(), set.name.clone(), why.to_string()));
        }
        let n_before = ext.items.len();
        let map = multiversion::clone_tree(ext, &set, &tree);
        let order: Vec<ItemId> = elab::order::dependency_order(&ext).into_iter().filter(|i| i.0 as usize >= n_before).collect();
        let mut captured: Vec<elab::generated::GenDef> = Vec::new();
        let failed = match elab::generated::resume(cx.out, &ext, &order, chain, eopts, Some(&mut captured)) {
            Ok(f) => f,
            Err(e) => order.iter().copied().inspect(|_| cx.warnings.push(format!("clone elaboration: {e}"))).collect(),
        };
        let mut ok = failed.is_empty();
        if !ok {
            failing.extend(failed.iter().filter_map(|c| map.iter().find(|(_, cc)| *cc == c).map(|(o, _)| *o)));
            // the first error of this attempt says why (its elaboration records are taken back below)
            let why = cx.out.diags.list.get(marks.2..).and_then(|l| l.iter().find(|d| d.severity == crate::diag::Severity::Error)).map(|d| format!(" (first error: {})", d.msg.chars().take(300).collect::<String>())).unwrap_or_default();
            set_failure(cx, &mut fo_notes, format!("variant set {{{}}}: {} clone(s) failed to elaborate: {}; the set is not dispatched{why}", set.name, failed.len(), failed.iter().map(|i| ext.item(*i).path.to_string()).collect::<Vec<_>>().join(", ")));
        }
        // relation check (kernel α-equivalence modulo the renaming)
        let mut corr: HashMap<GlobalId, GlobalId> = HashMap::new();
        for (p, v) in &set.map {
            if let (Some(gv), Some(gp)) = (cx.out.fn_globals.get(v), cx.out.fn_globals.get(p)) {
                corr.insert(*gv, *gp);
            }
        }
        for (o, c) in map.iter().filter(|_| ok) {
            // callees before callers: relate in dependency order below
            let _ = (o, c);
        }
        if ok {
            for c in order.iter() {
                let (o, _) = map.iter().find(|(_, cc)| *cc == c).map(|(o, cc)| (*o, *cc)).unwrap();
                let cn = ext.item(*c).path.to_string();
                let on = ext.item(o).path.to_string();
                let related = cx.related_fn(&cn, &on, &mut corr);
                if let Err(e) = &related {
                    ok = false;
                    failing.push(o);
                    set_failure(cx, &mut fo_notes, format!("clone `{cn}` is not the renaming of `{on}`: {e}"));
                }
                clones.push(CloneReport { clone: cn, original: on, set: set.name.clone(), related, lemma: None });
            }
        }
        // kernel-checked equality lemmas (callees first; see `mirror`)
        let mut set_lemmas: HashMap<GlobalId, (GlobalId, GlobalId)> = HashMap::new();
        if ok && let Some(eq) = mirror::EqIds::new(&cx.out.env) {
            let lemmas = &mut set_lemmas;
            for v in variants {
                if let (Ok((lemma, rhs, _)), Some(gv)) = (&v.equivalence, cx.out.env.lookup_global(&v.variant))
                    && let (Some(gl), Some(gr)) = (cx.out.env.lookup_global(lemma), cx.out.env.lookup_global(rhs))
                    && rhs == &v.implements
                {
                    lemmas.insert(gv, (gr, gl));
                }
            }
            for c in order.iter() {
                let (o, _) = map.iter().find(|(_, cc)| *cc == c).map(|(o, cc)| (*o, *cc)).unwrap();
                let cn = ext.item(*c).path.to_string();
                let (Some(gc), Some(go)) = (cx.out.fn_globals.get(c).copied(), cx.out.fn_globals.get(&o).copied()) else { continue };
                let Some(pre) = captured.iter().find(|d| d.global == gc) else { continue };
                // loop helpers first (matched by their deterministic names)
                let on = ext.item(o).path.to_string();
                let orig_defs: HashMap<String, GlobalId> = defs_of(cx.out, &on).into_iter().collect();
                for hd in captured.iter().filter(|d| d.name.starts_with(&format!("{cn}::loop#"))) {
                    let suffix = &hd.name[cn.len()..];
                    let Some(ho) = orig_defs.get(&format!("{on}{suffix}")).copied() else { continue };
                    match mirror::prove_clone(&mut cx.out.env, hd.global, ho, &hd.body, &hd.recursion, &lemmas, eq, &format!("{}::clone_equiv", hd.name), cx.opts.clone_budget) {
                        Ok(l) => {
                            lemmas.insert(hd.global, (ho, l));
                        }
                        Err(e) => trace(|| format!("clone lemma {}: {}", hd.name, e.chars().take(300).collect::<String>())),
                    }
                }
                let t = Instant::now();
                let size = elab::tm::size_capped(&cx.out.env.global_body(go).unwrap_or_else(|| pre.body.clone()), 1 << 20);
                // a clone without its lemma is not admitted (plan O4: QMDB
                // has none, so the renaming argument is retired): its
                // variant set falls back to the portable code
                if size > cx.opts.clone_lemma_max_nodes {
                    ok = false;
                    failing.push(o);
                    let msg = format!("clone `{cn}`: no kernel-checked equality lemma (body larger than {} nodes); variant set {{{}}} is not dispatched", cx.opts.clone_lemma_max_nodes, set.name);
                        set_failure(cx, &mut fo_notes, msg);
                    continue;
                }
                let lemma_name = format!("{cn}::clone_equiv");
                // test hooks: a clone whose proof is skipped but claimed
                // (R27), or a proof term injected in place of `mirror`'s
                if cx.opts.hooks().is_some_and(|h| h.forges_clone_lemma(&cn)) {
                    if let Some(r) = clones.iter_mut().find(|r| r.clone == cn) {
                        r.lemma = Some(lemma_name.clone());
                    }
                    continue;
                }
                let proven = match cx.opts.hooks().and_then(|h| h.proof(&lemma_name)) {
                    Some(p) => add_link_lemma(&mut cx.out.env, gc, go, &p, &pre.recursion, &lemma_name, cx.opts.clone_budget),
                    None => mirror::prove_clone(&mut cx.out.env, gc, go, &pre.body, &pre.recursion, &lemmas, eq, &lemma_name, cx.opts.clone_budget).or_else(|e| {
                        // a non-recursive clone: both sides unfold to
                        // the same value (`BvRefl`, transparent), as a
                        // variant's `VariantEquiv` (plan O8)
                        if matches!(pre.recursion, sandblaster_kernel::term::Recursion::None) {
                            variant::prove_named(&mut cx.out.env, gc, go, &lemma_name, cx.opts.clone_budget).map(|q| q.lemma).map_err(|e2| format!("{e}; by BvRefl: {}", e2.chars().take(200).collect::<String>()))
                        } else {
                            Err(e)
                        }
                    }),
                };
                match proven {
                    Ok(l) => {
                        lemmas.insert(gc, (go, l));
                        if let Some(r) = clones.iter_mut().find(|r| r.clone == cn) {
                            r.lemma = Some(lemma_name);
                        }
                        trace(|| format!("clone lemma {cn}: proven in {:?}", t.elapsed()));
                    }
                    Err(e) => {
                        trace(|| format!("clone lemma {cn}: {}", e.chars().take(300).collect::<String>()));
                        ok = false;
                        failing.push(o);
                        set_failure(cx, &mut fo_notes, format!("clone `{cn}`: no kernel-checked equality lemma ({}); variant set {{{}}} is not dispatched", e.chars().take(200).collect::<String>(), set.name));
                    }
                }
            }
        }
        // emission chain (design §3.1): every clone lemma the report
        // claims must be a kernel-checked lemma with exactly the
        // statement `Π x̄. Eq(R, clone x̄, original x̄)`. A claim that does
        // not verify is an optimizer bug, and the whole set falls back
        // to the portable code (red team R27).
        if ok {
            for r in clones.iter_mut().filter(|r| r.set == set.name) {
                let Some(l) = r.lemma.clone() else { continue };
                let (Some(gc), Some(go)) = (cx.out.env.lookup_global(&r.clone), cx.out.env.lookup_global(&r.original)) else { continue };
                if let Err(e) = verify_link_lemma(&cx.out.env, &l, gc, go) {
                    ok = false;
                    r.lemma = None;
                    let msg = format!("emission chain: clone `{}` claims the lemma `{l}`, which {e}; variant set {{{}}} is not dispatched", r.clone, set.name);
                    cx.failure(msg);
                }
            }
        }
        if ok {
            for (o, c) in &map {
                clone_of.insert(*c, (*o, set.name.clone()));
                cx.clone_of.insert(*c, (*o, set.name.clone()));
            }
            cx.clone_lemmas.extend(set_lemmas.drain());
            trace(|| format!("variant set {{{}}}: {} clone(s) admitted (attempt {})", set.name, map.len(), attempt + 1));
            tree_of.insert(set.name.clone(), map);
            return Some(set);
        }
        // clones stay in the crate (elaborated or not) but are
        // neither printed nor dispatched
        for c in map.values() {
            ext.items[c.0 as usize].ghost = true;
        }
        // a feature-only set is an optional speedup: its functions
        // whose clone could not be admitted are left out of its tree
        // (their callers call the portable code) and the tree is
        // built again, at most three times; a set that still fails
        // is not generated (a note, not an optimizer fault)
        if is_fo {
            clones.retain(|r| r.set != set.name);
            failing.sort();
            failing.dedup();
            cx.out.obligations.truncate(marks.0);
            cx.out.defs.truncate(marks.1);
            cx.out.diags.list.truncate(marks.2);
            if !failing.is_empty() && attempt < 3 {
                for o in &failing {
                    not_cloned.push((ext.item(*o).path.to_string(), set.name.clone(), "its clone was not admitted (no kernel-checked equality lemma); it keeps calling the portable code".into()));
                }
                set.blocked.extend(failing.iter().copied());
                continue 'attempt;
            }
            for n in &fo_notes {
                trace(|| format!("feature-only set {{{}}} not generated: {n}", set.name));
            }
        }
        break 'attempt;
    }
    None
}

/// The cost of a function as printed (its residual when specialized, else
/// its source) under one set's model, callees at their own printed cost
/// (memoized; a recursive callee costs a call).
#[derive(Default)]
struct PrintedCost {
    memo: HashMap<ItemId, u64>,
    active: HashSet<ItemId>,
}

impl PrintedCost {
    fn of(&mut self, ext: &Crate, specialized: &HashMap<ItemId, (usize, GlobalId, ItemId)>, model: &cost::model::SetModel, id: ItemId) -> u64 {
        if let Some(c) = self.memo.get(&id) {
            return *c;
        }
        if !self.active.insert(id) || self.active.len() > 64 {
            return model.tables.first().map(|t| t.op(cost::tables::Op::Call).lat).unwrap_or(0);
        }
        let body = specialized.get(&id).map(|(_, _, r)| *r).unwrap_or(id);
        let c = match ext.fn_def(body) {
            Some(f) => {
                let f = f.clone();
                let me = std::cell::RefCell::new(&mut *self);
                model.fn_cost(ext, &f, &|cid| Some(me.borrow_mut().of(ext, specialized, model, cid)))
            }
            None => 0,
        };
        self.active.remove(&id);
        self.memo.insert(id, c);
        c
    }
}

/// The hash of the inputs that may change the optimizer's choices besides
/// the source, the variant set and the options (design §17, DESIGN §8.2
/// item 10): the tuning evidence (its hash) and the crate's `PROFILE.json`
/// samples. It keys the proof cache.
pub fn choice_inputs_hash(opts: &OptOptions) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: &[u8]| {
        for x in b {
            h ^= u64::from(*x);
            h = h.wrapping_mul(0x100_0000_01b3);
        }
    };
    eat(&opts.tuning.hash.to_le_bytes());
    for (k, samples) in &opts.loops.profile {
        eat(k.as_bytes());
        for s in samples {
            for v in s {
                eat(&v.map(|x| x.to_le_bytes()).unwrap_or([0xff; 16]));
            }
        }
    }
    h
}

/// Adds the exactness lemmas of every shift by a literal in the bodies of
/// `fns` (`bits::shl_exact_<w>_<k>`, `bits::wshl_exact_<w>_<k>`, checked
/// lemmas generated on demand by `auto::bitlib`): linear arithmetic uses
/// them to read `a << k` as `a · 2^k` when `a ≤ MAX >> k` (design §12.3:
/// the accumulated groups of a varint reader), where the kernel's
/// linearization has a carry atom that only integer cuts would remove.
fn ensure_shift_lemmas(env: &mut sandblaster_kernel::api::Env, fns: &HashMap<GlobalId, ItemId>) {
    let mut gs: Vec<GlobalId> = fns.keys().copied().collect();
    gs.sort();
    ensure_shift_lemmas_in(env, &gs);
}

/// [`ensure_shift_lemmas`] for the bodies of `gs` (a committed helper or
/// residual: shifts whose amount became a literal by specialization).
fn ensure_shift_lemmas_in(env: &mut sandblaster_kernel::api::Env, gs: &[GlobalId]) {
    use crate::auto::bitlib::{self, Family};
    use sandblaster_kernel::term::{PrimOp, Term};
    let mut want: std::collections::BTreeSet<(u8, u32, u32)> = std::collections::BTreeSet::new();
    let widths = [sandblaster_kernel::term::Width::U8, sandblaster_kernel::term::Width::U16, sandblaster_kernel::term::Width::U32, sandblaster_kernel::term::Width::U64, sandblaster_kernel::term::Width::Usize];
    for &g in gs {
        let Some(body) = env.global_body(g) else { continue };
        elab::tm::any_node(&body, &mut |n| {
            if let Term::Prim { op: op @ (PrimOp::Shl(w) | PrimOp::WShl(w)), args, .. } = n
                && let Some(Term::Lit { n: k, .. }) = args.get(1).map(|a| &**a)
                && let Some(k) = num_traits::ToPrimitive::to_u32(k)
                && let Some(wi) = widths.iter().position(|x| x == w)
            {
                want.insert((matches!(op, PrimOp::Shl(_)) as u8, wi as u32, k));
            }
            false
        });
    }
    for (checked, wi, k) in want {
        let fam = if checked == 1 { Family::ShlExact } else { Family::WshlExact };
        let w = widths[wi as usize];
        if fam.valid(w, k) {
            let mut b = Budget { steps: 200_000_000 };
            if let Err(e) = bitlib::ensure(env, fam, w, k, &mut b) {
                trace(|| format!("shift lemma {}: {e}", bitlib::lemma_name(fam, w, k)));
            }
        }
    }
}

/// Result values larger than this many bytes are returned through memory,
/// and a caller using part of them pays for all of it (design §6.4: the
/// call ABI dominates).
const ABI_INLINE_BYTES: u64 = 64;

/// Residuals up to this size (nodes) get the ABI inlining hint.
const ABI_INLINE_NODES: usize = 1024;

/// Whether a driven residual of `f` is printed `#[inline(always)]` (design
/// §6.4, §6.7: the call ABI dominates): its result is an aggregate larger
/// than [`ABI_INLINE_BYTES`], returned through memory, so a caller that
/// uses part of it (a field, `is_some()`) lets the compiler drop the rest
/// only once the residual is inlined; loop-free residuals up to
/// [`ABI_INLINE_NODES`] nodes. A semantics-free attribute (the round trip
/// ignores it).
fn abi_inlined(k: &Crate, f: &FnDef, nodes: usize, calls_recursion: bool) -> bool {
    !calls_recursion && nodes <= ABI_INLINE_NODES && ty_bytes(k, &f.ret, 0).is_some_and(|b| b > ABI_INLINE_BYTES)
}

/// An estimate of the size of a value of type `t` (bytes; `None` for types
/// it does not know).
fn ty_bytes(k: &Crate, t: &Ty, depth: u32) -> Option<u64> {
    if depth > 16 {
        return None;
    }
    Some(match t {
        Ty::Bool => 1,
        Ty::Uint(u) => match u {
            UintTy::U8 => 1,
            UintTy::U16 => 2,
            UintTy::U32 => 4,
            UintTy::U64 | UintTy::Usize => 8,
        },
        Ty::I32 => 4,
        Ty::Tuple(ts) => ts.iter().map(|x| ty_bytes(k, x, depth + 1)).sum::<Option<u64>>()?,
        Ty::Array(e, n) => ty_bytes(k, e, depth + 1)?.saturating_mul(*n),
        Ty::Ref(inner) => match &**inner {
            Ty::Slice(_) => 16,
            _ => 8,
        },
        Ty::Option(x) => ty_bytes(k, x, depth + 1)?.saturating_add(1),
        Ty::Adt(item, args) => match &k.item(*item).kind {
            ItemKind::Struct(s) => s.fields.iter().map(|fd| ty_bytes(k, &fd.ty.subst(args), depth + 1)).sum::<Option<u64>>()?,
            _ => return None,
        },
        Ty::Vector(v) => (v.lanes().0.bits() as u64 / 8).saturating_mul(v.lanes().1),
        _ => return None,
    })
}

/// `VariantEquiv` against a transparent copy of the portable function
/// (see [`variant`]): the portable function is elaborated again as a hidden
/// clone, capturing its pre-commit definitions; each is added once more
/// with `opaque = false` (callee globals redirected to the earlier twins),
/// every twin is related to the portable definition by kernel
/// α-equivalence modulo the renaming, and the lemma is proven against the
/// twin of the function.
#[allow(clippy::too_many_arguments)]
fn transparent_equiv(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, _v: ItemId, p: ItemId, gv: GlobalId, gp: GlobalId) -> Result<variant::Equiv, String> {
    let set = VariantSet::of_variants("transparent".into(), vec![], vec![], HashMap::new());
    let map = multiversion::clone_tree(ext, &set, &[p]);
    let copy = map[&p];
    {
        let orig = krate_fn_features(ext, p);
        if let ItemKind::Fn(f) = &mut ext.items[copy.0 as usize].kind {
            f.target_features = orig.0;
            f.feature_set = orig.1;
        }
        ext.items[copy.0 as usize].cfg = ext.item(p).cfg.clone();
    }
    let mut captured = Vec::new();
    let failed = elab::generated::resume(cx.out, ext, &[copy], chain, eopts, Some(&mut captured));
    // the hidden copy is never printed
    ext.items[copy.0 as usize].ghost = true;
    if !failed?.is_empty() {
        return Err("the transparent copy did not check".into());
    }
    let copy_name = ext.item(copy).path.to_string();
    let orig_name = ext.item(p).path.to_string();
    let orig_defs: HashMap<String, GlobalId> = defs_of(cx.out, &orig_name).into_iter().collect();
    let mut twin_of: HashMap<GlobalId, GlobalId> = HashMap::new();
    let mut corr: HashMap<GlobalId, GlobalId> = HashMap::new();
    let mut fn_twin = None;
    for d in captured.iter().filter(|d| d.kind != sandblaster_kernel::term::DefKind::Ensures) {
        let body = map_globals(&d.body, &twin_of);
        let name = format!("{}#transparent", d.name);
        let decl = sandblaster_kernel::term::DefDecl { name: std::rc::Rc::from(name.as_str()), kind: d.kind, ty: d.ty.clone(), body, recursion: d.recursion.clone(), arity: d.arity, opaque: false };
        let mut b = Budget { steps: cx.opts.check_budget };
        let tg = cx.out.env.add_def(decl, &mut b).map_err(|e| format!("transparent twin `{name}`: {}", e.to_string().chars().take(300).collect::<String>()))?;
        twin_of.insert(d.global, tg);
        let suffix = d.name.strip_prefix(&copy_name).ok_or("unexpected captured definition")?;
        let o = orig_defs.get(&format!("{orig_name}{suffix}")).copied().ok_or_else(|| format!("`{}` has no portable counterpart", d.name))?;
        corr.insert(tg, o);
        if suffix.is_empty() {
            fn_twin = Some(tg);
        }
    }
    // every twin is the portable definition up to names and opacity
    for (t, o) in corr.clone() {
        cx.related(t, o, &corr)?;
    }
    let gc = fn_twin.ok_or("no twin of the function")?;
    let _ = gp;
    variant::prove(&mut cx.out.env, gv, gc, cx.opts.check_budget)
}

/// `t` with every `Global(g)` in `map` replaced (all positions).
fn map_globals(t: &sandblaster_kernel::term::Tm, map: &HashMap<GlobalId, GlobalId>) -> sandblaster_kernel::term::Tm {
    use sandblaster_kernel::term::Term;
    elab::tm::map_post(t, 0, &mut |n, _| match &*n {
        Term::Global(g) => Some(map.get(g).map(|h| std::rc::Rc::new(Term::Global(*h))).unwrap_or(n)),
        _ => Some(n),
    })
    .unwrap_or_else(|| t.clone())
}

fn krate_fn_features(k: &Crate, id: ItemId) -> (Vec<String>, Vec<String>) {
    let f = k.fn_def(id).unwrap();
    (f.target_features.clone(), f.feature_set.clone())
}

/// The result of [`specialize_one`].
struct SpecOut {
    outcome: Outcome,
    budgets: BudgetsUsed,
    /// A candidate was built or proposed (the straight-line rung was tried).
    attempted: bool,
    /// The checker that refused the candidate.
    rejected_by: Option<String>,
    /// The candidate was proposed by a test hook.
    injected: bool,
    /// The residual item (on success; the last item of the crate).
    ritem: Option<ItemId>,
    /// The residual keeps a call of a recursive user function (the driver
    /// may unroll it: static measure or structure).
    recursive_calls: bool,
    /// The residual keeps a call of a user recursion that is static within
    /// the driver's unroll limit (design §6.2): the driver runs too, and
    /// its unrolled residual replaces this one when admitted.
    static_recursion: bool,
    /// The symbolic value of an admitted straight-line residual (the
    /// aegraph's region, plan O8).
    sym: Option<symex::Symex>,
}

/// Distinct HIR expression nodes of a body (the cost of an injected
/// candidate, which has no residual DAG).
fn hir_nodes(e: &Expr) -> usize {
    struct V(usize);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            self.0 += 1;
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(0);
    crate::visit::Visitor::expr(&mut v, e);
    v.0
}

/// Specializes one function (see the module docs); on success the
/// residual item is the last item of `ext`.
///
/// The candidate is the straight-line residual of the symbolic execution,
/// or one proposed by a test hook ([`hooks`]: another function's body, or a
/// cache entry). A cache entry's proof skeleton is submitted to
/// `Env::add_def` first (the kernel re-checks every hit); every candidate is
/// then admitted only by `Env::check_residual_equal`.
#[allow(clippy::too_many_arguments)]
fn specialize_one(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, id: ItemId, user_globals: &HashMap<GlobalId, ItemId>, _specialized: &HashMap<ItemId, (usize, GlobalId, ItemId)>, growth: &mut usize) -> SpecOut {
    let mut budgets = BudgetsUsed::default();
    let name = ext.item(id).path.to_string();
    let injected = cx.opts.hooks().and_then(|h| h.candidate(&name));
    let cache_proof = cx.opts.hooks().and_then(|h| h.cache_proof(&name));
    let is_injected = injected.is_some() || cache_proof.is_some();
    macro_rules! out {
        ($reason:expr, $failure:expr, $attempted:expr, $rejected:expr) => {
            SpecOut { outcome: Outcome::Unspecialized { reason: $reason, failure: $failure }, budgets: budgets.clone(), attempted: $attempted, rejected_by: $rejected, injected: is_injected, ritem: None, recursive_calls: false, static_recursion: false, sym: None }
        };
    }
    let f = ext.fn_def(id).unwrap().clone();
    if !f.generics.is_empty() {
        return out!("generic function".into(), false, false, None);
    }
    let Some(g) = cx.checked(id) else { return out!("not kernel-checked".into(), true, false, None) };
    let mut recursive_calls = false;
    let mut static_recursion = false;
    let mut sym_keep: Option<symex::Symex> = None;
    // the candidate: (function definition of the residual, nodes, opaque calls)
    let (rf, nodes, calls): (FnDef, usize, Vec<String>) = match &injected {
        Some(src) => {
            let Some(sid) = ext.items.iter().find(|it| it.path.to_string() == *src && matches!(&it.kind, ItemKind::Fn(_))).map(|it| it.id) else {
                return out!(format!("injected candidate `{src}` is not a function of the crate"), true, true, Some("injection".into()));
            };
            let sf = ext.fn_def(sid).unwrap().clone();
            if sf.params.len() != f.params.len() || !matches!(sf.body, FnBody::Exec(_)) {
                return out!(format!("injected candidate `{src}` does not have the signature of `{name}`"), true, true, Some("injection".into()));
            }
            let FnBody::Exec(b) = &sf.body else { unreachable!() };
            let n = hir_nodes(b);
            // the candidate's own parameters, locals, requires and body under
            // the function's name and signature
            let mut rf = f.clone();
            rf.params = sf.params.clone();
            rf.locals = sf.locals.clone();
            rf.requires = sf.requires.clone();
            rf.body = sf.body.clone();
            rf.decreases = None;
            (rf, n, vec![])
        }
        None => {
            // callees: the ones tier 0 specialized below the inline threshold
            // are inlined, every other user function is an opaque call (tier
            // 0 stays what it was before the driver: a driven callee's body
            // has control flow)
            let inline: HashSet<GlobalId> = cx.tier0_nodes.iter().filter(|(_, n)| **n <= cx.opts.inline_threshold).filter_map(|(i, _)| cx.out.fn_globals.get(i).copied()).collect();
            // the inlined callees through their residuals (already evaluated;
            // a residual is always unfolded, never a call)
            let via: HashMap<GlobalId, GlobalId> = inline.iter().filter_map(|c| cx.tier0_residual.get(c).map(|r| (*c, *r))).collect();
            let via_residuals: HashSet<GlobalId> = via.values().copied().collect();
            let opaque = |h: GlobalId| h != g && user_globals.contains_key(&h) && !inline.contains(&h) && !via_residuals.contains(&h);
            let s = match symex::symex_via(&cx.out.env, g, &via, &opaque, cx.opts.symex_budget) {
                Ok(s) => s,
                Err(e) => return out!(format!("symbolic execution failed: {e}"), true, true, None),
            };
            budgets.symex_steps = s.steps;
            let index_g = match cx.out.env.lookup_global("seq::index") {
                Some(x) => x,
                None => return out!("prelude `seq::index` missing".into(), true, true, None),
            };
            let a = symex::analyze(&cx.out.env, &s.value, &opaque, index_g);
            budgets.residual_nodes = a.nodes as u64;
            if let Some(stuck) = a.stuck {
                return out!(format!("not stuck-free: {stuck}"), false, true, None);
            }
            if a.nodes > cx.opts.node_budget {
                return out!(format!("residual of {} nodes exceeds the node budget ({})", a.nodes, cx.opts.node_budget), false, true, None);
            }
            let maps = match residual::Maps::new(&cx.out.env, ext, &cx.out.fn_globals, &cx.out.adts) {
                Ok(m) => m,
                Err(e) => return out!(e, true, true, None),
            };
            let span = ext.item(id).span;
            let r = match residual::build(&cx.out.env, &maps, ext, &f, &s.value, span) {
                Ok(r) => r,
                Err(e) => return out!(format!("residual not printable: {e}"), true, true, None),
            };
            let mut rf = f.clone();
            rf.body = FnBody::Exec(r.body);
            rf.locals = r.locals;
            rf.decreases = if f.decreases.as_ref().is_some_and(|d| d.max.is_some()) { f.decreases.clone() } else { None };
            // sorted: `analyze` collects the calls in a hash set, and the list
            // is part of the byte-identical report (gate G1)
            let mut calls: Vec<String> = a.calls.iter().map(|c| cx.global_name(*c)).collect();
            calls.sort();
            recursive_calls = a.calls.iter().any(|c| symex::is_recursive(&cx.out.env, *c));
            if recursive_calls {
                let dcfg = drive::DriveConfig::default();
                let none = HashSet::new();
                let policy = drive::CratePolicy::new(&cx.out.env, ext, &dcfg, g, user_globals, &none);
                // (or a long loop Σ2 may summarize, plan O6)
                static_recursion = policy.applies_static_recursion(&s.value) || policy.applies_loop_summary(&s.value);
            }
            // a kept call with literal arguments: a polyvariant call-site
            // specialization (design §6.5) for the driver
            if !static_recursion && !a.calls.is_empty() {
                let dcfg = drive::DriveConfig::default();
                let none = HashSet::new();
                static_recursion = drive::CratePolicy::new(&cx.out.env, ext, &dcfg, g, user_globals, &none).with_summaries(&cx.summaries).applies_specializable_call(&s.value);
            }
            sym_keep = Some(s);
            (rf, r.nodes, calls)
        }
    };
    budgets.residual_nodes = nodes as u64;
    if *growth + nodes > cx.opts.growth_cap {
        return out!(format!("crate code-growth cap ({}) reached", cx.opts.growth_cap), false, true, None);
    }
    // the residual as a new exec item (never printed under its own name)
    let orig = ext.item(id).clone();
    let rid = ItemId(ext.items.len() as u32);
    let mut rf = rf;
    rf.ensures = None;
    rf.recursion = Recursion::None;
    let rname = format!("{}__residual", orig.name);
    let mut rpath = orig.path.clone();
    if let Some(l) = rpath.0.last_mut() {
        *l = rname.clone();
    }
    ext.items.push(Item { id: rid, name: rname, path: rpath, module: orig.module, vis: Vis::Crate, ghost: true, span: orig.span, docs: vec![], allow: orig.allow.clone(), cfg: orig.cfg.clone(), kind: ItemKind::Fn(rf) });
    ext.modules[orig.module.0 as usize].items.push(rid);
    // elaborate it (the residual item is ghost for printing; elaborate it as exec)
    ext.items[rid.0 as usize].ghost = false;
    let diags_before = cx.out.diags.list.len();
    let failed = {
        let _refute = refute::Enable::new();
        elab::generated::resume(cx.out, ext, &[rid], chain, eopts, None)
    };
    ext.items[rid.0 as usize].ghost = true;
    let failed = match failed {
        Ok(f) => f,
        Err(e) => {
            pop_residual(cx, ext, rid);
            return out!(format!("residual elaboration: {e}"), true, true, Some("elaboration".into()));
        }
    };
    if !failed.is_empty() {
        let why = cx.out.diags.list.iter().rev().find(|d| d.msg.contains("__residual")).map(|d| d.msg.clone()).unwrap_or_else(|| "obligations not re-proven".into());
        let new: Vec<crate::diag::Diagnostic> = cx.out.diags.list.get(diags_before..).map(|d| d.to_vec()).unwrap_or_default();
        let verdict = reproof_verdict(&new);
        // the failed residual's diagnostics must not fail the build
        cx.out.diags.list.truncate(diags_before);
        cx.out.diags.list.retain(|d| !d.msg.contains("__residual"));
        cx.out.obligations.retain(|o| !o.def.contains("__residual"));
        cx.out.defs.retain(|d| !d.name.contains(&format!("{}__residual", orig.name)) || d.status == DefStatus::Checked);
        pop_residual(cx, ext, rid);
        return match verdict {
            // obligations not re-proven, no counterexample: a proven fallback
            Reproof::NotReproven => out!(format!("the residual's obligations were not re-proven (no counterexample found; a proven fallback): {why}"), false, true, Some(NOT_REPROVEN.into())),
            Reproof::Refuted(n) => out!(format!("residual did not elaborate: {why}: {n}"), true, true, Some("elaboration".into())),
            Reproof::Inconsistent => out!(format!("residual did not elaborate: {why}"), true, true, Some("elaboration".into())),
        };
    }
    let Some(rg) = cx.out.fn_globals.get(&rid).copied() else {
        pop_residual(cx, ext, rid);
        return out!("residual has no global".into(), true, true, None);
    };
    // a cache hit: the kernel checks the cached proof skeleton of the link
    // `Π x̄. Eq(R, residual x̄, f x̄)` (design §17; R25)
    if let Some(p) = &cache_proof {
        let lemma = format!("{}__residual::cached_equiv", orig.path);
        if let Err(e) = add_link_lemma(&mut cx.out.env, rg, g, p, &sandblaster_kernel::term::Recursion::None, &lemma, cx.opts.check_budget) {
            pop_residual(cx, ext, rid);
            let kind = e.split(':').next().unwrap_or("").to_string();
            return out!(format!("cache entry rejected by the kernel (add_def): {e}"), true, true, Some(format!("add_def: {kind}")));
        }
    }
    // admit it: straight-line, well-typed, convertible with the function
    let ty = cx.out.env.global_type(g).unwrap();
    let body = cx.out.env.global_body(rg).unwrap();
    let mut b = Budget { steps: cx.opts.check_budget };
    let checked = cx.out.env.check_residual_equal(&ty, &body, g, &mut b);
    budgets.check_steps = cx.opts.check_budget - b.steps;
    if checked.is_err() && std::env::var_os("SANDBLASTER_OPT_DIFF").is_some() {
        let s1 = symex::symex(&cx.out.env, rg, &|_| false, 500_000_000);
        let s2 = symex::symex(&cx.out.env, g, &|_| false, 500_000_000);
        if let (Ok(s1), Ok(s2)) = (s1, s2) {
            eprintln!("opt: residual diff of {}: {:?}", ext.item(id).path, par::lift::value_diff(&cx.out.env, s1.tele.binders.len() as u32, &s1.value, &s2.value));
        }
    }
    if let Err(e) = checked {
        let m: String = e.to_string().chars().take(600).collect();
        pop_residual(cx, ext, rid);
        return out!(format!("the kernel rejected the residual: {m}"), true, true, Some(format!("check_residual_equal: {:?}", e.kind)));
    }
    *growth += nodes;
    SpecOut { outcome: Outcome::Specialized { nodes, residual: rg, calls }, budgets, attempted: true, rejected_by: None, injected: is_injected, ritem: Some(rid), recursive_calls, static_recursion, sym: sym_keep }
}

/// The link statement `Π x̄. Eq(R, a x̄, b x̄)` over `a`'s parameter
/// telescope, and its arity.
fn link_statement(env: &sandblaster_kernel::api::Env, a: GlobalId, b: GlobalId) -> Result<(sandblaster_kernel::term::Tm, u32), String> {
    use sandblaster_kernel::term::{Rel, Tm};
    use sandblaster_kernel::util::mk;
    let tele = symex::telescope(env, a).ok_or("no telescope")?;
    let n = tele.binders.len();
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    let mut ty = mk::eq(tele.ret.clone(), mk::apps(mk::global(a), args.clone()), mk::apps(mk::global(b), args));
    for (nm, rel, dom) in tele.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    Ok((ty, n as u32))
}

/// Submits the proof built by `proof` for the link statement of `a` and `b`
/// to the kernel as the lemma `name` (`Env::add_def`).
fn add_link_lemma(env: &mut sandblaster_kernel::api::Env, a: GlobalId, b: GlobalId, proof: &hooks::ProofSkeleton, recursion: &sandblaster_kernel::term::Recursion, name: &str, budget: u64) -> Result<GlobalId, String> {
    let (ty, arity) = link_statement(env, a, b)?;
    let body = proof(env, a, b)?;
    let d = sandblaster_kernel::term::DefDecl { name: std::rc::Rc::from(name), kind: sandblaster_kernel::term::DefKind::Lemma, ty, body, recursion: recursion.clone(), arity, opaque: true };
    let mut bud = Budget { steps: budget };
    env.add_def(d, &mut bud).map_err(|e| e.to_string().chars().take(600).collect())
}

/// `Ok` when `lemma` is a definition of the kernel environment whose type is
/// exactly the link statement of `a` and `b` (the emission-chain check of a
/// claimed lemma).
fn verify_link_lemma(env: &sandblaster_kernel::api::Env, lemma: &str, a: GlobalId, b: GlobalId) -> Result<(), String> {
    let g = env.lookup_global(lemma).ok_or("is not in the kernel environment")?;
    let ty = env.global_type(g).ok_or("has no type")?;
    let (want, _) = link_statement(env, a, b)?;
    if env.alpha_eq_relevant(&ty, &want, &|x, y| x == y) { Ok(()) } else { Err("does not state `Π x̄. Eq(R, clone x̄, original x̄)`".into()) }
}

/// [`pop_item`] for a residual that elaborated but was rejected: its item →
/// global entry goes too (the next residual reuses the item id, and
/// `residual::Maps::new` reads every entry's item).
fn pop_residual(cx: &mut Ctx<'_>, ext: &mut Crate, rid: ItemId) {
    cx.out.fn_globals.remove(&rid);
    pop_item(ext, rid);
}

/// [`pop_residual`] for a driven residual or a helper: its obligations and
/// definition records leave the report too, so a failed driven attempt
/// does not shift the obligation numbering (printed in `SAFETY:` comments)
/// of any later function (gate G10). Tier 0 keeps its own bookkeeping.
fn pop_driven(cx: &mut Ctx<'_>, ext: &mut Crate, rid: ItemId) {
    if let Some((om, dm)) = cx.marks.remove(&rid) {
        cx.out.obligations.truncate(om);
        cx.out.defs.truncate(dm);
    }
    pop_residual(cx, ext, rid);
}

/// Removes the last item (a failed residual) from the crate (its kernel
/// definition, if any, stays unused).
fn pop_item(ext: &mut Crate, rid: ItemId) {
    if ext.items.len() == rid.0 as usize + 1 {
        let m = ext.items[rid.0 as usize].module;
        ext.items.pop();
        ext.modules[m.0 as usize].items.retain(|i| *i != rid);
    }
}

/// The `rejected_by` of a driven candidate whose proof builder built a term
/// the kernel finds ill-typed ([`proof::steps::ILL_TYPED`]): an optimizer
/// fault, unlike the builder giving up (`"proof builder"`).
pub const PROOF_ILL_TYPED: &str = "proof builder: ill-typed term";

/// The driven candidate of one function (see [`drive_one`]).
struct DriveOut {
    /// `Some(Specialized)` when the driven residual was admitted.
    outcome: Option<Outcome>,
    /// The equality lemma of an admitted residual.
    lemma: Option<String>,
    /// The residual item of an admitted residual.
    ritem: Option<ItemId>,
    reason: String,
    rejected_by: Option<String>,
    budgets: BudgetsUsed,
    /// The process tree only unfolded the root and split on the source's
    /// own matches (no callee unfolding, decision, specialization or word
    /// form): the residual is the source up to evaluation.
    trivial: bool,
    /// The candidate was rejected by a check the optimizer relies on (the
    /// kernel refused its lemma, or its residual or a helper did not
    /// elaborate, or the proof builder built an ill-typed term,
    /// [`PROOF_ILL_TYPED`]): an optimizer fault, reported as a failure (a
    /// build error under strict options). The proof builder giving up (a
    /// budget, a leaf it cannot close, a proof of unknown type that breaks
    /// a motive) is not one.
    failure: bool,
    /// Result leaves of the admitted residual's process tree (the summary's
    /// case-of-case cost, design §6.4).
    leaves: usize,
    /// The same with the leaves of the specialization helpers it calls.
    expanded_leaves: usize,
    /// Its residual calls Σ2 loop helpers in place of loops: the weakest
    /// of their rungs (a closed form, else an early exit).
    loop_rung: Option<Rung>,
}

/// The candidates of one function: tier 0, then the driven one.
struct Summary {
    tier0: SpecOut,
    driven: Option<DriveOut>,
}

/// Summarizes one function (design §4 step 3): **tier 0** first, exactly
/// as before (`specialize_one`: symbolic execution, stuck-free analysis,
/// straight-line residual, `check_residual_equal`); when the analysis
/// finds the function stuck — or the straight-line residual keeps a call of
/// a recursive function the driver may unroll — the **Σ1 driver** runs
/// ([`drive_one`]) and its residual is admitted through its equality lemma
/// (`Link::Lemma`).
#[allow(clippy::too_many_arguments)]
fn summarize_one(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, id: ItemId, clone_of: Option<ItemId>, user_globals: &HashMap<GlobalId, ItemId>, specialized: &HashMap<ItemId, (usize, GlobalId, ItemId)>, growth: &mut usize) -> Summary {
    let mut s = summarize_driven(cx, ext, chain, eopts, id, clone_of, user_globals, specialized, growth);
    // the aegraph (plan O8): straight-line alternatives of a residual
    // admitted by conversion that the driver did not replace
    let admitted_driven = matches!(&s.driven, Some(DriveOut { outcome: Some(_), .. }));
    if !s.tier0.injected
        && !admitted_driven
        && let Outcome::Specialized { calls, .. } = &s.tier0.outcome
        && let Some(sym) = s.tier0.sym.take()
        && let Some(g) = cx.checked(id)
    {
        let calls = calls.clone();
        let f = ext.fn_def(id).unwrap();
        let set_name = if f.target_features.is_empty() { multiversion::PORTABLE_SUFFIX.to_string() } else { f.target_features.join("_").replace(['.', '-'], "_") };
        let arch = ext.target.arch.name().to_string();
        let model = cost::model::SetModel::new(&set_name, &arch, &f.feature_set.clone(), &cx.opts.tuning.clone());
        match egraph::improve(cx, ext, chain, eopts, id, g, &sym, &calls, &model, user_globals, growth) {
            egraph::Improved::Admitted(d) => s.driven = Some(d),
            egraph::Improved::Rejected(d) => {
                if s.driven.is_none() {
                    s.driven = Some(d);
                } else {
                    let name = ext.item(id).path.to_string();
                    cx.failure(format!("`{name}`: {}", d.reason.chars().take(600).collect::<String>()));
                }
            }
            egraph::Improved::None(why) => trace(|| format!("aegraph {}: {why}", ext.item(id).path)),
        }
    }
    s
}

/// Tier 0, then the Σ1 driver (see [`summarize_one`]).
#[allow(clippy::too_many_arguments)]
fn summarize_driven(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, id: ItemId, clone_of: Option<ItemId>, user_globals: &HashMap<GlobalId, ItemId>, specialized: &HashMap<ItemId, (usize, GlobalId, ItemId)>, growth: &mut usize) -> Summary {
    let tier0 = specialize_one(cx, ext, chain, eopts, id, user_globals, specialized, growth);
    if tier0.injected {
        return Summary { tier0, driven: None };
    }
    // the driver takes what tier 0 cannot: a straight-line residual (linked
    // by conversion) is not replaced
    let want = match &tier0.outcome {
        // a straight-line residual (linked by conversion) is replaced only
        // when it keeps a static recursion the driver unrolls
        Outcome::Specialized { .. } => tier0.static_recursion || cx.checked(id).is_some_and(|g| facts::body_applies(&cx.out.env, g)),
        Outcome::Unspecialized { failure: false, reason } => reason.starts_with("not stuck-free"),
        Outcome::Unspecialized { .. } => false,
    };
    let Some(g) = cx.checked(id) else { return Summary { tier0, driven: None } };
    if !want || symex::is_recursive(&cx.out.env, g) {
        return Summary { tier0, driven: None };
    }
    // development knob of the test builds: drive only the named functions
    #[cfg(any(test, feature = "opt-test-hooks"))]
    if let Ok(only) = std::env::var("SANDBLASTER_OPT_DRIVE_ONLY") {
        let name = ext.item(id).path.to_string();
        if !only.split(',').any(|n| n == name) {
            return Summary { tier0, driven: None };
        }
    }
    // a multiversioned clone fails where its original failed (same body up
    // to the variants of its callees)
    if let Some(o) = clone_of
        && let Some(why) = cx.drive_failed.get(&o)
    {
        let reason = format!("not driven: its original `{}` was not driven ({})", ext.item(o).path, why.chars().take(200).collect::<String>());
        return Summary { tier0, driven: Some(DriveOut { outcome: None, lemma: None, ritem: None, reason, rejected_by: None, budgets: BudgetsUsed::default(), trivial: false, failure: false, leaves: 0, expanded_leaves: 0, loop_rung: None }) };
    }
    // a clone of a function whose residual is its source up to evaluation
    // keeps its source (the same process tree, a lemma for no change)
    if let Some(o) = clone_of
        && cx.drive_trivial.contains(&o)
    {
        let reason = format!("not driven: the residual of its original `{}` only re-splits the source (a trivial process tree)", ext.item(o).path);
        return Summary { tier0, driven: Some(DriveOut { outcome: None, lemma: None, ritem: None, reason, rejected_by: None, budgets: BudgetsUsed::default(), trivial: true, failure: false, leaves: 0, expanded_leaves: 0, loop_rung: None }) };
    }
    let d = drive_one(cx, ext, chain, eopts, id, g, user_globals, specialized, growth);
    Summary { tier0, driven: Some(d) }
}

/// The Σ1 driver on one function (design §6, §11.1): drive it into a
/// process tree, print the residual (HIR with control flow), elaborate it
/// (`resume`: every proof slot re-proven, the kernel checks the
/// definition), prove `Π x̄ h̄. Eq(R, res x̄ h̄, f x̄ h̄)` from the tree and
/// commit it with `add_def` (kind `Lemma`, opaque). Static user recursions
/// become polyvariant specialization helpers first ([`ensure_helpers`]).
/// Any failure leaves the tier-0 outcome in place.
#[allow(clippy::too_many_arguments)]
fn drive_one(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, id: ItemId, g: GlobalId, user_globals: &HashMap<GlobalId, ItemId>, specialized: &HashMap<ItemId, (usize, GlobalId, ItemId)>, growth: &mut usize) -> DriveOut {
    let mut budgets = BudgetsUsed::default();
    // the loop summaries this driving builds (`loopsum::meter`)
    let loopsum_before = loopsum::meter::total();
    // loops that were not summarized (kept), with why (the report)
    let mut loop_notes: Vec<String> = Vec::new();
    let name = ext.item(id).path.to_string();
    // development diagnostics: `SANDBLASTER_OPT_TIMING` prints the phases of
    // every attempt (wall clock; never part of a decision)
    let timing = std::env::var_os("SANDBLASTER_OPT_TIMING").is_some();
    let t0 = std::time::Instant::now();
    macro_rules! fail {
        ($reason:expr, $rejected:expr) => {
            return {
                let rejected: Option<String> = $rejected;
                budgets.loopsum_steps = loopsum::meter::total().saturating_sub(loopsum_before);
                let failure = rejected.as_deref().is_some_and(|r| r.starts_with("add_def") || r == "elaboration" || r == PROOF_ILL_TYPED);
                let reason: String = $reason;
                let reason: String = format!("{reason}{}", loop_notes.iter().map(|n| format!("; {n}")).collect::<String>());
                if timing {
                    eprintln!("opt: timing {name}: failed after {:?}: {}", t0.elapsed(), reason.chars().take(160).collect::<String>());
                }
                DriveOut { outcome: None, lemma: None, ritem: None, reason, rejected_by: rejected, budgets, trivial: false, failure, leaves: 0, expanded_leaves: 0, loop_rung: None }
            }
        };
    }
    let f = ext.fn_def(id).unwrap().clone();
    let dcfg = drive::DriveConfig::default();
    let fault = cx.opts.hooks().and_then(|h| h.drive_fault(&name));
    // callees unfolded wherever they occur: specialized ones below the
    // inline threshold (as for tier 0)
    // (driven callees stay calls: their residual is already specialized; so
    // do callees whose residual calls a recursion)
    let inline: HashSet<GlobalId> = specialized.iter().filter(|(i, (n, _, _))| *n <= cx.opts.inline_threshold && !cx.driven.contains(i) && !cx.tier0_recursive.contains(i)).filter_map(|(i, _)| cx.out.fn_globals.get(i).copied()).collect();
    let trace_on = std::env::var_os("SANDBLASTER_OPT_TRACE").is_some();
    // plan O6: the callees whose driven residual failed get their guards
    // specialized instead of being unfolded for the facts
    let no_fact_unfold: HashSet<GlobalId> = cx.drive_failed.keys().filter_map(|i| cx.out.fn_globals.get(i).copied()).collect();
    let mut retried = false;
    let mut guard_retries = 0u32;
    let mut guard_notes: Vec<String> = Vec::new();
    let mut seg_rounds = 0u32;
    let mut seg_retries = 0u32;
    let mut seg_notes: Vec<String> = Vec::new();
    let _seg_fault = seqsum::FaultScope::enter(fault);
    let (driven, keys) = loop {
        let driven = {
            let env = &cx.out.env;
            let policy = drive::CratePolicy::new(env, ext, &dcfg, g, user_globals, &inline).with_summaries(&cx.summaries).with_facts(no_fact_unfold.clone());
            match drive::run(env, &dcfg, &policy, g, fault) {
                Ok(d) => d,
                Err(e) => fail!(format!("not driven: {e}"), None),
            }
        };
        budgets.symex_steps = driven.steps;
        if timing {
            eprintln!("opt: timing {name}: driven in {:?} ({} steps, {} process nodes)", t0.elapsed(), driven.steps, driven.nodes);
        }
        if trace_on {
            eprintln!("opt: drive {name}: {} process nodes, {:?}", driven.nodes, driven.tree.counts());
        }
        // Σ3: the segment specializations it asked for (then drive again),
        // and the helpers of those it calls (design §8.2)
        match seqsum::after_drive(cx, ext, chain, eopts, &driven.tree, user_globals, &inline, &mut seg_rounds, fault) {
            Ok(true) => continue,
            Ok(false) => {}
            // a segment helper that could not be built (not printable, not
            // elaborated, its proof not found) is not an optimizer fault: its
            // key is recorded as failed (`Registry::failed`, never proposed
            // again) and the function is driven again with the call kept, as
            // for fold helpers and loops; a lemma the kernel rejected is one
            Err(e) if seqsum::rejection_kind(&e).is_none() && seg_retries < 2 => {
                if trace_on {
                    eprintln!("opt: drive {name}: a segment specialization failed, driven again with the call kept: {e}");
                }
                seg_retries += 1;
                seg_notes.push(e.chars().take(200).collect());
                continue;
            }
            Err(e) => {
                let rejected = seqsum::rejection_kind(&e);
                fail!(format!("not driven: a segment specialization failed: {e}"), rejected)
            }
        }
        // the helpers of the static recursions and the polyvariant
        // call-site specializations it calls
        let keys = driven.tree.spec_keys();
        let fold_defs = driven.tree.fold_calls();
        let loop_keys = driven.tree.loop_keys();
        // guard helpers (plan O6); one that fails is recorded and the
        // function driven again with the call kept
        let guard_keys = driven.tree.guard_keys();
        if !guard_keys.is_empty()
            && let Err(e) = guardspec::ensure(cx, ext, chain, eopts, &guard_keys, user_globals)
        {
            // (a lemma the kernel rejected is recorded as an optimizer
            // failure by `ensure`)
            if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                eprintln!("opt: drive {}: guard helper not built: {e}", cx.global_name(g));
            }
            guard_notes.push(e.chars().take(200).collect());
            if guard_retries < 2 {
                guard_retries += 1;
                continue;
            }
        }
        match ensure_helpers(cx, ext, chain, eopts, &keys, user_globals, &inline, 0, fault).and_then(|()| ensure_folds(cx, ext, chain, eopts, &fold_defs, user_globals, &inline, fault)).and_then(|()| loopsum::ensure_loops(cx, ext, chain, eopts, &loop_keys, user_globals)) {
            Ok(()) => break (driven, keys),
            // a loop that could not be summarized is not an optimizer fault:
            // driven again with that call kept (its failure is recorded)
            Err(_) if !retried && loop_keys.iter().any(|k| loopsum::with_registry(|r| r.failed.contains_key(k))) => {
                for k in &loop_keys {
                    if let Some(f) = loopsum::with_registry(|r| r.failed.get(k).cloned()) {
                        loop_notes.push(format!("the loop `{}` was not summarized, the call kept ({})", cx.global_name(k.def), f.reason.chars().take(300).collect::<String>()));
                    }
                }
                retried = true;
                continue;
            }
            // a fold helper that could not be built is not an optimizer
            // fault: driven again with that call kept (a lemma the kernel
            // rejected is one, below)
            Err(e) if !retried && kernel_rejection(&e).is_none() && fold_defs.iter().any(|d| cx.summaries.fold_failed.contains(d)) => {
                retried = true;
                continue;
            }
            Err(e) if kernel_rejection(&e).is_some() => {
                let by = format!("add_def: {}", kernel_rejection(&e).unwrap());
                fail!(format!("not driven: a helper's lemma was rejected by the kernel: {e}"), Some(by));
            }
            // a polyvariant specialization that failed is not an optimizer
            // fault: the function is driven again with that call kept
            Err(_) if !retried && keys.iter().any(|k| cx.summaries.spec_failed.contains(k)) => {
                retried = true;
                continue;
            }
            Err(e) => {
                let by = if e.contains("rejected by elaboration") { "elaboration" } else { "specialization" };
                fail!(format!("not driven: a specialization helper failed: {e}"), Some(by.into()));
            }
        }
    };
    let r = {
        let env = &cx.out.env;
        let policy = drive::CratePolicy::new(env, ext, &dcfg, g, user_globals, &inline).with_summaries(&cx.summaries);
        let maps = match residual::Maps::new(env, ext, &cx.out.fn_globals, &cx.out.adts) {
            Ok(m) => m,
            Err(e) => fail!(e, None),
        };
        let op = |h: GlobalId| drive::Policy::folded(&policy, h);
        let ev = drive::step::Eval { env, opaque: &op };
        let span = ext.item(id).span;
        let spec_items: BTreeMap<drive::tree::SpecKey, ItemId> = cx.helpers.iter().map(|(k, h)| (k.clone(), h.item)).collect();
        let mut fold_items: BTreeMap<GlobalId, ItemId> = driven.tree.fold_calls().iter().filter_map(|d| cx.summaries.folds.get(d).map(|h| (*d, h.item))).collect();
        fold_items.extend(cx.summaries.seg.items());
        // (guard-specialized calls print as their helpers' calls)
        let print_tree = if driven.tree.guard_keys().is_empty() { None } else { Some(guardspec::for_printing(&driven.tree)) };
        match residual::tree::build_tree(env, &maps, ext, &f, print_tree.as_ref().unwrap_or(&driven.tree), &ev, &spec_items, &fold_items, dcfg.max_residual_nodes, span, fault) {
            Ok(r) => r,
            Err(e) => {
                let kept: String = seg_notes.iter().map(|n| format!("; a segment specialization was not built, the call kept ({n})")).collect();
                fail!(format!("driven residual not printable: {e}{kept}"), None)
            }
        }
    };
    if r.calls.contains(&id) {
        fail!("the driven residual calls the function itself (a recursive residual)".into(), None);
    }
    budgets.residual_nodes = r.nodes as u64;
    if *growth + r.nodes > cx.opts.growth_cap {
        fail!(format!("crate code-growth cap ({}) reached", cx.opts.growth_cap), None);
    }
    let orig = ext.item(id).clone();
    let mut rf = f.clone();
    rf.body = FnBody::Exec(r.body);
    rf.locals = r.locals;
    rf.ensures = None;
    rf.recursion = Recursion::None;
    rf.decreases = None;
    let t_print = t0.elapsed();
    let rid = match push_elaborate(cx, ext, chain, eopts, &orig, format!("{}__residual", orig.name), rf, true) {
        Ok(rid) => rid,
        Err((why, rej)) => fail!(why, rej),
    };
    let Some(rg) = cx.out.fn_globals.get(&rid).copied() else {
        pop_driven(cx, ext, rid);
        fail!("the driven residual has no global".into(), None);
    };
    ensure_shift_lemmas_in(&mut cx.out.env, &[rg]);
    // the equality lemma (Link::Lemma)
    let lemma = format!("{}__residual::equiv", orig.path);
    let specs: proof::Specs = cx.helpers.iter().map(|(k, h)| (k.clone(), proof::SpecLemma { helper: h.global, lemma: h.lemma })).collect();
    let t_elab = t0.elapsed();
    let folded = {
        let policy = drive::CratePolicy::new(&cx.out.env, ext, &dcfg, g, user_globals, &inline).with_summaries(&cx.summaries);
        policy.folded_set()
    };
    let mut folds: proof::Folds = cx.summaries.folds.iter().map(|(d, h)| (*d, (h.global, h.lemma))).collect();
    folds.extend(cx.summaries.seg.lemmas());
    // a clone whose residual is its original's up to the renaming: the link
    // by mirror and transitivity (`derive`), else from the process tree
    let derived = if fault.is_none() {
        match derive::residual_link(cx, id, rg, g, &lemma) {
            Some(Ok(())) => true,
            Some(Err(e)) => {
                trace(|| format!("derive {name}: {}", e.chars().take(400).collect::<String>()));
                false
            }
            None => false,
        }
    } else {
        false
    };
    let proven = if derived {
        Ok((cx.out.env.lookup_global(&lemma).unwrap_or(rg), proof::ProofStats::default()))
    } else {
        let _r16 = (fault == Some(DriveFault::TransportKeptProof)).then(crate::auto::abstraction::TransportAll::new);
        proof::prove_driven(&mut cx.out.env, rg, g, &driven, &specs, &folds, &folded, fault.is_some(), proof::Budgets::of(&dcfg), &lemma, &mut cx.outlines, if fault.is_some() { None } else { cx.cache.as_ref() })
    };
    if timing {
        eprintln!("opt: timing {name}: drive+print {:?}, elaborate {:?}, prove {:?} ({}; {:?})", t_print, t_elab - t_print, t0.elapsed() - t_elab, if proven.is_ok() { "ok" } else { "failed" }, driven.tree.counts());
    }
    let stats = match proven {
        Ok((_, s)) => s,
        Err(e) => {
            pop_driven(cx, ext, rid);
            let kind = if e.contains(proof::steps::ILL_TYPED) {
                // the builder's own term is ill-typed (not a search that ran
                // out): an optimizer fault
                PROOF_ILL_TYPED.to_string()
            } else if e.contains(": ") && e.split(':').next().is_some_and(|k| k.chars().all(|c| c.is_ascii_alphabetic())) {
                format!("add_def: {}", e.split(':').next().unwrap())
            } else {
                "proof builder".to_string()
            };
            fail!(format!("the equality lemma was not proven: {}", e.chars().take(600).collect::<String>()), Some(kind));
        }
    };
    if trace_on {
        eprintln!("opt: drive {name}: lemma proven ({stats:?})");
    }
    // the emission chain: the lemma states exactly the link
    if let Err(e) = verify_link_lemma(&cx.out.env, &lemma, rg, g) {
        pop_driven(cx, ext, rid);
        fail!(format!("emission chain: the lemma `{lemma}` {e}"), Some("emission chain".into()));
    }
    *growth += r.nodes;
    let mut calls: Vec<String> = r.calls.iter().map(|i| ext.item(*i).path.to_string()).collect();
    calls.sort();
    let helpers: Vec<String> = keys.iter().filter_map(|k| cx.helpers.get(k)).map(|h| ext.item(h.item).path.to_string()).collect();
    let mut reason = if helpers.is_empty() { "admitted: kernel-checked equality lemma (Link::Lemma)".to_string() } else { format!("admitted: kernel-checked equality lemma (Link::Lemma); specialization helpers {}", helpers.join(", ")) };
    for n in &guard_notes {
        reason.push_str(&format!("; a guard helper was not built ({n})"));
    }
    for n in &seg_notes {
        reason.push_str(&format!("; a segment specialization was not built, the call kept ({n})"));
    }
    for n in &loop_notes {
        reason.push_str(&format!("; {n}"));
    }
    // the process tree's shape (design §6): what was decided, merged,
    // instantiated through a callee's link or inlined as a value
    reason.push_str(&format!("; process tree: {}", driven.tree.counts().describe()));
    let trivial = driven.tree.counts().trivial();
    cx.set_aside_obligations(rid);
    // the leaves of its own tree: a helper call among them expands (or not)
    // at the caller by the helper's own shape (`HelperShape`), when the
    // instantiated residual brings the call to the head
    let helper_leaves: usize = keys.iter().filter_map(|k| cx.helpers.get(k)).filter_map(|h| cx.summaries.helpers.get(&h.global)).map(|s| s.result_leaves).sum();
    let leaves = driven.tree.result_leaves();
    // the loop summaries its residual uses (design §7): the helper, the
    // summary lemma and what it is
    let loop_keys = driven.tree.loop_keys();
    for k in &loop_keys {
        if let Some(lh) = loopsum::helper(k) {
            let what = match lh.rung {
                Rung::ClosedForm => "closed form, summary lemma",
                Rung::SetBits => "set-bit iteration, lemma",
                _ => "early exit, lemma",
            };
            reason.push_str(&format!("; loop summary of `{}`: {what} `{}`, {}", cx.global_name(k.def), lh.summary_lemma, lh.describe));
        }
    }
    // the facts its loops export, lifted to its own result (design §6.4)
    for k in &loop_keys {
        if let Some(lf) = loopsum::helper(k).and_then(|h| h.loop_facts) {
            match facts::lift(&mut cx.out.env, g, k, &lf) {
                Ok(fs) if !fs.is_empty() => {
                    reason.push_str(&format!("; exported facts {}", fs.iter().map(|f| format!("`{}`", f.states)).collect::<Vec<_>>().join(", ")));
                    facts::register(g, fs);
                }
                Ok(_) => {}
                Err(e) => reason.push_str(&format!("; its loop's facts are not exported ({})", e.chars().take(200).collect::<String>())),
            }
        }
    }
    let rungs: Vec<Option<Rung>> = loop_keys.iter().map(|k| loopsum::helper(k).map(|h| h.rung)).collect();
    let loop_rung = if rungs.is_empty() || rungs.iter().any(|r| r.is_none()) {
        None
    } else {
        // the weakest of them (the rungs are ordered strongest first)
        rungs.iter().flatten().max().copied()
    };
    budgets.loopsum_steps = loopsum::meter::total().saturating_sub(loopsum_before);
    // what the link of a multiversioned clone of it may go through (`derive`)
    if fault.is_none()
        && let Some(lg) = cx.out.env.lookup_global(&lemma)
    {
        cx.driven_info.insert(id, derive::DrivenInfo { residual: rg, lemma: lg });
    }
    DriveOut { outcome: Some(Outcome::Specialized { nodes: r.nodes, residual: rg, calls }), lemma: Some(lemma), ritem: Some(rid), reason, rejected_by: None, budgets, trivial, failure: false, leaves, expanded_leaves: leaves + helper_leaves, loop_rung }
}

/// Pushes `rf` as a new exec item named `name` next to `orig` and
/// elaborates it (`resume`); `ghost`: never printed under its own name (a
/// residual) as opposed to a printed helper. On failure the item is
/// removed.
#[allow(clippy::too_many_arguments)]
fn push_elaborate(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, orig: &Item, name: String, rf: FnDef, ghost: bool) -> Result<ItemId, (String, Option<String>)> {
    push_elaborate_capture(cx, ext, chain, eopts, orig, name, rf, ghost, None)
}

/// [`push_elaborate`], capturing the pre-commit definitions when `capture`
/// is given (`elab::generated::SinkMode::Capture`: a recursive definition's
/// self-calls with their measure proofs, for a `mirror` proof).
#[allow(clippy::too_many_arguments)]
fn push_elaborate_capture(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, orig: &Item, name: String, rf: FnDef, ghost: bool, capture: Option<&mut Vec<elab::generated::GenDef>>) -> Result<ItemId, (String, Option<String>)> {
    let rid = ItemId(ext.items.len() as u32);
    let mut rpath = orig.path.clone();
    if let Some(l) = rpath.0.last_mut() {
        *l = name.clone();
    }
    ext.items.push(Item { id: rid, name: name.clone(), path: rpath, module: orig.module, vis: Vis::Crate, ghost: false, span: orig.span, docs: vec![], allow: orig.allow.clone(), cfg: orig.cfg.clone(), kind: ItemKind::Fn(rf) });
    ext.modules[orig.module.0 as usize].items.push(rid);
    cx.marks.insert(rid, (cx.out.obligations.len(), cx.out.defs.len()));
    // every prover result is checked once, by `add_def` (not also when the
    // prover returns it: the residual's proofs are the prover's, re-found)
    let ropts = elab::Options { check_proofs: false, ..eopts.clone() };
    let diags_before = cx.out.diags.list.len();
    let failed = {
        // a failed obligation is searched for a counterexample (`refute`)
        let _refute = refute::Enable::new();
        elab::generated::resume(cx.out, ext, &[rid], chain, &ropts, capture)
    };
    ext.items[rid.0 as usize].ghost = ghost;
    let failed = match failed {
        Ok(f) => f,
        Err(e) => {
            pop_driven(cx, ext, rid);
            return Err((format!("driven residual elaboration: {e}"), Some("elaboration".into())));
        }
    };
    if !failed.is_empty() {
        let new: Vec<crate::diag::Diagnostic> = cx.out.diags.list.get(diags_before..).map(|d| d.to_vec()).unwrap_or_default();
        let why = new.iter().rev().chain(cx.out.diags.list.iter().rev()).find(|d| d.msg.contains(&name)).map(|d| d.msg.clone()).unwrap_or_else(|| "obligations not re-proven".into());
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            for d in &new {
                eprintln!("opt: {name} did not elaborate: {}\n  {}\n  {}", d.msg, d.notes.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>().join("\n  "), d.goal.as_deref().unwrap_or(""));
            }
        }
        let verdict = reproof_verdict(&new);
        cx.out.diags.list.truncate(diags_before);
        cx.out.diags.list.retain(|d| !d.msg.contains(&name));
        pop_driven(cx, ext, rid);
        return Err(match verdict {
            Reproof::Refuted(cx_note) => (format!("the driven residual did not elaborate: {why}: {cx_note}"), Some("elaboration".into())),
            Reproof::Inconsistent => (format!("the driven residual did not elaborate: {why}"), Some("elaboration".into())),
            Reproof::NotReproven => (format!("the driven residual's obligations were not re-proven (no counterexample found; a proven fallback): {why}"), Some(NOT_REPROVEN.into())),
        });
    }
    Ok(rid)
}

/// The `rejected_by` of a candidate whose residual or helper elaborated
/// except for obligations the provers did not re-prove, with no
/// counterexample found: a proven fallback, not an optimizer fault.
pub(crate) const NOT_REPROVEN: &str = "not re-proven";

/// Why an optimizer residual did not elaborate (design §4: a proven
/// fallback, or an optimizer fault).
enum Reproof {
    /// An obligation is false at a counterexample (`refute`): the residual
    /// performs an operation outside its domain on some input, which the
    /// source does not. An internal inconsistency (an optimizer fault).
    Refuted(String),
    /// Something other than a proof search failed (a type error, a proof
    /// the kernel rejects, a diagnostic of another kind): an internal
    /// inconsistency (an optimizer fault).
    Inconsistent,
    /// Only obligations the provers did not re-prove, and no counterexample
    /// found: an incompleteness of the proof search (the driver decided a
    /// test by its own procedure, say). A proven fallback: the function
    /// keeps its source, the reason is recorded in the report.
    NotReproven,
}

fn reproof_verdict(new: &[crate::diag::Diagnostic]) -> Reproof {
    use crate::diag::DiagKind;
    if new.is_empty() {
        return Reproof::Inconsistent;
    }
    for d in new {
        if let Some((_, n)) = d.notes.iter().find(|(_, n)| refute::is_refuted(n)) {
            return Reproof::Refuted(n.trim_start_matches("tried: ").to_string());
        }
    }
    let unproven_only = new.iter().all(|d| match d.kind {
        // a safety net that tripped fails the build on its own (the
        // driver's resource gate)
        DiagKind::Resource => true,
        DiagKind::Obligation => !d.notes.iter().any(|(_, n)| n.contains("the prover returned a proof the kernel rejects")),
        _ => false,
    });
    if unproven_only { Reproof::NotReproven } else { Reproof::Inconsistent }
}

/// Commits the specialization helpers of `keys` (and, first, the helpers
/// they call): each is `def` with its static arguments fixed, driven like a
/// function, printed as a private `#[inline]` function, and linked by its
/// lemma `Π dyn̄. Eq(R, helper dyn̄, def(statics, dyn̄))` (design §6.5).
/// Every helper's proof is shallow: its dynamic parameters are variables,
/// whatever the caller passes.
#[allow(clippy::too_many_arguments)]
fn ensure_helpers(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, keys: &[drive::tree::SpecKey], user_globals: &HashMap<GlobalId, ItemId>, inline: &HashSet<GlobalId>, depth: u32, fault: Option<DriveFault>) -> Result<(), String> {
    const MAX_HELPERS: usize = 64;
    const MAX_DEPTH: u32 = 64;
    for key in keys {
        if cx.helpers.contains_key(key) {
            continue;
        }
        if let Some(why) = cx.helper_failed.get(key) {
            return Err(why.clone());
        }
        if cx.helpers.len() >= MAX_HELPERS || depth >= MAX_DEPTH {
            return Err(format!("the specialization budget ({MAX_HELPERS} helpers, depth {MAX_DEPTH}) is exhausted"));
        }
        match build_helper(cx, ext, chain, eopts, key, user_globals, inline, depth, fault) {
            Ok(h) => {
                cx.helpers.insert(key.clone(), h);
            }
            Err(e) => {
                cx.helper_failed.insert(key.clone(), e.clone());
                // a polyvariant call-site specialization is not proposed
                // again: its caller is driven again with the call kept
                if !symex::is_recursive(&cx.out.env, key.def) {
                    cx.summaries.spec_failed.insert(key.clone());
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Commits the fold helpers of the recursions `defs` (design §6.6, see
/// [`build_fold`]); a failure is recorded (`Summaries::fold_failed`) and
/// returned.
#[allow(clippy::too_many_arguments)]
fn ensure_folds(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, defs: &[GlobalId], user_globals: &HashMap<GlobalId, ItemId>, inline: &HashSet<GlobalId>, fault: Option<DriveFault>) -> Result<(), String> {
    for &f in defs {
        if cx.summaries.folds.contains_key(&f) {
            continue;
        }
        if cx.summaries.fold_failed.contains(&f) {
            return Err(format!("the fold helper of `{}` failed", cx.global_name(f)));
        }
        match build_fold(cx, ext, chain, eopts, f, user_globals, inline, fault) {
            Ok(h) => {
                cx.summaries.folds.insert(f, h);
            }
            Err(e) => {
                cx.summaries.fold_failed.insert(f);
                if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                    eprintln!("opt: fold helper of {}: {e}", cx.global_name(f));
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

/// The fold helper of the user recursion `f` (design §6.6, folding under the
/// same-global rule, with a bound invariant — plan O5, P10):
///
/// 1. a probe drive of `f` itself, every tail call a back-edge, shows how
///    its `u64` accumulators grow at the back-edges: `acc + e` with `e`
///    bounded (`x as u64` of a narrower `x`: `e ≤ 2^w − 1`);
/// 2. the bound invariant `acc ≤ (N − m) · B` (the measure `m`, bounded by
///    `m ≤ N` in `f`'s `requires`) becomes a `requires` of an entry `E`
///    (`E x̄ = f x̄`, a ghost function) and of the helper `H`;
/// 3. `E` is driven with `f`'s recursive calls folded: the invariant is a
///    fact of the helper's root, so checks it implies are pruned (else no
///    helper: it would decide nothing);
/// 4. `H` is printed from the tree, calling itself at the back-edges (its
///    `requires` there, and at every caller, are elaboration obligations),
///    and linked by `Π x̄ h̄. Eq(R, H x̄ h̄, E x̄ h̄)`, measure recursive: the
///    back-edges are the induction hypothesis.
#[allow(clippy::too_many_arguments)]
fn build_fold(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, f: GlobalId, user_globals: &HashMap<GlobalId, ItemId>, inline: &HashSet<GlobalId>, fault: Option<DriveFault>) -> Result<summary::FoldHelper, String> {
    use sandblaster_kernel::term::{PrimOp, Width};
    let dcfg = drive::DriveConfig::default();
    let fid = *user_globals.get(&f).ok_or("not a user function")?;
    let fd = ext.fn_def(fid).ok_or("not a function")?.clone();
    let fname = ext.item(fid).path.to_string();
    let shape = drive::fold_shape(fid, &fd).ok_or("no bound-invariant shape")?;
    // 1. the probe: how the accumulators grow at the back-edges
    let probe = {
        let env = &cx.out.env;
        let policy = drive::CratePolicy::new(env, ext, &dcfg, f, user_globals, inline).with_summaries(&cx.summaries).with_fold_root(f);
        drive::run_fold_probe(env, &dcfg, &policy, f).map_err(|e| format!("the fold probe of `{fname}`: {e}"))?
    };
    let apps = probe.tree.fold_apps();
    if apps.is_empty() {
        return Err(format!("`{fname}` has no back-edge in tail position"));
    }
    let bound_of = |e: &sandblaster_kernel::value::V| -> Option<u128> {
        match crate::auto::util::as_prim(e) {
            Some((PrimOp::Cast { from, to: Width::U64 }, _)) => from.bits().filter(|b| *b < 64).map(|b| (1u128 << b) - 1),
            _ => match &**e {
                sandblaster_kernel::value::Value::Lit { n, .. } => num_traits::ToPrimitive::to_u128(n),
                _ => None,
            },
        }
    };
    let mut invs: Vec<(usize, u128)> = Vec::new();
    'acc: for &j in &shape.accs {
        let mut b_max: Option<u128> = None;
        for app in &apps {
            let Some((_, args)) = crate::auto::util::as_global_app(app) else { continue 'acc };
            let Some(v) = args.get(j).and_then(drive::step::rel) else { continue 'acc };
            let Some((op, xs)) = crate::auto::util::as_prim(v) else { continue 'acc };
            if !matches!(op, PrimOp::Add(Width::U64) | PrimOp::WAdd(Width::U64)) || xs.len() != 2 {
                continue 'acc;
            }
            let is_param = |x: &sandblaster_kernel::value::V| matches!(&**x, sandblaster_kernel::value::Value::Neu(sandblaster_kernel::value::Neutral { head: sandblaster_kernel::value::Head::Var(l), spine }) if l.0 as usize == j && spine.is_empty());
            let e = if is_param(&xs[0]) { &xs[1] } else if is_param(&xs[1]) { &xs[0] } else { continue 'acc };
            let Some(b) = bound_of(e) else { continue 'acc };
            b_max = Some(b_max.map_or(b, |m| m.max(b)));
        }
        if let Some(b) = b_max {
            invs.push((j, b));
        }
    }
    if invs.is_empty() {
        return Err(format!("no bounded accumulator in `{fname}`"));
    }
    // 2. the invariant clauses `acc <= (N - m as u64) * B`, one `requires`
    // each after `f`'s (whose `m <= N` guards the subtraction): separate
    // binders, so each is a fact of its own (an `&&` would be one Σ)
    let sp = ext.item(fid).span;
    let m_expr = match &shape.bound.kind {
        ExprKind::Binary(BinOp::Le, m, _) => (**m).clone(),
        _ => return Err("an unexpected measure bound".into()),
    };
    let u64t = Ty::Uint(UintTy::U64);
    let mut requires = fd.requires.clone();
    for (j, b) in &invs {
        let PatKind::Binding { local, .. } = &fd.params[*j].pat.kind else { return Err("an accumulator without a binding".into()) };
        let m64 = Expr::new(ExprKind::Cast(Box::new(m_expr.clone()), u64t.clone()), u64t.clone(), sp);
        let diff = Expr::new(ExprKind::Binary(BinOp::Sub, Box::new(Expr::new(ExprKind::Lit(Lit::Int(shape.n)), u64t.clone(), sp)), Box::new(m64)), u64t.clone(), sp);
        let prod = Expr::new(ExprKind::Binary(BinOp::Mul, Box::new(diff), Box::new(Expr::new(ExprKind::Lit(Lit::Int(*b)), u64t.clone(), sp))), u64t.clone(), sp);
        let inv = Expr::new(ExprKind::Binary(BinOp::Le, Box::new(Expr::new(ExprKind::Local(*local), u64t.clone(), sp)), Box::new(prod)), Ty::Bool, sp);
        requires.push(Expr::new(ExprKind::Coerce(Coercion::BoolToProp, Box::new(inv)), Ty::Prop, sp));
    }
    // the entry `E x̄ = f x̄` (ghost)
    let orig = ext.item(fid).clone();
    let mut ef = fd.clone();
    ef.requires = requires.clone();
    ef.ensures = None;
    ef.decreases = None;
    ef.recursion = Recursion::None;
    ef.specialize = false;
    ef.implements = None;
    ef.inline = None;
    let call_args: Vec<Expr> = fd.params.iter().map(|p| match &p.pat.kind {
        PatKind::Binding { local, .. } => Expr::new(ExprKind::Local(*local), p.ty.clone(), sp),
        _ => unreachable!("fold_shape binds every parameter"),
    }).collect();
    ef.body = FnBody::Exec(Expr::new(ExprKind::Call { callee: Callee::Item(fid, vec![]), args: call_args }, fd.ret.clone(), sp));
    let eid = push_elaborate(cx, ext, chain, eopts, &orig, format!("{}__fold_entry", orig.name), ef, true).map_err(|(why, _)| format!("the fold entry of `{fname}` rejected by elaboration: {why}"))?;
    // on failure the entry stays a ghost item, its obligations dropped
    // (its kernel definition stays, unused)
    let drop_entry = |cx: &mut Ctx<'_>| {
        if let Some((om, _)) = cx.marks.remove(&eid) {
            cx.out.obligations.truncate(om);
        }
    };
    let r = fold_from_entry(cx, ext, chain, eopts, f, fid, &fd, &fname, &orig, eid, requires, &invs, &shape, user_globals, inline, fault);
    match r {
        Ok(h) => {
            cx.set_aside_obligations(eid);
            cx.set_aside_obligations(h.item);
            Ok(h)
        }
        Err(e) => {
            drop_entry(cx);
            Err(e)
        }
    }
}

/// [`build_fold`] from its entry `eid` on: drive, print, prove.
#[allow(clippy::too_many_arguments)]
fn fold_from_entry(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, f: GlobalId, _fid: ItemId, fd: &FnDef, fname: &str, orig: &Item, eid: ItemId, requires: Vec<Expr>, invs: &[(usize, u128)], shape: &drive::FoldShape, user_globals: &HashMap<GlobalId, ItemId>, inline: &HashSet<GlobalId>, fault: Option<DriveFault>) -> Result<summary::FoldHelper, String> {
    let dcfg = drive::DriveConfig::default();
    let sp = orig.span;
    let eg = *cx.out.fn_globals.get(&eid).ok_or("the fold entry has no global")?;
    // 3. drive the entry with `f`'s recursive calls folded
    let driven = {
        let env = &cx.out.env;
        let policy = drive::CratePolicy::new(env, ext, &dcfg, eg, user_globals, inline).with_summaries(&cx.summaries).with_fold_root(f);
        drive::run(env, &dcfg, &policy, eg, None).map_err(|e| format!("the fold helper of `{fname}`: {e}"))?
    };
    let counts = driven.tree.counts();
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
        eprintln!("opt: fold helper of {fname}: invariant {invs:?}, {} process nodes, {counts:?}", driven.nodes);
    }
    if counts.prune == 0 || counts.fold == 0 {
        return Err(format!("the bound invariant of `{fname}` decides nothing"));
    }
    let keys = driven.tree.spec_keys();
    ensure_helpers(cx, ext, chain, eopts, &keys, user_globals, inline, 1, None)?;
    // 4. the helper, calling itself at the back-edges
    let own = ItemId(ext.items.len() as u32);
    let mut hf = fd.clone();
    hf.requires = requires;
    hf.ensures = None;
    hf.recursion = Recursion::Tail;
    hf.specialize = false;
    hf.implements = None;
    hf.inline = None;
    let r = {
        let env = &cx.out.env;
        let policy = drive::CratePolicy::new(env, ext, &dcfg, eg, user_globals, inline).with_summaries(&cx.summaries).with_fold_root(f);
        let maps = residual::Maps::new(env, ext, &cx.out.fn_globals, &cx.out.adts)?;
        let op = |h: GlobalId| drive::Policy::folded(&policy, h);
        let ev = drive::step::Eval { env, opaque: &op };
        let spec_items: BTreeMap<drive::tree::SpecKey, ItemId> = cx.helpers.iter().map(|(k, h)| (k.clone(), h.item)).collect();
        let mut ext2 = ext.clone();
        ext2.items.push(Item { id: own, kind: ItemKind::Fn(hf.clone()), ghost: true, ..orig.clone() });
        let fold_items: BTreeMap<GlobalId, ItemId> = BTreeMap::from([(f, own)]);
        residual::tree::build_tree(env, &maps, &ext2, &hf, &driven.tree, &ev, &spec_items, &fold_items, dcfg.max_residual_nodes, sp, None).map_err(|e| format!("the fold helper of `{fname}` is not printable: {e}"))?
    };
    hf.body = FnBody::Exec(r.body);
    hf.locals = r.locals;
    let hname = format!("{}__fold", orig.name);
    let hid = push_elaborate(cx, ext, chain, eopts, orig, hname.clone(), hf, false).map_err(|(why, _)| format!("the fold helper `{hname}` rejected by elaboration: {why}"))?;
    if hid != own {
        return Err("the fold helper's item moved".into());
    }
    let hg = *cx.out.fn_globals.get(&hid).ok_or("the fold helper has no global")?;
    ensure_shift_lemmas_in(&mut cx.out.env, &[hg]);
    // the lemma, measure recursive over the helper's telescope
    let n = symex::telescope(&cx.out.env, hg).ok_or("no telescope")?.binders.len() as u32;
    let m_ix = match shape.measure {
        drive::Measure::Param(i) | drive::Measure::SliceLen(i) => i as u32,
    };
    let measure: sandblaster_kernel::term::Tm = match (fault, shape.measure) {
        // fault R10: a measure that does not decrease (the accumulator)
        (Some(DriveFault::FoldBadMeasure), _) => sandblaster_kernel::util::mk::var(n - 1 - invs[0].0 as u32),
        (_, drive::Measure::Param(_)) => sandblaster_kernel::util::mk::var(n - 1 - m_ix),
        (_, drive::Measure::SliceLen(_)) => std::rc::Rc::new(sandblaster_kernel::term::Term::Fst(sandblaster_kernel::util::mk::var(n - 1 - m_ix))),
    };
    let specs: proof::Specs = cx.helpers.iter().map(|(k, h)| (k.clone(), proof::SpecLemma { helper: h.global, lemma: h.lemma })).collect();
    let folds: proof::Folds = cx.summaries.folds.iter().map(|(d, h)| (*d, (h.global, h.lemma))).collect();
    let folded = drive::CratePolicy::new(&cx.out.env, ext, &dcfg, eg, user_globals, inline).with_summaries(&cx.summaries).folded_set();
    let lemma_name = format!("{}::equiv", ext.item(hid).path);
    match proof::prove_fold(&mut cx.out.env, hg, eg, f, measure, &driven, &specs, &folds, &folded, fault.is_some(), proof::Budgets::of(&dcfg), &lemma_name, &mut cx.outlines) {
        Ok(lemma) => Ok(summary::FoldHelper { item: hid, global: hg, lemma, entry: eg }),
        Err(e) => {
            ext.items[hid.0 as usize].ghost = true;
            pop_driven(cx, ext, hid);
            Err(format!("the fold helper `{hname}`: its lemma was not proven: {}", e.chars().take(600).collect::<String>()))
        }
    }
}

/// The kernel's error kind when `e` reports a helper lemma `add_def`
/// refused (`… its lemma was not proven: Linarith: …`).
fn kernel_rejection(e: &str) -> Option<&str> {
    let rest = e.split("its lemma was not proven: ").nth(1)?;
    let kind = rest.split(':').next()?;
    (!kind.is_empty() && kind.chars().all(|c| c.is_ascii_alphabetic()) && kind.chars().next().is_some_and(|c| c.is_ascii_uppercase())).then_some(kind)
}

/// A polyvariant specialization helper with at most this many residual
/// nodes is printed `#[inline(always)]`.
const POLY_INLINE_NODES: usize = 64;

/// One specialization helper (see [`ensure_helpers`]).
#[allow(clippy::too_many_arguments)]
fn build_helper(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, key: &drive::tree::SpecKey, user_globals: &HashMap<GlobalId, ItemId>, inline: &HashSet<GlobalId>, depth: u32, fault: Option<DriveFault>) -> Result<Helper, String> {
    let dcfg = drive::DriveConfig::default();
    let gid = *user_globals.get(&key.def).ok_or("a specialization of a non-user function")?;
    let gname = ext.item(gid).path.to_string();
    let timing = std::env::var_os("SANDBLASTER_OPT_TIMING").is_some();
    let t0 = std::time::Instant::now();
    // a polyvariant call-site specialization (of a non-recursive callee)
    // or a level of a static recursion
    let polyvariant = !symex::is_recursive(&cx.out.env, key.def);
    let (driven, app) = {
        let env = &cx.out.env;
        let policy = drive::CratePolicy::new(env, ext, &dcfg, key.def, user_globals, inline).with_summaries(&cx.summaries).with_spec_unroll(polyvariant);
        drive::run_spec(env, &dcfg, &policy, key).map_err(|e| format!("`{gname}` at {:?}: {e}", key.statics))?
    };
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
        eprintln!("opt: helper {gname} {:?}: {} process nodes, {:?}", key.statics, driven.nodes, driven.tree.counts());
    }
    let nested = driven.tree.spec_keys();
    ensure_helpers(cx, ext, chain, eopts, &nested, user_globals, inline, depth + 1, fault)?;
    // the helper: the function without its static parameters and `requires`
    let fg = ext.fn_def(gid).unwrap().clone();
    let statics: Vec<usize> = key.statics.iter().map(|(i, _)| *i).collect();
    let mut hf = fg.clone();
    hf.params = fg.params.iter().enumerate().filter(|(j, _)| !statics.contains(j)).map(|(_, p)| p.clone()).collect();
    hf.requires = vec![];
    // fault R12: a `requires` over a dynamic parameter (`p == 0`) that the
    // call sites do not establish
    if fault == Some(DriveFault::HelperRequires)
        && let Some((l, w)) = hf.params.iter().find_map(|p| match (&p.pat.kind, p.ty.peel_refs()) {
            (PatKind::Binding { local, .. }, Ty::Uint(w)) => Some((*local, *w)),
            _ => None,
        })
    {
        let sp = ext.item(gid).span;
        let lhs = Expr::new(ExprKind::Local(l), Ty::Uint(w), sp);
        let rhs = Expr::new(ExprKind::Lit(Lit::Int(0)), Ty::Uint(w), sp);
        let b = Expr::new(ExprKind::Binary(BinOp::Eq, Box::new(lhs), Box::new(rhs)), Ty::Bool, sp);
        hf.requires = vec![Expr::new(ExprKind::Coerce(Coercion::BoolToProp, Box::new(b)), Ty::Prop, sp)];
    }
    hf.ensures = None;
    hf.decreases = None;
    hf.recursion = Recursion::None;
    hf.specialize = false;
    hf.implements = None;
    // always inlined: the chain of levels unrolls into the caller (a static
    // recursion; each level is small and called once); a polyvariant
    // specialization when it is small (below)
    hf.inline = Some(Inline::Always);
    let r = {
        let env = &cx.out.env;
        let policy = drive::CratePolicy::new(env, ext, &dcfg, key.def, user_globals, inline).with_summaries(&cx.summaries);
        let maps = residual::Maps::new(env, ext, &cx.out.fn_globals, &cx.out.adts)?;
        let op = |h: GlobalId| drive::Policy::folded(&policy, h);
        let ev = drive::step::Eval { env, opaque: &op };
        let mut spec_items: BTreeMap<drive::tree::SpecKey, ItemId> = cx.helpers.iter().map(|(k, h)| (k.clone(), h.item)).collect();
        // fault R11: the helper calls itself where it calls the next helper
        // (printed against a stand-in of its own item, removed right after)
        let own = ItemId(ext.items.len() as u32);
        let stand_in = fault == Some(DriveFault::SelfHelper) && !nested.is_empty();
        let mut ext2;
        let krate: &Crate = if stand_in {
            for k in &nested {
                spec_items.insert(k.clone(), own);
            }
            ext2 = ext.clone();
            let orig = ext2.item(gid).clone();
            ext2.items.push(Item { id: own, kind: ItemKind::Fn(hf.clone()), ghost: true, ..orig });
            &ext2
        } else {
            ext
        };
        let fold_items: BTreeMap<GlobalId, ItemId> = driven.tree.fold_calls().iter().filter_map(|d| cx.summaries.folds.get(d).map(|h| (*d, h.item))).collect();
        residual::tree::build_tree(env, &maps, krate, &hf, &driven.tree, &ev, &spec_items, &fold_items, dcfg.max_residual_nodes, ext.item(gid).span, None).map_err(|e| format!("helper of `{gname}` not printable: {e}"))?
    };
    hf.body = FnBody::Exec(r.body);
    hf.locals = r.locals;
    if polyvariant && r.nodes > POLY_INLINE_NODES {
        hf.inline = None;
    }
    let orig = ext.item(gid).clone();
    let vals: Vec<String> = key.statics.iter().map(|(_, n)| n.to_string()).collect();
    let hname = format!("{}__{}", orig.name, vals.join("_"));
    let t_print = t0.elapsed();
    let hid = push_elaborate(cx, ext, chain, eopts, &orig, hname.clone(), hf, false).map_err(|(why, rej)| if rej.as_deref() == Some(NOT_REPROVEN) { format!("helper `{hname}` not re-proven: {why}") } else { format!("helper `{hname}` rejected by elaboration: {why}") })?;
    let t_elab = t0.elapsed();
    let hg = *cx.out.fn_globals.get(&hid).ok_or("the helper has no global")?;
    ensure_shift_lemmas_in(&mut cx.out.env, &[hg]);
    let specs: proof::Specs = cx.helpers.iter().map(|(k, h)| (k.clone(), proof::SpecLemma { helper: h.global, lemma: h.lemma })).collect();
    let lemma_name = format!("{}::equiv", ext.item(hid).path);
    let folded = drive::CratePolicy::new(&cx.out.env, ext, &dcfg, key.def, user_globals, inline).with_summaries(&cx.summaries).folded_set();
    let folds: proof::Folds = cx.summaries.folds.iter().map(|(d, h)| (*d, (h.global, h.lemma))).collect();
    let proven = proof::prove_helper(&mut cx.out.env, hg, &app, &driven, &specs, &folds, &folded, proof::Budgets::of(&dcfg), &lemma_name, &mut cx.outlines, if fault.is_some() { None } else { cx.cache.as_ref() });
    if timing {
        eprintln!("opt: timing helper {hname}: drive+print {:?} (nested helpers included), elaborate {:?}, prove {:?}", t_print, t_elab - t_print, t0.elapsed() - t_elab);
    }
    match proven {
        Ok((lemma, _)) => {
            cx.set_aside_obligations(hid);
            // its shape for the cost model at call sites (design §6.4): the
            // result leaves of its tree, with the leaves of the helpers it
            // calls expanded
            let nested_leaves: usize = nested.iter().filter_map(|k| cx.helpers.get(k)).filter_map(|h| cx.summaries.helpers.get(&h.global)).map(|s| s.result_leaves).sum();
            let result_bytes = ty_bytes(ext, &fg.ret, 0);
            let helper_items: HashSet<ItemId> = cx.helpers.values().map(|h| h.item).collect();
            let calls_user = r.calls.iter().any(|c| !helper_items.contains(c) && *c != hid);
            cx.summaries.helpers.insert(hg, summary::HelperShape { nodes: r.nodes, result_leaves: driven.tree.result_leaves() + nested_leaves, result_bytes, calls_user });
            if polyvariant {
                cx.summaries.spec_keys.insert(key.clone());
            }
            Ok(Helper { item: hid, global: hg, lemma })
        }
        Err(e) => {
            // the helper stays out of the printed crate
            ext.items[hid.0 as usize].ghost = true;
            pop_driven(cx, ext, hid);
            Err(format!("helper `{hname}`: its lemma was not proven: {}", e.chars().take(500).collect::<String>()))
        }
    }
}
