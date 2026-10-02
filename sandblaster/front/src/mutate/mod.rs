//! The counterexample engine (DESIGN.md §15.9, §15.7 spec mutation, §15.1
//! LR8 law sensitivity; stage **S4**). Untrusted and diagnostic: it
//! explains why a specification does not pin code down, and it never makes
//! anything pass.
//!
//! # What it does
//!
//! 1. **Mutants** ([`ops`]): typed-HIR operators on exec functions and
//!    constants (*implementation mutants*) and on spec functions and spec
//!    constants (*spec mutants*), each printed back as a source diff that
//!    parses as the mutant evaluated (parenthesized where an operator's
//!    binding power changes). A constant whose value is also an array
//!    length or a repeat count somewhere in the crate is **not mutated**:
//!    the typechecker resolves those to numbers before mutation, so a mutant
//!    could not follow the constant into the types (listed as excluded).
//! 2. **Incremental re-verification** ([`clone`]): a mutant re-elaborates
//!    only the mutated item and the items that depend on it (callers,
//!    laws, lemmas, proofs, refinement lemmas, examples), as clones in an
//!    extension of the crate. Mutants run in sequential **batches**: each
//!    batch is one fresh elaboration (the kernel `Env` has no removal, so
//!    this is the "re-elaborate from scratch every N mutants" of §15.9) of
//!    the unchanged crate plus the clones of its mutants. The batch size
//!    adapts to memory: when a batch's heap exceeds the fraction
//!    [`MutateOptions::mem_fraction`] of the memguard soft limit the next
//!    batch is smaller, and no batch starts above it (the rest are
//!    reported as not run: incomplete).
//! 3. **Classification** ([`Verdict`]) by the **underlying** failure: a
//!    clone that depends on another clone that did not verify (which the
//!    elaborator replaced by a placeholder with a default body) fails as a
//!    consequence, and its failures — `Blocked` examples, vector records,
//!    refinements and laws included — are never the reason for a verdict.
//!    *Killed by safety*: the mutant's own obligations (overflow, bounds,
//!    termination, callee `requires`, loop invariants), then those of the
//!    code that uses it, fail; for a spec mutant, the mutated spec, or a
//!    spec function that uses it, is ill-formed. *Killed by the
//!    specification*: an `ensures`, a type invariant or an example fails
//!    for the mutant, or a law or a determining refinement has a **definite
//!    counterexample** (the law's `bool` checker evaluates to `false`; the
//!    mutant differs from the function its refinement determines). *Killed
//!    by proofs*: a law, refinement or lemma proof fails without such a
//!    counterexample (the law may still hold; not a specification kill).
//!    *Killed by budget*: only budget-limited failures, and no definite
//!    counterexample (reported separately, never a specification kill, and
//!    the run is incomplete). Otherwise *survived*.
//! 4. **Distinguishing inputs** ([`eval`]) for survivors: example
//!    arguments, boundary values, the mutated code's constants ±1 and
//!    pseudo-random values, evaluated by the kernel's `eval_closed` (the
//!    reference evaluator for functions with `Irr` binders), never through
//!    a placeholder; a found input is **shrunk** (arguments and elements
//!    towards zero, sequences shorter) while the difference persists, and
//!    the differing positions of a compound output are listed. For an
//!    implementation mutant the observation points are the published
//!    members whose own `complete_p` is **not** proven: a difference there
//!    is a **definite counterexample** to `complete_p(R)`
//!    (`error[spec-incomplete]`, with the diff, the input and both
//!    outputs). A published member whose `complete_p` is proven only
//!    relative to a dependency that is not fully specified (a section that
//!    is not well founded) is observed too, and a difference there is
//!    reported against that dependency. No difference found: *possibly
//!    equivalent* (listed, never an error). A member whose completeness is
//!    proven in a well-founded section cannot have one (the surviving mutant
//!    satisfies `H(R)`, so `complete_p(R)` makes it equal), and is never
//!    searched.
//! 5. **Spec mutation (§15.7)**: a spec mutant must be killed by an example
//!    (vector files included; `provenance = production` fixtures are the
//!    oracle's answers) or by a definite counterexample to a law it
//!    changes. A failing refinement of the implementation, or a law whose
//!    proof no longer goes through without a counterexample, does not
//!    count (a spec wrong from the start would come with a matching
//!    implementation and proof). A surviving spec mutant with a
//!    distinguishing input is `error[spec-mutant-survived]` (through the
//!    §15.8 gate [`spec15_gate_mutants`]), with the example to add (its
//!    expected value left to an independent source) — on the function,
//!    and on the nearest spec function known answers exist for (a
//!    refinement target or one with examples) when that differs too.
//! 6. **LR8** ([`LawSensitivity`]): per law, the spec mutants with a
//!    definite counterexample to the mutated law (the law's `bool` checker
//!    evaluated false); a law that kills none of the well-formed, decided
//!    spec mutants in its scope is `warning[law-insensitive]`.
//!
//! Everything is deterministic: mutants are enumerated in item and node
//! order; beyond the cap [`MutateOptions::max_mutants`]
//! (`SANDBLASTER_MUTANTS_MAX`) they are sampled round-robin over the mutated
//! items (return-value replacements first, then by a stable hash), so every
//! item gets mutants before any gets many; inputs come from a seeded
//! generator. Every proof runs with the build's step budgets; wall-clock and
//! memory limits only stop work (reported as budget/incomplete, never as a
//! result). A cap that leaves a mutant out — global, per item, or an
//! `only` entry that names no item — makes the run incomplete.
//!
//! # Enforcement
//!
//! [`spec15_gate_mutants`] turns a report into diagnostics:
//! `error[spec-incomplete]`, `error[spec-mutant-survived]`,
//! `warning[law-insensitive]` and `error[mutation-incomplete]` (a run that
//! did not finish: capped, not run for memory or time, or mutants killed
//! only by budget). The crate path (`driver::gates`) runs the engine in
//! **gate mode** ([`run_gate`]) and applies it to every build;
//! `sandblaster coverage` also runs the full engine for exploration and
//! prints its report ([`coverage`]).
//!
//! # Gate mode
//!
//! [`run_gate`] is what the crate gate runs, with fixed options
//! ([`MutateOptions::gate`]): no cap, no deadline, no environment variable
//! (the `SANDBLASTER_MUTANTS_*` variables only shape `sandblaster coverage`'s
//! exploration run). It reuses the build's own elaboration as the
//! baseline and runs:
//!
//! * **every spec mutant of the review surface** ([`review_scope`]): the
//!   spec functions and spec constants a locked statement depends on
//!   (DESIGN.md §15.6). A proof internal — a spec function only proofs
//!   use — is not mutated ([`MutationReport::internal`] lists them): no
//!   locked statement depends on its definition, so whatever it is the
//!   locked guarantees hold (or the proofs fail), and a known answer for it
//!   has no independent source (DESIGN.md §15.9).
//!   Only an example (vector records included) or
//!   a definite counterexample to a law kills a spec mutant (item 5), so a
//!   spec mutant's batch elaborates only its spec closure — the mutated
//!   spec item and the spec functions that use it, with their examples —
//!   plus the `bool` checkers of the laws in its closure and the originals
//!   it is compared with, through the elaborator's item filter
//!   (`elab::Options::items`, built by `elab::order::filter_closure`: with
//!   the `#[bridges]` lemmas, rules of `auto` in every proof of the build,
//!   and the types, which every elaboration elaborates, with what their
//!   invariants mention). Laws, lemmas, proofs and the refinements of
//!   the implementation are not re-proven: their failure is never a kill.
//!   Every law checker is evaluated (for LR8); then the known answers,
//!   one per elaboration, stopping at the first kill ([`example_slots`]):
//!   the `#[example]`s nearest the mutated item first, the smallest vector
//!   file (stopping at its first failing record), the distinguishing
//!   search ([`search_slot`]: no witness is possibly equivalent, a pass),
//!   and the larger vector files only for a survivor with a witness.
//!   Batches of fixed size run on up to four threads ([`run_parallel`]);
//!   verdicts are per mutant, so the result does not depend on the
//!   scheduling (the prover's per-goal heap cap counts the goal's own
//!   thread, so one batch's growth never trips another's goals);
//! * **implementation mutants only when some section is not fully
//!   specified**: when every `complete_p` is proven no implementation
//!   mutant has an observation point (item 4), so none can produce a
//!   finding. (The crate gate runs spec mutation after the section gate
//!   passed, so there it runs spec mutants only.)

pub mod cache;
pub mod clone;
pub mod coverage;
pub mod eval;
pub mod ops;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};

use sandblaster_kernel::term::GlobalId;

use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::elab::complete::{DepHow, SectionStatus};
use crate::elab::{self, DefStatus, OblStatus};
use crate::hir::*;
use crate::json::Json;
use crate::prover::ObligationKind;
use crate::span::{SourceMap, Span};

pub use clone::Target;

/// Options of a run. Every limit is deterministic except the optional
/// wall-clock [`MutateOptions::deadline`] (a safety net: mutants it stops
/// are reported as not run).
#[derive(Clone, Debug)]
pub struct MutateOptions {
    /// Mutants run at most (sampled deterministically beyond: incomplete).
    pub max_mutants: usize,
    /// Mutants per mutated item at most (sampled beyond: incomplete; no
    /// cap by default — the global cap samples round-robin over items).
    pub max_per_item: usize,
    /// Mutants per batch (one fresh elaboration each), before the memory
    /// adaptation.
    pub batch: usize,
    /// Fraction of the memguard soft limit a batch may use.
    pub mem_fraction: f64,
    /// Candidate inputs per observation point.
    pub inputs: usize,
    /// Evaluations the shrinking of one distinguishing input may use.
    pub shrink: usize,
    /// Kernel steps per evaluation.
    pub eval_budget: u64,
    /// Items one mutant may re-elaborate at most (larger: not run).
    pub max_closure: usize,
    pub impl_mutants: bool,
    pub spec_mutants: bool,
    /// Mutate only these items (display paths); empty: every item.
    pub only: Vec<String>,
    /// Elaboration options (the build's budgets by default).
    pub elab: elab::Options,
    /// Seed of the input generator and of sampling.
    pub seed: u64,
    /// Wall-clock limit of the whole run (`--time-budget`): mutants it stops
    /// are not run, and the run is incomplete.
    pub deadline: Option<Duration>,
    /// A progress line on stderr after each batch.
    pub progress: bool,
    /// Gate mode (see the module docs): spec mutants re-check only their
    /// spec closure, examples and law checkers.
    pub gate: bool,
}

impl Default for MutateOptions {
    fn default() -> MutateOptions {
        MutateOptions {
            max_mutants: 200,
            max_per_item: usize::MAX,
            batch: 12,
            mem_fraction: 0.5,
            inputs: 400,
            shrink: 240,
            eval_budget: 200_000_000,
            max_closure: 400,
            impl_mutants: true,
            spec_mutants: true,
            only: vec![],
            elab: elab::Options::default(),
            seed: 0x05ee_d159,
            deadline: None,
            progress: false,
            gate: false,
        }
    }
}

impl MutateOptions {
    /// The options of the crate gate ([`run_gate`]): every mutant, no
    /// deadline, spec mutants in gate mode. Reads no environment variable.
    pub fn gate() -> MutateOptions {
        MutateOptions { max_mutants: usize::MAX, max_per_item: usize::MAX, batch: 32, max_closure: usize::MAX, gate: true, ..MutateOptions::default() }
    }

    /// The defaults, with `SANDBLASTER_MUTANTS_MAX`, `SANDBLASTER_MUTANTS_BATCH`,
    /// `SANDBLASTER_MUTANTS_PER_ITEM`, `SANDBLASTER_MUTANTS_INPUTS` and
    /// `SANDBLASTER_MUTANTS_TIME_BUDGET` (seconds): the exploration run of
    /// `sandblaster coverage` only (caps only: none of them can turn a
    /// finding into a pass — a cap that leaves a mutant out makes the run
    /// incomplete). The crate gate uses [`MutateOptions::gate`] and reads
    /// none of them.
    pub fn from_env() -> MutateOptions {
        let mut o = MutateOptions::default();
        let num = |k: &str| std::env::var(k).ok().and_then(|v| v.trim().parse::<usize>().ok());
        if let Some(n) = num("SANDBLASTER_MUTANTS_MAX") {
            o.max_mutants = n;
        }
        if let Some(n) = num("SANDBLASTER_MUTANTS_BATCH") {
            o.batch = n.max(1);
        }
        if let Some(n) = num("SANDBLASTER_MUTANTS_PER_ITEM") {
            o.max_per_item = n;
        }
        if let Some(n) = num("SANDBLASTER_MUTANTS_INPUTS") {
            o.inputs = n;
        }
        if let Some(n) = num("SANDBLASTER_MUTANTS_TIME_BUDGET") {
            o.deadline = Some(Duration::from_secs(n as u64));
        }
        o
    }
}

/// A mutant's edit of the source, line-based (`old` lines from
/// `first_line` replaced by `new`).
#[derive(Clone, Debug)]
pub struct SourceEdit {
    pub path: String,
    pub first_line: u32,
    pub old: Vec<String>,
    pub new: Vec<String>,
}

/// One mutant.
#[derive(Clone, Debug)]
pub struct Mutant {
    pub id: usize,
    /// The mutated item.
    pub item: ItemId,
    pub path: String,
    pub target: Target,
    /// The operator family (`arithmetic`, `return-value`, …).
    pub family: &'static str,
    /// What the mutation does.
    pub desc: String,
    pub span: Span,
    /// `file:line`.
    pub location: String,
    /// The source diff: `- old` / `+ new` lines.
    pub diff: Vec<String>,
    /// The same edit, structured (`None` without source text).
    pub edit: Option<SourceEdit>,
    site: ops::Site,
}

/// How a mutant ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verdict {
    /// An `ensures`, a type invariant or an example fails for the mutant,
    /// or a law or a determining refinement has a definite counterexample
    /// (spec mutants: an example, or a definite counterexample to a law).
    KilledBySpec,
    /// A law, refinement or lemma proof fails for the mutant without a
    /// definite counterexample (the law may still hold): killed by the
    /// proofs, not by the specification.
    KilledByProofs,
    /// The mutant's own obligations fail (safety, termination, loop
    /// invariants), or those of the code that uses it; for a spec mutant,
    /// the mutated spec (or a spec function that uses it) is ill-formed.
    KilledBySafety,
    /// Only budget-limited failures: nothing is claimed (incomplete).
    KilledByBudget,
    /// The mutant is not a program the elaborator accepts.
    Invalid,
    /// Survived, and a distinguishing input was found: a definite
    /// counterexample (an error when the verdict is about an unproven
    /// section, an unspecified dependency, or a spec function).
    Counterexample,
    /// Survived; no distinguishing input found (never an error).
    PossiblyEquivalent,
    /// Not run (caps, memory, deadline): incomplete.
    NotRun,
}

impl Verdict {
    pub fn word(self) -> &'static str {
        match self {
            Verdict::KilledBySpec => "killed-by-spec",
            Verdict::KilledByProofs => "killed-by-proofs",
            Verdict::KilledBySafety => "killed-by-safety",
            Verdict::KilledByBudget => "killed-by-budget",
            Verdict::Invalid => "invalid",
            Verdict::Counterexample => "counterexample",
            Verdict::PossiblyEquivalent => "possibly-equivalent",
            Verdict::NotRun => "not-run",
        }
    }
    /// Killed by the proofs (the verification of the mutant fails).
    pub fn killed_by_proofs(self) -> bool {
        matches!(self, Verdict::KilledBySpec | Verdict::KilledByProofs | Verdict::KilledBySafety)
    }
    /// A verdict the kill rates count (not: not run, invalid, killed only
    /// by budget).
    pub fn decided(self) -> bool {
        !matches!(self, Verdict::NotRun | Verdict::Invalid | Verdict::KilledByBudget)
    }
    pub const ALL: [Verdict; 8] = [Verdict::KilledBySpec, Verdict::KilledByProofs, Verdict::KilledBySafety, Verdict::KilledByBudget, Verdict::Invalid, Verdict::Counterexample, Verdict::PossiblyEquivalent, Verdict::NotRun];
}

/// A distinguishing input.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Where the difference was observed (display path).
    pub function: String,
    pub item: ItemId,
    /// The arguments, printed (shrunk).
    pub input: String,
    pub original: String,
    pub mutant: String,
    /// The differing positions of a compound output (`[14]: 3 vs 4`).
    pub differs_at: Vec<String>,
    /// Which evaluator decided it ([`eval::Method::word`]).
    pub evaluator: String,
    /// The section whose `complete_p` it refutes (implementation mutants;
    /// only for a published member whose `complete_p` is not proven).
    pub section: Option<usize>,
    /// The dependency that is not fully specified, when the difference was
    /// seen at a member whose `complete_p` is proven only relative to it
    /// (a section that is not well founded): the witness shows that the
    /// dependency is not determined.
    pub dependency: Option<(ItemId, String)>,
    /// The optional kernel-checked refutation of `complete_p(R)` (§15.9):
    /// `Ok` with the refuting lemma's statement when the kernel checked
    /// `λ(c : complete_p(R)). … : complete_p(R) → Empty`, `Err` with why it
    /// was not built (the witness itself stays a definite counterexample by
    /// evaluation).
    pub refutation: Option<Result<String, String>>,
}

/// The result of one mutant.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub verdict: Verdict,
    /// What killed it (readable), or why it is not run.
    pub by: Vec<String>,
    pub witness: Option<Witness>,
    /// Spec mutants: a difference at the nearest spec function known answers
    /// exist for (a refinement target or one with examples), when the
    /// mutated function is not one.
    pub suggestion: Option<Witness>,
    /// Items re-elaborated.
    pub closure: usize,
    /// Informational notes (non-definite failures of a spec mutant,
    /// inputs tried, …).
    pub notes: Vec<String>,
    /// Laws with a definite counterexample under this mutant: `(law, input)`.
    pub law_counterexamples: Vec<(ItemId, String)>,
}

impl Outcome {
    fn new(verdict: Verdict, by: Vec<String>) -> Outcome {
        Outcome { verdict, by, witness: None, suggestion: None, closure: 0, notes: vec![], law_counterexamples: vec![] }
    }
}

/// LR8: what one law says about the spec functions it uses.
#[derive(Clone, Debug)]
pub struct LawSensitivity {
    pub law: ItemId,
    pub path: String,
    /// Spec mutants whose re-check included the law (well-formed and
    /// decided ones only, after the run).
    pub in_scope: Vec<usize>,
    /// The mutants with a definite counterexample to the mutated law.
    pub killed: Vec<usize>,
    /// The law has a `bool` checker (no quantifier), so counterexamples can
    /// be searched.
    pub evaluable: bool,
}

/// One batch (one fresh elaboration).
#[derive(Clone, Debug)]
pub struct BatchStat {
    pub mutants: usize,
    pub items: usize,
    pub elapsed: Duration,
    /// Heap after the batch's elaboration (bytes).
    pub heap: usize,
}

/// The baseline facts of one function (for the report and `coverage`).
#[derive(Clone, Debug, Default)]
pub struct BaseItem {
    /// `(kind, how discharged or "unproven")`.
    pub obligations: Vec<(String, String)>,
    /// `(spec, checked, determines, up_to)`.
    pub refines: Option<(String, bool, bool, Option<String>)>,
    /// `(index, status word, fully specified, published)`.
    pub section: Option<(usize, String, bool, bool)>,
    /// Laws whose statements mention it (directly or through spec
    /// functions).
    pub laws: Vec<String>,
    /// `(examples, failed)`.
    pub examples: (usize, usize),
    /// Spec functions: `(exercised, outcomes needed, outcomes seen)`.
    pub coverage: Option<(bool, Vec<String>, Vec<String>)>,
    /// Checked.
    pub checked: bool,
}

/// The result of a run.
#[derive(Clone, Debug, Default)]
pub struct MutationReport {
    /// The crate itself verified (the engine needs a verified baseline).
    pub baseline_verified: bool,
    pub baseline_problems: Vec<String>,
    pub mutants: Vec<(Mutant, Outcome)>,
    /// Mutants enumerated before any cap.
    pub enumerated: usize,
    /// Every enumerated mutant ran to a verdict and none was killed only by
    /// budget.
    pub complete: bool,
    pub incomplete_reasons: Vec<String>,
    pub batches: Vec<BatchStat>,
    pub laws: Vec<LawSensitivity>,
    pub base: BTreeMap<ItemId, BaseItem>,
    pub elapsed: Duration,
    /// Tests against mutated emitted code (DESIGN.md §15.10 "optionally"):
    /// why they were not run.
    pub tests_note: String,
    /// Items not mutated, with why (constants used at type level).
    pub excluded: Vec<(String, String)>,
    /// Gate mode: the spec functions and spec constants not mutated because
    /// they are proof internals — not on the review surface (DESIGN.md
    /// §15.6), so no locked statement depends on their definitions (§15.9,
    /// *Which spec functions the gate mutates*). By path; empty for the
    /// exploration run, which mutates every spec item.
    pub internal: Vec<String>,
    /// Items with mutation sites none of whose mutants was sampled.
    pub not_sampled: Vec<String>,
    /// Items whose mutants the per-item cap sampled: `(path, run, of)`.
    pub capped: Vec<(String, usize, usize)>,
    /// `only` entries that name no item, with the closest item paths.
    pub unknown_only: Vec<(String, Vec<String>)>,
    /// Gate mode with the verdict cache ([`cache`]): spec mutants whose
    /// stored verdict was reused, and those run (timing and report notes
    /// only; the verdicts are the same either way).
    pub cache_hits: usize,
    pub cache_misses: usize,
    /// A cache write that failed (a warning; never a verdict).
    pub cache_note: Option<String>,
}

impl MutationReport {
    /// `(mutant, outcome)` of one item.
    pub fn of_item(&self, id: ItemId) -> impl Iterator<Item = &(Mutant, Outcome)> {
        self.mutants.iter().filter(move |(m, _)| m.item == id)
    }
    /// Count of a verdict.
    pub fn count(&self, v: Verdict) -> usize {
        self.mutants.iter().filter(|(_, o)| o.verdict == v).count()
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// Runs the engine on a checked crate (see the module docs), on a thread
/// with a big stack.
pub fn run(krate: &Crate, sm: &SourceMap, opts: &MutateOptions) -> MutationReport {
    elab::with_big_stack(|| run_here(krate, sm, opts))
}

/// The crate gate's run (see *Gate mode* in the module docs): `out` is the
/// build's own elaboration of `krate` (the baseline), and the call must
/// run on its elaboration thread. The options are fixed
/// ([`MutateOptions::gate`]); the spec items mutated are those of the
/// review surface ([`review_scope`]), computed here from `out`.
pub fn run_gate(krate: &Crate, sm: &SourceMap, out: &elab::Output) -> MutationReport {
    let surface = crate::surface::compute(out, krate, sm, &crate::surface::SurfaceOptions { kernel_text: false, ..Default::default() });
    run_gate_cached(krate, sm, out, None, &surface)
}

/// The spec items the gate mutates: the spec functions and spec constants
/// of the review surface — the vocabulary of the locked statements
/// (DESIGN.md §15.6) — given as the surface `run_gate_cached` receives
/// (its [`crate::surface::Surface::items`] are the review surface). A spec
/// function only proofs use (a proof internal) is not mutated: no locked
/// statement depends on its definition (§15.9, *Which spec functions the
/// gate mutates*).
pub fn review_scope(surface: &crate::surface::Surface) -> BTreeSet<ItemId> {
    use crate::surface::SurfaceKind;
    surface.items.iter().filter(|i| matches!(i.kind, SurfaceKind::SpecFn | SurfaceKind::SpecConst | SurfaceKind::Constant)).filter_map(|i| i.item).collect()
}

/// [`run_gate`] with the verdict cache (`crate::driver::cache`): a spec
/// mutant whose inputs are unchanged since a run stored its verdict is not
/// re-run ([`cache`], *incremental spec mutation*); every decided verdict
/// of this run is stored. `surface` is the build's specification surface
/// (the spec items of its review surface are mutated, [`review_scope`]).
pub fn run_gate_cached(krate: &Crate, sm: &SourceMap, out: &elab::Output, vc: Option<&crate::driver::cache::VerdictCache>, surface: &crate::surface::Surface) -> MutationReport {
    let scope = review_scope(surface);
    let mut opts = MutateOptions::gate();
    opts.impl_mutants = out.sections.iter().any(|s| !s.fully_specified());
    // progress lines on stderr (output only)
    opts.progress = std::env::var_os("SANDBLASTER_TRACE_MUTATION").is_some();
    let t0 = Instant::now();
    let mut rep = MutationReport { tests_note: TESTS_NOTE.into(), ..Default::default() };
    let problems: Vec<String> = out.defs.iter().filter(|d| !matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))).map(|d| format!("`{}`: {}", d.name, crate::driver::def_status_str(&d.status))).take(20).collect();
    rep.base = base_items(out, krate);
    let base = baseline_of(out, krate);
    run_from(krate, sm, &opts, out.verified(), problems, base, 0, rep, t0, vc, Some(&scope))
}

/// How a published member of a section is specified.
struct PubInfo {
    section: usize,
    /// Its own `complete_p` is kernel-checked.
    proven: bool,
    status: SectionStatus,
    /// The section's dependencies that are not fully specified.
    unspecified: Vec<ItemId>,
}

/// Facts of the baseline elaboration used by the engine.
struct Baseline {
    published: HashMap<ItemId, PubInfo>,
    /// Section index by member.
    member: HashMap<ItemId, usize>,
    /// Determined by a refinement (established, or determined up to an
    /// `Abstract` view): never observed.
    determined: BTreeSet<ItemId>,
    /// Established by a determining refinement (injective view, no domain):
    /// a mutant that differs from it violates its refinement.
    established: BTreeSet<ItemId>,
    /// Spec functions known answers are published for: refinement targets
    /// and spec functions with examples or vector files.
    known_answers: BTreeSet<ItemId>,
}

fn obligation_owner(names: &HashMap<String, ItemId>, def: &str) -> Option<ItemId> {
    let mut s = def;
    loop {
        if let Some(id) = names.get(s) {
            return Some(*id);
        }
        let i = s.rfind("::")?;
        s = &s[..i];
    }
}

fn prover_word(o: &elab::ObligationRecord) -> String {
    match &o.status {
        OblStatus::Proven { by } if o.hinted => format!("{by} (with script hints)"),
        OblStatus::Proven { by } => by.clone(),
        OblStatus::Failed(_) => "UNPROVEN".into(),
        OblStatus::Todo => "todo()".into(),
    }
}

/// The items a law's statement mentions: directly, and through the bodies
/// of spec functions.
fn law_mentions(krate: &Crate, law: &FnDef) -> BTreeSet<ItemId> {
    struct M<'a> {
        krate: &'a Crate,
        out: BTreeSet<ItemId>,
        seen: BTreeSet<ItemId>,
    }
    impl crate::visit::Visitor for M<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(id, _), .. } = &e.kind {
                self.out.insert(*id);
                if self.seen.insert(*id)
                    && let Some(f) = self.krate.fn_def(*id)
                    && f.kind == FnKind::Spec
                    && let FnBody::Spec(b) = &f.body
                {
                    self.expr(b);
                }
            }
            if let ExprKind::Const(id) = &e.kind {
                self.out.insert(*id);
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut m = M { krate, out: BTreeSet::new(), seen: BTreeSet::new() };
    for r in &law.requires {
        crate::visit::Visitor::expr(&mut m, r);
    }
    if let Some(en) = &law.ensures {
        crate::visit::Visitor::expr(&mut m, &en.prop);
    }
    m.out
}

fn base_items(out: &elab::Output, krate: &Crate) -> BTreeMap<ItemId, BaseItem> {
    let mut base: BTreeMap<ItemId, BaseItem> = BTreeMap::new();
    let mut names: HashMap<String, ItemId> = HashMap::new();
    for it in &krate.items {
        if matches!(it.kind, ItemKind::Fn(_) | ItemKind::Const(_)) {
            names.insert(it.path.to_string(), it.id);
            base.insert(it.id, BaseItem::default());
        }
    }
    for d in &out.defs {
        if let Some(id) = d.item
            && d.name == krate.item(id).path.to_string()
            && let Some(b) = base.get_mut(&id)
        {
            b.checked = d.status == DefStatus::Checked;
        }
    }
    for o in &out.obligations {
        if let Some(id) = obligation_owner(&names, &o.def)
            && let Some(b) = base.get_mut(&id)
        {
            b.obligations.push((elab::obl::kind_name(&o.kind).to_string(), prover_word(o)));
        }
    }
    for r in &out.refinements {
        if let Some(b) = base.get_mut(&r.item) {
            b.refines = Some((krate.item(r.spec).path.to_string(), r.status == DefStatus::Checked, r.status == DefStatus::Checked && r.up_to.is_none() && r.lemma.is_some(), r.up_to.clone()));
        }
    }
    for s in &out.sections {
        for m in &s.members {
            if let Some(b) = base.get_mut(m) {
                b.section = Some((s.index, s.status.word().to_string(), s.fully_specified(), s.published.contains(m)));
            }
        }
    }
    for e in &out.examples {
        if let Some(b) = base.get_mut(&e.item) {
            b.examples.0 += 1;
            if e.status != DefStatus::Checked {
                b.examples.1 += 1;
            }
        }
    }
    for c in &out.coverage {
        if let Some(b) = base.get_mut(&c.spec) {
            b.coverage = Some((c.exercised, c.outcomes_needed.clone(), c.outcomes_seen.clone()));
        }
    }
    for it in &krate.items {
        if let ItemKind::Fn(f) = &it.kind
            && f.kind == FnKind::Law
        {
            for m in law_mentions(krate, f) {
                if let Some(b) = base.get_mut(&m) {
                    b.laws.push(it.path.to_string());
                }
            }
        }
    }
    base
}

fn baseline_of(out: &elab::Output, krate: &Crate) -> Baseline {
    let mut published = HashMap::new();
    let mut member = HashMap::new();
    for s in &out.sections {
        for m in &s.members {
            member.insert(*m, s.index);
        }
        let unspecified: Vec<ItemId> = s.dep_status.iter().filter(|(_, h)| matches!(h, DepHow::Unspecified | DepHow::UpToView(_))).map(|(d, _)| *d).collect();
        for p in &s.published {
            let proven = s.complete.iter().any(|(q, st)| q == p && *st == DefStatus::Checked) || s.statements.iter().any(|c| c.item == *p && c.status == DefStatus::Checked);
            published.insert(*p, PubInfo { section: s.index, proven, status: s.status.clone(), unspecified: unspecified.clone() });
        }
    }
    let determined = out.refinements.iter().filter(|r| r.status == DefStatus::Checked && r.up_to.is_none() && r.lemma.is_some()).map(|r| r.item).collect();
    let item_of: HashMap<GlobalId, ItemId> = out.fn_globals.iter().map(|(i, g)| (*g, *i)).collect();
    let established = out.established.iter().filter_map(|g| item_of.get(g).copied()).collect();
    let mut known_answers = BTreeSet::new();
    for it in &krate.items {
        if let ItemKind::Fn(f) = &it.kind {
            if let Some(r) = &f.spec.refines {
                known_answers.insert(r.spec);
            }
            if f.kind == FnKind::Spec && (!f.spec.examples.is_empty() || !f.spec.example_files.is_empty()) {
                known_answers.insert(it.id);
            }
        }
    }
    Baseline { published, member, determined, established, known_answers }
}

/// The body of a mutable item and its result type (`None` for constants).
fn body_of(it: &Item) -> Option<(&Expr, Option<&Ty>)> {
    match &it.kind {
        ItemKind::Fn(f) => match &f.body {
            FnBody::Exec(e) | FnBody::Spec(e) => Some((e, Some(&f.ret))),
            _ => None,
        },
        ItemKind::Const(c) => Some((&c.init, None)),
        _ => None,
    }
}

fn body_of_mut(it: &mut Item) -> Option<(&mut Expr, Option<Ty>)> {
    match &mut it.kind {
        ItemKind::Fn(f) => {
            let ret = f.ret.clone();
            match &mut f.body {
                FnBody::Exec(e) | FnBody::Spec(e) => Some((e, Some(ret))),
                _ => None,
            }
        }
        ItemKind::Const(c) => Some((&mut c.init, None)),
        _ => None,
    }
}

/// The mutated copy of `m`'s item (same id and path): what the engine
/// elaborates under the clone's name.
pub fn mutated_item(krate: &Crate, m: &Mutant) -> Item {
    let mut it = krate.item(m.item).clone();
    if let Some((body, ret)) = body_of_mut(&mut it) {
        ops::apply(body, &m.site, ret.as_ref());
    }
    if let ItemKind::Const(c) = &mut it.kind {
        c.value = match &c.init.kind {
            ExprKind::Lit(Lit::Int(n)) => Some(*n),
            _ => None,
        };
    }
    it
}

/// Hardware code (target features, `#[implements]`, intrinsics, vector
/// types; callers included): not mutated (the portable function it is
/// proven equal to is).
fn hardware(krate: &Crate) -> HashSet<ItemId> {
    struct Hw(bool);
    impl crate::visit::Visitor for Hw {
        fn expr(&mut self, e: &Expr) {
            if matches!(&e.kind, ExprKind::Call { callee: Callee::Intrinsic(..) | Callee::Helper(_), .. }) || matches!(&e.ty, Ty::Vector(_)) {
                self.0 = true;
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut hw = HashSet::new();
    for it in &krate.items {
        if let ItemKind::Fn(f) = &it.kind
            && f.kind == FnKind::Exec
        {
            let mut v = Hw(!f.target_features.is_empty() || f.implements.is_some());
            crate::visit::walk_fn(&mut v, f);
            if v.0 {
                hw.insert(it.id);
            }
        }
    }
    loop {
        let before = hw.len();
        for it in &krate.items {
            if !hw.contains(&it.id)
                && krate.fn_def(it.id).is_some_and(|f| f.kind == FnKind::Exec)
                && elab::order::refs(krate, it.id).iter().any(|r| hw.contains(r))
            {
                hw.insert(it.id);
            }
        }
        if hw.len() == before {
            return hw;
        }
    }
}

/// Every array length, repeat count and intrinsic immediate of the crate:
/// the values the typechecker resolved from constants before mutation.
fn type_level_values(krate: &Crate) -> BTreeSet<u128> {
    struct Tl(BTreeSet<u128>);
    impl Tl {
        fn ty(&mut self, t: &Ty) {
            match t {
                Ty::Array(e, n) => {
                    self.0.insert(*n as u128);
                    self.ty(e);
                }
                Ty::Tuple(ts) | Ty::Adt(_, ts) => ts.iter().for_each(|x| self.ty(x)),
                Ty::Slice(e) | Ty::Ref(e) | Ty::Option(e) | Ty::Seq(e) => self.ty(e),
                _ => {}
            }
        }
    }
    impl crate::visit::Visitor for Tl {
        fn expr(&mut self, e: &Expr) {
            self.ty(&e.ty);
            match &e.kind {
                ExprKind::Repeat { count, .. } => {
                    self.0.insert(*count as u128);
                }
                ExprKind::Call { callee: Callee::Intrinsic(_, imms), .. } => self.0.extend(imms.iter().filter(|i| **i >= 0).map(|i| *i as u128)),
                ExprKind::Cast(_, t) => self.ty(t),
                _ => {}
            }
            crate::visit::walk_expr(self, e);
        }
        fn pat(&mut self, p: &Pat) {
            self.ty(&p.ty);
            crate::visit::walk_pat(self, p);
        }
    }
    let mut v = Tl(BTreeSet::new());
    for it in &krate.items {
        match &it.kind {
            ItemKind::Fn(f) => {
                f.params.iter().for_each(|p| v.ty(&p.ty));
                v.ty(&f.ret);
                f.locals.iter().for_each(|l| v.ty(&l.ty));
                crate::visit::walk_fn(&mut v, f);
                crate::visit::walk_fn_spec(&mut v, &f.spec);
            }
            ItemKind::Const(c) => {
                v.ty(&c.ty);
                c.locals.iter().for_each(|l| v.ty(&l.ty));
                crate::visit::Visitor::expr(&mut v, &c.init);
            }
            ItemKind::Struct(s) => s.fields.iter().for_each(|f| v.ty(&f.ty)),
            ItemKind::Enum(e) => e.variants.iter().flat_map(|x| &x.fields).for_each(|f| v.ty(&f.ty)),
            ItemKind::TypeAlias(a) => v.ty(&a.ty),
        }
    }
    v.0
}

/// Constants that are not mutated: the constant, or a constant computed
/// from it, has a value that is also a type-level value of the crate
/// ([`type_level_values`]) — it may be used in a type, where a mutant could
/// not follow it. Conservative: a coincidence of values also excludes.
fn type_level_consts(krate: &Crate, rev: &HashMap<ItemId, BTreeSet<ItemId>>) -> HashMap<ItemId, String> {
    let lens = type_level_values(krate);
    let mut out = HashMap::new();
    if lens.is_empty() {
        return out;
    }
    let value = |id: ItemId| match &krate.item(id).kind {
        ItemKind::Const(c) => c.value,
        _ => None,
    };
    for it in &krate.items {
        if !matches!(it.kind, ItemKind::Const(_)) {
            continue;
        }
        let mut stack = vec![it.id];
        let mut seen = BTreeSet::new();
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            if let Some(v) = value(x)
                && lens.contains(&v)
            {
                let via = if x == it.id { format!("its value {v}") } else { format!("the value {v} of `{}` (computed from it)", krate.item(x).path) };
                out.insert(it.id, format!("{via} is also an array length, repeat count or intrinsic immediate in the crate: types are resolved before mutation, so a mutant of the constant could not follow it into them"));
                break;
            }
            for r in rev.get(&x).into_iter().flatten() {
                if matches!(krate.item(*r).kind, ItemKind::Const(_)) {
                    stack.push(*r);
                }
            }
        }
    }
    out
}

/// Which items are mutated, and as what.
fn mutation_target(krate: &Crate, it: &Item, hw: &HashSet<ItemId>) -> Option<Target> {
    match &it.kind {
        ItemKind::Fn(f) => match f.kind {
            // plain `fn`s of ghost modules are proof helpers, not code
            FnKind::Exec if !it.ghost && !hw.contains(&it.id) && f.implements.is_none() && f.spec.trusted_extern.is_none() => Some(Target::Impl),
            // `#[assumption]` functions have no logical content
            FnKind::Spec if f.spec.assumption.is_none() => Some(Target::Spec),
            _ => None,
        },
        ItemKind::Const(_) if it.ghost || krate.in_spec_module(it.id) => Some(Target::Spec),
        ItemKind::Const(_) => Some(Target::Impl),
        _ => None,
    }
}

/// The source diff of a site: `(file:line, lines, edit)`.
fn source_diff(sm: &SourceMap, edits: &[(Span, String)]) -> Option<(String, Vec<String>, SourceEdit)> {
    let first = edits.iter().map(|e| e.0).filter(|s| !s.is_dummy()).min_by_key(|s| s.lo)?;
    let file = sm.get(first.file)?;
    let lo_line = edits.iter().map(|e| e.0.lo.0).min()?;
    let hi_line = edits.iter().map(|e| e.0.hi.0).max()?;
    let old: Vec<String> = (lo_line..=hi_line).filter_map(|l| file.line(l).map(str::to_string)).collect();
    // apply the edits right to left on the affected lines
    let mut lines = old.clone();
    let mut sorted: Vec<&(Span, String)> = edits.iter().collect();
    sorted.sort_by_key(|e| std::cmp::Reverse(e.0.lo));
    for (sp, text) in sorted {
        let (l0, c0) = sp.lo;
        let (l1, c1) = sp.hi;
        let i0 = (l0 - lo_line) as usize;
        let i1 = (l1 - lo_line) as usize;
        if i1 >= lines.len() {
            return None;
        }
        let byte = |s: &str, col: u32| s.char_indices().nth(col as usize).map(|(i, _)| i).unwrap_or(s.len());
        let head = lines[i0][..byte(&lines[i0], c0)].to_string();
        let tail = lines[i1][byte(&lines[i1], c1)..].to_string();
        let merged = format!("{head}{text}{tail}");
        lines.splice(i0..=i1, merged.lines().map(str::to_string).collect::<Vec<_>>());
        if merged.is_empty() {
            lines.insert(i0, String::new());
        }
    }
    let mut out: Vec<String> = old.iter().map(|l| format!("- {}", l.trim_end())).collect();
    out.extend(lines.iter().map(|l| format!("+ {}", l.trim_end())));
    let path = sm.path(first.file).display().to_string();
    Some((format!("{path}:{lo_line}"), out, SourceEdit { path, first_line: lo_line, old, new: lines }))
}

/// Every mutant of an item's body.
fn item_mutants(it: &Item, target: Target, sm: &SourceMap, sites: Vec<ops::Site>, out: &mut Vec<Mutant>) {
    let Some((body, ret)) = body_of(it) else { return };
    let path = it.path.to_string();
    for site in sites {
        let (location, diff, edit) = match ops::source_edits(body, &site, sm, ret).and_then(|e| source_diff(sm, &e)) {
            Some((l, d, e)) => (l, d, Some(e)),
            None => (format!("{}:{}", sm.path(site.span.file).display(), site.span.lo.0), vec![format!("  ({})", site.desc)], None),
        };
        // name the node: `constant `0u8` → `1` in `b[1] != 0u8``
        let desc = match (&site.op, sm.snippet(site.span)) {
            (ops::Op::Return(_), _) | (_, None) => site.desc.clone(),
            // a constant in the radix it is written in
            (ops::Op::Lit { to, .. }, Some(text)) => format!("constant `{}` → `{}`", text.trim(), ops::relit(&text, *to)),
            (_, Some(text)) => {
                let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
                let short: String = if flat.chars().count() > 48 { format!("{}…", flat.chars().take(47).collect::<String>()) } else { flat };
                format!("{} in `{short}`", site.desc)
            }
        };
        out.push(Mutant { id: out.len(), item: it.id, path: path.clone(), target, family: site.op.family(), desc, span: site.span, location, diff, edit, site });
    }
}

fn only_matches(only: &[String], path: &str) -> bool {
    only.is_empty() || only.iter().any(|o| o == path || format!("crate::{o}") == path)
}

/// The `only` entries that name no function or constant of the crate, each
/// with the closest item paths (for a usage error).
pub fn unknown_only(krate: &Crate, only: &[String]) -> Vec<(String, Vec<String>)> {
    let paths: Vec<String> = krate.items.iter().filter(|it| matches!(it.kind, ItemKind::Fn(_) | ItemKind::Const(_))).map(|it| it.path.to_string()).collect();
    let mut out = Vec::new();
    for o in only {
        if paths.iter().any(|p| only_matches(std::slice::from_ref(o), p)) {
            continue;
        }
        let want = if o.starts_with("crate::") { o.clone() } else { format!("crate::{o}") };
        let last = want.rsplit("::").next().unwrap_or("").to_string();
        let mut scored: Vec<(usize, &String)> = paths.iter().map(|p| {
            let pl = p.rsplit("::").next().unwrap_or("");
            (if pl == last { 0 } else { 1 + levenshtein(&want, p).min(levenshtein(&last, pl) * 2) }, p)
        }).collect();
        scored.sort();
        let close: Vec<String> = scored.into_iter().filter(|(d, _)| *d <= 8).take(3).map(|(_, p)| p.clone()).collect();
        out.push((o.clone(), close));
    }
    out
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + usize::from(a[i - 1] != b[j - 1]));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// The enumeration of a crate (before the global cap).
struct Enumeration {
    all: Vec<Mutant>,
    /// Mutants before the per-item cap.
    total: usize,
    excluded: Vec<(String, String)>,
    capped: Vec<(String, usize, usize)>,
    /// Spec items outside the scope (proof internals), not mutated.
    internal: Vec<String>,
}

/// Every mutant of the crate, in item and node order (the per-item cap
/// applied; see the module docs). With a `scope` (gate mode: the review
/// surface, [`review_scope`]) only the spec items in it are mutated; the
/// others are listed in [`Enumeration::internal`].
fn enumerate(krate: &Crate, sm: &SourceMap, opts: &MutateOptions, rev: &HashMap<ItemId, BTreeSet<ItemId>>, scope: Option<&BTreeSet<ItemId>>) -> Enumeration {
    let hw = hardware(krate);
    let type_level = type_level_consts(krate, rev);
    let mut e = Enumeration { all: vec![], total: 0, excluded: vec![], capped: vec![], internal: vec![] };
    for it in &krate.items {
        let Some(target) = mutation_target(krate, it, &hw) else { continue };
        if target == Target::Impl && !opts.impl_mutants || target == Target::Spec && !opts.spec_mutants {
            continue;
        }
        let path = it.path.to_string();
        if !only_matches(&opts.only, &path) {
            continue;
        }
        // a proof internal: no locked statement depends on its definition
        if target == Target::Spec
            && let Some(sc) = scope
            && !sc.contains(&it.id)
        {
            if body_of(it).is_some() {
                e.internal.push(path);
            }
            continue;
        }
        if let Some(why) = type_level.get(&it.id) {
            e.excluded.push((path, why.clone()));
            continue;
        }
        let Some((body, ret)) = body_of(it) else { continue };
        let mut sites = ops::sites(body, ret);
        e.total += sites.len();
        // per-item cap: deterministic sample by a stable hash
        if sites.len() > opts.max_per_item {
            let mut keyed: Vec<(u64, usize)> = sites.iter().enumerate().map(|(i, s)| (eval::hash_str(&format!("{path}#{}#{:?}", s.node, s.op)) ^ opts.seed, i)).collect();
            keyed.sort();
            let mut keep: Vec<usize> = keyed.into_iter().take(opts.max_per_item).map(|(_, i)| i).collect();
            // the return-value mutants (`λ_. false`) are always kept
            for (i, s) in sites.iter().enumerate() {
                if matches!(s.op, ops::Op::Return(_)) && !keep.contains(&i) {
                    keep.push(i);
                }
            }
            keep.sort();
            e.capped.push((path.clone(), keep.len(), sites.len()));
            sites = keep.into_iter().map(|i| sites[i].clone()).collect();
        }
        item_mutants(it, target, sm, sites, &mut e.all);
    }
    e
}

/// Every mutant of the crate (no cap; for tools and tests).
pub fn enumerate_mutants(krate: &Crate, sm: &SourceMap, opts: &MutateOptions) -> Vec<Mutant> {
    let rev = clone::reverse_refs(krate);
    enumerate(krate, sm, &MutateOptions { max_per_item: usize::MAX, ..opts.clone() }, &rev, None).all
}

/// The global sample: round-robin over the mutated items (each item's
/// return-value mutants first, then by a stable hash), in enumeration
/// order.
fn sample(all: &[Mutant], max: usize, seed: u64) -> Vec<usize> {
    if all.len() <= max {
        return (0..all.len()).collect();
    }
    let mut groups: Vec<(ItemId, Vec<usize>)> = Vec::new();
    for (i, m) in all.iter().enumerate() {
        match groups.last_mut() {
            Some((id, g)) if *id == m.item => g.push(i),
            _ => groups.push((m.item, vec![i])),
        }
    }
    for (_, g) in &mut groups {
        g.sort_by_key(|i| {
            let m = &all[*i];
            (!matches!(m.site.op, ops::Op::Return(_)), eval::hash_str(&format!("{}#{}#{:?}", m.path, m.site.node, m.site.op)) ^ seed)
        });
    }
    let mut keep = Vec::new();
    let mut round = 0;
    while keep.len() < max {
        let mut any = false;
        for (_, g) in &groups {
            if let Some(i) = g.get(round) {
                any = true;
                if keep.len() < max {
                    keep.push(*i);
                }
            }
        }
        if !any {
            break;
        }
        round += 1;
    }
    keep.sort();
    keep
}

/// Where a mutant's effect is looked for.
#[derive(Clone, Debug)]
struct Obs {
    x: ItemId,
    /// The unspecified dependency a difference at `x` is reported against.
    via: Option<ItemId>,
}

/// One mutant's plan: its re-verification set and observation points.
struct Plan {
    mutant: usize,
    closure: BTreeSet<ItemId>,
    /// Functions whose original and mutated versions are compared.
    obs: Vec<Obs>,
    /// Why there is no observation point.
    no_obs: Option<String>,
    /// Spec mutants: known-answer spec functions that use the mutated one,
    /// nearest first.
    suggest: Vec<ItemId>,
    /// Every function that may be compared (requires checkers are built).
    compared: BTreeSet<ItemId>,
    /// Gate mode, spec mutants: the known answers that may kill it, in the
    /// order they are tried (see [`example_slots`]).
    slots: Vec<ExSlot>,
}

/// One known answer of a spec mutant's closure: an `#[example]` or a whole
/// vector file of a spec function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExSlot {
    item: ItemId,
    file: bool,
    index: usize,
}

/// Gate mode: the slot after which the distinguishing search runs — the
/// first vector file (the smallest), or the last `#[example]` when there
/// is no vector file. A survivor without a distinguishing input passes the
/// gate whether or not a known answer would also kill it, so the larger
/// vector files after that slot run only for a mutant with a witness (or
/// an undecided known answer) to overturn.
fn search_slot(slots: &[ExSlot]) -> usize {
    let n_attr = slots.iter().take_while(|x| !x.file).count();
    if n_attr < slots.len() { n_attr } else { n_attr.saturating_sub(1) }
}

/// The known answers a spec mutant of `root` can be killed by (the
/// examples and vector files of the spec functions of its closure), in the
/// order gate mode tries them, one per elaboration, stopping at the first
/// kill: `#[example]`s before vector files; `#[example]`s nearer the
/// mutated item (in the call graph of the closure) first; vector files by
/// size (smallest first); then item and position order.
fn example_slots(krate: &Crate, rev: &HashMap<ItemId, BTreeSet<ItemId>>, root: ItemId, closure: &BTreeSet<ItemId>) -> Vec<ExSlot> {
    // distance from the mutated item through its users
    let mut dist: BTreeMap<ItemId, usize> = BTreeMap::from([(root, 0)]);
    let mut frontier = vec![root];
    let mut d = 0;
    while !frontier.is_empty() {
        d += 1;
        let mut next = Vec::new();
        for x in frontier {
            for r in rev.get(&x).into_iter().flatten() {
                if closure.contains(r) && !dist.contains_key(r) {
                    dist.insert(*r, d);
                    next.push(*r);
                }
            }
        }
        frontier = next;
    }
    let mut out: Vec<(bool, usize, usize, ItemId, usize)> = Vec::new();
    for x in closure {
        let Some(f) = krate.fn_def(*x) else { continue };
        if !gate_cloned(krate, *x) {
            continue;
        }
        let dx = dist.get(x).copied().unwrap_or(usize::MAX);
        out.extend((0..f.spec.examples.len()).map(|i| (false, dx, 0, *x, i)));
        out.extend(f.spec.example_files.iter().enumerate().map(|(i, ef)| (true, 0, ef.text.len(), *x, i)));
    }
    out.sort();
    out.into_iter().map(|(file, _, _, item, index)| ExSlot { item, file, index }).collect()
}

fn evaluable(krate: &Crate, id: ItemId) -> bool {
    krate.fn_def(id).is_some_and(|f| f.generics.is_empty() && f.params.iter().all(|p| !p.ghost))
}

fn plan(krate: &Crate, rev: &HashMap<ItemId, BTreeSet<ItemId>>, base: &Baseline, m: &Mutant, cap: usize) -> Result<Plan, String> {
    let closure = clone::closure(krate, rev, m.item, m.target, cap).ok_or_else(|| format!("its re-verification set exceeds {cap} items"))?;
    let mut suggest = Vec::new();
    let (obs, no_obs) = match m.target {
        Target::Spec => {
            let obs = if matches!(krate.item(m.item).kind, ItemKind::Const(_)) || evaluable(krate, m.item) { vec![Obs { x: m.item, via: None }] } else { vec![] };
            let why = obs.is_empty().then(|| "the spec function is generic or has ghost parameters".to_string());
            if !base.known_answers.contains(&m.item) {
                // breadth first through the spec functions that use it
                let mut frontier = vec![m.item];
                let mut seen: BTreeSet<ItemId> = BTreeSet::from([m.item]);
                while !frontier.is_empty() && suggest.len() < 3 {
                    let mut next = Vec::new();
                    for x in frontier {
                        for r in rev.get(&x).into_iter().flatten() {
                            if closure.contains(r) && krate.fn_def(*r).is_some_and(|f| f.kind == FnKind::Spec) && seen.insert(*r) {
                                if base.known_answers.contains(r) && evaluable(krate, *r) && suggest.len() < 3 {
                                    suggest.push(*r);
                                }
                                next.push(*r);
                            }
                        }
                    }
                    frontier = next;
                }
            }
            (obs, why)
        }
        Target::Impl => {
            let mut obs = Vec::new();
            let mut determined_seen = false;
            let mut unevaluable = Vec::new();
            let mut cands: Vec<ItemId> = vec![m.item];
            cands.extend(closure.iter().copied().filter(|x| *x != m.item && krate.fn_def(*x).is_some_and(|f| f.kind == FnKind::Exec)));
            for x in cands {
                if krate.fn_def(x).is_none_or(|f| f.kind != FnKind::Exec) {
                    continue;
                }
                if base.determined.contains(&x) {
                    determined_seen = true;
                    continue;
                }
                let Some(pi) = base.published.get(&x) else { continue };
                let via = if pi.proven {
                    // proven: only relative to an unspecified dependency
                    // the mutant changes can a difference show here
                    match pi.status {
                        SectionStatus::NotWellFounded => pi.unspecified.iter().copied().find(|d| *d == m.item || closure.contains(d)),
                        _ => None,
                    }
                } else {
                    None
                };
                if pi.proven && via.is_none() {
                    determined_seen = true;
                } else if evaluable(krate, x) {
                    obs.push(Obs { x, via });
                } else {
                    unevaluable.push(x);
                }
            }
            let why = if obs.is_empty() {
                Some(if !unevaluable.is_empty() {
                    format!("the functions a difference would show at ({}) are generic or have ghost parameters: not evaluated", unevaluable.iter().map(|x| format!("`{}`", krate.item(*x).path)).collect::<Vec<_>>().join(", "))
                } else if determined_seen {
                    "every function the specification must determine that uses it is determined (a proven refinement or completeness statement): the surviving mutant is equivalent where it is observable".to_string()
                } else {
                    "no function the specification must determine uses it (not exported, and in no section)".to_string()
                })
            } else {
                None
            };
            (obs, why)
        }
    };
    let mut compared: BTreeSet<ItemId> = obs.iter().map(|o| o.x).collect();
    compared.extend(suggest.iter().copied());
    if m.target == Target::Impl {
        compared.extend(closure.iter().copied().filter(|x| base.established.contains(x)));
    }
    let slots = if m.target == Target::Spec { example_slots(krate, rev, m.item, &closure) } else { vec![] };
    Ok(Plan { mutant: m.id, closure, obs, no_obs, suggest, compared, slots })
}

/// A mutant's items in its batch.
struct BatchMutant {
    plan_index: usize,
    /// original → clone.
    map: HashMap<ItemId, ItemId>,
    /// `(law, law clone, checker)`.
    law_checkers: Vec<(ItemId, ItemId, ItemId)>,
    /// Requires checkers by function (originals and clones).
    req_checkers: HashMap<ItemId, ItemId>,
}

fn synthetic_item(krate: &Crate, like: ItemId, id: ItemId, suffix: &str, f: FnDef) -> Item {
    let it = krate.item(like);
    Item { id, name: format!("{}{suffix}", it.name), path: clone::clone_path(&it.path, suffix), module: it.module, vis: Vis::Private, ghost: true, span: it.span, docs: vec![], allow: vec![], cfg: None, kind: ItemKind::Fn(f) }
}

/// The extended crate of a batch (see [`clone`]).
fn build_batch(krate: &Crate, plans: &[Plan], idx: &[usize], mutants: &[Mutant]) -> (Crate, Vec<BatchMutant>) {
    let mut k = krate.clone();
    let mut bms = Vec::new();
    let mut orig_req: HashMap<ItemId, ItemId> = HashMap::new();
    for &pi in idx {
        let p = &plans[pi];
        let m = &mutants[p.mutant];
        let suffix = format!("__mut{}", m.id);
        let mut map = HashMap::new();
        let base_id = k.items.len() as u32;
        for (j, orig) in p.closure.iter().enumerate() {
            map.insert(*orig, ItemId(base_id + j as u32));
        }
        for orig in &p.closure {
            let mut it = clone::clone_item(krate, *orig, map[orig], &suffix, &map);
            if *orig == m.item
                && let Some((body, ret)) = body_of_mut(&mut it)
            {
                ops::apply(body, &m.site, ret.as_ref());
                if let ItemKind::Const(c) = &mut it.kind {
                    c.value = match &c.init.kind {
                        ExprKind::Lit(Lit::Int(n)) => Some(*n),
                        _ => None,
                    };
                }
            }
            k.items.push(it);
        }
        let mut law_checkers = Vec::new();
        for orig in &p.closure {
            let cl = map[orig];
            if let ItemKind::Fn(f) = &k.items[cl.0 as usize].kind
                && f.kind == FnKind::Law
                && let Some(chk) = clone::law_checker(f)
            {
                let id = ItemId(k.items.len() as u32);
                let item = synthetic_item(&k, cl, id, "__chk", chk);
                k.items.push(item);
                law_checkers.push((*orig, cl, id));
            }
        }
        let mut req_checkers = HashMap::new();
        for x in &p.compared {
            let Some(f) = krate.fn_def(*x) else { continue };
            if f.requires.is_empty() {
                continue;
            }
            let orig_chk = match orig_req.get(x) {
                Some(c) => Some(*c),
                None => clone::requires_checker(f).map(|chk| {
                    let id = ItemId(k.items.len() as u32);
                    let item = synthetic_item(krate, *x, id, "__req", chk);
                    k.items.push(item);
                    orig_req.insert(*x, id);
                    id
                }),
            };
            if let Some(c) = orig_chk {
                req_checkers.insert(*x, c);
            }
            let Some(&cl) = map.get(x) else { continue };
            if let ItemKind::Fn(cf) = &k.items[cl.0 as usize].kind
                && let Some(chk) = clone::requires_checker(cf)
            {
                let id = ItemId(k.items.len() as u32);
                let item = synthetic_item(&k, cl, id, "__req", chk);
                k.items.push(item);
                req_checkers.insert(cl, id);
            }
        }
        bms.push(BatchMutant { plan_index: pi, map, law_checkers, req_checkers });
    }
    (k, bms)
}

/// Obligation kinds that belong to the specification (the rest are the
/// code's own: safety, termination, proof annotations).
fn spec_kind(k: &ObligationKind) -> bool {
    matches!(k, ObligationKind::Ensures | ObligationKind::LawGoal | ObligationKind::Refines | ObligationKind::Example | ObligationKind::TypeInvariant | ObligationKind::ViewInjective | ObligationKind::Completeness)
}

/// A failure whose search was stopped by a limit (the step budget or a
/// safety net) rather than finished.
fn budget_limited(tried: &[String]) -> bool {
    tried.iter().any(|t| t.contains("budget exhausted") || t.contains("deadline exceeded") || t.contains("memory soft limit") || t.contains("heap cap") || t.contains("too large for proof search") || t.contains("not tried"))
}

/// Where a failure is, for the classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Src {
    /// The mutated item's own safety obligations.
    OwnSafety,
    /// The mutated item's own `ensures` / invariants.
    OwnSpec,
    /// A spec function or spec constant that uses the mutated item (its
    /// well-formedness: `Nat` bounds, `requires` of callees, …).
    DepSafety,
    /// Code that uses the mutated item (callers' safety).
    OtherSafety,
    /// A law (or its proof item): the original law.
    Law(ItemId),
    /// A refinement of an exec function: the original function.
    Refines(ItemId),
    /// A lemma or another proof item.
    Proof,
    /// An example or vector record that evaluated to `false`.
    Example,
    /// Other specification obligations (`ensures` of callers, invariants).
    Spec,
}

struct Fail {
    what: String,
    src: Src,
    /// Budget-limited (or not decided: an evaluation error).
    lim: bool,
}

/// What failed in a mutant's clones, the consequences of other failures
/// left out (see the module docs).
#[derive(Default)]
struct Failures {
    list: Vec<Fail>,
    /// The mutated item could not be elaborated.
    invalid: Option<String>,
    /// Failures left out as consequences of another clone's failure.
    consequences: usize,
    /// Refinements of implementations that failed (spec mutants: notes).
    refines_failed: Vec<String>,
    /// Every law (original) whose clone did not verify, consequences
    /// included: their checkers are evaluated when they reach no
    /// placeholder.
    all_failed_laws: BTreeSet<ItemId>,
}

impl Failures {
    fn whats(&self, lim: bool, pred: impl Fn(Src) -> bool) -> Vec<String> {
        self.list.iter().filter(|f| f.lim == lim && pred(f.src)).map(|f| f.what.clone()).collect()
    }
    fn laws(&self, lim: Option<bool>) -> BTreeSet<ItemId> {
        self.list.iter().filter(|f| lim.is_none_or(|l| f.lim == l)).filter_map(|f| if let Src::Law(l) = f.src { Some(l) } else { None }).collect()
    }
    fn refines(&self, lim: Option<bool>) -> BTreeSet<ItemId> {
        self.list.iter().filter(|f| lim.is_none_or(|l| f.lim == l)).filter_map(|f| if let Src::Refines(x) = f.src { Some(x) } else { None }).collect()
    }
    fn push(&mut self, what: String, src: Src, lim: bool) {
        if !self.list.iter().any(|f| f.what == what && f.src == src) {
            self.list.push(Fail { what, src, lim });
        }
    }
}

/// The owner kind of a clone.
enum Owner {
    Law(ItemId),
    Refines(ItemId),
    Proof,
    Exec,
    SpecFn,
}

fn collect_failures(out: &elab::Output, bk: &Crate, bm: &BatchMutant, root: ItemId, clone_of: &HashMap<ItemId, ItemId>) -> Failures {
    let mut f = Failures::default();
    let clones: BTreeSet<ItemId> = bm.map.values().copied().collect();
    let root_clone = bm.map[&root];
    let mut names: HashMap<String, ItemId> = HashMap::new();
    for c in &clones {
        names.insert(bk.item(*c).path.to_string(), *c);
    }
    let orig = |c: ItemId| clone_of.get(&c).copied().unwrap_or(c);
    let orig_path = |c: ItemId| bk.item(orig(c)).path.to_string();
    let is_exec = |c: ItemId| bk.fn_def(c).is_some_and(|x| x.kind == FnKind::Exec) || matches!(bk.item(c).kind, ItemKind::Const(_)) && !bk.item(c).ghost;
    let owner = |c: ItemId| -> Owner {
        match &bk.item(c).kind {
            ItemKind::Fn(x) if x.kind == FnKind::Law => Owner::Law(orig(c)),
            ItemKind::Fn(x) if x.kind == FnKind::Proof => match (x.proves, x.spec.proof_of) {
                (Some(l), _) => Owner::Law(orig(l)),
                (_, Some(po)) if po.kind == ProofKind::Refines => Owner::Refines(orig(po.target)),
                _ => Owner::Proof,
            },
            ItemKind::Fn(x) if x.kind == FnKind::Lemma => Owner::Proof,
            _ if is_exec(c) => Owner::Exec,
            _ => Owner::SpecFn,
        }
    };
    // the clones that did not verify (placeholders or not elaborated)
    let failed: BTreeSet<ItemId> = out.defs.iter().filter(|d| d.item.is_some_and(|i| clones.contains(&i)) && d.name == bk.item(d.item.unwrap()).path.to_string() && !matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))).filter_map(|d| d.item).collect();
    // reachability among the clones
    let direct: HashMap<ItemId, BTreeSet<ItemId>> = clones.iter().map(|c| (*c, elab::order::refs(bk, *c).into_iter().filter(|r| clones.contains(r) && r != c).collect())).collect();
    let reach = |c: ItemId| -> BTreeSet<ItemId> {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<ItemId> = direct.get(&c).into_iter().flatten().copied().collect();
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                stack.extend(direct.get(&x).into_iter().flatten().copied());
            }
        }
        seen
    };
    let reaches: HashMap<ItemId, BTreeSet<ItemId>> = clones.iter().map(|c| (*c, reach(*c))).collect();
    // `c` depends on a clone that failed (strictly upstream of it)
    let consequence = |c: ItemId| failed.iter().any(|d| *d != c && reaches[&c].contains(d) && !reaches.get(d).is_some_and(|r| r.contains(&c)));
    for o in &out.obligations {
        let tried = match &o.status {
            OblStatus::Proven { .. } => continue,
            OblStatus::Failed(fl) => fl.tried.clone(),
            OblStatus::Todo => vec![],
        };
        let Some(c) = obligation_owner(&names, &o.def) else { continue };
        if consequence(c) {
            f.consequences += 1;
            continue;
        }
        let lim = budget_limited(&tried);
        let kind = elab::obl::kind_name(&o.kind);
        let mut what = format!("[{kind}] in `{}`", o.def.replace(&bk.item(c).path.to_string(), &orig_path(c)));
        // a budget-limited failure names the limit that stopped it
        if lim && let Some(t) = tried.iter().find(|t| budget_limited(std::slice::from_ref(*t))) {
            what.push_str(&format!(" ({t})"));
        }
        let src = if c == root_clone {
            match o.kind {
                ObligationKind::Refines => Src::Refines(orig(c)),
                ObligationKind::Example => Src::Spec,
                _ if spec_kind(&o.kind) => Src::OwnSpec,
                _ => Src::OwnSafety,
            }
        } else {
            match owner(c) {
                Owner::Law(l) => Src::Law(l),
                Owner::Refines(x) => Src::Refines(x),
                Owner::Proof => Src::Proof,
                Owner::Exec if o.kind == ObligationKind::Refines => Src::Refines(orig(c)),
                Owner::Exec if spec_kind(&o.kind) => Src::Spec,
                Owner::Exec => Src::OtherSafety,
                Owner::SpecFn if spec_kind(&o.kind) => Src::Spec,
                Owner::SpecFn => Src::DepSafety,
            }
        };
        f.push(what, src, lim);
    }
    for d in &out.defs {
        let Some(item) = d.item else { continue };
        if !clones.contains(&item) {
            continue;
        }
        match &d.status {
            DefStatus::Rejected(m) | DefStatus::Unsupported(m) if item == root_clone && d.name == bk.item(item).path.to_string() => {
                f.invalid = Some(m.chars().take(300).collect());
            }
            DefStatus::Rejected(m) | DefStatus::Unsupported(m) => {
                if consequence(item) {
                    f.consequences += 1;
                    continue;
                }
                // a dependent that cannot be elaborated any more (e.g. a
                // proof term no longer fits)
                let what = format!("`{}` could not be re-elaborated: {}", orig_path(item), m.chars().take(160).collect::<String>());
                let src = match owner(item) {
                    Owner::Law(l) => Src::Law(l),
                    Owner::Refines(x) => Src::Refines(x),
                    Owner::Proof => Src::Proof,
                    Owner::Exec => Src::OtherSafety,
                    Owner::SpecFn => Src::DepSafety,
                };
                f.push(what, src, false);
            }
            _ => {}
        }
    }
    for r in &out.refinements {
        if !clones.contains(&r.item) || r.status == DefStatus::Checked {
            continue;
        }
        let what = format!("the refinement `{}` refines `{}`", orig_path(r.item), orig_path(r.spec));
        // a blocked refinement is a consequence of the failure it reached
        if matches!(r.status, DefStatus::Blocked(_)) || consequence(r.item) {
            f.consequences += 1;
            continue;
        }
        f.refines_failed.push(what.clone());
        if !f.list.iter().any(|x| x.src == Src::Refines(orig(r.item))) {
            f.push(what, Src::Refines(orig(r.item)), false);
        }
    }
    for e in &out.examples {
        if !clones.contains(&e.item) || e.status == DefStatus::Checked {
            continue;
        }
        if matches!(e.status, DefStatus::Blocked(_)) {
            f.consequences += 1;
            continue;
        }
        let which = match e.source {
            elab::examples::ExampleSource::Attr { index } => format!("example #{index}"),
            elab::examples::ExampleSource::File { record, .. } => format!("vector record #{record}"),
        };
        let first = e.detail.lines().next().unwrap_or("");
        // a closed evaluation gave `false` (`evaluates to …`, or both sides
        // of `l == r`: `left: …; right: …`): definite; an obligation of the
        // example failed: its obligation record says how; an evaluation
        // error, an exhausted budget or a rejected lemma: not decided
        if first.starts_with("an obligation of") {
            continue;
        }
        // (vector records say `is false`, `#[example]`s `evaluates to …` or
        // `left: …; right: …`)
        let definite = e.status == DefStatus::Unproven && (first.starts_with("evaluates to") || first.starts_with("left: ") || first == "is false");
        f.push(format!("{which} of `{}`: {first}", orig_path(e.item)), Src::Example, !definite);
    }
    for l in &out.laws {
        if !clones.contains(&l.item) || l.status == DefStatus::Checked {
            continue;
        }
        f.all_failed_laws.insert(orig(l.item));
        if matches!(l.status, DefStatus::Blocked(_)) || consequence(l.item) {
            f.consequences += 1;
            continue;
        }
        let law = orig(l.item);
        if !f.list.iter().any(|x| x.src == Src::Law(law)) {
            f.push(format!("law `{}`: {}", orig_path(l.item), crate::driver::def_status_str(&l.status)), Src::Law(law), false);
        }
    }
    f
}

/// The evaluation context of one batch: what may be evaluated (never a
/// placeholder, nor anything that reaches one).
struct Ev<'a> {
    out: &'a elab::Output,
    bk: &'a Crate,
    krate: &'a Crate,
    opts: &'a MutateOptions,
    placeholders: HashSet<GlobalId>,
    clean: RefCell<HashMap<GlobalId, bool>>,
}

/// A distinguishing input found (before printing).
struct Found {
    w: Witness,
    tms: Vec<sandblaster_kernel::term::Tm>,
}

impl<'a> Ev<'a> {
    fn new(out: &'a elab::Output, bk: &'a Crate, krate: &'a Crate, opts: &'a MutateOptions) -> Ev<'a> {
        let placeholders = out.defs.iter().filter(|d| !matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))).filter_map(|d| d.global).collect();
        Ev { out, bk, krate, opts, placeholders, clean: RefCell::new(HashMap::new()) }
    }

    fn evaluator(&self) -> eval::Evaluator<'_> {
        eval::Evaluator { env: &self.out.env, krate: self.bk, adts: &self.out.adts, budget: self.opts.eval_budget }
    }

    /// `g` is a checked definition that reaches no placeholder: evaluating
    /// it evaluates the code, not a default body.
    fn clean(&self, g: GlobalId) -> bool {
        if let Some(c) = self.clean.borrow().get(&g) {
            return *c;
        }
        let checked = self.out.defs.iter().any(|d| d.global == Some(g) && d.status == DefStatus::Checked);
        let c = checked && !self.placeholders.contains(&g) && !self.out.env.refs_closure(&sandblaster_kernel::util::mk::global(g), &[]).iter().any(|r| self.placeholders.contains(r));
        self.clean.borrow_mut().insert(g, c);
        c
    }

    /// Searches (and shrinks) a distinguishing input between function `x`
    /// of the original crate and its clone.
    fn distinguish(&self, x: ItemId, bm: &BatchMutant, m: &Mutant, tried: &mut usize) -> Option<Found> {
        let cl = *bm.map.get(&x)?;
        let g0 = *self.out.fn_globals.get(&x)?;
        let g1 = *self.out.fn_globals.get(&cl)?;
        if !self.clean(g0) || !self.clean(g1) {
            return None;
        }
        let krate = self.krate;
        let ev = self.evaluator();
        let ret = match &krate.item(x).kind {
            ItemKind::Fn(f) => f.ret.clone(),
            ItemKind::Const(c) => c.ty.clone(),
            _ => return None,
        };
        let (params, ins) = inputs_for(krate, x, m, self.opts);
        let req0 = bm.req_checkers.get(&x).and_then(|c| self.out.fn_globals.get(c)).copied();
        let req1 = bm.req_checkers.get(&cl).and_then(|c| self.out.fn_globals.get(c)).copied();
        let has_req = krate.fn_def(x).is_some_and(|f| !f.requires.is_empty());
        if has_req && !(req0.is_some_and(|g| self.clean(g)) && req1.is_some_and(|g| self.clean(g))) {
            return None;
        }
        // `Some((original, mutant, v0, v1, method))` when `args` distinguish
        let differs = |args: &[eval::Val]| {
            let tms: Vec<_> = params.iter().zip(args).map(|(t, v)| ev.term(t, v).ok()).collect::<Option<_>>()?;
            if let (Some(r0), Some(r1)) = (req0, req1) {
                let ok = |g| ev.call(g, &tms).ok().and_then(|(v, _)| ev.as_bool(&v)) == Some(true);
                if !ok(r0) || !ok(r1) {
                    return None;
                }
            }
            let (v0, m0) = ev.call(g0, &tms).ok()?;
            let (v1, m1) = ev.call(g1, &tms).ok()?;
            let (s0, s1) = (ev.show(&ret, &v0).ok()?, ev.show(&ret, &v1).ok()?);
            (s0 != s1).then(|| {
                let method = if m0 == eval::Method::Kernel && m1 == eval::Method::Kernel { eval::Method::Kernel } else { eval::Method::Reference };
                (s0, s1, v0, v1, method, tms)
            })
        };
        let mut found = None;
        for args in ins {
            *tried += 1;
            if let Some(d) = differs(&args) {
                found = Some((args, d));
                break;
            }
        }
        let (mut args, mut d) = found?;
        // shrink: each argument (and element) towards zero, sequences
        // shorter, while the difference persists
        let mut budget = self.opts.shrink;
        'outer: while budget > 0 {
            // every argument halved at once (bit-aligned differences), then
            // one argument at a time; a struct with an invariant is kept
            let half: Vec<eval::Val> = args.iter().zip(&params).map(|(v, t)| if has_invariant(krate, t) { v.clone() } else { eval::halved(v) }).collect();
            if half != args {
                budget -= 1;
                if let Some(nd) = differs(&half) {
                    args = half;
                    d = nd;
                    continue 'outer;
                }
            }
            for i in 0..args.len() {
                for cand in eval::simpler(krate, &params[i], &args[i]) {
                    if budget == 0 {
                        break 'outer;
                    }
                    budget -= 1;
                    let mut t = args.clone();
                    t[i] = cand;
                    if let Some(nd) = differs(&t) {
                        args = t;
                        d = nd;
                        continue 'outer;
                    }
                }
            }
            break;
        }
        let (s0, s1, v0, v1, method, tms) = d;
        let input = format!("({})", params.iter().zip(&args).map(|(t, v)| eval::show_val(krate, t, v)).collect::<Vec<_>>().join(", "));
        let differs_at = ev.differences(&ret, &v0, &v1, 8);
        Some(Found { w: Witness { function: krate.item(x).path.to_string(), item: x, input, original: s0, mutant: s1, differs_at, evaluator: method.word().to_string(), section: None, dependency: None, refutation: None }, tms })
    }

    /// Definite counterexamples to the given (original) laws under the
    /// mutant: their checkers evaluate to `false`. `(law, input)`.
    fn refute_laws(&self, bm: &BatchMutant, laws: &BTreeSet<ItemId>, m: &Mutant) -> Vec<(ItemId, String)> {
        let ev = self.evaluator();
        let mut found = Vec::new();
        for (law, _cl, chk) in &bm.law_checkers {
            if !laws.contains(law) {
                continue;
            }
            let Some(g) = self.out.fn_globals.get(chk).copied() else { continue };
            if !self.clean(g) {
                continue;
            }
            let (params, ins) = inputs_for(self.krate, *law, m, self.opts);
            for args in ins {
                let tms: Option<Vec<_>> = params.iter().zip(&args).map(|(t, v)| ev.term(t, v).ok()).collect();
                let Some(tms) = tms else { continue };
                if let Ok((v, _)) = ev.call(g, &tms)
                    && ev.as_bool(&v) == Some(false)
                {
                    let input = format!("({})", params.iter().zip(&args).map(|(t, v)| eval::show_val(self.krate, t, v)).collect::<Vec<_>>().join(", "));
                    found.push((*law, input));
                    break;
                }
            }
        }
        found
    }

    /// Definite counterexamples to failed refinements: the function is
    /// established by its refinement (an injective view, no domain), so the
    /// refinement holds for the mutant only where it agrees with the
    /// original. `(function, readable)`.
    fn refute_refines(&self, bm: &BatchMutant, fns: &BTreeSet<ItemId>, m: &Mutant, base: &Baseline) -> Vec<(ItemId, String)> {
        let mut out = Vec::new();
        for x in fns {
            if !base.established.contains(x) {
                continue;
            }
            let mut tried = 0;
            if let Some(Found { w, .. }) = self.distinguish(*x, bm, m, &mut tried) {
                let spec = self.krate.fn_def(*x).and_then(|f| f.spec.refines.as_ref()).map(|r| self.krate.item(r.spec).path.to_string()).unwrap_or_default();
                out.push((*x, format!("the refinement `{}` refines `{spec}` is false for the mutant at {}: the specification gives {} (through `{}`, which it determines), the mutant returns {}", w.function, w.input, w.original, w.function, w.mutant)));
            }
        }
        out
    }
}

/// A type that contains a struct with an invariant (its values are not
/// shrunk jointly: halving could break the invariant).
fn has_invariant(krate: &Crate, t: &Ty) -> bool {
    fn go(krate: &Crate, t: &Ty, depth: u32) -> bool {
        if depth > 8 {
            return true;
        }
        match t.peel_refs() {
            Ty::Adt(id, args) => match &krate.item(*id).kind {
                ItemKind::Struct(s) => s.invariant.is_some() || s.fields.iter().any(|f| go(krate, &f.ty.subst(args), depth + 1)),
                ItemKind::Enum(e) => e.variants.iter().flat_map(|v| &v.fields).any(|f| go(krate, &f.ty.subst(args), depth + 1)),
                _ => true,
            },
            Ty::Tuple(ts) => ts.iter().any(|x| go(krate, x, depth + 1)),
            Ty::Array(e, _) | Ty::Slice(e) | Ty::Seq(e) | Ty::Option(e) => go(krate, e, depth + 1),
            _ => false,
        }
    }
    go(krate, t, 0)
}

/// Candidate inputs for function `x` of the original crate.
fn inputs_for(krate: &Crate, x: ItemId, m: &Mutant, opts: &MutateOptions) -> (Vec<Ty>, Vec<Vec<eval::Val>>) {
    let Some(f) = krate.fn_def(x) else { return (vec![], vec![vec![]]) };
    let params: Vec<Ty> = f.params.iter().filter(|p| !p.ghost).map(|p| p.ty.clone()).collect();
    let mut consts = BTreeSet::new();
    if let Some((body, _)) = body_of(krate.item(m.item)) {
        eval::literals(body, &mut consts);
    }
    if let Some((body, _)) = body_of(krate.item(x)) {
        eval::literals(body, &mut consts);
    }
    if let ops::Op::Lit { to, .. } = m.site.op {
        consts.insert(to);
    }
    let mut h = eval::Hints { consts, rng: eval::Rng(opts.seed ^ eval::hash_str(&format!("{}#{}", krate.item(x).path, m.id))) };
    let given = eval::example_calls(krate, x);
    let ins = eval::inputs(krate, &params, given, opts.inputs, &mut h);
    (params, ins)
}

/// The optional kernel-checked refutation of `complete_x(R)` for a
/// `bool`-valued published member `x` with a definite counterexample
/// (§15.9): `λ(c : complete_x(R)). ne (c F' h̄ x̄)` where `F'` is the
/// mutant (the other members unchanged), `h̄` the mutant's re-proven
/// hypotheses (the clones of the laws and contracts of `H(R)`), `x̄` the
/// distinguishing input, and `ne` is `bool::false_ne_true` or
/// `bool::true_ne_false` — checked by the kernel against
/// `complete_x(R) → Empty`. Built only when conversion evaluates both
/// applications (transparent functions without `requires`).
fn refute_complete(out: &elab::Output, bk: &Crate, bm: &BatchMutant, x: ItemId, args: &[sandblaster_kernel::term::Tm], w: &Witness) -> Result<String, String> {
    use sandblaster_kernel::term::{Lvl, Rel, Term};
    use sandblaster_kernel::util::mk;
    use sandblaster_kernel::value::{Budget, VEnv};
    let rec = out.sections.iter().find(|s| s.published.contains(&x)).ok_or("the function is published by no section of the batch")?;
    let st = rec.statements.iter().find(|c| c.item == x).ok_or("the section has no statement for the function")?;
    if st.status == DefStatus::Checked {
        return Err("its completeness statement is proven".into());
    }
    let env = &out.env;
    let clone_global = |id: ItemId| bm.map.get(&id).and_then(|c| out.fn_globals.get(c)).or_else(|| out.fn_globals.get(&id)).copied();
    let mut vals: Vec<sandblaster_kernel::term::Tm> = Vec::new();
    for m in &rec.members {
        vals.push(mk::global(clone_global(*m).ok_or_else(|| format!("no global for member `{}`", bk.item(*m).path))?));
    }
    for (kind, name) in &rec.hyps {
        let g = if kind == "law" {
            let id = bk.find(name).ok_or_else(|| format!("no law `{name}`"))?;
            clone_global(id)
        } else {
            let mut renamed = None;
            for m in &rec.members {
                let p = bk.item(*m).path.to_string();
                if let Some(rest) = name.strip_prefix(&p)
                    && rest.starts_with("::")
                    && let Some(c) = bm.map.get(m)
                {
                    renamed = env.lookup_global(&format!("{}{rest}", bk.item(*c).path));
                }
            }
            renamed.or_else(|| env.lookup_global(name))
        };
        vals.push(mk::global(g.ok_or_else(|| format!("no lemma for the hypothesis `{name}`"))?));
    }
    vals.extend(args.iter().cloned());
    let mut t = st.statement.clone();
    let mut app: Vec<(Rel, sandblaster_kernel::term::Tm)> = Vec::new();
    for v in vals {
        match &*t {
            Term::Pi { rel, cod, .. } => {
                app.push((*rel, v));
                t = cod.clone();
            }
            _ => return Err("the statement's telescope is shorter than expected".into()),
        }
    }
    if matches!(&*t, Term::Pi { .. }) {
        return Err("the function has `requires` (`Irr` binders): not attempted".into());
    }
    let ne = match (w.mutant.as_str(), w.original.as_str()) {
        ("false", "true") => "bool::false_ne_true",
        ("true", "false") => "bool::true_ne_false",
        _ => return Err("not a `bool` disagreement".into()),
    };
    let ne = env.lookup_global(ne).ok_or_else(|| format!("`{ne}` is not loaded"))?;
    let stmt = st.statement.clone();
    let term = mk::lam("c", Rel::Rel, stmt.clone(), mk::app(mk::global(ne), mk::apps(mk::var(0), app)));
    let ty = mk::pi("c", Rel::Rel, stmt, mk::ind(env.empty_ind(), vec![]));
    let mut b = Budget { steps: 200_000_000 };
    let tyv = env.eval(&VEnv::default(), Lvl(0), &ty, &mut b).map_err(|e| format!("{e:?}"))?;
    env.check(&sandblaster_kernel::api::Ctx::default(), &term, &tyv, &mut b).map_err(|e| format!("the kernel rejected the refutation: {}", e.message.lines().next().unwrap_or("")))?;
    Ok(format!("the kernel checked `λ(c : complete_{}(R)). {} (c {} …)` : `complete_{}(R) → Empty`", w.function, env.global_name(ne).map(|n| n.to_string()).unwrap_or_default(), w.input, w.function))
}

const TESTS_NOTE: &str = "not run: `cargo test` against the emitted code of each mutant needs one optimized emission and one rustc build per mutant (minutes each); the proof kill rates above are the mandatory measure (DESIGN.md §15.10 lists tests as optional)";

fn run_here(krate: &Crate, sm: &SourceMap, opts: &MutateOptions) -> MutationReport {
    let t0 = Instant::now();
    let mut rep = MutationReport { tests_note: TESTS_NOTE.into(), ..Default::default() };
    // the baseline: the unchanged crate
    let heap_before = crate::memguard::allocated();
    let base_growth;
    let (base, verified, problems) = {
        let mut chain = elab::ProverChain::standard();
        let out = elab::elaborate(krate, &mut chain, &opts.elab);
        base_growth = crate::memguard::allocated().saturating_sub(heap_before);
        let problems: Vec<String> = out.defs.iter().filter(|d| !matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))).map(|d| format!("`{}`: {}", d.name, crate::driver::def_status_str(&d.status))).take(20).collect();
        let verified = out.verified();
        rep.base = base_items(&out, krate);
        (baseline_of(&out, krate), verified, problems)
    };
    run_from(krate, sm, opts, verified, problems, base, base_growth, rep, t0, None, None)
}

/// The engine after the baseline (shared by [`run`] and [`run_gate`]);
/// `scope`: the spec items mutated (gate mode, [`review_scope`]), or every
/// spec item.
#[allow(clippy::too_many_arguments)]
fn run_from(krate: &Crate, sm: &SourceMap, opts: &MutateOptions, verified: bool, problems: Vec<String>, base: Baseline, base_growth: usize, mut rep: MutationReport, t0: Instant, vc: Option<&crate::driver::cache::VerdictCache>, scope: Option<&BTreeSet<ItemId>>) -> MutationReport {
    rep.baseline_verified = verified;
    rep.baseline_problems = problems;
    rep.unknown_only = unknown_only(krate, &opts.only);
    for (o, close) in &rep.unknown_only {
        rep.incomplete_reasons.push(format!("the `only` entry `{o}` names no function or constant of the crate{}", if close.is_empty() { String::new() } else { format!(" (closest: {})", close.iter().map(|c| format!("`{c}`")).collect::<Vec<_>>().join(", ")) }));
    }
    if !verified {
        rep.incomplete_reasons.push("the crate does not verify: the counterexample engine needs a verified baseline (every mutant is judged against it)".into());
        rep.elapsed = t0.elapsed();
        return rep;
    }
    let rev = clone::reverse_refs(krate);
    let en = enumerate(krate, sm, opts, &rev, scope);
    rep.enumerated = en.total;
    rep.excluded = en.excluded;
    rep.internal = en.internal;
    for (p, kept, of) in &en.capped {
        rep.incomplete_reasons.push(format!("{kept} of {of} mutants of `{p}` run (SANDBLASTER_MUTANTS_PER_ITEM = {}; a deterministic sample)", opts.max_per_item));
    }
    rep.capped = en.capped;
    let all = en.all;
    // global cap: round-robin over the items, in enumeration order
    let keep = sample(&all, opts.max_mutants, opts.seed);
    if keep.len() < all.len() {
        rep.incomplete_reasons.push(format!("{} of {} mutants run (SANDBLASTER_MUTANTS_MAX = {}; a deterministic sample, round-robin over the items)", keep.len(), rep.enumerated, opts.max_mutants));
        let kept_items: BTreeSet<ItemId> = keep.iter().map(|i| all[*i].item).collect();
        let mut ns: Vec<String> = Vec::new();
        for m in &all {
            if !kept_items.contains(&m.item) && ns.last() != Some(&m.path) {
                ns.push(m.path.clone());
            }
        }
        rep.not_sampled = ns;
    }
    let mutants: Vec<Mutant> = keep.into_iter().enumerate().map(|(i, k)| {
        let mut m = all[k].clone();
        m.id = i;
        m
    }).collect();
    let mut outcomes: Vec<Option<Outcome>> = vec![None; mutants.len()];
    let mut plans: Vec<Plan> = Vec::new();
    for m in &mutants {
        match plan(krate, &rev, &base, m, opts.max_closure) {
            Ok(p) => plans.push(p),
            Err(why) => outcomes[m.id] = Some(Outcome::new(Verdict::NotRun, vec![why])),
        }
    }
    // implementation mutants first, and never in one batch with spec
    // mutants: the clone of a law under a spec mutant mentions the original
    // exec functions, and when it fails it blocks their sections in that
    // batch's (unused) section records — which the optional refutation of
    // an implementation mutant reads
    plans.sort_by_key(|p| (mutants[p.mutant].target == Target::Spec, p.mutant));
    // law scopes for LR8
    let mut laws: BTreeMap<ItemId, LawSensitivity> = BTreeMap::new();
    // incremental spec mutation (gate mode, with a cache): the spec mutants
    // whose inputs did not change take their stored verdicts ([`cache`])
    let mut keys: HashMap<usize, String> = HashMap::new();
    let mut hits: Vec<(usize, Vec<(ItemId, cache::LawRecord)>)> = Vec::new();
    if let Some(vc) = vc.filter(|_| opts.gate) {
        let fps = cache::Fps::new(krate);
        let opts_text = {
            let mut o = opts.clone();
            o.progress = false;
            format!("{o:?}")
        };
        let paths: HashMap<String, ItemId> = krate.items.iter().map(|it| (it.path.to_string(), it.id)).collect();
        let mut rest = Vec::with_capacity(plans.len());
        for p in plans {
            let m = &mutants[p.mutant];
            if m.target != Target::Spec {
                rest.push(p);
                continue;
            }
            let key = cache::mutant_key(&vc.toolchain, &opts_text, &fps, m, &p);
            let hit = match vc.store.get(cache::NS, &key) {
                crate::driver::cache::Lookup::Hit(files) => files.iter().find(|(n, _)| n == "outcome").and_then(|(_, t)| cache::decode(t, &paths)),
                _ => None,
            };
            match hit {
                Some((mut o, lr)) => {
                    o.closure = p.closure.len();
                    outcomes[m.id] = Some(o);
                    hits.push((m.id, lr));
                }
                None => {
                    keys.insert(m.id, key);
                    rest.push(p);
                }
            }
        }
        plans = rest;
        rep.cache_hits = hits.len();
        rep.cache_misses = keys.len();
    }
    let (_, soft) = crate::memguard::limits();
    let mem_cap = (soft as f64 * opts.mem_fraction) as usize;
    let mut next = 0usize;
    let mut size = opts.batch.max(1);
    // gate mode: batches of fixed size on a few worker threads (each batch
    // is its own elaboration; verdicts are per mutant, so the result does
    // not depend on the scheduling)
    if opts.gate {
        run_parallel(krate, &plans, &mutants, opts, &base, mem_cap, &mut laws, &mut outcomes, &mut rep, t0);
        next = plans.len();
        rerun_alone(krate, &plans, &mutants, opts, &base, &mut laws, &mut outcomes, &mut rep);
    }
    while next < plans.len() {
        if opts.deadline.is_some_and(|d| t0.elapsed() > d) {
            for p in &plans[next..] {
                outcomes[p.mutant] = Some(Outcome::new(Verdict::NotRun, vec!["the run's time budget ran out before this mutant's batch".into()]));
            }
            rep.incomplete_reasons.push(format!("the run's wall-clock budget ran out ({} of {} mutant(s) not run)", plans.len() - next, mutants.len()));
            break;
        }
        if crate::memguard::allocated() > mem_cap {
            for p in &plans[next..] {
                outcomes[p.mutant] = Some(Outcome::new(Verdict::NotRun, vec!["memory: the heap is above the batch limit".into()]));
            }
            rep.incomplete_reasons.push(format!("memory: the heap exceeded {:.0}% of the memguard soft limit before a batch", opts.mem_fraction * 100.0));
            break;
        }
        let target = mutants[plans[next].mutant].target;
        let idx: Vec<usize> = (next..(next + size).min(plans.len())).take_while(|i| mutants[plans[*i].mutant].target == target).collect();
        next += idx.len();
        let tb = Instant::now();
        let heap0 = crate::memguard::allocated();
        let phase = if opts.gate && target == Target::Spec { Phase::Slot(0) } else { Phase::Full };
        let mut pending: Vec<usize> = Vec::new();
        let mut carry: HashMap<usize, GateCarry> = HashMap::new();
        let (mut items, heap, mut tripped) = run_batch(krate, &plans, &idx, &mutants, opts, &base, &mut laws, &mut outcomes, phase, &mut pending, &mut carry);
        // gate mode: the next known answer, for the mutants still alive
        let mut slot = 0;
        while !pending.is_empty() {
            slot += 1;
            let alive = std::mem::take(&mut pending);
            let (i2, _, t2) = run_batch(krate, &plans, &alive, &mutants, opts, &base, &mut laws, &mut outcomes, Phase::Slot(slot), &mut pending, &mut carry);
            items += i2;
            tripped.extend(t2);
        }
        if opts.progress && opts.gate {
            eprintln!("sandblaster mutation gate: batch of {} ({:?}): {} item(s) in {} elaboration(s), {:.2} s", idx.len(), target, items, slot + 1, tb.elapsed().as_secs_f64());
        }
        rep.batches.push(BatchStat { mutants: idx.len(), items, elapsed: tb.elapsed(), heap });
        if !tripped.is_empty() {
            rep.incomplete_reasons.push(format!("a resource safety net tripped in a batch ({})", tripped.iter().map(|t| t.note.clone()).take(2).collect::<Vec<_>>().join("; ")));
        }
        // memory-aware batch size: the next batch's growth must stay under
        // the cap
        let per = heap.saturating_sub(heap0).saturating_sub(base_growth) / idx.len().max(1);
        let room = mem_cap.saturating_sub(heap0 + base_growth);
        if let Some(n) = room.checked_div(per) {
            size = n.clamp(1, opts.batch.max(1));
        }
        if opts.progress {
            let done = next;
            let elapsed = t0.elapsed().as_secs_f64();
            let per_mutant = elapsed / done.max(1) as f64;
            let left = plans.len() - done;
            eprintln!(
                "sandblaster coverage: batch {} ({} of {} mutant(s) decided, about {} batch(es) left): {:.0} s elapsed, ETA {:.0} s, heap {} MiB",
                rep.batches.len(),
                done,
                plans.len(),
                left.div_ceil(size.max(1)),
                elapsed,
                per_mutant * left as f64,
                heap >> 20
            );
        }
    }
    // the cache: the LR8 records of the hits, then store the decided
    // verdicts of this run
    if let Some(vc) = vc.filter(|_| opts.gate) {
        for (mid, lr) in &hits {
            for (law, (path, killed, evaluable)) in lr {
                let e = laws.entry(*law).or_insert_with(|| LawSensitivity { law: *law, path: path.clone(), in_scope: vec![], killed: vec![], evaluable: false });
                e.in_scope.push(*mid);
                if *killed {
                    e.killed.push(*mid);
                }
                e.evaluable |= *evaluable;
            }
        }
        for l in laws.values_mut() {
            l.in_scope.sort_unstable();
            l.in_scope.dedup();
            l.killed.sort_unstable();
            l.killed.dedup();
        }
        let mut entries: Vec<(String, Vec<(String, String)>)> = Vec::new();
        let mut stored: Vec<(&usize, &String)> = keys.iter().collect();
        stored.sort();
        for (mid, key) in stored {
            let Some(o) = outcomes[*mid].as_ref().filter(|o| cache::cacheable(o.verdict)) else { continue };
            let lr: Vec<cache::LawRecord> = laws.values().filter(|l| l.in_scope.contains(mid)).map(|l| (l.path.clone(), l.killed.contains(mid), l.evaluable)).collect();
            entries.push((key.clone(), vec![("outcome".to_string(), cache::encode(krate, o, &lr))]));
        }
        if let Err(e) = vc.store.put_many(cache::NS, &entries) {
            rep.cache_note = Some(format!("the mutant cache could not store every verdict: {e}"));
        }
    }
    rep.mutants = mutants.into_iter().zip(outcomes).map(|(m, o)| (m, o.unwrap_or_else(|| Outcome::new(Verdict::NotRun, vec!["not planned".into()])))).collect();
    let not_run = rep.count(Verdict::NotRun);
    if not_run > 0 {
        rep.incomplete_reasons.push(format!("{not_run} mutant(s) not run"));
    }
    let budget = rep.count(Verdict::KilledByBudget);
    if budget > 0 {
        rep.incomplete_reasons.push(format!("{budget} mutant(s) killed only by budget exhaustion (nothing is claimed about them)"));
    }
    rep.incomplete_reasons.dedup();
    rep.complete = rep.incomplete_reasons.is_empty();
    // LR8's scope: the spec mutants that are well-formed and decided (an
    // ill-formed, invalid, undecided or not-run mutant says nothing about a
    // law)
    let decided: BTreeSet<usize> = rep.mutants.iter().filter(|(_, o)| matches!(o.verdict, Verdict::KilledBySpec | Verdict::Counterexample | Verdict::PossiblyEquivalent)).map(|(m, _)| m.id).collect();
    for l in laws.values_mut() {
        l.in_scope.retain(|m| decided.contains(m));
        l.killed.retain(|m| decided.contains(m));
    }
    rep.laws = laws.into_values().collect();
    rep.elapsed = t0.elapsed();
    rep
}

/// Goal-budget factor of [`rerun_alone`].
const RERUN_BUDGET_FACTOR: u64 = 8;

/// Gate mode: re-runs, one at a time and with [`RERUN_BUDGET_FACTOR`] times
/// the goal budget, the mutants that were killed only by budget. Such a
/// mutant has no verdict yet (nothing is claimed about it); more steps can
/// only decide it — a definite failure or kill found with more steps is as
/// definite as one found with fewer. (QMDB, S5: the underflow obligation of a
/// `+` → `-` mutant of `Proof::accepts` fails definitely in the crate's own
/// elaboration, but exhausts the 20M-step goal budget in the gate's
/// spec-closure elaboration.) A mutant still killed only by budget stays so
/// (incomplete, an error).
#[allow(clippy::too_many_arguments)]
fn rerun_alone(krate: &Crate, plans: &[Plan], mutants: &[Mutant], opts: &MutateOptions, base: &Baseline, laws: &mut BTreeMap<ItemId, LawSensitivity>, outcomes: &mut [Option<Outcome>], rep: &mut MutationReport) {
    let again: Vec<usize> = (0..plans.len()).filter(|&i| outcomes[plans[i].mutant].as_ref().is_some_and(|o| o.verdict == Verdict::KilledByBudget)).collect();
    let mut more = opts.clone();
    more.elab.goal_budget = opts.elab.goal_budget.saturating_mul(RERUN_BUDGET_FACTOR);
    let opts = &more;
    for i in again {
        let tb = Instant::now();
        let m = plans[i].mutant;
        let target = mutants[m].target;
        let phase = if target == Target::Spec { Phase::Slot(0) } else { Phase::Full };
        let mut local: Vec<Option<Outcome>> = vec![None; mutants.len()];
        let mut local_laws: BTreeMap<ItemId, LawSensitivity> = BTreeMap::new();
        let mut pending: Vec<usize> = Vec::new();
        let mut carry: HashMap<usize, GateCarry> = HashMap::new();
        let (mut items, heap, mut tripped) = run_batch(krate, plans, &[i], mutants, opts, base, &mut local_laws, &mut local, phase, &mut pending, &mut carry);
        let mut slot = 0;
        while !pending.is_empty() {
            slot += 1;
            let alive = std::mem::take(&mut pending);
            let (i2, _, t2) = run_batch(krate, plans, &alive, mutants, opts, base, &mut local_laws, &mut local, Phase::Slot(slot), &mut pending, &mut carry);
            items += i2;
            tripped.extend(t2);
        }
        if let Some(o) = local[m].take() {
            outcomes[m] = Some(o);
        }
        for (l, s) in local_laws {
            let e = laws.entry(l).or_insert_with(|| LawSensitivity { law: s.law, path: s.path.clone(), in_scope: vec![], killed: vec![], evaluable: false });
            e.in_scope.extend(s.in_scope);
            e.killed.extend(s.killed);
            e.evaluable |= s.evaluable;
        }
        if !tripped.is_empty() {
            rep.incomplete_reasons.push(format!("a resource safety net tripped in a batch ({})", tripped.iter().map(|t| t.note.clone()).take(2).collect::<Vec<_>>().join("; ")));
        }
        if opts.progress {
            eprintln!("sandblaster mutation gate: mutant #{} alone with {}x the goal budget (it was killed only by budget): {:?}, {} item(s) in {} elaboration(s), {:.2} s", mutants[m].id, RERUN_BUDGET_FACTOR, outcomes[m].as_ref().map(|o| o.verdict), items, slot + 1, tb.elapsed().as_secs_f64());
        }
        rep.batches.push(BatchStat { mutants: 1, items, elapsed: tb.elapsed(), heap });
    }
    for l in laws.values_mut() {
        l.in_scope.sort_unstable();
        l.in_scope.dedup();
        l.killed.sort_unstable();
        l.killed.dedup();
    }
}

/// Worker threads of the gate's batches: a resource setting (at most 4, and
/// at most the machine's parallelism); it never changes a verdict.
fn gate_workers() -> usize {
    let machine = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 4);
    // `SANDBLASTER_GATE_WORKERS` (1-4) lowers it when the memory limit leaves no room for four
    // batches at once: a resource setting like `SANDBLASTER_MEM_LIMIT_GB`, never a verdict
    match std::env::var("SANDBLASTER_GATE_WORKERS").ok().and_then(|v| v.trim().parse::<usize>().ok()) {
        Some(n) if n >= 1 => machine.min(n),
        _ => machine,
    }
}

/// The gate's batches (see [`run_from`]): consecutive groups of
/// [`MutateOptions::batch`] plans of one target, taken in order by
/// [`gate_workers`] threads; each batch runs its known-answer slots to the
/// end on its thread. A worker waits while the heap is above `mem_cap` and
/// another batch is running; alone above it, the batch is not run (the run
/// is then incomplete: an error, never a pass). Outcomes and LR8 records
/// are merged in mutant order.
#[allow(clippy::too_many_arguments)]
fn run_parallel(krate: &Crate, plans: &[Plan], mutants: &[Mutant], opts: &MutateOptions, base: &Baseline, mem_cap: usize, laws: &mut BTreeMap<ItemId, LawSensitivity>, outcomes: &mut [Option<Outcome>], rep: &mut MutationReport, t0: Instant) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for i in 0..plans.len() {
        let t = mutants[plans[i].mutant].target;
        match groups.last_mut() {
            Some(g) if g.len() < opts.batch.max(1) && mutants[plans[g[0]].mutant].target == t => g.push(i),
            _ => groups.push(vec![i]),
        }
    }
    let next = AtomicUsize::new(0);
    let active = AtomicUsize::new(0);
    struct Done {
        group: usize,
        outcomes: Vec<(usize, Outcome)>,
        laws: BTreeMap<ItemId, LawSensitivity>,
        stat: BatchStat,
        tripped: Vec<String>,
        memory: bool,
    }
    let done: Mutex<Vec<Done>> = Mutex::new(Vec::new());
    let workers = gate_workers().min(groups.len().max(1));
    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| {
                elab::with_big_stack(|| loop {
                    let g = next.fetch_add(1, Ordering::SeqCst);
                    let Some(idx) = groups.get(g) else { return };
                    while crate::memguard::allocated() > mem_cap && active.load(Ordering::SeqCst) > 0 {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    if crate::memguard::allocated() > mem_cap {
                        let outs = idx.iter().map(|i| (plans[*i].mutant, Outcome::new(Verdict::NotRun, vec!["memory: the heap is above the batch limit".into()]))).collect();
                        done.lock().unwrap().push(Done { group: g, outcomes: outs, laws: BTreeMap::new(), stat: BatchStat { mutants: idx.len(), items: 0, elapsed: Duration::ZERO, heap: crate::memguard::allocated() }, tripped: vec![], memory: true });
                        continue;
                    }
                    active.fetch_add(1, Ordering::SeqCst);
                    let tb = Instant::now();
                    let target = mutants[plans[idx[0]].mutant].target;
                    let phase = if target == Target::Spec { Phase::Slot(0) } else { Phase::Full };
                    let mut local: Vec<Option<Outcome>> = vec![None; mutants.len()];
                    let mut local_laws: BTreeMap<ItemId, LawSensitivity> = BTreeMap::new();
                    let mut pending: Vec<usize> = Vec::new();
                    let mut carry: HashMap<usize, GateCarry> = HashMap::new();
                    let (mut items, heap, mut tripped) = run_batch(krate, plans, idx, mutants, opts, base, &mut local_laws, &mut local, phase, &mut pending, &mut carry);
                    let mut slot = 0;
                    while !pending.is_empty() {
                        slot += 1;
                        let alive = std::mem::take(&mut pending);
                        let (i2, _, t2) = run_batch(krate, plans, &alive, mutants, opts, base, &mut local_laws, &mut local, Phase::Slot(slot), &mut pending, &mut carry);
                        items += i2;
                        tripped.extend(t2);
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                    if opts.progress {
                        eprintln!("sandblaster mutation gate: batch {g} of {} ({} mutant(s), {:?}): {} item(s) in {} elaboration(s), {:.2} s; {:.0} s elapsed", groups.len(), idx.len(), target, items, slot + 1, tb.elapsed().as_secs_f64(), t0.elapsed().as_secs_f64());
                    }
                    let outs = local.into_iter().enumerate().filter_map(|(i, o)| o.map(|o| (i, o))).collect();
                    done.lock().unwrap().push(Done { group: g, outcomes: outs, laws: local_laws, stat: BatchStat { mutants: idx.len(), items, elapsed: tb.elapsed(), heap }, tripped: tripped.into_iter().map(|t| t.note).collect(), memory: false });
                });
            });
        }
    });
    let mut done = done.into_inner().unwrap();
    done.sort_by_key(|d| d.group);
    let mut memory = false;
    for d in done {
        for (i, o) in d.outcomes {
            outcomes[i] = Some(o);
        }
        for (l, s) in d.laws {
            let e = laws.entry(l).or_insert_with(|| LawSensitivity { law: s.law, path: s.path.clone(), in_scope: vec![], killed: vec![], evaluable: false });
            e.in_scope.extend(s.in_scope);
            e.killed.extend(s.killed);
            e.evaluable |= s.evaluable;
        }
        if !d.tripped.is_empty() {
            rep.incomplete_reasons.push(format!("a resource safety net tripped in a batch ({})", d.tripped.into_iter().take(2).collect::<Vec<_>>().join("; ")));
        }
        memory |= d.memory;
        rep.batches.push(d.stat);
    }
    for l in laws.values_mut() {
        l.in_scope.sort_unstable();
        l.killed.sort_unstable();
    }
    if memory {
        rep.incomplete_reasons.push(format!("memory: the heap exceeded {:.0}% of the memguard soft limit before a batch", opts.mem_fraction * 100.0));
    }
}

/// Which re-check a batch runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Every item of each mutant's closure (the full engine).
    Full,
    /// Gate mode, spec mutants: the spec closure with its `k`-th known
    /// answer ([`Plan::slots`]); slot 0 also evaluates the law checkers.
    Slot(usize),
}

/// Elaborates one batch and judges its mutants; mutants a [`Phase::Slot`]
/// batch leaves alive with known answers still to try go to `pending`
/// (plan indices). Returns the batch's items, the heap after its elaboration and
/// the safety nets that tripped.
#[allow(clippy::too_many_arguments)]
fn run_batch(krate: &Crate, plans: &[Plan], idx: &[usize], mutants: &[Mutant], opts: &MutateOptions, base: &Baseline, laws: &mut BTreeMap<ItemId, LawSensitivity>, outcomes: &mut [Option<Outcome>], phase: Phase, pending: &mut Vec<usize>, carry: &mut HashMap<usize, GateCarry>) -> (usize, usize, Vec<crate::auto::meter::Trip>) {
    let (bk, bms, filter) = match phase {
        Phase::Full => {
            let (bk, bms) = build_batch(krate, plans, idx, mutants);
            (bk, bms, None)
        }
        Phase::Slot(k) => build_batch_gate(krate, plans, idx, mutants, k),
    };
    let clone_of: HashMap<ItemId, ItemId> = bms.iter().flat_map(|b| b.map.iter().map(|(o, c)| (*c, *o))).collect();
    let eo = elab::Options { items: filter.map(std::sync::Arc::new), ..opts.elab.clone() };
    let mut chain = elab::ProverChain::standard();
    let out = elab::elaborate(&bk, &mut chain, &eo);
    let tripped = crate::auto::meter::take_trips();
    // the unchanged crate (what of it the batch elaborates) must re-verify
    let clone_of_base = krate.items.len();
    let base_bad: Vec<String> = out.defs.iter().filter(|d| d.item.is_some_and(|i| (i.0 as usize) < clone_of_base) && !matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))).map(|d| d.name.clone()).take(5).collect();
    let ev = Ev::new(&out, &bk, krate, opts);
    for bm in &bms {
        let p = &plans[bm.plan_index];
        let m = &mutants[p.mutant];
        let o = if !base_bad.is_empty() {
            Some(Outcome::new(Verdict::NotRun, vec![format!("the unchanged crate did not re-verify in this batch ({}): a resource failure, not a result", base_bad.join(", "))]))
        } else {
            match phase {
                Phase::Full => Some(judge(&ev, bm, p, m, &clone_of, laws, base)),
                Phase::Slot(k) => judge_spec_gate(&ev, bm, p, m, &clone_of, laws, k, carry.entry(m.id).or_default()),
            }
        };
        match o {
            Some(mut o) => {
                o.closure = p.closure.len();
                outcomes[m.id] = Some(o);
            }
            None => pending.push(bm.plan_index),
        }
    }
    let heap = crate::memguard::allocated();
    let items = bk.items.len();
    drop(ev);
    drop(out);
    drop(bk);
    (items, heap, tripped)
}

/// The spec items of a closure that a gate-mode batch clones: spec
/// functions and spec constants (laws become checkers; lemmas, proofs and
/// exec leaves are not re-checked: their failure never kills a spec
/// mutant).
fn gate_cloned(krate: &Crate, id: ItemId) -> bool {
    match &krate.item(id).kind {
        ItemKind::Fn(f) => f.kind == FnKind::Spec,
        ItemKind::Const(_) => krate.item(id).ghost || krate.in_spec_module(id),
        _ => false,
    }
}

/// The extended crate of a gate-mode batch of spec mutants (see *Gate
/// mode* in the module docs) and the item filter of its elaboration: the
/// clones, the law checkers, the `requires` checkers and the compared
/// originals, closed under references with the `#[bridges]` lemmas and
/// the types ([`elab::order::filter_closure`]). Each clone keeps only the
/// mutant's `slot`-th known answer ([`Plan::slots`]); the law checkers are
/// built in slot 0.
fn build_batch_gate(krate: &Crate, plans: &[Plan], idx: &[usize], mutants: &[Mutant], slot: usize) -> (Crate, Vec<BatchMutant>, Option<BTreeSet<ItemId>>) {
    let mut k = krate.clone();
    let mut bms = Vec::new();
    let mut seeds: BTreeSet<ItemId> = BTreeSet::new();
    let mut orig_req: HashMap<ItemId, ItemId> = HashMap::new();
    for &pi in idx {
        let p = &plans[pi];
        let m = &mutants[p.mutant];
        let suffix = format!("__mut{}", m.id);
        let kept: Vec<ItemId> = p.closure.iter().copied().filter(|x| gate_cloned(krate, *x)).collect();
        let mut map = HashMap::new();
        let base_id = k.items.len() as u32;
        for (j, orig) in kept.iter().enumerate() {
            map.insert(*orig, ItemId(base_id + j as u32));
        }
        for orig in &kept {
            let mut it = clone::clone_item(krate, *orig, map[orig], &suffix, &map);
            if *orig == m.item
                && let Some((body, ret)) = body_of_mut(&mut it)
            {
                ops::apply(body, &m.site, ret.as_ref());
                if let ItemKind::Const(c) = &mut it.kind {
                    c.value = match &c.init.kind {
                        ExprKind::Lit(Lit::Int(n)) => Some(*n),
                        _ => None,
                    };
                }
            }
            // only this slot's known answer
            if let ItemKind::Fn(f) = &mut it.kind {
                let keep = p.slots.get(slot).filter(|x| x.item == *orig);
                let ex = std::mem::take(&mut f.spec.examples);
                let files = std::mem::take(&mut f.spec.example_files);
                if let Some(x) = keep {
                    if x.file {
                        f.spec.example_files.extend(files.into_iter().nth(x.index));
                    } else {
                        f.spec.examples.extend(ex.into_iter().nth(x.index));
                    }
                }
            }
            seeds.insert(it.id);
            k.items.push(it);
        }
        // the checkers of the laws in the closure, over the clones
        let mut law_checkers = Vec::new();
        if slot == 0 {
            for orig in &p.closure {
                let Some(f) = krate.fn_def(*orig) else { continue };
                if f.kind != FnKind::Law {
                    continue;
                }
                let mut lf = f.clone();
                clone::remap_fn(&mut lf, &map);
                if let Some(chk) = clone::law_checker(&lf) {
                    let id = ItemId(k.items.len() as u32);
                    let item = synthetic_item(krate, *orig, id, &format!("{suffix}__chk"), chk);
                    k.items.push(item);
                    seeds.insert(id);
                    law_checkers.push((*orig, *orig, id));
                }
            }
        }
        // the compared functions: originals, clones and their `requires`
        // checkers
        let mut req_checkers = HashMap::new();
        for x in &p.compared {
            seeds.insert(*x);
            let Some(f) = krate.fn_def(*x) else { continue };
            if f.requires.is_empty() {
                continue;
            }
            let orig_chk = match orig_req.get(x) {
                Some(c) => Some(*c),
                None => clone::requires_checker(f).map(|chk| {
                    let id = ItemId(k.items.len() as u32);
                    let item = synthetic_item(krate, *x, id, "__req", chk);
                    k.items.push(item);
                    orig_req.insert(*x, id);
                    id
                }),
            };
            if let Some(c) = orig_chk {
                req_checkers.insert(*x, c);
                seeds.insert(c);
            }
            let Some(&cl) = map.get(x) else { continue };
            if let ItemKind::Fn(cf) = &k.items[cl.0 as usize].kind
                && let Some(chk) = clone::requires_checker(cf)
            {
                let id = ItemId(k.items.len() as u32);
                let item = synthetic_item(&k, cl, id, "__req", chk);
                k.items.push(item);
                req_checkers.insert(cl, id);
                seeds.insert(id);
            }
        }
        bms.push(BatchMutant { plan_index: pi, map, law_checkers, req_checkers });
    }
    // the originals were checked by the baseline: their examples are not
    // re-run
    for it in k.items.iter_mut().take(krate.items.len()) {
        if let ItemKind::Fn(f) = &mut it.kind {
            f.spec.examples.clear();
            f.spec.example_files.clear();
        }
    }
    // everything the seeds refer to, transitively, with what the build
    // elaborates for every proof unreferenced (the `#[bridges]` lemmas, the
    // types and what their invariants, views and representations mention):
    // the unchanged part of the batch must re-verify as it does in the build
    let filter = elab::order::filter_closure(&k, seeds);
    (k, bms, Some(filter))
}

/// The gate-mode verdict of a spec mutant in slot `k` ([`Phase::Slot`]):
/// killed by safety (the mutated spec, or a spec function using it, is
/// ill-formed), killed by the specification (a definite failure of the
/// slot's known answer, or a law counterexample in slot 0); at
/// [`search_slot`], the distinguishing search of [`judge`] — no witness:
/// possibly equivalent (never an error, so the larger vector files are not
/// needed); a witness: the remaining vector files may still kill it, else
/// it is a counterexample. `None`: alive, with known answers still to try.
/// `carry` holds what earlier slots found: known answers that could not be
/// decided (a budget; with no kill later they make the verdict
/// killed-by-budget, incomplete, never a pass) and the witness of the
/// distinguishing search.
#[allow(clippy::too_many_arguments)]
fn judge_spec_gate(ev: &Ev<'_>, bm: &BatchMutant, p: &Plan, m: &Mutant, clone_of: &HashMap<ItemId, ItemId>, laws: &mut BTreeMap<ItemId, LawSensitivity>, slot: usize, carry: &mut GateCarry) -> Option<Outcome> {
    let krate = ev.krate;
    let f = collect_failures(ev.out, ev.bk, bm, m.item, clone_of);
    let mut cex = Vec::new();
    if slot == 0 {
        // LR8: every law of the closure is in scope, and every law checker
        // is evaluated (not only those of failed proofs: laws are not
        // re-proven here)
        let mut checkable: BTreeSet<ItemId> = BTreeSet::new();
        for c in &p.closure {
            if krate.fn_def(*c).is_some_and(|f| f.kind == FnKind::Law) {
                let e = laws.entry(*c).or_insert_with(|| LawSensitivity { law: *c, path: krate.item(*c).path.to_string(), in_scope: vec![], killed: vec![], evaluable: false });
                e.in_scope.push(m.id);
                if bm.law_checkers.iter().any(|(l, _, _)| l == c) {
                    e.evaluable = true;
                    checkable.insert(*c);
                }
            }
        }
        if f.invalid.is_none() {
            cex = ev.refute_laws(bm, &checkable, m);
            for (l, _) in &cex {
                if let Some(e) = laws.get_mut(l) {
                    e.killed.push(m.id);
                }
            }
        }
    }
    if let Some(why) = &f.invalid {
        return Some(Outcome::new(Verdict::Invalid, vec![why.clone()]));
    }
    let own = f.whats(false, |s| s == Src::OwnSafety);
    if !own.is_empty() {
        return Some(Outcome::new(Verdict::KilledBySafety, own));
    }
    let dep = f.whats(false, |s| s == Src::DepSafety);
    if !dep.is_empty() {
        return Some(Outcome::new(Verdict::KilledBySafety, dep.into_iter().map(|w| format!("the mutated spec makes a spec function that uses it ill-formed: {w}")).collect()));
    }
    let mut by = f.whats(false, |s| s == Src::Example);
    by.extend(cex.iter().map(|(l, i)| format!("law `{}` is false for the mutant at {i}", krate.item(*l).path)));
    if !by.is_empty() {
        let mut o = Outcome::new(Verdict::KilledBySpec, by);
        o.law_counterexamples = cex;
        return Some(o);
    }
    carry.limited.extend(f.whats(true, |s| matches!(s, Src::Example | Src::OwnSpec)));
    // the `#[example]`s and the smallest vector file first; then the
    // distinguishing search; then the other vector files ([`search_slot`])
    let search_at = search_slot(&p.slots);
    let last = slot + 1 >= p.slots.len();
    if slot < search_at {
        return None;
    }
    if slot == search_at {
        let own_limited = f.whats(true, |s| matches!(s, Src::OwnSafety | Src::DepSafety));
        if !own_limited.is_empty() {
            return Some(Outcome::new(Verdict::KilledByBudget, own_limited));
        }
        let mut tried = 0usize;
        for ob in &p.obs {
            if let Some(Found { w, .. }) = ev.distinguish(ob.x, bm, m, &mut tried) {
                let mut suggestion = None;
                for s in &p.suggest {
                    let mut t2 = 0usize;
                    if let Some(Found { w, .. }) = ev.distinguish(*s, bm, m, &mut t2) {
                        suggestion = Some(w);
                        break;
                    }
                }
                carry.witness = Some((w, suggestion, tried));
                break;
            }
        }
        carry.tried = tried;
        if carry.witness.is_none() && carry.limited.is_empty() {
            let mut o = Outcome::new(Verdict::PossiblyEquivalent, vec![]);
            o.notes.push(match &p.no_obs {
                Some(why) => why.clone(),
                None if last => format!("no distinguishing input among {tried} tried"),
                None => format!("no distinguishing input among {tried} tried (the larger vector files were not needed)"),
            });
            return Some(o);
        }
    }
    if !last {
        return None;
    }
    if let Some((w, suggestion, tried)) = carry.witness.take() {
        let mut o = Outcome::new(Verdict::Counterexample, vec![]);
        o.witness = Some(w);
        o.suggestion = suggestion;
        o.notes.push(format!("{tried} input(s) tried"));
        return Some(o);
    }
    let limited = std::mem::take(&mut carry.limited);
    let mut o = Outcome::new(if limited.is_empty() { Verdict::PossiblyEquivalent } else { Verdict::KilledByBudget }, limited);
    o.notes.push(match &p.no_obs {
        Some(why) => why.clone(),
        None => format!("no distinguishing input among {} tried", carry.tried),
    });
    Some(o)
}

/// What a gate-mode spec mutant carries from one known answer's batch to
/// the next ([`judge_spec_gate`]).
#[derive(Default)]
struct GateCarry {
    /// Known answers that could not be decided (a budget).
    limited: Vec<String>,
    /// The distinguishing input found after the `#[example]`s (and the one
    /// at the nearest function with known answers), with the inputs tried.
    witness: Option<(Witness, Option<Witness>, usize)>,
    tried: usize,
}

/// The verdict of one mutant from its batch's elaboration.
fn judge(ev: &Ev<'_>, bm: &BatchMutant, p: &Plan, m: &Mutant, clone_of: &HashMap<ItemId, ItemId>, laws: &mut BTreeMap<ItemId, LawSensitivity>, base: &Baseline) -> Outcome {
    let krate = ev.krate;
    let f = collect_failures(ev.out, ev.bk, bm, m.item, clone_of);
    let law_cex_words = |cex: &[(ItemId, String)]| cex.iter().map(|(l, i)| format!("law `{}` is false for the mutant at {i}", krate.item(*l).path)).collect::<Vec<_>>();
    match m.target {
        Target::Impl => {
            if let Some(why) = &f.invalid {
                return Outcome::new(Verdict::Invalid, vec![why.clone()]);
            }
            let own = f.whats(false, |s| s == Src::OwnSafety);
            if !own.is_empty() {
                return Outcome::new(Verdict::KilledBySafety, own);
            }
            let spec = f.whats(false, |s| matches!(s, Src::OwnSpec | Src::Spec | Src::Example));
            if !spec.is_empty() {
                return Outcome::new(Verdict::KilledBySpec, spec);
            }
            // laws and refinements: a kill only with a definite
            // counterexample
            let (laws_def, refs_def) = (f.laws(Some(false)), f.refines(Some(false)));
            let proofs_failed = !f.whats(false, |s| matches!(s, Src::Law(_) | Src::Refines(_) | Src::Proof)).is_empty();
            if proofs_failed {
                // every failed law is evaluated (a law that failed as a
                // consequence of a lemma may still be false for the mutant;
                // a checker that reaches a placeholder is never evaluated)
                let cex = ev.refute_laws(bm, &f.all_failed_laws, m);
                let rcex = ev.refute_refines(bm, &refs_def, m, base);
                if !cex.is_empty() || !rcex.is_empty() {
                    let mut by = law_cex_words(&cex);
                    by.extend(rcex.into_iter().map(|(_, w)| w));
                    let mut o = Outcome::new(Verdict::KilledBySpec, by);
                    o.law_counterexamples = cex;
                    return o;
                }
            }
            let other = f.whats(false, |s| matches!(s, Src::OtherSafety | Src::DepSafety));
            if !other.is_empty() {
                return Outcome::new(Verdict::KilledBySafety, other);
            }
            let proofs = f.whats(false, |s| matches!(s, Src::Law(_) | Src::Refines(_) | Src::Proof));
            if !proofs.is_empty() {
                let mut by: Vec<String> = Vec::new();
                for l in &laws_def {
                    let evaluable = bm.law_checkers.iter().any(|(x, _, _)| x == l);
                    by.push(format!("the proof of law `{}` fails for the mutant, but {} (the law may still hold for it)", krate.item(*l).path, if evaluable { "no counterexample to the law was found" } else { "the law has no `bool` reading (a quantifier), so no counterexample could be evaluated" }));
                }
                for x in &refs_def {
                    by.push(format!("the refinement of `{}` fails for the mutant, but {} (it may still refine its spec)", krate.item(*x).path, if base.established.contains(x) { "the mutant agrees with it on every input tried" } else { "its view is not injective (or it has a domain), so the mutant cannot be compared with it" }));
                }
                by.extend(f.whats(false, |s| s == Src::Proof).into_iter().map(|w| format!("{w} (a lemma or proof, not the specification)")));
                let mut o = Outcome::new(Verdict::KilledByProofs, by);
                // does it differ where the specification must determine it?
                let mut tried = 0usize;
                for ob in &p.obs {
                    if let Some(Found { w, .. }) = ev.distinguish(ob.x, bm, m, &mut tried) {
                        o.notes.push(format!("it differs from `{}` on {}: {} vs {} — if the failing law holds for it, this is a counterexample to the completeness of `{}`", w.function, w.input, w.original, w.mutant, w.function));
                        break;
                    }
                }
                return o;
            }
            let lim = f.whats(true, |_| true);
            if !lim.is_empty() {
                // a budget-limited law or refinement failure may still be
                // definite
                let cex = ev.refute_laws(bm, &f.all_failed_laws, m);
                let rcex = ev.refute_refines(bm, &f.refines(Some(true)), m, base);
                if cex.is_empty() && rcex.is_empty() {
                    return Outcome::new(Verdict::KilledByBudget, lim);
                }
                let mut by = law_cex_words(&cex);
                by.extend(rcex.into_iter().map(|(_, w)| w));
                let mut o = Outcome::new(Verdict::KilledBySpec, by);
                o.law_counterexamples = cex;
                return o;
            }
            let mut tried = 0usize;
            for ob in &p.obs {
                if let Some(Found { mut w, tms }) = ev.distinguish(ob.x, bm, m, &mut tried) {
                    match ob.via {
                        Some(d) => w.dependency = Some((d, krate.item(d).path.to_string())),
                        None => {
                            w.section = base.published.get(&ob.x).map(|s| s.section).or_else(|| base.member.get(&ob.x).copied());
                            if krate.fn_def(ob.x).is_some_and(|f| f.ret == Ty::Bool) {
                                w.refutation = Some(refute_complete(ev.out, ev.bk, bm, ob.x, &tms, &w));
                            }
                        }
                    }
                    let mut o = Outcome::new(Verdict::Counterexample, vec![]);
                    o.witness = Some(w);
                    o.notes.push(format!("{tried} input(s) tried"));
                    return o;
                }
            }
            let mut o = Outcome::new(Verdict::PossiblyEquivalent, vec![]);
            match &p.no_obs {
                Some(why) => o.notes.push(why.clone()),
                None => o.notes.push(format!("no distinguishing input among {tried} tried at {}", p.obs.iter().map(|x| format!("`{}`", krate.item(x.x).path)).collect::<Vec<_>>().join(", "))),
            }
            o
        }
        Target::Spec => {
            // LR8 scope: every law re-checked for this mutant
            let mut checkable: BTreeSet<ItemId> = BTreeSet::new();
            for c in &p.closure {
                if krate.fn_def(*c).is_some_and(|f| f.kind == FnKind::Law) {
                    let e = laws.entry(*c).or_insert_with(|| LawSensitivity { law: *c, path: krate.item(*c).path.to_string(), in_scope: vec![], killed: vec![], evaluable: false });
                    e.in_scope.push(m.id);
                    if bm.law_checkers.iter().any(|(l, _, _)| l == c) {
                        e.evaluable = true;
                        checkable.insert(*c);
                    }
                }
            }
            if let Some(why) = &f.invalid {
                return Outcome::new(Verdict::Invalid, vec![why.clone()]);
            }
            let own = f.whats(false, |s| s == Src::OwnSafety);
            if !own.is_empty() {
                return Outcome::new(Verdict::KilledBySafety, own);
            }
            let dep = f.whats(false, |s| s == Src::DepSafety);
            if !dep.is_empty() {
                return Outcome::new(Verdict::KilledBySafety, dep.into_iter().map(|w| format!("the mutated spec makes a spec function that uses it ill-formed: {w}")).collect());
            }
            // examples (definite)
            let examples = f.whats(false, |s| s == Src::Example);
            // laws: only a definite counterexample counts
            let failed_laws = f.all_failed_laws.clone();
            let cex = ev.refute_laws(bm, &failed_laws.intersection(&checkable).copied().collect(), m);
            for (l, _) in &cex {
                if let Some(e) = laws.get_mut(l) {
                    e.killed.push(m.id);
                }
            }
            let mut by = examples.clone();
            by.extend(law_cex_words(&cex));
            let mut notes: Vec<String> = Vec::new();
            for l in &failed_laws {
                if !cex.iter().any(|(x, _)| x == l) {
                    notes.push(format!("the proof of law `{}` fails for the mutant, but no counterexample to it was found (not a kill: the law may still hold)", krate.item(*l).path));
                }
            }
            for r in &f.refines_failed {
                notes.push(format!("{r} fails for the mutant (not a kill: an implementation written from the same wrong spec would refine it)"));
            }
            for x in &f.list {
                if matches!(x.src, Src::Spec | Src::OwnSpec | Src::Proof | Src::OtherSafety) {
                    notes.push(format!("{} fails for the mutant (not a kill for spec mutation)", x.what));
                }
            }
            if !by.is_empty() {
                let mut o = Outcome::new(Verdict::KilledBySpec, by);
                o.law_counterexamples = cex;
                o.notes = notes;
                return o;
            }
            let own_limited = f.whats(true, |s| matches!(s, Src::OwnSafety | Src::DepSafety));
            if !own_limited.is_empty() {
                let mut o = Outcome::new(Verdict::KilledByBudget, own_limited);
                o.notes = notes;
                return o;
            }
            let mut tried = 0usize;
            for ob in &p.obs {
                if let Some(Found { w, .. }) = ev.distinguish(ob.x, bm, m, &mut tried) {
                    let mut o = Outcome::new(Verdict::Counterexample, vec![]);
                    o.witness = Some(w);
                    o.notes = notes;
                    o.notes.push(format!("{tried} input(s) tried"));
                    // a known answer is easier to find for the nearest
                    // refinement target or spec function with examples
                    for s in &p.suggest {
                        let mut t2 = 0usize;
                        if let Some(Found { w, .. }) = ev.distinguish(*s, bm, m, &mut t2) {
                            o.suggestion = Some(w);
                            break;
                        }
                    }
                    return o;
                }
            }
            let limited = f.list.iter().any(|x| x.lim && matches!(x.src, Src::Example | Src::Law(_) | Src::Spec | Src::OwnSpec));
            let mut o = Outcome::new(if limited { Verdict::KilledByBudget } else { Verdict::PossiblyEquivalent }, vec![]);
            if limited {
                o.by = f.whats(true, |s| matches!(s, Src::Example | Src::Law(_) | Src::Spec | Src::OwnSpec));
            }
            o.notes = notes;
            o.notes.push(match &p.no_obs {
                Some(why) => why.clone(),
                None => format!("no distinguishing input among {tried} tried"),
            });
            o
        }
    }
}

// ---------------------------------------------------------------------------
// Enforcement and output
// ---------------------------------------------------------------------------

fn diff_notes(mut d: Diagnostic, m: &Mutant) -> Diagnostic {
    d = d.note(format!("mutant #{} of `{}` ({}): {} at {}", m.id, m.path, m.family, m.desc, m.location));
    for l in &m.diff {
        d = d.note(format!("  {l}"));
    }
    d
}

/// The example call of a witness, relative to the function's own module
/// (where `#[example]` resolves names): `name(args)`.
pub fn example_call(krate: &Crate, w: &Witness) -> String {
    format!("{}{}", krate.item(w.item).name, w.input)
}

fn outputs_note(w: &Witness) -> String {
    if w.differs_at.is_empty() { String::new() } else { format!("; they differ at {}", w.differs_at.join(", ")) }
}

/// The §15.8 gate of the engine (see the module docs): errors for definite
/// counterexamples and surviving spec mutants, a warning per insensitive
/// law, and an error for an incomplete run. The crate path applies it to the
/// gate-mode run ([`run_gate`]); `sandblaster coverage` also to its
/// exploration run.
pub fn spec15_gate_mutants(rep: &MutationReport, krate: &Crate, diags: &mut Diagnostics) {
    if !rep.baseline_verified {
        diags.push(Diagnostic::error(DiagKind::MutationIncomplete, Span::DUMMY, "the counterexample engine did not run: the crate does not verify".to_string()));
        return;
    }
    // one error per observed function, or per unspecified dependency (the
    // first mutant in full, the others listed)
    let mut groups: BTreeMap<(bool, String), Vec<(&Mutant, &Outcome)>> = BTreeMap::new();
    for (m, o) in &rep.mutants {
        if o.verdict == Verdict::Counterexample
            && let Some(w) = &o.witness
        {
            let key = w.dependency.as_ref().map(|d| d.1.clone()).unwrap_or_else(|| w.function.clone());
            groups.entry((m.target == Target::Spec, key)).or_default().push((m, o));
        }
    }
    for ((spec, _), list) in &groups {
        let (m, o) = list[0];
        let w = o.witness.as_ref().expect("witness");
        let mut d = if !spec {
            match &w.dependency {
                Some((dep, dp)) => {
                    let sp = krate.item(*dep).span;
                    let mut d = Diagnostic::error(DiagKind::SpecIncomplete, sp, format!("`{dp}` is not determined by its specification: a mutant satisfies every law, contract and example, yet changes `{}` on {}", w.function, w.input));
                    d = diff_notes(d, m);
                    d = d.note(format!("input: {}", w.input)).note(format!("`{}` returns: {}", w.function, w.original)).note(format!("with the mutant it returns: {}{}", w.mutant, outputs_note(w))).note(format!("decided by {}", w.evaluator));
                    d.note(format!("the completeness of `{}` is proven only relative to `{dp}`, which no section fully specifies (its section is not well founded): specify `{dp}` (a refinement, or laws that determine it)", w.function))
                }
                None => {
                    let sp = krate.item(w.item).span;
                    let mut d = Diagnostic::error(DiagKind::SpecIncomplete, sp, format!("`{}` is not determined by its specification: a mutant satisfies every law, contract and example, yet differs from it on {}", w.function, w.input));
                    d = diff_notes(d, m);
                    d = d.note(format!("input: {}", w.input)).note(format!("`{}` returns: {}", w.function, w.original)).note(format!("the mutant returns: {}{}", w.mutant, outputs_note(w))).note(format!("decided by {}", w.evaluator));
                    if let Some(s) = w.section {
                        d = d.note(format!("a definite counterexample to `complete_{}` of section #{s}, which is not proven: add the law that rules the mutant out (e.g. the other direction of a soundness law, or the canonicity of a decoder)", w.function));
                    }
                    if let Some(Ok(r)) = &w.refutation {
                        d = d.note(format!("refutation: {r}"));
                    }
                    d
                }
            }
        } else {
            let sp = krate.item(m.item).span;
            let mut d = Diagnostic::error(DiagKind::SpecMutantSurvived, sp, format!("a mutant of `{}` survives every example and law: nothing pins `{}` down on {}", m.path, w.function, w.input));
            d = diff_notes(d, m);
            let call = example_call(krate, w);
            d = d.note(format!("`{call}` is {} in the specification and {} in the mutant{} (decided by {})", w.original, w.mutant, outputs_note(w), w.evaluator));
            d = d.note(format!("a known answer from an independent source kills it: add `#[example({call} == <expected>)]` to `{}`, with `<expected>` taken from the standard or an independent implementation — not from this specification (DESIGN.md §15.7)", w.function));
            if let Some(s) = &o.suggestion {
                let scall = example_call(krate, s);
                d = d.note(format!("known answers are usually published for `{}`, which uses `{}` and differs too: `#[example({scall} == <expected>)]` on it also kills the mutant (the specification gives {}, the mutant {})", s.function, m.path, s.original, s.mutant));
            }
            for n in &o.notes {
                d = d.note(n.clone());
            }
            d
        };
        if list.len() > 1 {
            let more: Vec<String> = list[1..].iter().map(|(m, o)| format!("#{} ({}; {})", m.id, m.desc, o.witness.as_ref().map(|w| format!("at `{}` on {}: {} vs {}", w.function, w.input, w.original, w.mutant)).unwrap_or_default())).collect();
            d = d.note(format!("{} more surviving mutant(s) with a counterexample: {}", more.len(), more.join("; ")));
        }
        diags.push(d);
    }
    for l in &rep.laws {
        if l.in_scope.is_empty() || !l.killed.is_empty() {
            continue;
        }
        let sp = krate.item(l.law).span;
        let mut d = Diagnostic::warning(DiagKind::LawInsensitive, sp, format!("law `{}` kills none of the {} spec mutant(s) of the spec functions it uses (§15.1 LR8): it says nothing about their definitions", l.path, l.in_scope.len()));
        if !l.evaluable {
            d = d.note("the law has a quantifier (or a proposition without a `bool` reading), so no counterexample could be evaluated for it".to_string());
        }
        diags.push(d);
    }
    if !rep.complete {
        let mut d = Diagnostic::error(DiagKind::MutationIncomplete, Span::DUMMY, "the counterexample engine did not finish: its verdict is incomplete, and nothing is claimed about the mutants it did not decide".to_string());
        for r in &rep.incomplete_reasons {
            d = d.note(r.clone());
        }
        if !rep.not_sampled.is_empty() {
            d = d.note(format!("{} item(s) got no mutant in the sample: {}", rep.not_sampled.len(), rep.not_sampled.iter().take(12).map(|p| format!("`{p}`")).collect::<Vec<_>>().join(", ")));
        }
        for (m, o) in rep.mutants.iter().filter(|(_, o)| o.verdict == Verdict::KilledByBudget).take(8) {
            d = d.note(format!("mutant #{} of `{}` ({}): killed only by budget: {}", m.id, m.path, m.desc, o.by.first().cloned().unwrap_or_default()));
        }
        diags.push(d);
    }
}

fn witness_json(w: &Witness) -> Json {
    let mut wj = Json::obj();
    wj.str("function", &w.function);
    wj.str("input", &w.input);
    wj.str("original", &w.original);
    wj.str("mutant", &w.mutant);
    wj.put("differs_at", Json::Arr(w.differs_at.iter().map(|x| Json::string(x)).collect()));
    wj.str("evaluator", &w.evaluator);
    if let Some(s) = w.section {
        wj.num("section", s as i64);
    }
    if let Some((_, d)) = &w.dependency {
        wj.str("unspecified_dependency", d);
    }
    match &w.refutation {
        Some(Ok(r)) => wj.str("refutation", r),
        Some(Err(e)) => wj.str("refutation_not_built", e),
        None => {}
    }
    wj
}

/// The report as JSON.
pub fn report_json(rep: &MutationReport) -> Json {
    let strs = |v: &[String]| Json::Arr(v.iter().map(|x| Json::string(x)).collect());
    let mut o = Json::obj();
    o.bool("baseline_verified", rep.baseline_verified);
    o.put("baseline_problems", strs(&rep.baseline_problems));
    o.num("enumerated", rep.enumerated as i64);
    o.num("run", rep.mutants.iter().filter(|(_, x)| x.verdict != Verdict::NotRun).count() as i64);
    o.bool("complete", rep.complete);
    o.str("status", if !rep.baseline_verified { "not run" } else if rep.complete { "complete" } else { "incomplete" });
    o.put("incomplete_reasons", strs(&rep.incomplete_reasons));
    o.put("not_sampled", strs(&rep.not_sampled));
    o.put(
        "excluded",
        Json::Arr(
            rep.excluded
                .iter()
                .map(|(p, why)| {
                    let mut j = Json::obj();
                    j.str("item", p);
                    j.str("why", why);
                    j
                })
                .collect(),
        ),
    );
    o.put("proof_internals_not_mutated", strs(&rep.internal));
    let mut counts = Json::obj();
    for v in Verdict::ALL {
        counts.num(v.word(), rep.count(v) as i64);
    }
    o.put("counts", counts);
    o.put(
        "batches",
        Json::Arr(
            rep.batches
                .iter()
                .map(|b| {
                    let mut j = Json::obj();
                    j.num("mutants", b.mutants as i64);
                    j.num("items", b.items as i64);
                    j.num("elapsed_ms", b.elapsed.as_millis() as i64);
                    j.num("heap_mib", (b.heap >> 20) as i64);
                    j
                })
                .collect(),
        ),
    );
    o.put(
        "mutants",
        Json::Arr(
            rep.mutants
                .iter()
                .map(|(m, x)| {
                    let mut j = Json::obj();
                    j.num("id", m.id as i64);
                    j.str("item", &m.path);
                    j.str("target", if m.target == Target::Impl { "implementation" } else { "spec" });
                    j.str("operator", m.family);
                    j.str("mutation", &m.desc);
                    j.str("location", &m.location);
                    j.put("diff", strs(&m.diff));
                    j.str("verdict", x.verdict.word());
                    j.put("by", strs(&x.by));
                    j.num("reverified_items", x.closure as i64);
                    if let Some(w) = &x.witness {
                        j.put("witness", witness_json(w));
                    }
                    if let Some(w) = &x.suggestion {
                        j.put("known_answer_site", witness_json(w));
                    }
                    j.put("notes", strs(&x.notes));
                    j
                })
                .collect(),
        ),
    );
    o.put(
        "law_sensitivity",
        Json::Arr(
            rep.laws
                .iter()
                .map(|l| {
                    let mut j = Json::obj();
                    j.str("law", &l.path);
                    j.num("spec_mutants_in_scope", l.in_scope.len() as i64);
                    j.put("kills", Json::Arr(l.killed.iter().map(|k| Json::Num(*k as i64)).collect()));
                    j.bool("evaluable", l.evaluable);
                    j.bool("insensitive", !l.in_scope.is_empty() && l.killed.is_empty());
                    j
                })
                .collect(),
        ),
    );
    o.str("tests", &rep.tests_note);
    o.num("elapsed_ms", rep.elapsed.as_millis() as i64);
    o
}
