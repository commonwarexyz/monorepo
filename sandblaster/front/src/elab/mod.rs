//! Elaboration of the typed HIR into kernel core terms (DESIGN.md §3.5, §7).
//!
//! Elaboration **is** the formal semantics of the exec subset (the K idea,
//! §0): every construct of the canonical dialect is given a meaning here, and
//! `SEMANTICS.md` (repository root) states the rules normatively. The kernel
//! checks every definition this module produces; the elaborator itself is
//! untrusted except for the claim that the core it produces for a function
//! denotes what `rustc` compiles (§1.1 item 2).
//!
//! # Pipeline (§7.1)
//!
//! [`elaborate`] visits the items of a checked [`Crate`] in dependency order
//! ([`order`]) and adds each to a kernel [`Env`] loaded with the prelude
//! (§6) and the elaboration-semantics definitions ([`semantics`]):
//!
//! | HIR item | core | module |
//! | --- | --- | --- |
//! | struct / enum | `add_inductive` (+ derived `PartialEq`, §7.7) | [`types`], [`eqs`] |
//! | `const` | nullary definition | [`items`] |
//! | exec fn | definition `Π(T..)(x..)(h :Irr P..). R` + loop helpers (§7.4) + `f::ensures` (§7.3) | [`exec`], [`pat`], [`loops`], [`ensures`] |
//! | spec fn | definition (value or `-> Prop`) | [`spec`] |
//! | lemma / law / proof | definition `Π(x..)(h : P..). Q` with a script proof (§4.4) | [`script`] |
//!
//! **§15 (DESIGN.md §15).** After every item, [`Elab::spec15_hooks`] hands
//! the recorded §15 annotations to the stage hooks: [`refines`] (S1:
//! `#[refines]`, `#[proof(refines)]`, views, `#[represents]`), [`examples`]
//! (S1: examples, vector files, mirrors, fuel), [`invariant`] (S2:
//! invariants, ghost parameters) and [`complete`] (S3: sections, run once);
//! then [`law_rules`] (S3: the §15.1 law rules LR1–LR10, recorded in
//! [`Output::law_rules`] and enforced by the §15.8 gate).
//! Until a stage lands its hook reports each annotation as "not implemented
//! yet (§15 Sn)" — an error, never a silent pass. `#[spec]` modules need no
//! hook: their functions are spec functions.
//!
//! Every partial operation, callee `requires`, termination measure, loop
//! invariant, `ensures`, `assert` and law goal becomes a
//! [`prover::Goal`](crate::prover::Goal) ([`obl`]); the prover is pluggable
//! ([`ProverChain`] of trait objects; [`ProverChain::standard`] is the
//! build's chain: the cheap development [`basic::BasicProver`], then
//! [`crate::auto::Auto`]). Each result is re-certified ([`recert`]) and
//! kernel-checked on the spot. Unproven obligations are recorded with their
//! goal, facts and the prover's notes; a definition with an unproven
//! obligation is not added to the kernel (an opaque placeholder of the same
//! type is, so later definitions can still be elaborated and reported).
//!
//! # Entry points
//!
//! [`elaborate`] (on a thread with a big stack: [`with_big_stack`]) returns
//! an [`Output`] with the kernel environment, every definition, obligation
//! and law record, and the diagnostics. The build, the CLI and the tests
//! go through `crate::driver` (`verify`, `with_elaboration`, `eval_in`).
//!
//! # Tracing (development)
//!
//! `SANDBLASTER_TRACE_ELAB` prints each item as it is elaborated,
//! `SANDBLASTER_TRACE_OBL` each obligation with its prover, proof size and
//! times, `SANDBLASTER_DUMP_PROOFS=<dir>` writes rejected proofs,
//! `SANDBLASTER_DEBUG_BASIC` / `SANDBLASTER_DEBUG_RECERT` explain failed steps
//! of the development prover and of re-certification,
//! `SANDBLASTER_TRACE_SECTIONS` each computed section (§15.5) with its status
//! and time and each prover call of its completeness proofs.

pub mod basic;
pub mod complete;
pub mod ensures;
pub mod eqs;
pub mod examples;
pub mod exec;
pub mod fm;
pub mod invariant;
pub mod items;
pub mod law_rules;
pub mod lockstep;
pub mod loops;
pub mod obl;
pub mod order;
pub mod pat;
pub mod prelude;
pub mod recert;
pub mod refine;
pub mod recursive;
pub mod refines;
pub mod scope;
pub mod script;
pub mod semantics;
pub mod show;
pub mod spec;
pub mod tm;
pub mod types;
pub mod facts;
pub mod generated;
pub mod value;
pub mod views;

use std::collections::{HashMap, HashSet};

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{DefKind, GlobalId, IndId, Rel, Tm, Width};
use sandblaster_kernel::value::{Budget, EnvEntry, V, VEnv};

use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::hir::{Crate, FnDef, ItemId, ItemKind, LocalDecl, Ty};
use crate::prover::{AutoFailure, Goal, ObligationKind, Prover};
use crate::span::Span;

pub use scope::{Scope, Val};

/// Elaboration options. There is deliberately **no** option that skips
/// proofs: every generated obligation is always attempted and reported.
#[derive(Clone, Debug)]
pub struct Options {
    /// Test-only: elaborate the exec code (and the types and constants it
    /// needs) but not spec functions, lemmas and laws. The build pipeline
    /// never sets this.
    pub exec_only: bool,
    /// Kernel step budget of one prover call.
    pub goal_budget: u64,
    /// Kernel step budget for checking one definition.
    pub def_budget: u64,
    /// Kernel-check every prover result immediately (precise diagnostics
    /// for bad proofs; the definition is checked again when added).
    pub check_proofs: bool,
    /// Load the prelude lemma files of the automation
    /// (`sandblaster/front/lemmas/*.core`, via
    /// [`crate::auto::lemmas::load`]) before elaborating. They are
    /// kernel-checked; [`crate::auto::Auto`] needs them.
    pub load_lemmas: bool,
    /// Kernel step budget for deciding one `#[example]` or vector record
    /// (§15.7): exhausting it fails the build, never skips the example.
    pub example_budget: u64,
    /// Step budget of each prover call of a completeness proof (§15.5;
    /// [`complete`]): the typical discharges (rewriting with a refinement,
    /// a split of both boolean results, an induction case) are small goals.
    /// Deterministic, like every budget (§15.8); not user-facing.
    pub complete_budget: u64,
    /// The mutation gate's item filter (`crate::mutate`, gate mode): only
    /// these items are elaborated (types are always elaborated; the set
    /// must be closed under [`order::refs`]), and the whole-crate passes
    /// (§15 post passes, sections, law rules) are skipped. The output of a
    /// filtered elaboration is **never a verification**: it carries an
    /// error diagnostic, so [`Output::verified`] is false. The build and
    /// the CLI never set it.
    pub items: Option<std::sync::Arc<std::collections::BTreeSet<ItemId>>>,
}

impl Options {
    /// Whether item `id` is elaborated (see [`Options::items`]).
    pub fn elaborates(&self, krate: &Crate, id: ItemId) -> bool {
        match &self.items {
            None => true,
            Some(set) => set.contains(&id) || matches!(krate.item(id).kind, ItemKind::Struct(_) | ItemKind::Enum(_) | ItemKind::TypeAlias(_)),
        }
    }
}

impl Default for Options {
    fn default() -> Options {
        Options { exec_only: false, goal_budget: 20_000_000, def_budget: 2_000_000_000, check_proofs: true, load_lemmas: true, example_budget: examples::EXAMPLE_BUDGET, complete_budget: 1_000_000, items: None }
    }
}

/// How an obligation ended.
#[derive(Clone, Debug)]
pub enum OblStatus {
    /// Proven; `by` names the prover (`eval` for goals closed by
    /// evaluation, `script` for goals closed by a script step).
    Proven { by: String },
    /// Not proven (the build fails).
    Failed(AutoFailure),
    /// Left open with `todo()` (the build fails).
    Todo,
}

/// One obligation, for the report and diagnostics.
#[derive(Clone, Debug)]
pub struct ObligationRecord {
    pub id: u32,
    pub kind: ObligationKind,
    pub span: Span,
    /// Kernel name of the definition the obligation belongs to.
    pub def: String,
    pub status: OblStatus,
    /// Whether script hints were supplied.
    pub hinted: bool,
    /// The goal, pretty-printed in core syntax.
    pub goal: String,
}

impl ObligationRecord {
    pub fn proven(&self) -> bool {
        matches!(self.status, OblStatus::Proven { .. })
    }
}

/// Status of one definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefStatus {
    /// Added to the kernel environment (every obligation proven).
    Checked,
    /// Some obligation is unproven (a placeholder was added, if possible).
    Unproven,
    /// The kernel rejected the definition (an elaborator or prover bug).
    Rejected(String),
    /// Not elaborated: an unsupported construct.
    Unsupported(String),
    /// Not elaborated: depends on a definition that failed.
    Blocked(String),
    /// Not elaborated in this phase (e.g. hardware variants without core
    /// models, §9.2).
    Deferred(String),
    /// A law without a proof (open claim, §4.5).
    Open,
}

/// One kernel definition produced (or attempted) by elaboration.
#[derive(Clone, Debug)]
pub struct DefRecord {
    pub name: String,
    pub kind: DefKind,
    pub item: Option<ItemId>,
    pub global: Option<GlobalId>,
    pub status: DefStatus,
    pub span: Span,
}

/// A measure-recursive definition as the kernel checked it, before its
/// commit replaced the recursive calls (`Rec`) by the definition itself and
/// dropped their decrease proofs: the body with its `Rec` nodes, and the
/// measure. The checked-structuring walker proves a loop lemma by measure
/// recursion with these very decrease proofs (docs/checked-structuring.md
/// §5.1). Kept next to the [`DefRecord`]s, keyed by the definition's
/// global (a `DefRecord` crosses threads in `driver::Verification`; kernel
/// terms do not).
#[derive(Clone, Debug)]
pub struct PreCommit {
    pub body: Tm,
    pub measure: Tm,
}

/// A law and how it ended.
#[derive(Clone, Debug)]
pub struct LawRecord {
    pub item: ItemId,
    pub name: String,
    /// `inline`, the proof item's path, or `missing`.
    pub proof: String,
    pub status: DefStatus,
}

/// The result of elaborating a crate.
pub struct Output {
    pub env: Env,
    pub defs: Vec<DefRecord>,
    pub obligations: Vec<ObligationRecord>,
    pub laws: Vec<LawRecord>,
    pub diags: Diagnostics,
    /// Kernel globals of exec/spec functions and constants, by item.
    pub fn_globals: HashMap<ItemId, GlobalId>,
    /// Inductives of user types, by item.
    pub adts: HashMap<ItemId, IndId>,
    /// Items not elaborated in this phase (hardware variants etc.).
    pub deferred: Vec<(ItemId, String)>,
    /// `f::refines` lemmas (§15.2; filled from S1). S0: always empty (the
    /// stage that fills a record list adds its accumulator to [`Elab`] and
    /// to `generated::rebuild`/`finish`).
    pub refinements: Vec<refines::RefinesRecord>,
    /// Checked examples (§15.7; filled from S1). S0: always empty.
    pub examples: Vec<examples::ExampleRecord>,
    /// Computed sections and their completeness (§15.5; S3): recorded, and
    /// enforced by the §15.8 gate [`complete::spec15_gate_s3`].
    pub sections: Vec<complete::SectionRecord>,
    /// Example coverage per spec function (§15.7; S1 records it, the §15.8
    /// gate [`examples::spec15_gate_s1`] enforces it).
    pub coverage: Vec<examples::CoverageRecord>,
    /// Spec-closure, fuel and mirror findings of spec items outside the S1
    /// surface (legacy `#[spec] fn`s): errors of the §15.8 gate.
    pub spec_closure: Vec<examples::ClosureRecord>,
    /// Exec functions established by a determining refinement (§15.1).
    pub established: Vec<GlobalId>,
    /// The findings of the law rules (§15.1 LR1–LR10 but LR8; S3):
    /// recorded, and enforced by the §15.8 gate
    /// [`law_rules::spec15_gate_laws`].
    pub law_rules: Vec<law_rules::LawRuleRecord>,
    /// The pre-commit body and measure of every measure-recursive
    /// definition the kernel accepted ([`PreCommit`]).
    pub pre_commit: HashMap<GlobalId, PreCommit>,
    /// What the theorem gate generated and proved per MIR module (the
    /// literal reading's state and the callee lemmas), for the lifted
    /// round trip's theorems (`mir::checked::prove_roundtrip`).
    pub mir_gate: crate::mir::checked::GateMemory,
}

impl Output {
    /// An output with no records (elaboration could not start).
    pub fn empty(env: Env, diags: Diagnostics) -> Output {
        Output { env, defs: vec![], obligations: vec![], laws: vec![], diags, fn_globals: HashMap::new(), adts: HashMap::new(), deferred: vec![], refinements: vec![], examples: vec![], sections: vec![], coverage: vec![], spec_closure: vec![], established: vec![], law_rules: vec![], pre_commit: HashMap::new(), mir_gate: Default::default() }
    }

    /// Whether every definition was checked, every obligation proven and
    /// every law proven.
    pub fn verified(&self) -> bool {
        self.defs.iter().all(|d| matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))) && self.obligations.iter().all(|o| o.proven()) && !self.diags.has_errors()
    }
}

/// A sequence of provers tried in order; remembers which one succeeded.
///
/// Every goal is bounded: each prover gets the goal's step budget (kernel
/// and front-end work, [`crate::auto::meter`]), and all of them together
/// get one wall-clock deadline ([`ProverChain::timeout`]) and stop at the
/// memory soft limit.
pub struct ProverChain {
    pub provers: Vec<(String, Box<dyn Prover>)>,
    pub last: Option<usize>,
    /// Wall-clock limit of one goal, all provers together (`None`:
    /// [`crate::auto::meter::goal_timeout`], i.e. `SANDBLASTER_GOAL_TIMEOUT_MS`
    /// or 30 s).
    pub timeout: Option<std::time::Duration>,
    /// The first prover tried (a retry after the kernel rejected an
    /// earlier prover's proof starts after it, `elab::obl`).
    pub start: usize,
}

impl ProverChain {
    pub fn new(provers: Vec<(String, Box<dyn Prover>)>) -> ProverChain {
        ProverChain { provers, last: None, timeout: None, start: 0 }
    }
    /// The development chain: [`basic::BasicProver`] only.
    pub fn basic() -> ProverChain {
        ProverChain::new(vec![("basic".into(), Box::new(basic::BasicProver::default()))])
    }
    /// The standard chain of the build (DESIGN.md §8.1): the fast
    /// [`basic::BasicProver`] first, then [`crate::auto::Auto`].
    pub fn standard() -> ProverChain {
        ProverChain::new(vec![
            ("basic".into(), Box::new(basic::BasicProver::default())),
            ("auto".into(), Box::new(crate::auto::Auto::new())),
        ])
    }
    /// Name of the prover that closed the last goal.
    pub fn last_name(&self) -> String {
        self.last.and_then(|i| self.provers.get(i)).map(|p| p.0.clone()).unwrap_or_default()
    }
}

impl Prover for ProverChain {
    fn prove(&mut self, env: &Env, g: &Goal, b: &mut Budget) -> Result<Tm, AutoFailure> {
        self.last = None;
        // the goal's deadline (shared by the provers of the chain)
        let _scope = crate::auto::meter::Scope::enter(self.timeout, b);
        let mut failure = AutoFailure::default();
        let start = self.start;
        for (i, (name, p)) in self.provers.iter_mut().enumerate() {
            if i < start {
                continue;
            }
            if let Some(r) = crate::auto::meter::check() {
                failure.tried.push(format!("{name}: not tried: {}", crate::auto::meter::describe(r)));
                continue;
            }
            let mut sub = Budget { steps: b.steps };
            match p.prove(env, g, &mut sub) {
                Ok(t) => {
                    b.steps = sub.steps;
                    self.last = Some(i);
                    return Ok(t);
                }
                Err(f) => {
                    if failure.goal.is_empty() {
                        failure.goal = f.goal.clone();
                    }
                    if failure.facts.is_empty() {
                        failure.facts = f.facts.clone();
                    }
                    failure.stuck.extend(f.stuck);
                    failure.tried.extend(f.tried.into_iter().map(|t| format!("{name}: {t}")));
                }
            }
        }
        Err(failure)
    }
}

/// An elaboration error: aborts the current definition.
#[derive(Clone, Debug)]
pub struct ElabError {
    pub span: Span,
    pub msg: String,
    pub kind: ErrKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrKind {
    /// A construct the elaborator does not support (yet).
    Unsupported,
    /// Depends on a definition that failed.
    Blocked,
    /// Deferred to a later phase.
    Deferred,
    /// An internal inconsistency (a bug).
    Internal,
}

pub type R<T> = Result<T, ElabError>;

pub fn unsupported<T>(span: Span, msg: impl Into<String>) -> R<T> {
    Err(ElabError { span, msg: msg.into(), kind: ErrKind::Unsupported })
}

pub fn internal<T>(span: Span, msg: impl Into<String>) -> R<T> {
    Err(ElabError { span, msg: msg.into(), kind: ErrKind::Internal })
}

/// What kind of term is being built (decides the relevance of facts and
/// path equations, §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Exec or spec function bodies: facts and path equations are
    /// irrelevant binders; obligations are proof slots.
    Exec,
    /// Relevant proofs (lemma/law bodies, `ensures` proofs): facts and path
    /// equations are relevant binders.
    Proof,
}

/// Self-recursion of the definition being built.
#[derive(Clone, Debug)]
pub struct RecInfo {
    /// The item whose calls become `Rec` (functions, lemmas, proofs).
    pub item: Option<ItemId>,
    /// The definition's full type (closed term).
    pub ty: Tm,
    pub arity: u32,
    /// The measure (a term in the context of the telescope) and its width.
    pub measure: Option<(Tm, Width)>,
}

/// Per-definition elaboration state.
pub struct FnState<'a> {
    /// Kernel name of the definition being built.
    pub name: String,
    pub item: Option<ItemId>,
    pub locals: &'a [LocalDecl],
    pub scope: Scope,
    /// Number of leading type-parameter binders.
    pub ngen: u32,
    pub mode: Mode,
    /// HIR type of the answer of the current (CPS or join) computation.
    pub answer: Ty,
    /// The function's return type (the CPS answer).
    pub ret: Ty,
    pub rec: Option<RecInfo>,
    /// Some obligation failed.
    pub failed: bool,
    pub span: Span,
    /// Loop helpers created for this function, by `LoopInfo::index`.
    pub helpers: HashMap<u32, GlobalId>,
    /// Whether the definition is opaque (functions with loops, §5.6).
    pub opaque: bool,
    /// The HIR of the function being elaborated.
    pub fdef: Option<&'a FnDef>,
    /// The goal of the current arm of a refinement match (scripts).
    pub branch_goal: Option<Val>,
    /// Nesting of continuation duplication (see `Elab::use_cps`).
    pub cps_depth: u32,
    /// Nesting of pure elaboration (`Elab::in_pure`): propositions
    /// elaborated as types (contracts, loop invariants, assertions) and
    /// values that must not bind anything (place indices, loop bounds,
    /// measures). There the invariant facts of a projected value (§15.3)
    /// are hints of the proof slots (`Scope::hint_facts`), never `let`s.
    pub pure_facts: u32,
    /// In a `#[proof(complete = p)]` script (§15.5, [`complete`]): the
    /// members of `p`'s section: the level of their `F'` binder and its
    /// type (a term at that depth) — a call of a member denotes the
    /// hypothetical implementation `F'`, which the script reasons about (the
    /// real function is the goal's right side).
    pub abstracted: HashMap<ItemId, (u32, Tm)>,
    /// When set, every failed obligation is also recorded here: its span,
    /// kind and goal in surface syntax (the restatement of a law with a
    /// section abstracted locates the proof slots that do not re-check).
    pub slot_failures: Option<Vec<(Span, crate::prover::ObligationKind, String)>>,
}

impl<'a> FnState<'a> {
    pub fn new(name: String, item: Option<ItemId>, locals: &'a [LocalDecl], span: Span) -> FnState<'a> {
        FnState {
            name,
            item,
            locals,
            scope: Scope::default(),
            ngen: 0,
            mode: Mode::Exec,
            answer: Ty::unit(),
            ret: Ty::unit(),
            rec: None,
            failed: false,
            span,
            helpers: HashMap::new(),
            opaque: false,
            fdef: None,
            branch_goal: None,
            cps_depth: 0,
            pure_facts: 0,
            abstracted: HashMap::new(),
            slot_failures: None,
        }
    }
}

/// Where a user item lives in the kernel.
#[derive(Clone, Debug)]
pub enum ItemGlobal {
    Def(GlobalId),
    /// The item failed; dependents are blocked (reason).
    Failed(String),
}

/// The elaborator.
pub struct Elab<'a> {
    pub krate: &'a Crate,
    pub env: Env,
    pub p: prelude::Prelude,
    pub sem: semantics::Semantics,
    pub prover: &'a mut ProverChain,
    pub opts: Options,
    pub adts: HashMap<ItemId, IndId>,
    pub globals: HashMap<ItemId, ItemGlobal>,
    /// Derived equality functions and their lemmas (§7.7).
    pub eq_fns: HashMap<ItemId, eqs::EqGlobals>,
    pub defs: Vec<DefRecord>,
    /// [`Output::pre_commit`].
    pub pre_commit: HashMap<GlobalId, PreCommit>,
    pub obligations: Vec<ObligationRecord>,
    pub laws: Vec<LawRecord>,
    pub diags: Diagnostics,
    pub deferred: Vec<(ItemId, String)>,
    /// Items transitively using intrinsics without core models (§9.2).
    pub hw_items: HashSet<ItemId>,
    /// Obligation kinds of the irrelevant binders of loop helpers.
    pub helper_kinds: HashMap<GlobalId, Vec<ObligationKind>>,
    /// Per exec function: its stack-depth requires index and opacity.
    pub fn_info: HashMap<ItemId, items::FnInfo>,
    /// While proving `f::ensures` of a recursive `f`: `(f, arity)` (its
    /// calls in the body get induction hypotheses).
    pub ens_rec: Option<(GlobalId, u32)>,
    /// The implicit "Nat range" lemmas of the spec functions whose results
    /// have `Nat` components (spec function ↦ `f::nat_range`, its arity),
    /// [`ensures::Elab::nat_range_def`].
    pub nat_ranges: HashMap<GlobalId, (GlobalId, u32)>,
    /// The spec functions with `Nat` components whose range proof did not go
    /// through (spec function ↦ the first unproven goal): named in the
    /// failures of obligations that mention them.
    pub nat_range_missing: HashMap<GlobalId, String>,
    /// Generated mode of the codegen round trip (DESIGN.md §8.3): definitions
    /// are recorded instead of added ([`generated`]).
    pub generated: Option<generated::Sink>,
    /// The §15 S1 stages' state (views, refinements, examples, spec
    /// closure; [`views::S1State`]).
    pub s1: views::S1State,
    /// The §15 S3 state (computed sections; [`complete::S3State`]).
    pub s3: complete::S3State,
    pub f: FnState<'a>,
}

thread_local! {
    static HIDDEN_FACTS: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Registers the context levels of the goal about to be proven whose facts
/// are superseded (a refining script match re-introduced them specialized,
/// [`refine`]); the provers of this crate skip them when collecting facts.
pub fn set_hidden_facts(levels: Vec<u32>) {
    HIDDEN_FACTS.with(|c| *c.borrow_mut() = levels);
}

/// Whether context level `l` holds a superseded fact of the current goal.
pub fn fact_hidden(l: u32) -> bool {
    HIDDEN_FACTS.with(|c| c.borrow().contains(&l))
}

/// Stack size of the thread that runs elaboration and the kernel.
pub const STACK_BYTES: usize = 512 << 20;

/// Runs `f` on a thread with a large stack ([`STACK_BYTES`]) and raises the
/// kernel's stack allowance accordingly (the kernel is recursive over terms
/// and values; deep symbolic execution needs the room, and running out is
/// reported as `OutOfFuel`, never a crash).
pub fn with_big_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|sc| {
        std::thread::Builder::new()
            .name("sandblaster-kernel".into())
            .stack_size(STACK_BYTES)
            .spawn_scoped(sc, || {
                sandblaster_kernel::util::set_stack_limit(STACK_BYTES - (32 << 20));
                f()
            })
            .expect("spawn the elaboration thread")
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e))
    })
}

/// Elaborates a checked crate (see the module docs).
pub fn elaborate(krate: &Crate, prover: &mut ProverChain, opts: &Options) -> Output {
    crate::auto::lemmas::clear_bridges();
    lockstep::reset();
    let mut env = Env::with_prelude();
    let mut diags = Diagnostics::new();
    if opts.load_lemmas {
        if let Err(e) = crate::auto::lemmas::load(&mut env) {
            diags.push(Diagnostic::error(DiagKind::Build, Span::DUMMY, format!("internal error: prelude lemmas failed to load: {e}")));
            return Output::empty(env, diags);
        }
    }
    // per-literal bit-family lemmas the proofs name (`sandblaster::lemmas::bits::lz_ge_u16_9`)
    for it in &krate.items {
        if let Some(k) = crate::resolve::prelude_lemma_kernel_name(&it.path)
            && let Some((f, w, n)) = crate::auto::bitlib::parse_lemma_name(&k)
        {
            let mut b = sandblaster_kernel::value::Budget { steps: 2_000_000_000 };
            if let Err(e) = crate::auto::bitlib::ensure(&mut env, f, w, n, &mut b) {
                diags.push(Diagnostic::error(DiagKind::Build, Span::DUMMY, format!("internal error: bit lemma `{k}` failed to load: {e}")));
            }
        }
    }
    let sem = match semantics::install(&mut env, &krate.target.arch) {
        Ok(s) => s,
        Err(e) => {
            diags.push(Diagnostic::error(DiagKind::Build, Span::DUMMY, format!("internal error: elaboration semantics failed to load: {e}")));
            return Output::empty(env, diags);
        }
    };
    let p = match prelude::Prelude::new(&env) {
        Ok(p) => p,
        Err(e) => {
            diags.push(Diagnostic::error(DiagKind::Build, Span::DUMMY, format!("internal error: {e}")));
            return Output::empty(env, diags);
        }
    };
    let mut el = Elab {
        krate,
        env,
        p,
        sem,
        prover,
        opts: opts.clone(),
        adts: HashMap::new(),
        globals: HashMap::new(),
        eq_fns: HashMap::new(),
        defs: vec![],
        pre_commit: HashMap::new(),
        obligations: vec![],
        laws: vec![],
        diags,
        deferred: vec![],
        hw_items: HashSet::new(),
        helper_kinds: HashMap::new(),
        fn_info: HashMap::new(),
        ens_rec: None,
        nat_ranges: HashMap::new(),
        nat_range_missing: HashMap::new(),
        generated: None,
        s1: views::S1State { on: !opts.exec_only, ..Default::default() },
        s3: complete::S3State::default(),
        f: FnState::new(String::new(), None, &[], Span::DUMMY),
    };
    el.run();
    // §15.1 law rules (S3): recorded, enforced by the §15.8 gate
    let law_rules = if el.s1.on && opts.items.is_none() { el.law_rules_pass() } else { vec![] };
    if opts.items.is_some() {
        el.diags.push(Diagnostic::error(DiagKind::Build, Span::DUMMY, "partial elaboration (the mutation gate's item filter): not a verification of the crate".to_string()));
    }
    let fn_globals = el
        .globals
        .iter()
        .filter_map(|(k, v)| match v {
            ItemGlobal::Def(g) => Some((*k, *g)),
            ItemGlobal::Failed(_) => None,
        })
        .collect();
    let s1 = std::mem::take(&mut el.s1);
    let sections = std::mem::take(&mut el.s3.sections);
    Output {
        env: el.env,
        defs: el.defs,
        obligations: el.obligations,
        laws: el.laws,
        diags: el.diags,
        fn_globals,
        adts: el.adts,
        deferred: el.deferred,
        refinements: s1.refinements,
        examples: s1.examples,
        sections,
        coverage: s1.coverage,
        spec_closure: s1.closure,
        established: s1.established.into_iter().collect(),
        law_rules,
        pre_commit: el.pre_commit,
        mir_gate: Default::default(),
    }
}

impl<'a> Elab<'a> {
    fn run(&mut self) {
        self.hw_items = order::hardware_items(self.krate, &self.sem);
        // §15.1: a refinement whose specification reaches the function itself
        self.refines_cycle_check();
        for id in order::dependency_order(self.krate) {
            if self.opts.elaborates(self.krate, id) {
                self.item(id);
            }
        }
        self.spec15_hooks();
    }

    /// Hands every recorded §15 annotation to its stage hook (see the
    /// module docs), in item order; then runs the section hook once.
    fn spec15_hooks(&mut self) {
        let krate = self.krate;
        for it in &krate.items {
            let id = it.id;
            if !self.opts.elaborates(krate, id) {
                continue;
            }
            match &it.kind {
                ItemKind::Fn(f) => {
                    if let Some(r) = &f.spec.refines {
                        self.refines_hook(id, r);
                    }
                    if let Some(p) = f.spec.proof_of.filter(|p| p.kind == crate::hir::ProofKind::Refines) {
                        self.refines_proof_hook(id, &p);
                    }
                    if !f.spec.examples.is_empty() || !f.spec.example_files.is_empty() {
                        self.examples_hook(id, &f.spec.examples, &f.spec.example_files);
                    }
                    if let Some(j) = &f.spec.mirrors_impl {
                        self.mirrors_hook(id, j);
                    }
                    if let Some(fs) = &f.spec.fuel_sufficient {
                        self.fuel_hook(id, fs);
                    }
                    if f.params.iter().any(|p| p.ghost) {
                        self.ghost_params_hook(id);
                    }
                    if let Some(j) = &f.spec.trusted_extern {
                        let what = format!("`#[trusted_extern]` on `{}`", it.path);
                        self.diag(
                            Diagnostic::error(DiagKind::Elab, j.span, format!("{what} is not implemented yet (§13, §15.8)"))
                                .note("trusted externs are the §13 runtime primitives; until they land nothing may be assumed without proof"),
                        );
                    }
                }
                ItemKind::Const(c) if !c.examples.is_empty() => self.examples_hook(id, &c.examples, &[]),
                ItemKind::Struct(s) => {
                    if let Some(inv) = &s.invariant {
                        self.invariant_hook(id, inv);
                    }
                    if let Some(v) = &s.view {
                        self.view_hook(id, v);
                    }
                    if let Some(r) = &s.represents {
                        self.represents_hook(id, r);
                    }
                }
                ItemKind::Enum(e) => {
                    if let Some(v) = &e.view {
                        self.view_hook(id, v);
                    }
                }
                _ => {}
            }
        }
        // a filtered elaboration (the mutation gate) has no whole-crate passes
        if self.opts.items.is_some() {
            return;
        }
        // §15 S2: the determinacy of simulation-form refinements, Abstract(S)
        self.s2_post_pass();
        // §15 S1 cross-item checks: mirrors, fuel, example coverage
        self.s1_post_pass();
        self.sections_hook();
    }

    /// Reports a recorded §15 annotation whose stage has not landed: an
    /// error, so that nothing gives false assurance.
    pub fn spec15_not_implemented(&mut self, span: Span, what: &str, stage: &str) {
        self.diag(
            Diagnostic::error(DiagKind::Elab, span, format!("{what} is not implemented yet (§15 {stage})"))
                .note("the front end checks and records this annotation, but its meaning lands in a later stage; until then it fails the build instead of being ignored (DESIGN.md §15.12)"),
        );
    }

    // ------------------------------------------------------------------
    // context helpers
    // ------------------------------------------------------------------

    pub fn depth(&self) -> u32 {
        self.f.scope.depth()
    }

    pub fn budget(&self) -> Budget {
        Budget { steps: self.opts.goal_budget }
    }

    /// Evaluates a term in the current context.
    pub fn eval(&self, t: &Tm) -> R<V> {
        let mut b = Budget { steps: self.opts.def_budget };
        self.env.eval(&self.f.scope.venv, sandblaster_kernel::term::Lvl(self.depth()), t, &mut b).map_err(|e| self.eval_error(e))
    }

    /// Evaluates `t` in an explicit environment at the current depth.
    pub fn eval_in(&self, env: &VEnv, t: &Tm) -> R<V> {
        let mut b = Budget { steps: self.opts.def_budget };
        self.env.eval(env, sandblaster_kernel::term::Lvl(self.depth()), t, &mut b).map_err(|e| self.eval_error(e))
    }

    /// An evaluation failure while elaborating: a ghost `Int` beyond the
    /// kernel's documented implementation limit is the user's (a value too
    /// large, DESIGN.md §5.7, SEMANTICS.md §13.5), anything else an
    /// internal error.
    fn eval_error(&self, e: sandblaster_kernel::value::EvalError) -> ElabError {
        match e {
            sandblaster_kernel::value::EvalError::IntOverflow => ElabError {
                span: self.f.span,
                msg: format!(
                    "a ghost `Int` value in `{}` exceeds the kernel's implementation limit of {} bits (DESIGN.md §5.7, SEMANTICS.md §13.5): the kernel does not compute with larger values",
                    self.f.name,
                    sandblaster_kernel::prim::INT_BITS_LIMIT
                ),
                kind: ErrKind::Unsupported,
            },
            e => ElabError { span: self.f.span, msg: format!("evaluation failed while elaborating `{}`: {e:?}", self.f.name), kind: ErrKind::Internal },
        }
    }

    /// Typed read-back of a value in the current context.
    pub fn quote(&self, v: &V, ty: Option<&V>) -> Tm {
        self.env.quote_typed(&self.f.scope.ctx, v, ty, false)
    }

    /// Pushes a binder of type `ty`; with `def`, a `let` whose value is
    /// known to conversion. Returns its level.
    pub fn push(&mut self, name: &str, rel: Rel, ty: &Tm, def: Option<&Tm>) -> R<u32> {
        let tv = self.eval(ty)?;
        let (entry, is_def) = match def {
            Some(d) => match rel {
                Rel::Rel => {
                    let v = self.eval(d)?;
                    let lvl = self.depth();
                    std::rc::Rc::make_mut(&mut self.f.scope.let_tms).insert(lvl, (ty.clone(), d.clone(), v.clone()));
                    (EnvEntry::Rel(v), true)
                }
                Rel::Irr => (EnvEntry::Irr(self.f.scope.closure(d)), true),
            },
            None => (self.env.fresh_var(sandblaster_kernel::term::Lvl(self.depth()), rel, &tv), false),
        };
        Ok(self.f.scope.push_entry(name, rel, tv, entry, is_def))
    }

    /// Pushes a binder whose type is already a value.
    pub fn push_v(&mut self, name: &str, rel: Rel, tv: V) -> u32 {
        let entry = self.env.fresh_var(sandblaster_kernel::term::Lvl(self.depth()), rel, &tv);
        self.f.scope.push_entry(name, rel, tv, entry, false)
    }

    /// Relevance of fact binders in the current mode.
    pub fn fact_rel(&self) -> Rel {
        match self.f.mode {
            Mode::Exec => Rel::Irr,
            Mode::Proof => Rel::Rel,
        }
    }

    /// Pushes a fact binder (a `let` with its proof when `proof` is given,
    /// else a λ/arm binder) and records it for the prover.
    pub fn push_fact(&mut self, name: &str, ty: &Tm, proof: Option<&Tm>, origin: crate::prover::FactOrigin, span: Span) -> R<u32> {
        let rel = self.fact_rel();
        self.push_fact_rel(name, rel, ty, proof, origin, span)
    }

    /// [`Elab::push_fact`] with an explicit relevance.
    pub fn push_fact_rel(&mut self, name: &str, rel: Rel, ty: &Tm, proof: Option<&Tm>, origin: crate::prover::FactOrigin, span: Span) -> R<u32> {
        // A relevant fact binder (proof mode) with its proof is a variable
        // for evaluation, not the proof's value: a proof is irrelevant to
        // every computation, and its evaluated value (a lemma body unfolded
        // at its arguments, stuck transports that do not store their
        // equations) quoted back into a statement loses its proof slots
        // (D1). Statements and proof slots that mention the fact then read
        // back as the fact itself, which the kernel checks in the `let`.
        let lvl = if rel == Rel::Rel && proof.is_some() && std::env::var_os("SANDBLASTER_X_FACT_VALUES").is_none() {
            let tv = self.eval(ty)?;
            let entry = self.env.fresh_var(sandblaster_kernel::term::Lvl(self.depth()), rel, &tv);
            self.f.scope.push_entry(name, rel, tv, entry, false)
        } else {
            self.push(name, rel, ty, proof)?
        };
        self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin, span });
        self.f.scope.fact_tys.insert(lvl, ty.clone());
        Ok(lvl)
    }

    /// Records a diagnostic.
    pub fn diag(&mut self, d: Diagnostic) {
        self.diags.push(d);
    }

    /// The HIR declaration of a local of the current function.
    pub fn local_decl(&self, l: crate::hir::LocalId) -> &'a LocalDecl {
        &self.f.locals[l.0 as usize]
    }

    /// Current term of a HIR local.
    pub fn local_tm(&self, l: crate::hir::LocalId, span: Span) -> R<Tm> {
        // a `#[ghost]` parameter: its projection of the ghost bundle
        if let Some(v) = self.f.scope.ghost_locals.get(&l) {
            return Ok(v.at(self.depth()));
        }
        match self.f.scope.local(l) {
            Some(lvl) => Ok(self.f.scope.var(lvl)),
            None => internal(span, format!("local `{}` is not in scope", self.f.locals.get(l.0 as usize).map(|d| d.name.as_str()).unwrap_or("?"))),
        }
    }

    /// Kernel global of a user item, or a blocking error.
    pub fn item_global(&self, id: ItemId, span: Span) -> R<GlobalId> {
        match self.globals.get(&id) {
            Some(ItemGlobal::Def(g)) => Ok(*g),
            Some(ItemGlobal::Failed(why)) => Err(ElabError { span, msg: format!("depends on `{}`, which {why}", self.krate.item(id).path), kind: ErrKind::Blocked }),
            None => {
                if self.hw_items.contains(&id) {
                    Err(ElabError { span, msg: format!("depends on `{}`, a hardware function deferred to phase 3", self.krate.item(id).path), kind: ErrKind::Deferred })
                } else {
                    Err(ElabError { span, msg: format!("`{}` has not been elaborated (dependency order)", self.krate.item(id).path), kind: ErrKind::Blocked })
                }
            }
        }
    }

    /// Kernel inductive of a user type.
    pub fn adt(&self, id: ItemId, span: Span) -> R<IndId> {
        match self.adts.get(&id) {
            Some(i) => Ok(*i),
            None => Err(ElabError { span, msg: format!("type `{}` is not available", self.krate.item(id).path), kind: ErrKind::Blocked }),
        }
    }
}
