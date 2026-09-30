//! Test hooks of the optimizer (docs/optimizer-plan.md O1; design §20):
//! inject unsound candidates, proofs and cache entries, and simulate
//! optimizer bugs, so the must-reject suite (`tests/opt_reject.rs`) can show
//! that the kernel, the evidence gate or the emission-chain check rejects
//! each of them and that the proven fallback is emitted.
//!
//! **Never in a production build.** This module is compiled only under
//! `cfg(test)` or the `opt-test-hooks` feature. Integration tests cannot see
//! `cfg(test)` items of the library, so the feature exists for them, and
//! only this crate's own dev-dependency on itself enables it (see
//! `Cargo.toml`). `sandblaster`, `sandblaster-cli` and every build script link
//! the front end without it; `tools/gates` checks that with `cargo tree`.
//! Without the feature, [`OptOptions`](super::OptOptions) has no hook field
//! and the stand-in `OptTestHooks` of `opt/mod.rs` is uninhabited, so every
//! hook site is statically dead.
//!
//! Hooks only ever make the optimizer *propose* something (a candidate, a
//! proof, a cache hit, a dispatch, a clone-lemma claim). What is admitted is
//! still decided by the kernel and the gates, exactly as for the
//! optimizer's own proposals.
//!
//! The driven route (O4) takes simulated faults (`drive_faults`, R1–R15).
//! Rules (`#[rewrite]` laws) and parallel executors have no consumer in
//! today's pipeline; their hooks arrive with their stages.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, Rel, Tm};
use sandblaster_kernel::util::mk;

/// Builds the body (its parameter `λ`s included) of a link lemma
/// `Π x̄ h̄. Eq(R, a x̄ h̄, b x̄ h̄)`, given `a` (the residual or clone) and `b`
/// (the source function it must equal).
pub type ProofSkeleton = Arc<dyn Fn(&Env, GlobalId, GlobalId) -> Result<Tm, String> + Send + Sync>;

/// A hints-cache entry (design §17): the chosen candidate and the proof-term
/// skeleton of its link. The kernel re-checks every hit: the skeleton is
/// submitted to `Env::add_def`, and the candidate is then admitted by the
/// ordinary route.
#[derive(Clone)]
pub struct CacheEntry {
    /// The cached candidate: the body of this function (same signature)
    /// instead of the residual the optimizer builds; `None` keeps the
    /// optimizer's residual.
    pub candidate: Option<String>,
    /// The cached proof skeleton of `Π x̄. Eq(R, residual x̄, f x̄)`.
    pub proof: ProofSkeleton,
}

/// A simulated CPU for the dispatch of one variant set (must-reject R21,
/// optimizer design §13.2): the emitted detection reports the set's
/// features whatever the CPU has, and the known-answer self-test decides.
/// The emitted code is otherwise the production template; R21 simulates a
/// CPU on which `lzcnt`/`tzcnt` run as `bsr`/`bsf` by patching those
/// encodings in the compiled binary (the fault is in the machine code, as
/// on real hardware, not in the Rust source).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KatFault {
    /// Detection reports the set's features.
    ForceDetect,
}

/// What a test injects. Keys are item paths as the report prints them
/// (`crate::m::f`, clones `crate::m::f__<set>`).
#[derive(Clone, Default)]
pub struct OptTestHooks {
    /// Function → the function whose body is proposed as its residual (a
    /// candidate from an untrusted summarizer; same signature and
    /// `requires`).
    pub candidates: BTreeMap<String, String>,
    /// Lemma name → the proof term submitted to `add_def` in place of the
    /// one the optimizer builds. Today this covers the clone lemmas
    /// `f__<set>::clone_equiv`.
    pub proofs: BTreeMap<String, ProofSkeleton>,
    /// Function → a cache hit for it.
    pub cache: BTreeMap<String, CacheEntry>,
    /// Variants dispatched although their models lack hardware evidence (a
    /// simulated optimizer bug; R26).
    pub force_dispatch: BTreeSet<String>,
    /// Clones whose `clone_equiv` lemma is skipped but still claimed in the
    /// report (a simulated optimizer bug; R27).
    pub forge_clone_lemma: BTreeSet<String>,
    /// Function → a simulated fault of its driven route (R1–R15, see
    /// [`DriveFault`](super::DriveFault)).
    pub drive_faults: BTreeMap<String, super::DriveFault>,
    /// Loop head → a simulated fault of its Σ2 summary (R6–R8, see
    /// [`LoopFault`](super::loopsum::LoopFault)).
    pub loop_faults: BTreeMap<String, super::loopsum::LoopFault>,
    /// Variant set → a simulated CPU for its dispatch (R21, see
    /// [`KatFault`]).
    pub kat_faults: BTreeMap<String, KatFault>,
    /// Feature-only variant sets generated as if a host had run them (their
    /// host evidence granted: `sandblaster_targets::evidence::SetRecord`), so
    /// tests exercise the sets' clones, dispatch and self-test before any
    /// host round has recorded them.
    pub set_evidence: BTreeSet<String>,
    /// The aegraph's rule library, `(file, text)` in load order, in place
    /// of the committed `lemmas/cong.core` and `lemmas/rules/*.core` (a
    /// stale or corrupted rule file; `None` keeps the committed files).
    pub rule_files: Option<Vec<(String, String)>>,
    /// Lane kernel (`s__<target>`) → a simulated fault of the lane functor
    /// (R16, see [`LaneFault`](super::par::lift::LaneFault)).
    pub lane_faults: BTreeMap<String, super::par::lift::LaneFault>,
}

impl std::fmt::Debug for OptTestHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OptTestHooks")
            .field("candidates", &self.candidates)
            .field("proofs", &self.proofs.keys().collect::<Vec<_>>())
            .field("cache", &self.cache.iter().map(|(k, e)| (k, &e.candidate)).collect::<Vec<_>>())
            .field("force_dispatch", &self.force_dispatch)
            .field("forge_clone_lemma", &self.forge_clone_lemma)
            .field("drive_faults", &self.drive_faults)
            .field("loop_faults", &self.loop_faults)
            .field("kat_faults", &self.kat_faults)
            .field("set_evidence", &self.set_evidence)
            .field("rule_files", &self.rule_files.as_ref().map(|v| v.iter().map(|(f, _)| f).collect::<Vec<_>>()))
            .field("lane_faults", &self.lane_faults)
            .finish()
    }
}

impl OptTestHooks {
    pub(crate) fn candidate(&self, f: &str) -> Option<String> {
        self.candidates.get(f).cloned().or_else(|| self.cache.get(f).and_then(|e| e.candidate.clone()))
    }
    pub(crate) fn cache_proof(&self, f: &str) -> Option<ProofSkeleton> {
        self.cache.get(f).map(|e| e.proof.clone())
    }
    pub(crate) fn proof(&self, lemma: &str) -> Option<ProofSkeleton> {
        self.proofs.get(lemma).cloned()
    }
    pub(crate) fn forces_dispatch(&self, variant: &str) -> bool {
        self.force_dispatch.contains(variant)
    }
    pub(crate) fn forges_clone_lemma(&self, clone: &str) -> bool {
        self.forge_clone_lemma.contains(clone)
    }
    pub(crate) fn drive_fault(&self, f: &str) -> Option<super::DriveFault> {
        self.drive_faults.get(f).copied()
    }
    pub(crate) fn loop_fault(&self, f: &str) -> Option<super::loopsum::LoopFault> {
        self.loop_faults.get(f).copied()
    }
    pub(crate) fn kat_fault(&self, set: &str) -> Option<KatFault> {
        self.kat_faults.get(set).copied()
    }
    pub(crate) fn rule_files(&self) -> Option<Vec<(String, String)>> {
        self.rule_files.clone()
    }
    pub(crate) fn grants_set_evidence(&self, set: &str) -> bool {
        self.set_evidence.contains(set)
    }
    pub(crate) fn lane_fault(&self, kernel: &str) -> Option<super::par::lift::LaneFault> {
        self.lane_faults.get(kernel).copied()
    }
}

/// The skeleton of a conversion link: `λ x̄. refl(R, b x̄)`. It checks
/// exactly when `a x̄` and `b x̄` are convertible (tier 0), so it is the
/// untampered cache entry of any straight-line residual.
pub fn refl_skeleton() -> ProofSkeleton {
    Arc::new(|env: &Env, _a: GlobalId, b: GlobalId| {
        let tele = super::symex::telescope(env, b).ok_or("no telescope")?;
        let n = tele.binders.len();
        let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
        let mut body = mk::refl(tele.ret.clone(), mk::apps(mk::global(b), args));
        for (nm, rel, dom) in tele.binders.iter().rev() {
            body = mk::lam(nm, *rel, dom.clone(), body);
        }
        Ok(body)
    })
}

/// Runs `f` with the load/store helper `name` of `arch` printed from
/// `template` instead of its trusted template, on this thread only
/// (must-reject R26: a changed helper template must rename the evidence
/// record of every lane kernel that calls the helper, so a host run of the
/// old code never covers the new). Call it inside the elaboration thread
/// (`elab::with_big_stack`), around the optimization and the printing.
/// Panics if there is no such helper.
pub fn with_helper_template<R>(arch: &crate::target::Arch, name: &str, template: &'static str, f: impl FnOnce() -> R) -> R {
    let id = crate::intrinsics::lookup_helper(arch, name).unwrap_or_else(|| panic!("no helper {name} on {}", arch.name()));
    struct Restore(crate::intrinsics::HelperId, Option<&'static str>);
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::intrinsics::TEMPLATE_OVERRIDE.with(|o| match self.1 {
                Some(t) => {
                    o.borrow_mut().insert(self.0, t);
                }
                None => {
                    o.borrow_mut().remove(&self.0);
                }
            });
        }
    }
    let old = crate::intrinsics::TEMPLATE_OVERRIDE.with(|o| o.borrow_mut().insert(id, template));
    let _restore = Restore(id, old);
    f()
}
