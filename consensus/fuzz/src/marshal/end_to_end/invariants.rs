//! During-execution and end-of-run invariants for the multi-node marshal model.
//!
//! These checks cover both the marshal/application boundary and observations
//! made while Simplex drives marshal. They panic on violation with the
//! offending state, matching the rest of the consensus fuzz crate.
//!
//! Delivery checks operate on the sink's append-only delivery log
//! ([`Application::delivered`]) -- the actual `(height, digest)` arrival
//! sequence -- rather than a by-height snapshot, so out-of-order delivery,
//! gaps, duplicates, and same-height forks are all observable (a by-height map
//! would silently overwrite them).

use super::app::{ApplicationChoice, BlockContextRegistry};
use crate::simplex::Simplex;
use commonware_consensus::{
    Block,
    marshal::mocks::application::Application,
    simplex::types::Context as SimplexContext,
    types::{Height, Round},
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroUsize,
    sync::Arc,
};

type PublicKeyOf<P> =
    <<P as Simplex>::Scheme as commonware_cryptography::certificate::Verifier>::PublicKey;
type Ctx<P> = SimplexContext<Sha256Digest, PublicKeyOf<P>>;
type VerifiedContexts<P> = HashMap<(Round, Sha256Digest), Vec<Ctx<P>>>;
type CertifyVerdicts = HashMap<(Round, Sha256Digest), (usize, bool)>;

#[derive(Default)]
struct CertificationState {
    agreement: CertifyVerdicts,
}

/// Ensures correct automata return the same completed certification verdict
/// for the same `(round, digest)`.
#[derive(Clone)]
pub(crate) struct CertificationAgreementInvariant {
    state: Arc<Mutex<CertificationState>>,
    stack: Arc<str>,
}

impl CertificationAgreementInvariant {
    pub(crate) fn new(stack: Arc<str>) -> Self {
        Self {
            state: Arc::new(Mutex::new(CertificationState::default())),
            stack,
        }
    }

    pub(crate) fn check_certify_agreement(
        &self,
        validator: usize,
        round: Round,
        digest: Sha256Digest,
        verdict: bool,
    ) {
        let mut state = self.state.lock();
        if let Some((first_validator, first_verdict)) = state.agreement.get(&(round, digest)) {
            assert_eq!(
                *first_verdict, verdict,
                "marshal automaton certify agreement violated: honest node{first_validator} \
                 returned {first_verdict} but honest node{validator} returned {verdict} for \
                 round={round} digest={digest}; stack={}",
                self.stack,
            );
            return;
        }
        state
            .agreement
            .insert((round, digest), (validator, verdict));
    }
}

/// Ensures a rejection scoped to one proposal header cannot poison
/// certification of the same payload under its embedded header.
pub(super) struct HeaderMismatchInvariant<P: Simplex, C: Copy> {
    verified_contexts: Arc<Mutex<VerifiedContexts<P>>>,
    block_contexts: BlockContextRegistry<Ctx<P>>,
    app_choice: ApplicationChoice,
    app_config: C,
    rejects: fn(ApplicationChoice, C, &Ctx<P>) -> bool,
    stack: Arc<str>,
}

impl<P: Simplex, C: Copy> Clone for HeaderMismatchInvariant<P, C> {
    fn clone(&self) -> Self {
        Self {
            verified_contexts: self.verified_contexts.clone(),
            block_contexts: self.block_contexts.clone(),
            app_choice: self.app_choice,
            app_config: self.app_config,
            rejects: self.rejects,
            stack: self.stack.clone(),
        }
    }
}

impl<P: Simplex, C: Copy> HeaderMismatchInvariant<P, C> {
    pub(super) fn new(
        app_choice: ApplicationChoice,
        app_config: C,
        rejects: fn(ApplicationChoice, C, &Ctx<P>) -> bool,
        block_contexts: BlockContextRegistry<Ctx<P>>,
        stack: Arc<str>,
    ) -> Self {
        Self {
            verified_contexts: Arc::new(Mutex::new(HashMap::new())),
            block_contexts,
            app_choice,
            app_config,
            rejects,
            stack,
        }
    }

    pub(super) fn record_verify(&self, context: Ctx<P>, digest: Sha256Digest) {
        self.verified_contexts
            .lock()
            .entry((context.round, digest))
            .or_default()
            .push(context);
    }

    pub(super) fn block_context(&self, digest: &Sha256Digest) -> Option<Ctx<P>> {
        self.block_contexts.get(digest)
    }

    fn observed_mismatch(&self, round: Round, digest: Sha256Digest) -> bool {
        let block_context = self.block_context(&digest).unwrap_or_else(|| {
            panic!(
                "marshal fuzz harness could not resolve the embedded context for a completed \
                 certification: round={round} digest={digest}; stack={}",
                self.stack,
            )
        });
        let mismatch = self
            .verified_contexts
            .lock()
            .get(&(round, digest))
            .is_some_and(|contexts| contexts.iter().any(|context| context != &block_context));
        mismatch && !(self.rejects)(self.app_choice, self.app_config, &block_context)
    }

    /// Check a completed certification outcome after a header-mismatching verification.
    pub(super) fn check_certification(&self, round: Round, digest: Sha256Digest, verdict: bool) {
        if verdict {
            return;
        }
        let mismatch = self.observed_mismatch(round, digest);
        assert!(
            !mismatch,
            "marshal invariant violated: certification reused a \
             header-scoped verification rejection; stack={}",
            self.stack,
        );
    }
}

/// Run block-ordering and agreement invariants.
pub fn check_all_blocks<B: Block<Digest = Sha256Digest>>(
    honest_apps: &[(usize, Application<B>)],
    stack: Option<&str>,
) {
    let stack = stack.unwrap_or("unspecified");
    for (idx, app) in honest_apps {
        check_in_order(*idx, &app.delivered(), stack);
        check_parent_linkage(*idx, &app.blocks(), stack);
    }
    agreement(honest_apps, stack);
}

/// Invariant: every pair of consecutively delivered blocks is parent-linked.
fn check_parent_linkage<B: Block<Digest = Sha256Digest>>(
    idx: usize,
    blocks: &BTreeMap<Height, Arc<B>>,
    stack: &str,
) {
    for (height, block) in blocks {
        let Some(next_height) = height.get().checked_add(1).map(Height::new) else {
            continue;
        };
        let Some(next) = blocks.get(&next_height) else {
            continue;
        };
        assert_eq!(
            next.parent(),
            block.digest(),
            "node{idx} delivered a chain with a broken parent link: height {} digest={} \
             but height {} parent={}; stack={stack}",
            height.get(),
            block.digest(),
            next_height.get(),
            next.parent(),
        );
    }
}

/// Invariant: before height `H` is delivered, every height at or below
/// `H - max_pending_acks` has been acknowledged.
pub(super) fn check_pending_acks<B: Block>(
    validator: usize,
    application: &Application<B>,
    height: Height,
    max_pending_acks: NonZeroUsize,
    stack: &str,
) {
    let acknowledged_through = height.get().saturating_sub(max_pending_acks.get() as u64);
    let pending = application.pending_ack_heights();
    assert!(
        pending
            .iter()
            .all(|pending_height| pending_height.get() > acknowledged_through),
        "marshal max_pending_acks backpressure violated: node{validator} delivered height {} \
         while pending heights {pending:?} include a height at or below \
         {acknowledged_through}; max_pending_acks={max_pending_acks}; stack={stack}",
        height.get(),
    );
}

/// Invariant: per-node in-order, gap-free delivery.
///
/// Walks the arrival-ordered delivery log. Delivery starts either at the
/// genesis floor block (height 0, surfaced on a fresh start) or at the first
/// finalized container (height 1), then every subsequent delivery must advance
/// by exactly one. Because this is the true arrival sequence, an out-of-order
/// delivery, a gap, or a duplicate/refinalized height all fail the `+ 1` check.
fn check_in_order<D>(idx: usize, delivered: &[(Height, D)], stack: &str) {
    let heights: Vec<u64> = delivered.iter().map(|(h, _)| h.get()).collect();
    let first = heights.first().copied().unwrap_or(0);
    assert!(
        first <= 1,
        "node{idx} first delivery at height {first} is above the genesis floor + 1 \
         (sequence={heights:?}); stack={stack}",
    );
    for window in heights.windows(2) {
        assert_eq!(
            window[1],
            window[0] + 1,
            "node{idx} violated in-order delivery (out-of-order, gap, or duplicate); \
             sequence={heights:?}; stack={stack}",
        );
    }
}

/// Invariant: cross-node agreement (safety).
///
/// For every pair of honest nodes, the shorter finalized chain must be a prefix
/// of the longer chain. Marshal can check this stronger block-level property
/// because its application sink retains finalized `(height, digest)` entries;
/// comparing finalized heights alone would not detect conflicting blocks.
///
/// [`check_in_order`] establishes that each node's delivery log is contiguous
/// and contains no duplicate heights. Given that, requiring one digest per
/// height across all honest delivery logs and current tips is equivalent to
/// pairwise prefix compatibility and also checks that a tip agrees with any
/// delivered block at the same height. Heights are used instead of raw
/// sequence indexes because a fresh application may surface genesis at height
/// 0 or begin with the first finalized block at height 1.
///
/// This detects conflicting finalization, fork divergence, and recovery that
/// delivers a different block at an already observed height.
fn agreement<B: Block<Digest = Sha256Digest>>(
    honest_apps: &[(usize, Application<B>)],
    stack: &str,
) {
    let mut seen: BTreeMap<Height, (usize, &'static str, Sha256Digest)> = BTreeMap::new();
    for (idx, app) in honest_apps {
        for (height, digest) in app.delivered() {
            if let Some((first_idx, first_source, first_digest)) = seen.get(&height) {
                assert_eq!(
                    *first_digest,
                    digest,
                    "honest fork at height {}: node{first_idx} {first_source} {first_digest:?} \
                     but node{idx} delivered {digest:?}; stack={stack}",
                    height.get(),
                );
            } else {
                seen.insert(height, (*idx, "delivered", digest));
            }
        }
        if let Some((height, digest)) = app.tip() {
            if let Some((first_idx, first_source, first_digest)) = seen.get(&height) {
                assert_eq!(
                    *first_digest,
                    digest,
                    "honest tip disagreement at height {}: node{first_idx} {first_source} \
                     {first_digest:?} but node{idx} reported tip {digest:?}; stack={stack}",
                    height.get(),
                );
            } else {
                seen.insert(height, (*idx, "reported tip", digest));
            }
        }
    }
}
