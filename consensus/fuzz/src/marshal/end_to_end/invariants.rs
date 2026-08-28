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

use super::{
    app::{ApplicationChoice, BlockContextRegistry},
    scenario::{SETTLE, ScenarioOutcome},
    twins::stack::MarshalChoice,
};
use crate::{network::CertificatePoison, simplex::Simplex};
use commonware_consensus::{
    Block,
    marshal::mocks::{application::Application, block::Block as MockBlock},
    simplex::types::Context as SimplexContext,
    types::{Height, Round, coding::Commitment},
};
use commonware_cryptography::{Digest, Digestible, PublicKey, sha256::Digest as Sha256Digest};
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

type PublicKeyOf<P> =
    <<P as Simplex>::Scheme as commonware_cryptography::certificate::Verifier>::PublicKey;
type GenericCtx<P, D> = SimplexContext<D, PublicKeyOf<P>>;
type VerifiedContexts<P, D> = HashMap<(Round, D), Vec<GenericCtx<P, D>>>;
type CertifyVerdicts<D> = HashMap<(Round, D), (usize, bool)>;
type ProposedBlocks<D> = HashSet<(usize, Round, D)>;
type AuditedBlock<D, P> = MockBlock<Sha256Digest, SimplexContext<D, P>>;
type AuditedApplication<D, P> = Application<AuditedBlock<D, P>>;
type AuditedBlocks<D, P> = BTreeMap<Height, Arc<AuditedBlock<D, P>>>;

pub(crate) trait ConsensusParentDigest: Digest {
    fn block_digest(&self) -> Sha256Digest;
}

impl ConsensusParentDigest for Sha256Digest {
    fn block_digest(&self) -> Sha256Digest {
        *self
    }
}

impl ConsensusParentDigest for Commitment {
    fn block_digest(&self) -> Sha256Digest {
        self.block()
    }
}

struct CertificationState<D: Digest> {
    agreement: CertifyVerdicts<D>,
    proposals: ProposedBlocks<D>,
}

impl<D: Digest> Default for CertificationState<D> {
    fn default() -> Self {
        Self {
            agreement: HashMap::new(),
            proposals: HashSet::new(),
        }
    }
}

/// Ensures correct non-inline automata return the same completed certification
/// verdict for the same `(round, digest)`. Direct drivers may also record
/// completed proposals to ensure no marshal choice certifies them as false on
/// the proposing node.
///
/// Inline certification structurally returns `true`, so false-verdict
/// agreement, self-proposal rejection, and certification-poisoning checks are
/// unreachable on Inline stacks. Their split-header coverage is verify-side.
#[derive(Clone)]
pub(crate) struct CertificationAgreementInvariant<D: Digest = Sha256Digest> {
    state: Arc<Mutex<CertificationState<D>>>,
    stack: Arc<str>,
    skip_cross_node_agreement: bool,
}

impl<D: Digest> CertificationAgreementInvariant<D> {
    pub(crate) fn new(stack: Arc<str>, marshal: MarshalChoice) -> Self {
        Self {
            state: Arc::new(Mutex::new(CertificationState::default())),
            stack,
            skip_cross_node_agreement: matches!(marshal, MarshalChoice::Inline),
        }
    }

    pub(crate) fn coding(stack: Arc<str>) -> Self {
        Self {
            state: Arc::new(Mutex::new(CertificationState::default())),
            stack,
            skip_cross_node_agreement: false,
        }
    }

    pub(crate) fn record_proposal(&self, validator: usize, round: Round, digest: D) {
        self.state
            .lock()
            .proposals
            .insert((validator, round, digest));
    }

    pub(crate) fn check_certify_agreement(
        &self,
        validator: usize,
        round: Round,
        digest: D,
        verdict: bool,
    ) {
        let mut state = self.state.lock();
        assert!(
            verdict || !state.proposals.contains(&(validator, round, digest)),
            "marshal automaton certified its own proposal as false: honest node{validator} \
             round={round} digest={digest}; stack={}",
            self.stack,
        );

        if self.skip_cross_node_agreement {
            return;
        }

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

#[derive(Clone, Copy)]
pub(crate) enum MarshalObservation {
    Deferred,
    Inline,
    Coding,
}

impl From<MarshalChoice> for MarshalObservation {
    fn from(marshal: MarshalChoice) -> Self {
        match marshal {
            MarshalChoice::Deferred => Self::Deferred,
            MarshalChoice::Inline => Self::Inline,
        }
    }
}

impl std::fmt::Display for MarshalObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deferred => formatter.write_str("deferred"),
            Self::Inline => formatter.write_str("inline"),
            Self::Coding => formatter.write_str("coding"),
        }
    }
}

/// Ensures a rejection scoped to one proposal header cannot poison
/// certification of the same payload under its embedded header.
pub(crate) struct HeaderMismatchInvariant<
    P: Simplex,
    C: Copy,
    D: ConsensusParentDigest = Sha256Digest,
> {
    verified_contexts: Arc<Mutex<VerifiedContexts<P, D>>>,
    missing_block_contexts: Arc<AtomicUsize>,
    block_contexts: BlockContextRegistry<GenericCtx<P, D>>,
    app_choice: ApplicationChoice,
    app_config: C,
    rejects: fn(ApplicationChoice, C, &GenericCtx<P, D>) -> bool,
    marshal: MarshalObservation,
    stack: Arc<str>,
}

impl<P: Simplex, C: Copy, D: ConsensusParentDigest> Clone for HeaderMismatchInvariant<P, C, D> {
    fn clone(&self) -> Self {
        Self {
            verified_contexts: self.verified_contexts.clone(),
            missing_block_contexts: self.missing_block_contexts.clone(),
            block_contexts: self.block_contexts.clone(),
            app_choice: self.app_choice,
            app_config: self.app_config,
            rejects: self.rejects,
            marshal: self.marshal,
            stack: self.stack.clone(),
        }
    }
}

impl<P: Simplex, C: Copy, D: ConsensusParentDigest> HeaderMismatchInvariant<P, C, D> {
    pub(crate) fn new(
        app_choice: ApplicationChoice,
        app_config: C,
        rejects: fn(ApplicationChoice, C, &GenericCtx<P, D>) -> bool,
        block_contexts: BlockContextRegistry<GenericCtx<P, D>>,
        marshal: MarshalChoice,
        stack: Arc<str>,
    ) -> Self {
        Self {
            verified_contexts: Arc::new(Mutex::new(HashMap::new())),
            missing_block_contexts: Arc::new(AtomicUsize::new(0)),
            block_contexts,
            app_choice,
            app_config,
            rejects,
            marshal: marshal.into(),
            stack,
        }
    }

    pub(crate) fn coding(
        app_choice: ApplicationChoice,
        app_config: C,
        rejects: fn(ApplicationChoice, C, &GenericCtx<P, D>) -> bool,
        block_contexts: BlockContextRegistry<GenericCtx<P, D>>,
        stack: Arc<str>,
    ) -> Self {
        Self {
            verified_contexts: Arc::new(Mutex::new(HashMap::new())),
            missing_block_contexts: Arc::new(AtomicUsize::new(0)),
            block_contexts,
            app_choice,
            app_config,
            rejects,
            marshal: MarshalObservation::Coding,
            stack,
        }
    }

    pub(crate) fn record_verify(&self, context: GenericCtx<P, D>, digest: D) {
        self.verified_contexts
            .lock()
            .entry((context.round, digest))
            .or_default()
            .push(context);
    }

    pub(crate) fn block_context(&self, digest: &D) -> Option<GenericCtx<P, D>> {
        self.block_contexts.get(&digest.block_digest())
    }

    pub(crate) fn verification_mismatch(
        &self,
        context: &GenericCtx<P, D>,
        block_context: &GenericCtx<P, D>,
        digest: D,
    ) -> bool {
        if digest == context.parent.1 {
            return false;
        }
        match self.marshal {
            MarshalObservation::Deferred | MarshalObservation::Coding => block_context != context,
            MarshalObservation::Inline => block_context.parent.1 != context.parent.1,
        }
    }

    pub(crate) fn marshal(&self) -> MarshalObservation {
        self.marshal
    }

    pub(crate) fn stack(&self) -> &str {
        &self.stack
    }

    pub(crate) fn missing_block_contexts(&self) -> usize {
        self.missing_block_contexts.load(Ordering::Relaxed)
    }

    fn observed_mismatch(&self, round: Round, digest: D) -> bool {
        if matches!(self.marshal, MarshalObservation::Inline) {
            return false;
        }
        let Some(block_context) = self.block_context(&digest) else {
            self.missing_block_contexts.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let mismatch = self
            .verified_contexts
            .lock()
            .get(&(round, digest))
            .is_some_and(|contexts| {
                contexts
                    .iter()
                    .any(|context| self.verification_mismatch(context, &block_context, digest))
            });
        mismatch && !(self.rejects)(self.app_choice, self.app_config, &block_context)
    }

    /// Check a completed certification outcome after a header-mismatching verification.
    pub(crate) fn check_certification(&self, round: Round, digest: D, verdict: bool) {
        if verdict {
            return;
        }
        let mismatch = self.observed_mismatch(round, digest);
        assert!(
            !mismatch,
            "marshal invariant violated: certification reused a \
             header-scoped verification rejection; stack={} missing_block_contexts={}",
            self.stack,
            self.missing_block_contexts(),
        );
    }
}

/// Invariant: a certificate backfill answer the requester cannot act on must
/// not retire the fetch.
///
/// A node that accepts a notarization whose block never arrives still needs a
/// certificate for that view: until it has one it can neither vote on nor build
/// a later proposal, so the view must be fetched again. Called once that node
/// has stopped delivering blocks, so the absence of any answer matched to a
/// fresh request for the view is evidence that the fetch was retired by an
/// answer which resolved nothing.
pub(super) fn check_certificate_backfill_retry<P: commonware_cryptography::PublicKey>(
    poison: &CertificatePoison<P>,
    progress: &str,
) {
    let Some(view) = poison.view() else {
        return;
    };
    assert!(
        poison.retries_answered() > 0,
        "marshal certificate backfill starved: a response for view {view} carried a notarization \
         that can never certify, no later request for that view was ever answered, and the node \
         stopped delivering blocks;{progress}"
    );
}

/// Run block-ordering and agreement invariants.
///
/// `floor` is the height every honest node started from (0 for genesis-started
/// clusters); it anchors [`check_in_order`]'s first-delivery check.
pub(crate) fn check_all_blocks<D: ConsensusParentDigest, P: PublicKey>(
    honest_apps: &[(usize, AuditedApplication<D, P>)],
    genesis: Sha256Digest,
    floor: Height,
    stack: Option<&str>,
) {
    let stack = stack.unwrap_or("unspecified");
    for (idx, app) in honest_apps {
        check_local_blocks(*idx, app, genesis, floor, stack);
    }
    agreement(honest_apps, stack);
}

/// Run block-ordering and parent-linkage invariants for one node.
///
/// `floor` is the height the node started from (0 for a genesis-started node).
pub(crate) fn check_local_blocks<D: ConsensusParentDigest, P: PublicKey>(
    idx: usize,
    app: &AuditedApplication<D, P>,
    genesis: Sha256Digest,
    floor: Height,
    stack: &str,
) {
    check_in_order(idx, &app.delivered(), floor, stack);
    check_parent_linkage(idx, &app.blocks(), genesis, stack);
}

/// Invariant: every pair of consecutively delivered blocks is parent-linked.
///
/// [`check_in_order`] runs first and guarantees that after exact duplicate
/// deliveries are collapsed, the by-height snapshot is one contiguous chain.
pub(crate) fn check_parent_linkage<D: ConsensusParentDigest, P: PublicKey>(
    idx: usize,
    blocks: &AuditedBlocks<D, P>,
    genesis: Sha256Digest,
    stack: &str,
) {
    if let Some((height, block)) = blocks.first_key_value() {
        if *height == Height::zero() {
            assert_eq!(
                block.digest(),
                genesis,
                "node{idx} delivered the wrong genesis block: digest={} expected={genesis}; \
                 stack={stack}",
                block.digest(),
            );
        } else {
            assert_eq!(
                block.parent(),
                genesis,
                "node{idx} delivered a chain not rooted at genesis: first_height={} parent={} \
                 expected={genesis}; stack={stack}",
                height.get(),
                block.parent(),
            );
            assert_eq!(
                block.context.parent.1.block_digest(),
                genesis,
                "node{idx} delivered a chain whose first embedded consensus parent is not \
                 genesis: first_height={} context_parent={} expected={genesis}; stack={stack}",
                height.get(),
                block.context.parent.1.block_digest(),
            );
        }
    }

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
        assert_eq!(
            next.context.parent.1.block_digest(),
            block.digest(),
            "node{idx} delivered a chain with a broken embedded consensus parent: height {} \
             digest={} but height {} context_parent={}; stack={stack}",
            height.get(),
            block.digest(),
            next_height.get(),
            next.context.parent.1.block_digest(),
        );
        assert!(
            next.context.round > block.context.round,
            "node{idx} delivered a chain with non-increasing consensus rounds: height {} \
             round={} but height {} round={}; stack={stack}",
            height.get(),
            block.context.round,
            next_height.get(),
            next.context.round,
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
    let Some(acknowledged_through) = height.get().checked_sub(max_pending_acks.get() as u64) else {
        return;
    };
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
/// Walks the arrival-ordered delivery log. The first delivery must be either
/// height 0 (the anchor block surfaced on a fresh start) or the node's floor
/// height: a genesis-started node has floor 0, whose first finalized container
/// is height 1, while a node started from a floor at height `H` (via
/// `Start::Floor` or `set_floor`) delivers that anchor block at `H` first. Every
/// subsequent delivery must advance by exactly one or repeat the identical
/// `(height, digest)`. Because delivery is at-least-once, any number of exact
/// duplicates is allowed; an out-of-order delivery, gap, or same-height fork
/// fails the check.
fn check_in_order<D: Debug + PartialEq>(
    idx: usize,
    delivered: &[(Height, D)],
    floor: Height,
    stack: &str,
) {
    // A genesis-started node (floor 0) accepts a first delivery at height 0 or
    // 1; a node started above genesis at floor `H` accepts 0 or `H`. `max(1)`
    // keeps the genesis floor's anchor at 1, so genesis nodes behave exactly as
    // before.
    let anchor = floor.get().max(1);
    let first = delivered.first().map_or(0, |(height, _)| height.get());
    assert!(
        first == 0 || first == anchor,
        "node{idx} first delivery at height {first} is neither genesis (0) nor the floor \
         anchor {anchor}; sequence={delivered:?}; stack={stack}",
    );
    for window in delivered.windows(2) {
        let (height_0, digest_0) = &window[0];
        let (height_1, digest_1) = &window[1];
        if height_1 == height_0 && digest_1 == digest_0 {
            continue;
        }
        assert!(
            height_0.get().checked_add(1) == Some(height_1.get()),
            "node{idx} violated in-order delivery (out-of-order, gap, or same-height fork): \
             previous_height={} next_height={}; sequence={delivered:?}; stack={stack}",
            height_0.get(),
            height_1.get(),
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
/// and permits exact duplicates at one height. Given that, requiring one digest
/// per height across all honest delivery logs and current tips is
/// equivalent to pairwise prefix compatibility and also checks that a tip
/// agrees with any delivered block at the same height. Heights are used instead
/// of raw sequence indexes because a fresh application may surface genesis at
/// height 0 or begin with the first finalized block at height 1.
///
/// This detects conflicting finalization, fork divergence, and recovery that
/// delivers a different block at an already observed height.
pub(crate) fn agreement<B: Block<Digest = Sha256Digest>>(
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

/// The phase discipline a scenario must keep for its liveness verdict to mean
/// anything.
///
/// GST must leave every directed link up, after it no correct node's message
/// may be withheld, and no answer to the victim's certificate backfill may be
/// withheld at any point: a byzantine answer has to win by delivery order, not
/// by the harness silencing the alternatives.
pub(super) fn check_scenario_phases(outcome: &ScenarioOutcome) {
    assert!(
        outcome.unhealed_links.is_empty(),
        "GST must heal every link, still down={:?}",
        outcome.unhealed_links
    );
    assert_eq!(
        outcome.honest_drops_post_gst, 0,
        "post-GST honest-message drops must be zero, ledger={:?}",
        outcome.ledger
    );
    assert_eq!(
        outcome.resolver_drops, 0,
        "certificate-backfill answers must never be withheld, ledger={:?}",
        outcome.ledger
    );
}

/// Post-GST liveness, measured from each correct node's height at GST.
///
/// With one byzantine node out of four, quorum three, and every link healed,
/// every correct node must deliver one more finalized block than it held at
/// GST. A run that finalized before GST and stalled afterwards therefore fails
/// here even though its heights are nonzero. A node already at the single-epoch
/// boundary this harness can deliver is only required to hold its height.
/// Returns the stall diagnostic when the window closes short.
pub(super) fn scenario_progress(outcome: &ScenarioOutcome) -> Result<(), String> {
    let stalled: Vec<String> = outcome
        .baselines
        .iter()
        .filter_map(|(label, baseline)| {
            let target = ScenarioOutcome::target(*baseline);
            let current = outcome.height(label);
            (current < target).then(|| {
                format!("{label}{{baseline={baseline} target={target} current={current}}}")
            })
        })
        .collect();
    if stalled.is_empty() {
        return Ok(());
    }
    Err(format!(
        "no post-GST progress within {SETTLE:?}: template={} actions={} forwarding={:?} \
         byzantine_policy={:?} stalled={stalled:?} heights={:?} baselines={:?} \
         honest_drops(pre/post)={}/{} byzantine_withholds={} attack_payload={:?} \
         victim_attack_view_requests={} observations={}",
        outcome.template.as_str(),
        outcome.actions,
        outcome.forwarding,
        outcome.byzantine_policy,
        outcome.heights,
        outcome.baselines,
        outcome.honest_drops_pre_gst,
        outcome.honest_drops_post_gst,
        outcome.byzantine_withholds,
        outcome.attack_payload,
        outcome.requests.len(),
        outcome.events.len()
    ))
}

/// Panicking form of [`scenario_progress`]: the crash oracle of the scenario
/// target.
pub(super) fn check_scenario_progress(outcome: &ScenarioOutcome) {
    if let Err(diagnostic) = scenario_progress(outcome) {
        panic!("marshal scenario: {diagnostic}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SimplexCertificateMock, simplex_certificate_mock};
    use commonware_consensus::{
        Reporter as _,
        marshal::{
            Update,
            mocks::block::{Block as MockBlock, EmptyBlock},
        },
        types::{Epoch, View},
    };
    use commonware_cryptography::{Sha256, ed25519::PublicKey as Ed25519PublicKey};
    use commonware_utils::{Acknowledgement as _, NZUsize, acknowledgement::Exact, test_rng};

    type TestContext = SimplexContext<Sha256Digest, Ed25519PublicKey>;
    type ContextBlock = MockBlock<Sha256Digest, TestContext>;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    fn leader() -> Ed25519PublicKey {
        simplex_certificate_mock::fixture_with::<false, true, true, _>(
            &mut test_rng(),
            b"marshal-invariants",
            1,
        )
        .participants
        .remove(0)
    }

    fn context(view: u64, parent: Sha256Digest) -> TestContext {
        TestContext {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader: leader(),
            parent: (View::new(view.saturating_sub(1)), parent),
        }
    }

    fn commitment(byte: u8) -> Commitment {
        Commitment::from((
            digest(byte),
            digest(byte.wrapping_add(1)),
            digest(byte.wrapping_add(2)),
            commonware_consensus::marshal::mocks::harness::GENESIS_CODING_CONFIG,
        ))
    }

    fn coding_context(
        view: u64,
        parent: Commitment,
    ) -> SimplexContext<Commitment, Ed25519PublicKey> {
        SimplexContext {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader: leader(),
            parent: (View::new(view.saturating_sub(1)), parent),
        }
    }

    fn block(
        view: u64,
        context_parent: Sha256Digest,
        parent: Sha256Digest,
        height: u64,
    ) -> ContextBlock {
        ContextBlock::new::<Sha256>(
            context(view, context_parent),
            parent,
            Height::new(height),
            height,
        )
    }

    #[test]
    fn exact_duplicate_delivery_is_allowed() {
        check_in_order(
            0,
            &[
                (Height::new(1), digest(0xA)),
                (Height::new(1), digest(0xA)),
                (Height::new(2), digest(0xB)),
            ],
            Height::zero(),
            "test",
        );
    }

    #[test]
    fn repeated_duplicate_delivery_is_allowed() {
        check_in_order(
            0,
            &[
                (Height::new(1), digest(0xA)),
                (Height::new(1), digest(0xA)),
                (Height::new(1), digest(0xA)),
            ],
            Height::zero(),
            "test",
        );
    }

    #[test]
    #[should_panic(expected = "same-height fork")]
    fn same_height_different_digest_is_rejected() {
        check_in_order(
            0,
            &[(Height::new(1), digest(0xA)), (Height::new(1), digest(0xB))],
            Height::zero(),
            "test",
        );
    }

    #[test]
    #[should_panic(expected = "in-order delivery")]
    fn delivery_gap_is_rejected() {
        check_in_order(
            0,
            &[(Height::new(1), digest(0xA)), (Height::new(3), digest(0xB))],
            Height::zero(),
            "test",
        );
    }

    #[test]
    fn floor_started_delivery_from_floor_is_allowed() {
        // A node started from a floor at height 5 delivers its anchor block at
        // height 5 first, then advances contiguously.
        check_in_order(
            0,
            &[
                (Height::new(5), digest(0xA)),
                (Height::new(6), digest(0xB)),
                (Height::new(7), digest(0xC)),
            ],
            Height::new(5),
            "test",
        );
    }

    #[test]
    #[should_panic(expected = "in-order delivery")]
    fn floor_started_gap_above_floor_is_rejected() {
        // First delivery at the floor is accepted; the jump to height 7 skips 6.
        check_in_order(
            0,
            &[(Height::new(5), digest(0xA)), (Height::new(7), digest(0xB))],
            Height::new(5),
            "test",
        );
    }

    #[test]
    #[should_panic(expected = "floor anchor")]
    fn floor_started_delivery_below_floor_is_rejected() {
        // A node with floor 5 must not deliver first below its floor.
        check_in_order(
            0,
            &[(Height::new(3), digest(0xA)), (Height::new(4), digest(0xB))],
            Height::new(5),
            "test",
        );
    }

    #[test]
    fn genesis_started_delivery_is_unchanged() {
        // Floor 0 accepts a first delivery at genesis (0) or the first finalized
        // container (1), exactly as before the floor generalization.
        check_in_order(
            0,
            &[(Height::zero(), digest(0xA)), (Height::new(1), digest(0xB))],
            Height::zero(),
            "test",
        );
        check_in_order(
            0,
            &[(Height::new(1), digest(0xA)), (Height::new(2), digest(0xB))],
            Height::zero(),
            "test",
        );
    }

    #[test]
    #[should_panic(expected = "not rooted at genesis")]
    fn wrong_chain_root_is_rejected() {
        let genesis = digest(0xA);
        let first = block(1, genesis, digest(0xB), 1);
        let blocks = BTreeMap::from([(Height::new(1), Arc::new(first))]);

        check_parent_linkage(0, &blocks, genesis, "test");
    }

    #[test]
    #[should_panic(expected = "broken embedded consensus parent")]
    fn embedded_parent_linkage_is_checked() {
        let genesis = digest(0xA);
        let first = block(1, genesis, genesis, 1);
        let second = block(2, digest(0xB), first.digest(), 2);
        let blocks = BTreeMap::from([
            (Height::new(1), Arc::new(first)),
            (Height::new(2), Arc::new(second)),
        ]);

        check_parent_linkage(0, &blocks, genesis, "test");
    }

    #[test]
    #[should_panic(expected = "non-increasing consensus rounds")]
    fn consensus_rounds_must_increase() {
        let genesis = digest(0xA);
        let first = block(2, genesis, genesis, 1);
        let second = block(2, first.digest(), first.digest(), 2);
        let blocks = BTreeMap::from([
            (Height::new(1), Arc::new(first)),
            (Height::new(2), Arc::new(second)),
        ]);

        check_parent_linkage(0, &blocks, genesis, "test");
    }

    #[test]
    fn pending_ack_boundary_below_window_is_vacuous() {
        type TestBlock = EmptyBlock<Sha256>;

        let mut application = Application::<TestBlock>::manual_ack();
        let block = TestBlock::new(digest(0), Height::zero(), 0);
        let (ack, _waiter) = Exact::handle();
        application.report(Update::Block(Arc::new(block), ack));

        check_pending_acks(0, &application, Height::new(1), NZUsize!(2), "test");
    }

    #[test]
    #[should_panic(expected = "max_pending_acks backpressure violated")]
    fn pending_ack_at_window_boundary_is_rejected() {
        type TestBlock = EmptyBlock<Sha256>;

        let mut application = Application::<TestBlock>::manual_ack();
        let block = TestBlock::new(digest(0), Height::zero(), 0);
        let (ack, _waiter) = Exact::handle();
        application.report(Update::Block(Arc::new(block), ack));

        check_pending_acks(0, &application, Height::new(2), NZUsize!(2), "test");
    }

    #[test]
    #[should_panic(expected = "max_pending_acks backpressure violated")]
    fn pending_ack_deep_window_is_reachable() {
        type TestBlock = EmptyBlock<Sha256>;

        let mut application = Application::<TestBlock>::manual_ack();
        let block = TestBlock::new(digest(0), Height::zero(), 0);
        let (ack, _waiter) = Exact::handle();
        application.report(Update::Block(Arc::new(block), ack));

        check_pending_acks(0, &application, Height::new(8), NZUsize!(8), "test");
    }

    #[test]
    fn missing_block_context_is_an_incomplete_observation() {
        let invariant = HeaderMismatchInvariant::<SimplexCertificateMock, ()>::new(
            ApplicationChoice::AlwaysAccept,
            (),
            |_, _, _| false,
            BlockContextRegistry::default(),
            MarshalChoice::Deferred,
            "test".into(),
        );

        assert!(!invariant.observed_mismatch(Round::zero(), digest(0xA)));
        assert_eq!(invariant.missing_block_contexts(), 1);
    }

    #[test]
    fn certification_mismatch_ignores_parent_digest_reproposal() {
        let registry = BlockContextRegistry::default();
        let payload = digest(0xA);
        let embedded = context(2, digest(0xB));
        registry.record(payload, embedded.clone());
        let invariant = HeaderMismatchInvariant::<SimplexCertificateMock, ()>::new(
            ApplicationChoice::AlwaysAccept,
            (),
            |_, _, _| false,
            registry,
            MarshalChoice::Deferred,
            "test".into(),
        );
        let mut reproposal = embedded;
        reproposal.parent.0 = View::zero();
        reproposal.parent.1 = payload;
        invariant.record_verify(reproposal, payload);

        assert!(!invariant.observed_mismatch(Round::new(Epoch::zero(), View::new(2)), payload,));
    }

    #[test]
    fn certification_mismatch_is_deferred_only() {
        let registry = BlockContextRegistry::default();
        let payload = digest(0xA);
        let embedded = context(2, digest(0xB));
        registry.record(payload, embedded.clone());
        let invariant = HeaderMismatchInvariant::<SimplexCertificateMock, ()>::new(
            ApplicationChoice::AlwaysAccept,
            (),
            |_, _, _| false,
            registry,
            MarshalChoice::Inline,
            "test".into(),
        );
        let mut mutated = embedded;
        mutated.parent.0 = View::zero();
        invariant.record_verify(mutated, payload);

        assert!(!invariant.observed_mismatch(Round::new(Epoch::zero(), View::new(2)), payload,));
    }

    #[test]
    fn certification_mismatch_detects_deferred_header_poison() {
        let registry = BlockContextRegistry::default();
        let payload = digest(0xA);
        let embedded = context(2, digest(0xB));
        registry.record(payload, embedded.clone());
        let invariant = HeaderMismatchInvariant::<SimplexCertificateMock, ()>::new(
            ApplicationChoice::AlwaysAccept,
            (),
            |_, _, _| false,
            registry,
            MarshalChoice::Deferred,
            "test".into(),
        );
        let mut mutated = embedded;
        mutated.parent.0 = View::zero();
        invariant.record_verify(mutated, payload);

        assert!(invariant.observed_mismatch(Round::new(Epoch::zero(), View::new(2)), payload,));
    }

    #[test]
    fn certification_mismatch_detects_coding_header_poison() {
        let registry = BlockContextRegistry::default();
        let payload = commitment(0xA);
        let embedded = coding_context(2, commitment(0xB));
        registry.record(payload.block(), embedded.clone());
        let invariant = HeaderMismatchInvariant::<SimplexCertificateMock, (), Commitment>::coding(
            ApplicationChoice::AlwaysAccept,
            (),
            |_, _, _| false,
            registry,
            "test".into(),
        );
        let mut mutated = embedded;
        mutated.parent.0 = View::zero();
        invariant.record_verify(mutated, payload);

        assert!(invariant.observed_mismatch(Round::new(Epoch::zero(), View::new(2)), payload,));
    }

    #[test]
    fn inline_certification_disagreement_is_allowed() {
        let invariant = CertificationAgreementInvariant::new("test".into(), MarshalChoice::Inline);
        invariant.check_certify_agreement(0, Round::zero(), digest(0xA), true);
        invariant.check_certify_agreement(1, Round::zero(), digest(0xA), false);
    }

    #[test]
    #[should_panic(expected = "certify agreement violated")]
    fn deferred_certification_disagreement_is_rejected() {
        let invariant =
            CertificationAgreementInvariant::new("test".into(), MarshalChoice::Deferred);
        invariant.check_certify_agreement(0, Round::zero(), digest(0xA), true);
        invariant.check_certify_agreement(1, Round::zero(), digest(0xA), false);
    }

    #[test]
    #[should_panic(expected = "certify agreement violated")]
    fn coding_certification_disagreement_is_rejected() {
        let invariant = CertificationAgreementInvariant::coding("test".into());
        invariant.check_certify_agreement(0, Round::zero(), commitment(0xA), true);
        invariant.check_certify_agreement(1, Round::zero(), commitment(0xA), false);
    }

    #[test]
    #[should_panic(expected = "certified its own proposal as false")]
    fn inline_self_proposal_clause_remains_unconditional() {
        let invariant = CertificationAgreementInvariant::new("test".into(), MarshalChoice::Inline);
        invariant.record_proposal(0, Round::zero(), digest(0xA));
        invariant.check_certify_agreement(0, Round::zero(), digest(0xA), false);
    }
}
