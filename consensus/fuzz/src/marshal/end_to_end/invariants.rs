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
    twins::stack::MarshalChoice,
};
use crate::simplex::Simplex;
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
type Ctx<P> = SimplexContext<Sha256Digest, PublicKeyOf<P>>;
type VerifiedContexts<P> = HashMap<(Round, Sha256Digest), Vec<Ctx<P>>>;
type CertifyVerdicts = HashMap<(Round, Sha256Digest), (usize, bool)>;
type ProposedBlocks = HashSet<(usize, Round, Sha256Digest)>;
type AuditedBlock<D, P> = MockBlock<Sha256Digest, SimplexContext<D, P>>;
type AuditedApplication<D, P> = Application<AuditedBlock<D, P>>;
type AuditedBlocks<D, P> = BTreeMap<Height, Arc<AuditedBlock<D, P>>>;

pub(super) trait ConsensusParentDigest: Digest {
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

#[derive(Default)]
struct CertificationState {
    agreement: CertifyVerdicts,
    proposals: ProposedBlocks,
}

/// Ensures correct deferred automata return the same completed certification
/// verdict for the same `(round, digest)`. Direct drivers may also record
/// completed proposals to ensure no marshal choice certifies them as false on
/// the proposing node.
#[derive(Clone)]
pub(crate) struct CertificationAgreementInvariant {
    state: Arc<Mutex<CertificationState>>,
    stack: Arc<str>,
    marshal: MarshalChoice,
}

impl CertificationAgreementInvariant {
    pub(crate) fn new(stack: Arc<str>, marshal: MarshalChoice) -> Self {
        Self {
            state: Arc::new(Mutex::new(CertificationState::default())),
            stack,
            marshal,
        }
    }

    pub(crate) fn record_proposal(&self, validator: usize, round: Round, digest: Sha256Digest) {
        self.state
            .lock()
            .proposals
            .insert((validator, round, digest));
    }

    pub(crate) fn check_certify_agreement(
        &self,
        validator: usize,
        round: Round,
        digest: Sha256Digest,
        verdict: bool,
    ) {
        let mut state = self.state.lock();
        assert!(
            verdict || !state.proposals.contains(&(validator, round, digest)),
            "marshal automaton certified its own proposal as false: honest node{validator} \
             round={round} digest={digest}; stack={}",
            self.stack,
        );

        if matches!(self.marshal, MarshalChoice::Inline) {
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

/// Ensures a rejection scoped to one proposal header cannot poison
/// certification of the same payload under its embedded header.
pub(super) struct HeaderMismatchInvariant<P: Simplex, C: Copy> {
    verified_contexts: Arc<Mutex<VerifiedContexts<P>>>,
    missing_block_contexts: Arc<AtomicUsize>,
    block_contexts: BlockContextRegistry<Ctx<P>>,
    app_choice: ApplicationChoice,
    app_config: C,
    rejects: fn(ApplicationChoice, C, &Ctx<P>) -> bool,
    marshal: MarshalChoice,
    stack: Arc<str>,
}

impl<P: Simplex, C: Copy> Clone for HeaderMismatchInvariant<P, C> {
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

impl<P: Simplex, C: Copy> HeaderMismatchInvariant<P, C> {
    pub(super) fn new(
        app_choice: ApplicationChoice,
        app_config: C,
        rejects: fn(ApplicationChoice, C, &Ctx<P>) -> bool,
        block_contexts: BlockContextRegistry<Ctx<P>>,
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
            marshal,
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

    pub(super) const fn marshal(&self) -> MarshalChoice {
        self.marshal
    }

    pub(super) fn stack(&self) -> &str {
        &self.stack
    }

    pub(super) fn missing_block_contexts(&self) -> usize {
        self.missing_block_contexts.load(Ordering::Relaxed)
    }

    fn observed_mismatch(&self, round: Round, digest: Sha256Digest) -> bool {
        let Some(block_context) = self.block_context(&digest) else {
            self.missing_block_contexts.fetch_add(1, Ordering::Relaxed);
            return false;
        };
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
             header-scoped verification rejection; stack={} missing_block_contexts={}",
            self.stack,
            self.missing_block_contexts(),
        );
    }
}

/// Run block-ordering and agreement invariants.
pub(super) fn check_all_blocks<D: ConsensusParentDigest, P: PublicKey>(
    honest_apps: &[(usize, AuditedApplication<D, P>)],
    genesis: Sha256Digest,
    stack: Option<&str>,
) {
    let stack = stack.unwrap_or("unspecified");
    for (idx, app) in honest_apps {
        check_local_blocks(*idx, app, genesis, stack);
    }
    agreement(honest_apps, stack);
}

/// Run block-ordering and parent-linkage invariants for one node.
pub(super) fn check_local_blocks<D: ConsensusParentDigest, P: PublicKey>(
    idx: usize,
    app: &AuditedApplication<D, P>,
    genesis: Sha256Digest,
    stack: &str,
) {
    check_in_order(idx, &app.delivered(), stack);
    check_parent_linkage(idx, &app.blocks(), genesis, stack);
}

/// Invariant: every pair of consecutively delivered blocks is parent-linked.
///
/// [`check_in_order`] runs first and guarantees that after exact duplicate
/// deliveries are collapsed, the by-height snapshot is one contiguous chain.
fn check_parent_linkage<D: ConsensusParentDigest, P: PublicKey>(
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
/// Walks the arrival-ordered delivery log. Delivery starts either at the
/// genesis floor block (height 0, surfaced on a fresh start) or at the first
/// finalized container (height 1), then every subsequent delivery must advance
/// by exactly one or repeat the identical `(height, digest)` once. Because this
/// is the true arrival sequence, an out-of-order delivery, a gap, repeated
/// duplicate, or same-height fork fails the check.
fn check_in_order<D: Debug + PartialEq>(idx: usize, delivered: &[(Height, D)], stack: &str) {
    let first = delivered.first().map_or(0, |(height, _)| height.get());
    assert!(
        first <= 1,
        "node{idx} first delivery at height {first} is above the genesis floor + 1; \
         sequence={delivered:?}; stack={stack}",
    );
    let mut previous_was_duplicate = false;
    for window in delivered.windows(2) {
        let (height_0, digest_0) = &window[0];
        let (height_1, digest_1) = &window[1];
        if height_1 == height_0 && digest_1 == digest_0 {
            assert!(
                !previous_was_duplicate,
                "node{idx} delivered more than one duplicate at height {}; \
                 sequence={delivered:?}; stack={stack}",
                height_1.get(),
            );
            previous_was_duplicate = true;
            continue;
        }
        previous_was_duplicate = false;
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
/// and permits at most one exact duplicate at one height. Given that, requiring
/// one digest per height across all honest delivery logs and current tips is
/// equivalent to pairwise prefix compatibility and also checks that a tip
/// agrees with any delivered block at the same height. Heights are used instead
/// of raw sequence indexes because a fresh application may surface genesis at
/// height 0 or begin with the first finalized block at height 1.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SimplexId, id_mock};
    use commonware_consensus::{
        Reporter as _,
        marshal::{Update, mocks::block::Block as MockBlock},
        types::{Epoch, View},
    };
    use commonware_cryptography::Sha256;
    use commonware_utils::{Acknowledgement as _, NZUsize, acknowledgement::Exact};

    type TestContext = SimplexContext<Sha256Digest, id_mock::PublicKey>;
    type ContextBlock = MockBlock<Sha256Digest, TestContext>;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    fn context(view: u64, parent: Sha256Digest) -> TestContext {
        TestContext {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader: id_mock::PublicKey::from_index(0),
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
            "test",
        );
    }

    #[test]
    #[should_panic(expected = "more than one duplicate")]
    fn more_than_one_duplicate_delivery_is_rejected() {
        check_in_order(
            0,
            &[
                (Height::new(1), digest(0xA)),
                (Height::new(1), digest(0xA)),
                (Height::new(1), digest(0xA)),
            ],
            "test",
        );
    }

    #[test]
    #[should_panic(expected = "same-height fork")]
    fn same_height_different_digest_is_rejected() {
        check_in_order(
            0,
            &[(Height::new(1), digest(0xA)), (Height::new(1), digest(0xB))],
            "test",
        );
    }

    #[test]
    #[should_panic(expected = "in-order delivery")]
    fn delivery_gap_is_rejected() {
        check_in_order(
            0,
            &[(Height::new(1), digest(0xA)), (Height::new(3), digest(0xB))],
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
        type TestBlock = MockBlock<Sha256Digest, ()>;

        let mut application = Application::<TestBlock>::manual_ack();
        let block = TestBlock::new::<Sha256>((), digest(0), Height::zero(), 0);
        let (ack, _waiter) = Exact::handle();
        application.report(Update::Block(Arc::new(block), ack));

        check_pending_acks(0, &application, Height::new(1), NZUsize!(2), "test");
    }

    #[test]
    #[should_panic(expected = "max_pending_acks backpressure violated")]
    fn pending_ack_at_window_boundary_is_rejected() {
        type TestBlock = MockBlock<Sha256Digest, ()>;

        let mut application = Application::<TestBlock>::manual_ack();
        let block = TestBlock::new::<Sha256>((), digest(0), Height::zero(), 0);
        let (ack, _waiter) = Exact::handle();
        application.report(Update::Block(Arc::new(block), ack));

        check_pending_acks(0, &application, Height::new(2), NZUsize!(2), "test");
    }

    #[test]
    fn missing_block_context_is_an_incomplete_observation() {
        let invariant = HeaderMismatchInvariant::<SimplexId, ()>::new(
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
    #[should_panic(expected = "certified its own proposal as false")]
    fn inline_self_proposal_clause_remains_unconditional() {
        let invariant = CertificationAgreementInvariant::new("test".into(), MarshalChoice::Inline);
        invariant.record_proposal(0, Round::zero(), digest(0xA));
        invariant.check_certify_agreement(0, Round::zero(), digest(0xA), false);
    }
}
