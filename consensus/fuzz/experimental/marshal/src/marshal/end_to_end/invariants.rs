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
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::{
    Block, CertifiableBlock, Handoff,
    marshal::mocks::application::Application,
    simplex::types::Context as SimplexContext,
    types::{Height, Round, TermLength, ViewDelta, coding::Commitment},
};
use commonware_consensus_fuzz_core::{network::CertificatePoison, reach, simplex::Simplex};
use commonware_cryptography::{
    Digest, Digestible, Hasher, PublicKey, sha256::Digest as Sha256Digest,
};
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
type Certifiers<D> = HashMap<(Round, D), HashSet<usize>>;
/// The honest voters of a payload, each with how it stood on the payload's
/// parent when it voted.
type Voters<D> = HashMap<(Round, D), HashMap<usize, VoterStanding>>;

/// How an honest voter of a payload stood on the payload's parent when it voted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VoterStanding {
    /// The incoming leader's early vote from a `Vote` handoff, which marshal
    /// requests only over an uncertified parent.
    EarlyLeader,
    Certified,
    Uncertified,
}

/// Labels an honest node's application prepare (marshal's Build branch) counts
/// under, by the decision it answers.
pub const PREPARE_WAIT: &str = "prepare_wait";
pub const PREPARE_STAGE: &str = "prepare_stage";
pub const PREPARE_VOTE: &str = "prepare_vote";
/// Label an honest node's staged boundary re-proposal counts under.
pub const PREPARE_REUSE: &str = "prepare_reuse";
/// Label a proposal an honest node is asked to verify in a view its application
/// rejects counts under. Honest proposers skip such views, so the proposal is the
/// byzantine node's.
pub const REJECTED_VIEW_OFFER: &str = "rejected_view_offer";
/// Label an honest leader's early vote whose parent sits in a view its
/// application rejects counts under: the uncertified handoff parent is a block
/// the application rejects.
pub const REJECTED_PARENT_VOTE: &str = "rejected_parent_vote";
/// Label an honest leader's early vote whose parent the compromised proposer
/// corrupted counts under.
pub const CORRUPTED_PARENT_VOTE: &str = "corrupted_parent_vote";
/// Label a term-start child notarized at an honest node while exactly one honest
/// node had certified its parent counts under.
pub const SINGLE_CERTIFIER_TERM_START: &str = "term_start_single_certifier";
/// Label a term-start child notarized at an honest node after its leader's early
/// vote, with exactly one honest voter that had certified its parent when it
/// voted, counts under: the handoff composition where the child's quorum carries
/// a single honest certifier of the outgoing term's last block.
pub const SINGLE_CERTIFIER_QUORUM: &str = "term_start_single_certifier_quorum";

/// Whether a run's end-of-run oracle also demands post-GST progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Liveness {
    /// A run that stalls after GST fails.
    Checked,
    /// A stall is allowed by contract (an early handoff trusts the outgoing
    /// leader): the run checks safety only.
    SafetyOnly,
}

impl Liveness {
    /// The decision for a run whose handoff, lookahead and term length are
    /// sampled: only the pinned configuration (`Wait`, no lookahead, single-view
    /// terms) keeps the liveness check.
    pub(crate) fn sampled(
        handoff: Handoff<()>,
        optimistic_views: ViewDelta,
        term_length: TermLength,
    ) -> Self {
        if handoff.is_wait() && optimistic_views.is_zero() && term_length == TermLength::ONE {
            Self::Checked
        } else {
            Self::SafetyOnly
        }
    }
}

pub(crate) trait ConsensusParentDigest: Digest {
    fn block_digest(&self) -> Sha256Digest;
}

impl ConsensusParentDigest for Sha256Digest {
    fn block_digest(&self) -> Sha256Digest {
        *self
    }
}

impl<B: Digestible<Digest = Sha256Digest>, C: CodingScheme, H: Hasher> ConsensusParentDigest
    for Commitment<B, C, H>
{
    fn block_digest(&self) -> Sha256Digest {
        self.block()
    }
}

struct CertificationState<D: Digest> {
    agreement: CertifyVerdicts<D>,
    proposals: ProposedBlocks<D>,
    /// The honest nodes whose certification of a payload returned true.
    certifiers: Certifiers<D>,
    voters: Voters<D>,
}

impl<D: Digest> Default for CertificationState<D> {
    fn default() -> Self {
        Self {
            agreement: HashMap::new(),
            proposals: HashSet::new(),
            certifiers: HashMap::new(),
            voters: HashMap::new(),
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
    term_length: TermLength,
}

impl<D: Digest> CertificationAgreementInvariant<D> {
    pub(crate) fn new(stack: Arc<str>, marshal: MarshalChoice, term_length: TermLength) -> Self {
        Self {
            state: Arc::new(Mutex::new(CertificationState::default())),
            stack,
            skip_cross_node_agreement: matches!(marshal, MarshalChoice::Inline),
            term_length,
        }
    }

    pub(crate) fn coding(stack: Arc<str>, term_length: TermLength) -> Self {
        Self {
            state: Arc::new(Mutex::new(CertificationState::default())),
            stack,
            skip_cross_node_agreement: false,
            term_length,
        }
    }

    /// Records honest `validator`'s early vote for `digest` in `child`, answered
    /// to a handoff over an uncertified parent.
    pub(crate) fn record_early_vote(&self, validator: usize, child: Round, digest: D) {
        self.state
            .lock()
            .voters
            .entry((child, digest))
            .or_default()
            .insert(validator, VoterStanding::EarlyLeader);
    }

    /// Records that honest `validator` votes for `digest` in `child`, whose parent
    /// is `parent`, noting whether it has certified that parent by now.
    pub(crate) fn record_vote(
        &self,
        validator: usize,
        child: Round,
        digest: D,
        parent: (Round, D),
    ) {
        let mut state = self.state.lock();
        let standing = if state
            .certifiers
            .get(&parent)
            .is_some_and(|certifiers| certifiers.contains(&validator))
        {
            VoterStanding::Certified
        } else {
            VoterStanding::Uncertified
        };
        state
            .voters
            .entry((child, digest))
            .or_default()
            .insert(validator, standing);
    }

    /// Records that an honest node holds a notarization of `digest` in `child`,
    /// whose parent is `parent`. A term-start child notarized while exactly one
    /// honest node has certified its parent counts under
    /// [SINGLE_CERTIFIER_TERM_START]; one voted for early by its leader whose
    /// other recorded honest voters include exactly one that had certified the
    /// parent when it voted counts under [SINGLE_CERTIFIER_QUORUM].
    pub(crate) fn record_notarized(&self, child: Round, digest: D, parent: (Round, D)) {
        if !child.view().is_term_start(self.term_length) {
            return;
        }
        let state = self.state.lock();
        if state
            .certifiers
            .get(&parent)
            .is_some_and(|certifiers| certifiers.len() == 1)
        {
            reach::record(SINGLE_CERTIFIER_TERM_START);
        }
        if state.voters.get(&(child, digest)).is_some_and(|voters| {
            let standing = |wanted: VoterStanding| {
                voters
                    .values()
                    .filter(|standing| **standing == wanted)
                    .count()
            };
            standing(VoterStanding::EarlyLeader) == 1 && standing(VoterStanding::Certified) == 1
        }) {
            reach::record(SINGLE_CERTIFIER_QUORUM);
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
        if verdict {
            state
                .certifiers
                .entry((round, digest))
                .or_default()
                .insert(validator);
        }

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

    /// Whether the honest applications reject every block proposed under `context`.
    pub(crate) fn rejects_context(&self, context: &GenericCtx<P, D>) -> bool {
        (self.rejects)(self.app_choice, self.app_config, context)
    }

    /// Whether the compromised proposer corrupted the block behind `digest`.
    pub(crate) fn corrupted(&self, digest: &D) -> bool {
        self.block_contexts.is_corrupted(&digest.block_digest())
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
/// clusters); it anchors [`check_in_order`]'s first-delivery check. `rejects`
/// is the honest applications' rejection predicate (see
/// [`check_no_rejected_delivery`]).
pub(crate) fn check_all_blocks<B, D, K>(
    honest_apps: &[(usize, Application<B>)],
    genesis: Sha256Digest,
    floor: Height,
    rejects: &dyn Fn(&SimplexContext<D, K>) -> bool,
    stack: Option<&str>,
) where
    B: CertifiableBlock<Digest = Sha256Digest, Context = SimplexContext<D, K>>,
    D: ConsensusParentDigest,
    K: PublicKey,
{
    let stack = stack.unwrap_or("unspecified");
    for (idx, app) in honest_apps {
        check_local_blocks(*idx, app, genesis, floor, rejects, stack);
    }
    agreement(honest_apps, stack);
}

/// Run block-ordering, parent-linkage and rejected-delivery invariants for one
/// node.
///
/// `floor` is the height the node started from (0 for a genesis-started node).
pub(crate) fn check_local_blocks<B, D, K>(
    idx: usize,
    app: &Application<B>,
    genesis: Sha256Digest,
    floor: Height,
    rejects: &dyn Fn(&SimplexContext<D, K>) -> bool,
    stack: &str,
) where
    B: CertifiableBlock<Digest = Sha256Digest, Context = SimplexContext<D, K>>,
    D: ConsensusParentDigest,
    K: PublicKey,
{
    check_in_order(idx, &app.delivered(), floor, stack);
    check_parent_linkage(idx, &app.blocks(), genesis, floor, stack);
    check_no_rejected_delivery(idx, &app.blocks(), rejects, stack);
}

/// Invariant: no node delivers a finalized block its own application rejects.
///
/// Honest proposers skip the contexts their application rejects, so such a
/// block came from the byzantine node, and its finalization means a
/// certification bypassed the application's verdict. The height-0 anchor
/// predates every verdict.
pub(crate) fn check_no_rejected_delivery<B, D, K>(
    idx: usize,
    blocks: &BTreeMap<Height, Arc<B>>,
    rejects: &dyn Fn(&SimplexContext<D, K>) -> bool,
    stack: &str,
) where
    B: CertifiableBlock<Digest = Sha256Digest, Context = SimplexContext<D, K>>,
    D: Digest,
    K: PublicKey,
{
    for (height, block) in blocks {
        if *height == Height::zero() {
            continue;
        }
        let context = block.context();
        assert!(
            !rejects(&context),
            "node{idx} delivered a block its application rejects: height={} round={} \
             digest={}; stack={stack}",
            height.get(),
            context.round,
            block.digest(),
        );
    }
}

/// Invariant: every pair of consecutively delivered blocks is parent-linked.
///
/// [`check_in_order`] runs first and guarantees that after exact duplicate
/// deliveries are collapsed, the by-height snapshot is one contiguous chain.
/// A chain that starts at a floor above genesis has its root below the floor,
/// so only chains starting elsewhere must be rooted at genesis.
pub(crate) fn check_parent_linkage<B, D, K>(
    idx: usize,
    blocks: &BTreeMap<Height, Arc<B>>,
    genesis: Sha256Digest,
    floor: Height,
    stack: &str,
) where
    B: CertifiableBlock<Digest = Sha256Digest, Context = SimplexContext<D, K>>,
    D: ConsensusParentDigest,
    K: PublicKey,
{
    if let Some((height, block)) = blocks.first_key_value() {
        if *height == Height::zero() {
            assert_eq!(
                block.digest(),
                genesis,
                "node{idx} delivered the wrong genesis block: digest={} expected={genesis}; \
                 stack={stack}",
                block.digest(),
            );
        } else if *height != floor {
            assert_eq!(
                block.parent(),
                genesis,
                "node{idx} delivered a chain not rooted at genesis: first_height={} parent={} \
                 expected={genesis}; stack={stack}",
                height.get(),
                block.parent(),
            );
            assert_eq!(
                block.context().parent.1.block_digest(),
                genesis,
                "node{idx} delivered a chain whose first embedded consensus parent is not \
                 genesis: first_height={} context_parent={} expected={genesis}; stack={stack}",
                height.get(),
                block.context().parent.1.block_digest(),
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
            next.context().parent.1.block_digest(),
            block.digest(),
            "node{idx} delivered a chain with a broken embedded consensus parent: height {} \
             digest={} but height {} context_parent={}; stack={stack}",
            height.get(),
            block.digest(),
            next_height.get(),
            next.context().parent.1.block_digest(),
        );
        assert!(
            next.context().round > block.context().round,
            "node{idx} delivered a chain with non-increasing consensus rounds: height {} \
             round={} but height {} round={}; stack={stack}",
            height.get(),
            block.context().round,
            next_height.get(),
            next.context().round,
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
    use super::{
        super::coding_stack::{CodingCtx, CommitmentOf},
        *,
    };
    use commonware_consensus::{
        Reporter as _,
        marshal::{
            Update,
            mocks::block::{Block as MockBlock, EmptyBlock, ready},
        },
        types::{Epoch, View},
    };
    use commonware_consensus_fuzz_core::{SimplexCertificateMock, simplex_certificate_mock};
    use commonware_cryptography::{Sha256, ed25519::PublicKey as Ed25519PublicKey};
    use commonware_utils::{Acknowledgement as _, NZUsize, acknowledgement::Exact, test_rng};

    type TestContext = SimplexContext<Sha256Digest, Ed25519PublicKey>;
    type ContextBlock = MockBlock<Sha256Digest, TestContext>;
    type TestCommitment = CommitmentOf<SimplexCertificateMock>;

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

    fn commitment(byte: u8) -> TestCommitment {
        TestCommitment::from((
            digest(byte),
            digest(byte.wrapping_add(1)),
            digest(byte.wrapping_add(2)),
            commonware_consensus::marshal::mocks::harness::GENESIS_CODING_CONFIG,
        ))
    }

    fn coding_context(view: u64, parent: TestCommitment) -> CodingCtx<SimplexCertificateMock> {
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

        check_parent_linkage(0, &blocks, genesis, Height::zero(), "test");
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

        check_parent_linkage(0, &blocks, genesis, Height::zero(), "test");
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

        check_parent_linkage(0, &blocks, genesis, Height::zero(), "test");
    }

    #[test]
    fn pending_ack_boundary_below_window_is_vacuous() {
        type TestBlock = EmptyBlock<Sha256>;

        let mut application = Application::<TestBlock>::manual_ack();
        let block = TestBlock::new(digest(0), Height::zero(), 0);
        let (ack, _waiter) = Exact::handle();
        application.report(Update::Block(ready(block), ack));

        check_pending_acks(0, &application, Height::new(1), NZUsize!(2), "test");
    }

    #[test]
    #[should_panic(expected = "max_pending_acks backpressure violated")]
    fn pending_ack_at_window_boundary_is_rejected() {
        type TestBlock = EmptyBlock<Sha256>;

        let mut application = Application::<TestBlock>::manual_ack();
        let block = TestBlock::new(digest(0), Height::zero(), 0);
        let (ack, _waiter) = Exact::handle();
        application.report(Update::Block(ready(block), ack));

        check_pending_acks(0, &application, Height::new(2), NZUsize!(2), "test");
    }

    #[test]
    #[should_panic(expected = "max_pending_acks backpressure violated")]
    fn pending_ack_deep_window_is_reachable() {
        type TestBlock = EmptyBlock<Sha256>;

        let mut application = Application::<TestBlock>::manual_ack();
        let block = TestBlock::new(digest(0), Height::zero(), 0);
        let (ack, _waiter) = Exact::handle();
        application.report(Update::Block(ready(block), ack));

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
        let invariant =
            HeaderMismatchInvariant::<SimplexCertificateMock, (), TestCommitment>::coding(
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
    #[should_panic(expected = "delivered a block its application rejects")]
    fn rejected_delivery_is_rejected() {
        let genesis = digest(0xA);
        let first = block(1, genesis, genesis, 1);
        let second = block(2, first.digest(), first.digest(), 2);
        let blocks = BTreeMap::from([
            (Height::new(1), Arc::new(first)),
            (Height::new(2), Arc::new(second)),
        ]);

        check_no_rejected_delivery(
            0,
            &blocks,
            &|context: &TestContext| context.round.view() == View::new(2),
            "test",
        );
    }

    #[test]
    fn rejected_genesis_anchor_is_allowed() {
        let genesis = digest(0xA);
        let anchor = block(0, genesis, genesis, 0);
        let blocks = BTreeMap::from([(Height::zero(), Arc::new(anchor))]);

        check_no_rejected_delivery(0, &blocks, &|_: &TestContext| true, "test");
    }

    #[test]
    fn liveness_is_checked_only_for_the_pinned_configuration() {
        let one = TermLength::ONE;
        let three = TermLength::new(commonware_utils::NZU32!(3));
        assert_eq!(
            Liveness::sampled(Handoff::Wait, ViewDelta::zero(), one),
            Liveness::Checked
        );
        for (handoff, lookahead, term) in [
            (Handoff::Vote(()), ViewDelta::zero(), one),
            (Handoff::Stage(()), ViewDelta::zero(), one),
            (Handoff::Wait, ViewDelta::new(1), one),
            (Handoff::Wait, ViewDelta::zero(), three),
        ] {
            assert_eq!(
                Liveness::sampled(handoff, lookahead, term),
                Liveness::SafetyOnly,
                "{handoff:?} {lookahead:?} {term:?}"
            );
        }
    }

    #[test]
    fn single_certifier_term_start_is_counted() {
        let three = TermLength::new(commonware_utils::NZU32!(3));
        let invariant =
            CertificationAgreementInvariant::new("test".into(), MarshalChoice::Deferred, three);
        let parent = (Round::new(Epoch::zero(), View::new(3)), digest(0xA));
        let child = Round::new(Epoch::zero(), View::new(4));
        reach::reset();
        // No certifier yet, then one, then two; only the middle state counts, and
        // only at a term start.
        invariant.record_notarized(child, digest(0xB), parent);
        invariant.check_certify_agreement(1, parent.0, parent.1, true);
        invariant.record_notarized(Round::new(Epoch::zero(), View::new(5)), digest(0xB), parent);
        invariant.record_notarized(child, digest(0xB), parent);
        invariant.check_certify_agreement(2, parent.0, parent.1, true);
        invariant.record_notarized(child, digest(0xB), parent);
        assert_eq!(reach::count(SINGLE_CERTIFIER_TERM_START), 1);
        assert_eq!(reach::count(SINGLE_CERTIFIER_QUORUM), 0);
    }

    #[test]
    fn single_certifier_quorum_is_counted() {
        let three = TermLength::new(commonware_utils::NZU32!(3));
        let invariant =
            CertificationAgreementInvariant::new("test".into(), MarshalChoice::Deferred, three);
        let parent = (Round::new(Epoch::zero(), View::new(3)), digest(0xA));
        let child = Round::new(Epoch::zero(), View::new(4));
        let payload = digest(0xB);
        reach::reset();
        // The leader votes early; one voter certified the parent first, the
        // other votes before certifying.
        invariant.record_early_vote(1, child, payload);
        invariant.check_certify_agreement(2, parent.0, parent.1, true);
        invariant.record_vote(2, child, payload, parent);
        invariant.record_vote(3, child, payload, parent);
        invariant.record_notarized(child, payload, parent);
        assert_eq!(reach::count(SINGLE_CERTIFIER_QUORUM), 1);
        // The same certifier count without an early vote is an ordinary quorum.
        reach::reset();
        let ordinary = digest(0xC);
        for voter in 1..=3 {
            invariant.record_vote(voter, child, ordinary, parent);
        }
        invariant.record_notarized(child, ordinary, parent);
        assert_eq!(reach::count(SINGLE_CERTIFIER_QUORUM), 0);
        // Two certified voters behind an early vote are not the composition.
        invariant.check_certify_agreement(3, parent.0, parent.1, true);
        let later = digest(0xD);
        invariant.record_early_vote(1, child, later);
        invariant.record_vote(2, child, later, parent);
        invariant.record_vote(3, child, later, parent);
        invariant.record_notarized(child, later, parent);
        assert_eq!(reach::count(SINGLE_CERTIFIER_QUORUM), 0);
    }

    #[test]
    fn inline_certification_disagreement_is_allowed() {
        let invariant = CertificationAgreementInvariant::new(
            "test".into(),
            MarshalChoice::Inline,
            TermLength::ONE,
        );
        invariant.check_certify_agreement(0, Round::zero(), digest(0xA), true);
        invariant.check_certify_agreement(1, Round::zero(), digest(0xA), false);
    }

    #[test]
    #[should_panic(expected = "certify agreement violated")]
    fn deferred_certification_disagreement_is_rejected() {
        let invariant = CertificationAgreementInvariant::new(
            "test".into(),
            MarshalChoice::Deferred,
            TermLength::ONE,
        );
        invariant.check_certify_agreement(0, Round::zero(), digest(0xA), true);
        invariant.check_certify_agreement(1, Round::zero(), digest(0xA), false);
    }

    #[test]
    #[should_panic(expected = "certify agreement violated")]
    fn coding_certification_disagreement_is_rejected() {
        let invariant = CertificationAgreementInvariant::coding("test".into(), TermLength::ONE);
        invariant.check_certify_agreement(0, Round::zero(), commitment(0xA), true);
        invariant.check_certify_agreement(1, Round::zero(), commitment(0xA), false);
    }

    #[test]
    #[should_panic(expected = "certified its own proposal as false")]
    fn inline_self_proposal_clause_remains_unconditional() {
        let invariant = CertificationAgreementInvariant::new(
            "test".into(),
            MarshalChoice::Inline,
            TermLength::ONE,
        );
        invariant.record_proposal(0, Round::zero(), digest(0xA));
        invariant.check_certify_agreement(0, Round::zero(), digest(0xA), false);
    }
}
