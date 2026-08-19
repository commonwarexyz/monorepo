//! The fuzz-local compatibility harness `FuzzScenarioStandardHarness`.
//!
//! The production `commonware_consensus::marshal::mocks::harness::TestHarness`
//! hard-codes the BLS test scheme through its aliases, so it cannot be
//! instantiated with the fuzz mock certificate scheme without changing
//! `consensus/src`. This harness offers source-compatible operations over the
//! fuzz `Simplex` scheme instead: raw block construction that does not extend a
//! single global chain, quorum-certificate construction that is automatically
//! recorded in a ledger, awaited mailbox verbs, real wrapper `verify`/`certify`,
//! and a [`RecordingResolver`] per node so a prefix can assert the exact
//! backfill request each state produces and script the response to one.
//!
//! A prefix drives the honest core into a source-defined state and returns a
//! [`ScenarioHandoff`], which [`FuzzScenarioStandardHarness::finish`]
//! mechanically verifies before the engines start.

use super::{
    environment::{
        AttackAnchor, CertificateKind, FetchMatch, Mb, Node, PrefixCertificate, ScenarioHandoff,
    },
    recording_resolver::{FetchRecord, RecordingResolver},
};
use crate::{
    marshal::end_to_end::{
        app::AlwaysAcceptBlockBuilderApp,
        twins::{B, Ctx, PublicKeyOf, SchemeOf, stack::TwinsMarshal},
    },
    simplex::Simplex,
};
use bytes::Bytes;
use commonware_broadcast::buffered;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Automaton as _, CertifiableAutomaton as _, Heightable as _, Reporter as _,
    marshal::{
        Identifier,
        core::{Buffer, CommitmentFallback, DigestFallback, Retirement},
        mocks::application::Application,
        standard::Standard,
    },
    simplex::{
        Floor,
        types::{Activity, Finalization, Finalize, Notarization, Notarize, Proposal},
    },
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Digestible as _, Hasher as _, Sha256, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_parallel::Sequential;
use commonware_runtime::{Clock as _, Handle, deterministic};
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

/// The always-accept block builder wired under every marshal variant.
pub(crate) type App<P> = AlwaysAcceptBlockBuilderApp<Ctx<P>, SchemeOf<P>>;

/// Deadline for awaiting a wrapper verify/certify verdict during a prefix.
const WRAPPER_WAIT: Duration = Duration::from_secs(5);

/// A block dispatched to peers: round, block digest, and recipients.
pub(crate) type BufferSend<P> = (Round, Sha256Digest, Recipients<PublicKeyOf<P>>);

/// A marshal broadcast buffer that records every `send` and, only once
/// forwarding is enabled at handoff, delegates it to the real broadcast mailbox.
/// During the engine-free prefix it is recording-only (like the source
/// `RecordingBuffer`), so a scenario observes the exact count, order, and
/// recipients of dispatched blocks without the live buffered mailbox's cache and
/// subscription state changing; the runner enables forwarding before the engines
/// start so the fuzzing phase disseminates blocks normally.
pub(crate) struct RecordingBuffer<P: Simplex> {
    inner: buffered::Mailbox<PublicKeyOf<P>, B<P>>,
    sends: Arc<Mutex<Vec<BufferSend<P>>>>,
    forwarding: Arc<AtomicBool>,
    subscriptions: Arc<AtomicUsize>,
}

impl<P: Simplex> Clone for RecordingBuffer<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            sends: self.sends.clone(),
            forwarding: self.forwarding.clone(),
            subscriptions: self.subscriptions.clone(),
        }
    }
}

impl<P: Simplex> RecordingBuffer<P> {
    pub(crate) fn new(
        inner: buffered::Mailbox<PublicKeyOf<P>, B<P>>,
        sends: Arc<Mutex<Vec<BufferSend<P>>>>,
        forwarding: Arc<AtomicBool>,
        subscriptions: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inner,
            sends,
            forwarding,
            subscriptions,
        }
    }
}

impl<P: Simplex> Buffer<Standard<B<P>>> for RecordingBuffer<P> {
    type PublicKey = PublicKeyOf<P>;

    async fn find_by_digest(&self, digest: Sha256Digest) -> Option<Arc<B<P>>> {
        self.inner.get(digest).await
    }

    async fn find_by_commitment(&self, commitment: Sha256Digest) -> Option<Arc<B<P>>> {
        self.inner.get(commitment).await
    }

    fn subscribe_by_digest(&self, digest: Sha256Digest) -> Option<oneshot::Receiver<Arc<B<P>>>> {
        self.subscriptions.fetch_add(1, Ordering::Relaxed);
        Some(self.inner.subscribe(digest))
    }

    fn subscribe_by_commitment(
        &self,
        commitment: Sha256Digest,
    ) -> Option<oneshot::Receiver<Arc<B<P>>>> {
        self.subscriptions.fetch_add(1, Ordering::Relaxed);
        Some(self.inner.subscribe(commitment))
    }

    fn retire(&self, _update: Retirement<Sha256Digest>) {}

    fn send(&self, round: Round, block: Arc<B<P>>, recipients: Recipients<PublicKeyOf<P>>) {
        self.sends
            .lock()
            .push((round, block.digest(), recipients.clone()));
        if self.forwarding.load(Ordering::Relaxed) {
            self.inner.broadcast_shared(recipients, block);
        }
    }
}

/// The live per-node handles the harness drives.
pub(crate) struct HarnessNode<P: Simplex, M: TwinsMarshal<P, App<P>>> {
    pub(crate) mailbox: Mb<P>,
    pub(crate) wrapper: M::Wrapper,
    pub(crate) resolver: RecordingResolver<P>,
    pub(crate) application: Application<B<P>>,
    /// Blocks this node dispatched through its recording broadcast buffer.
    pub(crate) sends: Arc<Mutex<Vec<BufferSend<P>>>>,
    /// Local-wait block subscriptions registered through the recording buffer.
    pub(crate) subscriptions: Arc<AtomicUsize>,
}

/// The scenario scripting surface over the four-node cluster.
pub(crate) struct FuzzScenarioStandardHarness<P: Simplex, M: TwinsMarshal<P, App<P>>> {
    context: deterministic::Context,
    participants: Vec<PublicKeyOf<P>>,
    schemes: Vec<SchemeOf<P>>,
    genesis: B<P>,
    nodes: Vec<Option<HarnessNode<P, M>>>,
    /// The canonical chain built by the convenience [`Self::block`] helper.
    canonical: Vec<B<P>>,
    /// Every fabricated certificate, retained for the I1 assertion.
    ledger: Vec<PrefixCertificate>,
    /// The source test a prefix is porting, for ledger provenance.
    scenario: &'static str,
}

// Some verbs (the subscribe/report/hint/get_info surface) are unused by the
// current scenario set but document the source-compatible authoring surface and
// are exercised by future scenarios.
#[allow(dead_code)]
impl<P: Simplex, M: TwinsMarshal<P, App<P>>> FuzzScenarioStandardHarness<P, M>
where
    M::Wrapper: Clone,
{
    pub(crate) fn new(
        context: deterministic::Context,
        participants: Vec<PublicKeyOf<P>>,
        schemes: Vec<SchemeOf<P>>,
        genesis: B<P>,
        nodes: Vec<Option<HarnessNode<P, M>>>,
    ) -> Self {
        Self {
            context,
            participants,
            schemes,
            genesis,
            nodes,
            canonical: Vec::new(),
            ledger: Vec::new(),
            scenario: "",
        }
    }

    /// Set the source test a prefix is porting (ledger provenance).
    pub(crate) fn begin(&mut self, scenario: &'static str) {
        self.scenario = scenario;
    }

    /// The canonical chain the convenience [`Self::block`] helper has built.
    pub(crate) fn canonical(&self) -> &[B<P>] {
        &self.canonical
    }

    /// The certificates fabricated so far, for composition-soundness inspection.
    pub(crate) fn ledger(&self) -> &[PrefixCertificate] {
        &self.ledger
    }

    /// The height-zero genesis block.
    pub(crate) fn genesis(&self) -> &B<P> {
        &self.genesis
    }

    /// The participant public keys, in index order.
    pub(crate) fn participants(&self) -> &[PublicKeyOf<P>] {
        &self.participants
    }

    fn node(&self, node: Node) -> &HarnessNode<P, M> {
        self.nodes[node.idx()]
            .as_ref()
            .expect("scenario addressed a node without a marshal")
    }

    fn node_mut(&mut self, node: Node) -> &mut HarnessNode<P, M> {
        self.nodes[node.idx()]
            .as_mut()
            .expect("scenario addressed a node without a marshal")
    }

    fn mailbox(&self, node: Node) -> &Mb<P> {
        &self.node(node).mailbox
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    // ---- Block construction ------------------------------------------------

    /// The consensus context for a block: round, leader, and parent reference.
    pub(crate) fn context(
        &self,
        round: Round,
        leader: Node,
        parent_view: View,
        parent_digest: Sha256Digest,
    ) -> Ctx<P> {
        Ctx::<P> {
            round,
            leader: self.participants[leader.idx()].clone(),
            parent: (parent_view, parent_digest),
        }
    }

    /// Build a block from an explicit parent, round, leader, and height,
    /// without extending any global chain. Named distinctly from the source
    /// harness's `make_raw_block`, which takes only a parent, height, and
    /// timestamp and derives the rest (S6).
    pub(crate) fn block_with_context(
        &self,
        parent_digest: Sha256Digest,
        parent_view: View,
        round: Round,
        leader: Node,
        height: Height,
        timestamp: u64,
    ) -> B<P> {
        build_block::<P>(
            &self.participants,
            parent_digest,
            parent_view,
            round,
            leader.idx(),
            height,
            timestamp,
        )
    }

    /// Build a raw block whose parent digest is `hash(seed)`: the source
    /// `make_raw_block(Sha256::hash(&[b"..."]), ..)` shape for an independent
    /// branch anchor.
    pub(crate) fn make_seeded_block(
        &self,
        seed: &[u8],
        parent_view: View,
        round: Round,
        leader: Node,
        height: Height,
        timestamp: u64,
    ) -> B<P> {
        self.block_with_context(
            Sha256::hash(&[seed]),
            parent_view,
            round,
            leader,
            height,
            timestamp,
        )
    }

    /// Build a child of `parent`, reading the parent digest and view from it.
    pub(crate) fn make_child(
        &self,
        parent: &B<P>,
        round: Round,
        leader: Node,
        height: Height,
        timestamp: u64,
    ) -> B<P> {
        self.block_with_context(
            parent.digest(),
            parent.context.round.view(),
            round,
            leader,
            height,
            timestamp,
        )
    }

    /// Build a same-round equivocation of `block`: identical context and
    /// height, distinguished only by `timestamp`.
    pub(crate) fn make_equivocation(&self, block: &B<P>, timestamp: u64) -> B<P> {
        B::<P>::new::<Sha256>(
            block.context.clone(),
            block.context.parent.1,
            block.height(),
            timestamp,
        )
    }

    /// The digest of a block.
    pub(crate) fn digest(block: &B<P>) -> Sha256Digest {
        block.digest()
    }

    /// The consensus commitment of a block (equal to its digest for the standard
    /// variant).
    pub(crate) fn commitment(block: &B<P>) -> Sha256Digest {
        block.digest()
    }

    /// Convenience canonical-chain builder: append and return the next block on
    /// the chain at `view`, led by `leader`. Retained only for source tests that
    /// actually construct a canonical chain.
    pub(crate) fn block(&mut self, leader: Node, view: u64) -> B<P> {
        let parent = self.canonical.last().unwrap_or(&self.genesis);
        let parent_digest = parent.digest();
        let parent_view = parent.context.round.view();
        let height = Height::new(parent.height().get() + 1);
        let block = self.block_with_context(
            parent_digest,
            parent_view,
            Self::round(view),
            leader,
            height,
            height.get(),
        );
        self.canonical.push(block.clone());
        block
    }

    /// A side/fork block on an explicit parent, not appended to the chain.
    pub(crate) fn fork_block(
        &self,
        parent: &B<P>,
        leader: Node,
        view: u64,
        height: Height,
    ) -> B<P> {
        self.make_child(parent, Self::round(view), leader, height, height.get())
    }

    // ---- Certificate construction (recorded in the ledger) -----------------

    #[allow(clippy::too_many_arguments)]
    fn signed_proposal(
        &mut self,
        kind: CertificateKind,
        round: Round,
        parent_view: View,
        payload: Sha256Digest,
        signers: &[Node],
        encoded: Bytes,
    ) {
        self.ledger.push(PrefixCertificate {
            kind,
            round,
            parent_view,
            payload,
            signers: signers.to_vec(),
            scenario: self.scenario,
            encoded,
        });
    }

    /// Build a notarization over an explicit proposal, recording it.
    pub(crate) fn make_notarization(
        &mut self,
        round: Round,
        parent_view: View,
        payload: Sha256Digest,
        signers: &[Node],
    ) -> Notarization<SchemeOf<P>, Sha256Digest> {
        let signer_idxs: Vec<usize> = signers.iter().map(|node| node.idx()).collect();
        let notarization =
            build_notarization::<P>(&self.schemes, round, parent_view, payload, &signer_idxs);
        self.signed_proposal(
            CertificateKind::Notarization,
            round,
            parent_view,
            payload,
            signers,
            notarization.encode(),
        );
        notarization
    }

    /// Build a finalization over an explicit proposal, recording it.
    pub(crate) fn make_finalization(
        &mut self,
        round: Round,
        parent_view: View,
        payload: Sha256Digest,
        signers: &[Node],
    ) -> Finalization<SchemeOf<P>, Sha256Digest> {
        let signer_idxs: Vec<usize> = signers.iter().map(|node| node.idx()).collect();
        let finalization =
            build_finalization::<P>(&self.schemes, round, parent_view, payload, &signer_idxs);
        self.signed_proposal(
            CertificateKind::Finalization,
            round,
            parent_view,
            payload,
            signers,
            finalization.encode(),
        );
        finalization
    }

    /// Notarization over `block`, reading its view and parent view from context.
    pub(crate) fn notarization_of(
        &mut self,
        block: &B<P>,
        signers: &[Node],
    ) -> Notarization<SchemeOf<P>, Sha256Digest> {
        let round = block.context.round;
        let parent_view = block.context.parent.0;
        self.make_notarization(round, parent_view, block.digest(), signers)
    }

    /// Finalization over `block`, reading its view and parent view from context.
    pub(crate) fn finalization_of(
        &mut self,
        block: &B<P>,
        signers: &[Node],
    ) -> Finalization<SchemeOf<P>, Sha256Digest> {
        let round = block.context.round;
        let parent_view = block.context.parent.0;
        self.make_finalization(round, parent_view, block.digest(), signers)
    }

    // ---- Awaited mailbox verbs --------------------------------------------

    /// Persist `block` as verified at `view` on `node`, asserting durability.
    pub(crate) async fn verified(&self, node: Node, view: u64, block: &B<P>) {
        assert!(
            self.mailbox(node)
                .verified(Self::round(view), block.clone())
                .await,
            "verified must be durable: node={node:?} view={view}",
        );
    }

    /// Persist `block` as certified at `view` on `node`, asserting durability.
    pub(crate) async fn certified(&self, node: Node, view: u64, block: &B<P>) {
        assert!(
            self.mailbox(node)
                .certified(Self::round(view), block.clone())
                .await,
            "certified must be durable: node={node:?} view={view}",
        );
    }

    /// Enqueue a source `proposed` operation to `Recipients::All` without
    /// awaiting durability, returning the durable-sync-handle receiver. Enqueuing
    /// several before awaiting preserves the source's concurrent propose handshake
    /// (blocks staged and broadcast in submission order before any durability
    /// wait).
    pub(crate) fn proposed_all_deferred(
        &self,
        node: Node,
        view: u64,
        block: &B<P>,
    ) -> oneshot::Receiver<Handle<()>> {
        let (ack, persist) = oneshot::channel();
        assert!(
            self.mailbox(node)
                .proposed(Self::round(view), block.clone(), Recipients::All, ack)
                .accepted(),
            "proposed must be accepted: node={node:?} view={view}",
        );
        persist
    }

    /// The blocks `node` dispatched through its recording broadcast buffer, in
    /// order, each as `(round, digest, recipients)`.
    pub(crate) fn buffer_sends(&self, node: Node) -> Vec<BufferSend<P>> {
        self.node(node).sends.lock().clone()
    }

    /// Report a notarization to `node`'s marshal (fire-and-forget).
    pub(crate) fn report_notarization(
        &self,
        node: Node,
        notarization: Notarization<SchemeOf<P>, Sha256Digest>,
    ) {
        let _ = self
            .mailbox(node)
            .clone()
            .report(Activity::Notarization(notarization));
    }

    /// Report a finalization to `node`'s marshal (fire-and-forget).
    pub(crate) fn report_finalization(
        &self,
        node: Node,
        finalization: Finalization<SchemeOf<P>, Sha256Digest>,
    ) {
        let _ = self
            .mailbox(node)
            .clone()
            .report(Activity::Finalization(finalization));
    }

    /// Install a finalization as the marshal floor on `node` (fire-and-forget).
    pub(crate) fn set_floor(
        &self,
        node: Node,
        finalization: Finalization<SchemeOf<P>, Sha256Digest>,
    ) {
        self.mailbox(node).set_floor(finalization);
    }

    /// Issue a round-bound backfill hint for a notarized commitment on `node`.
    pub(crate) fn hint_notarized(&self, node: Node, view: u64, commitment: Sha256Digest) {
        self.mailbox(node)
            .hint_notarized(Self::round(view), commitment);
    }

    /// Install a finalization as the marshal floor on every present marshal node
    /// except `except`. Used when the engine floor's chain is not reachable from
    /// genesis, so every scaffolding node must deliver from the floor for the
    /// cluster to be live; the victim node's own floor sequence is scripted
    /// separately and excluded here.
    pub(crate) fn set_floor_others(
        &self,
        except: Node,
        finalization: Finalization<SchemeOf<P>, Sha256Digest>,
    ) {
        for idx in 0..self.nodes.len() {
            if idx == except.idx() {
                continue;
            }
            if let Some(node) = self.nodes[idx].as_ref() {
                node.mailbox.set_floor(finalization.clone());
            }
        }
    }

    /// Best-effort local block lookup by digest.
    pub(crate) async fn get_block(&self, node: Node, digest: Sha256Digest) -> Option<B<P>> {
        self.mailbox(node).get_block(&digest).await
    }

    /// Best-effort local finalization lookup by height.
    pub(crate) async fn get_finalization(
        &self,
        node: Node,
        height: Height,
    ) -> Option<Finalization<SchemeOf<P>, Sha256Digest>> {
        self.mailbox(node).get_finalization(height).await
    }

    /// Best-effort `(height, digest)` lookup.
    pub(crate) async fn get_info(
        &self,
        node: Node,
        identifier: impl Into<Identifier<Sha256Digest>>,
    ) -> Option<(Height, Sha256Digest)> {
        self.mailbox(node).get_info(identifier).await
    }

    /// Register a pending block subscription by digest on `node`, returning the
    /// receiver (retain it to keep the subscription alive).
    pub(crate) fn subscribe_by_digest(
        &self,
        node: Node,
        digest: Sha256Digest,
        fallback: DigestFallback,
    ) -> oneshot::Receiver<Arc<B<P>>> {
        self.mailbox(node).subscribe_by_digest(digest, fallback)
    }

    /// Register a pending block subscription by commitment on `node`.
    pub(crate) fn subscribe_by_commitment(
        &self,
        node: Node,
        commitment: Sha256Digest,
        fallback: CommitmentFallback,
    ) -> oneshot::Receiver<Arc<B<P>>> {
        self.mailbox(node)
            .subscribe_by_commitment(commitment, fallback)
    }

    /// FIFO barrier: a round-trip that flushes prior fire-and-forget messages.
    pub(crate) async fn barrier(&self, node: Node) -> Option<Height> {
        self.mailbox(node).get_processed_height().await
    }

    /// The application delivery tip on `node` (`(height, digest)`), set from the
    /// marshal's startup Tip report.
    pub(crate) fn app_tip(&self, node: Node) -> Option<(Height, Sha256Digest)> {
        self.node(node).application.tip()
    }

    /// Fence every honest node so all prior fire-and-forget messages are
    /// processed before the prefix finishes.
    pub(crate) async fn barrier_all(&self) {
        for idx in 0..self.nodes.len() {
            if self.nodes[idx].is_some() {
                let _ = self
                    .mailbox(node_from_idx(idx))
                    .get_processed_height()
                    .await;
            }
        }
    }

    // ---- Wrapper operations -----------------------------------------------

    /// Execute the real wrapper `verify` on `node`, returning its pending
    /// receiver.
    pub(crate) async fn wrapper_verify(
        &mut self,
        node: Node,
        context: Ctx<P>,
        digest: Sha256Digest,
    ) -> oneshot::Receiver<bool> {
        self.node_mut(node).wrapper.verify(context, digest).await
    }

    /// Execute the real wrapper `certify` on `node`, returning its pending
    /// receiver.
    pub(crate) async fn wrapper_certify(
        &mut self,
        node: Node,
        round: Round,
        digest: Sha256Digest,
    ) -> oneshot::Receiver<bool> {
        self.node_mut(node).wrapper.certify(round, digest).await
    }

    /// Await a wrapper verify/certify verdict, racing it against a deterministic
    /// deadline so an unresolved operation fails loudly rather than hanging.
    pub(crate) async fn await_wrapper(
        &self,
        receiver: oneshot::Receiver<bool>,
        label: &str,
    ) -> bool {
        select! {
            result = receiver => result.expect("wrapper receiver dropped"),
            _ = self.context.sleep(WRAPPER_WAIT) => {
                panic!("{label}: wrapper operation did not resolve within {WRAPPER_WAIT:?}")
            }
        }
    }

    // ---- Recording resolver and buffer -------------------------------------

    /// Arm a payload answering `node`'s next backfill fetch, delivered through
    /// the held resolver handler as if a peer had responded.
    pub(crate) fn respond_to_next_fetch(&self, node: Node, value: Bytes) {
        self.node(node).resolver.respond_to_next_fetch(value);
    }

    /// Await the marshal's validation verdict for `node`'s most recent armed
    /// delivery.
    pub(crate) async fn wait_for_delivery_response(&self, node: Node) -> bool {
        self.node(node).resolver.wait_for_delivery_response().await
    }

    /// Whether `node` issued no targeted fetch.
    pub(crate) fn targeted_is_empty(&self, node: Node) -> bool {
        self.node(node).resolver.targeted_is_empty()
    }

    /// Number of local-wait block subscriptions `node`'s marshal registered
    /// through its broadcast buffer.
    pub(crate) fn buffer_subscription_count(&self, node: Node) -> usize {
        self.node(node).subscriptions.load(Ordering::Relaxed)
    }

    // ---- Verified handoff --------------------------------------------------

    /// Assert an observed fetch multiset corresponds one-to-one with `expected`.
    fn assert_fetch_multiset(
        node: Node,
        kind: &str,
        observed: &[FetchRecord],
        expected: &[FetchMatch],
    ) {
        assert_eq!(
            observed.len(),
            expected.len(),
            "node {node:?} {kind} fetch count {} != expected {}; {kind}={observed:?}",
            observed.len(),
            expected.len(),
        );
        let mut used = vec![false; observed.len()];
        for expectation in expected {
            let mut matched = false;
            for (index, (key, annotation)) in observed.iter().enumerate() {
                if !used[index] && expectation.matches(key, annotation) {
                    used[index] = true;
                    matched = true;
                    break;
                }
            }
            assert!(
                matched,
                "node {node:?}: expected fetch {expectation:?} not in {kind}; {kind}={observed:?}",
            );
        }
    }

    /// Fence, then mechanically assert every part of `handoff`; the engines must
    /// start only after this returns.
    pub(crate) async fn finish(&self, handoff: &ScenarioHandoff<P>) {
        self.barrier_all().await;

        // Exact per-node fetch history and still-active fetches: the observed
        // multiset on each listed node must correspond one-to-one with the
        // expectation, so unexpected extras and missing fetches both fail (an
        // empty list requires no fetch at all). Nodes without a marshal (the
        // byzantine node in the adversarial mode) are skipped.
        for (node, expected) in &handoff.node_fetches {
            let Some(live) = self.nodes[node.idx()].as_ref() else {
                continue;
            };
            Self::assert_fetch_multiset(*node, "history", &live.resolver.fetches(), expected);
        }
        for (node, expected) in &handoff.node_active_fetches {
            let Some(live) = self.nodes[node.idx()].as_ref() else {
                continue;
            };
            Self::assert_fetch_multiset(*node, "active", &live.resolver.active_fetches(), expected);
        }

        // Per-node block presence: the defining state names which marshal
        // holds each candidate and which must lack it, so the handoff proves
        // it mechanically (for example, that the victim is the sole holder of
        // a fetched candidate). Nodes without a marshal (the byzantine node in
        // the adversarial mode) are skipped.
        for expectation in &handoff.expected_nodes {
            if self.nodes[expectation.node.idx()].is_none() {
                continue;
            }
            for digest in &expectation.present {
                assert!(
                    self.get_block(expectation.node, *digest).await.is_some(),
                    "node {:?} must hold block {digest} at handoff",
                    expectation.node,
                );
            }
            for digest in &expectation.absent {
                assert!(
                    self.get_block(expectation.node, *digest).await.is_none(),
                    "node {:?} must lack block {digest} at handoff",
                    expectation.node,
                );
            }
        }

        // Composition soundness (I1): a fabricated certificate must sit at or
        // below the engine floor, or be exactly one of the artifacts every
        // honest engine recovers from its seeded voter journal.
        let floor_view = floor_view(&handoff.engine_floor);
        for certificate in &self.ledger {
            if certificate.round.view() <= floor_view {
                continue;
            }
            let recovered = certificate.kind == CertificateKind::Notarization
                && handoff
                    .engine_journal
                    .iter()
                    .any(|notarization| notarization.encode() == certificate.encoded);
            assert!(
                recovered,
                "I1 violated: {:?} certificate at view {} exceeds engine floor view {} and \
                 matches no recovered journal entry (scenario={}, parent_view={}, signers={:?})",
                certificate.kind,
                certificate.round.view().get(),
                floor_view.get(),
                certificate.scenario,
                certificate.parent_view.get(),
                certificate.signers,
            );
        }
        assert_attack_anchor_consistent::<P>(
            &handoff.attack_anchor,
            &handoff.engine_floor,
            &handoff.engine_journal,
            &handoff.reference_chain,
        );
    }
}

/// Build a raw block from explicit parts. Shared by the live harness and the
/// pre-start seed path so both produce byte-identical blocks.
pub(crate) fn build_block<P: Simplex>(
    participants: &[PublicKeyOf<P>],
    parent_digest: Sha256Digest,
    parent_view: View,
    round: Round,
    leader_idx: usize,
    height: Height,
    timestamp: u64,
) -> B<P> {
    let context = Ctx::<P> {
        round,
        leader: participants[leader_idx].clone(),
        parent: (parent_view, parent_digest),
    };
    B::<P>::new::<Sha256>(context, parent_digest, height, timestamp)
}

/// Build a quorum finalization from explicit parts. Shared by the live harness
/// and the pre-start seed path.
pub(crate) fn build_finalization<P: Simplex>(
    schemes: &[SchemeOf<P>],
    round: Round,
    parent_view: View,
    payload: Sha256Digest,
    signer_idxs: &[usize],
) -> Finalization<SchemeOf<P>, Sha256Digest> {
    let proposal = Proposal::new(round, parent_view, payload);
    let finalizes: Vec<_> = signer_idxs
        .iter()
        .map(|idx| Finalize::sign(&schemes[*idx], proposal.clone()).expect("finalize sign failed"))
        .collect();
    Finalization::from_finalizes(&schemes[signer_idxs[0]], &finalizes, &Sequential)
        .expect("finalization assembly failed")
}

/// Build a quorum notarization from explicit parts.
pub(crate) fn build_notarization<P: Simplex>(
    schemes: &[SchemeOf<P>],
    round: Round,
    parent_view: View,
    payload: Sha256Digest,
    signer_idxs: &[usize],
) -> Notarization<SchemeOf<P>, Sha256Digest> {
    let proposal = Proposal::new(round, parent_view, payload);
    let notarizes: Vec<_> = signer_idxs
        .iter()
        .map(|idx| Notarize::sign(&schemes[*idx], proposal.clone()).expect("notarize sign failed"))
        .collect();
    Notarization::from_notarizes(&schemes[signer_idxs[0]], &notarizes, &Sequential)
        .expect("notarization assembly failed")
}

fn node_from_idx(idx: usize) -> Node {
    match idx {
        0 => Node::A,
        1 => Node::B,
        2 => Node::C,
        _ => Node::D,
    }
}

/// The view of the finalization an engine floor starts from (genesis is view 0).
fn floor_view<S, D>(floor: &Floor<S, D>) -> View
where
    S: commonware_cryptography::certificate::Scheme,
    D: commonware_cryptography::Digest,
{
    match floor {
        Floor::Genesis(_) => View::zero(),
        Floor::Finalized(finalization) => finalization.round().view(),
    }
}

/// Assert the attack anchor is the first live view above the floor and the
/// recovered journal state, and extends the reference chain tip.
fn assert_attack_anchor_consistent<P: Simplex>(
    anchor: &AttackAnchor,
    floor: &Floor<SchemeOf<P>, Sha256Digest>,
    journal: &[Notarization<SchemeOf<P>, Sha256Digest>],
    reference_chain: &[B<P>],
) {
    let floor_view = floor_view(floor);
    let recovered_view = journal
        .iter()
        .map(|notarization| notarization.round().view())
        .max();
    let base_view = recovered_view.map_or(floor_view, |view| view.max(floor_view));
    assert_eq!(
        anchor.view.get(),
        base_view.get() + 1,
        "attack view must be one above the floor and recovered journal views",
    );
    // With recovered journal entries, the live chain begins at the recovered
    // proposal rather than the floor, so the anchor is pinned by the reference
    // chain below instead of the floor payload.
    if journal.is_empty() {
        match floor {
            Floor::Finalized(finalization) => assert_eq!(
                anchor.digest, finalization.proposal.payload,
                "attack anchor digest must be the engine floor block",
            ),
            Floor::Genesis(digest) => {
                // Above genesis, the adversary extends the genesis block at height 1.
                assert_eq!(
                    anchor.digest, *digest,
                    "attack anchor digest must be genesis"
                );
                assert_eq!(
                    anchor.height.get(),
                    1,
                    "attack height above genesis must be 1"
                );
            }
        }
    } else {
        assert!(
            !reference_chain.is_empty(),
            "recovered journal state requires a reference chain to pin the attack anchor",
        );
    }
    if let Some(tip) = reference_chain.last() {
        assert_eq!(
            anchor.height.get(),
            tip.height().get() + 1,
            "attack height must be one above the reference chain tip",
        );
        assert_eq!(
            anchor.digest,
            tip.digest(),
            "attack anchor digest must be the reference chain tip",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SimplexCertificateMock,
        marshal::end_to_end::twins::stack::{DeferredMarshal, genesis_block},
        scenarios::environment::{CertificateKind, QUORUM_SIGNERS},
    };
    use commonware_consensus::marshal::mocks::harness::{NAMESPACE, NUM_VALIDATORS};
    use commonware_runtime::{Runner, Supervisor as _, deterministic};

    type P = SimplexCertificateMock;
    type H = FuzzScenarioStandardHarness<P, DeferredMarshal>;

    /// Build a construction-only harness (no live marshal nodes) for testing the
    /// pure block and certificate builders.
    fn with_harness(test: impl FnOnce(&mut H)) {
        deterministic::Runner::default().start(|mut context| async move {
            let (participants, schemes) = P::setup(&mut context, NAMESPACE, NUM_VALIDATORS);
            let genesis = genesis_block::<P>(participants[0].clone());
            let nodes = (0..NUM_VALIDATORS).map(|_| None).collect();
            let mut harness = H::new(
                context.child("harness"),
                participants,
                schemes,
                genesis,
                nodes,
            );
            harness.begin("construction_test");
            test(&mut harness);
        });
    }

    #[test]
    fn independent_branches_remain_independent() {
        with_harness(|harness| {
            let old = harness.make_seeded_block(
                b"old-floor-parent",
                View::new(4),
                Round::new(Epoch::zero(), View::new(5)),
                Node::B,
                Height::new(5),
                500,
            );
            let new = harness.make_seeded_block(
                b"new-floor-parent",
                View::new(6),
                Round::new(Epoch::zero(), View::new(7)),
                Node::B,
                Height::new(7),
                700,
            );
            assert_ne!(
                old.context.parent.1, new.context.parent.1,
                "branches must have distinct parents"
            );
            assert_ne!(
                old.digest(),
                new.digest(),
                "branches must produce distinct blocks"
            );
            assert_ne!(
                new.context.parent.1,
                old.digest(),
                "the new branch must not extend the old anchor"
            );
        });
    }

    #[test]
    fn make_child_links_to_parent() {
        with_harness(|harness| {
            let parent = harness.block_with_context(
                harness.genesis().digest(),
                View::zero(),
                Round::new(Epoch::zero(), View::new(1)),
                Node::B,
                Height::new(1),
                100,
            );
            let child = harness.make_child(
                &parent,
                Round::new(Epoch::zero(), View::new(2)),
                Node::C,
                Height::new(2),
                200,
            );
            assert_eq!(child.context.parent.1, parent.digest());
            assert_eq!(child.context.parent.0, parent.context.round.view());
        });
    }

    #[test]
    fn equivocation_shares_context_but_differs() {
        with_harness(|harness| {
            let block = harness.block_with_context(
                harness.genesis().digest(),
                View::zero(),
                Round::new(Epoch::zero(), View::new(1)),
                Node::B,
                Height::new(1),
                1,
            );
            let equivocation = harness.make_equivocation(&block, 999);
            assert_eq!(block.context.round, equivocation.context.round);
            assert_eq!(block.context.parent, equivocation.context.parent);
            assert_eq!(block.height(), equivocation.height());
            assert_ne!(block.digest(), equivocation.digest());
            assert_eq!(H::commitment(&block), H::digest(&block));
        });
    }

    #[test]
    fn canonical_helper_extends_one_chain() {
        with_harness(|harness| {
            let first = harness.block(Node::B, 1);
            let second = harness.block(Node::C, 2);
            assert_eq!(harness.canonical().len(), 2);
            assert_eq!(first.context.parent.1, harness.genesis().digest());
            assert_eq!(second.context.parent.1, first.digest());
            assert_eq!(second.height().get(), 2);
        });
    }

    #[test]
    fn certificate_ledger_records_kind_view_and_signers() {
        with_harness(|harness| {
            let block = harness.block_with_context(
                harness.genesis().digest(),
                View::new(4),
                Round::new(Epoch::zero(), View::new(5)),
                Node::B,
                Height::new(5),
                500,
            );
            let _finalization = harness.make_finalization(
                Round::new(Epoch::zero(), View::new(5)),
                View::new(4),
                block.digest(),
                &QUORUM_SIGNERS,
            );
            let _notarization = harness.make_notarization(
                Round::new(Epoch::zero(), View::new(3)),
                View::new(2),
                block.digest(),
                &QUORUM_SIGNERS,
            );
            let ledger = harness.ledger();
            assert_eq!(ledger.len(), 2);
            assert_eq!(ledger[0].kind, CertificateKind::Finalization);
            assert_eq!(ledger[0].round.view(), View::new(5));
            assert_eq!(ledger[0].signers, QUORUM_SIGNERS.to_vec());
            assert_eq!(ledger[1].kind, CertificateKind::Notarization);
            assert_eq!(ledger[1].round.view(), View::new(3));
            assert_eq!(ledger[1].payload, block.digest());
        });
    }
}
