//! Scripted marshal environment: the verbs a [`Scenario`](super::scenarios::Scenario)
//! prefix uses to drive four validators into an interesting state.
//!
//! The verbs act directly on the marshal mailboxes below the consensus engine,
//! so a scenario can build a canonical chain, fabricate quorum certificates over
//! a chosen signer subset, report them, and install floors without a running
//! engine. The prefix network carries no links, so state cannot leak between
//! nodes: every fetch a prefix provokes stays pending until the fuzzing phase
//! applies the input topology. The prefix stops at a chosen semantic point and
//! hands back a [`FuzzPoint`] describing the certified floor the engines then
//! start from.

use crate::{
    marshal::end_to_end::twins::{B, Ctx, PublicKeyOf, SchemeOf},
    simplex::Simplex,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    Heightable, Reporter as _,
    marshal::{
        core::{CommitmentFallback, DigestFallback, Mailbox},
        standard::Standard,
    },
    simplex::types::{Activity, Finalization, Finalize, Notarization, Notarize, Proposal},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digestible, Sha256, sha256::Digest as Sha256Digest};
use commonware_p2p::Recipients;
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, deterministic};
use commonware_utils::channel::oneshot;
use std::{sync::Arc, time::Duration};

/// Marshal mailbox for the standard variant over the mock block.
pub(crate) type Mb<P> = Mailbox<SchemeOf<P>, Standard<B<P>>>;

/// A validator of the four-node cluster, addressed by its participant index.
///
/// In the adversarial mode [`Node::A`] (index 0) is the byzantine node, so
/// scenarios only script the honest core {B, C, D}; that keeps a scenario
/// identical in both fuzzing modes.
#[allow(dead_code)] // `A` names node 0, addressed by the adversary rather than scenarios.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Node {
    A,
    B,
    C,
    D,
}

impl Node {
    pub(crate) const fn idx(self) -> usize {
        self as usize
    }
}

/// Certificate signer set for a fabricated quorum: the three honest validators.
pub(crate) const QUORUM_SIGNERS: [Node; 3] = [Node::B, Node::C, Node::D];

/// The scripted-prefix surface handed to a scenario.
///
/// `context` and `buffers` back the timing and broadcast verbs, which the
/// current scenarios do not need but future ones may.
pub(crate) struct ScenarioEnv<P: Simplex> {
    #[allow(dead_code)]
    pub(crate) context: deterministic::Context,
    pub(crate) participants: Vec<PublicKeyOf<P>>,
    pub(crate) schemes: Vec<SchemeOf<P>>,
    pub(crate) mailboxes: Vec<Mb<P>>,
    #[allow(dead_code)]
    pub(crate) buffers: Vec<buffered::Mailbox<PublicKeyOf<P>, B<P>>>,
    pub(crate) genesis: B<P>,
    pub(crate) canonical: Vec<B<P>>,
    /// Receivers for block subscriptions the prefix registered. Held here so
    /// the subscriptions stay alive through the fuzzing phase (dropping a
    /// receiver cancels its subscription); scenarios never await them.
    pub(crate) subscriptions: Vec<oneshot::Receiver<Arc<B<P>>>>,
}

/// The verbs a scenario uses. Some are unused by the current five scenarios but
/// document the authoring surface and are exercised by future scenarios.
#[allow(dead_code)]
impl<P: Simplex> ScenarioEnv<P> {
    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    /// The block a fresh canonical block extends: the last canonical block, or
    /// genesis when the chain is empty.
    fn parent(&self) -> &B<P> {
        self.canonical.last().unwrap_or(&self.genesis)
    }

    /// Build and append the next canonical block at `view`, led by `leader`.
    ///
    /// `view` need not equal the height: a nullified view can be skipped by
    /// giving a later canonical block a higher view than its height.
    pub(crate) fn block(&mut self, leader: Node, view: u64) -> B<P> {
        let parent = self.parent();
        let parent_digest = parent.digest();
        let parent_view = parent.context.round.view();
        let height = Height::new(parent.height().get() + 1);
        let block = self.build_block(leader, view, parent_view, parent_digest, height);
        self.canonical.push(block.clone());
        block
    }

    /// Build a same-round equivocation of `block`: identical context (round,
    /// leader, parent) and height, distinguished only by `timestamp`. Not
    /// appended to the canonical chain.
    pub(crate) fn equivocate(&self, block: &B<P>, timestamp: u64) -> B<P> {
        B::<P>::new::<Sha256>(
            block.context.clone(),
            block.context.parent.1,
            block.height(),
            timestamp,
        )
    }

    /// Build a side/fork block on an explicit parent without appending it to the
    /// canonical chain.
    pub(crate) fn fork_block(
        &self,
        parent: &B<P>,
        leader: Node,
        view: u64,
        height: Height,
    ) -> B<P> {
        self.build_block(
            leader,
            view,
            parent.context.round.view(),
            parent.digest(),
            height,
        )
    }

    fn build_block(
        &self,
        leader: Node,
        view: u64,
        parent_view: View,
        parent_digest: Sha256Digest,
        height: Height,
    ) -> B<P> {
        let context = Ctx::<P> {
            round: Self::round(view),
            leader: self.participants[leader.idx()].clone(),
            parent: (parent_view, parent_digest),
        };
        B::<P>::new::<Sha256>(context, parent_digest, height, height.get())
    }

    /// Persist `block` as verified at `view` on `node`, asserting durability.
    /// This is the harness `propose`/`verify`: it does not broadcast.
    pub(crate) async fn verify(&self, node: Node, view: u64, block: &B<P>) {
        assert!(
            self.mailboxes[node.idx()]
                .verified(Self::round(view), block.clone())
                .await,
            "verified must be durable: node={:?} view={view}",
            node,
        );
    }

    /// Persist `block` as certified at `view` on `node`, asserting durability.
    pub(crate) async fn certify(&self, node: Node, view: u64, block: &B<P>) {
        assert!(
            self.mailboxes[node.idx()]
                .certified(Self::round(view), block.clone())
                .await,
            "certified must be durable: node={:?} view={view}",
            node,
        );
    }

    /// Build a notarization over `block`, reading its view and parent view from
    /// the block context, signed by `signers`.
    pub(crate) fn notarization(
        &self,
        block: &B<P>,
        signers: &[Node],
    ) -> Notarization<SchemeOf<P>, Sha256Digest> {
        self.notarization_at(
            block.context.round.view().get(),
            block.context.parent.0.get(),
            block,
            signers,
        )
    }

    /// Build a notarization over `block` at an explicit `view`/`parent_view`.
    pub(crate) fn notarization_at(
        &self,
        view: u64,
        parent_view: u64,
        block: &B<P>,
        signers: &[Node],
    ) -> Notarization<SchemeOf<P>, Sha256Digest> {
        let proposal = Proposal::new(Self::round(view), View::new(parent_view), block.digest());
        let notarizes: Vec<_> = signers
            .iter()
            .map(|node| {
                Notarize::sign(&self.schemes[node.idx()], proposal.clone())
                    .expect("notarize sign failed")
            })
            .collect();
        Notarization::from_notarizes(&self.schemes[signers[0].idx()], &notarizes, &Sequential)
            .expect("notarization assembly failed")
    }

    /// Build a finalization over `block`, reading its view and parent view from
    /// the block context, signed by `signers`.
    pub(crate) fn finalization(
        &self,
        block: &B<P>,
        signers: &[Node],
    ) -> Finalization<SchemeOf<P>, Sha256Digest> {
        self.finalization_at(
            block.context.round.view().get(),
            block.context.parent.0.get(),
            block,
            signers,
        )
    }

    /// Build a finalization over `block` at an explicit `view`/`parent_view`.
    pub(crate) fn finalization_at(
        &self,
        view: u64,
        parent_view: u64,
        block: &B<P>,
        signers: &[Node],
    ) -> Finalization<SchemeOf<P>, Sha256Digest> {
        let proposal = Proposal::new(Self::round(view), View::new(parent_view), block.digest());
        let finalizes: Vec<_> = signers
            .iter()
            .map(|node| {
                Finalize::sign(&self.schemes[node.idx()], proposal.clone())
                    .expect("finalize sign failed")
            })
            .collect();
        Finalization::from_finalizes(&self.schemes[signers[0].idx()], &finalizes, &Sequential)
            .expect("finalization assembly failed")
    }

    /// Report a notarization to `node`'s marshal (fire-and-forget).
    pub(crate) fn report_notarization(
        &self,
        node: Node,
        notarization: Notarization<SchemeOf<P>, Sha256Digest>,
    ) {
        let mut mailbox = self.mailboxes[node.idx()].clone();
        let _ = mailbox.report(Activity::Notarization(notarization));
    }

    /// Report a finalization to `node`'s marshal (fire-and-forget).
    pub(crate) fn report_finalization(
        &self,
        node: Node,
        finalization: Finalization<SchemeOf<P>, Sha256Digest>,
    ) {
        let mut mailbox = self.mailboxes[node.idx()].clone();
        let _ = mailbox.report(Activity::Finalization(finalization));
    }

    /// Issue a round-bound backfill hint for a notarized commitment on `node`.
    pub(crate) fn hint_notarized(&self, node: Node, view: u64, commitment: Sha256Digest) {
        self.mailboxes[node.idx()].hint_notarized(Self::round(view), commitment);
    }

    /// Register a pending block subscription by digest on `node`, waiting for
    /// local availability only.
    pub(crate) fn subscribe_wait(&mut self, node: Node, digest: Sha256Digest) {
        let receiver = self.mailboxes[node.idx()].subscribe_by_digest(digest, DigestFallback::Wait);
        self.subscriptions.push(receiver);
    }

    /// Register a pending block subscription by digest on `node` with a
    /// round-bound fetch fallback.
    pub(crate) fn subscribe_fetch_by_round(&mut self, node: Node, view: u64, digest: Sha256Digest) {
        let receiver = self.mailboxes[node.idx()].subscribe_by_digest(
            digest,
            DigestFallback::FetchByRound {
                round: Self::round(view),
            },
        );
        self.subscriptions.push(receiver);
    }

    /// Register a pending block subscription by commitment on `node` with a
    /// round-bound fetch fallback: the exact mailbox call the wrapper's verify
    /// makes for a missing parent.
    pub(crate) fn subscribe_commitment_fetch_by_round(
        &mut self,
        node: Node,
        view: u64,
        commitment: Sha256Digest,
    ) {
        let receiver = self.mailboxes[node.idx()].subscribe_by_commitment(
            commitment,
            CommitmentFallback::FetchByRound {
                round: Self::round(view),
            },
        );
        self.subscriptions.push(receiver);
    }

    /// Install a finalization as the marshal floor on `node`.
    pub(crate) fn set_floor(
        &self,
        node: Node,
        finalization: Finalization<SchemeOf<P>, Sha256Digest>,
    ) {
        self.mailboxes[node.idx()].set_floor(finalization);
    }

    /// Seed `block` into `from`'s broadcast buffer addressed to `to`. The
    /// prefix network has no links, so nothing is delivered before the fuzzing
    /// phase.
    pub(crate) fn broadcast(&self, from: Node, to: &[Node], block: &B<P>) {
        let recipients = Recipients::Some(
            to.iter()
                .map(|node| self.participants[node.idx()].clone())
                .collect(),
        );
        let _ = self.buffers[from.idx()].broadcast_shared(recipients, Arc::new(block.clone()));
    }

    /// FIFO barrier: a round-trip that flushes prior fire-and-forget messages so
    /// the prefix reaches a deterministic stop point.
    pub(crate) async fn barrier(&self, node: Node) -> Option<Height> {
        self.mailboxes[node.idx()].get_processed_height().await
    }

    /// Fence a pending state: assert `digest` is not locally available on
    /// `node`. The round-trip doubles as a FIFO barrier, so the absence is
    /// validated after every prior message has been processed.
    pub(crate) async fn missing(&self, node: Node, digest: Sha256Digest) {
        assert!(
            self.mailboxes[node.idx()]
                .get_block(&digest)
                .await
                .is_none(),
            "block must still be missing at handoff: node={node:?} digest={digest}",
        );
    }

    /// Advance simulated time.
    pub(crate) async fn settle(&self, duration: Duration) {
        self.context.sleep(duration).await;
    }
}

/// The state the prefix leaves for the fuzzing phase.
pub(crate) struct FuzzPoint<P: Simplex> {
    /// The canonical tip finalization every honest engine starts from.
    pub(crate) floor: Finalization<SchemeOf<P>, Sha256Digest>,
    /// The canonical chain the honest nodes reconstruct.
    pub(crate) canonical: Vec<B<P>>,
    /// Per-scenario invariant-selection hints.
    pub(crate) expectation: Expectation,
}

/// Scenario shape that selects which safety invariant applies.
pub(crate) struct Expectation {
    /// A node whose marshal floor was advanced in the prefix, so its delivery
    /// begins at the floor height rather than height 1. It is still checked for
    /// cross-node agreement and parent linkage; only the genesis-rooted
    /// in-order rule is replaced with a floor-aware one.
    pub(crate) floor_started: Option<Node>,
}
