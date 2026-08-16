//! Scripted marshal environment: the verbs a [`Scenario`](super::scenarios::Scenario)
//! prefix uses to drive four validators into an interesting state.
//!
//! The verbs act directly on the marshal mailboxes below the consensus engine,
//! so a scenario can build a canonical chain, fabricate quorum certificates over
//! a chosen signer subset, report them, open subscriptions, and install floors
//! without a running engine. The prefix stops at a chosen semantic point and
//! hands back a [`FuzzPoint`] describing the certified floor the engines then
//! start from plus the state the fuzzing phase must reconcile.

use crate::{
    marshal::end_to_end::{
        app::SelectedBlockBuilderApp,
        twins::{
            B, Ctx, PublicKeyOf, SchemeOf,
            stack::{SelectedMarshal, TwinsMarshal},
        },
    },
    simplex::Simplex,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    Automaton as _, CertifiableAutomaton as _, Heightable, Reporter as _,
    marshal::{
        core::{DigestFallback, Mailbox},
        standard::Standard,
    },
    simplex::types::{Activity, Finalization, Finalize, Notarization, Notarize, Proposal},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digestible, Sha256};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, deterministic};
use commonware_utils::channel::oneshot;
use std::{sync::Arc, time::Duration};

/// Marshal mailbox for the standard variant over the mock block.
pub(crate) type Mb<P> = Mailbox<SchemeOf<P>, Standard<B<P>>>;

/// Bounded wait for the real automaton certify to resolve, so a broken
/// certify -> notarized-fetch path fails clearly instead of hanging.
const CERTIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// The marshal automaton wrapper the scenario setup builds, matching the wrapper
/// type in [`runner`](super::runner). Lets a scenario drive the real
/// `verify`/`certify` automaton path rather than the raw mailbox.
pub(crate) type Wrapper<P> =
    <SelectedMarshal as TwinsMarshal<P, SelectedBlockBuilderApp<Ctx<P>, SchemeOf<P>>>>::Wrapper;

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
    /// One automaton wrapper per node (placeholder for the marshal-less
    /// adversary slot), for scenarios that drive the real verify/certify path.
    pub(crate) builders: Vec<Wrapper<P>>,
    #[allow(dead_code)]
    pub(crate) buffers: Vec<buffered::Mailbox<PublicKeyOf<P>, B<P>>>,
    pub(crate) genesis: B<P>,
    pub(crate) canonical: Vec<B<P>>,
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

    /// Build a side/fork block on an explicit parent without appending it to the
    /// canonical chain.
    pub(crate) fn fork_block(
        &self,
        parent: &B<P>,
        leader: Node,
        view: u64,
        height: Height,
    ) -> B<P> {
        self.build_block(leader, view, parent.context.round.view(), parent.digest(), height)
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

    /// Drive the real automaton's optimistic verify on `node` for a block it does
    /// not yet hold, registering the certification gate. The returned receiver
    /// must be kept alive until after [`Self::automaton_certify`] resolves, so the
    /// gate stays open and certify takes the existing-task (hint-notarized) path.
    pub(crate) async fn automaton_verify_hold(
        &self,
        node: Node,
        context: Ctx<P>,
        digest: Sha256Digest,
    ) -> oneshot::Receiver<bool> {
        let mut builder = self.builders[node.idx()].clone();
        builder.verify(context, digest).await
    }

    /// Invoke the real automaton's certify on `node`, returning whether it
    /// resolved true. Certify itself issues the notarized fetch, so this drives
    /// the candidate repair rather than the scenario nudging it by hand.
    pub(crate) async fn automaton_certify(
        &self,
        node: Node,
        view: u64,
        digest: Sha256Digest,
    ) -> bool {
        let mut builder = self.builders[node.idx()].clone();
        let receiver = builder.certify(Self::round(view), digest).await;
        select! {
            result = receiver => result.unwrap_or(false),
            _ = self.context.sleep(CERTIFY_TIMEOUT) => {
                panic!("certify never resolved on node {node:?} at view {view}: notarized fetch stalled");
            },
        }
    }

    /// Whether `node` holds the block for `digest` in local marshal storage.
    pub(crate) async fn get_block(&self, node: Node, digest: Sha256Digest) -> Option<B<P>> {
        self.mailboxes[node.idx()].get_block(&digest).await
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

    /// Install a finalization as the marshal floor on `node`.
    pub(crate) fn set_floor(&self, node: Node, finalization: Finalization<SchemeOf<P>, Sha256Digest>) {
        self.mailboxes[node.idx()].set_floor(finalization);
    }

    /// Open a wait-only digest subscription on `node`; the receiver must be held
    /// until the fuzzing phase or the subscription is cancelled.
    pub(crate) fn subscribe(&self, node: Node, digest: Sha256Digest) -> oneshot::Receiver<Arc<B<P>>> {
        self.mailboxes[node.idx()].subscribe_by_digest(digest, DigestFallback::Wait)
    }

    /// Gossip `block` from `from` to `to` through the broadcast buffer.
    pub(crate) fn broadcast(&self, from: Node, to: &[Node], block: &B<P>) {
        let recipients =
            Recipients::Some(to.iter().map(|node| self.participants[node.idx()].clone()).collect());
        let _ = self.buffers[from.idx()].broadcast_shared(recipients, Arc::new(block.clone()));
    }

    /// The view of the finalization `node` has stored for `height`, if any.
    pub(crate) async fn finalization_view(&self, node: Node, height: u64) -> Option<u64> {
        self.mailboxes[node.idx()]
            .get_finalization(Height::new(height))
            .await
            .map(|finalization| finalization.round().view().get())
    }

    /// FIFO barrier: a round-trip that flushes prior fire-and-forget messages so
    /// the prefix reaches a deterministic stop point.
    pub(crate) async fn barrier(&self, node: Node) -> Option<Height> {
        self.mailboxes[node.idx()].get_processed_height().await
    }

    /// Advance simulated time.
    pub(crate) async fn settle(&self, duration: Duration) {
        self.context.sleep(duration).await;
    }
}

/// A subscription opened in the prefix that must resolve with a specific block.
pub(crate) struct PendingBlock<P: Simplex> {
    pub(crate) node: Node,
    /// The digest the resolved block must have.
    pub(crate) expected: Sha256Digest,
    pub(crate) receiver: oneshot::Receiver<Arc<B<P>>>,
}

/// The state the prefix leaves for the fuzzing phase.
pub(crate) struct FuzzPoint<P: Simplex> {
    /// The canonical tip finalization every honest engine starts from.
    pub(crate) floor: Finalization<SchemeOf<P>, Sha256Digest>,
    /// The canonical chain the deprived node must reconstruct.
    pub(crate) canonical: Vec<B<P>>,
    /// Fetches that must resolve, with the correct block, before the engines
    /// start (so a later floor advance cannot prune them first).
    pub(crate) prefix_fetches: Vec<PendingBlock<P>>,
    /// Subscriptions that must resolve, with the correct block, after the
    /// fuzzing window.
    pub(crate) subscriptions: Vec<PendingBlock<P>>,
    /// Per-scenario recovery expectations.
    pub(crate) expectation: Expectation,
}

/// What the fuzzing phase must observe for the scenario to be considered
/// recovered.
pub(crate) struct Expectation {
    /// A node whose marshal floor was advanced in the prefix, so its delivery
    /// begins at the floor height rather than height 1. It is still checked for
    /// cross-node agreement and parent linkage; only the genesis-rooted
    /// in-order rule is replaced with a floor-aware one.
    pub(crate) floor_started: Option<Node>,
    /// The deprived node whose processed height must catch up.
    pub(crate) deprived: Node,
    /// The height the deprived node must reach after the fuzzing window.
    pub(crate) deprived_min_height: u64,
    /// Per-node finalization-view re-checks after the fuzzing window:
    /// `(node, height, expected_view)`. The immutable finalization archive never
    /// prunes, so `node` must retain exactly the view it finalized first; the
    /// re-check reads it reliably and requires `Some(expected_view)`, so both an
    /// overwrite to the losing view and a lost/absent entry fail.
    pub(crate) finalization_views: Vec<(Node, u64, u64)>,
}
