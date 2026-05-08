use super::Variant;
use crate::{
    marshal::{
        ancestry::{AncestorStream, BlockProvider},
        Identifier,
    },
    simplex::types::{Activity, Finalization, Notarization},
    types::{Height, Round},
    Heightable, Reporter,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_p2p::Recipients;
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    vec::NonEmptyVec,
};

/// Messages sent to the marshal [Actor](super::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub(crate) enum Message<S: Scheme, V: Variant> {
    /// A request to retrieve the `(height, digest)` of a block by its identifier.
    /// The block must be finalized; returns `None` if the block is not finalized.
    GetInfo {
        /// The identifier of the block to get the information of.
        identifier: Identifier<<V::Block as Digestible>::Digest>,
        /// A channel to send the retrieved `(height, digest)`.
        response: oneshot::Sender<Option<(Height, <V::Block as Digestible>::Digest)>>,
    },
    /// A request to retrieve a block by its identifier.
    ///
    /// Requesting by [Identifier::Height] or [Identifier::Latest] will only return finalized
    /// blocks, whereas requesting by [Identifier::Digest] may return non-finalized
    /// or even unverified blocks.
    GetBlock {
        /// The identifier of the block to retrieve.
        identifier: Identifier<<V::Block as Digestible>::Digest>,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<V::Block>>,
    },
    /// A request to retrieve a finalization by height.
    GetFinalization {
        /// The height of the finalization to retrieve.
        height: Height,
        /// A channel to send the retrieved finalization.
        response: oneshot::Sender<Option<Finalization<S, V::Commitment>>>,
    },
    /// A hint that a finalized block may be available at a given height.
    ///
    /// This triggers a network fetch if the finalization is not available locally.
    /// This is fire-and-forget: the finalization will be stored in marshal and
    /// delivered via the normal finalization flow when available.
    ///
    /// The height must be covered by both the epocher and the provider. If the
    /// epocher cannot map the height to an epoch, or the provider cannot supply
    /// a scheme for that epoch, the hint is silently dropped.
    ///
    /// Targets are required because this is typically called when a peer claims to
    /// be ahead. If a target returns invalid data, the resolver will block them.
    /// Sending this message multiple times with different targets adds to the
    /// target set.
    HintFinalized {
        /// The height of the finalization to fetch.
        height: Height,
        /// Target peers to fetch from. Added to any existing targets for this height.
        targets: NonEmptyVec<S::PublicKey>,
    },
    /// A request to subscribe to a block by its digest.
    SubscribeByDigest {
        /// The round in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
        /// The digest of the block to retrieve.
        digest: <V::Block as Digestible>::Digest,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<V::Block>,
    },
    /// A request to subscribe to a block by its commitment.
    SubscribeByCommitment {
        /// Whether marshal should request the block if it is missing locally.
        request: CommitmentRequest,
        /// The commitment of the block to retrieve.
        commitment: V::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<V::Block>,
    },
    /// A request to retrieve the verified block previously persisted for `round`.
    GetVerified {
        /// The round to query.
        round: Round,
        /// A channel to send the retrieved block, if any.
        response: oneshot::Sender<Option<V::Block>>,
    },
    /// A request to forward a block to a set of recipients.
    Forward {
        /// The round in which the block was proposed.
        round: Round,
        /// The commitment of the block to forward.
        commitment: V::Commitment,
        /// The recipients to forward the block to.
        recipients: Recipients<S::PublicKey>,
    },
    /// A notification that a block has been locally proposed by this node.
    Proposed {
        /// The round in which the block was proposed.
        round: Round,
        /// The proposed block.
        block: V::Block,
        /// A channel signaled once the block is durably stored.
        ack: oneshot::Sender<()>,
    },
    /// A notification that a block has been verified by the application.
    Verified {
        /// The round in which the block was verified.
        round: Round,
        /// The verified block.
        block: V::Block,
        /// A channel signaled once the block is durably stored.
        ack: oneshot::Sender<()>,
    },
    /// A notification that a block has been certified by the application.
    Certified {
        /// The round in which the block was certified.
        round: Round,
        /// The certified block.
        block: V::Block,
        /// A channel signaled once the block is durably stored.
        ack: oneshot::Sender<()>,
    },
    /// Sets the sync starting point (advances if higher than current).
    ///
    /// Marshal will sync and deliver blocks starting at `floor + 1`. Data below
    /// the floor is pruned.
    ///
    /// To prune data without affecting the sync starting point (say at some trailing depth
    /// from tip), use [Message::Prune] instead.
    ///
    /// The default floor is 0.
    SetFloor {
        /// The candidate floor height.
        height: Height,
    },
    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [Message::SetFloor], this does not affect the sync starting point.
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
    Prune {
        /// The minimum height to keep (blocks below this are pruned).
        height: Height,
    },
    /// A notarization from the consensus engine.
    Notarization {
        /// The notarization.
        notarization: Notarization<S, V::Commitment>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The finalization.
        finalization: Finalization<S, V::Commitment>,
    },
}

/// How a commitment subscription should behave when the block is missing locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentRequest {
    /// Wait for local availability only.
    Wait,
    /// Request the notarized proposal for `round` from peers.
    FetchByRound { round: Round },
    /// Request the exact commitment from peers and prune the request at `height`.
    FetchByCommitment { height: Height },
}

/// A mailbox for sending messages to the marshal [Actor](super::Actor).
#[derive(Clone)]
pub struct Mailbox<S: Scheme, V: Variant> {
    sender: mpsc::Sender<Message<S, V>>,
}

/// A block provider with explicit network-fetch behavior for missing ancestors.
#[derive(Clone)]
pub struct AncestryProvider<S: Scheme, V: Variant> {
    mailbox: Mailbox<S, V>,
    fetch_missing: bool,
}

impl<S: Scheme, V: Variant> Mailbox<S, V> {
    /// Creates a new mailbox.
    pub(crate) const fn new(sender: mpsc::Sender<Message<S, V>>) -> Self {
        Self { sender }
    }

    /// Create an ancestry provider that only listens for local block availability.
    pub(crate) fn local_ancestry_provider(&self) -> AncestryProvider<S, V> {
        AncestryProvider {
            mailbox: self.clone(),
            fetch_missing: false,
        }
    }

    /// Create an ancestry provider that fetches missing parents by commitment.
    pub(crate) fn fetching_ancestry_provider(&self) -> AncestryProvider<S, V> {
        AncestryProvider {
            mailbox: self.clone(),
            fetch_missing: true,
        }
    }

    /// A request to retrieve the information about the highest finalized block.
    pub async fn get_info(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> Option<(Height, <V::Block as Digestible>::Digest)> {
        let identifier = identifier.into();
        self.sender
            .request(|response| Message::GetInfo {
                identifier,
                response,
            })
            .await
            .flatten()
    }

    /// A best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub async fn get_block(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> Option<V::Block> {
        let identifier = identifier.into();
        self.sender
            .request(|response| Message::GetBlock {
                identifier,
                response,
            })
            .await
            .flatten()
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub async fn get_finalization(&self, height: Height) -> Option<Finalization<S, V::Commitment>> {
        self.sender
            .request(|response| Message::GetFinalization { height, response })
            .await
            .flatten()
    }

    /// Hints that a finalized block may be available at the given height.
    ///
    /// This method will request the finalization from the network via the resolver
    /// if it is not available locally.
    ///
    /// Targets are required because this is typically called when a peer claims to be
    /// ahead. By targeting only those peers, we limit who we ask. If a target returns
    /// invalid data, they will be blocked by the resolver. If targets don't respond
    /// or return "no data", they effectively rate-limit themselves.
    ///
    /// Calling this multiple times for the same height with different targets will
    /// add to the target set if there is an ongoing fetch, allowing more peers to be tried.
    ///
    /// This is fire-and-forget: the finalization will be stored in marshal and delivered
    /// via the normal finalization flow when available.
    ///
    /// The height must be covered by both the epocher and the provider. If the
    /// epocher cannot map the height to an epoch, or the provider cannot supply
    /// a scheme for that epoch, the hint is silently dropped.
    pub async fn hint_finalized(&self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        self.sender
            .send_lossy(Message::HintFinalized { height, targets })
            .await;
    }

    /// Subscribe to a block by its digest.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the subscription will be registered and the caller
    /// will be notified when the block is available. If the block is not finalized, it's possible
    /// that it may never become available.
    ///
    /// If `round` is provided, marshal also asks peers for the notarized proposal at that round.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    async fn subscribe_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
        round: Option<Round>,
    ) -> oneshot::Receiver<V::Block> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send_lossy(Message::SubscribeByDigest {
                round,
                digest,
                response: tx,
            })
            .await;
        rx
    }

    /// Subscribe to a block by its commitment.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the subscription will be registered and the caller
    /// will be notified when the block is available. If the block is not finalized, it's possible
    /// that it may never become available.
    ///
    /// The `request` parameter controls whether marshal also asks peers for the missing block.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub async fn subscribe_by_commitment(
        &self,
        commitment: V::Commitment,
        request: CommitmentRequest,
    ) -> oneshot::Receiver<V::Block> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send_lossy(Message::SubscribeByCommitment {
                request,
                commitment,
                response: tx,
            })
            .await;
        rx
    }

    /// Returns an [AncestorStream] over the ancestry of a given block, leading up to genesis.
    ///
    /// If the starting block is not found, `None` is returned.
    pub async fn ancestry(
        &self,
        (start_round, start_digest): (Option<Round>, <V::Block as Digestible>::Digest),
    ) -> Option<AncestorStream<AncestryProvider<S, V>>> {
        let receiver = self.subscribe_by_digest(start_digest, start_round).await;
        receiver
            .await
            .ok()
            .map(|block| AncestorStream::new(self.fetching_ancestry_provider(), [block]))
    }

    /// Returns the verified block previously persisted for `round`, if any.
    pub async fn get_verified(&self, round: Round) -> Option<V::Block> {
        self.sender
            .request(|response| Message::GetVerified { round, response })
            .await
            .flatten()
    }

    /// Notifies the actor that a block has been locally proposed, awaiting
    /// the actor's confirmation that the block has been durably persisted
    /// before returning.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn proposed(&self, round: Round, block: V::Block) -> bool {
        self.sender
            .request(|ack| Message::Proposed { round, block, ack })
            .await
            .is_some()
    }

    /// Notifies the actor that a block has been verified, awaiting the actor's
    /// confirmation that the block has been durably persisted before returning.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn verified(&self, round: Round, block: V::Block) -> bool {
        self.sender
            .request(|ack| Message::Verified { round, block, ack })
            .await
            .is_some()
    }

    /// Notifies the actor that a block has been certified, awaiting the actor's
    /// confirmation that the block has been durably persisted before returning.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn certified(&self, round: Round, block: V::Block) -> bool {
        self.sender
            .request(|ack| Message::Certified { round, block, ack })
            .await
            .is_some()
    }

    /// Sets the sync starting point (advances if higher than current).
    ///
    /// Marshal will sync and deliver blocks starting at `floor + 1`. Data below
    /// the floor is pruned.
    ///
    /// To prune data without affecting the sync starting point (say at some trailing depth
    /// from tip), use [Self::prune] instead.
    ///
    /// The default floor is 0.
    pub async fn set_floor(&self, height: Height) {
        self.sender.send_lossy(Message::SetFloor { height }).await;
    }

    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [Self::set_floor], this does not affect the sync starting point.
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
    ///
    /// A `prune` request for a height above marshal's current floor is dropped.
    pub async fn prune(&self, height: Height) {
        self.sender.send_lossy(Message::Prune { height }).await;
    }

    /// Forward a block to a set of recipients.
    pub async fn forward(
        &self,
        round: Round,
        commitment: V::Commitment,
        recipients: Recipients<S::PublicKey>,
    ) {
        self.sender
            .send_lossy(Message::Forward {
                round,
                commitment,
                recipients,
            })
            .await;
    }
}

impl<S: Scheme, V: Variant> BlockProvider for AncestryProvider<S, V> {
    type Block = V::ApplicationBlock;
    type AncestryBlock = V::Block;

    async fn subscribe(
        self,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<Self::AncestryBlock> {
        let subscription = self.mailbox.subscribe_by_digest(digest, None).await;
        subscription.await.ok()
    }

    async fn subscribe_parent(self, block: Self::AncestryBlock) -> Option<Self::AncestryBlock> {
        let parent_height = block.height().previous()?;
        let commitment = V::parent_commitment(&block);
        let request = if self.fetch_missing {
            CommitmentRequest::FetchByCommitment {
                height: parent_height,
            }
        } else {
            CommitmentRequest::Wait
        };
        let subscription = self
            .mailbox
            .subscribe_by_commitment(commitment, request)
            .await;
        subscription.await.ok()
    }

    fn into_block(block: Self::AncestryBlock) -> Self::Block {
        V::into_inner(block)
    }
}

impl<S: Scheme, V: Variant> Reporter for Mailbox<S, V> {
    type Activity = Activity<S, V::Commitment>;

    async fn report(&mut self, activity: Self::Activity) {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization { notarization },
            Activity::Finalization(finalization) => Message::Finalization { finalization },
            _ => {
                // Ignore other activity types
                return;
            }
        };
        self.sender.send_lossy(message).await;
    }
}
