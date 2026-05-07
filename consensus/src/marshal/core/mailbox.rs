use super::Variant;
use crate::{
    marshal::{
        ancestry::{AncestorStream, BlockProvider},
        Identifier,
    },
    simplex::types::{Activity, Finalization, Notarization},
    types::{Height, Round},
    Reporter,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_p2p::Recipients;
use commonware_utils::{
    channel::{
        actor::{ActorMailbox, Enqueue, FullPolicy, MessagePolicy},
        oneshot,
    },
    vec::NonEmptyVec,
};
use std::collections::VecDeque;

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
        /// The round in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
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

impl<S: Scheme, V: Variant> MessagePolicy for Message<S, V> {
    fn kind(&self) -> &'static str {
        match self {
            Self::GetInfo { .. } => "get_info",
            Self::GetBlock { .. } => "get_block",
            Self::GetFinalization { .. } => "get_finalization",
            Self::HintFinalized { .. } => "hint_finalized",
            Self::SubscribeByDigest { .. } => "subscribe_by_digest",
            Self::SubscribeByCommitment { .. } => "subscribe_by_commitment",
            Self::GetVerified { .. } => "get_verified",
            Self::Forward { .. } => "forward",
            Self::Proposed { .. } => "proposed",
            Self::Verified { .. } => "verified",
            Self::Certified { .. } => "certified",
            Self::SetFloor { .. } => "set_floor",
            Self::Prune { .. } => "prune",
            Self::Notarization { .. } => "notarization",
            Self::Finalization { .. } => "finalization",
        }
    }

    fn full_policy(&self) -> FullPolicy {
        match self {
            Self::HintFinalized { .. } => FullPolicy::Replace,
            _ => FullPolicy::Retain,
        }
    }

    fn replace(queue: &mut VecDeque<Self>, message: Self) -> Result<(), Self> {
        match message {
            Self::HintFinalized {
                height,
                targets,
            } => {
                for pending in queue.iter_mut().rev() {
                    let Self::HintFinalized {
                        height: pending_height,
                        targets: pending_targets,
                    } = pending
                    else {
                        continue;
                    };
                    if *pending_height != height {
                        continue;
                    }
                    pending_targets.extend(targets);
                    return Ok(());
                }
                Err(Self::HintFinalized { height, targets })
            }
            message => Err(message),
        }
    }
}

/// A mailbox for sending messages to the marshal [Actor](super::Actor).
#[derive(Clone)]
pub struct Mailbox<S: Scheme, V: Variant> {
    sender: ActorMailbox<Message<S, V>>,
}

impl<S: Scheme, V: Variant> Mailbox<S, V> {
    /// Creates a new mailbox.
    pub(crate) const fn new(sender: ActorMailbox<Message<S, V>>) -> Self {
        Self { sender }
    }

    async fn request<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<T>) -> Message<S, V>,
    ) -> Option<T> {
        let (response, receiver) = oneshot::channel();
        if !self.sender.enqueue(make(response)).accepted() {
            return None;
        }
        receiver.await.ok()
    }

    /// A request to retrieve the information about the highest finalized block.
    pub async fn get_info(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> Option<(Height, <V::Block as Digestible>::Digest)> {
        let identifier = identifier.into();
        self.request(|response| Message::GetInfo {
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
        self.request(|response| Message::GetBlock {
                identifier,
                response,
            })
            .await
            .flatten()
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub async fn get_finalization(&self, height: Height) -> Option<Finalization<S, V::Commitment>> {
        self.request(|response| Message::GetFinalization { height, response })
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
        let _ = self
            .sender
            .enqueue(Message::HintFinalized { height, targets });
    }

    /// Subscribe to a block by its digest.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub async fn subscribe_by_digest(
        &self,
        round: Option<Round>,
        digest: <V::Block as Digestible>::Digest,
    ) -> oneshot::Receiver<V::Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByDigest {
                round,
                digest,
                response: tx,
            });
        rx
    }

    /// Subscribe to a block by its commitment.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub async fn subscribe_by_commitment(
        &self,
        round: Option<Round>,
        commitment: V::Commitment,
    ) -> oneshot::Receiver<V::Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByCommitment {
                round,
                commitment,
                response: tx,
            });
        rx
    }

    /// Returns an [AncestorStream] over the ancestry of a given block, leading up to genesis.
    ///
    /// If the starting block is not found, `None` is returned.
    pub async fn ancestry(
        &self,
        (start_round, start_digest): (Option<Round>, <V::Block as Digestible>::Digest),
    ) -> Option<AncestorStream<Self, V::ApplicationBlock>> {
        self.subscribe_by_digest(start_round, start_digest)
            .await
            .await
            .ok()
            .map(|block| AncestorStream::new(self.clone(), [V::into_inner(block)]))
    }

    /// Returns the verified block previously persisted for `round`, if any.
    pub async fn get_verified(&self, round: Round) -> Option<V::Block> {
        self.request(|response| Message::GetVerified { round, response })
            .await
            .flatten()
    }

    /// Notifies the actor that a block has been locally proposed, awaiting
    /// the actor's confirmation that the block has been durably persisted
    /// before returning.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn proposed(&self, round: Round, block: V::Block) -> bool {
        self.request(|ack| Message::Proposed { round, block, ack })
            .await
            .is_some()
    }

    /// Notifies the actor that a block has been verified, awaiting the actor's
    /// confirmation that the block has been durably persisted before returning.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn verified(&self, round: Round, block: V::Block) -> bool {
        self.request(|ack| Message::Verified { round, block, ack })
            .await
            .is_some()
    }

    /// Notifies the actor that a block has been certified, awaiting the actor's
    /// confirmation that the block has been durably persisted before returning.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn certified(&self, round: Round, block: V::Block) -> bool {
        self.request(|ack| Message::Certified { round, block, ack })
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
        let _ = self.sender.enqueue(Message::SetFloor { height });
    }

    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [Self::set_floor], this does not affect the sync starting point.
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
    ///
    /// A `prune` request for a height above marshal's current floor is dropped.
    pub async fn prune(&self, height: Height) {
        let _ = self.sender.enqueue(Message::Prune { height });
    }

    /// Forward a block to a set of recipients.
    pub async fn forward(
        &self,
        round: Round,
        commitment: V::Commitment,
        recipients: Recipients<S::PublicKey>,
    ) {
        let _ = self.sender.enqueue(Message::Forward {
                round,
                commitment,
                recipients,
            });
    }
}

impl<S: Scheme, V: Variant> BlockProvider for Mailbox<S, V> {
    type Block = V::ApplicationBlock;

    async fn fetch_block(self, digest: <V::Block as Digestible>::Digest) -> Option<Self::Block> {
        let subscription = self.subscribe_by_digest(None, digest).await;
        subscription.await.ok().map(V::into_inner)
    }
}

impl<S: Scheme, V: Variant> Reporter for Mailbox<S, V> {
    type Activity = Activity<S, V::Commitment>;

    fn report(&mut self, activity: Self::Activity) -> Enqueue<()> {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization { notarization },
            Activity::Finalization(finalization) => Message::Finalization { finalization },
            _ => {
                // Ignore other activity types
                return Enqueue::Rejected(());
            }
        };
        match self.sender.enqueue(message) {
            Enqueue::Queued => Enqueue::Queued,
            Enqueue::Replaced => Enqueue::Replaced,
            Enqueue::Rejected(_) => Enqueue::Rejected(()),
            Enqueue::Closed(_) => Enqueue::Closed(()),
        }
    }
}
