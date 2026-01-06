use crate::{
    marshal::{
        ancestry::{AncestorStream, AncestryProvider},
        coding::types::{CodedBlock, DigestOrCommitment},
        Identifier,
    },
    simplex::types::{Activity, Finalization, Notarization},
    types::{CodingCommitment, Round},
    Block, Reporter,
};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::certificate::Scheme;
use commonware_utils::vec::NonEmptyVec;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// Messages sent to the marshal [Actor](super::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub(crate) enum Message<S: Scheme, B: Block, C: CodingScheme> {
    // -------------------- Application Messages --------------------
    /// A request to retrieve the (height, digest) of a block by its identifier.
    /// The block must be finalized; returns `None` if the block is not finalized.
    GetInfo {
        /// The identifier of the block to get the information of.
        identifier: Identifier<B::Digest>,
        /// A channel to send the retrieved (height, digest).
        response: oneshot::Sender<Option<(u64, B::Digest)>>,
    },
    /// A request to retrieve a block by its identifier.
    ///
    /// Requesting by [Identifier::Height] or [Identifier::Latest] will only return finalized
    /// blocks, whereas requesting by digest may return non-finalized or even unverified blocks.
    GetBlock {
        /// The identifier of the block to retrieve.
        identifier: Identifier<B::Digest>,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<CodedBlock<B, C>>>,
    },
    /// A request to retrieve a finalization by height.
    GetFinalization {
        /// The height of the finalization to retrieve.
        height: u64,
        /// A channel to send the retrieved finalization.
        response: oneshot::Sender<Option<Finalization<S, CodingCommitment>>>,
    },
    /// A hint that a finalized block may be available at a given height.
    ///
    /// This triggers a network fetch if the finalization is not available locally.
    /// This is fire-and-forget: the finalization will be stored in marshal and
    /// delivered via the normal finalization flow when available.
    ///
    /// Targets are required because this is typically called when a peer claims to
    /// be ahead. If a target returns invalid data, the resolver will block them.
    /// Sending this message multiple times with different targets adds to the
    /// target set.
    HintFinalized {
        /// The height of the finalization to fetch.
        height: u64,
        /// Target peers to fetch from. Added to any existing targets for this height.
        targets: NonEmptyVec<S::PublicKey>,
    },
    /// A request to retrieve a block by its digest.
    Subscribe {
        /// The view in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
        /// The [DigestOrCommitment] of the block to retrieve.
        id: DigestOrCommitment<B::Digest>,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<CodedBlock<B, C>>,
    },
    /// Sets the sync starting point (advances if higher than current).
    ///
    /// Marshal will sync and deliver blocks starting at `floor + 1`. Data at or
    /// below the floor is pruned.
    ///
    /// To prune data without affecting the sync starting point (say at some trailing depth
    /// from tip), prune the finalized stores directly.
    ///
    /// The default floor is 0.
    SetFloor {
        /// The candidate floor height.
        height: u64,
    },

    // -------------------- Consensus Engine Messages --------------------
    /// A notarization from the consensus engine.
    Notarization {
        /// The notarization.
        notarization: Notarization<S, CodingCommitment>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The finalization.
        finalization: Finalization<S, CodingCommitment>,
    },
}

/// A mailbox for sending messages to the marshal [Actor](super::Actor).
#[derive(Clone)]
pub struct Mailbox<S: Scheme, B: Block, C: CodingScheme> {
    sender: mpsc::Sender<Message<S, B, C>>,
}

impl<S: Scheme, B: Block, C: CodingScheme> Mailbox<S, B, C> {
    /// Creates a new mailbox.
    pub(crate) const fn new(sender: mpsc::Sender<Message<S, B, C>>) -> Self {
        Self { sender }
    }

    /// A request to retrieve the information about the highest finalized block.
    pub async fn get_info(
        &mut self,
        identifier: impl Into<Identifier<B::Digest>>,
    ) -> Option<(u64, B::Digest)> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::GetInfo {
                identifier: identifier.into(),
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send get info message to actor: receiver dropped");
        }
        rx.await.unwrap_or_else(|_| {
            error!("failed to get info: receiver dropped");
            None
        })
    }

    /// A best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub async fn get_block(
        &mut self,
        identifier: impl Into<Identifier<B::Digest>>,
    ) -> Option<CodedBlock<B, C>> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::GetBlock {
                identifier: identifier.into(),
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send get block message to actor: receiver dropped");
        }
        rx.await.unwrap_or_else(|_| {
            error!("failed to get block: receiver dropped");
            None
        })
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub async fn get_finalization(
        &mut self,
        height: u64,
    ) -> Option<Finalization<S, CodingCommitment>> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::GetFinalization {
                height,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send get finalization message to actor: receiver dropped");
        }
        rx.await.unwrap_or_else(|_| {
            error!("failed to get finalization: receiver dropped");
            None
        })
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
    pub async fn hint_finalized(&mut self, height: u64, targets: NonEmptyVec<S::PublicKey>) {
        if self
            .sender
            .send(Message::HintFinalized { height, targets })
            .await
            .is_err()
        {
            error!("failed to send hint finalized message to actor: receiver dropped");
        }
    }

    /// A request to retrieve a block by its [DigestOrCommitment].
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub async fn subscribe(
        &mut self,
        round: Option<Round>,
        id: DigestOrCommitment<B::Digest>,
    ) -> oneshot::Receiver<CodedBlock<B, C>> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::Subscribe {
                round,
                id,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send subscribe message to actor: receiver dropped");
        }
        rx
    }

    /// Returns an [AncestorStream] over the ancestry of a given block, leading up to genesis.
    ///
    /// If the starting block is not found, `None` is returned.
    pub async fn ancestry(
        &mut self,
        (start_round, start_digest): (Option<Round>, B::Digest),
    ) -> Option<AncestorStream<Self, B>> {
        self.subscribe(start_round, DigestOrCommitment::Digest(start_digest))
            .await
            .await
            .ok()
            .map(|block| AncestorStream::new(self.clone(), [block.into_inner()]))
    }

    /// Sets the sync starting point (advances if higher than current).
    ///
    /// Marshal will sync and deliver blocks starting at `floor + 1`. Data at or
    /// below the floor is pruned.
    ///
    /// To prune data without affecting the sync starting point (say at some trailing depth
    /// from tip), prune the finalized stores directly.
    ///
    /// The default floor is 0.
    pub async fn set_floor(&mut self, height: u64) {
        if self
            .sender
            .send(Message::SetFloor { height })
            .await
            .is_err()
        {
            error!("failed to send set floor message to actor: receiver dropped");
        }
    }

    /// Notifies the actor of a verified [`Finalization`].
    ///
    /// This is a trusted call that injects a finalization directly into marshal. The
    /// finalization is expected to have already been verified by the caller.
    pub async fn finalization(&mut self, finalization: Finalization<S, CodingCommitment>) {
        if self
            .sender
            .send(Message::Finalization { finalization })
            .await
            .is_err()
        {
            error!("failed to send finalization message to actor: receiver dropped");
        }
    }
}

impl<S: Scheme, B: Block, C: CodingScheme> AncestryProvider for Mailbox<S, B, C> {
    type Block = B;

    async fn fetch_block(mut self, digest: B::Digest) -> B {
        let subscription = self
            .subscribe(None, DigestOrCommitment::Digest(digest))
            .await;
        subscription
            .await
            .expect("marshal actor dropped before fulfilling subscription")
            .into_inner()
    }
}

impl<S: Scheme, B: Block, C: CodingScheme> Reporter for Mailbox<S, B, C> {
    type Activity = Activity<S, CodingCommitment>;

    async fn report(&mut self, activity: Self::Activity) {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization { notarization },
            Activity::Finalization(finalization) => Message::Finalization { finalization },
            _ => {
                // Ignore other activity types
                return;
            }
        };
        if self.sender.send(message).await.is_err() {
            error!("failed to report activity to actor: receiver dropped");
        }
    }
}
