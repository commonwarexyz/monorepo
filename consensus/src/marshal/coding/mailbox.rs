use crate::{
    marshal::{
        ancestry::{AncestorStream, AncestryProvider},
        coding::types::{CodedBlock, DigestOrCommitment},
        Identifier,
    },
    simplex::types::{Activity, Finalization, Notarization},
    types::{CodingCommitment, Height, Round},
    Block, Reporter,
};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::certificate::Scheme;
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    vec::NonEmptyVec,
};

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
        response: oneshot::Sender<Option<(Height, B::Digest)>>,
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
        height: Height,
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
        height: Height,
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
    ) -> Option<(Height, B::Digest)> {
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
        &mut self,
        identifier: impl Into<Identifier<B::Digest>>,
    ) -> Option<CodedBlock<B, C>> {
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
    pub async fn get_finalization(
        &mut self,
        height: Height,
    ) -> Option<Finalization<S, CodingCommitment>> {
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
    pub async fn hint_finalized(&mut self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        self.sender
            .send_lossy(Message::HintFinalized { height, targets })
            .await;
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
        self.sender
            .send_lossy(Message::Subscribe {
                round,
                id,
                response: tx,
            })
            .await;
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
    /// Marshal will sync and deliver blocks starting at `floor + 1`. Data below
    /// the floor is pruned.
    ///
    /// To prune data without affecting the sync starting point (say at some trailing depth
    /// from tip), use [Self::prune] instead.
    ///
    /// The default floor is 0.
    pub async fn set_floor(&mut self, height: Height) {
        self.sender.send_lossy(Message::SetFloor { height }).await;
    }

    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [Self::set_floor], this does not affect the sync starting point.
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
    pub async fn prune(&mut self, height: Height) {
        self.sender.send_lossy(Message::Prune { height }).await;
    }

    /// Notifies the actor of a verified [`Finalization`].
    ///
    /// This is a trusted call that injects a finalization directly into marshal. The
    /// finalization is expected to have already been verified by the caller.
    pub async fn finalization(&mut self, finalization: Finalization<S, CodingCommitment>) {
        self.sender
            .send_lossy(Message::Finalization { finalization })
            .await;
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
        self.sender.send_lossy(message).await;
    }
}
