use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Activity, Finalization, Notarization},
    },
    types::Round,
    Block, Reporter,
};
use commonware_cryptography::Digest;
use commonware_storage::archive;
use futures::{
    channel::{mpsc, oneshot},
    future::BoxFuture,
    stream::{FuturesOrdered, Stream},
    FutureExt, SinkExt,
};
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tracing::error;

/// An identifier for a block request.
pub enum Identifier<D: Digest> {
    /// The height of the block to retrieve.
    Height(u64),
    /// The commitment of the block to retrieve.
    Commitment(D),
    /// The highest finalized block. It may be the case that marshal does not have some of the
    /// blocks below this height.
    Latest,
}

// Allows using u64 directly for convenience.
impl<D: Digest> From<u64> for Identifier<D> {
    fn from(src: u64) -> Self {
        Self::Height(src)
    }
}

// Allows using &Digest directly for convenience.
impl<D: Digest> From<&D> for Identifier<D> {
    fn from(src: &D) -> Self {
        Self::Commitment(*src)
    }
}

// Allows using archive identifiers directly for convenience.
impl<D: Digest> From<archive::Identifier<'_, D>> for Identifier<D> {
    fn from(src: archive::Identifier<'_, D>) -> Self {
        match src {
            archive::Identifier::Index(index) => Self::Height(index),
            archive::Identifier::Key(key) => Self::Commitment(*key),
        }
    }
}

/// Messages sent to the marshal [Actor](super::super::actor::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub(crate) enum Message<S: Scheme, B: Block> {
    // -------------------- Application Messages --------------------
    /// A request to retrieve the (height, commitment) of a block by its identifier.
    /// The block must be finalized; returns `None` if the block is not finalized.
    GetInfo {
        /// The identifier of the block to get the information of.
        identifier: Identifier<B::Commitment>,
        /// A channel to send the retrieved (height, commitment).
        response: oneshot::Sender<Option<(u64, B::Commitment)>>,
    },
    /// A request to retrieve a block by its identifier.
    ///
    /// Requesting by [Identifier::Height] or [Identifier::Latest] will only return finalized
    /// blocks, whereas requesting by commitment may return non-finalized or even unverified blocks.
    GetBlock {
        /// The identifier of the block to retrieve.
        identifier: Identifier<B::Commitment>,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<B>>,
    },
    /// A request to retrieve a finalization by height.
    GetFinalization {
        /// The height of the finalization to retrieve.
        height: u64,
        /// A channel to send the retrieved finalization.
        response: oneshot::Sender<Option<Finalization<S, B::Commitment>>>,
    },
    /// A request to retrieve a block by its commitment.
    Subscribe {
        /// The view in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
        /// The commitment of the block to retrieve.
        commitment: B::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<B>,
    },
    /// A request to broadcast a block to all peers.
    Broadcast {
        /// The block to broadcast.
        block: B,
    },
    /// A notification that a block has been verified by the application.
    Verified {
        /// The round in which the block was verified.
        round: Round,
        /// The verified block.
        block: B,
    },

    // -------------------- Consensus Engine Messages --------------------
    /// A notarization from the consensus engine.
    Notarization {
        /// The notarization.
        notarization: Notarization<S, B::Commitment>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The finalization.
        finalization: Finalization<S, B::Commitment>,
    },
}

/// A mailbox for sending messages to the marshal [Actor](super::super::actor::Actor).
#[derive(Clone)]
pub struct Mailbox<S: Scheme, B: Block> {
    sender: mpsc::Sender<Message<S, B>>,
}

impl<S: Scheme, B: Block> Mailbox<S, B> {
    /// Creates a new mailbox.
    pub(crate) fn new(sender: mpsc::Sender<Message<S, B>>) -> Self {
        Self { sender }
    }

    /// A request to retrieve the information about the highest finalized block.
    pub async fn get_info(
        &mut self,
        identifier: impl Into<Identifier<B::Commitment>>,
    ) -> Option<(u64, B::Commitment)> {
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
        match rx.await {
            Ok(result) => result,
            Err(_) => {
                error!("failed to get info: receiver dropped");
                None
            }
        }
    }

    /// A best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub async fn get_block(
        &mut self,
        identifier: impl Into<Identifier<B::Commitment>>,
    ) -> Option<B> {
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
        match rx.await {
            Ok(result) => result,
            Err(_) => {
                error!("failed to get block: receiver dropped");
                None
            }
        }
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub async fn get_finalization(
        &mut self,
        height: u64,
    ) -> Option<Finalization<S, B::Commitment>> {
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
        match rx.await {
            Ok(result) => result,
            Err(_) => {
                error!("failed to get finalization: receiver dropped");
                None
            }
        }
    }

    /// A request to retrieve a block by its commitment.
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
        commitment: B::Commitment,
    ) -> oneshot::Receiver<B> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::Subscribe {
                round,
                commitment,
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
        (start_round, start_commitment): (Option<Round>, B::Commitment),
    ) -> Option<AncestorStream<S, B>> {
        self.subscribe(start_round, start_commitment)
            .await
            .await
            .ok()
            .map(|block| AncestorStream::new(self.clone(), block))
    }

    /// Broadcast indicates that a block should be sent to all peers.
    pub async fn broadcast(&mut self, block: B) {
        if self
            .sender
            .send(Message::Broadcast { block })
            .await
            .is_err()
        {
            error!("failed to send broadcast message to actor: receiver dropped");
        }
    }

    /// Notifies the actor that a block has been verified.
    pub async fn verified(&mut self, round: Round, block: B) {
        if self
            .sender
            .send(Message::Verified { round, block })
            .await
            .is_err()
        {
            error!("failed to send verified message to actor: receiver dropped");
        }
    }
}

impl<S: Scheme, B: Block> Reporter for Mailbox<S, B> {
    type Activity = Activity<S, B::Commitment>;

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

/// Returns a boxed subscription future for a block.
#[inline]
fn subscribe_block_future<S: Scheme, B: Block>(
    mut marshal: Mailbox<S, B>,
    commitment: B::Commitment,
) -> BoxFuture<'static, Option<B>> {
    async move {
        let receiver = marshal.subscribe(None, commitment).await;
        receiver.await.ok()
    }
    .boxed()
}

/// Yields the ancestors of a block while prefetching parents, _not_ including the genesis block.
///
/// TODO(clabby): Once marshal can also yield the genesis block, this stream should end
/// at block height 0 rather than 1.
#[pin_project]
pub struct AncestorStream<S: Scheme, B: Block> {
    marshal: Mailbox<S, B>,
    buffered: Option<B>,
    #[pin]
    pending: FuturesOrdered<BoxFuture<'static, Option<B>>>,
}

impl<S: Scheme, B: Block> AncestorStream<S, B> {
    pub(crate) fn new(marshal: Mailbox<S, B>, initial: B) -> Self {
        Self {
            marshal,
            buffered: Some(initial),
            pending: FuturesOrdered::new(),
        }
    }
}

impl<S: Scheme, B: Block> Stream for AncestorStream<S, B> {
    type Item = B;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Because marshal cannot currently yield the genesis block, we stop at height 1.
        const END_BOUND: u64 = 1;

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.take() {
            let height = block.height();
            let should_fetch_parent = height > END_BOUND;
            if should_fetch_parent {
                let parent_commitment = block.parent();
                let future = subscribe_block_future(this.marshal.clone(), parent_commitment);
                this.pending.push_back(future);

                // Explicitly poll the pending futures to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                if let Poll::Ready(Some(Some(block))) = this.pending.as_mut().poll_next(cx) {
                    this.buffered.replace(block);
                }
            }

            return Poll::Ready(Some(block));
        }

        match this.pending.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) | Poll::Ready(Some(None)) => Poll::Ready(None),
            Poll::Ready(Some(Some(block))) => {
                let height = block.height();
                let should_fetch_parent = height > END_BOUND;
                if should_fetch_parent {
                    let parent_commitment = block.parent();
                    let future = subscribe_block_future(this.marshal.clone(), parent_commitment);
                    this.pending.push_back(future);

                    // Explicitly poll the pending futures to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    if let Poll::Ready(Some(Some(block))) = this.pending.as_mut().poll_next(cx) {
                        this.buffered.replace(block);
                    }
                }

                Poll::Ready(Some(block))
            }
        }
    }
}
