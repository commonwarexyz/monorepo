use super::handler;
use crate::{
    simplex::types::{Activity, Finalization, Notarization},
    types::{Height, Round},
    Block, Heightable, Reporter,
};
use bytes::Bytes;
use commonware_actor::ingress;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_storage::archive;
use commonware_utils::{channel::oneshot, vec::NonEmptyVec, BoxedError};
use futures::{
    future::BoxFuture,
    stream::{FuturesOrdered, Stream},
    FutureExt,
};
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// An identifier for a block request.
pub enum Identifier<D: Digest> {
    /// The height of the block to retrieve.
    Height(Height),
    /// The commitment of the block to retrieve.
    Commitment(D),
    /// The highest finalized block. It may be the case that marshal does not have some of the
    /// blocks below this height.
    Latest,
}

// Allows using Height directly for convenience.
impl<D: Digest> From<Height> for Identifier<D> {
    fn from(src: Height) -> Self {
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
            archive::Identifier::Index(index) => Self::Height(Height::new(index)),
            archive::Identifier::Key(key) => Self::Commitment(*key),
        }
    }
}

ingress! {
    Mailbox<S: Scheme, B: Block>,

    // -------------------- Application Messages --------------------

    /// A request to retrieve the (height, commitment) of a block by its identifier.
    /// The block must be finalized; returns `None` if the block is not finalized.
    ask GetInfo {
        /// The identifier of the block to get the information of.
        identifier: Identifier<B::Commitment>,
    } -> Option<(Height, B::Commitment)>;

    /// A request to retrieve a block by its identifier.
    ///
    /// Requesting by [Identifier::Height] or [Identifier::Latest] will only return finalized
    /// blocks, whereas requesting by commitment may return non-finalized or even unverified blocks.
    ask GetBlock {
        /// The identifier of the block to retrieve.
        identifier: Identifier<B::Commitment>,
    } -> Option<B>;

    /// A request to retrieve a finalization by height.
    pub ask GetFinalization {
        /// The height of the finalization to retrieve.
        height: Height,
    } -> Option<Finalization<S, B::Commitment>>;

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
    pub tell HintFinalized {
        /// The height of the finalization to fetch.
        height: Height,
        /// Target peers to fetch from. Added to any existing targets for this height.
        targets: NonEmptyVec<S::PublicKey>,
    };

    /// A request to retrieve a block by its commitment.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub subscribe Subscribe {
        /// The view in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
        /// The commitment of the block to retrieve.
        commitment: B::Commitment,
    } -> B;

    /// A request to broadcast a proposed block to all peers.
    pub tell Proposed {
        /// The round in which the block was proposed.
        round: Round,
        /// The block to broadcast.
        block: B,
    };

    /// A notification that a block has been verified by the application.
    pub tell Verified {
        /// The round in which the block was verified.
        round: Round,
        /// The verified block.
        block: B,
    };

    /// Sets the sync starting point (advances if higher than current).
    ///
    /// Marshal will sync and deliver blocks starting at `floor + 1`. Data below
    /// the floor is pruned.
    ///
    /// To prune data without affecting the sync starting point (say at some trailing depth
    /// from tip), use [Mailbox::prune] instead.
    ///
    /// The default floor is 0.
    pub tell SetFloor {
        /// The candidate floor height.
        height: Height,
    };

    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [Mailbox::set_floor], this does not affect the sync starting point.
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
    pub tell Prune {
        /// The minimum height to keep (blocks below this are pruned).
        height: Height,
    };

    // -------------------- Consensus Engine Messages --------------------

    /// A notarization from the consensus engine.
    tell NotifyNotarization {
        /// The notarization.
        notarization: Notarization<S, B::Commitment>,
    };

    /// A finalization from the consensus engine.
    tell NotifyFinalization {
        /// The finalization.
        finalization: Finalization<S, B::Commitment>,
    };

    // -------------------- Resolver Messages --------------------

    /// A request from a peer to produce data for a backfill key.
    tell ResolverProduce {
        /// The backfill request key.
        key: handler::Request<B>,
        /// Channel to send the produced value.
        response: oneshot::Sender<Bytes>,
    };

    /// A delivery from a peer with data for a backfill key.
    tell ResolverDeliver {
        /// The backfill request key.
        key: handler::Request<B>,
        /// The delivered value.
        value: Bytes,
        /// Channel to confirm acceptance (true) or rejection (false).
        response: oneshot::Sender<bool>,
    };

    // -------------------- Internal Events --------------------

    /// A block subscription waiter completed successfully.
    tell WaiterCompleted {
        /// The commitment of the resolved block.
        commitment: B::Commitment,
        /// The resolved block.
        block: B,
    };

    /// The pending application acknowledgement resolved.
    tell AckCompleted {
        /// The height of the block that was acknowledged.
        height: Height,
        /// The commitment of the block that was acknowledged.
        commitment: B::Commitment,
        /// The result of the acknowledgement (Ok on success, Err with the failure reason).
        result: Result<(), BoxedError>,
    };
}

// Custom methods that cannot be expressed by the macro's generated convenience methods.
impl<S: Scheme, B: Block> Mailbox<S, B> {
    /// A request to retrieve the information about a block by its identifier.
    ///
    /// Returns `None` if the block is not finalized or the mailbox is closed.
    pub async fn get_info(
        &mut self,
        identifier: impl Into<Identifier<B::Commitment>>,
    ) -> Option<(Height, B::Commitment)> {
        let identifier = identifier.into();
        self.0.ask(GetInfo { identifier }).await.ok().flatten()
    }

    /// A best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    ///
    /// Returns `None` if the block is not found or the mailbox is closed.
    pub async fn get_block(
        &mut self,
        identifier: impl Into<Identifier<B::Commitment>>,
    ) -> Option<B> {
        let identifier = identifier.into();
        self.0.ask(GetBlock { identifier }).await.ok().flatten()
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
            .map(|block| AncestorStream::new(self.clone(), [block]))
    }
}

impl<S: Scheme, B: Block> Reporter for Mailbox<S, B> {
    type Activity = Activity<S, B::Commitment>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Activity::Notarization(notarization) => {
                self.0.tell_lossy(NotifyNotarization { notarization }).await;
            }
            Activity::Finalization(finalization) => {
                self.0.tell_lossy(NotifyFinalization { finalization }).await;
            }
            _ => {
                // Ignore other activity types
            }
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
    buffered: Vec<B>,
    #[pin]
    pending: FuturesOrdered<BoxFuture<'static, Option<B>>>,
}

impl<S: Scheme, B: Block> AncestorStream<S, B> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous in height.
    pub(crate) fn new(marshal: Mailbox<S, B>, initial: impl IntoIterator<Item = B>) -> Self {
        let mut buffered = initial.into_iter().collect::<Vec<B>>();
        buffered.sort_by_key(Heightable::height);

        // Check that the initial blocks are contiguous in height.
        buffered.windows(2).for_each(|window| {
            assert_eq!(
                window[0].height().next(),
                window[1].height(),
                "initial blocks must be contiguous in height"
            );
        });

        Self {
            marshal,
            buffered,
            pending: FuturesOrdered::new(),
        }
    }
}

impl<S: Scheme, B: Block> Stream for AncestorStream<S, B> {
    type Item = B;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Because marshal cannot currently yield the genesis block, we stop at height 1.
        const END_BOUND: Height = Height::new(1);

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.pop() {
            let height = block.height();
            let should_fetch_parent = height > END_BOUND && this.buffered.is_empty();
            if should_fetch_parent {
                let parent_commitment = block.parent();
                let future = subscribe_block_future(this.marshal.clone(), parent_commitment);
                this.pending.push_back(future);

                // Explicitly poll the pending futures to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                if let Poll::Ready(Some(Some(block))) = this.pending.as_mut().poll_next(cx) {
                    this.buffered.push(block);
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
                        this.buffered.push(block);
                    }
                }

                Poll::Ready(Some(block))
            }
        }
    }
}
