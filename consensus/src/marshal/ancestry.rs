//! A stream that yields the ancestors of a block while prefetching parents.

use crate::Block;
use commonware_cryptography::Digestible;
use futures::{future::BoxFuture, stream::FuturesOrdered, FutureExt, Stream};
use pin_project::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// An interface for providing ancestors.
pub trait AncestryProvider: Clone + Send + 'static {
    /// The block type the provider fetches.
    type Block: Block;

    /// A request to retrieve a block by its digest.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    fn fetch_ancestor(
        self,
        digest: <Self::Block as Digestible>::Digest,
    ) -> impl Future<Output = Self::Block> + Send;
}

/// Yields the ancestors of a block while prefetching parents, _not_ including the genesis block.
///
/// TODO(clabby): Once marshal can also yield the genesis block, this stream should end
/// at block height 0 rather than 1.
#[pin_project]
pub struct AncestorStream<M, B: Block> {
    buffered: Vec<B>,
    marshal: M,
    #[pin]
    pending: FuturesOrdered<BoxFuture<'static, B>>,
}

impl<M, B: Block> AncestorStream<M, B> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous in height.
    pub(crate) fn new(marshal: M, initial: impl IntoIterator<Item = B>) -> Self {
        let mut buffered = initial.into_iter().collect::<Vec<B>>();
        buffered.sort_by_key(Block::height);

        // Check that the initial blocks are contiguous in height.
        buffered.windows(2).for_each(|window| {
            assert_eq!(
                window[0].height() + 1,
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

impl<M, B> Stream for AncestorStream<M, B>
where
    M: AncestryProvider<Block = B>,
    B: Block,
{
    type Item = B;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Because marshal cannot currently yield the genesis block, we stop at height 1.
        const END_BOUND: u64 = 1;

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.pop() {
            let height = block.height();
            let should_fetch_parent = height > END_BOUND && this.buffered.is_empty();
            if should_fetch_parent {
                let parent_digest = block.parent();
                let future = this.marshal.clone().fetch_ancestor(parent_digest).boxed();
                this.pending.push_back(future);

                // Explicitly poll the pending futures to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                if let Poll::Ready(Some(block)) = this.pending.as_mut().poll_next(cx) {
                    this.buffered.push(block);
                }
            }

            return Poll::Ready(Some(block));
        }

        match this.pending.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(block)) => {
                let height = block.height();
                let should_fetch_parent = height > END_BOUND;
                if should_fetch_parent {
                    let parent_digest = block.parent();
                    let future = this.marshal.clone().fetch_ancestor(parent_digest).boxed();
                    this.pending.push_back(future);

                    // Explicitly poll the pending futures to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    if let Poll::Ready(Some(block)) = this.pending.as_mut().poll_next(cx) {
                        this.buffered.push(block);
                    }
                }

                Poll::Ready(Some(block))
            }
        }
    }
}
