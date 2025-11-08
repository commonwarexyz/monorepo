//! A stream that yields the ancestors of a block while prefetching parents.

use crate::{types::Height, Block, Heightable};
use commonware_cryptography::Digestible;
use futures::{
    future::{BoxFuture, OptionFuture},
    FutureExt, Stream,
};
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
    fn fetch_block(
        self,
        digest: <Self::Block as Digestible>::Digest,
    ) -> impl Future<Output = Self::Block> + Send;
}

/// Yields the ancestors of a block while prefetching parents, _not_ including the genesis block.
///
/// TODO(<https://github.com/commonwarexyz/monorepo/issues/2982>): Once marshal can also yield the genesis block,
/// this stream should end at block height 0 rather than 1.
#[pin_project]
pub struct AncestorStream<M, B: Block> {
    buffered: Vec<B>,
    marshal: M,
    #[pin]
    pending: OptionFuture<BoxFuture<'static, B>>,
}

impl<M, B: Block> AncestorStream<M, B> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous in height.
    pub(crate) fn new(marshal: M, initial: impl IntoIterator<Item = B>) -> Self {
        let mut buffered = initial.into_iter().collect::<Vec<B>>();
        buffered.sort_by_key(Heightable::height);

        // Check that the initial blocks are contiguous in height.
        buffered.windows(2).for_each(|window| {
            assert_eq!(
                window[0].height().next(),
                window[1].height(),
                "initial blocks must be contiguous in height"
            );
            assert_eq!(
                window[0].digest(),
                window[1].parent(),
                "initial blocks must be contiguous in ancestry"
            );
        });

        Self {
            marshal,
            buffered,
            pending: None.into(),
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
        const END_BOUND: Height = Height::new(1);

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.pop() {
            let height = block.height();
            let should_fetch_parent = height > END_BOUND;
            let end_of_buffered = this.buffered.is_empty();
            if should_fetch_parent && end_of_buffered {
                let parent_digest = block.parent();
                let future = this.marshal.clone().fetch_block(parent_digest).boxed();
                *this.pending.as_mut() = Some(future).into();

                // Explicitly poll the next future to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                if let Poll::Ready(Some(block)) = this.pending.as_mut().poll(cx) {
                    this.buffered.push(block);
                }
            } else if !should_fetch_parent {
                // No more parents to fetch; Finish the stream.
                *this.pending.as_mut() = None.into();
            }

            return Poll::Ready(Some(block));
        }

        match this.pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(block)) => {
                let height = block.height();
                let should_fetch_parent = height > END_BOUND;
                if should_fetch_parent {
                    let parent_digest = block.parent();
                    let future = this.marshal.clone().fetch_block(parent_digest).boxed();
                    *this.pending.as_mut() = Some(future).into();

                    // Explicitly poll the next future to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    if let Poll::Ready(Some(block)) = this.pending.as_mut().poll(cx) {
                        this.buffered.push(block);
                    }
                } else {
                    // No more parents to fetch; Finish the stream.
                    *this.pending.as_mut() = None.into();
                }

                Poll::Ready(Some(block))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::Block;
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Digest, Sha256};
    use commonware_macros::test_async;
    use futures::StreamExt;

    #[derive(Default, Clone)]
    struct MockProvider(Vec<Block<Sha256Digest, ()>>);
    impl AncestryProvider for MockProvider {
        type Block = Block<Sha256Digest, ()>;

        async fn fetch_block(self, digest: Sha256Digest) -> Self::Block {
            self.0
                .into_iter()
                .find(|b| b.digest() == digest)
                .expect("block not found in mock provider")
        }
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in height"]
    fn test_panics_on_non_contiguous_initial_blocks_height() {
        AncestorStream::new(
            MockProvider::default(),
            vec![
                Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1),
                Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(3), 3),
            ],
        );
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in ancestry"]
    fn test_panics_on_non_contiguous_initial_blocks_digest() {
        AncestorStream::new(
            MockProvider::default(),
            vec![
                Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1),
                Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(2), 2),
            ],
        );
    }

    #[test_async]
    async fn test_empty_yields_none() {
        let mut stream: AncestorStream<MockProvider, Block<Sha256Digest, ()>> =
            AncestorStream::new(MockProvider::default(), vec![]);
        assert_eq!(stream.next().await, None);
    }

    #[test_async]
    async fn test_yields_ancestors() {
        let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
        let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
        let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

        let provider = MockProvider(vec![block1.clone(), block2.clone()]);
        let stream = AncestorStream::new(provider, [block3.clone()]);

        let results = stream.collect::<Vec<_>>().await;
        assert_eq!(results, vec![block3, block2, block1]);
    }

    #[test_async]
    async fn test_yields_ancestors_all_buffered() {
        let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
        let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
        let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

        let provider = MockProvider(vec![]);
        let stream =
            AncestorStream::new(provider, [block1.clone(), block2.clone(), block3.clone()]);

        let results = stream.collect::<Vec<_>>().await;
        assert_eq!(results, vec![block3, block2, block1]);
    }
}
