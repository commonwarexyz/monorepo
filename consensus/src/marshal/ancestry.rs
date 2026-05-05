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

/// An interface for providing blocks.
pub trait BlockProvider: Clone + Send + 'static {
    /// The block type the provider yields.
    type Block: Block;

    /// The block type retained while walking ancestry.
    type AncestryBlock: Block<Digest = <Self::Block as Digestible>::Digest> + Clone;

    /// Subscribe to a block by its digest without requesting it from the network.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the subscription will be registered and the caller
    /// will be notified when the block is available. If the block is not finalized, it's possible
    /// that it may never become available.
    ///
    /// Returns `None` when the subscription is canceled or the provider can no longer deliver
    /// the block.
    fn subscribe(
        self,
        digest: <Self::Block as Digestible>::Digest,
    ) -> impl Future<Output = Option<Self::AncestryBlock>> + Send;

    /// Subscribe to the parent of a known block.
    fn subscribe_parent(
        self,
        block: Self::AncestryBlock,
    ) -> impl Future<Output = Option<Self::AncestryBlock>> + Send {
        let digest = block.parent();
        self.subscribe(digest)
    }

    /// Converts an ancestry block into the block yielded by ancestry streams.
    fn into_block(block: Self::AncestryBlock) -> Self::Block;
}

/// Yields the ancestors of a block while prefetching parents, _not_ including the genesis block.
///
// TODO(<https://github.com/commonwarexyz/monorepo/issues/2982>): Once marshal can also yield the genesis block,
// this stream should end at block height 0 rather than 1.
#[pin_project]
pub struct AncestorStream<M: BlockProvider> {
    buffered: Vec<M::AncestryBlock>,
    marshal: M,
    #[pin]
    pending: OptionFuture<BoxFuture<'static, Option<M::AncestryBlock>>>,
}

impl<M: BlockProvider> AncestorStream<M> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous in height.
    pub(crate) fn new(marshal: M, initial: impl IntoIterator<Item = M::AncestryBlock>) -> Self {
        let mut buffered = initial.into_iter().collect::<Vec<M::AncestryBlock>>();
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

impl<M> Stream for AncestorStream<M>
where
    M: BlockProvider,
{
    type Item = M::Block;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Because marshal cannot currently yield the genesis block, we stop at height 1.
        const END_BOUND: Height = Height::new(1);

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.pop() {
            let height = block.height();
            let should_subscribe_parent = height > END_BOUND;
            let end_of_buffered = this.buffered.is_empty();
            if should_subscribe_parent && end_of_buffered {
                let future = this.marshal.clone().subscribe_parent(block.clone()).boxed();
                *this.pending.as_mut() = Some(future).into();

                // Explicitly poll the next future to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                match this.pending.as_mut().poll(cx) {
                    Poll::Ready(Some(Some(block))) => {
                        this.buffered.push(block);
                    }
                    Poll::Ready(Some(None)) => {
                        *this.pending.as_mut() = None.into();
                    }
                    Poll::Ready(None) | Poll::Pending => {}
                }
            } else if !should_subscribe_parent {
                // No more parents to fetch; Finish the stream.
                *this.pending.as_mut() = None.into();
            }

            return Poll::Ready(Some(M::into_block(block)));
        }

        match this.pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) | Poll::Ready(Some(None)) => {
                *this.pending.as_mut() = None.into();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Some(block))) => {
                let height = block.height();
                let should_subscribe_parent = height > END_BOUND;
                if should_subscribe_parent {
                    let future = this.marshal.clone().subscribe_parent(block.clone()).boxed();
                    *this.pending.as_mut() = Some(future).into();

                    // Explicitly poll the next future to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    match this.pending.as_mut().poll(cx) {
                        Poll::Ready(Some(Some(block))) => {
                            this.buffered.push(block);
                        }
                        Poll::Ready(Some(None)) => {
                            *this.pending.as_mut() = None.into();
                        }
                        Poll::Ready(None) | Poll::Pending => {}
                    }
                } else {
                    // No more parents to fetch; Finish the stream.
                    *this.pending.as_mut() = None.into();
                }

                Poll::Ready(Some(M::into_block(block)))
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
    impl BlockProvider for MockProvider {
        type Block = Block<Sha256Digest, ()>;
        type AncestryBlock = Block<Sha256Digest, ()>;

        async fn subscribe(self, digest: Sha256Digest) -> Option<Self::AncestryBlock> {
            self.0.into_iter().find(|b| b.digest() == digest)
        }

        fn into_block(block: Self::AncestryBlock) -> Self::Block {
            block
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
        let mut stream: AncestorStream<MockProvider> =
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

    #[test_async]
    async fn test_missing_parent_ends_stream() {
        let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
        let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
        let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

        let provider = MockProvider(vec![block1]);
        let stream = AncestorStream::new(provider, [block3.clone()]);

        let results = stream.collect::<Vec<_>>().await;
        assert_eq!(results, vec![block3]);
    }
}
