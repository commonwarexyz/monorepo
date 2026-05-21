//! A stream that yields the ancestors of a block while prefetching parents.

use crate::{types::Height, Block, Heightable};
use commonware_cryptography::{Digest, Digestible};
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

/// A stream of blocks used by application propose and verify calls.
pub trait Ancestry<B: Block>: Stream<Item = B> + Send + Unpin + 'static {}

impl<T, B> Ancestry<B> for T
where
    T: Stream<Item = B> + Send + Unpin + 'static,
    B: Block,
{
}

/// An interface for providing parent blocks.
pub trait BlockProvider: Send + 'static {
    /// The block type the provider walks.
    type Block: Block;

    /// Subscribe to the parent of a known block.
    ///
    /// If the parent is found available locally, the parent will be returned immediately.
    ///
    /// If the parent is not available locally, the subscription will be registered and the caller
    /// will be notified when the parent is available. If the parent is not finalized, it's possible
    /// that it may never become available.
    ///
    /// Returns `None` when the subscription is canceled or the provider can no longer deliver
    /// the parent.
    ///
    /// The child block can carry variant-specific context needed to retrieve its parent.
    ///
    /// The returned future must be `'static` because [AncestorStream] stores it
    /// between polls.
    fn subscribe_parent(
        &self,
        block: &Self::Block,
    ) -> impl Future<Output = Option<Self::Block>> + Send + 'static;
}

// Expected parent height and digest for a pending fetch.
struct ExpectedParent<D>(Height, D);

// Pending parent fetch paired with the relationship it must satisfy.
type PendingFetch<B> = BoxFuture<'static, Option<(ExpectedParent<<B as Digestible>::Digest>, B)>>;

impl<D: Digest> ExpectedParent<D> {
    fn from_child<B: Block<Digest = D>>(child: &B) -> Self {
        Self(
            child.height().previous().expect("child must have parent"),
            child.parent(),
        )
    }

    fn assert_matches<B: Block<Digest = D>>(self, parent: &B) {
        let Self(parent_height, parent_digest) = self;
        assert_eq!(
            parent.height(),
            parent_height,
            "fetched parent must be contiguous in height"
        );
        assert_eq!(
            parent.digest(),
            parent_digest,
            "fetched parent must be contiguous in ancestry"
        );
    }
}

/// Yields the ancestors of a block while prefetching parents, including the
/// height-zero genesis block if it is available.
#[pin_project]
pub struct AncestorStream<M: BlockProvider> {
    buffered: Vec<M::Block>,
    marshal: M,
    #[pin]
    pending: OptionFuture<PendingFetch<M::Block>>,
}

impl<M: BlockProvider> AncestorStream<M> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous.
    pub(crate) fn new(marshal: M, initial: impl IntoIterator<Item = M::Block>) -> Self {
        let mut buffered = initial.into_iter().collect::<Vec<M::Block>>();
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
        const END_BOUND: Height = Height::zero();

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.pop() {
            let height = block.height();
            let should_walk_parent = height > END_BOUND;
            let end_of_buffered = this.buffered.is_empty();
            if should_walk_parent && end_of_buffered {
                let expected = ExpectedParent::from_child(&block);
                let future = this
                    .marshal
                    .subscribe_parent(&block)
                    .map(move |parent| parent.map(|parent| (expected, parent)))
                    .boxed();
                *this.pending.as_mut() = Some(future).into();

                // Explicitly poll the next future to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                match this.pending.as_mut().poll(cx) {
                    Poll::Ready(Some(Some((expected, parent)))) => {
                        expected.assert_matches(&parent);
                        this.buffered.push(parent);
                    }
                    Poll::Ready(Some(None)) => {
                        *this.pending.as_mut() = None.into();
                    }
                    Poll::Ready(None) | Poll::Pending => {}
                }
            } else if !should_walk_parent {
                // No more parents to fetch; Finish the stream.
                *this.pending.as_mut() = None.into();
            }

            return Poll::Ready(Some(block));
        }

        match this.pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) | Poll::Ready(Some(None)) => {
                *this.pending.as_mut() = None.into();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Some((expected, block)))) => {
                expected.assert_matches(&block);
                let height = block.height();
                let should_walk_parent = height > END_BOUND;
                if should_walk_parent {
                    let expected = ExpectedParent::from_child(&block);
                    let future = this
                        .marshal
                        .subscribe_parent(&block)
                        .map(move |parent| parent.map(|parent| (expected, parent)))
                        .boxed();
                    *this.pending.as_mut() = Some(future).into();

                    // Explicitly poll the next future to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    match this.pending.as_mut().poll(cx) {
                        Poll::Ready(Some(Some((expected, parent)))) => {
                            expected.assert_matches(&parent);
                            this.buffered.push(parent);
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
    impl BlockProvider for MockProvider {
        type Block = Block<Sha256Digest, ()>;

        fn subscribe_parent(
            &self,
            block: &Self::Block,
        ) -> impl Future<Output = Option<Self::Block>> + Send + 'static {
            let parent = block.parent;
            std::future::ready(self.0.iter().find(|b| b.digest() == parent).cloned())
        }
    }

    #[derive(Clone)]
    struct WrongParentProvider(Block<Sha256Digest, ()>);
    impl BlockProvider for WrongParentProvider {
        type Block = Block<Sha256Digest, ()>;

        fn subscribe_parent(
            &self,
            _block: &Self::Block,
        ) -> impl Future<Output = Option<Self::Block>> + Send + 'static {
            std::future::ready(Some(self.0.clone()))
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

    #[test]
    #[should_panic = "fetched parent must be contiguous in height"]
    fn test_panics_on_non_contiguous_fetched_parent_height() {
        let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
        let child = Block::new::<Sha256>((), parent.digest(), Height::new(3), 3);
        let stream = AncestorStream::new(MockProvider(vec![parent]), [child]);
        futures::pin_mut!(stream);

        let waker = futures::task::noop_waker_ref();
        let mut cx = std::task::Context::from_waker(waker);
        let _ = futures::Stream::poll_next(stream.as_mut(), &mut cx);
    }

    #[test]
    #[should_panic = "fetched parent must be contiguous in ancestry"]
    fn test_panics_on_non_contiguous_fetched_parent_digest() {
        let expected_parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
        let fetched_parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 1);
        let child = Block::new::<Sha256>((), expected_parent.digest(), Height::new(1), 2);
        let stream = AncestorStream::new(WrongParentProvider(fetched_parent), [child]);
        futures::pin_mut!(stream);

        let waker = futures::task::noop_waker_ref();
        let mut cx = std::task::Context::from_waker(waker);
        let _ = futures::Stream::poll_next(stream.as_mut(), &mut cx);
    }

    #[test_async]
    async fn test_yields_genesis_and_stops() {
        let genesis = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
        let child = Block::new::<Sha256>((), genesis.digest(), Height::new(1), 1);

        let provider = MockProvider(vec![genesis.clone()]);
        let stream = AncestorStream::new(provider, [child.clone()]);

        let results = stream.collect::<Vec<_>>().await;
        assert_eq!(results, vec![child, genesis]);
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
