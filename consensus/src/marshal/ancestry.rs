//! A stream that yields the ancestors of a block while prefetching parents.

use crate::{types::Height, Block, Heightable};
use commonware_cryptography::Digestible;
use commonware_runtime::{telemetry::metrics::histogram::Timed, Clock};
use futures::{
    future::{BoxFuture, OptionFuture},
    FutureExt, Stream,
};
use pin_project::pin_project;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// An interface for providing blocks.
pub trait BlockProvider: Clone + Send + 'static {
    /// The block type the provider walks.
    type Block: Block;

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
    ///
    /// This is intentionally narrower than [`Self::subscribe_parent`]. A digest is enough to
    /// identify a block in local storage, but it may not be enough to form the network request
    /// used by a marshal variant. Variants whose consensus commitment contains extra context
    /// should keep that logic in [`Self::subscribe_parent`], where the known child block is
    /// still available.
    fn subscribe(
        self,
        digest: <Self::Block as Digestible>::Digest,
    ) -> impl Future<Output = Option<Self::Block>> + Send;

    /// Subscribe to the parent of a known block.
    ///
    /// This is a separate hook from [`Self::subscribe`] because the child block can carry
    /// variant-specific context needed to retrieve its parent. The default implementation
    /// follows the digest link and waits locally, but providers may override this to derive a
    /// full parent commitment and issue a fetching subscription.
    fn subscribe_parent(
        self,
        block: Self::Block,
    ) -> impl Future<Output = Option<Self::Block>> + Send {
        let digest = block.parent();
        self.subscribe(digest)
    }
}

/// Yields the ancestors of a block while prefetching parents, _not_ including the genesis block.
///
// TODO(<https://github.com/commonwarexyz/monorepo/issues/2982>): Once marshal can also yield the genesis block,
// this stream should end at block height 0 rather than 1.
#[pin_project]
pub struct AncestorStream<M: BlockProvider, C: Clock> {
    buffered: Vec<M::Block>,
    marshal: M,
    fetch_duration: Timed,
    clock: Arc<C>,
    #[pin]
    pending: OptionFuture<BoxFuture<'static, Option<M::Block>>>,
}

impl<M: BlockProvider, C: Clock> AncestorStream<M, C> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous in height.
    pub(crate) fn new(
        marshal: M,
        initial: impl IntoIterator<Item = M::Block>,
        fetch_duration: Timed,
        clock: Arc<C>,
    ) -> Self {
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
            fetch_duration,
            clock,
            pending: None.into(),
        }
    }
}

impl<M, C> Stream for AncestorStream<M, C>
where
    M: BlockProvider,
    M::Block: Clone,
    C: Clock,
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
                let marshal = this.marshal.clone();
                let fetch_duration = this.fetch_duration.clone();
                let clock = this.clock.clone();
                let child = block.clone();
                let future = async move {
                    let timer = fetch_duration.timer(clock.as_ref());
                    let parent = marshal.subscribe_parent(child).await;
                    if parent.is_some() {
                        timer.observe(clock.as_ref());
                    }
                    parent
                }
                .boxed();
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

            return Poll::Ready(Some(block));
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
                    let marshal = this.marshal.clone();
                    let fetch_duration = this.fetch_duration.clone();
                    let clock = this.clock.clone();
                    let child = block.clone();
                    let future = async move {
                        let timer = fetch_duration.timer(clock.as_ref());
                        let parent = marshal.subscribe_parent(child).await;
                        if parent.is_some() {
                            timer.observe(clock.as_ref());
                        }
                        parent
                    }
                    .boxed();
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
    use commonware_runtime::{
        deterministic,
        telemetry::metrics::{
            histogram::{Buckets, Timed},
            MetricsExt as _,
        },
        Runner as _, Supervisor as _,
    };
    use futures::StreamExt;

    #[derive(Default, Clone)]
    struct MockProvider(Vec<Block<Sha256Digest, ()>>);
    impl BlockProvider for MockProvider {
        type Block = Block<Sha256Digest, ()>;

        async fn subscribe(self, digest: Sha256Digest) -> Option<Self::Block> {
            self.0.into_iter().find(|b| b.digest() == digest)
        }
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in height"]
    fn test_panics_on_non_contiguous_initial_blocks_height() {
        deterministic::Runner::default().start(|context| async move {
            let stream_context = context.child("ancestor_stream");
            let timed = timed(&stream_context);
            AncestorStream::new(
                MockProvider::default(),
                vec![
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1),
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(3), 3),
                ],
                timed,
                Arc::new(stream_context),
            );
        });
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in ancestry"]
    fn test_panics_on_non_contiguous_initial_blocks_digest() {
        deterministic::Runner::default().start(|context| async move {
            let stream_context = context.child("ancestor_stream");
            let timed = timed(&stream_context);
            AncestorStream::new(
                MockProvider::default(),
                vec![
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1),
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(2), 2),
                ],
                timed,
                Arc::new(stream_context),
            );
        });
    }

    fn timed(context: &deterministic::Context) -> Timed {
        Timed::new(context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            Buckets::NETWORK,
        ))
    }

    #[test]
    fn test_empty_yields_none() {
        deterministic::Runner::default().start(|context| async move {
            let stream_context = context.child("ancestor_stream");
            let timed = timed(&stream_context);
            let mut stream: AncestorStream<MockProvider, deterministic::Context> =
                AncestorStream::new(MockProvider::default(), vec![], timed, Arc::new(stream_context));
            assert_eq!(stream.next().await, None);
        });
    }

    #[test]
    fn test_yields_ancestors() {
        deterministic::Runner::default().start(|context| async move {
            let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
            let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![block1.clone(), block2.clone()]);
            let stream_context = context.child("ancestor_stream");
            let stream = AncestorStream::new(
                provider,
                [block3.clone()],
                timed(&stream_context),
                Arc::new(stream_context),
            );

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![block3, block2, block1]);
        });
    }

    #[test]
    fn test_yields_ancestors_all_buffered() {
        deterministic::Runner::default().start(|context| async move {
            let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
            let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![]);
            let stream_context = context.child("ancestor_stream");
            let stream = AncestorStream::new(
                provider,
                [block1.clone(), block2.clone(), block3.clone()],
                timed(&stream_context),
                Arc::new(stream_context),
            );

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![block3, block2, block1]);
        });
    }

    #[test]
    fn test_missing_parent_ends_stream() {
        deterministic::Runner::default().start(|context| async move {
            let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
            let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![block1]);
            let stream_context = context.child("ancestor_stream");
            let stream = AncestorStream::new(
                provider,
                [block3.clone()],
                timed(&stream_context),
                Arc::new(stream_context),
            );

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![block3]);
        });
    }
}
