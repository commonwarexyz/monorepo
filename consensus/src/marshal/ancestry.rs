//! Streams over a block's ancestry.
//!
//! [AncestorStream] walks backward from a block toward genesis, prefetching
//! parents as it goes. [DescendantStream] walks the same ancestry forward:
//! starting from a chosen ancestor, it yields blocks in ascending height
//! order until it reaches the tip whose ancestry defines the chain.

use crate::{Block, Heightable, marshal::BlockID, types::Height};
use commonware_cryptography::{Digest, Digestible};
use commonware_macros::stability;
use commonware_runtime::{Clock, telemetry::metrics::histogram::Timed};
use futures::{
    FutureExt, Stream,
    future::{BoxFuture, OptionFuture},
};
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// A stream of blocks used by application propose and verify calls.
pub trait Ancestry<B: Block>: Stream<Item = Arc<B>> + Clone + Send + Unpin + 'static {
    /// Peeks at the latest block in the stream without consuming it. Returns [None]
    /// if the stream does not yet have a block available or has been exhausted.
    fn peek(&self) -> Option<&B>;

    /// Returns a forward stream over this ancestry's chain, yielding blocks
    /// in ascending height order from `start` up to this ancestry's tip.
    ///
    /// `start` identifies where iteration begins within the chain: a height
    /// or a digest on the chain.
    ///
    /// Only locally known blocks are served; no network fetches are issued.
    /// Returns `None` when `start` does not lie in the locally known chain.
    fn descendants(
        &self,
        start: BlockID<B::Digest>,
    ) -> impl Future<Output = Option<impl Ancestry<B>>> + Send;
}

fn sort_and_validate_chain<B: Block>(blocks: impl IntoIterator<Item = Arc<B>>) -> Vec<Arc<B>> {
    let mut chain = blocks.into_iter().collect::<Vec<_>>();
    chain.sort_by_key(|block| block.height());

    for window in chain.windows(2) {
        let parent = &window[0];
        let child = &window[1];
        assert_eq!(
            parent.height().next(),
            child.height(),
            "initial blocks must be contiguous in height"
        );
        assert_eq!(
            parent.digest(),
            child.parent(),
            "initial blocks must be contiguous in ancestry"
        );
    }

    chain
}

fn chain_suffix<B: Block>(chain: &[Arc<B>], start: BlockID<B::Digest>) -> Option<Vec<Arc<B>>> {
    let position = match start {
        BlockID::Height(height) => chain.iter().position(|block| block.height() == height),
        BlockID::Digest(digest) => chain.iter().position(|block| block.digest() == digest),
    }?;
    Some(chain[position..].to_vec())
}

/// Creates an ancestry stream from a fixed sequence of blocks.
///
/// Blocks are yielded in iterator order and no parent fetching is performed. This is useful when
/// the caller wants to bound the ancestry available to the application.
///
/// # Panics
///
/// Panics if the blocks do not form a contiguous chain.
pub fn from_iter<B: Block>(blocks: impl IntoIterator<Item = Arc<B>>) -> impl Ancestry<B> {
    let blocks: VecDeque<_> = blocks.into_iter().collect();
    let chain = sort_and_validate_chain(blocks.iter().cloned());
    BoundedAncestry { blocks, chain }
}

/// Prepends a fixed sequence of blocks to an existing ancestry stream.
///
/// Blocks are yielded in iterator order before the tail is polled.
pub fn with_prefix<B, S>(blocks: impl IntoIterator<Item = Arc<B>>, tail: S) -> impl Ancestry<B>
where
    B: Block,
    S: Ancestry<B>,
{
    PrefixedAncestry {
        blocks: blocks.into_iter().collect(),
        tail,
    }
}

/// Type-erased ancestry stream that preserves cloneability.
pub struct BoxedAncestry<B: Block>(Box<dyn ErasedAncestry<B>>);

impl<B: Block> BoxedAncestry<B> {
    /// Erases the concrete ancestry stream type.
    pub fn new(ancestry: impl Ancestry<B>) -> Self {
        Self(Box::new(ancestry))
    }
}

impl<B: Block> Clone for BoxedAncestry<B> {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

impl<B: Block> Unpin for BoxedAncestry<B> {}

impl<B: Block> Ancestry<B> for BoxedAncestry<B> {
    fn peek(&self) -> Option<&B> {
        self.0.peek_erased()
    }
}

impl<B: Block> Stream for BoxedAncestry<B> {
    type Item = Arc<B>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut *self.0).poll_next(cx)
    }
}

trait ErasedAncestry<B: Block>: Stream<Item = Arc<B>> + Send + Unpin + 'static {
    fn peek_erased(&self) -> Option<&B>;

    fn clone_box(&self) -> Box<dyn ErasedAncestry<B>>;
}

impl<B, A> ErasedAncestry<B> for A
where
    B: Block,
    A: Ancestry<B>,
{
    fn peek_erased(&self) -> Option<&B> {
        Ancestry::peek(self)
    }

    fn clone_box(&self) -> Box<dyn ErasedAncestry<B>> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
struct BoundedAncestry<B: Block> {
    /// Blocks remaining to yield, in caller-provided order.
    blocks: VecDeque<Arc<B>>,
    /// The chain fixed at construction, ascending in height, serving forward
    /// walks regardless of how much of the stream has been consumed.
    chain: Vec<Arc<B>>,
}

impl<B: Block> Unpin for BoundedAncestry<B> {}

impl<B: Block> Ancestry<B> for BoundedAncestry<B> {
    fn peek(&self) -> Option<&B> {
        self.blocks.front().map(Arc::as_ref)
    }

    fn descendants(
        &self,
        start: BlockID<B::Digest>,
    ) -> impl Future<Output = Option<impl Ancestry<B>>> + Send {
        // A bounded ancestry is fully in memory: serve the chain fixed at
        // construction from the start onward, in ascending height order.
        std::future::ready(chain_suffix(&self.chain, start).map(|chain| Self {
            blocks: chain.clone().into(),
            chain,
        }))
    }
}

impl<B: Block> Stream for BoundedAncestry<B> {
    type Item = Arc<B>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.blocks.pop_front())
    }
}

#[derive(Clone)]
struct PrefixedAncestry<B: Block, S> {
    blocks: VecDeque<Arc<B>>,
    tail: S,
}

impl<B: Block, S> Unpin for PrefixedAncestry<B, S> {}

impl<B, S> Ancestry<B> for PrefixedAncestry<B, S>
where
    B: Block,
    S: Ancestry<B>,
{
    fn peek(&self) -> Option<&B> {
        self.blocks
            .front()
            .map(Arc::as_ref)
            .or_else(|| self.tail.peek())
    }
}

impl<B, S> Stream for PrefixedAncestry<B, S>
where
    B: Block,
    S: Ancestry<B>,
{
    type Item = Arc<B>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(block) = self.blocks.pop_front() {
            return Poll::Ready(Some(block));
        }
        Pin::new(&mut self.tail).poll_next(cx)
    }
}

/// An interface for providing blocks from a locally known ancestry.
pub trait BlockProvider: Clone + Send + 'static {
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
    fn subscribe_parent(
        &self,
        block: &Self::Block,
    ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static;

    /// Retrieve the block at `start` within the locally known ancestry of
    /// `tip`, together with the resolved tip digest.
    ///
    /// The chain is defined by the ancestry of `tip`, which may be an
    /// unfinalized candidate (a fork tracked by marshal) or a finalized
    /// block. Finalized blocks are served from storage and candidates from
    /// marshal's in-memory fork tree. Unlike [Self::subscribe_parent], this
    /// lookup never waits and never fetches from the network.
    ///
    /// Returns `None` when `tip` is unknown locally, `start` does not lie in
    /// the tip's locally known ancestry, or the block at `start` is not
    /// locally available.
    #[allow(clippy::type_complexity)]
    fn get_descendant(
        &self,
        start: BlockID<<Self::Block as Digestible>::Digest>,
        tip: BlockID<<Self::Block as Digestible>::Digest>,
    ) -> impl Future<Output = Option<(Arc<Self::Block>, <Self::Block as Digestible>::Digest)>>
    + Send
    + 'static;
}

// Expected parent height and digest for a pending fetch.
struct ExpectedParent<D>(Height, D);

// Pending parent fetch paired with the relationship it must satisfy.
type PendingFetch<B> =
    BoxFuture<'static, Option<(ExpectedParent<<B as Digestible>::Digest>, Arc<B>)>>;

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

// Asserts that `block` directly extends the chain link `last`.
fn assert_extends<B: Block>(last: &(Height, B::Digest), block: &B) {
    let (height, digest) = last;
    assert_eq!(
        block.height(),
        height.next(),
        "block must be contiguous in height"
    );
    assert_eq!(
        block.parent(),
        *digest,
        "block must be contiguous in ancestry"
    );
}

// Wraps `fetch`, recording its latency on success.
fn timed_fetch<C, T>(
    clock: &Arc<C>,
    fetch_duration: &Timed,
    fetch: impl Future<Output = Option<T>> + Send + 'static,
) -> BoxFuture<'static, Option<T>>
where
    C: Clock,
    T: Send + 'static,
{
    let timer = fetch_duration.timer(clock.as_ref());
    let clock = clock.clone();
    fetch
        .map(move |result| result.inspect(|_| timer.observe(clock.as_ref())))
        .boxed()
}

// Builds a pending parent fetch that records successful fetch latency and carries the
// expected relationship for validation when the parent is delivered.
fn timed_parent_fetch<C, M>(
    clock: &Arc<C>,
    marshal: &M,
    child: &M::Block,
    fetch_duration: &Timed,
) -> PendingFetch<M::Block>
where
    C: Clock,
    M: BlockProvider,
{
    let expected = ExpectedParent::from_child(child);
    timed_fetch(
        clock,
        fetch_duration,
        marshal
            .subscribe_parent(child)
            .map(move |parent| parent.map(|parent| (expected, parent))),
    )
}

/// Yields the ancestors of a block while prefetching parents, including the
/// height-zero genesis block if it is available.
#[pin_project]
pub struct AncestorStream<M: BlockProvider, C: Clock> {
    buffered: Vec<Arc<M::Block>>,
    /// The initial chain fixed at construction, ascending in height.
    chain: Vec<Arc<M::Block>>,
    /// The digest of the highest initial block, identifying the chain this
    /// stream walks.
    tip: Option<<M::Block as Digestible>::Digest>,
    marshal: M,
    fetch_duration: Timed,
    clock: Arc<C>,
    pending_child: Option<Arc<M::Block>>,
    #[pin]
    pending: OptionFuture<PendingFetch<M::Block>>,
}

impl<M: BlockProvider, C: Clock> AncestorStream<M, C> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous.
    #[stability(ALPHA)]
    pub(crate) fn new(
        clock: Arc<C>,
        marshal: M,
        initial: impl IntoIterator<Item = Arc<M::Block>>,
        fetch_duration: Timed,
    ) -> Self {
        let chain = sort_and_validate_chain(initial);

        let tip = chain.last().map(|block| block.digest());
        Self {
            marshal,
            buffered: chain.clone(),
            chain,
            tip,
            fetch_duration,
            clock,
            pending_child: None,
            pending: None.into(),
        }
    }

    /// Peeks at the latest block in the stream without consuming it. Returns [None]
    /// if the stream does not yet have a block available or has been exhausted.
    pub fn peek(&self) -> Option<&M::Block> {
        self.buffered.last().map(Arc::as_ref)
    }
}

impl<M, C> Clone for AncestorStream<M, C>
where
    M: BlockProvider + Clone,
    C: Clock,
{
    fn clone(&self) -> Self {
        let pending_child = self.pending_child.clone();
        let marshal = self.marshal.clone();
        let fetch_duration = self.fetch_duration.clone();
        let clock = self.clock.clone();
        let pending = pending_child
            .as_ref()
            .map(|child| timed_parent_fetch(&clock, &marshal, child, &fetch_duration))
            .into();

        Self {
            buffered: self.buffered.clone(),
            marshal,
            fetch_duration,
            clock,
            pending_child,
            pending,
        }
    }
}

impl<M, C> Ancestry<M::Block> for AncestorStream<M, C>
where
    M: BlockProvider + Clone,
    C: Clock,
{
    fn peek(&self) -> Option<&M::Block> {
        Self::peek(self)
    }

    fn descendants(
        &self,
        start: BlockID<<M::Block as Digestible>::Digest>,
    ) -> impl Future<Output = Option<impl Ancestry<M::Block>>> + Send {
        let chain = chain_suffix(&self.chain, start);
        let tip = self.tip;
        let marshal = self.marshal.clone();
        let clock = self.clock.clone();
        let fetch_duration = self.fetch_duration.clone();
        async move {
            if let Some(chain) = chain {
                return Some(DescendantStream::from_chain(
                    clock,
                    marshal,
                    chain,
                    fetch_duration,
                ));
            }
            let (block, tip) = marshal.get_descendant(start, BlockID::Digest(tip?)).await?;
            Some(DescendantStream::new(
                clock,
                marshal,
                block,
                tip,
                fetch_duration,
            ))
        }
    }
}

impl<M, C> Stream for AncestorStream<M, C>
where
    M: BlockProvider,
    C: Clock,
{
    type Item = Arc<M::Block>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        const END_BOUND: Height = Height::zero();

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.pop() {
            let height = block.height();
            let should_walk_parent = height > END_BOUND;
            let end_of_buffered = this.buffered.is_empty();
            if should_walk_parent && end_of_buffered {
                let future =
                    timed_parent_fetch(this.clock, this.marshal, &block, this.fetch_duration);
                *this.pending_child = Some(block.clone());
                *this.pending.as_mut() = Some(future).into();

                // Explicitly poll the next future to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                match this.pending.as_mut().poll(cx) {
                    Poll::Ready(Some(Some((expected, parent)))) => {
                        expected.assert_matches(parent.as_ref());
                        this.buffered.push(parent);
                        *this.pending_child = None;
                    }
                    Poll::Ready(Some(None)) => {
                        *this.pending.as_mut() = None.into();
                        *this.pending_child = None;
                    }
                    Poll::Ready(None) => {
                        *this.pending_child = None;
                    }
                    Poll::Pending => {}
                }
            } else if !should_walk_parent {
                // No more parents to fetch; Finish the stream.
                *this.pending.as_mut() = None.into();
                *this.pending_child = None;
            }

            return Poll::Ready(Some(block));
        }

        match this.pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) | Poll::Ready(Some(None)) => {
                *this.pending.as_mut() = None.into();
                *this.pending_child = None;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Some((expected, block)))) => {
                expected.assert_matches(block.as_ref());
                let height = block.height();
                let should_walk_parent = height > END_BOUND;
                if should_walk_parent {
                    let future =
                        timed_parent_fetch(this.clock, this.marshal, &block, this.fetch_duration);
                    *this.pending_child = Some(block.clone());
                    *this.pending.as_mut() = Some(future).into();

                    // Explicitly poll the next future to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    match this.pending.as_mut().poll(cx) {
                        Poll::Ready(Some(Some((expected, parent)))) => {
                            expected.assert_matches(parent.as_ref());
                            this.buffered.push(parent);
                            *this.pending_child = None;
                        }
                        Poll::Ready(Some(None)) => {
                            *this.pending.as_mut() = None.into();
                            *this.pending_child = None;
                        }
                        Poll::Ready(None) => {
                            *this.pending_child = None;
                        }
                        Poll::Pending => {}
                    }
                } else {
                    // No more parents to fetch; Finish the stream.
                    *this.pending.as_mut() = None.into();
                    *this.pending_child = None;
                }

                Poll::Ready(Some(block))
            }
        }
    }
}

// A pending descendant fetch paired with the chain link it must extend.
type PendingDescendantFetch<B> =
    BoxFuture<'static, Option<((Height, <B as Digestible>::Digest), Arc<B>)>>;

// Builds a pending fetch for the block directly above `parent` in `tip`'s
// ancestry, recording successful fetch latency and carrying the link the
// fetched block must extend.
fn timed_descendant_fetch<C, M>(
    clock: &Arc<C>,
    marshal: &M,
    parent: &M::Block,
    tip: <M::Block as Digestible>::Digest,
    fetch_duration: &Timed,
) -> PendingDescendantFetch<M::Block>
where
    C: Clock,
    M: BlockProvider,
{
    let link = (parent.height(), parent.digest());
    timed_fetch(
        clock,
        fetch_duration,
        marshal
            .get_descendant(BlockID::Height(link.0.next()), BlockID::Digest(tip))
            .map(move |block| block.map(|(block, _)| (link, block))),
    )
}

/// Yields a tip's ancestry in ascending height order, from a chosen ancestor
/// up to the tip itself.
///
/// The stream is armed with its first block and lazily fetches each following
/// block from the provider (prefetching the next block while the previous one
/// is consumed), mirroring [AncestorStream] in the opposite direction. It
/// finishes once the tip is yielded, and ends early if the next block becomes
/// unavailable locally (e.g. its branch was pruned by a finalization, or a
/// finalized block was pruned while iterating).
///
/// # Panics
///
/// Panics if fetched blocks do not form a contiguous chain, which indicates
/// local storage corruption.
#[pin_project]
pub struct DescendantStream<M: BlockProvider, C: Clock> {
    /// Blocks ready to yield in ascending height order.
    buffered: VecDeque<Arc<M::Block>>,
    /// A complete chain known at construction, when available.
    chain: Option<Vec<Arc<M::Block>>>,
    /// The digest of the tip; the stream finishes once it is yielded.
    tip: <M::Block as Digestible>::Digest,
    marshal: M,
    fetch_duration: Timed,
    clock: Arc<C>,
    #[pin]
    pending: OptionFuture<PendingDescendantFetch<M::Block>>,
}

impl<M: BlockProvider, C: Clock> DescendantStream<M, C> {
    /// Creates a new [DescendantStream] armed with the first block of the
    /// walk, ending at `tip`.
    ///
    /// `start` must lie in the ancestry of `tip`; providers validate this
    /// when resolving the anchor (see [BlockProvider::get_descendant]).
    pub(crate) fn new(
        clock: Arc<C>,
        marshal: M,
        start: Arc<M::Block>,
        tip: <M::Block as Digestible>::Digest,
        fetch_duration: Timed,
    ) -> Self {
        Self {
            buffered: [start].into(),
            chain: None,
            tip,
            marshal,
            fetch_duration,
            clock,
            pending: None.into(),
        }
    }

    /// Creates a forward stream from a complete in-memory chain.
    fn from_chain(
        clock: Arc<C>,
        marshal: M,
        chain: Vec<Arc<M::Block>>,
        fetch_duration: Timed,
    ) -> Self {
        let chain = sort_and_validate_chain(chain);
        let tip = chain
            .last()
            .expect("descendant chain must not be empty")
            .digest();
        Self {
            buffered: chain.clone().into(),
            chain: Some(chain),
            tip,
            marshal,
            fetch_duration,
            clock,
            pending: None.into(),
        }
    }

    /// Peeks at the next block in the stream without consuming it. Returns
    /// [None] if the stream does not yet have a block available or has been
    /// exhausted.
    pub fn peek(&self) -> Option<&M::Block> {
        self.buffered.front().map(Arc::as_ref)
    }
}

impl<M, C> Ancestry<M::Block> for DescendantStream<M, C>
where
    M: BlockProvider,
    C: Clock,
{
    fn peek(&self) -> Option<&M::Block> {
        Self::peek(self)
    }

    fn descendants(
        &self,
        start: BlockID<<M::Block as Digestible>::Digest>,
    ) -> impl Future<Output = Option<impl Ancestry<M::Block>>> + Send {
        let chain = self
            .chain
            .as_ref()
            .and_then(|chain| chain_suffix(chain, start));
        let tip = self.tip;
        let marshal = self.marshal.clone();
        let clock = self.clock.clone();
        let fetch_duration = self.fetch_duration.clone();
        async move {
            if let Some(chain) = chain {
                return Some(Self::from_chain(clock, marshal, chain, fetch_duration));
            }
            let (block, tip) = marshal.get_descendant(start, BlockID::Digest(tip)).await?;
            Some(Self::new(clock, marshal, block, tip, fetch_duration))
        }
    }
}

impl<M, C> Stream for DescendantStream<M, C>
where
    M: BlockProvider,
    C: Clock,
{
    type Item = Arc<M::Block>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // If a block has been buffered, return it and queue the next fetch
        // if the tip has not been reached.
        if let Some(block) = this.buffered.pop_front() {
            if let Some(child) = this.buffered.front() {
                assert_extends(&(block.height(), block.digest()), child.as_ref());
            } else if block.digest() != *this.tip {
                let future = timed_descendant_fetch(
                    this.clock,
                    this.marshal,
                    &block,
                    *this.tip,
                    this.fetch_duration,
                );
                *this.pending.as_mut() = Some(future).into();

                // Explicitly poll the next future to kick off the fetch. If
                // it's already ready, buffer it for the next poll.
                match this.pending.as_mut().poll(cx) {
                    Poll::Ready(Some(Some((link, child)))) => {
                        assert_extends(&link, child.as_ref());
                        this.buffered.push_back(child);
                    }
                    Poll::Ready(Some(None)) => {
                        *this.pending.as_mut() = None.into();
                    }
                    Poll::Ready(None) | Poll::Pending => {}
                }
            } else {
                // The tip has been reached; finish the stream.
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
            Poll::Ready(Some(Some((link, block)))) => {
                assert_extends(&link, block.as_ref());
                if block.digest() != *this.tip {
                    let future = timed_descendant_fetch(
                        this.clock,
                        this.marshal,
                        &block,
                        *this.tip,
                        this.fetch_duration,
                    );
                    *this.pending.as_mut() = Some(future).into();

                    // Explicitly poll the next future to kick off the fetch.
                    // If it's already ready, buffer it for the next poll.
                    match this.pending.as_mut().poll(cx) {
                        Poll::Ready(Some(Some((link, child)))) => {
                            assert_extends(&link, child.as_ref());
                            this.buffered.push_back(child);
                        }
                        Poll::Ready(Some(None)) => {
                            *this.pending.as_mut() = None.into();
                        }
                        Poll::Ready(None) | Poll::Pending => {}
                    }
                } else {
                    // The tip has been reached; finish the stream.
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
    use commonware_cryptography::{Digest, Sha256, sha256::Digest as Sha256Digest};
    use commonware_runtime::{
        Runner as _, Supervisor as _, deterministic,
        telemetry::metrics::{
            MetricsExt as _,
            histogram::{Buckets, Timed},
        },
    };
    use commonware_utils::{channel::oneshot, sync::Mutex};
    use futures::StreamExt;

    #[derive(Default, Clone)]
    struct MockProvider(Vec<Block<Sha256Digest, ()>>);
    impl BlockProvider for MockProvider {
        type Block = Block<Sha256Digest, ()>;

        fn subscribe_parent(
            &self,
            block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            let parent = block.parent;
            std::future::ready(
                self.0
                    .iter()
                    .find(|b| b.digest() == parent)
                    .cloned()
                    .map(Arc::new),
            )
        }
    }

    type TestBlock = Block<Sha256Digest, ()>;
    type ParentSubscription = oneshot::Sender<Arc<TestBlock>>;

    #[derive(Default, Clone)]
    struct PendingProvider {
        subscriptions: Arc<Mutex<Vec<ParentSubscription>>>,
    }

    impl PendingProvider {
        fn subscription_count(&self) -> usize {
            self.subscriptions.lock().len()
        }

        fn complete_all(&self, parent: Arc<Block<Sha256Digest, ()>>) {
            let subscriptions = std::mem::take(&mut *self.subscriptions.lock());
            for subscription in subscriptions {
                assert!(subscription.send(parent.clone()).is_ok());
            }
        }
    }

    impl BlockProvider for PendingProvider {
        type Block = Block<Sha256Digest, ()>;

        fn subscribe_parent(
            &self,
            _block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            let (subscription, parent) = oneshot::channel();
            self.subscriptions.lock().push(subscription);
            parent.map(Result::ok)
        }

        fn get_descendant(
            &self,
            start: BlockID<Sha256Digest>,
            tip: BlockID<Sha256Digest>,
        ) -> impl Future<Output = Option<(Arc<Self::Block>, Sha256Digest)>> + Send + 'static
        {
            // Walk parent links from the tip down to locate the start on
            // the tip's chain.
            let result = (|| {
                let BlockID::Digest(tip) = tip else {
                    return None;
                };
                let mut cursor = tip;
                loop {
                    let block = self.0.iter().find(|b| b.digest() == cursor)?;
                    let found = match start {
                        BlockID::Height(height) => block.height() == height,
                        BlockID::Digest(digest) => block.digest() == digest,
                    };
                    if found {
                        return Some((Arc::new(block.clone()), tip));
                    }
                    cursor = block.parent;
                }
            })();
            std::future::ready(result)
        }
    }

    #[derive(Clone)]
    struct WrongParentProvider(Block<Sha256Digest, ()>);
    impl BlockProvider for WrongParentProvider {
        type Block = Block<Sha256Digest, ()>;

        fn subscribe_parent(
            &self,
            _block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            std::future::ready(Some(Arc::new(self.0.clone())))
        }

        fn get_descendant(
            &self,
            _start: BlockID<Sha256Digest>,
            tip: BlockID<Sha256Digest>,
        ) -> impl Future<Output = Option<(Arc<Self::Block>, Sha256Digest)>> + Send + 'static
        {
            let BlockID::Digest(tip) = tip else {
                return std::future::ready(None);
            };
            std::future::ready(Some((Arc::new(self.0.clone()), tip)))
        }
    }

    fn timed(context: &deterministic::Context) -> Timed {
        Timed::new(context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            Buckets::LOCAL,
        ))
    }

    fn stream<M>(
        context: &deterministic::Context,
        marshal: M,
        initial: impl IntoIterator<Item = M::Block>,
    ) -> AncestorStream<M, deterministic::Context>
    where
        M: BlockProvider,
    {
        let stream_context = context.child("ancestor_stream");
        let fetch_duration = timed(&stream_context);
        AncestorStream::new(
            Arc::new(stream_context),
            marshal,
            initial.into_iter().map(Arc::new),
            fetch_duration,
        )
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in height"]
    fn test_panics_on_non_contiguous_initial_blocks_height() {
        deterministic::Runner::default().start(|context| async move {
            stream(
                &context,
                MockProvider::default(),
                vec![
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1),
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(3), 3),
                ],
            );
        });
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in ancestry"]
    fn test_panics_on_non_contiguous_initial_blocks_digest() {
        deterministic::Runner::default().start(|context| async move {
            stream(
                &context,
                MockProvider::default(),
                vec![
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1),
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(2), 2),
                ],
            );
        });
    }

    #[test]
    #[should_panic = "fetched parent must be contiguous in height"]
    fn test_panics_on_non_contiguous_fetched_parent_height() {
        deterministic::Runner::default().start(|context| async move {
            let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
            let child = Block::new::<Sha256>((), parent.digest(), Height::new(3), 3);
            let stream = stream(&context, MockProvider(vec![parent]), [child]);
            futures::pin_mut!(stream);

            let waker = futures::task::noop_waker_ref();
            let mut cx = std::task::Context::from_waker(waker);
            let _ = futures::Stream::poll_next(stream.as_mut(), &mut cx);
        });
    }

    #[test]
    #[should_panic = "fetched parent must be contiguous in ancestry"]
    fn test_panics_on_non_contiguous_fetched_parent_digest() {
        deterministic::Runner::default().start(|context| async move {
            let expected_parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
            let fetched_parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 1);
            let child = Block::new::<Sha256>((), expected_parent.digest(), Height::new(1), 2);
            let stream = stream(&context, WrongParentProvider(fetched_parent), [child]);
            futures::pin_mut!(stream);

            let waker = futures::task::noop_waker_ref();
            let mut cx = std::task::Context::from_waker(waker);
            let _ = futures::Stream::poll_next(stream.as_mut(), &mut cx);
        });
    }

    #[test]
    fn test_peek_available_through_ancestry_trait() {
        deterministic::Runner::default().start(|context| async move {
            fn peek_height(ancestry: impl Ancestry<Block<Sha256Digest, ()>>) -> Option<Height> {
                ancestry.peek().map(Heightable::height)
            }

            let block = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let stream = stream(&context, MockProvider::default(), [block.clone()]);
            assert_eq!(peek_height(stream), Some(block.height()));
        });
    }

    #[test]
    fn test_descendants_use_initial_chain_when_tip_is_unknown_to_provider() {
        deterministic::Runner::default().start(|context| async move {
            let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let child = Block::new::<Sha256>((), parent.digest(), Height::new(2), 2);
            let mut ancestry = stream(
                &context,
                MockProvider::default(),
                [child.clone(), parent.clone()],
            );

            assert_eq!(ancestry.next().await.as_deref(), Some(&child));
            let descendants = ancestry
                .descendants(BlockID::Digest(parent.digest()))
                .await
                .expect("initial chain should not require the provider to know its tip");
            assert_eq!(
                descendants.collect::<Vec<_>>().await,
                vec![Arc::new(parent), Arc::new(child)]
            );
        });
    }

    #[test]
    fn test_from_iter_descendants_survive_consumption() {
        deterministic::Runner::default().start(|_| async move {
            let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let child = Block::new::<Sha256>((), parent.digest(), Height::new(2), 2);
            let mut ancestry = from_iter([Arc::new(child.clone()), Arc::new(parent.clone())]);

            // Consuming the tip must not remove it from the chain served by
            // forward walks.
            assert_eq!(ancestry.next().await.as_deref(), Some(&child));
            let forward = ancestry
                .descendants(BlockID::Digest(parent.digest()))
                .await
                .expect("start on chain");
            let results = forward.collect::<Vec<_>>().await;
            assert_eq!(results, vec![Arc::new(parent), Arc::new(child)]);
        });
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in height"]
    fn test_from_iter_panics_on_non_contiguous_height() {
        let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
        let child = Block::new::<Sha256>((), parent.digest(), Height::new(3), 3);

        let _ = from_iter([Arc::new(child), Arc::new(parent)]);
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in ancestry"]
    fn test_from_iter_panics_on_non_contiguous_ancestry() {
        let expected_parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
        let wrong_parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 2);
        let child = Block::new::<Sha256>((), expected_parent.digest(), Height::new(2), 3);

        let _ = from_iter([Arc::new(child), Arc::new(wrong_parent)]);
    }

    #[test]
    fn test_from_iter_available_through_ancestry_trait() {
        fn peek_height(ancestry: impl Ancestry<Block<Sha256Digest, ()>>) -> Option<Height> {
            ancestry.peek().map(Heightable::height)
        }

        let block = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
        let ancestry = from_iter([Arc::new(block.clone())]);

        assert_eq!(peek_height(ancestry), Some(block.height()));
    }

    #[test]
    fn test_from_iter_yields_blocks_in_order_and_peeks_next() {
        deterministic::Runner::default().start(|_| async move {
            let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let child = Block::new::<Sha256>((), parent.digest(), Height::new(2), 2);
            let mut ancestry = from_iter([Arc::new(child.clone()), Arc::new(parent.clone())]);

            assert_eq!(ancestry.peek(), Some(&child));
            assert_eq!(ancestry.next().await.as_deref(), Some(&child));
            assert_eq!(ancestry.peek(), Some(&parent));
            assert_eq!(ancestry.next().await.as_deref(), Some(&parent));
            assert_eq!(ancestry.peek(), None);
            assert_eq!(ancestry.next().await, None);
        });
    }

    #[test]
    fn test_with_prefix_peeks_tail_when_prefix_empty() {
        deterministic::Runner::default().start(|_| async move {
            let block = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let mut ancestry = with_prefix([], from_iter([Arc::new(block.clone())]));

            assert_eq!(ancestry.peek(), Some(&block));
            assert_eq!(ancestry.next().await.as_deref(), Some(&block));
            assert_eq!(ancestry.peek(), None);
        });
    }

    #[test]
    fn test_with_prefix_peeks_tail_after_prefix_consumed() {
        deterministic::Runner::default().start(|_| async move {
            let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let child = Block::new::<Sha256>((), parent.digest(), Height::new(2), 2);
            let mut ancestry = with_prefix(
                [Arc::new(child.clone())],
                from_iter([Arc::new(parent.clone())]),
            );

            assert_eq!(ancestry.peek(), Some(&child));
            assert_eq!(ancestry.next().await.as_deref(), Some(&child));
            assert_eq!(ancestry.peek(), Some(&parent));
            assert_eq!(ancestry.next().await.as_deref(), Some(&parent));
            assert_eq!(ancestry.peek(), None);
        });
    }

    #[test]
    fn test_yields_genesis_and_stops() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
            let child = Block::new::<Sha256>((), genesis.digest(), Height::new(1), 1);

            let provider = MockProvider(vec![genesis.clone()]);
            let stream = stream(&context, provider, [child.clone()]);

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![Arc::new(child), Arc::new(genesis)]);
        });
    }

    #[test]
    fn test_clone_preserves_pending_parent_fetch() {
        deterministic::Runner::default().start(|context| async move {
            let parent = Arc::new(Block::new::<Sha256>(
                (),
                Sha256Digest::EMPTY,
                Height::zero(),
                0,
            ));
            let child = Block::new::<Sha256>((), parent.digest(), Height::new(1), 1);
            let provider = PendingProvider::default();
            let mut stream = stream(&context, provider.clone(), [child.clone()]);

            assert_eq!(stream.next().await.as_deref(), Some(&child));
            assert_eq!(provider.subscription_count(), 1);

            let mut cloned = stream.clone();
            assert_eq!(provider.subscription_count(), 2);
            provider.complete_all(parent.clone());

            assert_eq!(stream.next().await, Some(parent.clone()));
            assert_eq!(cloned.next().await, Some(parent.clone()));
            assert_eq!(stream.next().await, None);
            assert_eq!(cloned.next().await, None);
        });
    }

    #[test]
    fn test_empty_yields_none() {
        deterministic::Runner::default().start(|context| async move {
            let mut stream: AncestorStream<MockProvider, deterministic::Context> =
                stream(&context, MockProvider::default(), vec![]);
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
            let stream = stream(&context, provider, [block3.clone()]);

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(
                results,
                vec![Arc::new(block3), Arc::new(block2), Arc::new(block1)]
            );
        });
    }

    #[test]
    fn test_yields_ancestors_all_buffered() {
        deterministic::Runner::default().start(|context| async move {
            let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
            let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![]);
            let stream = stream(
                &context,
                provider,
                [block1.clone(), block2.clone(), block3.clone()],
            );

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(
                results,
                vec![Arc::new(block3), Arc::new(block2), Arc::new(block1)]
            );
        });
    }

    #[test]
    fn test_missing_parent_ends_stream() {
        deterministic::Runner::default().start(|context| async move {
            let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
            let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![block1]);
            let stream = stream(&context, provider, [block3.clone()]);

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![Arc::new(block3)]);
        });
    }

    /// Builds a chain of `len` contiguous blocks starting at height `start`.
    fn make_chain(start: u64, len: u64) -> Vec<Block<Sha256Digest, ()>> {
        let mut blocks = Vec::new();
        let mut parent = Sha256Digest::EMPTY;
        for height in start..start + len {
            let block = Block::new::<Sha256>((), parent, Height::new(height), height);
            parent = block.digest();
            blocks.push(block);
        }
        blocks
    }

    fn descendant_stream<M>(
        context: &deterministic::Context,
        provider: M,
        start: M::Block,
        tip: Sha256Digest,
    ) -> DescendantStream<M, deterministic::Context>
    where
        M: BlockProvider<Block = Block<Sha256Digest, ()>>,
    {
        let stream_context = context.child("descendant_stream");
        let fetch_duration = timed(&stream_context);
        DescendantStream::new(
            Arc::new(stream_context),
            provider,
            Arc::new(start),
            tip,
            fetch_duration,
        )
    }

    #[test]
    fn test_descendant_walks_chain_to_tip() {
        deterministic::Runner::default().start(|context| async move {
            let chain = make_chain(0, 5);
            let provider = MockProvider(chain.clone());

            let stream = descendant_stream(&context, provider, chain[0].clone(), chain[4].digest());
            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(
                results,
                chain.iter().cloned().map(Arc::new).collect::<Vec<_>>()
            );
        });
    }

    #[test]
    fn test_descendant_single_block_when_start_is_tip() {
        deterministic::Runner::default().start(|context| async move {
            let chain = make_chain(3, 1);
            let provider = MockProvider(chain.clone());

            let mut stream =
                descendant_stream(&context, provider, chain[0].clone(), chain[0].digest());
            assert_eq!(stream.peek(), Some(&chain[0]));
            assert_eq!(stream.next().await.as_deref(), Some(&chain[0]));
            assert_eq!(stream.peek(), None);
            assert_eq!(stream.next().await, None);
        });
    }

    #[test]
    fn test_descendant_missing_block_ends_stream() {
        deterministic::Runner::default().start(|context| async move {
            let chain = make_chain(0, 5);

            // The block at height 2 is missing locally, so the provider can
            // no longer connect the tip's chain to the next requested height;
            // the walk ends after the anchor.
            let mut stored = chain.clone();
            stored.remove(2);
            let provider = MockProvider(stored);

            let stream = descendant_stream(&context, provider, chain[0].clone(), chain[4].digest());
            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![Arc::new(chain[0].clone())]);
        });
    }

    #[test]
    fn test_descendant_peek_available_through_ancestry_trait() {
        deterministic::Runner::default().start(|context| async move {
            fn peek_height(ancestry: impl Ancestry<Block<Sha256Digest, ()>>) -> Option<Height> {
                ancestry.peek().map(Heightable::height)
            }

            let block = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let stream = descendant_stream(
                &context,
                MockProvider::default(),
                block.clone(),
                block.digest(),
            );
            assert_eq!(peek_height(stream), Some(block.height()));
        });
    }

    #[test]
    fn test_descendant_restarts_from_any_position() {
        deterministic::Runner::default().start(|context| async move {
            let chain = make_chain(0, 5);
            let provider = MockProvider(chain.clone());

            // A forward stream can itself be flipped to a new start on the
            // same chain through the Ancestry trait.
            let stream = descendant_stream(&context, provider, chain[0].clone(), chain[4].digest());
            let restarted = stream
                .descendants(BlockID::Height(Height::new(2)))
                .await
                .expect("restart within chain");
            let results = restarted.collect::<Vec<_>>().await;
            assert_eq!(
                results,
                chain[2..].iter().cloned().map(Arc::new).collect::<Vec<_>>()
            );

            // A start outside the chain resolves to nothing.
            let provider = MockProvider(chain.clone());
            let stream = descendant_stream(&context, provider, chain[0].clone(), chain[4].digest());
            assert!(
                stream
                    .descendants(BlockID::Height(Height::new(9)))
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    #[should_panic = "block must be contiguous in height"]
    fn test_descendant_panics_on_non_contiguous_fetched_block() {
        deterministic::Runner::default().start(|context| async move {
            // The provider serves a block that does not extend the anchor.
            let anchor = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let lying = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(9), 9);
            let provider = WrongParentProvider(lying);

            let stream = descendant_stream(&context, provider, anchor, Sha256::fill(0xAB));
            let _ = stream.collect::<Vec<_>>().await;
        });
    }
}
