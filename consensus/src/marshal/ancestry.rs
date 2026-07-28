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
    stream::{BoxStream, StreamExt as _},
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
    ) -> impl Future<Output = Option<impl Stream<Item = Arc<B>> + Send + Unpin + 'static>> + Send;
}

fn sort_and_validate_chain<B: Block>(blocks: impl IntoIterator<Item = Arc<B>>) -> Vec<Arc<B>> {
    let mut chain = blocks.into_iter().collect::<Vec<_>>();
    chain.sort_by_key(|block| block.height());

    for window in chain.windows(2) {
        let parent = &window[0];
        let child = &window[1];
        assert_eq!(
            child.height().previous(),
            Some(parent.height()),
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
    let chain = Arc::from(sort_and_validate_chain(blocks.iter().cloned()));
    BoundedAncestry { blocks, chain }
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

    fn descendants(
        &self,
        start: BlockID<B::Digest>,
    ) -> impl Future<Output = Option<impl Stream<Item = Arc<B>> + Send + Unpin + 'static>> + Send {
        self.0.descendants_erased(start)
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

    fn descendants_erased(
        &self,
        start: BlockID<B::Digest>,
    ) -> BoxFuture<'_, Option<BoxStream<'static, Arc<B>>>>;

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

    fn descendants_erased(
        &self,
        start: BlockID<B::Digest>,
    ) -> BoxFuture<'_, Option<BoxStream<'static, Arc<B>>>> {
        Ancestry::descendants(self, start)
            .map(|ancestry| ancestry.map(|stream| stream.boxed()))
            .boxed()
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
    chain: Arc<[Arc<B>]>,
}

impl<B: Block> Unpin for BoundedAncestry<B> {}

impl<B: Block> Ancestry<B> for BoundedAncestry<B> {
    fn peek(&self) -> Option<&B> {
        self.blocks.front().map(Arc::as_ref)
    }

    fn descendants(
        &self,
        start: BlockID<B::Digest>,
    ) -> impl Future<Output = Option<impl Stream<Item = Arc<B>> + Send + Unpin + 'static>> + Send {
        // A bounded ancestry is fully in memory: serve the chain fixed at
        // construction from the start onward, in ascending height order.
        std::future::ready(chain_suffix(&self.chain, start).map(futures::stream::iter))
    }
}

impl<B: Block> Stream for BoundedAncestry<B> {
    type Item = Arc<B>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.blocks.pop_front())
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
}

/// An interface for forward walks over locally known block ancestry.
pub trait DescendantProvider: BlockProvider {
    /// Opaque state used to continue a forward ancestry walk.
    type Cursor: Clone + Send + 'static;

    /// Retrieves the next non-empty, contiguous batch from `start` toward
    /// `tip`, together with the resolved tip digest.
    fn get_descendants(
        &self,
        request: DescendantRequest<<Self::Block as Digestible>::Digest, Self::Cursor>,
    ) -> impl Future<Output = Option<DescendantPage<Self::Block, Self::Cursor>>> + Send + 'static;
}

/// A request to start or continue a forward ancestry walk.
pub enum DescendantRequest<D: Digest, C> {
    /// Starts a walk at `start` within the ancestry of `tip`.
    Start {
        /// The first block to return.
        start: BlockID<D>,
        /// The block whose ancestry defines the chain.
        tip: BlockID<D>,
    },
    /// Continues a previously started walk.
    Continue(C),
}

/// One non-empty page of a forward ancestry walk.
pub struct DescendantPage<B: Block, C> {
    /// Contiguous blocks in ascending height order.
    pub blocks: Vec<Arc<B>>,
    /// The resolved digest of the walk's tip.
    pub tip: B::Digest,
    /// State for retrieving the next page, if any.
    pub cursor: Option<C>,
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
        block.height().previous(),
        Some(*height),
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

fn prefetch_parent<B: Block>(
    child: Arc<B>,
    future: PendingFetch<B>,
    buffered: &mut Vec<Arc<B>>,
    pending_child: &mut Option<Arc<B>>,
    mut pending: Pin<&mut OptionFuture<PendingFetch<B>>>,
    cx: &mut Context<'_>,
) {
    *pending_child = Some(child);
    pending.as_mut().set(Some(future).into());

    match pending.as_mut().poll(cx) {
        Poll::Ready(Some(Some((expected, parent)))) => {
            expected.assert_matches(parent.as_ref());
            buffered.push(parent);
            *pending_child = None;
        }
        Poll::Ready(Some(None)) => {
            pending.as_mut().set(None.into());
            *pending_child = None;
        }
        Poll::Ready(None) => *pending_child = None,
        Poll::Pending => {}
    }
}

/// Yields the ancestors of a block while prefetching parents, including the
/// height-zero genesis block if it is available.
#[pin_project]
pub struct AncestorStream<M: BlockProvider, C: Clock> {
    buffered: Vec<Arc<M::Block>>,
    /// The initial chain fixed at construction, ascending in height.
    chain: Arc<[Arc<M::Block>]>,
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
        let chain: Arc<[Arc<M::Block>]> = Arc::from(sort_and_validate_chain(initial));

        let tip = chain.last().map(|block| block.digest());
        Self {
            marshal,
            buffered: chain.iter().cloned().collect(),
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
            chain: self.chain.clone(),
            tip: self.tip,
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
    M: DescendantProvider + Clone,
    C: Clock,
{
    fn peek(&self) -> Option<&M::Block> {
        Self::peek(self)
    }

    fn descendants(
        &self,
        start: BlockID<<M::Block as Digestible>::Digest>,
    ) -> impl Future<
        Output = Option<impl Stream<Item = Arc<M::Block>> + Send + Unpin + 'static>,
    > + Send {
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
            let tip = tip?;
            let descendants = marshal.get_descendants(DescendantRequest::Start {
                start,
                tip: BlockID::Digest(tip),
            });
            let page = timed_fetch(&clock, &fetch_duration, descendants).await?;
            if page.tip != tip {
                return None;
            }
            Some(DescendantStream::from_page(
                clock,
                marshal,
                page,
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
                prefetch_parent(
                    block.clone(),
                    timed_parent_fetch(
                        this.clock,
                        this.marshal,
                        block.as_ref(),
                        this.fetch_duration,
                    ),
                    this.buffered,
                    this.pending_child,
                    this.pending.as_mut(),
                    cx,
                );
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
                    prefetch_parent(
                        block.clone(),
                        timed_parent_fetch(
                            this.clock,
                            this.marshal,
                            block.as_ref(),
                            this.fetch_duration,
                        ),
                        this.buffered,
                        this.pending_child,
                        this.pending.as_mut(),
                        cx,
                    );
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
type PendingDescendantFetch<B, C> =
    BoxFuture<'static, Option<((Height, <B as Digestible>::Digest), DescendantPage<B, C>)>>;

// Builds a pending fetch for the ancestry batch starting directly above
// `parent`, recording successful fetch latency and carrying the link the
// fetched batch must extend.
fn timed_descendant_fetch<C, M>(
    clock: &Arc<C>,
    marshal: &M,
    parent: &M::Block,
    cursor: M::Cursor,
    tip: <M::Block as Digestible>::Digest,
    fetch_duration: &Timed,
) -> PendingDescendantFetch<M::Block, M::Cursor>
where
    C: Clock,
    M: DescendantProvider,
{
    let link = (parent.height(), parent.digest());
    timed_fetch(
        clock,
        fetch_duration,
        marshal
            .get_descendants(DescendantRequest::Continue(cursor))
            .map(move |page| {
                page.and_then(|page| {
                    (page.tip == tip && !page.blocks.is_empty()).then_some((link, page))
                })
            }),
    )
}

fn buffer_descendants<B: Block>(
    link: &(Height, B::Digest),
    blocks: Vec<Arc<B>>,
    tip: B::Digest,
    buffered: &mut VecDeque<Arc<B>>,
) {
    let blocks = sort_and_validate_chain(blocks);
    assert_extends(
        link,
        blocks
            .first()
            .expect("descendant batch must not be empty")
            .as_ref(),
    );
    if let Some(position) = blocks.iter().position(|block| block.digest() == tip) {
        assert_eq!(
            position + 1,
            blocks.len(),
            "descendant batch must end at the requested tip"
        );
    }
    buffered.extend(blocks);
}

/// Yields a tip's ancestry in ascending height order, from a chosen ancestor
/// up to the tip itself.
///
/// The stream is armed with its first batch and lazily fetches following
/// batches from the provider (prefetching the next batch while the previous one
/// is consumed), mirroring [AncestorStream] in the opposite direction. It
/// finishes once the tip is yielded. Candidate ancestry is snapshotted when
/// the walk starts; finalized archive pages remain lazy and can end early if
/// they become unavailable locally while iterating.
///
/// # Panics
///
/// Panics if fetched blocks do not form a contiguous chain, which indicates
/// local storage corruption.
#[pin_project]
pub struct DescendantStream<M: DescendantProvider, C: Clock> {
    /// Blocks ready to yield in ascending height order.
    buffered: VecDeque<Arc<M::Block>>,
    /// The digest of the tip; the stream finishes once it is yielded.
    tip: <M::Block as Digestible>::Digest,
    marshal: M,
    fetch_duration: Timed,
    clock: Arc<C>,
    cursor: Option<M::Cursor>,
    #[pin]
    pending: OptionFuture<PendingDescendantFetch<M::Block, M::Cursor>>,
}

impl<M: DescendantProvider, C: Clock> DescendantStream<M, C> {
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
            buffered: chain.into(),
            tip,
            marshal,
            fetch_duration,
            clock,
            cursor: None,
            pending: None.into(),
        }
    }

    /// Creates a forward stream from a provider batch that may not yet reach
    /// the resolved tip.
    fn from_page(
        clock: Arc<C>,
        marshal: M,
        page: DescendantPage<M::Block, M::Cursor>,
        fetch_duration: Timed,
    ) -> Self {
        let batch = sort_and_validate_chain(page.blocks);
        assert!(!batch.is_empty(), "descendant batch must not be empty");
        Self {
            buffered: batch.into(),
            tip: page.tip,
            marshal,
            fetch_duration,
            clock,
            cursor: page.cursor,
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

impl<M, C> Stream for DescendantStream<M, C>
where
    M: DescendantProvider,
    C: Clock,
{
    type Item = Arc<M::Block>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        if this.buffered.is_empty() {
            match this.pending.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) | Poll::Ready(Some(None)) => {
                    *this.pending.as_mut() = None.into();
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Some((link, page)))) => {
                    buffer_descendants(&link, page.blocks, *this.tip, this.buffered);
                    *this.cursor = page.cursor;
                }
            }
        }

        let Some(block) = this.buffered.pop_front() else {
            return Poll::Ready(None);
        };
        if block.digest() == *this.tip {
            this.buffered.clear();
            *this.pending.as_mut() = None.into();
        } else if let Some(child) = this.buffered.front() {
            assert_extends(&(block.height(), block.digest()), child.as_ref());
        } else {
            let Some(cursor) = this.cursor.take() else {
                return Poll::Ready(Some(block));
            };
            let future = timed_descendant_fetch(
                this.clock,
                this.marshal,
                &block,
                cursor,
                *this.tip,
                this.fetch_duration,
            );
            *this.pending.as_mut() = Some(future).into();

            // Kick off the next batch while the current block is consumed.
            match this.pending.as_mut().poll(cx) {
                Poll::Ready(Some(Some((link, page)))) => {
                    buffer_descendants(&link, page.blocks, *this.tip, this.buffered);
                    *this.cursor = page.cursor;
                }
                Poll::Ready(Some(None)) => {
                    *this.pending.as_mut() = None.into();
                }
                Poll::Ready(None) => {}
                Poll::Pending => {}
            }
        }

        Poll::Ready(Some(block))
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    impl DescendantProvider for MockProvider {
        type Cursor = ();

        fn get_descendants(
            &self,
            request: DescendantRequest<Sha256Digest, Self::Cursor>,
        ) -> impl Future<Output = Option<DescendantPage<Self::Block, Self::Cursor>>> + Send + 'static {
            let result = (|| {
                let DescendantRequest::Start { start, tip } = request else {
                    return None;
                };
                let BlockID::Digest(tip) = tip else {
                    return None;
                };
                let mut cursor = tip;
                let mut blocks = Vec::new();
                loop {
                    let block = self.0.iter().find(|block| block.digest() == cursor)?;
                    blocks.push(Arc::new(block.clone()));
                    let found = match start {
                        BlockID::Height(height) => block.height() == height,
                        BlockID::Digest(digest) => block.digest() == digest,
                    };
                    if found {
                        blocks.reverse();
                        return Some(DescendantPage {
                            blocks,
                            tip,
                            cursor: None,
                        });
                    }
                    cursor = block.parent;
                }
            })();
            std::future::ready(result)
        }
    }

    #[derive(Clone)]
    struct BulkProvider {
        chain: Arc<Vec<Block<Sha256Digest, ()>>>,
        bulk: Arc<AtomicUsize>,
    }

    impl BlockProvider for BulkProvider {
        type Block = Block<Sha256Digest, ()>;

        fn subscribe_parent(
            &self,
            _block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            std::future::ready(None)
        }

    }

    impl DescendantProvider for BulkProvider {
        type Cursor = usize;

        fn get_descendants(
            &self,
            request: DescendantRequest<Sha256Digest, Self::Cursor>,
        ) -> impl Future<Output = Option<DescendantPage<Self::Block, Self::Cursor>>> + Send + 'static {
            self.bulk.fetch_add(1, Ordering::Relaxed);
            let chain = self.chain.clone();
            async move {
                let position = match request {
                    DescendantRequest::Start { start, tip } => {
                        let BlockID::Digest(tip) = tip else {
                            return None;
                        };
                        if tip != chain.last()?.digest() {
                            return None;
                        }
                        chain.iter().position(|block| match start {
                            BlockID::Height(height) => block.height() == height,
                            BlockID::Digest(digest) => block.digest() == digest,
                        })?
                    }
                    DescendantRequest::Continue(position) => position,
                };
                let end = position.saturating_add(8).min(chain.len());
                Some(DescendantPage {
                    blocks: chain[position..end]
                        .iter()
                        .cloned()
                        .map(Arc::new)
                        .collect(),
                    tip: chain.last()?.digest(),
                    cursor: (end < chain.len()).then_some(end),
                })
            }
        }
    }

    type TestBlock = Block<Sha256Digest, ()>;

    #[derive(Clone)]
    struct PageProvider {
        pages: Arc<Mutex<VecDeque<DescendantPage<TestBlock, ()>>>>,
    }

    impl BlockProvider for PageProvider {
        type Block = TestBlock;

        fn subscribe_parent(
            &self,
            _block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            std::future::ready(None)
        }
    }

    impl DescendantProvider for PageProvider {
        type Cursor = ();

        fn get_descendants(
            &self,
            _request: DescendantRequest<Sha256Digest, Self::Cursor>,
        ) -> impl Future<Output = Option<DescendantPage<Self::Block, Self::Cursor>>> + Send + 'static
        {
            std::future::ready(self.pages.lock().pop_front())
        }
    }

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
    fn test_descendants_use_bounded_bulk_lookups() {
        deterministic::Runner::default().start(|context| async move {
            let chain = make_chain(0, 64);
            let bulk = Arc::new(AtomicUsize::new(0));
            let provider = BulkProvider {
                chain: Arc::new(chain.clone()),
                bulk: bulk.clone(),
            };
            let ancestry = stream(&context, provider, [chain.last().unwrap().clone()]);

            let descendants = ancestry
                .descendants(BlockID::Height(Height::zero()))
                .await
                .expect("bulk chain should resolve")
                .collect::<Vec<_>>()
                .await;
            assert_eq!(descendants.len(), chain.len());
            assert_eq!(bulk.load(Ordering::Relaxed), 8);
        });
    }

    #[test]
    fn test_descendants_reject_changed_tip() {
        deterministic::Runner::default().start(|context| async move {
            let chain = make_chain(0, 3);
            let wrong_tip = Sha256::fill(0xAB);
            let provider = PageProvider {
                pages: Arc::new(Mutex::new(
                    [
                        DescendantPage {
                            blocks: vec![Arc::new(chain[0].clone())],
                            tip: chain[2].digest(),
                            cursor: Some(()),
                        },
                        DescendantPage {
                            blocks: vec![Arc::new(chain[1].clone())],
                            tip: wrong_tip,
                            cursor: None,
                        },
                    ]
                    .into(),
                )),
            };
            let ancestry = stream(&context, provider, [chain[2].clone()]);
            let descendants = ancestry
                .descendants(BlockID::Height(Height::zero()))
                .await
                .expect("initial page should resolve")
                .collect::<Vec<_>>()
                .await;
            assert_eq!(descendants, vec![Arc::new(chain[0].clone())]);
        });
    }

    #[test]
    fn test_descendants_stop_at_tip_with_buffered_child() {
        deterministic::Runner::default().start(|context| async move {
            let chain = make_chain(0, 4);
            let provider = PageProvider {
                pages: Arc::new(Mutex::new(
                    [DescendantPage {
                        blocks: chain.iter().cloned().map(Arc::new).collect(),
                        tip: chain[2].digest(),
                        cursor: None,
                    }]
                    .into(),
                )),
            };
            let ancestry = stream(&context, provider, [chain[2].clone()]);
            let descendants = ancestry
                .descendants(BlockID::Height(Height::zero()))
                .await
                .expect("page should resolve")
                .collect::<Vec<_>>()
                .await;
            assert_eq!(
                descendants,
                chain[..3].iter().cloned().map(Arc::new).collect::<Vec<_>>()
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

}
