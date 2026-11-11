//! Bounded forward access to a selected branch and the history below it.

use super::core::{Mailbox, Variant};
use crate::{Block, Heightable, History, types::Height};
use commonware_cryptography::{Digested, Digestible, certificate::Scheme};
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::{
    FutureExt as _, Stream,
    future::{BoxFuture, WeakShared},
    stream::FuturesOrdered,
};
use std::{
    collections::BTreeMap,
    ops::RangeInclusive,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
#[cfg(any(test, feature = "mocks"))]
use std::{future::Future, num::NonZeroUsize};
use thiserror::Error;

/// Metadata and acquisition for one selected branch.
trait Source<B: Block>: Send + Sync {
    /// Returns the resident digest selected at `height`.
    fn digest(&self, height: Height) -> Option<B::Digest>;

    /// Acquires the selected block at `height` and checks it against the resident digest.
    fn fetch(self: Arc<Self>, height: Height) -> BoxFuture<'static, Result<Digested<B>, Error>>;

    /// Returns the digest selected at `height`, discovering it when the source can.
    fn resolve(
        self: Arc<Self>,
        height: Height,
    ) -> BoxFuture<'static, Result<Option<B::Digest>, Error>>;

    /// Registers forward demand for the part of `heights` whose commitments the source holds,
    /// if it serves such demand.
    fn prefetch(&self, heights: RangeInclusive<Height>) -> Option<oneshot::Receiver<()>>;
}

/// Adapts the callback constructor to a branch source.
#[cfg(any(test, feature = "mocks"))]
struct CallbackSource<D, F> {
    digest: D,
    fetch: F,
}

#[cfg(any(test, feature = "mocks"))]
impl<B, D, F, Fut> Source<B> for CallbackSource<D, F>
where
    B: Block,
    D: Fn(Height) -> Option<B::Digest> + Send + Sync + 'static,
    F: Fn(Height) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<Digested<B>>> + Send + 'static,
{
    fn digest(&self, height: Height) -> Option<B::Digest> {
        (self.digest)(height)
    }

    fn fetch(self: Arc<Self>, height: Height) -> BoxFuture<'static, Result<Digested<B>, Error>> {
        let request = (self.fetch)(height);
        Box::pin(async move {
            let block = request.await.ok_or(Error::Unavailable)?;
            check_block(self.as_ref(), height, block)
        })
    }

    fn resolve(
        self: Arc<Self>,
        height: Height,
    ) -> BoxFuture<'static, Result<Option<B::Digest>, Error>> {
        let digest = self.digest(height);
        Box::pin(async move { Ok(digest) })
    }

    fn prefetch(&self, _heights: RangeInclusive<Height>) -> Option<oneshot::Receiver<()>> {
        None
    }
}

/// Checks an acquired block's height, and its digest when one is resident after acquisition.
fn check_block<B: Block>(
    source: &impl Source<B>,
    height: Height,
    block: Digested<B>,
) -> Result<Digested<B>, Error> {
    let expected = source.digest(height);
    if block.height() != height {
        return Err(Error::InvalidHeight);
    }
    if expected.is_some_and(|digest| digest != block.digest()) {
        return Err(Error::InvalidDigest);
    }
    Ok(block)
}

/// A failure to acquire a block on the selected branch.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    /// The block cannot be acquired: the source closed, holds no commitment to start from, or
    /// selects a branch that conflicts with finalized history.
    #[error("block unavailable")]
    Unavailable,
    /// A block or requested range is outside its expected heights.
    #[error("unexpected block height")]
    InvalidHeight,
    /// A block does not extend the preceding selected block.
    #[error("unexpected parent digest")]
    InvalidParent,
    /// A block does not match the selected commitment's digest.
    #[error("unexpected block digest")]
    InvalidDigest,
}

/// Access to blocks on one selected branch, ending at [`Self::tip`].
///
/// Clones share commitment metadata and the acquisition service, and start no requests. Each
/// [`range`](Self::range) owns its cursor and bounds both pending acquisitions and completed
/// bodies awaiting consumption. Dropping a range cancels its remaining demand.
///
/// A source that [`Mailbox::blocks_with_parent`] builds over a [`History`] suffix discovers the
/// commitments below it by following parent links through block bodies. Every clone and range of
/// the source shares one such walk. It advances only while a caller waits on it and acquires one
/// body at a time. Dropping every waiter cancels the step in flight, and the commitments
/// discovered so far stay with the source. The walk retains at most a range's window of the
/// lowest bodies it read, and a range takes a retained body without acquiring it again.
///
/// Later finalization or pruning does not redirect an acquisition that is already pending. It
/// stays pending until the body arrives, every waiter drops, or marshal shuts down. A read of a
/// canonical height also ends with [`Error::Unavailable`] when a floor update skips that height.
pub struct Blocks<B: Block> {
    tip: Height,
    source: Arc<dyn Source<B>>,
    window: usize,
}

impl<B: Block> Clone for Blocks<B> {
    fn clone(&self) -> Self {
        Self {
            tip: self.tip,
            source: self.source.clone(),
            window: self.window,
        }
    }
}

/// The parent of a block and the selected branch that ends at it.
///
/// Marshal supplies one for each block an [`Application`](crate::Application) builds or verifies.
pub struct Ancestry<B: Block> {
    /// The parent block.
    pub parent: Digested<B>,
    /// Access to the selected branch ending at [`Self::parent`], including finalized history.
    /// Its [`tip`](Blocks::tip) is the parent's height.
    pub blocks: Blocks<B>,
}

/// Returns the height of the first entry of a suffix of `len` commitments ending at
/// `tip`, or `None` when the suffix cannot fit below `tip`.
fn suffix_start(tip: Height, len: usize) -> Option<u64> {
    let Some(distance) = len.checked_sub(1) else {
        return Some(tip.get());
    };
    tip.get().checked_sub(u64::try_from(distance).ok()?)
}

/// Returns the commitment selected at `height` by a suffix ending at `tip`.
fn suffix_at<C: Copy>(tip: Height, commitments: &[C], height: Height) -> Option<C> {
    let first = suffix_start(tip, commitments.len())?;
    let index = usize::try_from(height.get().checked_sub(first)?).ok()?;
    commitments.get(index).copied()
}

impl<S: Scheme, V: Variant> Mailbox<S, V> {
    /// Provides forward access to the selected branch that ends at a request's parent.
    ///
    /// `parent` is the exact commitment bound by the request's context at `parent_height`. The
    /// caller must have acquired and validated that block. Neither this call nor the clones of its
    /// result start a request.
    ///
    /// `history` supplies the consensus-selected commitments in increasing height order, ending
    /// at that parent, with consecutive re-proposals occupying one entry. An empty `history`
    /// selects the parent alone. A history that ends at another commitment, or that holds more
    /// commitments than the branch has heights, makes every height [`Error::Unavailable`].
    ///
    /// Heights below the commitments are read according to the history:
    ///
    /// - Anchored: they are canonical and come from finalized storage.
    /// - Suffix: their commitments are discovered by walking down from the lowest known
    ///   commitment, one parent link per step.
    ///
    /// A step first asks marshal which block it records as finalized at the lowest known height,
    /// and a stored finalization or a stored block answers. A matching digest makes every lower
    /// height canonical, and those heights then come from finalized storage. A different digest
    /// means the branch conflicts with finalized history, and lower heights are
    /// [`Error::Unavailable`]. Finalized storage is sampled once per step and never awaited for a
    /// height that is not known to be finalized.
    ///
    /// With no finalized block recorded there, the step acquires the body by its commitment and
    /// takes the parent it names as the next commitment. The first step reads the body of the
    /// history's first commitment. When `history` is empty or holds only the parent, that is the
    /// bound parent's body.
    ///
    /// An anchored history gives each commitment a height by its position, with the last at
    /// `parent_height`. If a block on the branch declares a height that is not one above its
    /// parent's, the anchor's inferred height is wrong, and a read below it can wait on a height
    /// that is not finalized. Such a block fails its own certification, so nothing built on it can
    /// finalize.
    ///
    /// A polled range keeps the part of its remaining heights that `history` covers prefetched
    /// in forward order, within the capacity shared by all ranges
    /// ([`Config::max_repair`](super::Config)). Each range's window of pending acquisitions and
    /// buffered bodies is additional to that capacity, as are the bodies a walk retains.
    pub fn blocks_with_parent(
        &self,
        parent_height: Height,
        parent: V::Commitment,
        history: History<V::Commitment>,
    ) -> Blocks<V::ApplicationBlock> {
        // The commitments must end at the bound parent. An empty history selects the parent
        // alone, and a history that ends elsewhere selects nothing.
        let commitments = match history.commitments().last() {
            None => Arc::from([parent]),
            Some(last) if *last == parent => history.commitments().clone(),
            Some(_) => Arc::from([]),
        };

        // Below an anchored history lies finalized storage, and below a suffix a walk from its
        // first commitment. Commitments that do not fit below the parent identify no height.
        let first = suffix_start(parent_height, commitments.len());
        let below = match (first, commitments.first()) {
            (Some(_), Some(_)) if history.is_anchored() => Below::Canonical,
            (Some(first), Some(commitment)) => {
                let walk = Walk::new(Height::new(first), *commitment);
                Below::Walked(Arc::new(Mutex::new(walk)))
            }
            _ => Below::Unknown,
        };
        self.source(parent_height, commitments, below)
    }

    /// Provides forward access to canonical finalized history through `tip`.
    ///
    /// Every height comes from finalized storage, and no commitment is resident. Neither this
    /// call nor the clones of its result start a request.
    pub fn finalized_blocks(&self, tip: Height) -> Blocks<V::ApplicationBlock> {
        self.source(tip, Arc::from([]), Below::Canonical)
    }

    /// Wraps the selected commitments in a source whose ranges use the repair window.
    fn source(
        &self,
        tip: Height,
        commitments: Arc<[V::Commitment]>,
        below: Below<V>,
    ) -> Blocks<V::ApplicationBlock> {
        Blocks {
            tip,
            source: Arc::new(SelectedSource {
                parent_height: tip,
                commitments,
                below,
                marshal: self.clone(),
            }),
            window: self.max_repair.get(),
        }
    }
}

/// Consensus-selected commitments and the mailbox that serves their bodies.
struct SelectedSource<S: Scheme, V: Variant> {
    /// Height of the branch's tip.
    parent_height: Height,
    /// Commitments consensus selected, ending at `parent_height`.
    commitments: Arc<[V::Commitment]>,
    /// How heights below `commitments` are read.
    below: Below<V>,
    /// Serves block bodies and finalized storage.
    marshal: Mailbox<S, V>,
}

/// How a selected source reads the heights below its commitments.
enum Below<V: Variant> {
    /// They are canonical and come from finalized storage.
    Canonical,
    /// Their commitments are discovered by following parent links.
    Walked(Arc<Mutex<Walk<V>>>),
    /// No commitment identifies any height.
    Unknown,
}

/// Discovery of the commitments below a suffix, shared by every user of its source.
struct Walk<V: Variant> {
    /// Height of the suffix's first commitment.
    start: Height,
    /// Commitments from `start` downward: the suffix's first, then each discovered parent.
    known: Vec<V::Commitment>,
    /// The lowest bodies the walk read, until a range takes them.
    bodies: BTreeMap<Height, V::Block>,
    /// Why the walk stopped at its lowest known commitment, once it has.
    end: Option<End>,
    /// The step in flight, owned by the callers awaiting it.
    step: Option<WeakShared<BoxFuture<'static, ()>>>,
}

/// Why a walk takes no further step.
#[derive(Clone, Copy)]
enum End {
    /// Its lowest known block is finalized, so every lower height is canonical.
    Junction,
    /// Lower heights cannot be read.
    Failed(Error),
}

impl<V: Variant> Walk<V> {
    /// Returns a walk that knows only `commitment`, the suffix's first commitment at `start`.
    fn new(start: Height, commitment: V::Commitment) -> Self {
        Self {
            start,
            known: vec![commitment],
            bodies: BTreeMap::new(),
            end: None,
            step: None,
        }
    }

    /// Returns the known commitment at `height`.
    fn commitment(&self, height: Height) -> Option<V::Commitment> {
        let depth = usize::try_from(self.start.get().checked_sub(height.get())?).ok()?;
        self.known.get(depth).copied()
    }

    /// Returns whether the walk has taken a step or has one in flight.
    fn started(&self) -> bool {
        let stepping = self.step.as_ref().and_then(WeakShared::upgrade).is_some();
        stepping || self.known.len() > 1 || self.end.is_some()
    }

    /// Returns the lowest known height and its commitment.
    fn lowest(&self) -> (Height, V::Commitment) {
        let depth = self.known.len() - 1;
        (
            Height::new(self.start.get() - depth as u64),
            self.known[depth],
        )
    }

    /// Takes one step from the lowest known commitment. The outcome is recorded before the
    /// step completes, so progress never depends on which caller observes it.
    async fn step<S: Scheme>(walk: Arc<Mutex<Self>>, marshal: Mailbox<S, V>) {
        // A block recorded as finalized at the lowest known height ends the walk, as a junction
        // when it matches and a conflict otherwise. Without one, the step acquires the body to
        // learn its parent.
        let (height, commitment) = walk.lock().lowest();
        let outcome = match marshal.get_info(height).await {
            Some((_, digest)) if digest == V::commitment_to_inner(commitment) => Err(End::Junction),
            Some(_) => Err(End::Failed(Error::Unavailable)),
            None => match marshal.acquire(commitment).await {
                Ok(block) if block.height() == height => Ok(block),
                Ok(_) => Err(End::Failed(Error::InvalidHeight)),
                Err(_) => Err(End::Failed(Error::Unavailable)),
            },
        };

        // Record the outcome and clear the finished step.
        let mut walk = walk.lock();
        walk.step = None;
        match outcome {
            Ok(block) => {
                // The next commitment is the parent this body names. Consensus may have
                // selected another parent, because a Standard block can name one parent in
                // its header and another in the context it embeds. Such a block fails its own
                // certification at every honest validator, and certification of its
                // descendants waits on it. A walk through it therefore wastes work without
                // producing a verdict that can finalize.
                walk.known.push(V::parent_commitment(&block));

                // Keep the body for a range to take, retaining at most a window of the lowest
                // bodies.
                walk.bodies.insert(height, block);
                if walk.bodies.len() > marshal.max_repair.get() {
                    walk.bodies.pop_last();
                }
            }
            Err(end) => walk.end = Some(end),
        }
    }
}

impl<S: Scheme, V: Variant> SelectedSource<S, V> {
    /// Returns the commitment selected at `height`, or `None` when the height is canonical
    /// finalized history, walking parent links until the height is reached.
    async fn discover(&self, height: Height) -> Result<Option<V::Commitment>, Error> {
        // Supplied commitments answer directly. Below them, canonical history needs no
        // commitment, and a branch with no usable commitments is unavailable.
        if let Some(commitment) = suffix_at(self.parent_height, &self.commitments, height) {
            return Ok(Some(commitment));
        }
        let walk = match &self.below {
            Below::Canonical => return Ok(None),
            Below::Walked(walk) => walk,
            Below::Unknown => return Err(Error::Unavailable),
        };

        loop {
            // Every caller awaits the same step and then checks its own height, so a caller
            // finishes as soon as its height is known, whatever deeper callers wait for.
            let step = {
                let mut state = walk.lock();
                if let Some(commitment) = state.commitment(height) {
                    return Ok(Some(commitment));
                }
                match state.end {
                    Some(End::Junction) => return Ok(None),
                    Some(End::Failed(error)) => return Err(error),
                    None => {}
                }
                let live = state.step.as_ref().and_then(WeakShared::upgrade);
                live.unwrap_or_else(|| {
                    let step = Walk::step(walk.clone(), self.marshal.clone())
                        .boxed()
                        .shared();
                    state.step = step.downgrade();
                    step
                })
            };
            step.await;
        }
    }

    /// Returns whether the walk reads the body at `height`: every body below the commitments,
    /// and the body of the lowest commitment once the walk has started.
    fn walk_reads(&self, height: Height) -> bool {
        let Below::Walked(walk) = &self.below else {
            return false;
        };
        let walk = walk.lock();
        height < walk.start || (height == walk.start && walk.started())
    }

    /// Takes the body a walk retained for `height`, if any.
    fn take(&self, height: Height) -> Option<V::Block> {
        let Below::Walked(walk) = &self.below else {
            return None;
        };
        walk.lock().bodies.remove(&height)
    }
}

impl<S: Scheme, V: Variant> Source<V::ApplicationBlock> for SelectedSource<S, V> {
    fn digest(&self, height: Height) -> Option<<V::ApplicationBlock as Digestible>::Digest> {
        suffix_at(self.parent_height, &self.commitments, height)
            .or_else(|| match &self.below {
                Below::Walked(walk) => walk.lock().commitment(height),
                Below::Canonical | Below::Unknown => None,
            })
            .map(V::commitment_to_inner)
    }

    fn fetch(
        self: Arc<Self>,
        height: Height,
    ) -> BoxFuture<'static, Result<Digested<V::ApplicationBlock>, Error>> {
        Box::pin(async move {
            // A selected commitment identifies the body, and a canonical height comes from
            // finalized storage.
            let block = match self.discover(height).await? {
                Some(commitment) => {
                    // Where the walk reads this body to learn the commitment under it, waiting
                    // for that step leaves the body with one acquirer. The walk holds no body
                    // that it evicted, that another reader took, or at which it ended, and this
                    // read then acquires the body itself.
                    if self.walk_reads(height)
                        && let Some(below) = height.previous()
                    {
                        let _ = self.discover(below).await;
                    }
                    match self.take(height) {
                        Some(block) => Ok(block),
                        None => self.marshal.acquire(commitment).await,
                    }
                }
                None => self.marshal.finalized(height).await,
            }
            .map_err(|_| Error::Unavailable)?;

            // Metadata may have become resident while the body was acquired.
            check_block(self.as_ref(), height, V::into_shared(block))
        })
    }

    fn resolve(
        self: Arc<Self>,
        height: Height,
    ) -> BoxFuture<'static, Result<Option<<V::ApplicationBlock as Digestible>::Digest>, Error>>
    {
        Box::pin(async move {
            let commitment = self.discover(height).await?;
            Ok(commitment.map(V::commitment_to_inner))
        })
    }

    fn prefetch(&self, heights: RangeInclusive<Height>) -> Option<oneshot::Receiver<()>> {
        // Demand covers only the requested heights the supplied commitments select, as indices
        // into them.
        let first = suffix_start(self.parent_height, self.commitments.len())?;
        let start = heights.start().get().max(first);
        let end = heights.end().get().min(self.parent_height.get());
        let range = if start > end || self.commitments.is_empty() {
            0..0
        } else {
            let start = usize::try_from(start - first).ok()?;
            let end = usize::try_from(end - first).ok()?.checked_add(1)?;
            start..end
        };
        Some(self.marshal.prefetch(self.commitments.clone(), range))
    }
}

impl<B: Block> Blocks<B> {
    /// Creates a source from resident commitment metadata and an acquisition service.
    ///
    /// `digest` returns the digest selected at a height, when resident. `fetch` acquires the
    /// selected block, including canonical finalized history below the resident suffix. It must
    /// remain pending while a block may still arrive, and return `None` only when acquisition
    /// can no longer complete. The closures must share their metadata and must not retain block
    /// bodies.
    ///
    /// `digest` is consulted again when a fetched block arrives, so metadata that becomes
    /// resident during the request is still enforced. [`resolve_digest`](Self::resolve_digest)
    /// returns what `digest` returns and fetches nothing, so its `None` says only that `digest`
    /// has none for the height.
    ///
    /// Each range holds at most `window` pending or buffered body acquisitions.
    #[cfg(any(test, feature = "mocks"))]
    pub fn new<D, F, Fut>(tip: Height, window: NonZeroUsize, digest: D, fetch: F) -> Self
    where
        D: Fn(Height) -> Option<B::Digest> + Send + Sync + 'static,
        F: Fn(Height) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<Digested<B>>> + Send + 'static,
    {
        Self {
            tip,
            source: Arc::new(CallbackSource { digest, fetch }),
            window: window.get(),
        }
    }

    /// Returns the height of the highest block on this branch.
    pub const fn tip(&self) -> Height {
        self.tip
    }

    /// Returns a view of this branch ending at `tip`, sharing metadata and acquisition.
    ///
    /// # Panics
    ///
    /// Panics if `tip` is above this source's tip.
    pub fn ending_at(&self, tip: Height) -> Self {
        assert!(tip <= self.tip, "tip must not exceed the branch's tip");
        Self {
            tip,
            source: self.source.clone(),
            window: self.window,
        }
    }

    /// Returns the selected digest at `height` when its commitment is resident: supplied with
    /// the source or already discovered below it.
    ///
    /// Canonical finalized history and heights not yet discovered return `None`. This lookup
    /// starts no request.
    pub fn digest(&self, height: Height) -> Option<B::Digest> {
        if height > self.tip {
            return None;
        }
        self.source.digest(height)
    }

    /// Returns the selected digest at `height`, discovering it if it is not resident.
    ///
    /// Heights above [`Self::tip`] return `None`. Resident digests return without a request.
    ///
    /// Canonical finalized history returns `None`: every height of
    /// [`Mailbox::finalized_blocks`], and for [`Mailbox::blocks_with_parent`] the heights below
    /// an anchored history or below the finalized block its walk reached. Below a history
    /// suffix, the lookup acquires the bodies from the lowest known commitment down to the one
    /// above `height` and follows their parent links. The digests it discovers stay resident.
    ///
    /// It returns [`Error::Unavailable`] if the branch conflicts with finalized history, its
    /// history did not end at the bound parent or did not fit below it, or marshal shuts down,
    /// and [`Error::InvalidHeight`] if a walked body is not at its commitment's height.
    ///
    /// Dropping this lookup leaves the commitments discovered so far with the source, where
    /// other clones and later lookups continue from them.
    pub async fn resolve_digest(&self, height: Height) -> Result<Option<B::Digest>, Error> {
        if height > self.tip {
            return Ok(None);
        }
        self.source.clone().resolve(height).await
    }

    /// Returns a stream that yields the blocks of an inclusive range in increasing height order.
    ///
    /// Acquisition starts when the stream is polled. Consuming a block releases the stream's
    /// ownership of it and permits the next request. An empty range performs no work. A range
    /// extending above [`Self::tip`] yields [`Error::InvalidHeight`]. Any error terminates the
    /// range and cancels its remaining requests.
    ///
    /// Blocks are checked against resident commitments and preceding blocks. Consumers must also
    /// check linkage to their application state when the preceding commitment is not resident.
    pub fn range(&self, heights: RangeInclusive<Height>) -> BlockRange<B> {
        let start = *heights.start();
        let end = *heights.end();
        BlockRange {
            blocks: self.clone(),
            next: (start <= end).then_some(start),
            end,
            previous: None,
            pending: FuturesOrdered::new(),
            lease: Lease::Idle,
        }
    }
}

/// A bounded stream of selected blocks in increasing height order.
pub struct BlockRange<B: Block> {
    /// The branch this range reads.
    blocks: Blocks<B>,
    /// The next height to request, or `None` once every height is requested or the range failed.
    next: Option<Height>,
    /// The last height of the range.
    end: Height,
    /// Digest of the last yielded block. The next block must name it as its parent.
    previous: Option<B::Digest>,
    /// Acquisitions in flight or completed but not yet yielded, in height order.
    pending: FuturesOrdered<BoxFuture<'static, Result<Digested<B>, Error>>>,
    /// Forward demand registered for the remaining heights.
    lease: Lease,
}

/// Forward demand held by a range. Dropping an active lease cancels it.
enum Lease {
    /// The range has not registered demand.
    Idle,
    /// Demand is registered with the source.
    Active { _lease: oneshot::Receiver<()> },
    /// The range finished or failed, or its source serves no demand.
    Released,
}

impl<B: Block> Unpin for BlockRange<B> {}

impl<B: Block> Stream for BlockRange<B> {
    type Item = Result<Digested<B>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // A range above the tip fails once and then ends.
        if this.next.is_some() && this.end > this.blocks.tip {
            this.next = None;
            return Poll::Ready(Some(Err(Error::InvalidHeight)));
        }

        // The first poll registers forward demand for the remaining heights.
        if matches!(this.lease, Lease::Idle)
            && let Some(height) = this.next
        {
            this.lease = this
                .blocks
                .source
                .prefetch(height..=this.end)
                .map_or(Lease::Released, |lease| Lease::Active { _lease: lease });
        }

        // Keep up to a window of acquisitions pending, in height order.
        while this.pending.len() < this.blocks.window {
            let Some(height) = this.next else {
                break;
            };
            this.pending
                .push_back(this.blocks.source.clone().fetch(height));
            this.next = (height < this.end).then(|| height.next());
        }

        // Yield the next block. Its parent must be the preceding digest when that digest is
        // known.
        let Some(result) = ready!(Pin::new(&mut this.pending).poll_next(cx)) else {
            return Poll::Ready(None);
        };
        let result = result.and_then(|block| {
            // The preceding digest may have become resident while this block was acquired.
            let previous = this.previous.or_else(|| {
                block
                    .height()
                    .previous()
                    .and_then(|height| this.blocks.digest(height))
            });
            if previous.is_some_and(|digest| block.parent() != digest) {
                return Err(Error::InvalidParent);
            }
            this.previous = Some(block.digest());
            Ok(block)
        });

        // An error ends the range and cancels its outstanding acquisitions, and a finished
        // range releases its demand.
        if result.is_err() {
            this.next = None;
            this.pending.clear();
        }
        if this.next.is_none() && this.pending.is_empty() {
            this.lease = Lease::Released;
        }
        Poll::Ready(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::{
        Identifier,
        core::mailbox::Message,
        mocks::{block::EmptyBlock, harness},
        standard::Standard,
    };
    use commonware_actor::mailbox;
    use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, channel::oneshot, sync::Mutex};
    use futures::{FutureExt, StreamExt};
    use std::{collections::BTreeMap, ops::Range};

    type TestBlock = EmptyBlock<Sha256>;
    type TestMessage = Message<harness::S, Standard<TestBlock>>;
    type TestMailbox = Mailbox<harness::S, Standard<TestBlock>>;
    type Requests = Arc<Mutex<BTreeMap<Height, oneshot::Sender<Digested<TestBlock>>>>>;

    /// Wraps `block` with its precomputed digest.
    fn digested(block: impl Into<Arc<TestBlock>>) -> Digested<TestBlock> {
        let block = block.into();
        let digest = block.digest();
        Digested::precomputed(block, digest)
    }

    /// Returns `count` linked blocks starting at height 0.
    fn chain(count: u64) -> Vec<TestBlock> {
        let mut parent = Sha256::fill(0);
        (0..count)
            .map(|height| {
                let block = TestBlock::new(parent, Height::new(height), height);
                parent = block.digest();
                block
            })
            .collect()
    }

    /// Returns the digests of `blocks` in order.
    fn digests(blocks: &[TestBlock]) -> Arc<[Sha256Digest]> {
        blocks.iter().map(Digestible::digest).collect()
    }

    /// Returns a source whose fetches stay pending until the test answers them through
    /// `requests`.
    fn pending_source<D>(
        tip: Height,
        window: NonZeroUsize,
        requests: Requests,
        digest: D,
    ) -> Blocks<TestBlock>
    where
        D: Fn(Height) -> Option<<TestBlock as Digestible>::Digest> + Send + Sync + 'static,
    {
        Blocks::new(tip, window, digest, move |height| {
            let (sender, receiver) = oneshot::channel();
            assert!(requests.lock().insert(height, sender).is_none());
            async move { receiver.await.ok() }
        })
    }

    /// Returns a marshal mailbox whose ranges and walks use `window`, and the receiver that a
    /// test answers in marshal's place.
    fn marshal(
        context: deterministic::Context,
        window: usize,
    ) -> (TestMailbox, mailbox::Receiver<TestMessage>) {
        let (sender, receiver) = mailbox::new::<TestMessage>(context, NZUsize!(64));
        let window = NonZeroUsize::new(window).unwrap();
        (Mailbox::new(sender, NZUsize!(1), window), receiver)
    }

    /// Marshal as a test scripts it. It holds blocks, records the requests it receives, and
    /// keeps open the requests it cannot answer.
    #[derive(Default)]
    struct Scripted {
        finalized: BTreeMap<Height, TestBlock>,
        bodies: BTreeMap<Sha256Digest, Arc<TestBlock>>,
        infos: Vec<Height>,
        acquired: Vec<Sha256Digest>,
        awaited: Vec<Height>,
        prefetched: Vec<Range<usize>>,
        open: Vec<oneshot::Sender<Digested<TestBlock>>>,
        leases: Vec<oneshot::Sender<()>>,
    }

    impl Scripted {
        /// Serves `blocks` to acquisitions by commitment.
        fn serve(&mut self, blocks: &[TestBlock]) {
            for block in blocks {
                self.bodies.insert(block.digest(), Arc::new(block.clone()));
            }
        }

        /// Stores `blocks` as finalized at their heights.
        fn finalize(&mut self, blocks: &[TestBlock]) {
            for block in blocks {
                self.finalized.insert(block.height, block.clone());
            }
        }

        /// Answers every queued request and returns how many there were.
        fn answer(&mut self, receiver: &mut mailbox::Receiver<TestMessage>) -> usize {
            let mut answered = 0;
            while let Some(Some(message)) = receiver.recv().now_or_never() {
                answered += 1;
                match message {
                    TestMessage::GetInfo {
                        identifier: Identifier::Height(height),
                        response,
                        ..
                    } => {
                        self.infos.push(height);
                        let stored = self.finalized.get(&height);
                        let _ = response.send(stored.map(|block| (height, block.digest())));
                    }
                    TestMessage::Acquire {
                        commitment,
                        response,
                        ..
                    } => {
                        self.acquired.push(commitment);
                        match self.bodies.get(&commitment) {
                            Some(block) => drop(response.send(digested(block.clone()))),
                            None => self.open.push(response),
                        }
                    }
                    TestMessage::AwaitFinalized {
                        height, response, ..
                    } => {
                        self.awaited.push(height);
                        match self.finalized.get(&height) {
                            Some(block) => drop(response.send(digested(block.clone()))),
                            None => self.open.push(response),
                        }
                    }
                    TestMessage::Prefetch { range, lease, .. } => {
                        self.prefetched.push(range);
                        self.leases.push(lease);
                    }
                    _ => panic!("test must script every marshal request"),
                }
            }
            answered
        }

        /// Polls `future` to completion, answering the requests it sends.
        fn drive<T>(
            &mut self,
            receiver: &mut mailbox::Receiver<TestMessage>,
            future: impl Future<Output = T>,
        ) -> T {
            let mut future = Box::pin(future);
            loop {
                if let Some(output) = future.as_mut().now_or_never() {
                    return output;
                }
                assert!(self.answer(receiver) > 0, "the future must send a request");
            }
        }

        /// Reads `expected` from `range` in order, then its end.
        fn read(
            &mut self,
            receiver: &mut mailbox::Receiver<TestMessage>,
            range: &mut BlockRange<TestBlock>,
            expected: &[TestBlock],
        ) {
            for block in expected {
                let read = self.drive(receiver, range.next()).unwrap().unwrap();
                assert_eq!(read.digest(), block.digest());
            }
            assert!(self.drive(receiver, range.next()).is_none());
        }

        /// Returns the heights of served bodies that a walk or a range still holds.
        fn held(&self) -> Vec<u64> {
            let mut held: Vec<_> = self
                .bodies
                .values()
                .filter(|block| Arc::strong_count(block) > 1)
                .map(|block| block.height.get())
                .collect();
            held.sort_unstable();
            held
        }

        /// Returns how many times `block` was acquired by its commitment.
        fn acquisitions(&self, block: &TestBlock) -> usize {
            let digest = block.digest();
            self.acquired.iter().filter(|c| **c == digest).count()
        }
    }

    /// A range sends no request before its first poll and keeps at most its window of acquisitions
    /// pending or buffered. A consumed body is held only by its consumer, and dropping the range
    /// releases buffered bodies and cancels open requests.
    #[test]
    fn range_fetches_window_and_releases_consumed() {
        deterministic::Runner::default().start(|_| async move {
            // Creating a range starts no request, and its first poll opens a window of three.
            let blocks = chain(12);
            let requests = Requests::default();
            let digests: Arc<[_]> = blocks.iter().map(Digestible::digest).collect();
            let source = pending_source(
                Height::new(11),
                NZUsize!(3),
                requests.clone(),
                move |height| digests.get(height.get() as usize).copied(),
            );
            let source_clone = source.clone();
            let mut range = source.range(Height::zero()..=Height::new(11));
            assert!(requests.lock().is_empty());
            assert!(range.next().now_or_never().is_none());
            assert_eq!(requests.lock().len(), 3);

            // Bodies that arrive ahead of height 0 stay buffered and keep their window slots.
            let mut retained = Vec::new();
            for height in [2, 1] {
                let block = Arc::new(blocks[height].clone());
                retained.push(Arc::downgrade(&block));
                requests
                    .lock()
                    .remove(&Height::new(height as u64))
                    .unwrap()
                    .send(digested(block))
                    .unwrap();
            }
            assert!(range.next().now_or_never().is_none());
            assert_eq!(requests.lock().len(), 1);
            assert!(retained.iter().all(|block| block.upgrade().is_some()));

            // The range yields height 0 once it arrives, and dropping it releases the body.
            let first = Arc::new(blocks[0].clone());
            let first_weak = Arc::downgrade(&first);
            requests
                .lock()
                .remove(&Height::zero())
                .unwrap()
                .send(digested(first))
                .unwrap();
            let first = range.next().await.unwrap().unwrap();
            assert_eq!(first.height(), Height::zero());
            assert!(requests.lock().is_empty());
            drop(first);
            assert!(first_weak.upgrade().is_none());

            // Each consumed block frees a slot for the next request.
            let second = range.next().await.unwrap().unwrap();
            assert_eq!(second.height(), Height::new(1));
            assert_eq!(requests.lock().len(), 1);
            drop(second);
            assert!(retained[1].upgrade().is_none());

            // Dropping the range releases buffered bodies and cancels open requests, and clones
            // keep the metadata.
            drop(range);
            assert!(retained.iter().all(|block| block.upgrade().is_none()));
            assert!(requests.lock().values().all(oneshot::Sender::is_closed));
            assert_eq!(
                source_clone.digest(Height::new(11)),
                Some(blocks[11].digest())
            );
        });
    }

    /// A range's first poll registers demand only for its heights that the history supplies, and
    /// dropping the range closes that lease.
    #[test]
    fn range_scopes_prefetch_to_its_lifetime() {
        deterministic::Runner::default().start(|context| async move {
            // A source over an anchored history of heights 4 through 9.
            type TestMessage = Message<harness::S, Standard<TestBlock>>;
            let (sender, mut receiver) =
                commonware_actor::mailbox::new::<TestMessage>(context, NZUsize!(16));
            let marshal = Mailbox::new(sender, NZUsize!(1), NZUsize!(8));
            let blocks = chain(10);
            let commitments: Arc<[_]> = blocks[4..].iter().map(Digestible::digest).collect();
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::anchored(commitments.clone()),
            );
            let source_clone = source.clone();

            // The first poll registers demand for heights 4 through 7 of the range.
            let mut range = source.range(Height::new(2)..=Height::new(7));
            assert!(receiver.recv().now_or_never().is_none());
            assert!(range.next().now_or_never().is_none());
            let TestMessage::Prefetch {
                commitments: observed,
                range: selected,
                lease,
                ..
            } = receiver.recv().await.unwrap()
            else {
                panic!("range demand must precede body acquisition");
            };
            assert!(Arc::ptr_eq(&commitments, &observed));
            assert_eq!(selected, 0..4);
            assert!(!lease.is_closed());

            // Dropping the range releases the demand, and clones keep the metadata.
            drop(range);
            assert!(lease.is_closed());
            assert_eq!(
                source_clone.digest(Height::new(7)),
                Some(blocks[7].digest())
            );
        });
    }

    /// Reading heights a suffix supplies, including its lowest commitment, sends only demand and
    /// acquisitions and never starts the walk. Bodies that arrive out of order are yielded in
    /// height order.
    #[test]
    fn resident_range_reads_without_walking() {
        deterministic::Runner::default().start(|context| async move {
            // A suffix of heights 7 through 9, and a helper that collects marshal requests.
            let (marshal, mut receiver) = marshal(context, 8);
            let blocks = chain(10);
            let resident = digests(&blocks[7..]);
            let drain = |receiver: &mut mailbox::Receiver<TestMessage>| {
                let mut messages = Vec::new();
                while let Some(Some(message)) = receiver.recv().now_or_never() {
                    messages.push(message);
                }
                messages
            };

            // Building the source and reading supplied digests sends no request.
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(resident),
            );
            assert_eq!(source.digest(Height::new(8)), Some(blocks[8].digest()));
            assert_eq!(source.digest(Height::new(6)), None);
            assert!(drain(&mut receiver).is_empty());

            // Polling a range over heights 8 and 9 registers their demand and acquires each body.
            let mut range = source.range(Height::new(8)..=Height::new(9));
            assert!(range.next().now_or_never().is_none());
            let mut lease = None;
            let mut responses = BTreeMap::new();
            for message in drain(&mut receiver) {
                match message {
                    TestMessage::Prefetch {
                        range: selected,
                        lease: held,
                        ..
                    } => {
                        assert_eq!(selected, 1..3);
                        lease = Some(held);
                    }
                    TestMessage::Acquire {
                        commitment,
                        fetch,
                        response,
                        ..
                    } => {
                        assert!(fetch);
                        responses.insert(commitment, response);
                    }
                    _ => panic!("a resident range must only prefetch and acquire"),
                }
            }
            let lease = lease.expect("resident range must register demand");
            assert_eq!(responses.len(), 2);

            // Out-of-order results are delivered in order.
            responses
                .remove(&blocks[9].digest())
                .unwrap()
                .send(digested(blocks[9].clone()))
                .unwrap();
            assert!(range.next().now_or_never().is_none());
            let tail = responses.remove(&blocks[8].digest()).unwrap();
            tail.send(digested(blocks[8].clone())).unwrap();
            assert_eq!(
                range.next().await.unwrap().unwrap().height(),
                Height::new(8)
            );
            assert!(!lease.is_closed());
            assert_eq!(
                range.next().await.unwrap().unwrap().height(),
                Height::new(9)
            );

            // Reading the lowest commitment's body does not start the walk either.
            let mut range = source.range(Height::new(7)..=Height::new(7));
            assert!(range.next().now_or_never().is_none());
            for message in drain(&mut receiver) {
                assert!(
                    matches!(
                        message,
                        TestMessage::Prefetch { .. } | TestMessage::Acquire { .. }
                    ),
                    "a resident range must only prefetch and acquire"
                );
            }
        });
    }

    /// With nothing finalized, a range below a suffix discovers each commitment by walking parent
    /// links. Every body is acquired once, demand covers only the supplied commitments, and no read
    /// waits on finalized storage.
    #[test]
    fn range_below_suffix_walks_parent_links() {
        deterministic::Runner::default().start(|context| async move {
            // A suffix of heights 7 through 9 over a served chain with nothing finalized.
            let (marshal, mut receiver) = marshal(context, 8);
            let blocks = chain(10);
            let mut scripted = Scripted::default();
            scripted.serve(&blocks);
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(digests(&blocks[7..])),
            );

            // Read heights 3 through 9, below and through the suffix.
            let mut range = source.range(Height::new(3)..=Height::new(9));
            scripted.read(&mut receiver, &mut range, &blocks[3..]);

            // Demand covers only the supplied commitments.
            assert_eq!(scripted.prefetched, vec![0..3]);

            // Each step sampled finalized storage at the lowest known height, and no read
            // waited on it.
            assert_eq!(scripted.infos, [7, 6, 5, 4, 3].map(Height::new));
            assert!(scripted.awaited.is_empty());

            // Every body was acquired once, by the walk from the lowest commitment down or by
            // the range above it. The range took each body the walk read.
            for block in &blocks[3..] {
                assert_eq!(scripted.acquisitions(block), 1);
            }
            assert!(scripted.held().is_empty());

            // The discovered commitments are resident, and the walk stopped one below the
            // range.
            for block in &blocks[2..7] {
                assert_eq!(source.digest(block.height), Some(block.digest()));
            }
            assert_eq!(source.digest(Height::new(1)), None);
        });
    }

    /// When a walk reads no more bodies than the window holds, a later range takes every body the
    /// walk retained and acquires none of them again.
    #[test]
    fn gap_within_window_is_acquired_once() {
        deterministic::Runner::default().start(|context| async move {
            // A suffix holding only the parent, with a window of four.
            let (marshal, mut receiver) = marshal(context, 4);
            let blocks = chain(10);
            let mut scripted = Scripted::default();
            scripted.serve(&blocks);
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(digests(&blocks[9..])),
            );

            // Discovering a digest reads the bodies above it, and the walk retains them.
            let digest = scripted.drive(&mut receiver, source.resolve_digest(Height::new(5)));
            assert_eq!(digest, Ok(Some(blocks[5].digest())));
            assert_eq!(scripted.held(), [6, 7, 8, 9]);

            // A range takes the retained bodies, so none is acquired twice.
            let mut range = source.range(Height::new(6)..=Height::new(9));
            scripted.read(&mut receiver, &mut range, &blocks[6..]);
            for block in &blocks[6..] {
                assert_eq!(scripted.acquisitions(block), 1);
            }
            assert_eq!(scripted.acquisitions(&blocks[5]), 0);
            assert!(scripted.held().is_empty());
        });
    }

    /// A walk deeper than its window never holds more than its window of bodies and ends holding
    /// the lowest ones. A later range takes those and acquires each evicted body a second time.
    #[test]
    fn gap_beyond_window_keeps_lowest_bodies() {
        deterministic::Runner::default().start(|context| async move {
            // A suffix holding only the parent, with a window of two.
            let (marshal, mut receiver) = marshal(context, 2);
            let blocks = chain(10);
            let mut scripted = Scripted::default();
            scripted.serve(&blocks);
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(digests(&blocks[9..])),
            );

            // However deep the walk goes, it holds at most its window of bodies.
            let mut discovery = Box::pin(source.resolve_digest(Height::new(3)));
            let digest = loop {
                if let Some(digest) = discovery.as_mut().now_or_never() {
                    break digest;
                }
                assert!(scripted.held().len() <= 2);
                assert!(scripted.answer(&mut receiver) > 0);
            };
            assert_eq!(digest, Ok(Some(blocks[3].digest())));
            assert_eq!(scripted.held(), [4, 5]);

            // The range takes the two lowest bodies and acquires the released ones again.
            let mut range = source.range(Height::new(4)..=Height::new(9));
            scripted.read(&mut receiver, &mut range, &blocks[4..]);
            for block in &blocks[4..6] {
                assert_eq!(scripted.acquisitions(block), 1);
            }
            for block in &blocks[6..] {
                assert_eq!(scripted.acquisitions(block), 2);
            }
            assert!(scripted.awaited.is_empty());
        });
    }

    /// A body delivered for a commitment the walk discovered must match that commitment, so a range
    /// rejects another block at the same height with `InvalidDigest`.
    #[test]
    fn discovered_commitment_binds_its_body() {
        deterministic::Runner::default().start(|context| async move {
            // Discover the commitment at height 7 below a suffix holding only the parent.
            let (marshal, mut receiver) = marshal(context, 1);
            let blocks = chain(10);
            let mut scripted = Scripted::default();
            scripted.serve(&blocks);
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(digests(&blocks[9..])),
            );
            let digest = scripted.drive(&mut receiver, source.resolve_digest(Height::new(7)));
            assert_eq!(digest, Ok(Some(blocks[7].digest())));

            // The body delivered for the discovered commitment is another block.
            let impostor = TestBlock::new(blocks[6].digest(), Height::new(7), 99);
            scripted
                .bodies
                .insert(blocks[7].digest(), Arc::new(impostor));
            let mut range = source.range(Height::new(7)..=Height::new(8));
            let read = scripted.drive(&mut receiver, range.next());
            assert!(matches!(read, Some(Err(Error::InvalidDigest))));
        });
    }

    /// A walk that reaches a finalized block matching its commitment samples no lower height.
    /// Heights below that block come from finalized storage, and the block itself is acquired by
    /// its commitment.
    #[test]
    fn walk_ends_at_matching_finalized_block() {
        deterministic::Runner::default().start(|context| async move {
            // Heights 0 through 6 are finalized below a suffix of heights 8 and 9.
            let (marshal, mut receiver) = marshal(context, 8);
            let blocks = chain(10);
            let mut scripted = Scripted::default();
            scripted.serve(&blocks);
            scripted.finalize(&blocks[..=6]);
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(digests(&blocks[8..])),
            );

            // Read heights 3 through 9 across the finalized boundary.
            let mut range = source.range(Height::new(3)..=Height::new(9));
            scripted.read(&mut receiver, &mut range, &blocks[3..]);

            // The walk sampled finalized storage down to the first finalized height and nothing
            // below it.
            assert_eq!(scripted.infos, [8, 7, 6].map(Height::new));

            // Only heights below that finalized block came from finalized storage. The block
            // itself was acquired by its commitment.
            scripted.awaited.sort_unstable();
            assert_eq!(scripted.awaited, [3, 4, 5].map(Height::new));
            assert_eq!(scripted.acquisitions(&blocks[6]), 1);
            assert_eq!(scripted.acquisitions(&blocks[5]), 0);
            assert_eq!(source.digest(Height::new(6)), Some(blocks[6].digest()));
            assert_eq!(source.digest(Height::new(5)), None);
        });
    }

    /// A finalized block that conflicts with a walked commitment fails a range reading through it
    /// and makes lower heights unavailable. The commitments discovered down to the conflict stay
    /// readable by exact commitment.
    #[test]
    fn walk_fails_at_conflicting_finalized_block() {
        deterministic::Runner::default().start(|context| async move {
            // Marshal serves every body of a ten-block chain.
            let (marshal, mut receiver) = marshal(context, 8);
            let blocks = chain(10);
            let mut scripted = Scripted::default();
            scripted.serve(&blocks);

            // Finalized storage holds another block at a height the walk reaches.
            let canonical = TestBlock::new(blocks[5].digest(), Height::new(6), 99);
            scripted.finalize(&[canonical]);
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(digests(&blocks[8..])),
            );

            // Reading through the conflict fails and ends the range, and lower digests are
            // unavailable.
            let mut range = source.range(Height::new(5)..=Height::new(9));
            let read = scripted.drive(&mut receiver, range.next());
            assert!(matches!(read, Some(Err(Error::Unavailable))));
            assert!(scripted.drive(&mut receiver, range.next()).is_none());
            let below = scripted.drive(&mut receiver, source.resolve_digest(Height::new(5)));
            assert_eq!(below, Err(Error::Unavailable));

            // The commitments down to the conflicting height stay readable by exact commitment.
            assert_eq!(source.digest(Height::new(6)), Some(blocks[6].digest()));
            let mut range = source.range(Height::new(6)..=Height::new(9));
            scripted.read(&mut receiver, &mut range, &blocks[6..]);
            assert!(scripted.awaited.is_empty());
        });
    }

    /// A walk first samples finalized storage at the source's lowest commitment, whether the
    /// history supplied it or the request only bound it. A matching block makes lower heights
    /// canonical and a conflicting one makes them unavailable, while the held commitments stay
    /// readable.
    #[test]
    fn lowest_commitment_must_match_finalized_block() {
        deterministic::Runner::default().start(|context| async move {
            // Each case pairs a supplied or bound lowest commitment with a matching or
            // conflicting finalized block, on its own marshal.
            for (resident, matches) in [(true, true), (true, false), (false, true), (false, false)]
            {
                let (marshal, mut receiver) = marshal(
                    context.child(match (resident, matches) {
                        (true, true) => "resident_matching",
                        (true, false) => "resident_conflicting",
                        (false, true) => "bound_matching",
                        (false, false) => "bound_conflicting",
                    }),
                    1,
                );
                let blocks = chain(5);

                // The source holds two commitments, or only the parent its request bound.
                let (source, lowest) = if resident {
                    let history = History::suffix(digests(&blocks[2..4]));
                    (
                        marshal.blocks_with_parent(Height::new(3), blocks[3].digest(), history),
                        2,
                    )
                } else {
                    let history = History::suffix([]);
                    let parent = blocks[3].digest();
                    (
                        marshal.blocks_with_parent(Height::new(3), parent, history),
                        3,
                    )
                };

                // Heights below the lowest commitment are finalized, and the finalized block at
                // it matches or conflicts.
                let mut scripted = Scripted::default();
                scripted.serve(&blocks);
                scripted.finalize(&blocks[..lowest]);
                let canonical = if matches {
                    blocks[lowest].clone()
                } else {
                    TestBlock::new(blocks[lowest - 1].digest(), Height::new(lowest as u64), 99)
                };
                scripted.finalize(&[canonical]);

                // A view ending below every commitment reads through the source's lowest one.
                let view = source.ending_at(Height::new(1));
                let below = scripted.drive(&mut receiver, view.resolve_digest(Height::new(1)));
                assert_eq!(
                    below,
                    if matches {
                        Ok(None)
                    } else {
                        Err(Error::Unavailable)
                    }
                );
                assert_eq!(scripted.infos, [Height::new(lowest as u64)]);
                assert!(scripted.acquired.is_empty());

                // A range through the lowest commitment reads canonical history below a match
                // and fails at a conflict.
                let mut range = source.range(Height::new(1)..=Height::new(lowest as u64));
                if matches {
                    // Heights below the matching block come from finalized storage, and the
                    // block itself from its commitment.
                    scripted.read(&mut receiver, &mut range, &blocks[1..=lowest]);
                    scripted.awaited.sort_unstable();
                    let finalized: Vec<_> = (1..lowest as u64).map(Height::new).collect();
                    assert_eq!(scripted.awaited, finalized);
                    assert_eq!(scripted.acquired, [blocks[lowest].digest()]);
                } else {
                    let read = scripted.drive(&mut receiver, range.next());
                    assert!(matches!(read, Some(Err(Error::Unavailable))));
                    assert!(scripted.drive(&mut receiver, range.next()).is_none());
                    assert!(scripted.awaited.is_empty());
                }

                // A conflict below does not disturb exact acquisition of the commitments held.
                let parent = source.resolve_digest(Height::new(3)).now_or_never();
                assert_eq!(parent, Some(Ok(Some(blocks[3].digest()))));
                let mut range = source.range(Height::new(3)..=Height::new(3));
                scripted.read(&mut receiver, &mut range, &blocks[3..4]);
                assert_eq!(scripted.infos.len(), 1);
            }
        });
    }

    /// Finalized history reads every height from finalized storage. A bound parent with an empty
    /// history is read by its commitment, and lower heights come from finalized storage when the
    /// history is anchored or from its parent links when it is a suffix.
    #[test]
    fn empty_history_reads_canonical_or_follows_parent() {
        deterministic::Runner::default().start(|context| async move {
            // Every block of a four-block chain is finalized.
            let (marshal, mut receiver) = marshal(context, 8);
            let blocks = chain(4);
            let mut scripted = Scripted::default();
            scripted.finalize(&blocks);
            for tip in [0, 3] {
                // Canonical history reads every height through the tip from finalized storage.
                let canonical = marshal.finalized_blocks(Height::new(tip));
                assert_eq!(canonical.digest(Height::new(tip)), None);
                let digest = canonical.resolve_digest(Height::new(tip)).now_or_never();
                assert_eq!(digest, Some(Ok(None)));
                let mut range = canonical.range(Height::zero()..=Height::new(tip));
                scripted.read(&mut receiver, &mut range, &blocks[..=tip as usize]);
            }

            // Canonical reads only wait on finalized storage.
            scripted.awaited.sort_unstable();
            assert_eq!(scripted.awaited, [0, 0, 1, 2, 3].map(Height::new));
            assert!(scripted.infos.is_empty());
            assert!(scripted.acquired.is_empty());
            assert!(scripted.prefetched.is_empty());

            // A bound parent seeds an empty anchored history. The parent is read by its
            // commitment and everything below it from finalized storage.
            scripted.serve(&blocks);
            let parent = blocks[3].digest();
            let history = History::anchored([]);
            let anchored = marshal.blocks_with_parent(Height::new(3), parent, history);
            assert_eq!(anchored.digest(Height::new(3)), Some(parent));
            assert_eq!(anchored.digest(Height::new(2)), None);
            scripted.awaited.clear();
            let mut range = anchored.range(Height::new(2)..=Height::new(3));
            scripted.read(&mut receiver, &mut range, &blocks[2..]);
            assert_eq!(scripted.awaited, [Height::new(2)]);
            assert_eq!(scripted.acquired, [parent]);
            assert!(scripted.infos.is_empty());

            // A bound parent seeds an empty suffix, and lower heights follow the parent's links.
            let mut unfinalized = Scripted::default();
            unfinalized.serve(&blocks);
            let history = History::suffix([]);
            let suffix = marshal.blocks_with_parent(Height::new(3), parent, history);
            assert_eq!(suffix.digest(Height::new(3)), Some(parent));
            let mut range = suffix.range(Height::new(1)..=Height::new(3));
            unfinalized.read(&mut receiver, &mut range, &blocks[1..]);
            assert_eq!(unfinalized.infos, [3, 2, 1].map(Height::new));
            assert!(unfinalized.awaited.is_empty());
        });
    }

    /// `resolve_digest` answers resident heights, heights above the tip, and heights below an
    /// anchored history without a request. Below a suffix it discovers digests down to a finalized
    /// block, and a misplaced body or a stopped marshal ends discovery with an error.
    #[test]
    fn resolve_digest_distinguishes_heights() {
        deterministic::Runner::default().start(|context| async move {
            // Heights 7 through 9 are supplied as an anchored history and as a suffix.
            let (marshal, mut receiver) = marshal(context, 8);
            let blocks = chain(10);
            let resident = digests(&blocks[7..]);

            // Resident heights, heights above the tip, and heights below an anchored history
            // answer without a request.
            let anchored = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::anchored(resident.clone()),
            );
            let suffix = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(resident.clone()),
            );
            for source in [&anchored, &suffix] {
                let digest = source.resolve_digest(Height::new(8)).now_or_never();
                assert_eq!(digest, Some(Ok(Some(blocks[8].digest()))));
                let digest = source.resolve_digest(Height::new(10)).now_or_never();
                assert_eq!(digest, Some(Ok(None)));
            }
            let digest = anchored.resolve_digest(Height::new(6)).now_or_never();
            assert_eq!(digest, Some(Ok(None)));
            assert!(receiver.recv().now_or_never().is_none());

            // Below a suffix the digest is discovered and stays resident.
            let mut scripted = Scripted::default();
            scripted.serve(&blocks);
            scripted.finalize(&blocks[..=3]);
            let digest = scripted.drive(&mut receiver, suffix.resolve_digest(Height::new(5)));
            assert_eq!(digest, Ok(Some(blocks[5].digest())));
            assert_eq!(suffix.digest(Height::new(5)), Some(blocks[5].digest()));
            let above = suffix.ending_at(Height::new(4));
            let digest = above.resolve_digest(Height::new(5)).now_or_never();
            assert_eq!(digest, Some(Ok(None)));

            // Below the finalized block the walk reaches, history is canonical.
            let digest = scripted.drive(&mut receiver, suffix.resolve_digest(Height::new(1)));
            assert_eq!(digest, Ok(None));
            assert_eq!(suffix.digest(Height::new(3)), Some(blocks[3].digest()));
            assert_eq!(suffix.digest(Height::new(2)), None);
            assert!(scripted.awaited.is_empty());

            // A body at another height than its commitment selects ends the walk as invalid.
            let misplaced = TestBlock::new(blocks[3].digest(), Height::new(4), 77);
            scripted.serve(std::slice::from_ref(&misplaced));
            let history = History::suffix([misplaced.digest()]);
            let source = marshal.blocks_with_parent(Height::new(9), misplaced.digest(), history);
            let digest = scripted.drive(&mut receiver, source.resolve_digest(Height::new(8)));
            assert_eq!(digest, Err(Error::InvalidHeight));

            // Once marshal stops, undiscovered heights are unavailable.
            drop(receiver);
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(resident),
            );
            let digest = source.resolve_digest(Height::new(5)).now_or_never();
            assert_eq!(digest, Some(Err(Error::Unavailable)));
        });
    }

    /// A history that ends at another commitment or holds more commitments than the branch has
    /// heights leaves the tip without a digest and makes reads below it unavailable, anchored or
    /// suffix, without contacting marshal.
    #[test]
    fn bound_parent_rejects_malformed_history() {
        deterministic::Runner::default().start(|context| async move {
            // One history ends at another commitment, and the other holds more commitments than
            // the branch has heights.
            let (marshal, mut receiver) = marshal(context, 1);
            let blocks = chain(5);
            let commitments: [Arc<[_]>; 2] = [
                Arc::from([blocks[2].digest()]),
                Arc::from([blocks[3].digest(); 5]),
            ];

            // Both leave the tip without a digest and make reads below it unavailable, under
            // either anchoring and without contacting marshal.
            for commitments in commitments {
                for history in [
                    History::anchored(commitments.clone()),
                    History::suffix(commitments.clone()),
                ] {
                    let parent = blocks[3].digest();
                    let source = marshal.blocks_with_parent(Height::new(3), parent, history);
                    assert_eq!(source.digest(Height::new(3)), None);
                    assert_eq!(
                        source.resolve_digest(Height::new(1)).await,
                        Err(Error::Unavailable)
                    );
                    let mut range = source.range(Height::new(1)..=Height::new(1));
                    assert!(matches!(range.next().await, Some(Err(Error::Unavailable))));
                    assert!(range.next().await.is_none());
                    assert!(receiver.recv().now_or_never().is_none());
                }
            }
        });
    }

    /// Dropping the range that drives a walk cancels the pending step with the range's acquisitions
    /// and demand, even while an idle clone of the source remains. A later lookup starts the step
    /// again.
    #[test]
    fn walk_cancels_without_waiters() {
        deterministic::Runner::default().start(|context| async move {
            // A ten-block chain read with a window of four.
            let (marshal, mut receiver) = marshal(context, 4);
            let blocks = chain(10);

            // No body is served, so every acquisition stays open.
            let mut scripted = Scripted::default();
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(digests(&blocks[7..])),
            );
            let mut range = source.range(Height::new(5)..=Height::new(8));
            assert!(range.next().now_or_never().is_none());
            assert_eq!(scripted.answer(&mut receiver), 3);
            assert!(range.next().now_or_never().is_none());
            assert_eq!(scripted.answer(&mut receiver), 1);

            // The range acquires the body above the lowest commitment, and the walk's first
            // step the body at it.
            assert_eq!(scripted.prefetched, vec![0..2]);
            assert_eq!(scripted.infos, [Height::new(7)]);
            assert_eq!(scripted.acquisitions(&blocks[7]), 1);
            assert_eq!(scripted.acquisitions(&blocks[8]), 1);
            assert!(scripted.open.iter().all(|response| !response.is_closed()));

            // An idle handle keeps none of it alive.
            let idle = source.clone();
            drop(source);
            drop(range);
            assert!(scripted.open.iter().all(oneshot::Sender::is_closed));
            assert!(scripted.leases.iter().all(oneshot::Sender::is_closed));
            assert_eq!(scripted.answer(&mut receiver), 0);

            // A later reader starts the same step again.
            scripted.serve(&blocks);
            let digest = scripted.drive(&mut receiver, idle.resolve_digest(Height::new(6)));
            assert_eq!(digest, Ok(Some(blocks[6].digest())));
            assert_eq!(scripted.infos, [Height::new(7), Height::new(7)]);
        });
    }

    /// Concurrent lookups share one walk step, and each finishes once its own height is known. A
    /// pending step survives the lookup that started it while another lookup awaits it.
    #[test]
    fn walk_shares_pending_step() {
        deterministic::Runner::default().start(|context| async move {
            // A ten-block chain read with a window of four.
            let (marshal, mut receiver) = marshal(context, 4);
            let blocks = chain(10);

            // Only the first body is served.
            let mut scripted = Scripted::default();
            scripted.serve(&blocks[9..]);
            let source = marshal.blocks_with_parent(
                Height::new(9),
                blocks[9].digest(),
                History::suffix(digests(&blocks[9..])),
            );
            let clone = source.clone();

            // The deep waiter starts the walk, and the shallow waiter joins its step.
            let mut deep = Box::pin(source.resolve_digest(Height::new(3)));
            assert!(deep.as_mut().now_or_never().is_none());
            let mut shallow = Box::pin(clone.resolve_digest(Height::new(8)));
            assert!(shallow.as_mut().now_or_never().is_none());
            assert_eq!(scripted.answer(&mut receiver), 1);

            // The shallow waiter alone drives the step, and finishes at its own height.
            assert!(shallow.as_mut().now_or_never().is_none());
            assert_eq!(scripted.answer(&mut receiver), 1);
            let digest = shallow.as_mut().now_or_never();
            assert_eq!(digest, Some(Ok(Some(blocks[8].digest()))));
            assert_eq!(scripted.answer(&mut receiver), 0);

            // The deep waiter continues to a body that does not arrive.
            assert!(deep.as_mut().now_or_never().is_none());
            assert_eq!(scripted.answer(&mut receiver), 1);
            assert!(deep.as_mut().now_or_never().is_none());
            assert_eq!(scripted.answer(&mut receiver), 1);
            assert_eq!(scripted.infos, [9, 8].map(Height::new));
            assert_eq!(scripted.open.len(), 1);

            // Resident digests stay readable while the acquisition is pending.
            assert_eq!(clone.digest(Height::new(8)), Some(blocks[8].digest()));
            assert_eq!(clone.digest(Height::new(7)), None);

            // Another waiter joins the pending step, and the step survives its starter.
            let mut joined = Box::pin(clone.resolve_digest(Height::new(7)));
            assert!(joined.as_mut().now_or_never().is_none());
            drop(deep);
            assert_eq!(scripted.answer(&mut receiver), 0);
            let response = scripted.open.pop().unwrap();
            assert!(!response.is_closed());
            response.send(digested(blocks[8].clone())).unwrap();
            let digest = joined.as_mut().now_or_never();
            assert_eq!(digest, Some(Ok(Some(blocks[7].digest()))));
        });
    }

    /// A block finalized while a step's acquisition is pending does not redirect that acquisition.
    /// The next step samples finalized storage and ends the walk at a match or fails it at a
    /// conflict.
    #[test]
    fn walk_sees_finalization_at_next_step() {
        deterministic::Runner::default().start(|context| async move {
            // Each case uses its own marshal and a suffix holding only the parent.
            for matches in [true, false] {
                let name = if matches { "matching" } else { "conflicting" };
                let (marshal, mut receiver) = marshal(context.child(name), 4);
                let blocks = chain(10);
                let mut scripted = Scripted::default();
                let history = History::suffix(digests(&blocks[9..]));
                let source =
                    marshal.blocks_with_parent(Height::new(9), blocks[9].digest(), history);

                // The first step finds nothing finalized and waits for its body.
                let mut discovery = Box::pin(source.resolve_digest(Height::new(6)));
                assert!(discovery.as_mut().now_or_never().is_none());
                assert_eq!(scripted.answer(&mut receiver), 1);
                assert!(discovery.as_mut().now_or_never().is_none());
                assert_eq!(scripted.answer(&mut receiver), 1);

                // A block finalizes below. The pending acquisition is not redirected.
                let canonical = if matches {
                    blocks[8].clone()
                } else {
                    TestBlock::new(blocks[7].digest(), Height::new(8), 99)
                };
                scripted.finalize(&[canonical]);
                assert!(discovery.as_mut().now_or_never().is_none());
                assert_eq!(scripted.answer(&mut receiver), 0);
                let response = scripted.open.pop().unwrap();
                assert!(!response.is_closed());

                // Once the body arrives, the next step samples storage and ends the walk.
                response.send(digested(blocks[9].clone())).unwrap();
                let below = scripted.drive(&mut receiver, discovery);
                assert_eq!(
                    below,
                    if matches {
                        Ok(None)
                    } else {
                        Err(Error::Unavailable)
                    }
                );
                assert_eq!(scripted.infos, [9, 8].map(Height::new));
                assert_eq!(scripted.acquired, [blocks[9].digest()]);
                assert!(scripted.awaited.is_empty());
            }
        });
    }

    /// Any error a range yields, whether height, digest, parent, or availability, closes its
    /// demand, cancels its outstanding acquisitions, and releases its buffered bodies before the
    /// range drops.
    #[test]
    fn range_error_releases_prefetch_and_bodies() {
        deterministic::Runner::default().start(|context| async move {
            // Each error case uses its own marshal and fails the range at height 1.
            type TestMessage = Message<harness::S, Standard<TestBlock>>;
            for expected in [
                Error::InvalidHeight,
                Error::InvalidDigest,
                Error::InvalidParent,
                Error::Unavailable,
            ] {
                let (sender, mut receiver) = commonware_actor::mailbox::new::<TestMessage>(
                    context.child(match expected {
                        Error::InvalidHeight => "invalid_height",
                        Error::InvalidDigest => "invalid_digest",
                        Error::InvalidParent => "invalid_parent",
                        Error::Unavailable => "unavailable",
                    }),
                    NZUsize!(16),
                );
                let marshal = Mailbox::new(sender, NZUsize!(1), NZUsize!(8));
                let mut blocks = chain(6);
                let replacement = match expected {
                    Error::InvalidHeight => TestBlock::new(blocks[0].digest(), Height::new(7), 1),
                    Error::InvalidDigest => TestBlock::new(blocks[0].digest(), Height::new(1), 99),
                    Error::InvalidParent => {
                        // Match the detached body's digest so linkage is the only failed check.
                        blocks[1] = TestBlock::new(Sha256::fill(7), Height::new(1), 1);
                        blocks[1].clone()
                    }
                    Error::Unavailable => blocks[1].clone(),
                };

                // A range over an anchored history of the chain registers demand and acquires
                // every body.
                let commitments: Vec<_> = blocks.iter().map(Digestible::digest).collect();
                let source = marshal.blocks_with_parent(
                    Height::new(5),
                    blocks[5].digest(),
                    History::anchored(commitments),
                );
                let mut range = source.range(Height::new(1)..=Height::new(5));
                assert!(range.next().now_or_never().is_none());
                let TestMessage::Prefetch {
                    range: selected,
                    lease,
                    ..
                } = receiver.recv().await.unwrap()
                else {
                    panic!("range demand must precede body acquisition");
                };
                assert_eq!(selected, 1..6);
                let mut responses = BTreeMap::new();
                for _ in 1..=5 {
                    let TestMessage::Acquire {
                        commitment,
                        response,
                        ..
                    } = receiver.recv().await.unwrap()
                    else {
                        panic!("the range must acquire every body");
                    };
                    responses.insert(commitment, response);
                }

                // Keep a completed body buffered behind the failing request.
                let buffered = Arc::new(blocks[5].clone());
                let retained = Arc::downgrade(&buffered);
                responses
                    .remove(&blocks[5].digest())
                    .unwrap()
                    .send(digested(buffered))
                    .unwrap();
                assert!(range.next().now_or_never().is_none());
                assert!(retained.upgrade().is_some());
                assert!(!lease.is_closed());
                assert!(responses.values().all(|response| !response.is_closed()));

                // Height 1 fails when its acquisition closes or its replacement arrives.
                let response = responses.remove(&blocks[1].digest()).unwrap();
                if expected == Error::Unavailable {
                    drop(response);
                } else {
                    response.send(digested(replacement)).unwrap();
                }
                assert_eq!(range.next().await.unwrap().unwrap_err(), expected);

                // Terminal errors cancel demand while the range itself remains alive.
                assert!(lease.is_closed());
                assert_eq!(responses.len(), 3);
                assert!(responses.values().all(oneshot::Sender::is_closed));
                assert!(retained.upgrade().is_none());
                assert!(range.next().await.is_none());
                assert!(receiver.recv().now_or_never().is_none());
            }
        });
    }

    /// With no resident digests, each block after a range's first must name the block yielded
    /// before it as its parent. A mismatch fails with `InvalidParent` and cancels the remaining
    /// requests.
    #[test]
    fn range_checks_parent_against_yielded_block() {
        deterministic::Runner::default().start(|_| async move {
            // A source with no resident digests and a window of four.
            let blocks = chain(5);
            let requests = Requests::default();
            let source = pending_source(Height::new(4), NZUsize!(4), requests.clone(), |_| None);
            let mut range = source.range(Height::zero()..=Height::new(4));
            assert!(range.next().now_or_never().is_none());

            // Height 2 arrives first, naming a parent outside the chain.
            let detached = TestBlock::new(Sha256::fill(7), Height::new(2), 2);
            requests
                .lock()
                .remove(&Height::new(2))
                .unwrap()
                .send(digested(detached))
                .unwrap();
            assert!(range.next().now_or_never().is_none());

            // Heights 0 and 1 are yielded in order.
            for height in 0..2 {
                requests
                    .lock()
                    .remove(&Height::new(height))
                    .unwrap()
                    .send(digested(blocks[height as usize].clone()))
                    .unwrap();
                assert_eq!(
                    range.next().await.unwrap().unwrap().digest(),
                    blocks[height as usize].digest()
                );
            }

            // Height 2 fails linkage, ends the range, and cancels the remaining requests.
            assert_eq!(
                range.next().await.unwrap().unwrap_err(),
                Error::InvalidParent
            );
            assert_eq!(requests.lock().len(), 2);
            assert!(requests.lock().values().all(oneshot::Sender::is_closed));
            assert!(range.next().await.is_none());
        });
    }

    /// A digest that becomes resident while its body is acquired is enforced when the body arrives,
    /// so a mismatched body fails the range with `InvalidDigest`.
    #[test]
    fn range_rechecks_digest_metadata() {
        deterministic::Runner::default().start(|_| async move {
            // Resident digests start empty and the test adds them as it goes.
            let blocks = chain(3);
            let resident = Arc::new(Mutex::new(BTreeMap::new()));
            let metadata = resident.clone();
            let requests = Requests::default();
            let source = pending_source(
                Height::new(2),
                NZUsize!(3),
                requests.clone(),
                move |height| metadata.lock().get(&height).copied(),
            );
            let mut range = source.range(Height::zero()..=Height::new(2));

            // Height 0 is yielded with no resident digest.
            assert!(range.next().now_or_never().is_none());
            requests
                .lock()
                .remove(&Height::zero())
                .unwrap()
                .send(digested(blocks[0].clone()))
                .unwrap();
            assert_eq!(
                range.next().await.unwrap().unwrap().digest(),
                blocks[0].digest()
            );

            // Height 1's digest becomes resident before a mismatched body arrives. The mismatch
            // ends the range and cancels the last request.
            assert_eq!(source.digest(Height::new(1)), None);
            resident.lock().insert(Height::new(1), blocks[1].digest());
            let mismatch = TestBlock::new(blocks[0].digest(), Height::new(1), 99);
            requests
                .lock()
                .remove(&Height::new(1))
                .unwrap()
                .send(digested(mismatch))
                .unwrap();
            assert_eq!(
                range.next().await.unwrap().unwrap_err(),
                Error::InvalidDigest
            );
            assert_eq!(requests.lock().len(), 1);
            assert!(requests.lock().values().all(oneshot::Sender::is_closed));
            assert!(range.next().await.is_none());
        });
    }

    /// A parent digest that becomes resident while a block is acquired is checked against that
    /// block, though the range yielded no block before it.
    #[test]
    fn range_rechecks_parent_metadata() {
        deterministic::Runner::default().start(|_| async move {
            // The fetch makes both digests resident before delivering a block detached from
            // height 0.
            let blocks = chain(2);
            let detached = TestBlock::new(Sha256::fill(7), Height::new(1), 1);
            let commitments = [blocks[0].digest(), detached.digest()];
            let resident = Arc::new(Mutex::new(None::<[<TestBlock as Digestible>::Digest; 2]>));
            let metadata = resident.clone();
            let source = Blocks::new(
                Height::new(1),
                NZUsize!(1),
                move |height| {
                    metadata
                        .lock()
                        .as_ref()
                        .and_then(|digests| digests.get(height.get() as usize).copied())
                },
                move |_| {
                    let resident = resident.clone();
                    let block = detached.clone();
                    async move {
                        *resident.lock() = Some(commitments);
                        Some(digested(block))
                    }
                },
            );

            // No digest is resident at first, and the range then rejects the block's parent.
            assert_eq!(source.digest(Height::zero()), None);
            let mut range = source.range(Height::new(1)..=Height::new(1));
            assert_eq!(
                range.next().await.unwrap().unwrap_err(),
                Error::InvalidParent
            );
            assert!(range.next().await.is_none());
        });
    }

    /// An empty range ends without a request, a range at the maximum height reads one block without
    /// overflowing, and a range above the tip fails with `InvalidHeight` before any request.
    #[test]
    fn range_bounds_are_checked() {
        deterministic::Runner::default().start(|_| async move {
            // A source whose tip is the maximum height counts its requests.
            let requests = Arc::new(Mutex::new(0));
            let observed = requests.clone();
            let source = Blocks::new(
                Height::new(u64::MAX),
                NZUsize!(8),
                |_| None,
                move |height| {
                    *observed.lock() += 1;
                    async move { Some(digested(TestBlock::new(Sha256::fill(0), height, 0))) }
                },
            );

            // An empty range ends without a request.
            let mut empty = source.range(Height::new(2)..=Height::new(1));
            assert!(empty.next().await.is_none());
            assert_eq!(*requests.lock(), 0);

            // A range at the maximum height reads one block and ends without overflow.
            let mut last = source.range(Height::new(u64::MAX)..=Height::new(u64::MAX));
            assert_eq!(last.next().await.unwrap().unwrap().height().get(), u64::MAX);
            assert!(last.next().await.is_none());
            assert_eq!(*requests.lock(), 1);

            // A range above the tip fails before any request.
            let requests = Requests::default();
            let source = pending_source(Height::new(1), NZUsize!(8), requests.clone(), |_| None);
            let mut outside = source.range(Height::zero()..=Height::new(u64::MAX));
            assert_eq!(
                outside.next().await.unwrap().unwrap_err(),
                Error::InvalidHeight
            );
            assert!(outside.next().await.is_none());
            assert!(requests.lock().is_empty());
        });
    }
}
