//! Bounded forward access to a selected branch and its finalized prefix.

use super::core::{Mailbox, Variant};
use crate::{Block, Heightable, History, types::Height};
use commonware_cryptography::{Digested, Digestible, certificate::Scheme};
use commonware_utils::channel::oneshot;
use futures::{Stream, future::BoxFuture, stream::FuturesOrdered};
use std::{
    future::Future,
    num::NonZeroUsize,
    ops::RangeInclusive,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use thiserror::Error;

type Fetch<B> = dyn Fn(Height) -> BoxFuture<'static, Result<Digested<B>, Error>> + Send + Sync;
type DigestAt<B> =
    dyn Fn(Height) -> Option<<B as commonware_cryptography::Digestible>::Digest> + Send + Sync;
type Resolve = dyn Fn() -> BoxFuture<'static, bool> + Send + Sync;
type Demand = dyn Fn(RangeInclusive<Height>) -> BoxFuture<'static, Option<oneshot::Receiver<()>>>
    + Send
    + Sync;

/// A failure to acquire a block on the selected branch.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    /// The source closed before the requested block became available.
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

/// Access to blocks on one selected branch, ending at the proposal's parent.
///
/// Clones share commitment metadata and the acquisition service. They retain no
/// block bodies and do not start requests. Each [`range`](Self::range) owns its
/// cursor and bounds both pending acquisitions and completed bodies awaiting
/// consumption. Dropping a range cancels its remaining demand.
pub struct Blocks<B: Block> {
    tip: Height,
    digest: Arc<DigestAt<B>>,
    fetch: Arc<Fetch<B>>,
    demand: Option<Arc<Demand>>,
    resolve: Option<Arc<Resolve>>,
    window: usize,
}

impl<B: Block> Clone for Blocks<B> {
    fn clone(&self) -> Self {
        Self {
            tip: self.tip,
            digest: self.digest.clone(),
            fetch: self.fetch.clone(),
            demand: self.demand.clone(),
            resolve: self.resolve.clone(),
            window: self.window,
        }
    }
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
    /// Provides forward access to a selected branch ending at `parent_height`.
    ///
    /// `history` supplies the consensus-selected commitment suffix in increasing height order.
    /// Consecutive re-proposals occupy one entry. Older heights are supplied by canonical
    /// finalized storage. Neither this call nor its clones await or poll `history`; the
    /// suffix is consulted by [`Blocks::digest`] when already resident. A polled range or
    /// [`Blocks::resolve_digest`] can resolve a missing prefix.
    ///
    /// A polled range keeps its remaining selected suffix prefetched in forward order, within
    /// the capacity shared by all ranges ([`Config::max_repair`](super::Config)). Each range's
    /// window of pending acquisitions and buffered bodies is additional to that capacity.
    pub fn blocks(
        &self,
        parent_height: Height,
        history: History<V::Commitment>,
    ) -> Blocks<V::ApplicationBlock> {
        let resident = history.clone();
        let fetching = history.clone();
        let marshal = self.clone();
        let mut blocks = Blocks::new(
            parent_height,
            self.max_repair,
            move |height| {
                let commitments = resident.peek()?;
                suffix_at(parent_height, commitments, height).map(V::commitment_to_inner)
            },
            move |height| {
                let history = fetching.clone();
                let marshal = marshal.clone();
                async move {
                    // Heights within the resident suffix need no full metadata.
                    let resident = history.peek().and_then(|commitments| {
                        suffix_start(parent_height, commitments.len())?;
                        suffix_at(parent_height, commitments, height)
                    });
                    let commitment = match resident {
                        Some(commitment) => Some(commitment),
                        None => {
                            let commitments = history.resolve().await?;
                            suffix_start(parent_height, commitments.len())?;
                            suffix_at(parent_height, &commitments, height)
                        }
                    };
                    let block = match commitment {
                        Some(commitment) => marshal.acquire(commitment).await.ok()?,
                        None => marshal.finalized(height).await.ok()?,
                    };
                    Some(V::into_shared(block))
                }
            },
        );
        let resolving = history.clone();
        blocks.resolve = Some(Arc::new(move || {
            let history = resolving.clone();
            Box::pin(async move { history.resolve().await.is_some() })
        }));
        let marshal = self.clone();
        blocks.demand = Some(Arc::new(move |heights| {
            let history = history.clone();
            let marshal = marshal.clone();
            Box::pin(async move {
                // A range entirely within the resident suffix needs no full metadata.
                let resident = history.peek().cloned().filter(|commitments| {
                    suffix_start(parent_height, commitments.len())
                        .is_some_and(|first| heights.start().get() >= first)
                });
                let commitments = match resident {
                    Some(commitments) => commitments,
                    None => history.resolve().await?,
                };
                let first = suffix_start(parent_height, commitments.len())?;
                let start = heights.start().get().max(first);
                let end = heights.end().get().min(parent_height.get());
                let range = if start > end || commitments.is_empty() {
                    0..0
                } else {
                    let start = usize::try_from(start - first).ok()?;
                    let end = usize::try_from(end - first).ok()?.checked_add(1)?;
                    start..end
                };
                Some(marshal.prefetch(commitments, range))
            })
        }));
        blocks
    }
}

impl<B: Block> Blocks<B> {
    /// Creates a source from resident commitment metadata and an acquisition service.
    ///
    /// `digest` returns the digest selected at a height, when resident. `fetch`
    /// acquires the selected block, including canonical finalized history below
    /// the resident suffix. It must remain pending while a block may still
    /// arrive, and return `None` only when acquisition can no longer complete.
    /// The closures must share their metadata and must not retain block bodies.
    /// `digest` is consulted again when a fetched block arrives, so metadata that
    /// becomes resident during the request is still enforced.
    ///
    /// Each range holds at most `window` pending or buffered body acquisitions.
    pub fn new<D, F, Fut>(tip: Height, window: NonZeroUsize, digest: D, fetch: F) -> Self
    where
        D: Fn(Height) -> Option<B::Digest> + Send + Sync + 'static,
        F: Fn(Height) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<Digested<B>>> + Send + 'static,
    {
        let digest: Arc<DigestAt<B>> = Arc::new(digest);
        let expected = digest.clone();
        let fetch = Arc::new(move |height| {
            let request = fetch(height);
            let expected = expected.clone();
            Box::pin(async move {
                let block = request.await.ok_or(Error::Unavailable)?;
                // Resident metadata may only become available while the request runs.
                let expected = expected(height);
                if block.height() != height {
                    return Err(Error::InvalidHeight);
                }
                if expected.is_some_and(|digest| digest != block.digest()) {
                    return Err(Error::InvalidDigest);
                }
                Ok(block)
            }) as BoxFuture<'static, Result<Digested<B>, Error>>
        });
        Self {
            tip,
            digest,
            fetch,
            demand: None,
            resolve: None,
            window: window.get(),
        }
    }

    /// Returns the height of the selected parent.
    pub const fn tip(&self) -> Height {
        self.tip
    }

    /// Returns the selected digest when its commitment is resident.
    ///
    /// Older finalized history may require storage access and returns `None`.
    /// This lookup does not acquire a block.
    pub fn digest(&self, height: Height) -> Option<B::Digest> {
        if height > self.tip {
            return None;
        }
        (self.digest)(height)
    }

    /// Returns the selected digest at `height`, resolving selected history if it is not resident.
    ///
    /// Returns `None` for heights above [`Self::tip`] and for older canonical finalized history,
    /// which is not part of the selected suffix. Resident digests return without polling
    /// history. Returns [`Error::Unavailable`] if history is permanently unavailable. This lookup
    /// does not acquire a block. Other users and retained `Blocks` clones can keep shared
    /// resolution alive after this lookup is dropped.
    pub async fn resolve_digest(&self, height: Height) -> Result<Option<B::Digest>, Error> {
        if let Some(digest) = self.digest(height) {
            return Ok(Some(digest));
        }
        if height > self.tip {
            return Ok(None);
        }
        if let Some(resolve) = &self.resolve
            && !resolve().await
        {
            return Err(Error::Unavailable);
        }
        Ok(self.digest(height))
    }

    /// Acquires an inclusive range in increasing height order.
    ///
    /// Acquisition starts when the stream is polled. Consuming a block releases
    /// the stream's ownership of it and permits the next request. An empty range
    /// performs no work. A range extending above [`Self::tip`] yields
    /// [`Error::InvalidHeight`]. Any error terminates the range and cancels its
    /// remaining requests.
    ///
    /// Blocks are checked against resident commitments and preceding blocks.
    /// Consumers must also check linkage to their application state when the
    /// preceding commitment is outside the resident suffix.
    pub fn range(&self, heights: RangeInclusive<Height>) -> BlockRange<B> {
        let start = *heights.start();
        let end = *heights.end();
        BlockRange {
            source: self.clone(),
            next: (start <= end).then_some(start),
            end,
            start,
            previous: None,
            pending: FuturesOrdered::new(),
            lease: Lease::Idle,
        }
    }
}

/// A bounded stream of selected blocks in increasing height order.
pub struct BlockRange<B: Block> {
    source: Blocks<B>,
    next: Option<Height>,
    start: Height,
    end: Height,
    previous: Option<B::Digest>,
    pending: FuturesOrdered<BoxFuture<'static, Result<Digested<B>, Error>>>,
    lease: Lease,
}

/// Forward demand held by a range. Dropping it cancels both a pending registration and
/// an active lease.
enum Lease {
    Idle,
    Registering(BoxFuture<'static, Option<oneshot::Receiver<()>>>),
    Active { _lease: oneshot::Receiver<()> },
    Released,
}

impl<B: Block> Unpin for BlockRange<B> {}

impl<B: Block> Stream for BlockRange<B> {
    type Item = Result<Digested<B>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.next.is_some() && this.end > this.source.tip {
            this.next = None;
            return Poll::Ready(Some(Err(Error::InvalidHeight)));
        }
        if matches!(this.lease, Lease::Idle)
            && let Some(height) = this.next
            && let Some(demand) = &this.source.demand
        {
            this.lease = Lease::Registering(demand(height..=this.end));
        }
        if let Lease::Registering(registration) = &mut this.lease
            && let Poll::Ready(lease) = registration.as_mut().poll(cx)
        {
            this.lease = lease.map_or(Lease::Released, |lease| Lease::Active { _lease: lease });
        }
        while this.pending.len() < this.source.window {
            let Some(height) = this.next else {
                break;
            };
            this.pending.push_back((this.source.fetch)(height));
            this.next = (height < this.end).then(|| height.next());
        }

        let Some(result) = ready!(Pin::new(&mut this.pending).poll_next(cx)) else {
            return Poll::Ready(None);
        };
        let result = result.and_then(|block| {
            // The preceding digest may only be resident once history has resolved.
            let previous = this.previous.or_else(|| {
                (block.height() == this.start)
                    .then(|| this.start.previous())
                    .flatten()
                    .and_then(|height| this.source.digest(height))
            });
            if previous.is_some_and(|digest| block.parent() != digest) {
                return Err(Error::InvalidParent);
            }
            this.previous = Some(block.digest());
            Ok(block)
        });
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
        core::mailbox::Message,
        mocks::{block::EmptyBlock, harness},
        standard::Standard,
    };
    use commonware_cryptography::sha256::Sha256;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{NZUsize, channel::oneshot, sync::Mutex};
    use futures::{FutureExt, StreamExt};
    use std::collections::BTreeMap;

    type TestBlock = EmptyBlock<Sha256>;
    type Requests = Arc<Mutex<BTreeMap<Height, oneshot::Sender<Digested<TestBlock>>>>>;

    fn digested(block: impl Into<Arc<TestBlock>>) -> Digested<TestBlock> {
        let block = block.into();
        let digest = block.digest();
        Digested::precomputed(block, digest)
    }

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

    fn pending_source(
        blocks: &[TestBlock],
        window: NonZeroUsize,
        requests: Requests,
    ) -> Blocks<TestBlock> {
        let digests: Arc<[_]> = blocks.iter().map(Digestible::digest).collect();
        Blocks::new(
            blocks.last().unwrap().height(),
            window,
            move |height| digests.get(height.get() as usize).copied(),
            move |height| {
                let (sender, receiver) = oneshot::channel();
                assert!(requests.lock().insert(height, sender).is_none());
                async move { receiver.await.ok() }
            },
        )
    }

    #[test]
    fn ranges_fetch_concurrently_and_release_consumed_blocks() {
        deterministic::Runner::default().start(|_| async move {
            let blocks = chain(12);
            let requests = Requests::default();
            let source = pending_source(&blocks, NZUsize!(3), requests.clone());
            let source_clone = source.clone();
            let mut range = source.range(Height::zero()..=Height::new(11));
            assert!(requests.lock().is_empty());
            assert!(range.next().now_or_never().is_none());
            assert_eq!(requests.lock().len(), 3);

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

            let second = range.next().await.unwrap().unwrap();
            assert_eq!(second.height(), Height::new(1));
            assert_eq!(requests.lock().len(), 1);
            drop(second);
            assert!(retained[1].upgrade().is_none());

            drop(range);
            assert!(retained.iter().all(|block| block.upgrade().is_none()));
            assert!(requests.lock().values().all(oneshot::Sender::is_closed));
            assert_eq!(
                source_clone.digest(Height::new(11)),
                Some(blocks[11].digest())
            );
        });
    }

    #[test]
    fn selected_range_shares_commitments_and_scopes_prefetch_to_its_lifetime() {
        deterministic::Runner::default().start(|context| async move {
            type TestMessage = Message<harness::S, Standard<TestBlock>>;
            let (sender, mut receiver) =
                commonware_actor::mailbox::new::<TestMessage>(context, NZUsize!(16));
            let marshal = Mailbox::new(sender, NZUsize!(1), NZUsize!(8));
            let blocks = chain(10);
            let commitments: Arc<[_]> = blocks[4..].iter().map(Digestible::digest).collect();
            let source = marshal.blocks(Height::new(9), History::ready(commitments.clone()));
            let source_clone = source.clone();
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
            drop(range);
            assert!(lease.is_closed());
            assert_eq!(
                source_clone.digest(Height::new(7)),
                Some(blocks[7].digest())
            );
        });
    }

    #[test]
    fn lazy_history_is_not_polled_until_range_and_drop_cancels_demand() {
        deterministic::Runner::default().start(|context| async move {
            type TestMessage = Message<harness::S, Standard<TestBlock>>;
            let (sender, mut receiver) =
                commonware_actor::mailbox::new::<TestMessage>(context, NZUsize!(16));
            let marshal = Mailbox::new(sender, NZUsize!(1), NZUsize!(8));
            let blocks = chain(10);
            let commitments: Arc<[_]> = blocks[4..].iter().map(Digestible::digest).collect();
            let polled = Arc::new(Mutex::new(0));
            let observed = polled.clone();
            let (release, released) = oneshot::channel::<()>();
            let supplied = commitments.clone();
            let history = History::new(async move {
                *observed.lock() += 1;
                released.await.ok()?;
                Some(supplied)
            });
            let source = marshal.blocks(Height::new(9), history);
            let clone = source.clone();
            assert_eq!(source.digest(Height::new(7)), None);
            assert_eq!(*polled.lock(), 0);

            // Polling a range awaits history but registers no demand until it resolves.
            let mut range = source.range(Height::new(5)..=Height::new(7));
            assert!(range.next().now_or_never().is_none());
            assert!(receiver.recv().now_or_never().is_none());

            // Dropping the range while history is pending leaves no demand behind.
            drop(range);
            release.send(()).unwrap();
            assert!(receiver.recv().now_or_never().is_none());

            // Resolved history exposes resident digests and registers demand for a new range.
            let mut range = clone.range(Height::new(5)..=Height::new(7));
            assert!(range.next().now_or_never().is_none());
            assert_eq!(clone.digest(Height::new(7)), Some(blocks[7].digest()));
            let TestMessage::Prefetch {
                range: selected, ..
            } = receiver.recv().await.unwrap()
            else {
                panic!("resolved history must register demand");
            };
            assert_eq!(selected, 1..4);
        });
    }

    #[test]
    fn resident_suffix_ranges_never_poll_history_and_gaps_wait_for_it() {
        deterministic::Runner::default().start(|context| async move {
            type TestMessage = Message<harness::S, Standard<TestBlock>>;
            let (sender, mut receiver) =
                commonware_actor::mailbox::new::<TestMessage>(context, NZUsize!(32));
            let marshal = Mailbox::new(sender, NZUsize!(1), NZUsize!(8));
            let blocks = chain(10);
            let resident: Arc<[_]> = blocks[7..].iter().map(Digestible::digest).collect();
            let full: Arc<[_]> = blocks.iter().map(Digestible::digest).collect();

            // A resolver that counts its first poll and then stays pending forever.
            let history = || {
                let polls = Arc::new(Mutex::new(0usize));
                let observed = polls.clone();
                let full = full.clone();
                let history = History::pending(resident.clone(), async move {
                    *observed.lock() += 1;
                    futures::future::pending::<()>().await;
                    Some(full)
                });
                (history, polls)
            };
            let drain = |receiver: &mut commonware_actor::mailbox::Receiver<TestMessage>| {
                let mut messages = Vec::new();
                while let Some(Some(message)) = receiver.recv().now_or_never() {
                    messages.push(message);
                }
                messages
            };

            // A range inside the resident suffix never polls the resolver.
            let (history_a, polls_a) = history();
            let source = marshal.blocks(Height::new(9), history_a);
            let clone = source.clone();
            assert_eq!(source.digest(Height::new(8)), Some(blocks[8].digest()));
            assert_eq!(source.digest(Height::new(6)), None);
            assert!(drain(&mut receiver).is_empty());
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
                    _ => panic!("unexpected message for a resident range"),
                }
            }
            let lease = lease.expect("resident range must register demand");
            assert_eq!(responses.len(), 2);
            assert_eq!(*polls_a.lock(), 0);

            // Out-of-order results are delivered in order, still without resolving history.
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
            assert_eq!(*polls_a.lock(), 0);

            // Dropping a range with outstanding demand cancels its lease and bodies.
            let mut range = clone.range(Height::new(8)..=Height::new(9));
            assert!(range.next().now_or_never().is_none());
            let mut lease = None;
            let mut pending = Vec::new();
            for message in drain(&mut receiver) {
                match message {
                    TestMessage::Prefetch { lease: held, .. } => lease = Some(held),
                    TestMessage::Acquire { response, .. } => pending.push(response),
                    _ => panic!("unexpected message for a resident range"),
                }
            }
            let lease = lease.unwrap();
            assert_eq!(pending.len(), 2);
            drop(range);
            assert!(lease.is_closed());
            assert!(pending.iter().all(oneshot::Sender::is_closed));
            assert_eq!(clone.digest(Height::new(9)), Some(blocks[9].digest()));
            assert_eq!(*polls_a.lock(), 0);

            // A range reaching below the suffix starts the resolver and waits for it
            // rather than guessing at canonical finalized history.
            let (history_b, polls_b) = history();
            let source = marshal.blocks(Height::new(9), history_b);
            let mut range = source.range(Height::new(6)..=Height::new(8));
            assert!(range.next().now_or_never().is_none());
            assert_eq!(*polls_b.lock(), 1);
            let mut bodies = Vec::new();
            for message in drain(&mut receiver) {
                match message {
                    TestMessage::Acquire {
                        commitment,
                        response,
                        ..
                    } => bodies.push((commitment, response)),
                    _ => panic!("gap must not request finalized or prefetch demand"),
                }
            }
            // Only the resident heights are requested; they remain buffered behind the gap.
            assert_eq!(bodies.len(), 2);
            let mut bodies: BTreeMap<_, _> = bodies.into_iter().collect();
            for height in [7, 8] {
                bodies
                    .remove(&blocks[height].digest())
                    .unwrap()
                    .send(digested(blocks[height].clone()))
                    .unwrap();
            }
            assert!(range.next().now_or_never().is_none());
            assert!(drain(&mut receiver).is_empty());
            assert_eq!(*polls_b.lock(), 1);
            drop(range);
            assert!(drain(&mut receiver).is_empty());
        });
    }

    #[test]
    fn resolve_digest_polls_history_only_for_nonresident_heights() {
        deterministic::Runner::default().start(|context| async move {
            type TestMessage = Message<harness::S, Standard<TestBlock>>;
            let (sender, _receiver) =
                commonware_actor::mailbox::new::<TestMessage>(context, NZUsize!(32));
            let marshal = Mailbox::new(sender, NZUsize!(1), NZUsize!(8));
            let blocks = chain(10);
            let resident: Arc<[_]> = blocks[7..].iter().map(Digestible::digest).collect();
            let complete: Arc<[_]> = blocks[3..].iter().map(Digestible::digest).collect();
            let polls = Arc::new(Mutex::new(0usize));
            let observed = polls.clone();
            let history = History::pending(resident, async move {
                *observed.lock() += 1;
                Some(complete)
            });
            let source = marshal.blocks(Height::new(9), history);

            // Resident and above-tip heights do not poll history.
            let resident = source.resolve_digest(Height::new(8)).await;
            assert_eq!(resident, Ok(Some(blocks[8].digest())));
            assert_eq!(source.resolve_digest(Height::new(10)).await, Ok(None));
            assert_eq!(*polls.lock(), 0);

            // A gap resolves history once, while older canonical history stays absent.
            let gap = source.resolve_digest(Height::new(5)).await;
            assert_eq!(gap, Ok(Some(blocks[5].digest())));
            assert_eq!(source.resolve_digest(Height::new(2)).await, Ok(None));
            assert_eq!(*polls.lock(), 1);

            // Terminal history unavailability is surfaced.
            let unavailable = marshal.blocks(
                Height::new(9),
                History::pending(Arc::from([blocks[9].digest()]), async { None }),
            );
            let result = unavailable.resolve_digest(Height::new(5)).await;
            assert_eq!(result, Err(Error::Unavailable));
        });
    }

    #[test]
    fn gap_range_drop_cancels_resident_body_demand() {
        deterministic::Runner::default().start(|context| async move {
            type TestMessage = Message<harness::S, Standard<TestBlock>>;
            let (sender, mut receiver) =
                commonware_actor::mailbox::new::<TestMessage>(context, NZUsize!(32));
            let marshal = Mailbox::new(sender, NZUsize!(1), NZUsize!(8));
            let blocks = chain(10);
            let resident: Arc<[_]> = blocks[7..].iter().map(Digestible::digest).collect();
            let history = History::pending(resident, futures::future::pending());
            let source = marshal.blocks(Height::new(9), history);
            let mut range = source.range(Height::new(6)..=Height::new(8));
            assert!(range.next().now_or_never().is_none());
            let mut pending = Vec::new();
            while let Some(Some(message)) = receiver.recv().now_or_never() {
                let TestMessage::Acquire { response, .. } = message else {
                    panic!("gap must not request finalized or prefetch demand");
                };
                pending.push(response);
            }
            assert_eq!(pending.len(), 2);
            assert!(pending.iter().all(|response| !response.is_closed()));
            drop(range);
            assert!(pending.iter().all(oneshot::Sender::is_closed));
        });
    }

    #[test]
    fn invalid_block_terminates_range_and_cancels_prefetch() {
        deterministic::Runner::default().start(|_| async move {
            for expected in [
                Error::InvalidHeight,
                Error::InvalidDigest,
                Error::InvalidParent,
            ] {
                let mut blocks = chain(4);
                let replacement = match expected {
                    Error::InvalidHeight => TestBlock::new(blocks[0].digest(), Height::new(7), 1),
                    Error::InvalidDigest => TestBlock::new(blocks[0].digest(), Height::new(1), 99),
                    Error::InvalidParent => {
                        blocks[1] = TestBlock::new(Sha256::fill(7), Height::new(1), 1);
                        blocks[1].clone()
                    }
                    Error::Unavailable => unreachable!(),
                };
                let requests = Requests::default();
                let source = pending_source(&blocks, NZUsize!(8), requests.clone());
                let mut range = source.range(Height::new(1)..=Height::new(3));
                assert!(range.next().now_or_never().is_none());
                requests
                    .lock()
                    .remove(&Height::new(1))
                    .unwrap()
                    .send(digested(replacement))
                    .unwrap();
                assert_eq!(range.next().await.unwrap().unwrap_err(), expected);
                assert!(range.next().await.is_none());
                assert!(requests.lock().values().all(oneshot::Sender::is_closed));
            }
        });
    }

    #[test]
    fn empty_out_of_bounds_and_maximum_ranges_are_bounded() {
        deterministic::Runner::default().start(|_| async move {
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
            let mut empty = source.range(Height::new(2)..=Height::new(1));
            assert!(empty.next().await.is_none());
            assert_eq!(*requests.lock(), 0);

            let mut last = source.range(Height::new(u64::MAX)..=Height::new(u64::MAX));
            assert_eq!(last.next().await.unwrap().unwrap().height().get(), u64::MAX);
            assert!(last.next().await.is_none());
            assert_eq!(*requests.lock(), 1);

            let requests = Requests::default();
            let source = pending_source(&chain(2), NZUsize!(8), requests.clone());
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
