//! Bounded forward access to a selected branch and its finalized prefix.

use super::core::{Mailbox, Variant};
use crate::{Block, types::Height};
use commonware_cryptography::certificate::Scheme;
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

// Keep each resident digest with the body it validated. Older canonical
// history needs its digest only when consumed.
type Fetched<B> = (
    Arc<B>,
    Option<<B as commonware_cryptography::Digestible>::Digest>,
);
type Fetch<B> = dyn Fn(Height) -> BoxFuture<'static, Result<Fetched<B>, Error>> + Send + Sync;
type DigestAt<B> =
    dyn Fn(Height) -> Option<<B as commonware_cryptography::Digestible>::Digest> + Send + Sync;
type Demand = dyn Fn(RangeInclusive<Height>) -> oneshot::Receiver<()> + Send + Sync;

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
/// consumption. Marshal separately schedules forward prefetch for the whole
/// requested range within its configured capacity. Dropping a range cancels
/// its remaining demand.
pub struct Blocks<B: Block> {
    tip: Height,
    digest: Arc<DigestAt<B>>,
    fetch: Arc<Fetch<B>>,
    demand: Option<Arc<Demand>>,
    prefetch: usize,
}

impl<B: Block> Clone for Blocks<B> {
    fn clone(&self) -> Self {
        Self {
            tip: self.tip,
            digest: self.digest.clone(),
            fetch: self.fetch.clone(),
            demand: self.demand.clone(),
            prefetch: self.prefetch,
        }
    }
}

impl<S: Scheme, V: Variant> Mailbox<S, V> {
    /// Provides forward access to a selected branch ending at `parent_height`.
    ///
    /// `commitments` is the consensus-supplied suffix in increasing height order.
    /// Consecutive re-proposals occupy one entry. The suffix is shared without
    /// copying; older heights are supplied by canonical finalized storage.
    pub fn blocks(
        &self,
        parent_height: Height,
        commitments: Arc<[V::Commitment]>,
    ) -> Blocks<V::ApplicationBlock> {
        let first = commitments
            .len()
            .checked_sub(1)
            .and_then(|distance| u64::try_from(distance).ok())
            .and_then(|distance| parent_height.get().checked_sub(distance));
        let valid = commitments.is_empty() || first.is_some();
        let requested = commitments.clone();
        let commitment_at = move |height: Height| {
            let index = usize::try_from(height.get().checked_sub(first?)?).ok()?;
            commitments.get(index).copied()
        };
        let digest_at = commitment_at.clone();
        let marshal = self.clone();
        let mut blocks = Blocks::new(
            parent_height,
            move |height| digest_at(height).map(V::commitment_to_inner),
            move |height| {
                let commitment = commitment_at(height);
                let marshal = marshal.clone();
                async move {
                    if !valid {
                        return None;
                    }
                    let block = match commitment {
                        Some(commitment) => marshal.acquire(commitment).await.ok()?,
                        None => marshal.finalized(height).await.ok()?,
                    };
                    Some(V::into_shared(block))
                }
            },
        );
        let marshal = self.clone();
        blocks.demand = Some(Arc::new(move |heights| {
            let range = first
                .and_then(|first| {
                    let start = heights.start().get().max(first);
                    let end = heights.end().get().min(parent_height.get());
                    if start > end {
                        return None;
                    }
                    let start = usize::try_from(start - first).ok()?;
                    let end = usize::try_from(end - first).ok()?.checked_add(1)?;
                    Some(start..end)
                })
                .unwrap_or(0..0);
            marshal.prefetch(requested.clone(), range)
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
    ///
    /// A range holds at most eight pending or buffered body acquisitions by default.
    pub fn new<D, F, Fut>(tip: Height, digest: D, fetch: F) -> Self
    where
        D: Fn(Height) -> Option<B::Digest> + Send + Sync + 'static,
        F: Fn(Height) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<Arc<B>>> + Send + 'static,
    {
        let digest: Arc<DigestAt<B>> = Arc::new(digest);
        let expected = digest.clone();
        let fetch = Arc::new(move |height| {
            let request = fetch(height);
            let expected = expected(height);
            Box::pin(async move {
                let block = request.await.ok_or(Error::Unavailable)?;
                if block.height() != height {
                    return Err(Error::InvalidHeight);
                }
                if expected.is_some_and(|digest| digest != block.digest()) {
                    return Err(Error::InvalidDigest);
                }
                Ok((block, expected))
            }) as BoxFuture<'static, Result<Fetched<B>, Error>>
        });
        Self {
            tip,
            digest,
            fetch,
            demand: None,
            prefetch: 8,
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

    /// Sets the maximum combined number of pending and buffered blocks per range.
    pub const fn with_prefetch(mut self, prefetch: NonZeroUsize) -> Self {
        self.prefetch = prefetch.get();
        self
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
            previous: start.previous().and_then(|height| self.digest(height)),
            pending: FuturesOrdered::new(),
            lease: None,
        }
    }
}

/// A bounded stream of selected blocks in increasing height order.
pub struct BlockRange<B: Block> {
    source: Blocks<B>,
    next: Option<Height>,
    end: Height,
    previous: Option<B::Digest>,
    pending: FuturesOrdered<BoxFuture<'static, Result<Fetched<B>, Error>>>,
    lease: Option<oneshot::Receiver<()>>,
}

impl<B: Block> Unpin for BlockRange<B> {}

impl<B: Block> Stream for BlockRange<B> {
    type Item = Result<Arc<B>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.next.is_some() && this.end > this.source.tip {
            this.next = None;
            return Poll::Ready(Some(Err(Error::InvalidHeight)));
        }
        if this.lease.is_none()
            && let Some(height) = this.next
            && let Some(demand) = &this.source.demand
        {
            this.lease = Some(demand(height..=this.end));
        }
        while this.pending.len() < this.source.prefetch {
            let Some(height) = this.next else {
                break;
            };
            this.pending.push_back((this.source.fetch)(height));
            this.next = (height < this.end).then(|| height.next());
        }

        let Some(result) = ready!(Pin::new(&mut this.pending).poll_next(cx)) else {
            return Poll::Ready(None);
        };
        let result = result.and_then(|(block, digest)| {
            if this.previous.is_some_and(|digest| block.parent() != digest) {
                return Err(Error::InvalidParent);
            }
            this.previous = Some(digest.unwrap_or_else(|| block.digest()));
            Ok(block)
        });
        if result.is_err() {
            this.next = None;
            this.pending.clear();
        }
        if this.next.is_none() && this.pending.is_empty() {
            this.lease = None;
        }
        Poll::Ready(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Heightable,
        marshal::{
            core::mailbox::Message,
            mocks::{block::EmptyBlock, harness},
            standard::Standard,
        },
    };
    use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_cryptography::{Digestible, sha256::Sha256};
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{NZUsize, channel::oneshot, sync::Mutex};
    use futures::{FutureExt, StreamExt};
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    type TestBlock = EmptyBlock<Sha256>;
    type Requests = Arc<Mutex<BTreeMap<Height, oneshot::Sender<Arc<TestBlock>>>>>;

    #[derive(Clone)]
    struct CountedBlock {
        block: TestBlock,
        digests: Arc<AtomicUsize>,
    }

    impl Write for CountedBlock {
        fn write(&self, writer: &mut impl bytes::BufMut) {
            self.block.write(writer);
        }
    }

    impl EncodeSize for CountedBlock {
        fn encode_size(&self) -> usize {
            self.block.encode_size()
        }
    }

    impl Read for CountedBlock {
        type Cfg = Arc<AtomicUsize>;

        fn read_cfg(reader: &mut impl Buf, digests: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self {
                block: TestBlock::read(reader)?,
                digests: digests.clone(),
            })
        }
    }

    impl Digestible for CountedBlock {
        type Digest = <TestBlock as Digestible>::Digest;

        fn digest(&self) -> Self::Digest {
            self.digests.fetch_add(1, Ordering::Relaxed);
            self.block.digest()
        }
    }

    impl Heightable for CountedBlock {
        fn height(&self) -> Height {
            self.block.height()
        }
    }

    impl Block for CountedBlock {
        fn parent(&self) -> Self::Digest {
            self.block.parent()
        }
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

    fn pending_source(blocks: &[TestBlock], requests: Requests) -> Blocks<TestBlock> {
        let digests: Arc<[_]> = blocks.iter().map(Digestible::digest).collect();
        Blocks::new(
            blocks.last().unwrap().height(),
            move |height| digests.get(height.get() as usize).copied(),
            move |height| {
                let (sender, receiver) = oneshot::channel();
                assert!(requests.lock().insert(height, sender).is_none());
                async move { receiver.await.ok() }
            },
        )
    }

    #[test]
    fn acquired_blocks_compute_each_digest_once() {
        deterministic::Runner::default().start(|_| async move {
            for resident in [false, true] {
                let commitments: Arc<[_]> = chain(4).iter().map(Digestible::digest).collect();
                let parents = commitments.clone();
                let digests = Arc::new(AtomicUsize::new(0));
                let observed = digests.clone();
                let source = Blocks::new(
                    Height::new(3),
                    move |height| resident.then(|| commitments[height.get() as usize]),
                    move |height| {
                        let parent = height
                            .previous()
                            .map(|height| parents[height.get() as usize])
                            .unwrap_or_else(|| Sha256::fill(0));
                        let block = CountedBlock {
                            block: TestBlock::new(parent, height, height.get()),
                            digests: observed.clone(),
                        };
                        async move { Some(Arc::new(block)) }
                    },
                );
                let mut range = source.range(Height::new(1)..=Height::new(3));
                for height in 1..=3 {
                    assert_eq!(
                        range.next().await.unwrap().unwrap().height(),
                        Height::new(height),
                    );
                }
                assert!(range.next().await.is_none());
                assert_eq!(digests.load(Ordering::Relaxed), 3, "resident={resident}");
            }
        });
    }

    #[test]
    fn canonical_linkage_rejects_before_hashing_a_detached_block() {
        deterministic::Runner::default().start(|_| async move {
            let digests = Arc::new(AtomicUsize::new(0));
            let observed = digests.clone();
            let source = Blocks::new(
                Height::new(2),
                |_| None,
                move |height| {
                    let block = CountedBlock {
                        block: TestBlock::new(Sha256::fill(7), height, height.get()),
                        digests: observed.clone(),
                    };
                    async move { Some(Arc::new(block)) }
                },
            );
            let mut range = source.range(Height::zero()..=Height::new(2));
            assert_eq!(
                range.next().await.unwrap().unwrap().height(),
                Height::zero()
            );
            assert!(matches!(
                range.next().await,
                Some(Err(Error::InvalidParent))
            ));
            assert!(range.next().await.is_none());
            assert_eq!(digests.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn ranges_fetch_concurrently_and_release_consumed_blocks() {
        deterministic::Runner::default().start(|_| async move {
            let blocks = chain(12);
            let requests = Requests::default();
            let source = pending_source(&blocks, requests.clone()).with_prefetch(NZUsize!(3));
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
                    .send(block)
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
                .send(first)
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
            let marshal = Mailbox::new(sender, NZUsize!(1));
            let blocks = chain(10);
            let commitments: Arc<[_]> = blocks[4..].iter().map(Digestible::digest).collect();
            let source = marshal.blocks(Height::new(9), commitments.clone());
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
                let source = pending_source(&blocks, requests.clone());
                let mut range = source.range(Height::new(1)..=Height::new(3));
                assert!(range.next().now_or_never().is_none());
                requests
                    .lock()
                    .remove(&Height::new(1))
                    .unwrap()
                    .send(Arc::new(replacement))
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
                |_| None,
                move |height| {
                    *observed.lock() += 1;
                    async move { Some(Arc::new(TestBlock::new(Sha256::fill(0), height, 0))) }
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
            let source = pending_source(&chain(2), requests.clone());
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
