//! Bounded scheduling for pending-body reads requested through the catalog.
//!
//! The catalog owns this state machine and stays the only party that orders destructive storage
//! transitions. Every reader open, storage read, and block decode runs on a shared runtime task, so
//! producer admission does not wait behind bulk body I/O.
//!
//! # Bounds
//!
//! - Active jobs: at most `max_jobs` reader opens and body reads run at once, and running reads
//!   stay within `max_bytes` encoded bytes (one larger read may run alone).
//! - Resident readers: at most [`BODY_READER_RESIDENCY`] (or `max_jobs`, if larger) segment readers
//!   stay open between requests. Readers of appendable segments belong to the request that planned
//!   them and do not count.

use super::mailbox::Error;
use crate::multimmit::{
    marshal::{
        storage::{
            Error as StorageError,
            pending::{BodyRead, BodyReadGroup, BodyReader, BodySource, ColdSource},
        },
        types::{BodyValues, Reply},
    },
    types::{BlockRef, Body, TransactionBlock},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Spawner, telemetry::metrics::Counter};
use commonware_storage::Context;
use commonware_utils::futures::Pool;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry},
    future::Future,
    sync::Arc,
};
use tracing::{Instrument as _, Span, debug_span, info_span};

/// Bounds resident segment readers independently of active read jobs.
///
/// Residency exists to absorb request locality: a reader that stays resident serves later
/// requests for its segment without another acquisition. Reacquiring a retired segment is cheap
/// (index metadata only), so the bound caps file descriptors, not a recovery cliff.
pub(super) const BODY_READER_RESIDENCY: usize = 64;

type Materialized<H, B> = Vec<(usize, Arc<TransactionBlock<H, B>>)>;

struct Request<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    values: BodyValues<H, B>,
    references: BTreeSet<BlockRef<H::Digest>>,
    remaining: usize,
    materialized: usize,
    reply: Reply<BodyValues<H, B>, Error>,
    span: Span,
}

enum SegmentReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    Cold(ColdSource<E, H, B>),
    Opening,
    /// An immutable snapshot retained before any read demands its segment.
    Offered(BodyReader<E, H, B>),
    Opened(BodyReader<E, H, B>),
}

impl<E, H, B> SegmentReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    /// Whether this entry holds (or is about to hold) an open reader.
    const fn is_resident(&self) -> bool {
        matches!(self, Self::Opening | Self::Offered(_) | Self::Opened(_))
    }

    /// Whether this reader was retained before any request used it.
    const fn is_offered(&self) -> bool {
        matches!(self, Self::Offered(_))
    }

    /// Whether a request has used this reader.
    const fn is_opened(&self) -> bool {
        matches!(self, Self::Opened(_))
    }
}

struct QueuedRead<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    request: u64,
    read: BodyRead<H>,
    reader: Option<BodyReader<E, H, B>>,
}

enum Completion<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    Reader {
        segment: u64,
        result: Result<BodyReader<E, H, B>, StorageError>,
    },
    Read {
        request: u64,
        segment: u64,
        bytes: u64,
        result: Result<Materialized<H, B>, StorageError>,
    },
}

/// Scheduling pressure reported to catalog metrics.
pub(super) struct Stats {
    /// Reader opens and body reads currently running.
    pub(super) active_jobs: usize,
    /// Encoded bytes charged to running body reads.
    pub(super) active_bytes: u64,
    /// Body reads waiting for a reader or byte capacity.
    pub(super) queued_groups: usize,
}

pub(super) struct CompletedRequest<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    pub(super) values: BodyValues<H, B>,
    pub(super) materialized: usize,
    pub(super) reply: Reply<BodyValues<H, B>, Error>,
}

/// Globally bounds all body materialization admitted by the catalog.
pub(super) struct Materializer<R, E, H, B>
where
    R: Spawner,
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    context: R,
    max_jobs: usize,
    max_readers: usize,
    max_bytes: u64,
    request_capacity: usize,
    next_request: u64,
    requests: BTreeMap<u64, Request<H, B>>,
    inflight: BTreeSet<BlockRef<H::Digest>>,
    pinned: BTreeMap<u64, usize>,
    readers: BTreeMap<u64, SegmentReader<E, H, B>>,
    queued: VecDeque<QueuedRead<E, H, B>>,
    active: Pool<'static, Completion<E, H, B>>,
    active_bytes: u64,
    reader_acquisitions: Counter,
    materialized_body_bytes: Counter,
}

impl<R, E, H, B> Materializer<R, E, H, B>
where
    R: Spawner,
    E: Context,
    H: Hasher,
    B: Body<H>,
    B::Cfg: Clone,
{
    pub(super) fn new(
        context: R,
        max_jobs: usize,
        max_bytes: u64,
        request_capacity: usize,
        reader_acquisitions: Counter,
        materialized_body_bytes: Counter,
    ) -> Self {
        Self {
            context,
            max_jobs,
            max_readers: BODY_READER_RESIDENCY.max(max_jobs),
            max_bytes,
            request_capacity,
            next_request: 0,
            requests: BTreeMap::new(),
            inflight: BTreeSet::new(),
            pinned: BTreeMap::new(),
            readers: BTreeMap::new(),
            queued: VecDeque::new(),
            active: Pool::default(),
            active_bytes: 0,
            reader_acquisitions,
            materialized_body_bytes,
        }
    }

    pub(super) fn is_idle(&self) -> bool {
        self.requests.is_empty()
    }

    pub(super) fn has_capacity(&self) -> bool {
        self.requests.len() < self.request_capacity
    }

    pub(super) fn overlaps(
        &self,
        references: impl IntoIterator<Item = BlockRef<H::Digest>>,
    ) -> bool {
        references
            .into_iter()
            .any(|reference| self.inflight.contains(&reference))
    }

    pub(super) fn stats(&self) -> Stats {
        Stats {
            active_jobs: self.active.len(),
            active_bytes: self.active_bytes,
            queued_groups: self.queued.len(),
        }
    }

    pub(super) fn pinned_segments(&self) -> BTreeSet<u64> {
        self.pinned.keys().copied().collect()
    }

    /// Drops readers whose segment coordinates may be reused by a floor installation.
    pub(super) fn clear_reader_cache(&mut self) {
        debug_assert!(self.is_idle());
        self.readers.clear();
    }

    /// Releases idle readers after their durable custody segments are reclaimed.
    pub(super) fn release_readers(&mut self, segments: Vec<u64>) {
        for segment in segments {
            debug_assert!(!self.pinned.contains_key(&segment));
            self.readers.remove(&segment);
        }
    }

    /// Counts entries holding (or about to hold) an open reader.
    fn resident(&self) -> usize {
        self.readers
            .values()
            .filter(|reader| reader.is_resident())
            .count()
    }

    /// Retains already-open immutable readers without displacing the demanded working set.
    pub(super) fn retain_readers(&mut self, readers: Vec<BodyReader<E, H, B>>) {
        let mut resident = self.resident();
        for reader in readers {
            let segment = reader.segment();
            if resident >= self.max_readers {
                break;
            }
            if let Entry::Vacant(slot) = self.readers.entry(segment) {
                slot.insert(SegmentReader::Offered(reader));
                resident += 1;
            }
        }
    }

    pub(super) fn enqueue(
        &mut self,
        values: BodyValues<H, B>,
        groups: Vec<BodyReadGroup<E, H, B>>,
        reply: Reply<BodyValues<H, B>, Error>,
    ) -> Option<CompletedRequest<H, B>> {
        if groups.is_empty() {
            return Some(CompletedRequest {
                values,
                materialized: 0,
                reply,
            });
        }
        assert!(
            self.has_capacity(),
            "the catalog enqueues body reads only with materialization capacity"
        );
        let references = groups
            .iter()
            .flat_map(BodyReadGroup::references)
            .collect::<BTreeSet<_>>();
        assert!(
            self.inflight.is_disjoint(&references),
            "catalog scheduled duplicate body materialization"
        );
        self.inflight.extend(references.iter().copied());
        let request = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .expect("catalog body request coordinate overflow");
        for group in &groups {
            let count = self.pinned.entry(group.segment()).or_default();
            *count = count
                .checked_add(1)
                .expect("catalog body segment pin overflow");
        }
        let remaining = groups.len();
        self.requests.insert(
            request,
            Request {
                values,
                references,
                remaining,
                materialized: 0,
                reply,
                span: Span::current(),
            },
        );
        for BodyReadGroup { source, read } in groups {
            let segment = read.segment();
            let reader = match source {
                BodySource::Ready(reader) => Some(reader),
                BodySource::Cold(source) => {
                    self.readers
                        .entry(segment)
                        .or_insert_with(|| SegmentReader::Cold(source));
                    None
                }
            };
            self.queued.push_back(QueuedRead {
                request,
                read,
                reader,
            });
        }
        self.schedule();
        None
    }

    /// Applies one completed read and launches newly unblocked work before returning.
    pub(super) async fn complete_next(
        &mut self,
    ) -> Result<Option<CompletedRequest<H, B>>, StorageError> {
        let (request, segment, bytes, result) = match self.active.next_completed().await {
            Completion::Reader { segment, result } => {
                let slot = self
                    .readers
                    .get_mut(&segment)
                    .expect("opened body segment is tracked");
                assert!(
                    matches!(slot, SegmentReader::Opening),
                    "body segment reader opened twice"
                );
                let reader = result?;
                self.reader_acquisitions.inc();
                *slot = SegmentReader::Opened(reader);
                self.schedule();
                return Ok(None);
            }
            Completion::Read {
                request,
                segment,
                bytes,
                result,
            } => (request, segment, bytes, result),
        };
        self.active_bytes = self
            .active_bytes
            .checked_sub(bytes)
            .expect("active body bytes cover every completion");
        let count = self
            .pinned
            .get_mut(&segment)
            .expect("every body read group pins its segment");
        *count = count
            .checked_sub(1)
            .expect("a body read completion owns one segment pin");
        if *count == 0 {
            self.pinned.remove(&segment);
        }

        let values = result?;
        self.materialized_body_bytes.inc_by(bytes);
        let pending = self
            .requests
            .get_mut(&request)
            .expect("completed body read has a request");
        pending.materialized = pending
            .materialized
            .checked_add(values.len())
            .expect("materialized body count overflow");
        for (output, block) in values {
            let slot = pending
                .values
                .get_mut(output)
                .expect("body read output is inside its request");
            assert!(
                slot.replace(block).is_none(),
                "body read completed one output twice"
            );
        }
        pending.remaining = pending
            .remaining
            .checked_sub(1)
            .expect("each body group completes once");
        let completed = if pending.remaining == 0 {
            let pending = self
                .requests
                .remove(&request)
                .expect("completed body request remains registered");
            for reference in pending.references {
                self.inflight.remove(&reference);
            }
            Some(CompletedRequest {
                values: pending.values,
                materialized: pending.materialized,
                reply: pending.reply,
            })
        } else {
            None
        };
        self.schedule();
        Ok(completed)
    }

    fn schedule(&mut self) {
        while self.active.len() < self.max_jobs {
            if let Some(QueuedRead {
                request,
                read,
                reader,
            }) = self.next_read()
            {
                let segment = read.segment();
                let bytes = read.encoded_bytes();
                let reader = reader.expect("the selected body read has a ready segment");
                self.active_bytes = self
                    .active_bytes
                    .checked_add(bytes)
                    .expect("active body read bytes overflow");
                let span = debug_span!(
                    parent: &self.requests[&request].span,
                    "multimmit.marshal.materializer.read",
                    request = request,
                    segment = segment,
                    bytes = bytes,
                );
                self.launch(
                    "read",
                    span,
                    async move { read.read(reader).await },
                    move |result| Completion::Read {
                        request,
                        segment,
                        bytes,
                        result,
                    },
                );
                continue;
            }

            let Some(queued) = self.queued.iter().find(|queued| {
                matches!(
                    self.readers.get(&queued.read.segment()),
                    Some(SegmentReader::Cold(_))
                )
            }) else {
                break;
            };
            let segment = queued.read.segment();
            let request = queued.request;
            if self.resident() >= self.max_readers {
                if let Some(segment) = self.evictable() {
                    self.readers.remove(&segment);
                    continue;
                }
                break;
            }
            let reader = self
                .readers
                .get_mut(&segment)
                .expect("selected body segment is tracked");
            let SegmentReader::Cold(source) = std::mem::replace(reader, SegmentReader::Opening)
            else {
                unreachable!("the selected body segment is cold")
            };
            let span = info_span!(parent: &self.requests[&request].span,
                "multimmit.marshal.materializer.open", segment = segment);
            self.launch(
                "open",
                span,
                async move { source.open().await },
                move |result| Completion::Reader { segment, result },
            );
        }
    }

    /// Runs one storage operation on a shared task and tracks its completion.
    fn launch<T, F, C>(&mut self, label: &'static str, span: Span, operation: F, complete: C)
    where
        T: Send + 'static,
        F: Future<Output = Result<T, StorageError>> + Send + 'static,
        C: FnOnce(Result<T, StorageError>) -> Completion<E, H, B> + Send + 'static,
    {
        let handle = self
            .context
            .child(label)
            .shared(true)
            .spawn(move |_| operation.instrument(span));
        self.active.push(async move {
            complete(
                handle
                    .await
                    .map_err(StorageError::from)
                    .and_then(|result| result),
            )
        });
    }

    /// Returns an unpinned resident segment to evict.
    ///
    /// Readers no request has used go first, then readers that served earlier requests.
    fn evictable(&self) -> Option<u64> {
        [SegmentReader::is_offered, SegmentReader::is_opened]
            .into_iter()
            .find_map(|eligible| {
                self.readers.iter().find_map(|(&segment, reader)| {
                    (!self.pinned.contains_key(&segment) && eligible(reader)).then_some(segment)
                })
            })
    }

    /// Selects any ready group that fits the byte budget, rotating blocked groups behind it.
    fn next_read(&mut self) -> Option<QueuedRead<E, H, B>> {
        let queued = self.queued.len();
        for _ in 0..queued {
            let mut queued = self
                .queued
                .pop_front()
                .expect("the queued body group count was captured");
            let bytes = queued.read.encoded_bytes();
            let ready = queued.reader.is_some()
                || matches!(
                    self.readers.get(&queued.read.segment()),
                    Some(SegmentReader::Offered(_) | SegmentReader::Opened(_))
                );
            let runnable = ready
                && (self.active_bytes == 0
                    || self
                        .active_bytes
                        .checked_add(bytes)
                        .is_some_and(|total| total <= self.max_bytes));
            if runnable {
                if queued.reader.is_none() {
                    let Some(slot @ (SegmentReader::Offered(_) | SegmentReader::Opened(_))) =
                        self.readers.get_mut(&queued.read.segment())
                    else {
                        unreachable!("the selected body read has a ready segment")
                    };
                    let selected = match slot {
                        SegmentReader::Offered(reader) => {
                            let selected = reader.clone();
                            *slot = SegmentReader::Opened(selected.clone());
                            selected
                        }
                        SegmentReader::Opened(reader) => reader.clone(),
                        _ => unreachable!("the selected body read has a ready segment"),
                    };
                    queued.reader = Some(selected);
                }
                return Some(queued);
            }
            self.queued.push_back(queued);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            metrics::Metrics,
            tests::{config, producer_block},
        },
        *,
    };
    use crate::{
        multimmit::{
            marshal::storage::{
                catalog::{Admission, CatalogStore, Footprint},
                pending::BODY_READ_CONCURRENCY,
            },
            mocks::Committee,
            testing::TestBody,
            types::PathLimits,
        },
        types::Participant,
    };
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::translator::TwoCap;
    use commonware_utils::{NZU64, channel::oneshot};
    use futures::future::try_join_all;

    type Store = CatalogStore<TwoCap, deterministic::Context, Sha256, MinPk, TestBody>;
    type Block = Arc<TransactionBlock<Sha256, TestBody>>;

    fn committee(namespace: &[u8]) -> Committee<MinPk> {
        Committee::<MinPk>::builder(7, 6)
            .namespace(namespace)
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build()
    }

    fn materializer(
        context: &deterministic::Context,
    ) -> Materializer<deterministic::Context, deterministic::Context, Sha256, TestBody> {
        let metrics = Metrics::new(context);
        Materializer::new(
            context.child("materializer"),
            BODY_READ_CONCURRENCY.get(),
            u64::MAX,
            2,
            metrics.reader_acquisitions(),
            metrics.materialized_body_bytes(),
        )
    }

    /// Opens a store and makes `blocks` durable pending custody.
    async fn store_with(
        context: &deterministic::Context,
        committee: &Committee<MinPk>,
        blocks: &[Block],
    ) -> Store {
        let mut stores = Store::open(context, &config(context, committee))
            .await
            .unwrap();
        let mut writes = blocks
            .iter()
            .map(|block| Admission::Block(block.reference(), Arc::clone(block)))
            .collect::<Vec<_>>()
            .into_iter()
            .peekable();
        while writes.peek().is_some() {
            if let Some(write) = stores.start_admission(&mut writes).unwrap() {
                let write = write.await.unwrap();
                stores.finish_admission(write).unwrap();
            }
        }
        let footprint = Footprint {
            lqc: false,
            history: false,
            blocks: true,
        };
        try_join_all(stores.start_admission_sync(footprint).await.unwrap())
            .await
            .unwrap();
        stores
    }

    #[test]
    fn a_request_without_reads_completes_at_once() {
        deterministic::Runner::default().start(|context| async move {
            let mut materializer = materializer(&context);
            let (reply, _receiver) = oneshot::channel();
            let completed = materializer
                .enqueue(vec![None, None], Vec::new(), reply)
                .expect("a request without reads completes");
            assert_eq!(completed.values.len(), 2);
            assert_eq!(completed.materialized, 0);
            assert!(materializer.is_idle());
            assert!(materializer.pinned_segments().is_empty());
        });
    }

    #[test]
    fn reads_pin_their_segments_until_the_request_completes() {
        deterministic::Runner::default().start(|context| async move {
            let committee = committee(b"_COMMONWARE_CONSENSUS_MULTIMMIT_MATERIALIZER_PIN");
            let blocks = (0..2)
                .map(|chain| producer_block(&committee, chain, 10 + u64::from(chain)))
                .collect::<Vec<_>>();
            let stores = store_with(&context, &committee, &blocks).await;
            let groups = stores
                .pending()
                .body_read_groups(
                    blocks.iter().map(|block| block.reference()).enumerate(),
                    NZU64!(u64::MAX),
                    BODY_READ_CONCURRENCY,
                )
                .unwrap();
            assert!(!groups.is_empty());
            let segments = groups
                .iter()
                .map(BodyReadGroup::segment)
                .collect::<BTreeSet<_>>();

            let mut materializer = materializer(&context);
            let (reply, receiver) = oneshot::channel();
            assert!(
                materializer
                    .enqueue(vec![None; blocks.len()], groups, reply)
                    .is_none()
            );
            assert!(!materializer.is_idle());
            assert_eq!(materializer.pinned_segments(), segments);
            assert!(materializer.overlaps([blocks[0].reference()]));

            let completed = loop {
                if let Some(completed) = materializer.complete_next().await.unwrap() {
                    break completed;
                }
            };
            assert!(materializer.is_idle());
            assert!(materializer.pinned_segments().is_empty());
            assert!(!materializer.overlaps([blocks[0].reference()]));
            assert_eq!(completed.materialized, blocks.len());
            for (value, block) in completed.values.iter().zip(&blocks) {
                assert_eq!(value.as_deref(), Some(block.as_ref()));
            }
            drop(receiver);
        });
    }
}
