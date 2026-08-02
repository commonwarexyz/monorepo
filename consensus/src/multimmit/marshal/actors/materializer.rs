//! Bounded scheduling for immutable pending-body reads.
//!
//! The catalog owns this compact state machine, but every storage read and block decode executes
//! on a shared runtime task. This keeps destructive storage transitions ordered without putting
//! producer admission behind bulk body I/O.
//! Sealed readers remain resident across sequential requests under a residency bound independent
//! of the active read-job bound; appendable-segment snapshots stay attached to the exact request
//! that planned them.

use super::{catalog::Error, metrics::ReaderAcquisitions};
use crate::multimmit::{
    marshal::storage::pending::{
        BodyRead, BodyReadGroup, BodyReader, BodySource, ColdOpen, ColdSource,
    },
    types::{BlockRef, TransactionBlock},
};
use commonware_codec::Codec;
use commonware_cryptography::{Digestible, Hasher};
use commonware_runtime::{Spawner, telemetry::metrics::Counter};
use commonware_storage::Context;
use commonware_utils::{channel::oneshot, futures::Pool};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry},
    sync::Arc,
};
use tracing::{Instrument as _, info_span};

/// Bounds resident segment readers independently of active read jobs.
///
/// Residency exists to absorb request locality: a reader that stays resident serves later
/// requests for its segment without another acquisition. Sealed reacquisition is cheap (index
/// metadata only), so the bound caps file descriptors, not a recovery cliff.
pub(super) const BODY_READER_RESIDENCY: usize = 64;

type Values<H, B> = Vec<Option<Arc<TransactionBlock<H, B>>>>;
type Materialized<H, B> = Vec<(usize, Arc<TransactionBlock<H, B>>)>;
type Reply<H, B> = oneshot::Sender<Result<Values<H, B>, Error>>;

struct Request<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    values: Values<H, B>,
    references: BTreeSet<BlockRef<H::Digest>>,
    remaining: usize,
    materialized: usize,
    reply: Reply<H, B>,
}

enum SegmentReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Cold(ColdSource<E, H, B>),
    Opening,
    /// A sealed snapshot retained before any read demands its segment.
    Offered(BodyReader<E, H, B>),
    Opened(BodyReader<E, H, B>),
}

impl<E, H, B> SegmentReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    /// Whether this entry holds (or is about to hold) an open reader.
    const fn is_resident(&self) -> bool {
        matches!(self, Self::Opening | Self::Offered(_) | Self::Opened(_))
    }
}

struct QueuedRead<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    request: u64,
    read: BodyRead<H>,
    reader: Option<BodyReader<E, H, B>>,
}

enum Completion<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Reader {
        segment: u64,
        result: Result<(BodyReader<E, H, B>, ColdOpen), Error>,
    },
    Read {
        request: u64,
        segment: u64,
        bytes: u64,
        result: Result<Materialized<H, B>, Error>,
    },
}

pub(super) struct CompletedRequest<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(super) values: Values<H, B>,
    pub(super) materialized: usize,
    pub(super) reply: Reply<H, B>,
}

/// Globally bounds all body materialization admitted by the catalog.
pub(super) struct Materializer<R, E, H, B>
where
    R: Spawner,
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
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
    active: Pool<Completion<E, H, B>>,
    active_bytes: u64,
    reader_acquisitions: ReaderAcquisitions,
    materialized_body_bytes: Counter,
}

impl<R, E, H, B> Materializer<R, E, H, B>
where
    R: Spawner,
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    pub(super) fn new(
        context: R,
        max_jobs: usize,
        max_bytes: u64,
        request_capacity: usize,
        reader_acquisitions: ReaderAcquisitions,
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

    pub(super) fn stats(&self) -> (usize, u64, usize) {
        (self.active.len(), self.active_bytes, self.queued.len())
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

    /// Retains already-open sealed readers without displacing the demanded working set.
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
        values: Values<H, B>,
        groups: Vec<BodyReadGroup<E, H, B>>,
        reply: Reply<H, B>,
    ) -> Result<Option<CompletedRequest<H, B>>, Error> {
        if groups.is_empty() {
            return Ok(Some(CompletedRequest {
                values,
                materialized: 0,
                reply,
            }));
        }
        if !self.has_capacity() {
            drop(reply.send(Err(Error::Invalid(
                "catalog body materialization capacity is exhausted",
            ))));
            return Ok(None);
        }
        let references = groups
            .iter()
            .flat_map(BodyReadGroup::references)
            .collect::<BTreeSet<_>>();
        if !self.inflight.is_disjoint(&references) {
            return Err(Error::Invalid(
                "catalog scheduled duplicate body materialization",
            ));
        }
        self.inflight.extend(references.iter().copied());
        let request = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or(Error::Invalid("catalog body request coordinate overflow"))?;
        for group in &groups {
            let count = self.pinned.entry(group.segment()).or_default();
            *count = count
                .checked_add(1)
                .ok_or(Error::Invalid("catalog body segment pin overflow"))?;
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
            },
        );
        for group in groups {
            let segment = group.segment();
            let (source, read) = group.into_parts();
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
        self.schedule()?;
        Ok(None)
    }

    /// Applies one completed read and launches newly unblocked work before returning.
    pub(super) async fn complete_next(&mut self) -> Result<Option<CompletedRequest<H, B>>, Error> {
        let (request, segment, bytes, result) = match self.active.next_completed().await {
            Completion::Reader { segment, result } => {
                let slot = self
                    .readers
                    .get_mut(&segment)
                    .ok_or(Error::Invalid("opened body segment is not tracked"))?;
                if !matches!(slot, SegmentReader::Opening) {
                    return Err(Error::Invalid("body segment reader opened twice"));
                }
                let (reader, cold) = result?;
                self.reader_acquisitions.inc(cold);
                *slot = SegmentReader::Opened(reader);
                self.schedule()?;
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
            .ok_or(Error::Invalid("completed body read has no request"))?;
        pending.materialized = pending
            .materialized
            .checked_add(values.len())
            .ok_or(Error::Invalid("materialized body count overflow"))?;
        for (output, block) in values {
            let slot = pending
                .values
                .get_mut(output)
                .ok_or(Error::Invalid("body read output is outside its request"))?;
            if slot.replace(block).is_some() {
                return Err(Error::Invalid("body read completed one output twice"));
            }
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
        self.schedule()?;
        Ok(completed)
    }

    pub(super) fn fail(&mut self, error: Error) {
        self.queued.clear();
        self.active.cancel_all();
        self.active_bytes = 0;
        self.inflight.clear();
        self.pinned.clear();
        self.readers.clear();
        for (_, request) in std::mem::take(&mut self.requests) {
            drop(request.reply.send(Err(error.clone())));
        }
    }

    fn schedule(&mut self) -> Result<(), Error> {
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
                    .ok_or(Error::Invalid("active body read bytes overflow"))?;
                let span = info_span!(
                    "multimmit.marshal.materializer.read",
                    request = request,
                    segment = segment,
                    bytes = bytes,
                );
                let handle = self.context.child("read").shared(true).spawn(move |_| {
                    async move { read.read(reader).await.map_err(Error::storage) }.instrument(span)
                });
                self.active.push(async move {
                    Completion::Read {
                        request,
                        segment,
                        bytes,
                        result: handle
                            .await
                            .map_err(Error::storage)
                            .and_then(|result| result),
                    }
                });
                continue;
            }

            let Some(segment) = self
                .queued
                .iter()
                .map(|queued| queued.read.segment())
                .find(|segment| matches!(self.readers.get(segment), Some(SegmentReader::Cold(_))))
            else {
                break;
            };
            if self.resident() >= self.max_readers {
                let evictable = self
                    .readers
                    .iter()
                    .find_map(|(&segment, reader)| {
                        (!self.pinned.contains_key(&segment)
                            && matches!(reader, SegmentReader::Offered(_)))
                        .then_some(segment)
                    })
                    .or_else(|| {
                        self.readers.iter().find_map(|(&segment, reader)| {
                            (!self.pinned.contains_key(&segment)
                                && matches!(reader, SegmentReader::Opened(_)))
                            .then_some(segment)
                        })
                    });
                if let Some(segment) = evictable {
                    self.readers.remove(&segment);
                    continue;
                }
                break;
            }
            let reader = self
                .readers
                .get_mut(&segment)
                .expect("selected body segment is tracked");
            let SegmentReader::Cold(source) =
                std::mem::replace(reader, SegmentReader::Opening)
            else {
                unreachable!("the selected body segment is cold")
            };
            let span = info_span!("multimmit.marshal.materializer.open", segment = segment);
            let handle = self
                .context
                .child("open")
                .shared(true)
                .spawn(move |_| {
                    async move { source.open().await.map_err(Error::storage) }.instrument(span)
                });
            self.active.push(async move {
                Completion::Reader {
                    segment,
                    result: handle
                        .await
                        .map_err(Error::storage)
                        .and_then(|result| result),
                }
            });
        }
        Ok(())
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
