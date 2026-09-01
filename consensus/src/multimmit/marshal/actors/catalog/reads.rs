//! Body reads, the caches that serve them, and bounded segment walks.
//!
//! Reads stay on the catalog task because the segments they pin must outlive pruning,
//! promotion, and retirement, which only the catalog orders.

use super::{
    actor::{Fatal, outcome},
    admission::AdmittedBlocks,
    cache::BlockCache,
    mailbox::{Error, HeaderSegments, HistorySegment, OutputRefs},
    materializer::{CompletedRequest, Materializer},
    metrics::Metrics,
};
use crate::{
    multimmit::{
        marshal::{
            storage::{
                Error as StorageError,
                catalog::CatalogStore,
                pending::{BODY_READ_CONCURRENCY, BodyReadGroup},
            },
            types::{BodyValues, OutputIndex, Reply},
        },
        types::{BlockRef, Body, ChainId, TransactionBlock},
    },
    types::Height,
};
use commonware_codec::EncodeSize;
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::Spawner;
use commonware_storage::{Context, translator::Translator};
use commonware_utils::{channel::fallible::OneshotExt as _, futures::Pool};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::{Instrument as _, Span, debug_span};

type AvailableBodies<H, B> = HashMap<BlockRef<<H as Hasher>::Digest>, Arc<TransactionBlock<H, B>>>;

/// Pending segments whose retirement markers are syncing.
pub(super) type Retired = (Vec<u64>, Result<(), StorageError>);

/// A body request waiting for materialization capacity or an identical in-flight read.
///
/// Planned groups keep exact locations and pin their segments, so pruning cannot remove a
/// request's source before it reaches the materializer.
struct BodyWaiter<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    references: Vec<BlockRef<H::Digest>>,
    values: BodyValues<H, B>,
    groups: Vec<BodyReadGroup<E, H, B>>,
    reply: Reply<BodyValues<H, B>, Error>,
    span: Span,
}

/// Body reads in flight or waiting, the block caches, and pending-segment retirement.
pub(super) struct BodyReads<R, E, H, B>
where
    R: Spawner,
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    pub(super) materializer: Materializer<R, E, H, B>,
    waiters: VecDeque<BodyWaiter<E, H, B>>,
    waiter_capacity: usize,
    /// Newly admitted blocks, kept apart so historical reads cannot displace them.
    live: BlockCache<H, B>,
    /// Blocks read back from storage, kept for repeated requests and delivery handoff.
    materialized: BlockCache<H, B>,
    /// Pending-segment retirement syncs; floor installs and pruning do not wait for them.
    pub(super) retirements: Pool<'static, Retired>,
}

impl<R, E, H, B> BodyReads<R, E, H, B>
where
    R: Spawner,
    E: Context,
    H: Hasher,
    B: Body<H>,
    B::Cfg: Clone,
{
    pub(super) fn new(
        materializer: Materializer<R, E, H, B>,
        waiter_capacity: usize,
        live: BlockCache<H, B>,
        materialized: BlockCache<H, B>,
    ) -> Self {
        Self {
            materializer,
            waiters: VecDeque::new(),
            waiter_capacity,
            live,
            materialized,
            retirements: Pool::default(),
        }
    }

    /// Returns the live block cache.
    pub(super) const fn live(&self) -> &BlockCache<H, B> {
        &self.live
    }

    /// Returns the materialized block cache.
    pub(super) const fn materialized(&self) -> &BlockCache<H, B> {
        &self.materialized
    }

    /// Returns whether another body request may wait.
    pub(super) fn has_waiter_room(&self) -> bool {
        self.waiters.len() < self.waiter_capacity
    }

    /// Returns whether no read, waiter, or retirement remains.
    pub(super) fn is_drained(&self) -> bool {
        self.materializer.is_idle() && self.waiters.is_empty() && self.retirements.is_empty()
    }

    /// Returns a cached block by reference.
    fn cached(&self, reference: &BlockRef<H::Digest>) -> Option<Arc<TransactionBlock<H, B>>> {
        self.live
            .get(reference)
            .or_else(|| self.materialized.get(reference))
    }

    /// Returns a cached block by chain and header digest.
    pub(super) fn cached_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Option<Arc<TransactionBlock<H, B>>> {
        self.live
            .get_by_digest(chain, digest)
            .or_else(|| self.materialized.get_by_digest(chain, digest))
    }

    /// Caches newly admitted blocks.
    pub(super) fn cache_admitted(&mut self, metrics: &Metrics, blocks: AdmittedBlocks<H, B>) {
        let mut evictions = 0u64;
        for (reference, block) in blocks {
            evictions = evictions.saturating_add(self.live.insert(reference, block));
        }
        metrics.live_evicted(evictions);
        self.update_cache_metrics(metrics);
    }

    /// Drops every cached block.
    pub(super) fn clear_caches(&mut self, metrics: &Metrics) {
        self.live.clear();
        self.materialized.clear();
        self.update_cache_metrics(metrics);
    }

    /// Drops cached blocks at or below each chain's promoted frontier.
    pub(super) fn prune_caches(&mut self, metrics: &Metrics, frontiers: &[BlockRef<H::Digest>]) {
        self.live.prune(frontiers);
        self.materialized.prune(frontiers);
        self.update_cache_metrics(metrics);
    }

    /// Returns segments that planned or running reads pin.
    pub(super) fn pinned_segments(&self) -> BTreeSet<u64> {
        let mut pinned = self.materializer.pinned_segments();
        pinned.extend(
            self.waiters
                .iter()
                .flat_map(|waiter| waiter.groups.iter().map(BodyReadGroup::segment)),
        );
        pinned
    }

    /// Returns whether a request for `references` would wait for a waiter slot: some body is in
    /// no cache and its read cannot start now.
    pub(super) fn must_wait<T, V>(
        &self,
        stores: &CatalogStore<T, E, H, V, B>,
        references: &[BlockRef<H::Digest>],
    ) -> Result<bool, Fatal>
    where
        T: Translator,
        V: Variant,
    {
        let missing = references
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, reference)| self.cached(reference).is_none())
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(false);
        }
        let groups = stores.pending().body_read_groups(
            missing,
            self.materialized.max_bytes(),
            BODY_READ_CONCURRENCY,
        )?;
        Ok(self.blocked(&groups))
    }

    /// Returns whether reads of `groups` must wait behind capacity or an identical read.
    fn blocked(&self, groups: &[BodyReadGroup<E, H, B>]) -> bool {
        !groups.is_empty()
            && (!self.materializer.has_capacity()
                || self
                    .materializer
                    .overlaps(groups.iter().flat_map(BodyReadGroup::references)))
    }

    /// Serves `references` from the caches and plans reads of the rest.
    ///
    /// The caller has checked [`Self::has_waiter_room`] or [`Self::must_wait`].
    pub(super) fn request<T, V>(
        &mut self,
        stores: &CatalogStore<T, E, H, V, B>,
        metrics: &Metrics,
        references: Vec<BlockRef<H::Digest>>,
        reply: Reply<BodyValues<H, B>, Error>,
    ) -> Result<(), Fatal>
    where
        T: Translator,
        V: Variant,
    {
        let mut values = vec![None; references.len()];
        let missing = self.fill_cached(metrics, &references, &mut values);
        let groups = stores.pending().body_read_groups(
            missing,
            self.materialized.max_bytes(),
            BODY_READ_CONCURRENCY,
        )?;
        self.submit(
            metrics,
            BodyWaiter {
                references,
                values,
                groups,
                reply,
                span: Span::current(),
            },
        );
        Ok(())
    }

    /// Applies one materialization completion and retries waiters it may unblock.
    pub(super) fn finish_materialization(
        &mut self,
        metrics: &Metrics,
        completed: Option<CompletedRequest<H, B>>,
    ) -> Result<(), Fatal> {
        self.update_materialization_metrics(metrics);
        let Some(completed) = completed else {
            return Ok(());
        };
        let available = self.complete(metrics, completed);
        for mut waiter in std::mem::take(&mut self.waiters) {
            for (reference, value) in waiter.references.iter().zip(&mut waiter.values) {
                if value.is_none()
                    && let Some(block) = available.get(reference)
                {
                    *value = Some(Arc::clone(block));
                }
            }
            let missing = self
                .fill_cached(metrics, &waiter.references, &mut waiter.values)
                .into_iter()
                .map(|(_, reference)| reference)
                .collect::<BTreeSet<_>>();
            let mut retained = Vec::with_capacity(waiter.groups.len());
            for mut group in std::mem::take(&mut waiter.groups) {
                if group.retain_references(&missing)? {
                    retained.push(group);
                }
            }
            waiter.groups = retained;
            self.submit(metrics, waiter);
        }
        self.update_materialization_metrics(metrics);
        Ok(())
    }

    /// Fills `values` from the caches and returns the positions still missing.
    fn fill_cached(
        &self,
        metrics: &Metrics,
        references: &[BlockRef<H::Digest>],
        values: &mut BodyValues<H, B>,
    ) -> Vec<(usize, BlockRef<H::Digest>)> {
        let mut missing = Vec::new();
        let mut cache_hits = 0u64;
        for (output, reference) in references.iter().copied().enumerate() {
            if values[output].is_some() {
                continue;
            }
            if let Some(block) = self.cached(&reference) {
                values[output] = Some(block);
                cache_hits = cache_hits.saturating_add(1);
            } else {
                missing.push((output, reference));
            }
        }
        metrics.body_cache_hits(cache_hits);
        missing
    }

    /// Starts materializing a waiter, or queues it behind capacity or an identical read.
    fn submit(&mut self, metrics: &Metrics, waiter: BodyWaiter<E, H, B>) {
        if self.blocked(&waiter.groups) {
            assert!(
                self.has_waiter_room(),
                "readiness reserves a slot for every waiting body request"
            );
            self.waiters.push_back(waiter);
            self.update_materialization_metrics(metrics);
            return;
        }
        metrics.materialization_groups(waiter.groups.len());
        let completed = waiter.span.in_scope(|| {
            self.materializer
                .enqueue(waiter.values, waiter.groups, waiter.reply)
        });
        if let Some(completed) = completed {
            self.complete(metrics, completed);
        }
        self.update_materialization_metrics(metrics);
    }

    /// Caches and answers a completed request, returning the blocks it read.
    fn complete(
        &mut self,
        metrics: &Metrics,
        completed: CompletedRequest<H, B>,
    ) -> AvailableBodies<H, B> {
        metrics.materialized(completed.materialized);
        let available = completed
            .values
            .iter()
            .flatten()
            .map(|block| (block.reference(), Arc::clone(block)))
            .collect::<HashMap<_, _>>();
        let mut evictions = 0u64;
        for block in completed.values.iter().flatten() {
            evictions = evictions.saturating_add(
                self.materialized
                    .insert(block.reference(), Arc::clone(block)),
            );
        }
        metrics.materialized_evicted(evictions);
        self.update_cache_metrics(metrics);
        completed.reply.send_lossy(Ok(completed.values));
        available
    }

    /// Retires every full pending segment the last admission cut proved durable.
    ///
    /// Each retired segment's final marker bounds later recovery. Retirement has no ordering
    /// needs, so it never gates barriers; the store keeps retiring segments readable and
    /// unreclaimed until [`Self::finish_retirement`].
    pub(super) fn start_retirement<T, V>(
        &mut self,
        stores: &mut CatalogStore<T, E, H, V, B>,
        cut: &Span,
    ) -> Result<(), Fatal>
    where
        T: Translator,
        V: Variant,
    {
        let span = debug_span!(
            parent: cut,
            "multimmit.marshal.catalog.retire_pending",
            segments = tracing::field::Empty,
        );
        let retirement = stores.start_retire()?;
        span.record(
            "segments",
            retirement
                .as_ref()
                .map_or(0, |retirement| retirement.segments.len()),
        );
        if let Some(retirement) = retirement {
            self.retirements
                .push(async move { (retirement.segments, retirement.sync.await) }.instrument(span));
        }
        Ok(())
    }

    /// Reclaims retired segments that no read pins and releases their readers.
    pub(super) async fn finish_retirement<T, V>(
        &mut self,
        stores: &mut CatalogStore<T, E, H, V, B>,
        (retired, result): Retired,
    ) -> Result<(), Fatal>
    where
        T: Translator,
        V: Variant,
    {
        result?;
        let pinned = self.pinned_segments();
        let reclaimed = stores.finish_retire(retired, &pinned).await?;
        self.materializer.release_readers(reclaimed);
        Ok(())
    }

    /// Publishes materializer pressure.
    pub(super) fn update_materialization_metrics(&self, metrics: &Metrics) {
        let stats = self.materializer.stats();
        metrics.materialization(
            stats.active_jobs,
            stats.active_bytes,
            stats.queued_groups,
            self.waiters.len(),
        );
    }

    /// Publishes cache occupancy.
    pub(super) fn update_cache_metrics(&self, metrics: &Metrics) {
        metrics.caches(
            self.live.len(),
            self.live.bytes(),
            self.materialized.len(),
            self.materialized.bytes(),
        );
    }
}

/// An encoded-size budget for one length-prefixed segment of items.
struct SegmentBudget {
    max_bytes: usize,
    items: usize,
    item_bytes: usize,
}

impl SegmentBudget {
    const fn new(max_bytes: NonZeroUsize) -> Self {
        Self {
            max_bytes: max_bytes.get(),
            items: 0,
            item_bytes: 0,
        }
    }

    /// Charges one item of `size` encoded bytes, unless the segment would exceed its budget.
    fn try_push(&mut self, size: usize) -> bool {
        let item_bytes = self.item_bytes.saturating_add(size);
        let encoded_bytes = self
            .items
            .saturating_add(1)
            .encode_size()
            .saturating_add(item_bytes);
        if encoded_bytes > self.max_bytes {
            return false;
        }
        self.items += 1;
        self.item_bytes = item_bytes;
        true
    }
}

/// Walks up to `max_items` history openings back from `commitment`, encoding within `max_bytes`.
pub(super) async fn read_history_segment<T, E, H, V, B>(
    stores: &CatalogStore<T, E, H, V, B>,
    mut commitment: H::Digest,
    max_items: NonZeroUsize,
    max_bytes: NonZeroUsize,
    reply: Reply<HistorySegment<H>, Error>,
) -> Result<(), Fatal>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    let mut records = Vec::new();
    let mut budget = SegmentBudget::new(max_bytes);
    while records.len() < max_items.get() {
        if reply.is_closed() {
            return Ok(());
        }
        let record = match outcome(stores.history(commitment).await)? {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(error) => {
                reply.send_lossy(Err(error));
                return Ok(());
            }
        };
        if !budget.try_push(record.encode_size()) {
            break;
        }
        commitment = record.parent();
        records.push(record);
    }
    reply.send_lossy(Ok(records));
    Ok(())
}

/// Walks header ancestry back from each `(start, max_items)` request, encoding each segment
/// within `max_bytes`.
pub(super) async fn read_header_segments<T, E, H, V, B>(
    stores: &CatalogStore<T, E, H, V, B>,
    requests: Vec<(BlockRef<H::Digest>, NonZeroUsize)>,
    max_bytes: NonZeroUsize,
    reply: Reply<HeaderSegments<H>, Error>,
) -> Result<(), Fatal>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    let mut segments = Vec::with_capacity(requests.len());
    for (mut reference, max_items) in requests {
        let mut headers = Vec::new();
        let mut budget = SegmentBudget::new(max_bytes);
        while headers.len() < max_items.get() {
            if reply.is_closed() {
                return Ok(());
            }
            let header = match outcome(stores.block_header(reference).await)? {
                Ok(Some(header)) => header,
                Ok(None) => break,
                Err(error) => {
                    reply.send_lossy(Err(error));
                    return Ok(());
                }
            };
            if !budget.try_push(header.encode_size()) {
                break;
            }
            let height = reference.height().get();
            let parent = header.parent();
            headers.push(header);
            if height == 1 {
                break;
            }
            reference = BlockRef::new(reference.chain(), Height::new(height - 1), parent);
        }
        segments.push(headers);
    }
    reply.send_lossy(Ok(segments));
    Ok(())
}

/// Returns committed output rows from `start` through `committed`, up to `max_items` rows encoding
/// within `max_bytes` (one larger row is returned alone).
pub(super) async fn read_output_refs<T, E, H, V, B>(
    stores: &CatalogStore<T, E, H, V, B>,
    committed: OutputIndex,
    start: OutputIndex,
    max_items: NonZeroUsize,
    max_bytes: NonZeroUsize,
    reply: Reply<OutputRefs<H>, Error>,
) -> Result<(), Fatal>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    let max_bytes = u64::try_from(max_bytes.get()).unwrap_or(u64::MAX);
    let mut encoded_bytes = 0u64;
    let mut outputs = Vec::new();
    for index in start.get()..=committed.get() {
        if outputs.len() == max_items.get() {
            break;
        }
        if reply.is_closed() {
            return Ok(());
        }
        let output = match outcome(stores.stored_ref(index).await)? {
            Ok(output) => output,
            Err(error) => {
                reply.send_lossy(Err(error));
                return Ok(());
            }
        };
        if !outputs.is_empty()
            && encoded_bytes
                .checked_add(output.encoded_len)
                .is_none_or(|total| total > max_bytes)
        {
            break;
        }
        encoded_bytes = encoded_bytes.saturating_add(output.encoded_len);
        outputs.push(output);
    }
    reply.send_lossy(Ok(outputs));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZUsize;

    #[test]
    fn segment_budget_counts_the_length_prefix() {
        let mut budget = SegmentBudget::new(NZUsize!(10));
        assert!(budget.try_push(4));
        assert!(budget.try_push(4));
        assert!(!budget.try_push(2));
        assert!(budget.try_push(1));
        assert!(!budget.try_push(1));
    }
}
