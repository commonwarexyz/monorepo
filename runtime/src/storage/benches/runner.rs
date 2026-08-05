//! Timed I/O loops and helpers.

use crate::{
    config::{IntegrityMode, SyncMethod, SyncMode},
    error::{Error, Result},
    report::Stats,
};
use commonware_runtime::{
    AtomicBlob, BatchOperation, BatchStorage, Blob, IntegrityBoundary, IntegrityToken, IoBufMut,
    IoBufs, WriteOptions,
};
use futures::{TryStreamExt, stream::FuturesUnordered};
use rand::{RngExt as _, SeedableRng, rngs::SmallRng};
use std::{
    num::NonZeroU32,
    time::{Duration, Instant},
};

/// Operations between deadline checks.
///
/// Checking the clock on every operation noticeably perturbs hot-cache runs.
/// Workers only poll the deadline every N iterations, this can overshoot the
/// requested duration by up to N operations per worker.
const DEADLINE_CHECK_STRIDE: u64 = 8;

/// Operations between latency samples.
///
/// A constant stride avoids front-biasing the latency distribution while
/// reducing timing calls on the hot path.
const LATENCY_SAMPLE_STRIDE: u64 = 16;

#[derive(Clone, Copy)]
pub struct RunLimit {
    deadline: Instant,
    operations: Option<u64>,
}

#[derive(Clone, Copy)]
pub struct WritePolicy {
    options: WriteOptions,
    sync_mode: SyncMode,
}

#[derive(Clone, Copy)]
pub struct IntegrityPolicy {
    mode: IntegrityMode,
    chunk_data_size: NonZeroU32,
}

/// Per-blob compare tokens for integrity-aware atomic appends.
pub struct AtomicAppendState {
    policy: IntegrityPolicy,
    tokens: Option<Vec<IntegrityToken>>,
}

/// Results for an in-process ordinary-versus-atomic append comparison.
pub struct PairedAppendStats {
    pub ordinary: Stats,
    pub ordinary_elapsed: Duration,
    pub atomic: Stats,
    pub atomic_elapsed: Duration,
}

impl WritePolicy {
    pub const fn new(options: WriteOptions, sync_mode: SyncMode) -> Self {
        Self { options, sync_mode }
    }
}

impl IntegrityPolicy {
    pub fn new(mode: IntegrityMode, chunk_data_size: u32) -> Self {
        Self {
            mode,
            chunk_data_size: NonZeroU32::new(chunk_data_size)
                .expect("chunk data size is validated as non-zero"),
        }
    }

    fn boundary(self, completes_value: bool) -> Option<IntegrityBoundary> {
        match self.mode {
            IntegrityMode::None => None,
            IntegrityMode::Variable if completes_value => Some(IntegrityBoundary::Complete),
            IntegrityMode::Variable => Some(IntegrityBoundary::Continue),
            IntegrityMode::Chunked => Some(IntegrityBoundary::Chunked(self.chunk_data_size)),
        }
    }
}

impl RunLimit {
    pub const fn new(deadline: Instant, operations: Option<u64>) -> Self {
        Self {
            deadline,
            operations,
        }
    }
}

/// Capture one coherent initial integrity snapshot per blob before timing begins.
pub async fn prepare_atomic_append_state(
    blobs: &[impl AtomicBlob],
    policy: IntegrityPolicy,
) -> Result<AtomicAppendState> {
    let tokens = if policy.mode == IntegrityMode::None {
        None
    } else {
        let mut indexed = blobs
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, blob)| async move {
                let snapshot = blob.integrity_snapshot().await?;
                Ok::<_, commonware_runtime::Error>((index, snapshot.token))
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect::<Vec<_>>()
            .await?;
        indexed.sort_unstable_by_key(|(index, _)| *index);
        Some(indexed.into_iter().map(|(_, token)| token).collect())
    };
    Ok(AtomicAppendState { policy, tokens })
}

impl AtomicAppendState {
    fn validate_blob_count(&self, blob_count: usize) -> Result<()> {
        if self
            .tokens
            .as_ref()
            .is_some_and(|tokens| tokens.len() != blob_count)
        {
            return Err(Error::Harness(
                "integrity token count does not match atomic blob count".into(),
            ));
        }
        Ok(())
    }
}

/// Return a closure that yields block indices in sequential, strided order.
///
/// Each call advances by `stride` blocks and wraps around `total_blocks`,
/// giving interleaved sequential coverage when multiple workers use different
/// starting offsets.
#[inline]
pub fn sequential_blocks(start: u64, stride: u64, total_blocks: u64) -> impl FnMut() -> u64 {
    let mut block = start;
    move || {
        let cur = block;
        block = (block + stride) % total_blocks;
        cur
    }
}

/// Return a closure that yields uniformly random block indices.
#[inline]
pub fn random_blocks(seed: u64, total_blocks: u64) -> impl FnMut() -> u64 {
    let mut rng = SmallRng::seed_from_u64(seed);
    move || rng.random_range(0..total_blocks)
}

/// Read loop without statistics collection (for cache warm-up).
#[inline]
pub async fn warm_read_loop(
    blob: impl Blob,
    io_size: usize,
    ops: u64,
    mut next_block: impl FnMut() -> u64,
) -> Result<()> {
    let mut buffer = IoBufMut::with_capacity(io_size).into();
    for _ in 0..ops {
        let offset = next_block() * io_size as u64;
        buffer = blob.read_at_buf(offset, io_size, buffer).await?;
    }
    Ok(())
}

/// Timed read loop that collects sampled latency statistics.
#[inline]
pub async fn run_read_loop(
    blob: impl Blob,
    limit: RunLimit,
    io_size: usize,
    mut next_block: impl FnMut() -> u64,
) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut buffer = IoBufMut::with_capacity(io_size).into();
    while should_continue(limit, stats.ops) {
        let offset = next_block() * io_size as u64;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        buffer = blob.read_at_buf(offset, io_size, buffer).await?;
        stats.record(io_size as u64, started.map(|s| s.elapsed()));
    }
    Ok(stats)
}

/// Timed write loop with caller-defined offset selection.
///
/// Latency samples cover only the `write_at` call, periodic syncs are excluded
/// so that percentiles reflect pure write cost. The `after_write` callback runs
/// after each completed write (used by the frontier writer to publish the
/// visible length to concurrent readers).
#[inline]
pub async fn run_write_loop(
    blob: impl Blob,
    limit: RunLimit,
    io_size: usize,
    payload: IoBufs,
    policy: WritePolicy,
    mut next_block: impl FnMut() -> u64,
    mut after_write: impl FnMut(u64),
) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut writes_since_sync = 0u64;
    let io_size = io_size as u64;
    while should_continue(limit, stats.ops) {
        let offset = next_block() * io_size;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        blob.write_at(offset, payload.clone(), policy.options)
            .await?;

        // Record latency before sync so percentiles reflect pure write cost.
        stats.record(io_size, started.map(|s| s.elapsed()));

        after_write(offset + io_size);
        writes_since_sync += 1;
        if let SyncMode::Every(every) = policy.sync_mode
            && writes_since_sync == every
        {
            let started = Instant::now();
            blob.sync().await?;
            stats.record_sync(started.elapsed());
            writes_since_sync = 0;
        }
    }

    // Flush the last partial batch so `SyncMode::Every` reports only durable
    // writes even when the timed phase ends mid-batch.
    if matches!(policy.sync_mode, SyncMode::Every(_)) && writes_since_sync != 0 {
        let started = Instant::now();
        blob.sync().await?;
        stats.record_sync(started.elapsed());
    }

    Ok(stats)
}

/// Timed durable write loop with caller-defined offset selection.
#[inline]
pub async fn run_sync_write_loop(
    blob: impl Blob,
    limit: RunLimit,
    io_size: usize,
    payload: IoBufs,
    sync_method: SyncMethod,
    mut next_block: impl FnMut() -> u64,
) -> Result<Stats> {
    let mut stats = Stats::default();
    let io_size = io_size as u64;
    while should_continue(limit, stats.ops) {
        let offset = next_block() * io_size;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        match sync_method {
            SyncMethod::WriteThenSync => {
                blob.write_at(offset, payload.clone(), WriteOptions::default())
                    .await?;
                blob.sync().await?;
            }
            SyncMethod::WriteAtSync => {
                blob.write_at(offset, payload.clone(), WriteOptions::SYNC)
                    .await?;
            }
        }
        stats.record(io_size, started.map(|s| s.elapsed()));
    }
    Ok(stats)
}

/// Timed atomic append loop.
#[inline]
pub async fn run_atomic_append_loop(
    blob: impl AtomicBlob,
    limit: RunLimit,
    io_size: usize,
    payload: IoBufs,
    sync_mode: SyncMode,
    mut append_state: AtomicAppendState,
) -> Result<Stats> {
    append_state.validate_blob_count(1)?;
    let mut stats = Stats::default();
    let mut writes_since_sync = 0u64;
    let io_size = io_size as u64;
    while should_continue(limit, stats.ops) {
        let started = should_sample_latency(stats.ops).then(Instant::now);
        match (
            append_state.policy.boundary(true),
            append_state.tokens.as_mut(),
        ) {
            (None, None) => {
                blob.append(payload.clone()).await?;
            }
            (Some(boundary), Some(tokens)) => {
                let appended = blob
                    .append_integrity(tokens[0], payload.clone(), boundary, None)
                    .await?;
                tokens[0] = appended.token;
            }
            _ => {
                return Err(Error::Harness(
                    "atomic append integrity policy and token state disagree".into(),
                ));
            }
        }

        // Record latency before sync so percentiles reflect pure append cost.
        stats.record(io_size, started.map(|s| s.elapsed()));

        writes_since_sync += 1;
        if let SyncMode::Every(every) = sync_mode
            && writes_since_sync == every
        {
            let started = Instant::now();
            blob.sync().await?;
            stats.record_sync(started.elapsed());
            writes_since_sync = 0;
        }
    }
    if matches!(sync_mode, SyncMode::Every(_)) && writes_since_sync != 0 {
        let started = Instant::now();
        blob.sync().await?;
        stats.record_sync(started.elapsed());
    }
    Ok(stats)
}

/// Append a contiguous payload stream to every ordinary blob, then make all writes durable.
///
/// One reported operation covers the concurrent writes and concurrent sync completions for the
/// entire group. No handle remains outstanding when the operation is recorded.
pub async fn run_multi_blob_append_loop(
    blobs: &[impl Blob],
    limit: RunLimit,
    io_size: usize,
    appends_per_batch: u64,
    payload: IoBufs,
) -> Result<Stats> {
    let group = AppendGroup::new(blobs.len(), io_size, appends_per_batch)?;
    let mut stats = Stats::default();
    let mut offset = 0u64;

    while should_continue(limit, stats.ops) {
        let next_offset = group.next_offset(offset)?;
        run_ordinary_append_group(blobs, offset, group, &payload, &mut stats).await?;
        offset = next_offset;
    }
    Ok(stats)
}

/// Append a contiguous payload stream to every atomic blob and publish one durable batch.
///
/// The operation latency covers the concurrent writes through full batch-handle completion. The
/// durable decision return and completion-handle resolution are also recorded separately.
pub async fn run_atomic_batch_append_loop<S: BatchStorage>(
    storage: &S,
    blobs: &[S::AtomicBlob],
    limit: RunLimit,
    io_size: usize,
    appends_per_batch: u64,
    payload: IoBufs,
    mut append_state: AtomicAppendState,
) -> Result<Stats> {
    append_state.validate_blob_count(blobs.len())?;
    let group = AppendGroup::new(blobs.len(), io_size, appends_per_batch)?;
    let publications = blobs
        .iter()
        .cloned()
        .map(BatchOperation::Publish)
        .collect::<Vec<_>>();
    let mut stats = Stats::default();
    let mut offset = 0u64;

    while should_continue(limit, stats.ops) {
        let next_offset = group.next_offset(offset)?;
        run_atomic_append_group(
            storage,
            blobs,
            &publications,
            offset,
            group,
            &payload,
            &mut stats,
            &mut append_state,
        )
        .await?;
        offset = next_offset;
    }
    Ok(stats)
}

/// Run one ordinary and one atomic durable append group per iteration.
///
/// The order alternates to distribute within-run ordering effects. Each side's elapsed time only
/// includes its own operations, so paired wall time is never used as either throughput denominator.
#[allow(clippy::too_many_arguments)]
pub async fn run_paired_atomic_batch_append_loop<S: BatchStorage>(
    storage: &S,
    ordinary_blobs: &[S::Blob],
    atomic_blobs: &[S::AtomicBlob],
    limit: RunLimit,
    io_size: usize,
    appends_per_batch: u64,
    payload: IoBufs,
    mut append_state: AtomicAppendState,
) -> Result<PairedAppendStats> {
    if ordinary_blobs.len() != atomic_blobs.len() {
        return Err(Error::Harness(
            "paired append groups must contain the same number of blobs".into(),
        ));
    }
    append_state.validate_blob_count(atomic_blobs.len())?;
    let ordinary_group = AppendGroup::new(ordinary_blobs.len(), io_size, appends_per_batch)?;
    let atomic_group = AppendGroup::new(atomic_blobs.len(), io_size, appends_per_batch)?;
    let publications = atomic_blobs
        .iter()
        .cloned()
        .map(BatchOperation::Publish)
        .collect::<Vec<_>>();
    let mut paired = PairedAppendStats {
        ordinary: Stats::default(),
        ordinary_elapsed: Duration::ZERO,
        atomic: Stats::default(),
        atomic_elapsed: Duration::ZERO,
    };
    let mut offset = 0u64;

    while should_continue(limit, paired.ordinary.ops) {
        let next_offset = ordinary_group.next_offset(offset)?;
        if paired.ordinary.ops.is_multiple_of(2) {
            paired.ordinary_elapsed += run_ordinary_append_group(
                ordinary_blobs,
                offset,
                ordinary_group,
                &payload,
                &mut paired.ordinary,
            )
            .await?;
            paired.atomic_elapsed += run_atomic_append_group(
                storage,
                atomic_blobs,
                &publications,
                offset,
                atomic_group,
                &payload,
                &mut paired.atomic,
                &mut append_state,
            )
            .await?;
        } else {
            paired.atomic_elapsed += run_atomic_append_group(
                storage,
                atomic_blobs,
                &publications,
                offset,
                atomic_group,
                &payload,
                &mut paired.atomic,
                &mut append_state,
            )
            .await?;
            paired.ordinary_elapsed += run_ordinary_append_group(
                ordinary_blobs,
                offset,
                ordinary_group,
                &payload,
                &mut paired.ordinary,
            )
            .await?;
        }
        offset = next_offset;
    }
    Ok(paired)
}

#[derive(Clone, Copy)]
struct AppendGroup {
    append_size: u64,
    appends: u64,
    bytes: u64,
}

impl AppendGroup {
    fn new(blob_count: usize, io_size: usize, appends: u64) -> Result<Self> {
        let (append_size, group_bytes) = group_dimensions(blob_count, io_size)?;
        Ok(Self {
            append_size,
            appends,
            bytes: operation_bytes(group_bytes, appends)?,
        })
    }

    fn next_offset(self, offset: u64) -> Result<u64> {
        let epoch_len = self
            .append_size
            .checked_mul(self.appends)
            .ok_or_else(|| Error::Harness("append epoch exceeds u64".into()))?;
        offset
            .checked_add(epoch_len)
            .ok_or_else(|| Error::Harness("append offset exceeds u64".into()))
    }
}

fn operation_bytes(group_bytes: u64, appends_per_batch: u64) -> Result<u64> {
    group_bytes
        .checked_mul(appends_per_batch)
        .ok_or_else(|| Error::Harness("group byte count exceeds u64".into()))
}

async fn run_ordinary_append_group(
    blobs: &[impl Blob],
    mut offset: u64,
    group: AppendGroup,
    payload: &IoBufs,
    stats: &mut Stats,
) -> Result<Duration> {
    let started = Instant::now();
    for _ in 0..group.appends {
        write_ordinary_blob_group(blobs, offset, payload).await?;
        offset = offset
            .checked_add(group.append_size)
            .ok_or_else(|| Error::Harness("append offset exceeds u64".into()))?;
    }

    let sync_started = Instant::now();
    sync_blob_group(blobs).await?;
    stats.record_sync(sync_started.elapsed());
    let elapsed = started.elapsed();
    stats.record(group.bytes, Some(elapsed));
    Ok(elapsed)
}

// Keep every timed input explicit so the helper cannot accidentally capture setup work.
#[allow(clippy::too_many_arguments)]
async fn run_atomic_append_group<S: BatchStorage>(
    storage: &S,
    blobs: &[S::AtomicBlob],
    publications: &[BatchOperation<S::AtomicBlob>],
    mut offset: u64,
    group: AppendGroup,
    payload: &IoBufs,
    stats: &mut Stats,
    append_state: &mut AtomicAppendState,
) -> Result<Duration> {
    let started = Instant::now();
    for append in 0..group.appends {
        append_atomic_blob_group(
            blobs,
            offset,
            payload,
            append + 1 == group.appends,
            append_state,
        )
        .await?;
        offset = offset
            .checked_add(group.append_size)
            .ok_or_else(|| Error::Harness("append offset exceeds u64".into()))?;
    }

    let publication_started = Instant::now();
    let completion = storage.start_apply(publications.to_vec()).await?;
    let decision_return = publication_started.elapsed();
    completion.await?;
    let full_completion = publication_started.elapsed();
    stats.record_publication(decision_return, full_completion);
    let elapsed = started.elapsed();
    stats.record(group.bytes, Some(elapsed));
    Ok(elapsed)
}

fn group_dimensions(blob_count: usize, io_size: usize) -> Result<(u64, u64)> {
    if blob_count == 0 {
        return Err(Error::Harness("multi-blob group cannot be empty".into()));
    }
    let io_size =
        u64::try_from(io_size).map_err(|_| Error::Harness("I/O size exceeds u64".into()))?;
    let blob_count =
        u64::try_from(blob_count).map_err(|_| Error::Harness("blob count exceeds u64".into()))?;
    let group_bytes = io_size
        .checked_mul(blob_count)
        .ok_or_else(|| Error::Harness("group byte count exceeds u64".into()))?;
    Ok((io_size, group_bytes))
}

async fn write_ordinary_blob_group(
    blobs: &[impl Blob],
    offset: u64,
    payload: &IoBufs,
) -> Result<()> {
    blobs
        .iter()
        .cloned()
        .map(|blob| {
            let payload = payload.clone();
            async move {
                blob.write_at(offset, payload, WriteOptions::default())
                    .await
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;
    Ok(())
}

async fn append_atomic_blob_group(
    blobs: &[impl AtomicBlob],
    expected_offset: u64,
    payload: &IoBufs,
    completes_value: bool,
    append_state: &mut AtomicAppendState,
) -> Result<()> {
    match (
        append_state.policy.boundary(completes_value),
        append_state.tokens.as_mut(),
    ) {
        (None, None) => {
            let offsets = blobs
                .iter()
                .cloned()
                .map(|blob| {
                    let payload = payload.clone();
                    async move { blob.append(payload).await }
                })
                .collect::<FuturesUnordered<_>>()
                .try_collect::<Vec<_>>()
                .await?;
            if offsets.iter().any(|&offset| offset != expected_offset) {
                return Err(Error::Harness(
                    "atomic append group participants have different logical tails".into(),
                ));
            }
        }
        (Some(boundary), Some(tokens)) => {
            let appends = blobs
                .iter()
                .cloned()
                .zip(tokens.iter().copied())
                .enumerate()
                .map(|(index, (blob, token))| {
                    let payload = payload.clone();
                    async move {
                        let appended = blob
                            .append_integrity(token, payload, boundary, None)
                            .await?;
                        Ok::<_, commonware_runtime::Error>((index, appended.offset, appended.token))
                    }
                })
                .collect::<FuturesUnordered<_>>()
                .try_collect::<Vec<_>>()
                .await?;
            let first_offset = appends
                .first()
                .map(|(_, offset, _)| *offset)
                .ok_or_else(|| Error::Harness("atomic append group cannot be empty".into()))?;
            if appends.iter().any(|(_, offset, _)| *offset != first_offset) {
                return Err(Error::Harness(
                    "integrity append group participants have different encoded tails".into(),
                ));
            }
            for (index, _, token) in appends {
                tokens[index] = token;
            }
        }
        _ => {
            return Err(Error::Harness(
                "atomic append integrity policy and token state disagree".into(),
            ));
        }
    }
    Ok(())
}

async fn sync_blob_group(blobs: &[impl Blob]) -> Result<()> {
    blobs
        .iter()
        .cloned()
        .map(|blob| async move { blob.sync().await })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;
    Ok(())
}

/// Check whether the timed loop should keep running.
///
/// Only polls the clock every `DEADLINE_CHECK_STRIDE` operations to avoid
/// perturbing hot-cache benchmarks with frequent `Instant::now()` calls.
#[inline(always)]
fn should_continue(limit: RunLimit, completed_ops: u64) -> bool {
    if let Some(operations) = limit.operations {
        return completed_ops < operations;
    }
    if completed_ops.is_multiple_of(DEADLINE_CHECK_STRIDE) {
        Instant::now() < limit.deadline
    } else {
        true
    }
}

/// Whether to record a latency sample for this operation.
///
/// Uses a constant stride to avoid front-biasing the distribution.
#[inline(always)]
const fn should_sample_latency(completed_ops: u64) -> bool {
    completed_ops.is_multiple_of(LATENCY_SAMPLE_STRIDE)
}

#[cfg(test)]
#[allow(dead_code, unused_imports)]
mod tests {
    use super::*;

    #[test]
    fn variable_integrity_closes_only_the_last_append_in_a_value() {
        let policy = IntegrityPolicy::new(IntegrityMode::Variable, 4092);

        assert_eq!(policy.boundary(false), Some(IntegrityBoundary::Continue));
        assert_eq!(policy.boundary(true), Some(IntegrityBoundary::Complete));
    }

    #[test]
    fn chunked_integrity_applies_the_configured_size_to_every_append() {
        let policy = IntegrityPolicy::new(IntegrityMode::Chunked, 8192);
        let expected = Some(IntegrityBoundary::Chunked(NonZeroU32::new(8192).unwrap()));

        assert_eq!(policy.boundary(false), expected);
        assert_eq!(policy.boundary(true), expected);
    }

    #[test]
    fn integrity_footers_do_not_change_logical_group_byte_accounting() {
        let group = AppendGroup::new(4, 1024, 3).unwrap();

        assert_eq!(group.bytes, 4 * 1024 * 3);
    }
}
