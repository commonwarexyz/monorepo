//! Timed I/O loops and helpers.

use crate::{
    config::{SyncMethod, SyncMode},
    error::{Error, Result},
    report::Stats,
};
use commonware_runtime::{
    AtomicBlob, BatchOperation, BatchStorage, Blob, IoBufMut, IoBufs, WriteOptions,
};
use futures::{TryStreamExt, stream::FuturesUnordered};
use rand::{RngExt as _, SeedableRng, rngs::SmallRng};
use std::time::{Duration, Instant};

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

impl RunLimit {
    pub const fn new(deadline: Instant, operations: Option<u64>) -> Self {
        Self {
            deadline,
            operations,
        }
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
) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut writes_since_sync = 0u64;
    let io_size = io_size as u64;
    while should_continue(limit, stats.ops) {
        let started = should_sample_latency(stats.ops).then(Instant::now);
        blob.append(payload.clone()).await?;

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

/// Append one contiguous payload to every ordinary blob, then make all writes durable.
///
/// One reported operation covers the concurrent writes and concurrent sync completions for the
/// entire group. No handle remains outstanding when the operation is recorded.
pub async fn run_multi_blob_append_loop(
    blobs: &[impl Blob],
    limit: RunLimit,
    io_size: usize,
    payload: IoBufs,
) -> Result<Stats> {
    let (io_size, group_bytes) = group_dimensions(blobs.len(), io_size)?;
    let mut stats = Stats::default();
    let mut offset = 0u64;

    while should_continue(limit, stats.ops) {
        let next_offset = next_append_offset(offset, io_size)?;
        run_ordinary_append_group(blobs, offset, &payload, group_bytes, &mut stats).await?;
        offset = next_offset;
    }
    Ok(stats)
}

/// Append one contiguous payload to every atomic blob and publish one durable batch.
///
/// The operation latency covers the concurrent writes through full batch-handle completion. The
/// durable decision return and completion-handle resolution are also recorded separately.
pub async fn run_atomic_batch_append_loop<S: BatchStorage>(
    storage: &S,
    blobs: &[S::AtomicBlob],
    limit: RunLimit,
    io_size: usize,
    payload: IoBufs,
) -> Result<Stats> {
    let (io_size, group_bytes) = group_dimensions(blobs.len(), io_size)?;
    let publications = blobs
        .iter()
        .cloned()
        .map(BatchOperation::Publish)
        .collect::<Vec<_>>();
    let mut stats = Stats::default();
    let mut offset = 0u64;

    while should_continue(limit, stats.ops) {
        let next_offset = next_append_offset(offset, io_size)?;
        run_atomic_append_group(
            storage,
            blobs,
            &publications,
            offset,
            &payload,
            group_bytes,
            &mut stats,
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
pub async fn run_paired_atomic_batch_append_loop<S: BatchStorage>(
    storage: &S,
    ordinary_blobs: &[S::Blob],
    atomic_blobs: &[S::AtomicBlob],
    limit: RunLimit,
    io_size: usize,
    payload: IoBufs,
) -> Result<PairedAppendStats> {
    if ordinary_blobs.len() != atomic_blobs.len() {
        return Err(Error::Harness(
            "paired append groups must contain the same number of blobs".into(),
        ));
    }
    let (append_size, ordinary_group_bytes) = group_dimensions(ordinary_blobs.len(), io_size)?;
    let (_, atomic_group_bytes) = group_dimensions(atomic_blobs.len(), io_size)?;
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
        let next_offset = next_append_offset(offset, append_size)?;
        if paired.ordinary.ops.is_multiple_of(2) {
            paired.ordinary_elapsed += run_ordinary_append_group(
                ordinary_blobs,
                offset,
                &payload,
                ordinary_group_bytes,
                &mut paired.ordinary,
            )
            .await?;
            paired.atomic_elapsed += run_atomic_append_group(
                storage,
                atomic_blobs,
                &publications,
                offset,
                &payload,
                atomic_group_bytes,
                &mut paired.atomic,
            )
            .await?;
        } else {
            paired.atomic_elapsed += run_atomic_append_group(
                storage,
                atomic_blobs,
                &publications,
                offset,
                &payload,
                atomic_group_bytes,
                &mut paired.atomic,
            )
            .await?;
            paired.ordinary_elapsed += run_ordinary_append_group(
                ordinary_blobs,
                offset,
                &payload,
                ordinary_group_bytes,
                &mut paired.ordinary,
            )
            .await?;
        }
        offset = next_offset;
    }
    Ok(paired)
}

fn next_append_offset(offset: u64, io_size: u64) -> Result<u64> {
    offset
        .checked_add(io_size)
        .ok_or_else(|| Error::Harness("append offset exceeds u64".into()))
}

async fn run_ordinary_append_group(
    blobs: &[impl Blob],
    offset: u64,
    payload: &IoBufs,
    group_bytes: u64,
    stats: &mut Stats,
) -> Result<Duration> {
    let started = Instant::now();
    write_ordinary_blob_group(blobs, offset, payload).await?;

    let sync_started = Instant::now();
    sync_blob_group(blobs).await?;
    stats.record_sync(sync_started.elapsed());
    let elapsed = started.elapsed();
    stats.record(group_bytes, Some(elapsed));
    Ok(elapsed)
}

async fn run_atomic_append_group<S: BatchStorage>(
    storage: &S,
    blobs: &[S::AtomicBlob],
    publications: &[BatchOperation<S::AtomicBlob>],
    offset: u64,
    payload: &IoBufs,
    group_bytes: u64,
    stats: &mut Stats,
) -> Result<Duration> {
    let started = Instant::now();
    append_atomic_blob_group(blobs, offset, payload).await?;

    let publication_started = Instant::now();
    let completion = storage.start_apply(publications.to_vec()).await?;
    let decision_return = publication_started.elapsed();
    completion.await?;
    let full_completion = publication_started.elapsed();
    stats.record_publication(decision_return, full_completion);
    let elapsed = started.elapsed();
    stats.record(group_bytes, Some(elapsed));
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
) -> Result<()> {
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
