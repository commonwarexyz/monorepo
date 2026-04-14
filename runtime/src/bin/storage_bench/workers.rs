//! Worker loops and helpers for `storage_bench`.

use crate::{config::SyncMode, report::WorkerStats};
use bytes::Buf;
use commonware_runtime::{Blob, IoBufMut, IoBufs, IoBufsMut};
use std::{
    hint::black_box,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

/// Convert any `Display`-able error into `String`.
pub(crate) trait ResultExt<T> {
    fn str_err(self) -> Result<T, String>;
}

impl<T, E: std::fmt::Display> ResultExt<T> for Result<T, E> {
    fn str_err(self) -> Result<T, String> {
        self.map_err(|e| e.to_string())
    }
}

/// Operations between deadline checks.
///
/// Checking the clock on every operation noticeably perturbs hot-cache runs.
/// Workers only poll the deadline every N iterations; this can overshoot the
/// requested duration by up to N operations per worker.
const DEADLINE_CHECK_STRIDE: u64 = 8;

/// Operations between latency samples.
///
/// A constant stride avoids front-biasing the latency distribution. At typical
/// throughput rates this yields thousands of samples per second while keeping
/// `Instant::now()` overhead well below 1% of per-operation cost.
const LATENCY_SAMPLE_STRIDE: u64 = 16;

/// Partition of the block space assigned to one random-write worker.
pub(crate) struct BlockShard {
    pub(crate) start_block: u64,
    pub(crate) blocks: u64,
}

/// Return a closure that yields block indices in sequential, strided order.
///
/// Each call advances by `stride` blocks and wraps around `total_blocks`,
/// giving interleaved sequential coverage when multiple workers use different
/// starting offsets.
pub(crate) fn sequential_blocks(start: u64, stride: u64, total_blocks: u64) -> impl FnMut() -> u64 {
    let mut block = start;
    move || {
        let cur = block;
        block = (block + stride) % total_blocks;
        cur
    }
}

/// Read loop without statistics collection (for cache warm-up).
#[inline]
pub(crate) async fn warm_read_loop<B, F>(
    blob: B,
    io_size: usize,
    ops: u64,
    mut next_block: F,
) -> Result<(), String>
where
    B: Blob,
    F: FnMut() -> u64,
{
    let mut buffer = reusable_buffer(io_size);
    for _ in 0..ops {
        let offset = next_block() * io_size as u64;
        buffer = blob.read_at_buf(offset, io_size, buffer).await.str_err()?;
        black_box(touch_buffer(&buffer));
    }
    Ok(())
}

/// Timed read loop that collects sampled latency statistics.
#[inline]
pub(crate) async fn run_read_loop<B, F>(
    blob: B,
    deadline: Instant,
    io_size: usize,
    mut next_block: F,
) -> Result<WorkerStats, String>
where
    B: Blob,
    F: FnMut() -> u64,
{
    let mut stats = WorkerStats::default();
    let mut buffer = reusable_buffer(io_size);
    while should_continue(deadline, stats.ops) {
        let offset = next_block() * io_size as u64;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        buffer = blob.read_at_buf(offset, io_size, buffer).await.str_err()?;
        black_box(touch_buffer(&buffer));
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), io_size as u64);
        } else {
            stats.record(io_size as u64);
        }
    }
    Ok(stats)
}

/// Timed write loop with caller-defined offset selection.
///
/// Latency samples cover only the `write_at` call; periodic syncs are excluded
/// so that percentiles reflect pure write cost. The `after_write` callback runs
/// after each completed write (used by the frontier writer to publish the
/// visible length to concurrent readers).
#[inline]
pub(crate) async fn run_write_loop<B, F, G>(
    blob: B,
    deadline: Instant,
    payload: IoBufs,
    sync_mode: SyncMode,
    mut next_offset: F,
    mut after_write: G,
) -> Result<WorkerStats, String>
where
    B: Blob,
    F: FnMut() -> u64,
    G: FnMut(u64),
{
    let mut stats = WorkerStats::default();
    let mut writes_since_sync = 0u64;
    let payload_len = payload.remaining();
    while should_continue(deadline, stats.ops) {
        let offset = next_offset();
        let started = should_sample_latency(stats.ops).then(Instant::now);
        blob.write_at(offset, payload.clone()).await.str_err()?;

        // Record latency before sync so percentiles reflect pure write cost.
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), payload_len as u64);
        } else {
            stats.record(payload_len as u64);
        }

        after_write(offset + payload_len as u64);
        writes_since_sync += 1;
        if let SyncMode::Every(every) = sync_mode {
            if writes_since_sync == every {
                blob.sync().await.str_err()?;
                writes_since_sync = 0;
            }
        }
    }
    Ok(stats)
}

/// Random reader that tracks a growing visible frontier.
///
/// Used by `read_write_append`: yields until the writer has published at least
/// one full block, then samples uniformly below the current frontier.
pub(crate) async fn run_frontier_read_worker<B>(
    blob: B,
    deadline: Instant,
    io_size: usize,
    visible_len: Arc<AtomicU64>,
    seed: u64,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let mut stats = WorkerStats::default();
    let mut buffer = reusable_buffer(io_size);
    let mut state = seed;
    while should_continue(deadline, stats.ops) {
        let visible = visible_len.load(Ordering::Acquire);
        let total_blocks = visible / io_size as u64;
        if total_blocks == 0 {
            // Writer hasn't produced a full block yet; yield and retry.
            tokio::task::yield_now().await;
            continue;
        }

        let offset = next_random_block(&mut state, total_blocks) * io_size as u64;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        buffer = blob.read_at_buf(offset, io_size, buffer).await.str_err()?;
        black_box(touch_buffer(&buffer));
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), io_size as u64);
        } else {
            stats.record(io_size as u64);
        }
    }
    Ok(stats)
}

/// Divide `total_blocks` into `workers` non-overlapping shards.
pub(crate) fn build_worker_shards(
    total_blocks: u64,
    workers: usize,
) -> Result<Vec<BlockShard>, String> {
    if total_blocks < workers as u64 {
        return Err("not enough blocks to assign one random-write shard per worker".into());
    }

    let base = total_blocks / workers as u64;
    let remainder = total_blocks % workers as u64;
    let mut start_block = 0u64;
    let mut shards = Vec::with_capacity(workers);
    for worker_id in 0..workers as u64 {
        let blocks = base + u64::from(worker_id < remainder);
        shards.push(BlockShard {
            start_block,
            blocks,
        });
        start_block += blocks;
    }
    Ok(shards)
}

/// Advance a simple LCG and return a block index in `[0, total_blocks)`.
#[inline(always)]
pub(crate) const fn next_random_block(state: &mut u64, total_blocks: u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*state >> 32) % total_blocks
}

/// Derive a per-worker seed with good bit dispersion.
///
/// Uses the golden-ratio constant so workers with sequential IDs get
/// well-separated PRNG streams.
#[inline(always)]
pub(crate) const fn worker_seed(seed: u64, worker_id: usize) -> u64 {
    seed.wrapping_add((worker_id as u64).wrapping_mul(0x9E3779B97F4A7C15))
}

#[inline(always)]
fn reusable_buffer(size: usize) -> IoBufsMut {
    IoBufsMut::from(IoBufMut::with_capacity(size))
}

/// Touch the read buffer so the compiler cannot discard the I/O.
#[inline(always)]
fn touch_buffer(buf: &IoBufsMut) -> u8 {
    buf.as_single()
        .and_then(|chunk| chunk.as_ref().first())
        .copied()
        .unwrap_or_default()
}

#[inline(always)]
fn should_continue(deadline: Instant, completed_ops: u64) -> bool {
    if completed_ops.is_multiple_of(DEADLINE_CHECK_STRIDE) {
        Instant::now() < deadline
    } else {
        true
    }
}

#[inline(always)]
const fn should_sample_latency(completed_ops: u64) -> bool {
    completed_ops.is_multiple_of(LATENCY_SAMPLE_STRIDE)
}
