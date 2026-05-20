//! Timed I/O loops and helpers.

use crate::{
    config::{SyncMethod, SyncMode},
    error::Result,
    report::Stats,
};
use commonware_runtime::{Blob, IoBufMut, IoBufs};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use std::time::Instant;

/// Operations between deadline checks.
///
/// Checking the clock on every operation noticeably perturbs hot-cache runs.
/// Workers only poll the deadline every N iterations, this can overshoot the
/// requested duration by up to N operations per worker.
const DEADLINE_CHECK_STRIDE: u64 = 8;

/// Operations between latency samples.
///
/// A constant stride avoids front-biasing the latency distribution. At typical
/// throughput rates this yields thousands of samples per second while keeping
/// `Instant::now()` overhead well below 1% of per-operation cost.
const LATENCY_SAMPLE_STRIDE: u64 = 16;

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
    move || rng.gen_range(0..total_blocks)
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
    deadline: Instant,
    io_size: usize,
    mut next_block: impl FnMut() -> u64,
) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut buffer = IoBufMut::with_capacity(io_size).into();
    while should_continue(deadline, stats.ops) {
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
    deadline: Instant,
    io_size: usize,
    payload: IoBufs,
    sync_mode: SyncMode,
    mut next_block: impl FnMut() -> u64,
    mut after_write: impl FnMut(u64),
) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut writes_since_sync = 0u64;
    let io_size = io_size as u64;
    while should_continue(deadline, stats.ops) {
        let offset = next_block() * io_size;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        blob.write_at(offset, payload.clone()).await?;

        // Record latency before sync so percentiles reflect pure write cost.
        stats.record(io_size, started.map(|s| s.elapsed()));

        after_write(offset + io_size);
        writes_since_sync += 1;
        if let SyncMode::Every(every) = sync_mode {
            if writes_since_sync == every {
                blob.sync().await?;
                writes_since_sync = 0;
            }
        }
    }

    // Flush the last partial batch so `SyncMode::Every` reports only durable
    // writes even when the timed phase ends mid-batch.
    if matches!(sync_mode, SyncMode::Every(_)) && writes_since_sync != 0 {
        blob.sync().await?;
    }

    Ok(stats)
}

/// Timed durable write loop with caller-defined offset selection.
#[inline]
pub async fn run_sync_write_loop(
    blob: impl Blob,
    deadline: Instant,
    io_size: usize,
    payload: IoBufs,
    sync_method: SyncMethod,
    mut next_block: impl FnMut() -> u64,
) -> Result<Stats> {
    let mut stats = Stats::default();
    let io_size = io_size as u64;
    while should_continue(deadline, stats.ops) {
        let offset = next_block() * io_size;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        match sync_method {
            SyncMethod::WriteThenSync => {
                blob.write_at(offset, payload.clone()).await?;
                blob.sync().await?;
            }
            SyncMethod::WriteAtSync => {
                blob.write_at_sync(offset, payload.clone()).await?;
            }
        }
        stats.record(io_size, started.map(|s| s.elapsed()));
    }
    Ok(stats)
}

/// Check whether the timed loop should keep running.
///
/// Only polls the clock every `DEADLINE_CHECK_STRIDE` operations to avoid
/// perturbing hot-cache benchmarks with frequent `Instant::now()` calls.
#[inline(always)]
fn should_continue(deadline: Instant, completed_ops: u64) -> bool {
    if completed_ops.is_multiple_of(DEADLINE_CHECK_STRIDE) {
        Instant::now() < deadline
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
