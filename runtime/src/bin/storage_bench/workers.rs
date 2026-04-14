//! Worker loops for `storage_bench`.

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

/// Number of operations between deadline checks in the timed worker loops.
///
/// Checking the clock on every operation noticeably perturbs hot-cache runs, so
/// the workers only refresh the deadline state every few iterations. This can
/// overshoot the requested duration by a handful of operations, which is much
/// smaller than the per-op timestamping cost the benchmark would otherwise pay.
const DEADLINE_CHECK_STRIDE: u64 = 8;

/// Number of operations that retain every latency sample before decimation.
const EAGER_LATENCY_SAMPLES: u64 = 256;

/// Sampling stride used once the eager latency-sample window has been filled.
const LATENCY_SAMPLE_STRIDE: u64 = 64;

/// Partition of the block space assigned to one random-write worker.
pub(crate) struct BlockShard {
    /// Inclusive start block within the file.
    pub(crate) start_block: u64,
    /// Number of blocks owned by this shard.
    pub(crate) blocks: u64,
}

/// Warm a sequential-read workload by replaying one full strided pass.
pub(crate) async fn warm_sequential_read_worker<B>(
    blob: B,
    io_size: usize,
    total_blocks: u64,
    worker_id: usize,
    inflight: usize,
) -> Result<(), String>
where
    B: Blob,
{
    let mut block = worker_id as u64 % total_blocks;
    let warm_ops = total_blocks.div_ceil(inflight as u64);
    warm_read_loop(blob, io_size, warm_ops, || {
        let current = block;
        block = (block + inflight as u64) % total_blocks;
        current
    })
    .await
}

/// Warm a random-read workload by replaying a deterministic random trace.
///
/// The warm-up performs several file-sized worth of random reads so the timed
/// phase is much more likely to revisit already-cached pages when the working
/// set fits in memory.
pub(crate) async fn warm_random_read_worker<B>(
    blob: B,
    io_size: usize,
    total_blocks: u64,
    seed: u64,
    inflight: usize,
) -> Result<(), String>
where
    B: Blob,
{
    let mut state = seed;
    let warm_ops = total_blocks
        .saturating_mul(3)
        .div_ceil(inflight as u64)
        .max(1);
    warm_read_loop(blob, io_size, warm_ops, || {
        next_random_block(&mut state, total_blocks)
    })
    .await
}

/// One sequential read worker.
pub(crate) async fn run_sequential_read_worker<B>(
    blob: B,
    deadline: Instant,
    io_size: usize,
    total_blocks: u64,
    worker_id: usize,
    inflight: usize,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let mut block = worker_id as u64 % total_blocks;
    run_read_loop(blob, deadline, io_size, || {
        let current = block;
        block = (block + inflight as u64) % total_blocks;
        current
    })
    .await
}

/// One random read worker.
pub(crate) async fn run_random_read_worker<B>(
    blob: B,
    deadline: Instant,
    io_size: usize,
    total_blocks: u64,
    seed: u64,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let mut state = seed;
    run_read_loop(blob, deadline, io_size, || {
        next_random_block(&mut state, total_blocks)
    })
    .await
}

/// One sequential overwrite worker.
pub(crate) async fn run_sequential_write_worker<B>(
    blob: B,
    deadline: Instant,
    total_blocks: u64,
    worker_id: usize,
    inflight: usize,
    payload: IoBufs,
    sync_mode: SyncMode,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let payload_len = payload.remaining() as u64;
    let mut block = worker_id as u64 % total_blocks;
    run_write_loop(
        blob,
        deadline,
        payload,
        sync_mode,
        || {
            let offset = block * payload_len;
            block = (block + inflight as u64) % total_blocks;
            offset
        },
        |_| {},
    )
    .await
}

/// One random overwrite worker over a non-overlapping shard.
pub(crate) async fn run_random_write_worker<B>(
    blob: B,
    deadline: Instant,
    shard: BlockShard,
    payload: IoBufs,
    sync_mode: SyncMode,
    seed: u64,
    io_size: usize,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let mut state = seed;
    run_write_loop(
        blob,
        deadline,
        payload,
        sync_mode,
        || {
            let local_block = next_random_block(&mut state, shard.blocks);
            let block = shard.start_block + local_block;
            block * io_size as u64
        },
        |_| {},
    )
    .await
}

/// Single append writer used by `write_append`.
pub(crate) async fn run_append_writer<B>(
    blob: B,
    deadline: Instant,
    starting_offset: u64,
    payload: IoBufs,
    sync_mode: SyncMode,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    run_append_writer_with_frontier(
        blob,
        deadline,
        starting_offset,
        payload,
        sync_mode,
        Arc::new(AtomicU64::new(starting_offset)),
    )
    .await
}

/// Single append writer that also publishes a visible frontier for readers.
pub(crate) async fn run_append_writer_with_frontier<B>(
    blob: B,
    deadline: Instant,
    starting_offset: u64,
    payload: IoBufs,
    sync_mode: SyncMode,
    visible_len: Arc<AtomicU64>,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let payload_len = payload.remaining() as u64;
    let mut offset = starting_offset;
    run_write_loop(
        blob,
        deadline,
        payload,
        sync_mode,
        || {
            let current = offset;
            offset += payload_len;
            current
        },
        |end_offset| {
            visible_len.store(end_offset, Ordering::Release);
        },
    )
    .await
}

/// Random reader that tracks the append writer's published frontier.
pub(crate) async fn run_frontier_random_read_worker<B>(
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
            tokio::task::yield_now().await;
            continue;
        }

        let offset = next_random_block(&mut state, total_blocks) * io_size as u64;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        buffer = blob
            .read_at_buf(offset, io_size, buffer)
            .await
            .map_err(|err| err.to_string())?;
        let witness = touch_buffer(&buffer) as u64;
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), io_size as u64, witness);
        } else {
            stats.record(io_size as u64, witness);
        }
    }
    Ok(stats)
}

/// Build one non-empty random-write shard per worker.
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

/// Warm a read trace without collecting benchmark statistics.
#[inline]
async fn warm_read_loop<B, F>(
    blob: B,
    io_size: usize,
    warm_ops: u64,
    mut next_block: F,
) -> Result<(), String>
where
    B: Blob,
    F: FnMut() -> u64,
{
    let mut buffer = reusable_buffer(io_size);
    for _ in 0..warm_ops {
        let offset = next_block() * io_size as u64;
        buffer = blob
            .read_at_buf(offset, io_size, buffer)
            .await
            .map_err(|err| err.to_string())?;
        black_box(touch_buffer(&buffer) as u64);
    }
    Ok(())
}

/// Run a timed read loop and collect sampled latency statistics.
#[inline]
async fn run_read_loop<B, F>(
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
        buffer = blob
            .read_at_buf(offset, io_size, buffer)
            .await
            .map_err(|err| err.to_string())?;
        let witness = touch_buffer(&buffer) as u64;
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), io_size as u64, witness);
        } else {
            stats.record(io_size as u64, witness);
        }
    }
    Ok(stats)
}

/// Run a timed write loop with caller-defined offset selection.
#[inline]
async fn run_write_loop<B, F, G>(
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
    let witness = payload_len as u64;
    while should_continue(deadline, stats.ops) {
        let offset = next_offset();
        let started = should_sample_latency(stats.ops).then(Instant::now);
        blob.write_at(offset, payload.clone())
            .await
            .map_err(|err| err.to_string())?;
        after_write(offset + payload_len as u64);
        writes_since_sync += 1;
        if let SyncMode::Every(every) = sync_mode {
            if writes_since_sync == every {
                blob.sync().await.map_err(|err| err.to_string())?;
                writes_since_sync = 0;
            }
        }
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), payload_len as u64, witness);
        } else {
            stats.record(payload_len as u64, witness);
        }
    }
    Ok(stats)
}

/// Allocate a reusable read buffer.
#[inline(always)]
fn reusable_buffer(size: usize) -> IoBufsMut {
    IoBufsMut::from(IoBufMut::with_capacity(size))
}

/// Touch the read buffer to prevent the compiler from discarding the read.
#[inline(always)]
fn touch_buffer(buf: &IoBufsMut) -> u8 {
    buf.as_single()
        .and_then(|chunk| chunk.as_ref().first())
        .copied()
        .unwrap_or_default()
}

/// Deterministic random block selector.
#[inline(always)]
const fn next_random_block(state: &mut u64, total_blocks: u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*state >> 32) % total_blocks
}

/// Return whether another timed operation should begin.
#[inline(always)]
fn should_continue(deadline: Instant, completed_ops: u64) -> bool {
    if completed_ops.is_multiple_of(DEADLINE_CHECK_STRIDE) {
        Instant::now() < deadline
    } else {
        true
    }
}

/// Return whether this operation should record a latency sample.
#[inline(always)]
const fn should_sample_latency(completed_ops: u64) -> bool {
    completed_ops < EAGER_LATENCY_SAMPLES || completed_ops.is_multiple_of(LATENCY_SAMPLE_STRIDE)
}
