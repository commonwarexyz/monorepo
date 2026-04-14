//! Workload helpers shared across benchmark scenarios.

use crate::{
    config::{SyncMode, WriteShape},
    environment::{Environment, PARTITION},
    report::WorkerStats,
};
use bytes::{Buf, Bytes};
use commonware_runtime::{Blob, IoBuf, IoBufMut, IoBufs, IoBufsMut, Storage};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    hint::black_box,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

/// Large chunk used when initially populating fixed-size files.
const DEFAULT_FILL_CHUNK_SIZE: usize = 1024 * 1024;

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

/// Shape of a write payload reused by worker loops.
#[derive(Clone)]
pub(crate) enum WritePayload {
    /// Single-buffer write payload.
    Contiguous(Bytes),
    /// Four-buffer vectored write payload.
    Vectored(IoBufs),
}

impl WritePayload {
    /// Length of the logical write.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Contiguous(bytes) => bytes.len(),
            Self::Vectored(bufs) => bufs.remaining(),
        }
    }

    /// Clone and submit the payload to the target blob.
    pub(crate) async fn write_to<B>(&self, blob: &B, offset: u64) -> Result<(), String>
    where
        B: Blob,
    {
        match self {
            Self::Contiguous(bytes) => blob
                .write_at(offset, bytes.clone())
                .await
                .map_err(|err| err.to_string()),
            Self::Vectored(bufs) => blob
                .write_at(offset, bufs.clone())
                .await
                .map_err(|err| err.to_string()),
        }
    }
}

/// Partition of the block space assigned to one random-write worker.
pub(crate) struct BlockShard {
    /// Inclusive start block within the file.
    pub(crate) start_block: u64,
    /// Number of blocks owned by this shard.
    pub(crate) blocks: u64,
}

/// Create and fully populate a fixed-size blob for read-heavy scenarios.
pub(crate) async fn prepare_prefilled_blob<S>(
    storage: &S,
    environment: &Environment,
    name: &[u8],
    file_size: u64,
    seed: u64,
) -> Result<(), String>
where
    S: Storage,
{
    let (blob, _) = storage
        .open(PARTITION, name)
        .await
        .map_err(|err| err.to_string())?;
    blob.resize(file_size)
        .await
        .map_err(|err| err.to_string())?;
    blob.sync().await.map_err(|err| err.to_string())?;
    environment
        .preallocate_blob(PARTITION, name)
        .map_err(|err| {
            format!(
                "failed to preallocate {}: {err}",
                environment.root().display()
            )
        })?;

    let fill_chunk_size = DEFAULT_FILL_CHUNK_SIZE.max(crate::config::DEFAULT_IO_SIZE);
    let mut offset = 0u64;
    while offset < file_size {
        let remaining = (file_size - offset) as usize;
        let len = remaining.min(fill_chunk_size);
        let payload = payload_bytes(len, seed ^ offset);
        blob.write_at(offset, payload)
            .await
            .map_err(|err| err.to_string())?;
        offset += len as u64;
    }
    blob.sync().await.map_err(|err| err.to_string())?;
    Ok(())
}

/// Create a fixed-size preallocated blob for overwrite workloads.
pub(crate) async fn prepare_preallocated_blob<S>(
    storage: &S,
    environment: &Environment,
    name: &[u8],
    file_size: u64,
) -> Result<(), String>
where
    S: Storage,
{
    let (blob, _) = storage
        .open(PARTITION, name)
        .await
        .map_err(|err| err.to_string())?;
    blob.resize(file_size)
        .await
        .map_err(|err| err.to_string())?;
    blob.sync().await.map_err(|err| err.to_string())?;
    environment
        .preallocate_blob(PARTITION, name)
        .map_err(|err| {
            format!(
                "failed to preallocate {}: {err}",
                environment.root().display()
            )
        })?;
    Ok(())
}

/// Evict a blob from the page cache for a cold-cache benchmark.
pub(crate) fn prepare_cold_read_cache(
    environment: &Environment,
    name: &[u8],
) -> Result<(), String> {
    environment
        .evict_blob_cache(PARTITION, name)
        .map_err(|err| format!("failed to evict file cache: {err}"))?;
    Ok(())
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
    let mut buffer = reusable_buffer(io_size);
    let warm_ops = total_blocks.div_ceil(inflight as u64);
    let mut block = worker_id as u64 % total_blocks;
    for _ in 0..warm_ops {
        let offset = block * io_size as u64;
        buffer = blob
            .read_at_buf(offset, io_size, buffer)
            .await
            .map_err(|err| err.to_string())?;
        black_box(touch_buffer(&buffer) as u64);
        block = (block + inflight as u64) % total_blocks;
    }
    Ok(())
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
    let mut buffer = reusable_buffer(io_size);
    let mut state = seed;
    let warm_ops = total_blocks
        .saturating_mul(3)
        .div_ceil(inflight as u64)
        .max(1);
    for _ in 0..warm_ops {
        let block = next_random_block(&mut state, total_blocks);
        let offset = block * io_size as u64;
        buffer = blob
            .read_at_buf(offset, io_size, buffer)
            .await
            .map_err(|err| err.to_string())?;
        black_box(touch_buffer(&buffer) as u64);
    }
    Ok(())
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
    let mut stats = WorkerStats::default();
    let mut buffer = reusable_buffer(io_size);
    let mut block = worker_id as u64 % total_blocks;
    while should_continue(deadline, stats.ops) {
        let offset = block * io_size as u64;
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
        block = (block + inflight as u64) % total_blocks;
    }
    Ok(stats)
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
    let mut stats = WorkerStats::default();
    let mut buffer = reusable_buffer(io_size);
    let mut state = seed;
    while should_continue(deadline, stats.ops) {
        let block = next_random_block(&mut state, total_blocks);
        let offset = block * io_size as u64;
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

/// One sequential overwrite worker.
pub(crate) async fn run_sequential_write_worker<B>(
    blob: B,
    deadline: Instant,
    total_blocks: u64,
    worker_id: usize,
    inflight: usize,
    payload: WritePayload,
    sync_mode: SyncMode,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let mut stats = WorkerStats::default();
    let mut block = worker_id as u64 % total_blocks;
    let mut writes_since_sync = 0u64;
    let witness = payload.len() as u64;
    while should_continue(deadline, stats.ops) {
        let offset = block * payload.len() as u64;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        payload.write_to(&blob, offset).await?;
        writes_since_sync += 1;
        if let SyncMode::Every(every) = sync_mode {
            if writes_since_sync == every {
                blob.sync().await.map_err(|err| err.to_string())?;
                writes_since_sync = 0;
            }
        }
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), payload.len() as u64, witness);
        } else {
            stats.record(payload.len() as u64, witness);
        }
        block = (block + inflight as u64) % total_blocks;
    }
    Ok(stats)
}

/// One random overwrite worker over a non-overlapping shard.
pub(crate) async fn run_random_write_worker<B>(
    blob: B,
    deadline: Instant,
    shard: BlockShard,
    payload: WritePayload,
    sync_mode: SyncMode,
    seed: u64,
    io_size: usize,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let mut stats = WorkerStats::default();
    let mut state = seed;
    let mut writes_since_sync = 0u64;
    let witness = payload.len() as u64;
    while should_continue(deadline, stats.ops) {
        let local_block = next_random_block(&mut state, shard.blocks);
        let block = shard.start_block + local_block;
        let offset = block * io_size as u64;
        let started = should_sample_latency(stats.ops).then(Instant::now);
        payload.write_to(&blob, offset).await?;
        writes_since_sync += 1;
        if let SyncMode::Every(every) = sync_mode {
            if writes_since_sync == every {
                blob.sync().await.map_err(|err| err.to_string())?;
                writes_since_sync = 0;
            }
        }
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), payload.len() as u64, witness);
        } else {
            stats.record(payload.len() as u64, witness);
        }
    }
    Ok(stats)
}

/// Single append writer used by `write_append`.
pub(crate) async fn run_append_writer<B>(
    blob: B,
    deadline: Instant,
    starting_offset: u64,
    payload: WritePayload,
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
    payload: WritePayload,
    sync_mode: SyncMode,
    visible_len: Arc<AtomicU64>,
) -> Result<WorkerStats, String>
where
    B: Blob,
{
    let mut stats = WorkerStats::default();
    let mut writes_since_sync = 0u64;
    let mut offset = starting_offset;
    let witness = payload.len() as u64;
    while should_continue(deadline, stats.ops) {
        let started = should_sample_latency(stats.ops).then(Instant::now);
        payload.write_to(&blob, offset).await?;
        offset += payload.len() as u64;
        visible_len.store(offset, Ordering::Release);
        writes_since_sync += 1;
        if let SyncMode::Every(every) = sync_mode {
            if writes_since_sync == every {
                blob.sync().await.map_err(|err| err.to_string())?;
                writes_since_sync = 0;
            }
        }
        if let Some(started) = started {
            stats.record_latency_sample(started.elapsed(), payload.len() as u64, witness);
        } else {
            stats.record(payload.len() as u64, witness);
        }
    }
    Ok(stats)
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

        let block = next_random_block(&mut state, total_blocks);
        let offset = block * io_size as u64;
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

/// Build a write payload according to the configured shape.
pub(crate) fn create_write_payload(io_size: usize, seed: u64, shape: WriteShape) -> WritePayload {
    match shape {
        WriteShape::Contiguous => WritePayload::Contiguous(payload_bytes(io_size, seed)),
        WriteShape::Vectored => WritePayload::Vectored(vectored_payload(io_size, seed)),
    }
}

/// Create a deterministic contiguous payload.
fn payload_bytes(size: usize, seed: u64) -> Bytes {
    let mut bytes = vec![0u8; size];
    seeded_rng(size, seed).fill_bytes(&mut bytes);
    Bytes::from(bytes)
}

/// Create a deterministic four-buffer vectored payload.
fn vectored_payload(size: usize, seed: u64) -> IoBufs {
    const CHUNKS: usize = 4;
    let base = size / CHUNKS;
    let remainder = size % CHUNKS;
    let mut rng = seeded_rng(size, seed);
    let chunks = (0..CHUNKS)
        .map(|idx| {
            let len = base + usize::from(idx < remainder);
            let mut chunk = vec![0u8; len];
            rng.fill_bytes(&mut chunk);
            IoBuf::from(chunk)
        })
        .collect::<Vec<_>>();
    IoBufs::from(chunks)
}

/// Allocate a reusable read buffer.
fn reusable_buffer(size: usize) -> IoBufsMut {
    IoBufsMut::from(IoBufMut::with_capacity(size))
}

/// Touch the read buffer to prevent the compiler from discarding the read.
fn touch_buffer(buf: &IoBufsMut) -> u8 {
    buf.as_single()
        .and_then(|chunk| chunk.as_ref().first())
        .copied()
        .unwrap_or_default()
}

/// Deterministic random block selector.
const fn next_random_block(state: &mut u64, total_blocks: u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*state >> 32) % total_blocks
}

/// Deterministic RNG used for benchmark payloads.
fn seeded_rng(size: usize, discriminator: u64) -> StdRng {
    StdRng::seed_from_u64((size as u64).rotate_left(17) ^ discriminator)
}

/// Return whether another timed operation should begin.
fn should_continue(deadline: Instant, completed_ops: u64) -> bool {
    if completed_ops.is_multiple_of(DEADLINE_CHECK_STRIDE) {
        Instant::now() < deadline
    } else {
        true
    }
}

/// Return whether this operation should record a latency sample.
const fn should_sample_latency(completed_ops: u64) -> bool {
    completed_ops < EAGER_LATENCY_SAMPLES || completed_ops.is_multiple_of(LATENCY_SAMPLE_STRIDE)
}
