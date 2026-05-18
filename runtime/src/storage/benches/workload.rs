//! Benchmark workload orchestration.

use crate::{
    config::{CacheMode, Config, SyncMode, Workload},
    error::Result,
    filesystem::{drop_page_cache, prepare_blob, prepare_filled_blob, random_write_payload},
    report::Report,
    runner::{
        random_blocks, run_read_loop, run_sync_write_loop, run_write_loop, sequential_blocks,
        warm_read_loop,
    },
};
use commonware_runtime::{tokio::Context, Blob as _, Storage as _};
use futures::{stream::FuturesUnordered, TryStreamExt};
use rand::{
    rngs::{SmallRng, StdRng},
    Rng, SeedableRng,
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

/// Storage partition used for all benchmark blobs.
const PARTITION: &str = "storage-bench";
/// Key for the single blob within the partition.
const BLOB_NAME: &[u8] = b"blob";

type RuntimeBlob = <Context as commonware_runtime::Storage>::Blob;

/// Run the configured benchmark workload and return the results.
pub async fn run_benchmark(cfg: &Config, context: Context) -> Result<Report> {
    let result = match cfg.workload {
        Workload::ReadSeq | Workload::ReadRand => run_read(cfg, &context).await,
        Workload::WriteSeq | Workload::WriteRand => run_overwrite(cfg, &context).await,
        Workload::WriteAppend => run_write_append(cfg, &context).await,
        Workload::WriteSync => run_write_sync(cfg, &context).await,
        Workload::ReadWriteAppend => run_read_write_append(cfg, &context).await,
    };
    let _ = context.remove(PARTITION, None).await;
    result
}

/// Run a read-only workload (sequential or random).
async fn run_read(cfg: &Config, context: &Context) -> Result<Report> {
    let sequential = cfg.workload == Workload::ReadSeq;
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size as u64;
    let inflight = cfg.inflight as u64;

    // Fill the blob with random data so reads return realistic content.
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let blob = prepare_filled_blob(
        &mut rng, context, &cfg.root, PARTITION, BLOB_NAME, file_size,
    )
    .await?;

    // Warm or cold the page cache before the timed phase.
    prepare_cache(cfg, &blob, total_blocks).await?;

    // Timed phase: drive multiple read futures concurrently from the current
    // task with `FuturesUnordered`.
    let start = Instant::now();
    let deadline = start + cfg.duration();

    let workers = (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            async move {
                if sequential {
                    run_read_loop(
                        blob,
                        deadline,
                        cfg.io_size,
                        sequential_blocks(worker as u64 % total_blocks, inflight, total_blocks),
                    )
                    .await
                } else {
                    run_read_loop(
                        blob,
                        deadline,
                        cfg.io_size,
                        random_blocks(worker_seed(cfg.seed, worker), total_blocks),
                    )
                    .await
                }
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;

    Ok(Report::new(start.elapsed(), Some(workers), None, file_size))
}

/// Run a sequential or random overwrite workload on a fixed-size file.
async fn run_overwrite(cfg: &Config, context: &Context) -> Result<Report> {
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size as u64;
    let inflight = cfg.inflight as u64;
    let sequential = cfg.workload == Workload::WriteSeq;

    // Preallocate the blob so we measure steady-state write cost.
    let blob = prepare_blob(context, &cfg.root, PARTITION, BLOB_NAME, file_size).await?;
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size, cfg.write_shape);

    // Timed phase: drive multiple write futures concurrently from the current
    // task with `FuturesUnordered`.
    let start = Instant::now();
    let deadline = start + cfg.duration();

    let workers = (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            let payload = payload.clone();
            async move {
                if sequential {
                    run_write_loop(
                        blob,
                        deadline,
                        cfg.io_size,
                        payload,
                        cfg.sync_mode,
                        sequential_blocks(worker as u64 % total_blocks, inflight, total_blocks),
                        |_| {},
                    )
                    .await
                } else {
                    run_write_loop(
                        blob,
                        deadline,
                        cfg.io_size,
                        payload,
                        cfg.sync_mode,
                        random_blocks(worker_seed(cfg.seed, worker), total_blocks),
                        |_| {},
                    )
                    .await
                }
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;

    // `SyncMode::Every` flushes any partial tail in `run_write_loop`.
    // `SyncMode::End` still needs one final sync after all workers finish.
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await?;
    }

    Ok(Report::new(start.elapsed(), None, Some(workers), file_size))
}

/// Run durable positioned writes on a fixed-size file.
async fn run_write_sync(cfg: &Config, context: &Context) -> Result<Report> {
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size as u64;
    let inflight = cfg.inflight as u64;

    let blob = prepare_blob(context, &cfg.root, PARTITION, BLOB_NAME, file_size).await?;
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size, cfg.write_shape);

    let start = Instant::now();
    let deadline = start + cfg.duration();

    let workers = (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            let payload = payload.clone();
            async move {
                run_sync_write_loop(
                    blob,
                    deadline,
                    cfg.io_size,
                    payload,
                    cfg.sync_method,
                    sequential_blocks(worker as u64 % total_blocks, inflight, total_blocks),
                )
                .await
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;

    Ok(Report::new(start.elapsed(), None, Some(workers), file_size))
}

/// Run a single-writer append workload on a growing file.
async fn run_write_append(cfg: &Config, context: &Context) -> Result<Report> {
    // Start from an empty blob.
    let blob = prepare_blob(context, &cfg.root, PARTITION, BLOB_NAME, 0).await?;
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size, cfg.write_shape);

    // Timed phase: single writer appending sequentially.
    let start = Instant::now();
    let deadline = start + cfg.duration();

    let stats = run_write_loop(
        blob.clone(),
        deadline,
        cfg.io_size,
        payload,
        cfg.sync_mode,
        sequential_blocks(0, 1, u64::MAX),
        |_| {},
    )
    .await?;

    // `SyncMode::Every` flushes any partial tail in `run_write_loop`.
    // `SyncMode::End` still needs one final sync after the writer finishes.
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await?;
    }

    let final_file_size = stats.bytes;
    Ok(Report::new(
        start.elapsed(),
        None,
        Some(vec![stats]),
        final_file_size,
    ))
}

/// Run one append writer plus concurrent random readers.
///
/// Readers sample uniformly from the visible prefix, which grows as the
/// writer appends blocks.
async fn run_read_write_append(cfg: &Config, context: &Context) -> Result<Report> {
    let initial_size = cfg.file_size();
    let total_blocks = initial_size / cfg.io_size as u64;
    let io_size = cfg.io_size as u64;

    // Fill the initial region so readers have data from the start.
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let blob = prepare_filled_blob(
        &mut rng,
        context,
        &cfg.root,
        PARTITION,
        BLOB_NAME,
        initial_size,
    )
    .await?;
    prepare_cache(cfg, &blob, total_blocks).await?;

    let payload = random_write_payload(&mut rng, cfg.io_size, cfg.write_shape);

    // Tracks how far the writer has gotten so readers stay within bounds.
    let current_len = Arc::new(AtomicU64::new(initial_size));

    // Timed phase: one writer + concurrent readers.
    let start = Instant::now();
    let deadline = start + cfg.duration();

    // Writer appends blocks past the initial region, publishing the new
    // current length after each write so readers can expand their range.
    let writer = {
        let blob = blob.clone();
        let current_len = current_len.clone();
        async move {
            run_write_loop(
                blob,
                deadline,
                cfg.io_size,
                payload,
                cfg.sync_mode,
                sequential_blocks(total_blocks, 1, u64::MAX),
                |end_offset| current_len.store(end_offset, Ordering::Relaxed),
            )
            .await
        }
    };

    // Readers sample random blocks from the currently visible prefix.
    let readers = (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            let current_len = current_len.clone();
            let mut rng = SmallRng::seed_from_u64(worker_seed(cfg.seed, worker));
            async move {
                let random_block = || {
                    let total_blocks = current_len.load(Ordering::Relaxed) / io_size;
                    rng.gen_range(0..total_blocks)
                };
                run_read_loop(blob, deadline, cfg.io_size, random_block).await
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>();

    let (write_stats, read_workers) = futures::try_join!(writer, readers)?;

    // `SyncMode::Every` flushes any partial tail in `run_write_loop`.
    // `SyncMode::End` still needs one final sync after the writer finishes.
    let final_file_size = initial_size + write_stats.bytes;
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await?;
    }

    Ok(Report::new(
        start.elapsed(),
        Some(read_workers),
        Some(vec![write_stats]),
        final_file_size,
    ))
}

/// Prepare the page cache before the timed phase.
///
/// In `Warm` mode, workers read through the file to pull pages into cache.
/// In `Cold` mode, `posix_fadvise(DONTNEED)` evicts cached pages.
async fn prepare_cache(cfg: &Config, blob: &RuntimeBlob, total_blocks: u64) -> Result<()> {
    let cache = cfg.cache.expect("validated");

    // Evict cached pages so the timed phase starts from disk.
    if cache == CacheMode::Cold {
        drop_page_cache(&cfg.root, PARTITION, BLOB_NAME)?;
        return Ok(());
    }

    // Warm: read through the file to pull pages into cache.
    let inflight = cfg.inflight as u64;
    let sequential = cfg.workload == Workload::ReadSeq;
    (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            async move {
                if sequential {
                    // Each worker covers a strided slice of the file.
                    let warm_ops = total_blocks.div_ceil(inflight);
                    warm_read_loop(
                        blob,
                        cfg.io_size,
                        warm_ops,
                        sequential_blocks(worker as u64 % total_blocks, inflight, total_blocks),
                    )
                    .await
                } else {
                    // 3 * total_blocks random reads across all workers:
                    // each page has (1 - 1/total_blocks)^(3*total_blocks)
                    // ~ e^-3 ~ 5% chance of being missed. Stragglers warm
                    // in the first seconds of the timed phase. Only holds
                    // when the file fits in RAM, otherwise the OS evicts
                    // pages as fast as we warm them.
                    let warm_ops = total_blocks.saturating_mul(3).div_ceil(inflight).max(1);
                    warm_read_loop(
                        blob,
                        cfg.io_size,
                        warm_ops,
                        random_blocks(worker_seed(cfg.seed, worker), total_blocks),
                    )
                    .await
                }
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;

    Ok(())
}

#[inline]
const fn worker_seed(seed: u64, worker: usize) -> u64 {
    seed.wrapping_add(worker as u64)
}
