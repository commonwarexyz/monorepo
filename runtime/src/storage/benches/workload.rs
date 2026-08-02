//! Benchmark workload orchestration.

use crate::{
    config::{CacheMode, Config, SyncMode, Workload},
    error::Result,
    filesystem::{
        atomic_batch_protocol, atomic_protocol, drop_page_cache, file_metrics, group_file_metrics,
        prepare_atomic_blob, prepare_blob, prepare_filled_blob, random_write_payload,
        resident_set_size,
    },
    report::Report,
    runner::{
        RunLimit, WritePolicy, random_blocks, run_atomic_batch_append_loop, run_atomic_write_loop,
        run_multi_blob_append_loop, run_read_loop, run_sync_write_loop, run_write_loop,
        sequential_blocks, warm_read_loop,
    },
};
use commonware_runtime::{
    BatchOperation, BatchStorage as _, Blob as _, Storage as _, WriteOptions, tokio::Context,
};
use commonware_utils::TestRng;
use futures::{TryStreamExt, stream::FuturesUnordered};
use rand::{RngExt as _, SeedableRng, rngs::SmallRng};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

/// Storage partition used for all benchmark blobs.
const PARTITION: &str = "storage-bench";
/// Key for the single blob within the partition.
const BLOB_NAME: &[u8] = b"blob";
/// Temporary blob used to initialize the durable batch coordinator before timing.
const COORDINATOR_WARMUP_BLOB: &[u8] = b"coordinator-warmup";

type RuntimeBlob = <Context as commonware_runtime::Storage>::Blob;

fn write_policy(cfg: &Config) -> WritePolicy {
    let options = if cfg.dont_cache {
        WriteOptions::DONT_CACHE
    } else {
        WriteOptions::default()
    };
    WritePolicy::new(options, cfg.sync_mode)
}

fn run_limit(cfg: &Config, start: Instant) -> RunLimit {
    let deadline = if cfg.operations.is_some() {
        start
    } else {
        start + cfg.duration()
    };
    RunLimit::new(deadline, cfg.operations)
}

/// Run the configured benchmark workload and return the results.
pub async fn run_benchmark(cfg: &Config, context: Context) -> Result<Report> {
    let result = match cfg.workload {
        Workload::ReadSeq | Workload::ReadRand => run_read(cfg, &context).await,
        Workload::WriteSeq | Workload::WriteRand => run_overwrite(cfg, &context).await,
        Workload::WriteAppend => run_write_append(cfg, &context).await,
        Workload::WriteSync => run_write_sync(cfg, &context).await,
        Workload::WriteAtomic | Workload::WriteAtomicRand => run_write_atomic(cfg, &context).await,
        Workload::WriteAtomicAppend => run_write_atomic_append(cfg, &context).await,
        Workload::WriteMultiBlobAppend => run_write_multi_blob_append(cfg, &context).await,
        Workload::WriteAtomicBatchAppend => run_write_atomic_batch_append(cfg, &context).await,
        Workload::ReadWriteAppend => run_read_write_append(cfg, &context).await,
    };
    let result = result.and_then(|mut report| {
        let metrics = if cfg.workload.is_multi_blob_append() {
            group_file_metrics(
                &cfg.root,
                PARTITION,
                &multi_blob_names(cfg.blobs()),
                cfg.workload == Workload::WriteAtomicBatchAppend,
            )?
        } else {
            file_metrics(&cfg.root, PARTITION, BLOB_NAME)?
        };
        if let Some(metrics) = metrics {
            report.set_file_metrics(metrics);
        }
        if cfg.workload.is_atomic() {
            let protocol = if cfg.workload == Workload::WriteAtomicBatchAppend {
                atomic_batch_protocol()
            } else {
                atomic_protocol()
            };
            report.set_atomic_protocol(protocol);
        }
        Ok(report)
    });
    let _ = context.remove(PARTITION, None).await;
    result
}

/// Run a read-only workload (sequential or random).
async fn run_read(cfg: &Config, context: &Context) -> Result<Report> {
    let sequential = cfg.workload == Workload::ReadSeq;
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size() as u64;
    let inflight = cfg.inflight as u64;

    // Fill the blob with random data so reads return realistic content.
    let mut rng = TestRng::new(cfg.seed);
    let blob = prepare_filled_blob(
        &mut rng, context, &cfg.root, PARTITION, BLOB_NAME, file_size,
    )
    .await?;

    // Warm or cold the page cache before the timed phase.
    prepare_cache(cfg, &blob, total_blocks).await?;

    // Timed phase: drive multiple read futures concurrently from the current
    // task with `FuturesUnordered`.
    let start = Instant::now();
    let limit = run_limit(cfg, start);

    let workers = (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            async move {
                if sequential {
                    run_read_loop(
                        blob,
                        limit,
                        cfg.io_size(),
                        sequential_blocks(worker as u64 % total_blocks, inflight, total_blocks),
                    )
                    .await
                } else {
                    run_read_loop(
                        blob,
                        limit,
                        cfg.io_size(),
                        random_blocks(worker_seed(cfg.seed, worker), total_blocks),
                    )
                    .await
                }
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;

    Ok(Report::new(
        start.elapsed(),
        None,
        Some(workers),
        None,
        file_size,
    ))
}

/// Run a sequential or random overwrite workload on a fixed-size file.
async fn run_overwrite(cfg: &Config, context: &Context) -> Result<Report> {
    let rss_before = resident_set_size();
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size() as u64;
    let inflight = cfg.inflight as u64;
    let sequential = cfg.workload == Workload::WriteSeq;

    // Preallocate the blob so we measure steady-state write cost.
    let blob = prepare_blob(context, &cfg.root, PARTITION, BLOB_NAME, file_size).await?;
    let mut rng = TestRng::new(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size(), cfg.write_shape);

    // Timed phase: drive multiple write futures concurrently from the current
    // task with `FuturesUnordered`.
    let start = Instant::now();
    let limit = run_limit(cfg, start);

    let workers = (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            let payload = payload.clone();
            async move {
                if sequential {
                    run_write_loop(
                        blob,
                        limit,
                        cfg.io_size(),
                        payload,
                        write_policy(cfg),
                        sequential_blocks(worker as u64 % total_blocks, inflight, total_blocks),
                        |_| {},
                    )
                    .await
                } else {
                    run_write_loop(
                        blob,
                        limit,
                        cfg.io_size(),
                        payload,
                        write_policy(cfg),
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

    let hot_elapsed = start.elapsed();
    // `SyncMode::Every` flushes any partial tail in `run_write_loop`.
    // `SyncMode::End` still needs one final sync after all workers finish.
    let frontier_sync_elapsed = if cfg.sync_mode == SyncMode::End {
        let sync_started = Instant::now();
        blob.sync().await?;
        Some(sync_started.elapsed())
    } else {
        None
    };

    let mut report = Report::new(
        hot_elapsed,
        frontier_sync_elapsed,
        None,
        Some(workers),
        file_size,
    );
    report.set_resident_memory(rss_before, resident_set_size());
    Ok(report)
}

/// Run a single-writer append workload on a growing file.
async fn run_write_append(cfg: &Config, context: &Context) -> Result<Report> {
    let rss_before = resident_set_size();
    // Start from an empty blob.
    let blob = prepare_blob(context, &cfg.root, PARTITION, BLOB_NAME, 0).await?;
    let mut rng = TestRng::new(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size(), cfg.write_shape);

    // Timed phase: single writer appending sequentially.
    let start = Instant::now();
    let limit = run_limit(cfg, start);

    let stats = run_write_loop(
        blob.clone(),
        limit,
        cfg.io_size(),
        payload,
        write_policy(cfg),
        sequential_blocks(0, 1, u64::MAX),
        |_| {},
    )
    .await?;

    let hot_elapsed = start.elapsed();
    // `SyncMode::Every` flushes any partial tail in `run_write_loop`.
    // `SyncMode::End` still needs one final sync after the writer finishes.
    let frontier_sync_elapsed = if cfg.sync_mode == SyncMode::End {
        let sync_started = Instant::now();
        blob.sync().await?;
        Some(sync_started.elapsed())
    } else {
        None
    };

    let final_file_size = stats.bytes;
    let mut report = Report::new(
        hot_elapsed,
        frontier_sync_elapsed,
        None,
        Some(vec![stats]),
        final_file_size,
    );
    report.set_resident_memory(rss_before, resident_set_size());
    Ok(report)
}

/// Run sequential durable positioned writes on a fixed-size file.
async fn run_write_sync(cfg: &Config, context: &Context) -> Result<Report> {
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size() as u64;
    let inflight = cfg.inflight as u64;

    // Preallocate the blob so we measure steady-state write cost.
    let blob = prepare_blob(context, &cfg.root, PARTITION, BLOB_NAME, file_size).await?;
    let mut rng = TestRng::new(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size(), cfg.write_shape);

    let start = Instant::now();
    let limit = run_limit(cfg, start);

    // Timed phase: drive multiple sequential durable write futures concurrently
    // from the current task with `FuturesUnordered`.
    let workers = (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            let payload = payload.clone();
            async move {
                run_sync_write_loop(
                    blob,
                    limit,
                    cfg.io_size(),
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

    Ok(Report::new(
        start.elapsed(),
        None,
        None,
        Some(workers),
        file_size,
    ))
}

/// Run sequential atomic positioned writes on a fixed-size file.
async fn run_write_atomic(cfg: &Config, context: &Context) -> Result<Report> {
    let rss_before = resident_set_size();
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size() as u64;
    let inflight = cfg.inflight as u64;
    let sequential = cfg.workload == Workload::WriteAtomic;

    let blob = prepare_atomic_blob(context, &cfg.root, PARTITION, BLOB_NAME, file_size).await?;
    let mut rng = TestRng::new(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size(), cfg.write_shape);

    let start = Instant::now();
    let limit = run_limit(cfg, start);
    let workers = (0..cfg.inflight)
        .map(|worker| {
            let blob = blob.clone();
            let payload = payload.clone();
            async move {
                if sequential {
                    run_atomic_write_loop(
                        blob,
                        limit,
                        cfg.io_size(),
                        payload,
                        file_size,
                        cfg.sync_mode,
                        sequential_blocks(worker as u64 % total_blocks, inflight, total_blocks),
                    )
                    .await
                } else {
                    run_atomic_write_loop(
                        blob,
                        limit,
                        cfg.io_size(),
                        payload,
                        file_size,
                        cfg.sync_mode,
                        random_blocks(worker_seed(cfg.seed, worker), total_blocks),
                    )
                    .await
                }
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;

    let hot_elapsed = start.elapsed();
    let frontier_sync_elapsed = if cfg.sync_mode == SyncMode::End {
        let sync_started = Instant::now();
        blob.sync().await?;
        Some(sync_started.elapsed())
    } else {
        None
    };

    let mut report = Report::new(
        hot_elapsed,
        frontier_sync_elapsed,
        None,
        Some(workers),
        file_size,
    );
    report.set_resident_memory(rss_before, resident_set_size());
    Ok(report)
}

/// Run append writes through the atomic protocol on a growing file.
async fn run_write_atomic_append(cfg: &Config, context: &Context) -> Result<Report> {
    let rss_before = resident_set_size();
    let blob = prepare_atomic_blob(context, &cfg.root, PARTITION, BLOB_NAME, 0).await?;
    let mut rng = TestRng::new(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size(), cfg.write_shape);

    let start = Instant::now();
    let limit = run_limit(cfg, start);
    // Use the same Blob::write_at interface as the ordinary append workload so this comparison
    // isolates the cost of the R05 protocol used by existing buffered writers and journals.
    let stats = run_write_loop(
        blob.clone(),
        limit,
        cfg.io_size(),
        payload,
        write_policy(cfg),
        sequential_blocks(0, 1, u64::MAX),
        |_| {},
    )
    .await?;
    let final_file_size = stats.bytes;

    let hot_elapsed = start.elapsed();
    let frontier_sync_elapsed = if cfg.sync_mode == SyncMode::End {
        let sync_started = Instant::now();
        blob.sync().await?;
        Some(sync_started.elapsed())
    } else {
        None
    };

    let mut report = Report::new(
        hot_elapsed,
        frontier_sync_elapsed,
        None,
        Some(vec![stats]),
        final_file_size,
    );
    report.set_resident_memory(rss_before, resident_set_size());
    Ok(report)
}

/// Run durable append groups across multiple ordinary blobs.
async fn run_write_multi_blob_append(cfg: &Config, context: &Context) -> Result<Report> {
    let rss_before = resident_set_size();
    let names = multi_blob_names(cfg.blobs());
    let blobs = names
        .iter()
        .map(|name| prepare_blob(context, &cfg.root, PARTITION, name, 0))
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;
    let mut rng = TestRng::new(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size(), cfg.write_shape);

    let start = Instant::now();
    let limit = run_limit(cfg, start);
    let stats = run_multi_blob_append_loop(&blobs, limit, cfg.io_size(), payload).await?;
    let hot_elapsed = start.elapsed();
    let final_file_size = stats.bytes;

    let mut report = Report::new(hot_elapsed, None, None, Some(vec![stats]), final_file_size);
    report.set_resident_memory(rss_before, resident_set_size());
    Ok(report)
}

/// Run atomic append groups across multiple blobs through one coordinator decision.
async fn run_write_atomic_batch_append(cfg: &Config, context: &Context) -> Result<Report> {
    let rss_before = resident_set_size();
    let names = multi_blob_names(cfg.blobs());
    let blobs = names
        .iter()
        .map(|name| prepare_atomic_blob(context, &cfg.root, PARTITION, name, 0))
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>()
        .await?;
    warm_batch_coordinator(context, &cfg.root).await?;

    let mut rng = TestRng::new(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size(), cfg.write_shape);
    let start = Instant::now();
    let limit = run_limit(cfg, start);
    let stats =
        run_atomic_batch_append_loop(context, &blobs, limit, cfg.io_size(), payload).await?;
    let hot_elapsed = start.elapsed();
    let final_file_size = stats.bytes;

    let mut report = Report::new(hot_elapsed, None, None, Some(vec![stats]), final_file_size);
    report.set_resident_memory(rss_before, resident_set_size());
    Ok(report)
}

/// Force one-time coordinator creation and its first complete decision outside the timed phase.
async fn warm_batch_coordinator(context: &Context, root: &Path) -> Result<()> {
    let blob = prepare_atomic_blob(context, root, PARTITION, COORDINATOR_WARMUP_BLOB, 0).await?;
    blob.write_at(0, vec![0u8], WriteOptions::default()).await?;
    context
        .apply(vec![BatchOperation::Publish(blob.clone())])
        .await?;
    drop(blob);
    context
        .remove(PARTITION, Some(COORDINATOR_WARMUP_BLOB))
        .await?;
    Ok(())
}

fn multi_blob_names(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| format!("blob-{index:08}").into_bytes())
        .collect()
}

/// Run one append writer plus concurrent random readers.
///
/// Readers sample uniformly from the visible prefix, which grows as the
/// writer appends blocks.
async fn run_read_write_append(cfg: &Config, context: &Context) -> Result<Report> {
    let initial_size = cfg.file_size();
    let total_blocks = initial_size / cfg.io_size() as u64;
    let io_size = cfg.io_size() as u64;

    // Fill the initial region so readers have data from the start.
    let mut rng = TestRng::new(cfg.seed);
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

    let payload = random_write_payload(&mut rng, cfg.io_size(), cfg.write_shape);

    // Tracks how far the writer has gotten so readers stay within bounds.
    let current_len = Arc::new(AtomicU64::new(initial_size));

    // Timed phase: one writer + concurrent readers.
    let start = Instant::now();
    let limit = run_limit(cfg, start);

    // Writer appends blocks past the initial region, publishing the new
    // current length after each write so readers can expand their range.
    let writer = {
        let blob = blob.clone();
        let current_len = current_len.clone();
        async move {
            run_write_loop(
                blob,
                limit,
                cfg.io_size(),
                payload,
                write_policy(cfg),
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
                    rng.random_range(0..total_blocks)
                };
                run_read_loop(blob, limit, cfg.io_size(), random_block).await
            }
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<_>>();

    let (write_stats, read_workers) = futures::try_join!(writer, readers)?;

    // `SyncMode::Every` flushes any partial tail in `run_write_loop`.
    // `SyncMode::End` still needs one final sync after the writer finishes.
    let final_file_size = initial_size + write_stats.bytes;
    let hot_elapsed = start.elapsed();
    let frontier_sync_elapsed = if cfg.sync_mode == SyncMode::End {
        let sync_started = Instant::now();
        blob.sync().await?;
        Some(sync_started.elapsed())
    } else {
        None
    };

    Ok(Report::new(
        hot_elapsed,
        frontier_sync_elapsed,
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
                        cfg.io_size(),
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
                        cfg.io_size(),
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

#[cfg(test)]
#[allow(dead_code, unused_imports)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn fixed_operations_do_not_construct_a_duration_deadline() {
        let cfg = Config::try_parse_from([
            "storage_bench",
            "--workload",
            "write_append",
            "--operations",
            "1",
            "--duration",
            &u64::MAX.to_string(),
        ])
        .unwrap();

        let _ = run_limit(&cfg, Instant::now());
    }
}
