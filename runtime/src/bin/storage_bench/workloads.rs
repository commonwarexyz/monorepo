//! Benchmark workload orchestration for `storage_bench`.

use crate::{
    config::{CacheMode, Config, Scenario, SyncMode},
    filesystem::{random_write_payload, drop_page_cache, prepare_blob, prepare_filled_blob},
    report::{merge_worker_results, summarize_operation, ScenarioReport, WorkerStats},
    workers::{
        build_worker_shards, next_random_block, run_frontier_read_worker, run_read_loop,
        run_write_loop, sequential_blocks, warm_read_loop, worker_seed, ResultExt,
    },
};
use commonware_runtime::{tokio::Context, Blob as _, Storage as _};
use futures::future::join_all;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

type RuntimeBlob = <Context as commonware_runtime::Storage>::Blob;

/// Run the configured benchmark scenario and return the results.
pub async fn run_benchmark(
    cfg: &Config,
    root: &Path,
    context: Context,
) -> Result<ScenarioReport, String> {
    let result = match cfg.scenario {
        Scenario::ReadSeq | Scenario::ReadRand => run_read(cfg, root, &context).await,
        Scenario::WriteSeq | Scenario::WriteRand => run_overwrite(cfg, root, &context).await,
        Scenario::WriteAppend => run_write_append(cfg, &context).await,
        Scenario::ReadWriteAppend => run_read_write_append(cfg, root, &context).await,
    };
    let _ = context.remove("storage-bench", None).await;
    result
}

async fn run_read(cfg: &Config, root: &Path, context: &Context) -> Result<ScenarioReport, String> {
    let sequential = cfg.scenario == Scenario::ReadSeq;
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size as u64;
    let inflight = cfg.inflight as u64;

    let blob =
        prepare_filled_blob(context, root, "storage-bench", b"blob", file_size, cfg.seed).await?;
    warm_cache(cfg, root, &blob, total_blocks).await?;

    let start = Instant::now();
    let deadline = start + cfg.duration();

    let workers = join_all((0..cfg.inflight).map(|wid| {
        let blob = blob.clone();
        async move {
            if sequential {
                run_read_loop(
                    blob,
                    deadline,
                    cfg.io_size,
                    sequential_blocks(wid as u64 % total_blocks, inflight, total_blocks),
                )
                .await
            } else {
                let mut state = worker_seed(cfg.seed, wid);
                run_read_loop(blob, deadline, cfg.io_size, || {
                    next_random_block(&mut state, total_blocks)
                })
                .await
            }
        }
    }))
    .await;

    let elapsed = start.elapsed();
    let stats = merge_worker_results(workers)?;
    Ok(ScenarioReport {
        elapsed,
        read: Some(summarize_operation(stats, elapsed)),
        write: None,
        final_file_size: file_size,
    })
}

async fn run_overwrite(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<ScenarioReport, String> {
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size as u64;
    let io_size = cfg.io_size as u64;
    let inflight = cfg.inflight as u64;

    let blob = prepare_blob(context, root, "storage-bench", b"blob", file_size).await?;
    let payload = random_write_payload(cfg.io_size, cfg.seed, cfg.write_shape);

    let start = Instant::now();
    let deadline = start + cfg.duration();

    let workers = if cfg.scenario == Scenario::WriteSeq {
        join_all((0..cfg.inflight).map(|wid| {
            let blob = blob.clone();
            let payload = payload.clone();
            async move {
                let mut block = wid as u64 % total_blocks;
                run_write_loop(
                    blob,
                    deadline,
                    payload,
                    cfg.sync_mode,
                    || {
                        let offset = block * io_size;
                        block = (block + inflight) % total_blocks;
                        offset
                    },
                    |_| {},
                )
                .await
            }
        }))
        .await
    } else {
        let shards = build_worker_shards(total_blocks, cfg.inflight)?;
        join_all(shards.into_iter().enumerate().map(|(wid, shard)| {
            let blob = blob.clone();
            let payload = payload.clone();
            async move {
                let mut state = worker_seed(cfg.seed, wid);
                run_write_loop(
                    blob,
                    deadline,
                    payload,
                    cfg.sync_mode,
                    || {
                        let local = next_random_block(&mut state, shard.blocks);
                        (shard.start_block + local) * io_size
                    },
                    |_| {},
                )
                .await
            }
        }))
        .await
    };

    let stats = merge_worker_results(workers)?;
    finalize_write_report(blob, start, cfg.sync_mode, stats, file_size).await
}

async fn run_write_append(cfg: &Config, context: &Context) -> Result<ScenarioReport, String> {
    let (blob, _) = context.open("storage-bench", b"blob").await.str_err()?;
    let payload = random_write_payload(cfg.io_size, cfg.seed, cfg.write_shape);
    let io_size = cfg.io_size as u64;

    let start = Instant::now();
    let deadline = start + cfg.duration();

    let mut offset = 0u64;
    let stats = run_write_loop(
        blob.clone(),
        deadline,
        payload,
        cfg.sync_mode,
        || {
            let current = offset;
            offset += io_size;
            current
        },
        |_| {},
    )
    .await?;

    let final_file_size = stats.bytes;
    finalize_write_report(blob, start, cfg.sync_mode, stats, final_file_size).await
}

async fn run_read_write_append(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<ScenarioReport, String> {
    let initial_size = cfg.file_size();
    let total_blocks = initial_size / cfg.io_size as u64;
    let io_size = cfg.io_size as u64;

    let blob = prepare_filled_blob(
        context,
        root,
        "storage-bench",
        b"blob",
        initial_size,
        cfg.seed,
    )
    .await?;
    warm_cache(cfg, root, &blob, total_blocks).await?;

    // Use a different seed for the writer so its PRNG stream doesn't overlap
    // with the reader streams derived from cfg.seed.
    let payload = random_write_payload(cfg.io_size, cfg.seed ^ 0xA5A5_A5A5, cfg.write_shape);
    let visible_len = Arc::new(AtomicU64::new(initial_size));

    let start = Instant::now();
    let deadline = start + cfg.duration();

    let writer = {
        let blob = blob.clone();
        let visible_len = visible_len.clone();
        async move {
            let mut offset = initial_size;
            run_write_loop(
                blob,
                deadline,
                payload,
                cfg.sync_mode,
                || {
                    let current = offset;
                    offset += io_size;
                    current
                },
                |end_offset| {
                    visible_len.store(end_offset, Ordering::Release);
                },
            )
            .await
        }
    };

    let readers = join_all((0..cfg.inflight).map(|wid| {
        let blob = blob.clone();
        let visible_len = visible_len.clone();
        async move {
            run_frontier_read_worker(
                blob,
                deadline,
                cfg.io_size,
                visible_len,
                worker_seed(cfg.seed, wid),
            )
            .await
        }
    }));

    let (write_stats, read_workers) = tokio::join!(writer, readers);
    let mut elapsed = start.elapsed();
    let write_stats = write_stats?;
    let read_stats = merge_worker_results(read_workers)?;
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await.str_err()?;
        elapsed = start.elapsed();
    }
    let final_file_size = initial_size + write_stats.bytes;
    Ok(ScenarioReport {
        elapsed,
        read: Some(summarize_operation(read_stats, elapsed)),
        write: Some(summarize_operation(write_stats, elapsed)),
        final_file_size,
    })
}

/// Apply the requested cache preparation before the timed phase.
async fn warm_cache(
    cfg: &Config,
    root: &Path,
    blob: &RuntimeBlob,
    total_blocks: u64,
) -> Result<(), String> {
    let inflight = cfg.inflight as u64;
    match cfg.cache.expect("validated") {
        CacheMode::Warm => {
            let sequential = cfg.scenario == Scenario::ReadSeq;
            let results = join_all((0..cfg.inflight).map(|wid| {
                let blob = blob.clone();
                async move {
                    if sequential {
                        let warm_ops = total_blocks.div_ceil(inflight);
                        warm_read_loop(
                            blob,
                            cfg.io_size,
                            warm_ops,
                            sequential_blocks(wid as u64 % total_blocks, inflight, total_blocks),
                        )
                        .await
                    } else {
                        let warm_ops = total_blocks.saturating_mul(3).div_ceil(inflight).max(1);
                        let mut state = worker_seed(cfg.seed, wid);
                        warm_read_loop(blob, cfg.io_size, warm_ops, || {
                            next_random_block(&mut state, total_blocks)
                        })
                        .await
                    }
                }
            }))
            .await;
            for r in results {
                r?;
            }
        }
        CacheMode::Cold => {
            drop_page_cache(root, "storage-bench", b"blob")
                .map_err(|err| format!("failed to evict file cache: {err}"))?;
        }
    }
    Ok(())
}

/// Sync at the end when requested and assemble the final write report.
async fn finalize_write_report(
    blob: RuntimeBlob,
    start: Instant,
    sync_mode: SyncMode,
    stats: WorkerStats,
    final_file_size: u64,
) -> Result<ScenarioReport, String> {
    let mut elapsed = start.elapsed();
    if sync_mode == SyncMode::End {
        blob.sync().await.str_err()?;
        elapsed = start.elapsed();
    }
    Ok(ScenarioReport {
        elapsed,
        read: None,
        write: Some(summarize_operation(stats, elapsed)),
        final_file_size,
    })
}
