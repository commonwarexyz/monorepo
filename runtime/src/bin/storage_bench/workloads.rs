//! Benchmark workload orchestration for `storage_bench`.

use crate::{
    config::{CacheMode, Config, Scenario, SyncMode},
    filesystem::{
        create_write_payload, prepare_cold_read_cache, prepare_preallocated_blob,
        prepare_prefilled_blob, PARTITION,
    },
    report::{merge_worker_results, summarize_operation, ScenarioReport, WorkerStats},
    workers::{
        build_worker_shards, run_append_writer, run_append_writer_with_frontier,
        run_frontier_random_read_worker, run_random_read_worker, run_random_write_worker,
        run_sequential_read_worker, run_sequential_write_worker, warm_random_read_worker,
        warm_sequential_read_worker,
    },
};
use commonware_runtime::{tokio::Context, Blob as _, IoBufs, Storage as _};
use futures::future::join_all;
use std::{
    hint::black_box,
    path::Path,
    sync::{atomic::AtomicU64, Arc},
    time::{Duration, Instant},
};

type RuntimeBlob = <Context as commonware_runtime::Storage>::Blob;

const PRIMARY_BLOB_NAME: &[u8] = b"blob";

#[derive(Clone, Copy)]
enum ReadPattern {
    Sequential,
    Random,
}

pub(crate) async fn run_benchmark(
    cfg: &Config,
    root: &Path,
    context: Context,
) -> Result<ScenarioReport, String> {
    let result = match cfg.scenario {
        Scenario::ReadSeq => run_read_seq(cfg, root, &context).await,
        Scenario::ReadRand => run_read_rand(cfg, root, &context).await,
        Scenario::WriteSeq => run_write_seq(cfg, root, &context).await,
        Scenario::WriteRand => run_write_rand(cfg, root, &context).await,
        Scenario::WriteAppend => run_write_append(cfg, &context).await,
        Scenario::ReadWriteAppend => run_read_write_append(cfg, root, &context).await,
    };
    let _ = context.remove(PARTITION, None).await;
    result
}

async fn run_read_seq(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<ScenarioReport, String> {
    let total_blocks = prepare_read_input(
        cfg,
        root,
        context,
        cfg.file_size(),
        cfg.seed,
        ReadPattern::Sequential,
    )
    .await?;
    let blob = open_primary_blob(context).await?;
    let start = Instant::now();
    let deadline = start + cfg.duration;

    let workers = join_all((0..cfg.inflight).map(|worker_id| {
        let blob = blob.clone();
        async move {
            run_sequential_read_worker(
                blob,
                deadline,
                cfg.io_size,
                total_blocks,
                worker_id,
                cfg.inflight,
            )
            .await
        }
    }))
    .await;

    finalize_read_report(cfg.file_size(), start.elapsed(), workers)
}

async fn run_read_rand(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<ScenarioReport, String> {
    let total_blocks = prepare_read_input(
        cfg,
        root,
        context,
        cfg.file_size(),
        cfg.seed,
        ReadPattern::Random,
    )
    .await?;
    let blob = open_primary_blob(context).await?;
    let start = Instant::now();
    let deadline = start + cfg.duration;

    let workers = join_all((0..cfg.inflight).map(|worker_id| {
        let blob = blob.clone();
        async move {
            run_random_read_worker(
                blob,
                deadline,
                cfg.io_size,
                total_blocks,
                worker_seed(cfg.seed, worker_id),
            )
            .await
        }
    }))
    .await;

    finalize_read_report(cfg.file_size(), start.elapsed(), workers)
}

async fn run_write_seq(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<ScenarioReport, String> {
    let (blob, total_blocks, payload) = prepare_overwrite_input(cfg, root, context).await?;
    let start = Instant::now();
    let deadline = start + cfg.duration;

    let workers = join_all((0..cfg.inflight).map(|worker_id| {
        let blob = blob.clone();
        let payload = payload.clone();
        async move {
            run_sequential_write_worker(
                blob,
                deadline,
                total_blocks,
                worker_id,
                cfg.inflight,
                payload,
                cfg.sync_mode,
            )
            .await
        }
    }))
    .await;

    let stats = merge_worker_results(workers)?;
    finalize_write_report(blob, start, cfg.sync_mode, stats, cfg.file_size()).await
}

async fn run_write_rand(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<ScenarioReport, String> {
    let (blob, total_blocks, payload) = prepare_overwrite_input(cfg, root, context).await?;
    let start = Instant::now();
    let deadline = start + cfg.duration;
    let shards = build_worker_shards(total_blocks, cfg.inflight)?;

    let workers = join_all(shards.into_iter().enumerate().map(|(worker_id, shard)| {
        let blob = blob.clone();
        let payload = payload.clone();
        async move {
            run_random_write_worker(
                blob,
                deadline,
                shard,
                payload,
                cfg.sync_mode,
                worker_seed(cfg.seed, worker_id),
                cfg.io_size,
            )
            .await
        }
    }))
    .await;

    let stats = merge_worker_results(workers)?;
    finalize_write_report(blob, start, cfg.sync_mode, stats, cfg.file_size()).await
}

async fn run_write_append(cfg: &Config, context: &Context) -> Result<ScenarioReport, String> {
    let blob = open_primary_blob(context).await?;
    let payload = create_write_payload(cfg.io_size, cfg.seed, cfg.write_shape);
    let start = Instant::now();
    let deadline = start + cfg.duration;
    let stats = run_append_writer(blob.clone(), deadline, 0, payload, cfg.sync_mode).await?;
    let final_file_size = stats.bytes;
    finalize_write_report(blob, start, cfg.sync_mode, stats, final_file_size).await
}

async fn run_read_write_append(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<ScenarioReport, String> {
    let initial_size = cfg.file_size();
    prepare_read_input(
        cfg,
        root,
        context,
        initial_size,
        cfg.seed,
        ReadPattern::Random,
    )
    .await?;
    let blob = open_primary_blob(context).await?;
    let payload = create_write_payload(cfg.io_size, cfg.seed ^ 0xA5A5_A5A5, cfg.write_shape);
    let visible_len = Arc::new(AtomicU64::new(initial_size));
    let start = Instant::now();
    let deadline = start + cfg.duration;

    let writer = {
        let blob = blob.clone();
        let payload = payload.clone();
        let visible_len = visible_len.clone();
        async move {
            run_append_writer_with_frontier(
                blob,
                deadline,
                initial_size,
                payload,
                cfg.sync_mode,
                visible_len,
            )
            .await
        }
    };

    let readers = join_all((0..cfg.inflight).map(|worker_id| {
        let blob = blob.clone();
        let visible_len = visible_len.clone();
        async move {
            run_frontier_random_read_worker(
                blob,
                deadline,
                cfg.io_size,
                visible_len,
                worker_seed(cfg.seed, worker_id),
            )
            .await
        }
    }));

    let (write_stats, read_workers) = tokio::join!(writer, readers);
    let read_elapsed = start.elapsed();
    let mut total_elapsed = read_elapsed;
    let write_stats = write_stats?;
    let read_stats = merge_worker_results(read_workers)?;
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await.map_err(|err| err.to_string())?;
        total_elapsed = start.elapsed();
    }
    let final_file_size = initial_size + write_stats.bytes;
    black_box(write_stats.witness ^ read_stats.witness);
    Ok(ScenarioReport {
        elapsed: total_elapsed,
        read: Some(summarize_operation(read_stats, read_elapsed)),
        write: Some(summarize_operation(write_stats, total_elapsed)),
        final_file_size: Some(final_file_size),
    })
}

/// Create the fixed-size input file and apply the requested read-cache mode.
async fn prepare_read_input(
    cfg: &Config,
    root: &Path,
    context: &Context,
    file_size: u64,
    seed: u64,
    pattern: ReadPattern,
) -> Result<u64, String> {
    prepare_prefilled_blob(context, root, PRIMARY_BLOB_NAME, file_size, seed).await?;
    let total_blocks = file_size / cfg.io_size as u64;
    prepare_read_cache(cfg, root, context, total_blocks, seed, pattern).await?;
    Ok(total_blocks)
}

/// Prepare the on-disk state for fixed-size overwrite workloads.
async fn prepare_overwrite_input(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<(RuntimeBlob, u64, IoBufs), String> {
    prepare_preallocated_blob(context, root, PRIMARY_BLOB_NAME, cfg.file_size()).await?;
    let blob = open_primary_blob(context).await?;
    let total_blocks = cfg.file_size() / cfg.io_size as u64;
    let payload = create_write_payload(cfg.io_size, cfg.seed, cfg.write_shape);
    Ok((blob, total_blocks, payload))
}

/// Apply the requested warm or cold read-cache preparation.
async fn prepare_read_cache(
    cfg: &Config,
    root: &Path,
    context: &Context,
    total_blocks: u64,
    seed: u64,
    pattern: ReadPattern,
) -> Result<(), String> {
    match cfg.cache.expect("validated") {
        CacheMode::Warm => {
            let blob = open_primary_blob(context).await?;
            let warmers = join_all((0..cfg.inflight).map(|worker_id| {
                let blob = blob.clone();
                async move {
                    match pattern {
                        ReadPattern::Sequential => {
                            warm_sequential_read_worker(
                                blob,
                                cfg.io_size,
                                total_blocks,
                                worker_id,
                                cfg.inflight,
                            )
                            .await
                        }
                        ReadPattern::Random => {
                            warm_random_read_worker(
                                blob,
                                cfg.io_size,
                                total_blocks,
                                worker_seed(seed, worker_id),
                                cfg.inflight,
                            )
                            .await
                        }
                    }
                }
            }))
            .await;
            warmers.into_iter().collect::<Result<Vec<_>, _>>()?;
        }
        CacheMode::Cold => {
            prepare_cold_read_cache(root, PRIMARY_BLOB_NAME)?;
        }
    }
    Ok(())
}

async fn open_primary_blob(context: &Context) -> Result<RuntimeBlob, String> {
    let (blob, _) = context
        .open(PARTITION, PRIMARY_BLOB_NAME)
        .await
        .map_err(|err| err.to_string())?;
    Ok(blob)
}

/// Build the final report for a pure read workload.
fn finalize_read_report(
    file_size: u64,
    elapsed: Duration,
    workers: Vec<Result<WorkerStats, String>>,
) -> Result<ScenarioReport, String> {
    let stats = merge_worker_results(workers)?;
    black_box(stats.witness);
    Ok(ScenarioReport {
        elapsed,
        read: Some(summarize_operation(stats, elapsed)),
        write: None,
        final_file_size: Some(file_size),
    })
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
        blob.sync().await.map_err(|err| err.to_string())?;
        elapsed = start.elapsed();
    }
    black_box(stats.witness);
    Ok(ScenarioReport {
        elapsed,
        read: None,
        write: Some(summarize_operation(stats, elapsed)),
        final_file_size: Some(final_file_size),
    })
}

#[inline(always)]
const fn worker_seed(seed: u64, worker_id: usize) -> u64 {
    seed ^ worker_id as u64
}
