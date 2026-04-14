//! Scenario entrypoints for `storage_bench`.

use crate::{
    config::{Config, Scenario, SyncMode},
    environment::{BenchmarkEnvironment, PARTITION},
    helpers::{
        build_worker_shards, create_write_payload, prepare_cold_read_cache,
        prepare_preallocated_blob, prepare_prefilled_blob, run_append_writer,
        run_append_writer_with_frontier, run_frontier_random_read_worker, run_random_read_worker,
        run_random_write_worker, run_sequential_read_worker, run_sequential_write_worker,
        warm_random_read_worker, warm_sequential_read_worker,
    },
    report::{merge_worker_results, summarize_operation, ScenarioReport},
};
use commonware_runtime::{tokio::Context, Blob as _, Storage as _};
use futures::future::join_all;
use std::{
    hint::black_box,
    sync::{atomic::AtomicU64, Arc},
    time::Instant,
};

/// Primary blob name used by the benchmark scenarios.
const PRIMARY_BLOB_NAME: &[u8] = b"blob";

/// Dispatch to the selected scenario using the runtime's storage context.
pub(crate) async fn run_benchmark(
    cfg: &Config,
    environment: &BenchmarkEnvironment,
    context: Context,
) -> Result<ScenarioReport, String> {
    let result = match cfg.scenario {
        Scenario::ReadSeq => run_read_seq(cfg, environment, &context).await,
        Scenario::ReadRand => run_read_rand(cfg, environment, &context).await,
        Scenario::WriteSeq => run_write_seq(cfg, environment, &context).await,
        Scenario::WriteRand => run_write_rand(cfg, environment, &context).await,
        Scenario::WriteAppend => run_write_append(cfg, &context).await,
        Scenario::ReadWriteAppend => run_read_write_append(cfg, environment, &context).await,
    };
    let _ = context.remove(PARTITION, None).await;
    result
}

/// Run `read_seq`.
async fn run_read_seq(
    cfg: &Config,
    environment: &BenchmarkEnvironment,
    context: &Context,
) -> Result<ScenarioReport, String> {
    prepare_prefilled_blob(
        context,
        environment,
        PRIMARY_BLOB_NAME,
        cfg.file_size(),
        cfg.seed,
    )
    .await?;
    let total_blocks = cfg.file_size() / cfg.io_size as u64;
    match cfg.cache.expect("validated") {
        crate::config::CacheMode::Warm => {
            let (blob, _) = context
                .open(PARTITION, PRIMARY_BLOB_NAME)
                .await
                .map_err(|err| err.to_string())?;
            let warmers = join_all((0..cfg.inflight).map(|worker_id| {
                let blob = blob.clone();
                async move {
                    warm_sequential_read_worker(
                        blob,
                        cfg.io_size,
                        total_blocks,
                        worker_id,
                        cfg.inflight,
                    )
                    .await
                }
            }))
            .await;
            warmers.into_iter().collect::<Result<Vec<_>, _>>()?;
        }
        crate::config::CacheMode::Cold => {
            prepare_cold_read_cache(environment, PRIMARY_BLOB_NAME)?;
        }
    }
    let (blob, _) = context
        .open(PARTITION, PRIMARY_BLOB_NAME)
        .await
        .map_err(|err| err.to_string())?;
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

    let elapsed = start.elapsed();
    let stats = merge_worker_results(workers)?;
    black_box(stats.witness);
    Ok(ScenarioReport {
        elapsed,
        read: Some(summarize_operation(stats, elapsed)),
        write: None,
        final_file_size: Some(cfg.file_size()),
    })
}

/// Run `read_rand`.
async fn run_read_rand(
    cfg: &Config,
    environment: &BenchmarkEnvironment,
    context: &Context,
) -> Result<ScenarioReport, String> {
    prepare_prefilled_blob(
        context,
        environment,
        PRIMARY_BLOB_NAME,
        cfg.file_size(),
        cfg.seed,
    )
    .await?;
    let total_blocks = cfg.file_size() / cfg.io_size as u64;
    match cfg.cache.expect("validated") {
        crate::config::CacheMode::Warm => {
            let (blob, _) = context
                .open(PARTITION, PRIMARY_BLOB_NAME)
                .await
                .map_err(|err| err.to_string())?;
            let warmers = join_all((0..cfg.inflight).map(|worker_id| {
                let blob = blob.clone();
                async move {
                    warm_random_read_worker(
                        blob,
                        cfg.io_size,
                        total_blocks,
                        cfg.seed ^ worker_id as u64,
                        cfg.inflight,
                    )
                    .await
                }
            }))
            .await;
            warmers.into_iter().collect::<Result<Vec<_>, _>>()?;
        }
        crate::config::CacheMode::Cold => {
            prepare_cold_read_cache(environment, PRIMARY_BLOB_NAME)?;
        }
    }
    let (blob, _) = context
        .open(PARTITION, PRIMARY_BLOB_NAME)
        .await
        .map_err(|err| err.to_string())?;
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
                cfg.seed ^ worker_id as u64,
            )
            .await
        }
    }))
    .await;

    let elapsed = start.elapsed();
    let stats = merge_worker_results(workers)?;
    black_box(stats.witness);
    Ok(ScenarioReport {
        elapsed,
        read: Some(summarize_operation(stats, elapsed)),
        write: None,
        final_file_size: Some(cfg.file_size()),
    })
}

/// Run `write_seq`.
async fn run_write_seq(
    cfg: &Config,
    environment: &BenchmarkEnvironment,
    context: &Context,
) -> Result<ScenarioReport, String> {
    prepare_preallocated_blob(context, environment, PRIMARY_BLOB_NAME, cfg.file_size()).await?;
    let (blob, _) = context
        .open(PARTITION, PRIMARY_BLOB_NAME)
        .await
        .map_err(|err| err.to_string())?;
    let payload = create_write_payload(cfg.io_size, cfg.seed, cfg.write_shape);
    let start = Instant::now();
    let deadline = start + cfg.duration;
    let total_blocks = cfg.file_size() / cfg.io_size as u64;

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

    let mut elapsed = start.elapsed();
    let stats = merge_worker_results(workers)?;
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await.map_err(|err| err.to_string())?;
        elapsed = start.elapsed();
    }
    black_box(stats.witness);
    Ok(ScenarioReport {
        elapsed,
        read: None,
        write: Some(summarize_operation(stats, elapsed)),
        final_file_size: Some(cfg.file_size()),
    })
}

/// Run `write_rand`.
async fn run_write_rand(
    cfg: &Config,
    environment: &BenchmarkEnvironment,
    context: &Context,
) -> Result<ScenarioReport, String> {
    prepare_preallocated_blob(context, environment, PRIMARY_BLOB_NAME, cfg.file_size()).await?;
    let (blob, _) = context
        .open(PARTITION, PRIMARY_BLOB_NAME)
        .await
        .map_err(|err| err.to_string())?;
    let payload = create_write_payload(cfg.io_size, cfg.seed, cfg.write_shape);
    let start = Instant::now();
    let deadline = start + cfg.duration;
    let total_blocks = cfg.file_size() / cfg.io_size as u64;
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
                cfg.seed ^ worker_id as u64,
                cfg.io_size,
            )
            .await
        }
    }))
    .await;

    let mut elapsed = start.elapsed();
    let stats = merge_worker_results(workers)?;
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await.map_err(|err| err.to_string())?;
        elapsed = start.elapsed();
    }
    black_box(stats.witness);
    Ok(ScenarioReport {
        elapsed,
        read: None,
        write: Some(summarize_operation(stats, elapsed)),
        final_file_size: Some(cfg.file_size()),
    })
}

/// Run `write_append`.
async fn run_write_append(cfg: &Config, context: &Context) -> Result<ScenarioReport, String> {
    let (blob, _) = context
        .open(PARTITION, PRIMARY_BLOB_NAME)
        .await
        .map_err(|err| err.to_string())?;
    let payload = create_write_payload(cfg.io_size, cfg.seed, cfg.write_shape);
    let start = Instant::now();
    let deadline = start + cfg.duration;
    let stats = run_append_writer(blob.clone(), deadline, 0, payload, cfg.sync_mode).await?;
    let mut elapsed = start.elapsed();
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await.map_err(|err| err.to_string())?;
        elapsed = start.elapsed();
    }
    let final_file_size = stats.bytes;
    black_box(stats.witness);
    Ok(ScenarioReport {
        elapsed,
        read: None,
        write: Some(summarize_operation(stats, elapsed)),
        final_file_size: Some(final_file_size),
    })
}

/// Run `read_write_append`.
async fn run_read_write_append(
    cfg: &Config,
    environment: &BenchmarkEnvironment,
    context: &Context,
) -> Result<ScenarioReport, String> {
    let initial_size = cfg.file_size();
    prepare_prefilled_blob(
        context,
        environment,
        PRIMARY_BLOB_NAME,
        initial_size,
        cfg.seed,
    )
    .await?;
    match cfg.cache.expect("validated") {
        crate::config::CacheMode::Warm => {
            let (blob, _) = context
                .open(PARTITION, PRIMARY_BLOB_NAME)
                .await
                .map_err(|err| err.to_string())?;
            let total_blocks = initial_size / cfg.io_size as u64;
            let warmers = join_all((0..cfg.inflight).map(|worker_id| {
                let blob = blob.clone();
                async move {
                    warm_random_read_worker(
                        blob,
                        cfg.io_size,
                        total_blocks,
                        cfg.seed ^ worker_id as u64,
                        cfg.inflight,
                    )
                    .await
                }
            }))
            .await;
            warmers.into_iter().collect::<Result<Vec<_>, _>>()?;
        }
        crate::config::CacheMode::Cold => {
            prepare_cold_read_cache(environment, PRIMARY_BLOB_NAME)?;
        }
    }

    let (blob, _) = context
        .open(PARTITION, PRIMARY_BLOB_NAME)
        .await
        .map_err(|err| err.to_string())?;
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
                cfg.seed ^ worker_id as u64,
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
