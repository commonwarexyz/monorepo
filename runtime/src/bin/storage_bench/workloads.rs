//! Benchmark workload orchestration for `storage_bench`.

use crate::{
    config::{CacheMode, Config, Scenario, SyncMode},
    filesystem::{drop_page_cache, prepare_blob, prepare_filled_blob, random_write_payload},
    report::{Report, Stats},
    workers::{
        random_blocks, run_read_loop, run_write_loop, sequential_blocks, warm_read_loop, ResultExt,
    },
};
use commonware_runtime::{tokio::Context, Blob as _, Storage as _};
use futures::future::join_all;
use rand::{
    rngs::{SmallRng, StdRng},
    Rng, SeedableRng,
};
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
pub async fn run_benchmark(cfg: &Config, root: &Path, context: Context) -> Result<Report, String> {
    let result = match cfg.scenario {
        Scenario::ReadSeq | Scenario::ReadRand => run_read(cfg, root, &context).await,
        Scenario::WriteSeq | Scenario::WriteRand => run_overwrite(cfg, root, &context).await,
        Scenario::WriteAppend => run_write_append(cfg, &context).await,
        Scenario::ReadWriteAppend => run_read_write_append(cfg, root, &context).await,
    };
    let _ = context.remove("storage-bench", None).await;
    result
}

async fn run_read(cfg: &Config, root: &Path, context: &Context) -> Result<Report, String> {
    let sequential = cfg.scenario == Scenario::ReadSeq;
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size as u64;
    let inflight = cfg.inflight as u64;

    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let blob =
        prepare_filled_blob(&mut rng, context, root, "storage-bench", b"blob", file_size).await?;
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
                run_read_loop(
                    blob,
                    deadline,
                    cfg.io_size,
                    random_blocks(cfg.seed + wid as u64, total_blocks),
                )
                .await
            }
        }
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    Ok(Report::new(start.elapsed(), Some(workers), None, file_size))
}

async fn run_overwrite(cfg: &Config, root: &Path, context: &Context) -> Result<Report, String> {
    let file_size = cfg.file_size();
    let total_blocks = file_size / cfg.io_size as u64;
    let io_size = cfg.io_size as u64;
    let inflight = cfg.inflight as u64;
    let mut rng = StdRng::seed_from_u64(cfg.seed);

    let blob = prepare_blob(context, root, "storage-bench", b"blob", file_size).await?;
    let payload = random_write_payload(&mut rng, cfg.io_size, cfg.write_shape);

    let start = Instant::now();
    let deadline = start + cfg.duration();

    let sequential = cfg.scenario == Scenario::WriteSeq;
    let workers = join_all((0..cfg.inflight).map(|wid| {
        let blob = blob.clone();
        let payload = payload.clone();
        async move {
            if sequential {
                let mut blocks =
                    sequential_blocks(wid as u64 % total_blocks, inflight, total_blocks);
                run_write_loop(
                    blob,
                    deadline,
                    payload,
                    cfg.sync_mode,
                    || blocks() * io_size,
                    |_| {},
                )
                .await
            } else {
                let mut blocks = random_blocks(cfg.seed + wid as u64, total_blocks);
                run_write_loop(
                    blob,
                    deadline,
                    payload,
                    cfg.sync_mode,
                    || blocks() * io_size,
                    |_| {},
                )
                .await
            }
        }
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    if cfg.sync_mode == SyncMode::End {
        blob.sync().await.str_err()?;
    }
    Ok(Report::new(start.elapsed(), None, Some(workers), file_size))
}

async fn run_write_append(cfg: &Config, context: &Context) -> Result<Report, String> {
    let (blob, _) = context.open("storage-bench", b"blob").await.str_err()?;
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let payload = random_write_payload(&mut rng, cfg.io_size, cfg.write_shape);
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
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await.str_err()?;
    }
    Ok(Report::new(
        start.elapsed(),
        None,
        Some(vec![stats]),
        final_file_size,
    ))
}

async fn run_read_write_append(
    cfg: &Config,
    root: &Path,
    context: &Context,
) -> Result<Report, String> {
    let initial_size = cfg.file_size();
    let total_blocks = initial_size / cfg.io_size as u64;
    let io_size = cfg.io_size as u64;

    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let blob = prepare_filled_blob(
        &mut rng,
        context,
        root,
        "storage-bench",
        b"blob",
        initial_size,
    )
    .await?;
    warm_cache(cfg, root, &blob, total_blocks).await?;

    let payload = random_write_payload(&mut rng, cfg.io_size, cfg.write_shape);
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
            let mut rng = SmallRng::seed_from_u64(cfg.seed + wid as u64);
            let random_blocks = || {
                let total_blocks = visible_len.load(Ordering::Acquire) / io_size;
                rng.gen_range(0..total_blocks)
            };
            run_read_loop(blob, deadline, cfg.io_size, random_blocks).await
        }
    }));

    let (write_result, read_results) = tokio::join!(writer, readers);
    let write_stats = write_result?;
    let read_workers: Vec<Stats> = read_results.into_iter().collect::<Result<_, _>>()?;
    let final_file_size = initial_size + write_stats.bytes;
    if cfg.sync_mode == SyncMode::End {
        blob.sync().await.str_err()?;
    }
    Ok(Report::new(
        start.elapsed(),
        Some(read_workers),
        Some(vec![write_stats]),
        final_file_size,
    ))
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
                        warm_read_loop(
                            blob,
                            cfg.io_size,
                            warm_ops,
                            random_blocks(cfg.seed + wid as u64, total_blocks),
                        )
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
