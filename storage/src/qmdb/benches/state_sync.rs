//! Benchmarks for syncing a QMDB database from a local source.
//!
//! Each iteration syncs a populated source into a fresh client database. The source is local and
//! runs on the same runtime, so the measurement covers the source reading operations and building
//! proofs as well as response verification, journal writes, and building the client database at
//! the end of sync, without network latency.

use crate::common::{AnyUFixDb, any_fix_cfg, gen_random_kv, make_fixed_value};
use commonware_runtime::{
    Runner as _, Supervisor as _,
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::{
    merkle::mmr,
    qmdb::{any::FixedConfig, sync},
    translator::EightCap,
};
use commonware_utils::{NZU64, non_empty_range};
use criterion::{Criterion, criterion_group};
use std::{
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant},
};

type Db = AnyUFixDb<mmr::Family>;

const COMMIT_FREQUENCY: u32 = 10_000;

cfg_if::cfg_if! {
    if #[cfg(not(full_bench))] {
        const CASES: [(u64, u64); 1] = [(10_000, 100_000)];
    } else {
        const CASES: [(u64, u64); 2] = [(10_000, 100_000), (100_000, 1_000_000)];
    }
}

const FETCH_BATCH_SIZES: [u64; 2] = [256, 4096];

/// Returns the client configuration, which uses partitions apart from the source's.
fn client_config(ctx: &Context) -> FixedConfig<EightCap, commonware_parallel::Rayon> {
    let mut cfg = any_fix_cfg(ctx);
    cfg.merkle_config.journal_partition = "bench-sync-client-merkle-journal".into();
    cfg.merkle_config.metadata_partition = "bench-sync-client-merkle-metadata".into();
    cfg.journal_config.partition = "bench-sync-client-log".into();
    cfg
}

fn bench_sync(c: &mut Criterion) {
    let cfg = Config::default();
    for (elements, operations) in CASES {
        // Populated lazily on the first matched sample, then reused by every batch size.
        let mut populated = false;
        for fetch_batch_size in FETCH_BATCH_SIZES {
            let runner = tokio::Runner::new(cfg.clone());
            c.bench_function(
                &format!(
                    "{}/elements={elements} operations={operations} fetch_batch={fetch_batch_size}",
                    module_path!(),
                ),
                |b| {
                    if !populated {
                        commonware_runtime::tokio::Runner::new(cfg.clone()).start(
                            |ctx| async move {
                                let db = Db::init(ctx.child("source"), any_fix_cfg(&ctx), None)
                                    .await
                                    .unwrap();
                                let db = gen_random_kv::<mmr::Family, _>(
                                    db,
                                    elements,
                                    operations,
                                    Some(COMMIT_FREQUENCY),
                                    None,
                                    None,
                                    None,
                                    None,
                                    make_fixed_value,
                                )
                                .await;
                                let boundary = db.sync_boundary();
                                let db = db.prune(boundary).await.unwrap();
                                db.sync().await.unwrap();
                            },
                        );
                        populated = true;
                    }

                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let ctx = context::get::<Context>();
                        let source = Db::init(ctx.child("source"), any_fix_cfg(&ctx), None)
                            .await
                            .unwrap();
                        let target = sync::Target {
                            root: source.root(),
                            range: non_empty_range!(source.sync_boundary(), source.bounds().end),
                        };
                        let source = Arc::new(source);

                        let mut total = Duration::ZERO;
                        for iteration in 0..iters {
                            let start = Instant::now();
                            let synced: Db = sync::sync(sync::engine::Config {
                                context: ctx.child("client").with_attribute("iteration", iteration),
                                db_config: client_config(&ctx),
                                target: target.clone(),
                                source: source.clone(),
                                fetch_batch_size: NonZeroU64::new(fetch_batch_size).unwrap(),
                                apply_batch_size: NZU64!(1024),
                                max_outstanding_requests: 16,
                                update_rx: None,
                                finish_rx: None,
                                reached_target_tx: None,
                                max_retained_roots: 0,
                            })
                            .await
                            .unwrap();
                            total += start.elapsed();
                            assert_eq!(synced.root(), target.root);
                            synced.destroy().await.unwrap();
                        }
                        total
                    });
                },
            );
        }

        // Cleanup: destroy the source.
        if populated {
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                let db = Db::init(ctx.child("source"), any_fix_cfg(&ctx), None)
                    .await
                    .unwrap();
                db.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sync
}
