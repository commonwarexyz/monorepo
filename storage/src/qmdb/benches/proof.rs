//! Benchmarks for QMDB proof generation.
//!
//! Measures `Provable::proof()` for `any` variants and `db.range_proof()` for `current` variants.
//! These cannot share a dispatch macro because the proof APIs differ between `any` and `current`.

use crate::common::{
    any_fix_cfg, any_var_digest_cfg, cur_fix_cfg, cur_var_digest_cfg, make_fixed_value,
    populate_and_sync, AnyOFixDb, AnyOVarDigestDb, AnyUFixDb, AnyUVarDigestDb, CurOFixDb,
    CurOVarDigestDb, CurUFixDb, CurUVarDigestDb, Digest,
};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    Runner as _,
};
use commonware_storage::qmdb::any::traits::{DbAny, Provable};
use commonware_utils::NZU64;
use criterion::{criterion_group, Criterion};
use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

const ELEMENTS: u64 = 10_000;
const OPERATIONS: u64 = 10_000;
const COMMIT_FREQUENCY: u32 = 1_000;

const ANY_VARIANTS: [(&str, bool, bool); 4] = [
    ("any::unordered::fixed", false, false),
    ("any::ordered::fixed", true, false),
    ("any::unordered::variable", false, true),
    ("any::ordered::variable", true, true),
];

const CURRENT_VARIANTS: [(&str, bool, bool); 4] = [
    ("current::unordered::fixed", false, false),
    ("current::ordered::fixed", true, false),
    ("current::unordered::variable", false, true),
    ("current::ordered::variable", true, true),
];

async fn proof_any<D: DbAny<Key = Digest> + Provable>(db: &D, max_ops: NonZeroU64) -> Duration {
    let start_loc = db.bounds().await.start;
    let start = Instant::now();
    let _ = db.proof(start_loc, max_ops).await.unwrap();
    start.elapsed()
}

fn bench_any_proof(c: &mut Criterion) {
    let cfg = Config::default();
    for max_ops in [NZU64!(1), NZU64!(10), NZU64!(100)] {
        for &(name, ordered, variable) in &ANY_VARIANTS {
            // Setup
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                match (ordered, variable) {
                    (false, false) => {
                        let mut db = AnyUFixDb::init(ctx.clone(), any_fix_cfg(&ctx))
                            .await
                            .unwrap();
                        populate_and_sync(
                            &mut db,
                            ELEMENTS,
                            OPERATIONS,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    }
                    (true, false) => {
                        let mut db = AnyOFixDb::init(ctx.clone(), any_fix_cfg(&ctx))
                            .await
                            .unwrap();
                        populate_and_sync(
                            &mut db,
                            ELEMENTS,
                            OPERATIONS,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    }
                    (false, true) => {
                        let mut db = AnyUVarDigestDb::init(ctx.clone(), any_var_digest_cfg(&ctx))
                            .await
                            .unwrap();
                        populate_and_sync(
                            &mut db,
                            ELEMENTS,
                            OPERATIONS,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    }
                    (true, true) => {
                        let mut db = AnyOVarDigestDb::init(ctx.clone(), any_var_digest_cfg(&ctx))
                            .await
                            .unwrap();
                        populate_and_sync(
                            &mut db,
                            ELEMENTS,
                            OPERATIONS,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    }
                }
            });

            // Benchmark
            let runner = tokio::Runner::new(cfg.clone());
            c.bench_function(
                &format!("{}/variant={name} max_ops={max_ops}", module_path!()),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            total += match (ordered, variable) {
                                (false, false) => {
                                    let db = AnyUFixDb::init(ctx.clone(), any_fix_cfg(&ctx))
                                        .await
                                        .unwrap();
                                    proof_any(&db, max_ops).await
                                }
                                (true, false) => {
                                    let db = AnyOFixDb::init(ctx.clone(), any_fix_cfg(&ctx))
                                        .await
                                        .unwrap();
                                    proof_any(&db, max_ops).await
                                }
                                (false, true) => {
                                    let db = AnyUVarDigestDb::init(
                                        ctx.clone(),
                                        any_var_digest_cfg(&ctx),
                                    )
                                    .await
                                    .unwrap();
                                    proof_any(&db, max_ops).await
                                }
                                (true, true) => {
                                    let db = AnyOVarDigestDb::init(
                                        ctx.clone(),
                                        any_var_digest_cfg(&ctx),
                                    )
                                    .await
                                    .unwrap();
                                    proof_any(&db, max_ops).await
                                }
                            };
                        }
                        total
                    });
                },
            );

            // Cleanup
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                match (ordered, variable) {
                    (false, false) => {
                        AnyUFixDb::init(ctx.clone(), any_fix_cfg(&ctx))
                            .await
                            .unwrap()
                            .destroy()
                            .await
                            .unwrap();
                    }
                    (true, false) => {
                        AnyOFixDb::init(ctx.clone(), any_fix_cfg(&ctx))
                            .await
                            .unwrap()
                            .destroy()
                            .await
                            .unwrap();
                    }
                    (false, true) => {
                        AnyUVarDigestDb::init(ctx.clone(), any_var_digest_cfg(&ctx))
                            .await
                            .unwrap()
                            .destroy()
                            .await
                            .unwrap();
                    }
                    (true, true) => {
                        AnyOVarDigestDb::init(ctx.clone(), any_var_digest_cfg(&ctx))
                            .await
                            .unwrap()
                            .destroy()
                            .await
                            .unwrap();
                    }
                }
            });
        }
    }
}

fn bench_current_range_proof(c: &mut Criterion) {
    let cfg = Config::default();
    for max_ops in [NZU64!(1), NZU64!(10), NZU64!(100)] {
        for &(name, ordered, variable) in &CURRENT_VARIANTS {
            // Setup
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                match (ordered, variable) {
                    (false, false) => {
                        let mut db = CurUFixDb::init(ctx.clone(), cur_fix_cfg(&ctx))
                            .await
                            .unwrap();
                        populate_and_sync(
                            &mut db,
                            ELEMENTS,
                            OPERATIONS,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    }
                    (true, false) => {
                        let mut db = CurOFixDb::init(ctx.clone(), cur_fix_cfg(&ctx))
                            .await
                            .unwrap();
                        populate_and_sync(
                            &mut db,
                            ELEMENTS,
                            OPERATIONS,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    }
                    (false, true) => {
                        let mut db = CurUVarDigestDb::init(ctx.clone(), cur_var_digest_cfg(&ctx))
                            .await
                            .unwrap();
                        populate_and_sync(
                            &mut db,
                            ELEMENTS,
                            OPERATIONS,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    }
                    (true, true) => {
                        let mut db = CurOVarDigestDb::init(ctx.clone(), cur_var_digest_cfg(&ctx))
                            .await
                            .unwrap();
                        populate_and_sync(
                            &mut db,
                            ELEMENTS,
                            OPERATIONS,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    }
                }
            });

            // Benchmark
            let runner = tokio::Runner::new(cfg.clone());
            c.bench_function(
                &format!("{}/variant={name} max_ops={max_ops}", module_path!()),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            total += match (ordered, variable) {
                                (false, false) => {
                                    let db = CurUFixDb::init(ctx.clone(), cur_fix_cfg(&ctx))
                                        .await
                                        .unwrap();
                                    let start_loc = db.bounds().await.start;
                                    let mut hasher = Sha256::new();
                                    let start = Instant::now();
                                    let _ = db
                                        .range_proof(&mut hasher, start_loc, max_ops)
                                        .await
                                        .unwrap();
                                    start.elapsed()
                                }
                                (true, false) => {
                                    let db = CurOFixDb::init(ctx.clone(), cur_fix_cfg(&ctx))
                                        .await
                                        .unwrap();
                                    let start_loc = db.bounds().await.start;
                                    let mut hasher = Sha256::new();
                                    let start = Instant::now();
                                    let _ = db
                                        .range_proof(&mut hasher, start_loc, max_ops)
                                        .await
                                        .unwrap();
                                    start.elapsed()
                                }
                                (false, true) => {
                                    let db = CurUVarDigestDb::init(
                                        ctx.clone(),
                                        cur_var_digest_cfg(&ctx),
                                    )
                                    .await
                                    .unwrap();
                                    let start_loc = db.bounds().await.start;
                                    let mut hasher = Sha256::new();
                                    let start = Instant::now();
                                    let _ = db
                                        .range_proof(&mut hasher, start_loc, max_ops)
                                        .await
                                        .unwrap();
                                    start.elapsed()
                                }
                                (true, true) => {
                                    let db = CurOVarDigestDb::init(
                                        ctx.clone(),
                                        cur_var_digest_cfg(&ctx),
                                    )
                                    .await
                                    .unwrap();
                                    let start_loc = db.bounds().await.start;
                                    let mut hasher = Sha256::new();
                                    let start = Instant::now();
                                    let _ = db
                                        .range_proof(&mut hasher, start_loc, max_ops)
                                        .await
                                        .unwrap();
                                    start.elapsed()
                                }
                            };
                        }
                        total
                    });
                },
            );

            // Cleanup
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                match (ordered, variable) {
                    (false, false) => {
                        CurUFixDb::init(ctx.clone(), cur_fix_cfg(&ctx))
                            .await
                            .unwrap()
                            .destroy()
                            .await
                            .unwrap();
                    }
                    (true, false) => {
                        CurOFixDb::init(ctx.clone(), cur_fix_cfg(&ctx))
                            .await
                            .unwrap()
                            .destroy()
                            .await
                            .unwrap();
                    }
                    (false, true) => {
                        CurUVarDigestDb::init(ctx.clone(), cur_var_digest_cfg(&ctx))
                            .await
                            .unwrap()
                            .destroy()
                            .await
                            .unwrap();
                    }
                    (true, true) => {
                        CurOVarDigestDb::init(ctx.clone(), cur_var_digest_cfg(&ctx))
                            .await
                            .unwrap()
                            .destroy()
                            .await
                            .unwrap();
                    }
                }
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_any_proof, bench_current_range_proof
}
