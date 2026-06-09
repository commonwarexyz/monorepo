//! Benchmarks for speculative batch merkleization.
//!
//! Each iteration creates a speculative batch (10% random updates, sampled with replacement),
//! merkleizes it, and reads the root. The per-iteration `write_random_updates` + `merkleize` +
//! `root()` is timed; one-time setup (seed, churn batches, sync) is not.
//!
//! - [`bench_merkleize`]: timing on a freshly seeded DB (no prior overwrites).
//! - [`bench_merkleize_churned`]: timing after overwrite batches have accumulated inactive
//!   update operations above the inactivity floor — the workload the floor-raise bitmap-skip
//!   optimizes for.

use crate::merkleize_workload::*;
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    Supervisor as _,
};
use criterion::{criterion_group, Criterion};

const fn main_num_keys(seed_sync: bool) -> &'static [u64] {
    if seed_sync {
        SYNC_NUM_KEYS
    } else {
        NUM_KEYS
    }
}

fn bench_merkleize(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for chained in [false, true] {
        for seed_sync in [false, true] {
            for &num_keys in main_num_keys(seed_sync) {
                for &variant in VARIANTS {
                    c.bench_function(
                        &format!(
                            "{}/variant={} keys={num_keys} ch={chained} sync={seed_sync}",
                            module_path!(),
                            variant.name(),
                        ),
                        |b| {
                            b.to_async(&runner).iter_custom(|iters| async move {
                                let ctx = context::get::<Context>();
                                dispatch_variant!(ctx, variant, LARGE_PAGE_CACHE_SIZE, |db| {
                                    if chained {
                                        run_chained_bench(db, num_keys, iters, seed_sync, |p| {
                                            p.new_batch()
                                        })
                                        .await
                                    } else {
                                        run_bench(db, num_keys, iters, seed_sync).await
                                    }
                                })
                            });
                        },
                    );
                }
            }
        }
    }
}

/// Time merkleization after repeatedly overwriting existing keys.
///
/// The overwrite batches create inactive log entries that floor raising must
/// scan past. The smaller cache makes unnecessary reads of those entries show
/// up in the benchmark.
fn bench_merkleize_churned(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    let cache_pages = SMALL_PAGE_CACHE_SIZE.get();
    for &num_keys in CHURNED_NUM_KEYS {
        // `current::*` already used a bitmap; only `any::*` exercises the new scan path.
        for variant in VARIANTS.iter().copied().filter(Variant::is_any) {
            c.bench_function(
                &format!(
                    "{}/variant={} keys={num_keys} churn={CHURN_BATCHES} cache_pages={cache_pages}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        dispatch_variant!(ctx, variant, SMALL_PAGE_CACHE_SIZE, |db| {
                            run_churned_bench(db, num_keys, CHURN_BATCHES, iters).await
                        })
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_merkleize, bench_merkleize_churned
}
