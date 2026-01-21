//! Benchmark comparing `index_of` vs `get` for key-to-index lookups.
//!
//! This benchmark demonstrates the performance benefit of using `index_of`
//! when only the index is needed, as it avoids loading the full value.

use super::utils::{append_random, Archive, Key, Variant};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use commonware_storage::archive::{Archive as ArchiveTrait, Identifier};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{hint::black_box, time::Instant};

/// Items pre-loaded into the archive.
#[cfg(not(full_bench))]
const ITEMS: u64 = 10_000;
#[cfg(full_bench)]
const ITEMS: u64 = 250_000;

#[cfg(not(full_bench))]
const READS: [usize; 1] = [1_000];
#[cfg(full_bench)]
const READS: [usize; 3] = [1_000, 10_000, 50_000];

fn select_keys(keys: &[Key], reads: usize) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_keys = Vec::with_capacity(reads);
    for _ in 0..reads {
        selected_keys.push(keys[rng.gen_range(0..ITEMS as usize)].clone());
    }
    selected_keys
}

/// Lookup using `get(Identifier::Key(k))` - loads full value
async fn lookup_via_get(a: &Archive, keys: &[Key]) {
    for k in keys {
        // Get full value, then extract index (simulating old behavior)
        let _value = black_box(a.get(Identifier::Key(k)).await.unwrap());
    }
}

/// Lookup using `index_of(k)` - returns only index, no value loading
async fn lookup_via_index_of(a: &Archive, keys: &[Key]) {
    for k in keys {
        black_box(a.index_of(k).await.unwrap());
    }
}

fn bench_index_of(c: &mut Criterion) {
    let cfg = Config::default();
    for variant in [Variant::Prunable, Variant::Immutable] {
        for compression in [None, Some(3)] {
            // Create a shared on-disk archive once so later setup is fast.
            let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
            let keys = builder.start(|ctx| async move {
                let mut a = Archive::init(ctx, variant, compression).await;
                let keys = append_random(&mut a, ITEMS).await;
                a.sync().await.unwrap();
                keys
            });

            // Run the benchmarks.
            let runner = tokio::Runner::new(cfg.clone());
            for method in ["get", "index_of"] {
                for reads in READS {
                    let label = format!(
                        "{}/variant={} method={} comp={} reads={}",
                        module_path!(),
                        variant.name(),
                        method,
                        compression
                            .map(|l| l.to_string())
                            .unwrap_or_else(|| "off".into()),
                        reads
                    );
                    c.bench_function(&label, |b| {
                        let keys = keys.clone();
                        b.to_async(&runner).iter_custom(move |iters| {
                            let keys = keys.clone();
                            async move {
                                let ctx = context::get::<commonware_runtime::tokio::Context>();
                                let archive = Archive::init(ctx, variant, compression).await;
                                let selected_keys = select_keys(&keys, reads);
                                let start = Instant::now();
                                for _ in 0..iters {
                                    match method {
                                        "get" => lookup_via_get(&archive, &selected_keys).await,
                                        "index_of" => {
                                            lookup_via_index_of(&archive, &selected_keys).await
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                start.elapsed()
                            }
                        });
                    });
                }
            }

            // Clean up shared artifacts.
            let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
            cleaner.start(|ctx| async move {
                let a = Archive::init(ctx, variant, compression).await;
                a.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_index_of
}
