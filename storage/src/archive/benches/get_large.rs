//! Random key-lookup benchmark for Archive with large (64KB) values.

use super::utils::{append_random_large, LargeArchive, Variant};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use commonware_storage::archive::{Archive as ArchiveTrait, Identifier};
use criterion::{criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{hint::black_box, time::Instant};

/// Items pre-loaded into the archive (fewer due to 64KB values).
const ITEMS: u64 = 1_000;

fn select_indices(reads: usize) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_indices = Vec::with_capacity(reads);
    for _ in 0..reads {
        selected_indices.push(rng.gen_range(0..ITEMS));
    }
    selected_indices
}

async fn read_serial_indices(a: &LargeArchive, indices: &[u64]) {
    for idx in indices {
        black_box(a.get(Identifier::Index(*idx)).await.unwrap().unwrap());
    }
}

async fn read_concurrent_indices(a: &LargeArchive, indices: &[u64]) {
    let mut futs = Vec::with_capacity(indices.len());
    for idx in indices {
        futs.push(a.get(Identifier::Index(*idx)));
    }
    black_box(try_join_all(futs).await.unwrap());
}

fn bench_get_large(c: &mut Criterion) {
    let cfg = Config::default();
    for variant in [Variant::Prunable] {
        for compression in [Some(3)] {
            // Create a shared on-disk archive once so later setup is fast.
            let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
            let _keys = builder.start(|ctx| async move {
                let mut a = LargeArchive::init(ctx, variant, compression).await;
                let keys = append_random_large(&mut a, ITEMS).await;
                a.sync().await.unwrap();
                keys
            });

            // Run the benchmarks.
            let runner = tokio::Runner::new(cfg.clone());
            for mode in ["serial", "concurrent"] {
                for reads in [100, 500] {
                    let label = format!(
                        "{}/variant={} mode={} pattern=index comp={} reads={} val_size=64KB",
                        module_path!(),
                        variant.name(),
                        mode,
                        compression
                            .map(|l| l.to_string())
                            .unwrap_or_else(|| "off".into()),
                        reads
                    );
                    c.bench_function(&label, |b| {
                        b.to_async(&runner).iter_custom(move |iters| async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let archive = LargeArchive::init(ctx, variant, compression).await;
                            let selected_indices = select_indices(reads);
                            let start = Instant::now();
                            for _ in 0..iters {
                                match mode {
                                    "serial" => {
                                        read_serial_indices(&archive, &selected_indices).await
                                    }
                                    "concurrent" => {
                                        read_concurrent_indices(&archive, &selected_indices).await
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            start.elapsed()
                        });
                    });
                }
            }

            // Clean up shared artifacts.
            let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
            cleaner.start(|ctx| async move {
                let a = LargeArchive::init(ctx, variant, compression).await;
                a.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get_large
}
