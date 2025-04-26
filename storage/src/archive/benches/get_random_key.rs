//! Random key-lookup benchmark for Archive.

use super::utils::{append_random, get_archive, ArchiveType, Key};
use commonware_runtime::{
    benchmarks::{context, tokio},
    Runner,
};
use commonware_storage::archive::Identifier;
use criterion::{black_box, criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

/// Items pre-loaded into the archive.
const ITEMS: u64 = 1_000_000;

async fn read_serial(a: &ArchiveType, keys: &[Key], reads: usize) {
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0..reads {
        let k = &keys[rng.gen_range(0..ITEMS as usize)];
        black_box(a.get(Identifier::Key(k)).await.unwrap().unwrap());
    }
}

async fn read_concurrent(a: &ArchiveType, keys: &[Key], reads: usize) {
    let mut rng = StdRng::seed_from_u64(42);
    let mut owned_keys = Vec::with_capacity(reads);
    for _ in 0..reads {
        owned_keys.push(keys[rng.gen_range(0..ITEMS as usize)].clone());
    }
    let futures = owned_keys.iter().map(|k| a.get(Identifier::Key(k)));
    black_box(try_join_all(futures).await.unwrap());
}

fn bench_archive_get_random_key(c: &mut Criterion) {
    // Create a shared on-disk archive once so later setup is fast.
    let builder = commonware_runtime::tokio::Runner::default();
    let keys = builder.start(|ctx| async move {
        let mut a = get_archive(ctx, None).await;
        let keys = append_random(&mut a, ITEMS).await;
        a.close().await.unwrap();
        keys
    });

    // Run the benchmarks.
    let runner = tokio::Runner::default();
    for mode in ["serial", "concurrent"] {
        for reads in [1_000, 10_000, 100_000] {
            let label = format!("{}/mode={} reads={}", module_path!(), mode, reads);
            c.bench_function(&label, |b| {
                let keys = keys.clone();
                b.to_async(&runner).iter_custom(move |iters| {
                    let keys = keys.clone();
                    async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let archive = get_archive(ctx, None).await;
                        let mut total = Duration::ZERO;

                        for _ in 0..iters {
                            let start = Instant::now();
                            match mode {
                                "serial" => read_serial(&archive, &keys, reads).await,
                                "concurrent" => read_concurrent(&archive, &keys, reads).await,
                                _ => unreachable!(),
                            }
                            total += start.elapsed();
                        }
                        archive.destroy().await.unwrap();
                        total
                    }
                });
            });
        }
    }

    // Clean up shared artifacts.
    let cleaner = commonware_runtime::tokio::Runner::default();
    cleaner.start(|ctx| async move {
        let a = get_archive(ctx, None).await;
        a.destroy().await.unwrap();
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_archive_get_random_key
}
