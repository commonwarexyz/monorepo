//! Random index-lookup benchmark for Archive.

use super::utils::{append_random, get_archive, ArchiveType};
use commonware_runtime::{
    benchmarks::{context, tokio},
    Runner,
};
use commonware_storage::archive::Identifier;
use criterion::{black_box, criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

const ITEMS: u64 = 1_000_000;

async fn read_serial(a: &ArchiveType, reads: usize) {
    let mut rng = StdRng::seed_from_u64(0);
    for _ in 0..reads {
        let idx = rng.gen_range(0..ITEMS);
        black_box(a.get(Identifier::Index(idx)).await.unwrap().unwrap());
    }
}

async fn read_concurrent(a: &ArchiveType, reads: usize) {
    let mut rng = StdRng::seed_from_u64(0);
    let mut futs = Vec::with_capacity(reads);
    for _ in 0..reads {
        let idx = rng.gen_range(0..ITEMS);
        futs.push(a.get(Identifier::Index(idx)));
    }
    black_box(try_join_all(futs).await.unwrap());
}

fn bench_archive_get_random(c: &mut Criterion) {
    // Pre-populate a shared archive once.
    let writer = commonware_runtime::tokio::Runner::default();
    writer.start(|ctx| async move {
        let mut a = get_archive(ctx, None).await;
        append_random(&mut a, ITEMS).await;
        a.close().await.unwrap();
    });

    let runner = tokio::Runner::default();
    for mode in ["serial", "concurrent"] {
        for reads in [1_000, 10_000, 100_000] {
            let label = format!("{}/mode={} reads={}", module_path!(), mode, reads);
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let archive = get_archive(ctx, None).await;
                    let mut total = Duration::ZERO;

                    for _ in 0..iters {
                        let start = Instant::now();
                        match mode {
                            "serial" => read_serial(&archive, reads).await,
                            "concurrent" => read_concurrent(&archive, reads).await,
                            _ => unreachable!(),
                        }
                        total += start.elapsed();
                    }
                    archive.destroy().await.unwrap();
                    total
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
    targets = bench_archive_get_random
}
