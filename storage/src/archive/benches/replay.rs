use commonware_runtime::benchmarks::{context, tokio};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

mod util;
use util::*;

/// Measure `Archive::init` (replay) time for different data sizes.
fn bench_archive_replay(c: &mut Criterion) {
    // Build a single big archive once
    const ITEMS: u64 = 1_000_000;
    let builder = commonware_runtime::tokio::Runner::default();
    builder.start(|ctx| async move {
        let mut a = util::get_archive(ctx, None).await;
        util::append_random(&mut a, ITEMS).await;
        a.close().await.unwrap();
    });

    let runner = tokio::Runner::default();
    c.bench_function(&format!("{}/items={}", module_path!(), ITEMS), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let start = Instant::now();
                let a = util::get_archive(ctx, None).await; // replay happens inside init
                total += start.elapsed();
                a.close().await.unwrap();
            }
            total
        });
    });

    // Tear down
    let cleaner = commonware_runtime::tokio::Runner::default();
    cleaner.start(|ctx| async move {
        let a = util::get_archive(ctx, None).await;
        a.destroy().await.unwrap();
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_archive_replay
}
