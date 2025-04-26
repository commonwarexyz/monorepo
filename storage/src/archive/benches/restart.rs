use super::utils::{append_random, get_archive};
use commonware_runtime::{
    benchmarks::{context, tokio},
    Runner,
};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

/// Measure `Archive::init` time for different data sizes.
fn bench_restart(c: &mut Criterion) {
    for compression in [None, Some(3)] {
        // Build a single big archive once
        const ITEMS: u64 = 1_000_000;
        let builder = commonware_runtime::tokio::Runner::default();
        builder.start(|ctx| async move {
            let mut a = get_archive(ctx, compression).await;
            append_random(&mut a, ITEMS).await;
            a.close().await.unwrap();
        });

        let runner = tokio::Runner::default();
        c.bench_function(
            &format!(
                "{}/items={} comp={}",
                module_path!(),
                ITEMS,
                compression
                    .map(|l| l.to_string())
                    .unwrap_or_else(|| "off".into())
            ),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        let a = get_archive(ctx.clone(), compression).await; // replay happens inside init
                        total += start.elapsed();
                        a.close().await.unwrap();
                    }
                    total
                });
            },
        );

        // Tear down
        let cleaner = commonware_runtime::tokio::Runner::default();
        cleaner.start(|ctx| async move {
            let a = get_archive(ctx, compression).await;
            a.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
