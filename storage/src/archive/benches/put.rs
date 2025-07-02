use super::utils::{
    append_random, ArchiveFactory, ImmutableArchiveFactory, PrunableArchiveFactory,
};
use commonware_runtime::benchmarks::{context, tokio};
use commonware_storage::archive::Archive;
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_put_for_factory<F: ArchiveFactory>(
    c: &mut Criterion,
    runner: &tokio::Runner,
    compression: Option<u8>,
    impl_name: &str,
) {
    for items in [10_000, 50_000, 100_000] {
        let label = format!(
            "{}/impl={} items={} comp={}",
            module_path!(),
            impl_name,
            items,
            compression
                .map(|l| l.to_string())
                .unwrap_or_else(|| "off".into()),
        );
        c.bench_function(&label, |b| {
            b.to_async(runner).iter_custom(move |iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut archive = F::init(ctx.clone(), compression).await.unwrap();

                    let start = Instant::now();
                    append_random(&mut archive, items).await;
                    total += start.elapsed();

                    archive.destroy().await.unwrap();
                }
                total
            });
        });
    }
}

fn bench_put(c: &mut Criterion) {
    let runner = tokio::Runner::default();

    // Test prunable implementation
    for compression in [None, Some(3)] {
        bench_put_for_factory::<PrunableArchiveFactory>(c, &runner, compression, "prunable");
    }

    // Test immutable implementation
    for compression in [None, Some(3)] {
        bench_put_for_factory::<ImmutableArchiveFactory>(c, &runner, compression, "immutable");
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_put
}
