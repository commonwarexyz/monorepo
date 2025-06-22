use super::utils::{
    append_random_immutable, compression_label, create_benchmark_label, get_immutable_archive,
};
use commonware_runtime::benchmarks::{context, tokio};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_immutable_put(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for compression in [None, Some(3)] {
        for items in [10_000, 50_000, 100_000] {
            let label = create_benchmark_label(
                module_path!(),
                &[
                    ("items", items.to_string()),
                    ("comp", compression_label(compression)),
                ],
            );
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut archive = get_immutable_archive(ctx.clone(), compression).await;

                        let start = Instant::now();
                        append_random_immutable(&mut archive, items).await;
                        total += start.elapsed();

                        archive.destroy().await.unwrap();
                    }
                    total
                });
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_immutable_put
}
