use super::utils::{append_random_immutable, compression_label, get_immutable};
use commonware_runtime::benchmarks::{context, tokio};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_immutable_put(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for compression in [None, Some(3)] {
        for items in [10_000, 50_000, 100_000] {
            let label = format!(
                "{}/items={} comp={}",
                module_path!(),
                items,
                compression_label(compression)
            );
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut store = get_immutable(ctx.clone(), compression).await;

                        let start = Instant::now();
                        append_random_immutable(&mut store, items).await;
                        total += start.elapsed();

                        store.destroy().await.unwrap();
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
