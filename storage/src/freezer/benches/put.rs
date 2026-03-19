use super::utils::{append_random, init};
use commonware_runtime::benchmarks::{context, tokio};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

#[cfg(not(full_bench))]
const ITEMS: [u64; 1] = [10_000];
#[cfg(full_bench)]
const ITEMS: [u64; 4] = [10_000, 50_000, 100_000, 250_000];

fn bench_put(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for items in ITEMS {
        let label = format!("{}/items={}", module_path!(), items);
        c.bench_function(&label, |b| {
            b.to_async(&runner).iter_custom(move |iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut store = init(ctx.clone()).await;

                    let start = Instant::now();
                    append_random(&mut store, items).await;
                    total += start.elapsed();

                    store.destroy().await.unwrap();
                }
                total
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_put
}
