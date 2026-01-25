use super::utils::{append_random, Archive, Variant};
use commonware_runtime::benchmarks::{context, tokio};
use commonware_storage::archive::Archive as _;
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

#[cfg(not(full_bench))]
const ITEMS: [u64; 1] = [10_000];
#[cfg(full_bench)]
const ITEMS: [u64; 3] = [10_000, 50_000, 100_000];

fn bench_put(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for variant in [Variant::Prunable, Variant::Immutable] {
        for compression in [None, Some(3)] {
            for items in ITEMS {
                let label = format!(
                    "{}/variant={} items={} comp={}",
                    module_path!(),
                    variant.name(),
                    items,
                    compression
                        .map(|l| l.to_string())
                        .unwrap_or_else(|| "off".into()),
                );
                c.bench_function(&label, |b| {
                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let mut archive =
                                Archive::init(ctx.clone(), variant, compression).await;

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
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_put
}
