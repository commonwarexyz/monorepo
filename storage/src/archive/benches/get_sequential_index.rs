//! Sequential index-scan benchmark for Archive.

use super::utils::{append_random, get_archive};
use commonware_runtime::benchmarks::{context, tokio};
use commonware_storage::archive::Identifier;
use criterion::{black_box, criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_archive_get_sequential(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for items in [10_000_u64, 100_000_u64, 500_000_u64] {
        let label = format!("{}/items={}", module_path!(), items);
        c.bench_function(&label, |b| {
            b.to_async(&runner).iter_custom(move |iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut archive = get_archive(ctx, None).await;
                append_random(&mut archive, items).await;

                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    for idx in 0..items {
                        black_box(archive.get(Identifier::Index(idx)).await.unwrap().unwrap());
                    }
                    total += start.elapsed();
                }
                archive.destroy().await.unwrap();
                total
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_archive_get_sequential
}
