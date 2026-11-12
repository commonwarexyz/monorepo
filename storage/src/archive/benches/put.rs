use super::utils::{Archive, Variant, append_random};
use commonware_bench::Inputs;
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
};
use commonware_storage::archive::Archive as _;
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

fn n_items() -> &'static [u64] {
    match Inputs::current() {
        Inputs::Smoke => &[1_000],
        Inputs::Standard => &[10_000],
        Inputs::Full => &[10_000, 50_000, 100_000],
    }
}

fn bench_put(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for variant in [Variant::Prunable, Variant::Immutable] {
        for compression in [None, Some(3)] {
            for &items in n_items() {
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
                            let archive =
                                Archive::init(ctx.child("storage"), variant, compression).await;

                            let start = Instant::now();
                            let (archive, _) = append_random(archive, items).await;
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
