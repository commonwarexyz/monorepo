use commonware_runtime::benchmarks::{context, tokio};
use commonware_storage::archive::Archive;
use criterion::{black_box, criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

const ITEMS_WRITTEN: u64 = 1_000_000;

async fn read_random_serial(archive: &Archive, reads: usize) {
    let mut rng = StdRng::seed_from_u64(0);
    for _ in 0..reads {
        let idx = rng.gen_range(0..ITEMS_WRITTEN);
        black_box(
            archive
                .get(util::Identifier::Index(idx))
                .await
                .unwrap()
                .unwrap(),
        );
    }
}

async fn read_random_concurrent(archive: &Archive, reads: usize)
where
    Archive: commonware_storage::archive::ArchiveTrait,
{
    let mut rng = StdRng::seed_from_u64(0);
    let mut futs = Vec::with_capacity(reads);
    for _ in 0..reads {
        let idx = rng.gen_range(0..ITEMS_WRITTEN);
        futs.push(archive.get(util::Identifier::Index(idx)));
    }
    let results = try_join_all(futs).await.unwrap();
    black_box(results);
}

fn bench_archive_get_random(c: &mut Criterion) {
    let runner = tokio::Runner::default();

    // Ensure we have a pre-populated archive on disk that all iterations reuse
    let writer = commonware_runtime::tokio::Runner::default();
    writer.start(|ctx| async move {
        let mut a = util::get_archive(ctx, None).await;
        util::append_random(&mut a, ITEMS_WRITTEN).await;
        a.close().await.unwrap();
    });

    for mode in ["serial", "concurrent"] {
        for reads in [1_000, 10_000, 100_000] {
            let lbl = format!("{}/mode={} reads={}", module_path!(), mode, reads);
            c.bench_function(&lbl, |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let archive = util::get_archive(ctx, None).await;
                    let mut total = Duration::ZERO;

                    for _ in 0..iters {
                        let start = Instant::now();
                        match mode {
                            "serial" => read_random_serial(&archive, reads).await,
                            "concurrent" => read_random_concurrent(&archive, reads).await,
                            _ => unreachable!(),
                        }
                        total += start.elapsed();
                    }
                    total
                });
            });
        }
    }

    // Clean up
    let cleaner = commonware_runtime::tokio::Runner::default();
    cleaner.start(|ctx| async move {
        let a = util::get_archive(ctx, None).await;
        a.destroy().await.unwrap();
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_archive_get_random
}
