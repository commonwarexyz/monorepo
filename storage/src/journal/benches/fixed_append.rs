use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
};
use commonware_storage::journal::fixed::{Config as JConfig, Journal};
use commonware_utils::array::FixedBytes;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 10_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

async fn bench_run(journal: &mut Journal<Context, FixedBytes<ITEM_SIZE>>, items_to_write: usize) {
    let mut rng = StdRng::seed_from_u64(0);
    // Append a ton of random items to the journal
    let mut arr = [0; ITEM_SIZE];
    for _ in 0..items_to_write {
        rng.fill_bytes(&mut arr);
        journal
            .append(FixedBytes::new(arr))
            .await
            .expect("failed to append data");
    }
}

fn bench_fixed_append(c: &mut Criterion) {
    let executor = tokio::Executor::default();
    for items_to_write in [1_000, 10_000, 100_000, 1_000_000] {
        c.bench_function(
            &format!(
                "{}/items={} size={}",
                module_path!(),
                items_to_write,
                ITEM_SIZE
            ),
            |b| {
                b.to_async(&executor).iter_custom(|iters| async move {
                    // Configure the journal
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut j = Journal::init(
                        ctx.clone(),
                        JConfig {
                            partition: PARTITION.to_string(),
                            items_per_blob: ITEMS_PER_BLOB,
                        },
                    )
                    .await
                    .unwrap();

                    // Run the benchmark
                    let mut duration = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        bench_run(&mut j, items_to_write).await;
                        duration += start.elapsed();
                    }
                    j.destroy().await.unwrap();
                    duration
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_append
}
