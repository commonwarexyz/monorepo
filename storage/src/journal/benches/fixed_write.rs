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

/// Number of items to write to the journal in each benchmark iteration.
const ITEMS_TO_WRITE: usize = 500_000;

async fn bench_run(journal: &mut Journal<Context, FixedBytes<ITEM_SIZE>>) {
    let mut rng = StdRng::seed_from_u64(0);
    // Append a ton of random items to the journal
    let mut arr = [0; ITEM_SIZE];
    for _ in 0..ITEMS_TO_WRITE {
        rng.fill_bytes(&mut arr);
        journal
            .append(FixedBytes::new(arr))
            .await
            .expect("failed to append data");
    }
}

fn bench_fixed_write(c: &mut Criterion) {
    let executor = tokio::Executor::default();

    c.bench_function(module_path!(), |b| {
        b.to_async(&executor).iter_custom(|iters| async move {
            let ctx = context::get::<commonware_runtime::tokio::Context>();
            let mut duration = Duration::ZERO;
            for _ in 0..iters {
                let mut j = Journal::init(
                    ctx.clone(),
                    JConfig {
                        partition: PARTITION.to_string(),
                        items_per_blob: ITEMS_PER_BLOB,
                    },
                )
                .await
                .unwrap();

                let start = Instant::now();
                bench_run(&mut j).await;
                duration += start.elapsed();

                j.destroy().await.unwrap();
            }
            duration
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_write
}
