use super::append_random_data;
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
};
use commonware_storage::journal::fixed::Journal;
use commonware_utils::array::FixedBytes;
use criterion::{black_box, criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 10_000;

/// Number of items to write to the journal we will be reading from.
const ITEMS_TO_WRITE: u64 = 5_000_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Read `items_to_read` random items from the given `journal`, awaiting each
/// result before continuing.
async fn bench_run_serial(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, items_to_read: usize) {
    let mut rng = StdRng::seed_from_u64(0);
    for _ in 0..items_to_read {
        let pos = rng.gen_range(0..ITEMS_TO_WRITE);
        black_box(journal.read(pos).await.expect("failed to read data"));
    }
}

/// Concurrently read (via try_join_all) `items_to_read` random items from the given `journal`.
async fn bench_run_concurrent(
    journal: &Journal<Context, FixedBytes<ITEM_SIZE>>,
    items_to_read: usize,
) {
    let mut rng = StdRng::seed_from_u64(0);
    let mut futures = Vec::with_capacity(items_to_read);
    for _ in 0..items_to_read {
        let pos = rng.gen_range(0..ITEMS_TO_WRITE);
        futures.push(journal.read(pos));
    }
    try_join_all(futures).await.expect("failed to read data");
}

fn bench_fixed_read_random(c: &mut Criterion) {
    let executor = tokio::Executor::default();
    for mode in ["serial", "concurrent"] {
        for items_to_read in [100, 1_000, 10_000, 100_000] {
            c.bench_function(
                &format!(
                    "{}/mode={} items={} size={}",
                    module_path!(),
                    mode,
                    items_to_read,
                    ITEM_SIZE
                ),
                |b| {
                    b.to_async(&executor).iter_custom(|iters| async move {
                        // Append random data to the journal
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let j = append_random_data(
                            ctx.clone(),
                            PARTITION,
                            ITEMS_PER_BLOB,
                            ITEMS_TO_WRITE,
                        )
                        .await;

                        // Run the benchmark
                        let mut duration = Duration::ZERO;
                        for _ in 0..iters {
                            let start = Instant::now();
                            match mode {
                                "serial" => bench_run_serial(&j, items_to_read).await,
                                "concurrent" => bench_run_concurrent(&j, items_to_read).await,
                                _ => unreachable!(),
                            }
                            duration += start.elapsed();
                        }

                        // Destroy the journal after reading to avoid polluting the next iteration
                        j.destroy().await.unwrap();

                        duration
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_read_random
}
