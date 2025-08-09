use super::{append_random_data, get_journal};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
};
use commonware_storage::journal::fixed::Journal;
use commonware_utils::sequence::FixedBytes;
use criterion::{black_box, criterion_group, Criterion};
use std::time::{Duration, Instant};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: u64 = 100_000;

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Sequentially read `items_to_read` items in the given `journal` starting from item 0.
async fn bench_run(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, items_to_read: u64) {
    for pos in 0..items_to_read {
        black_box(journal.read(pos).await.expect("failed to read data"));
    }
}

/// Benchmark the sequential read of items from a journal containing exactly that
/// number of items.
fn bench_fixed_read_sequential(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for items in [1_000, 10_000, 100_000, 500_000] {
        c.bench_function(
            &format!("{}/items={} size={}", module_path!(), items, ITEM_SIZE),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    // Append random data to the journal
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut j = get_journal::<ITEM_SIZE>(ctx, PARTITION, ITEMS_PER_BLOB).await;
                    append_random_data::<ITEM_SIZE>(&mut j, items).await;
                    let sz = j.size().await.unwrap();
                    assert_eq!(sz, items);

                    // Run the benchmark
                    let mut duration = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        bench_run(&j, items).await;
                        duration += start.elapsed();
                    }

                    // Destroy the journal after appending to avoid polluting the next iteration
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
    targets = bench_fixed_read_sequential
}
