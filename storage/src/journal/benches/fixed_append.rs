use crate::{append_random_data, get_journal};
use commonware_runtime::benchmarks::{context, tokio};
use commonware_utils::NZU64;
use criterion::{criterion_group, Criterion};
use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

/// Partition name to use in the journal config.
const PARTITION: &str = "test_partition";

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000);

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

fn bench_fixed_append(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for items_to_write in [1_000, 10_000, 100_000, 1_000_000] {
        c.bench_function(
            &format!(
                "{}/items={} size={}",
                module_path!(),
                items_to_write,
                ITEM_SIZE
            ),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut duration = Duration::ZERO;
                    for _ in 0..iters {
                        // Create a new journal for each iteration
                        let mut j =
                            get_journal::<ITEM_SIZE>(ctx.clone(), PARTITION, ITEMS_PER_BLOB).await;

                        // Append random data to the journal
                        let start = Instant::now();
                        append_random_data(&mut j, items_to_write).await;
                        duration += start.elapsed();

                        // Destroy the journal after appending to avoid polluting the next iteration
                        j.destroy().await.unwrap();
                    }
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
