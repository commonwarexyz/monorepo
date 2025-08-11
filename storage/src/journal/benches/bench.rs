use commonware_runtime::{buffer::PoolRef, tokio::Context};
use commonware_storage::journal::fixed::{Config as JConfig, Journal};
use commonware_utils::{sequence::FixedBytes, NZUsize};
use criterion::criterion_main;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::num::{NonZeroU64, NonZeroUsize};

mod fixed_append;
mod fixed_read_random;
mod fixed_read_sequential;
mod fixed_replay;

criterion_main!(
    fixed_append::benches,
    fixed_read_random::benches,
    fixed_read_sequential::benches,
    fixed_replay::benches,
);

/// The size of the write buffer used by the journal.
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1_024 * 1024); // 1MB

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16384);

/// The number of pages to cache in the buffer pool. Make it big enough to be
/// fast, but not so big we avoid any page faults for the larger benchmarks.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Open and return a temp journal with the given config parameters and items of size ITEM_SIZE.
async fn get_journal<const ITEM_SIZE: usize>(
    context: Context,
    partition_name: &str,
    items_per_blob: NonZeroU64,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    // Initialize the journal at the given partition.
    let journal_config = JConfig {
        partition: partition_name.to_string(),
        items_per_blob,
        write_buffer: WRITE_BUFFER,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    };
    Journal::init(context, journal_config).await.unwrap()
}

/// Append `items_to_write` random items to the given journal, syncing the changes before returning.
async fn append_random_data<const ITEM_SIZE: usize>(
    journal: &mut Journal<Context, FixedBytes<ITEM_SIZE>>,
    items_to_write: u64,
) {
    // Append `items_to_write` random items to the journal.
    let mut rng = StdRng::seed_from_u64(0);
    let mut arr = [0; ITEM_SIZE];
    for _ in 0..items_to_write {
        rng.fill_bytes(&mut arr);
        journal
            .append(FixedBytes::new(arr))
            .await
            .expect("failed to append data");
    }

    // Sync the journal to ensure all data is written to disk.
    journal.sync().await.unwrap();
}
