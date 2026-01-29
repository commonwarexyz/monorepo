use commonware_runtime::{buffer::paged::CacheRef, tokio::Context};
use commonware_storage::{
    journal::contiguous::{
        fixed::{Config as FixedConfig, Journal as FixedJournal},
        variable::{Config as VariableConfig, Journal as VariableJournal},
        MutableContiguous,
    },
    Persistable,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use criterion::criterion_main;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

mod fixed_append;
mod fixed_read_random;
mod fixed_read_sequential;
mod fixed_replay;
mod variable_replay;

criterion_main!(
    fixed_append::benches,
    fixed_read_random::benches,
    fixed_read_sequential::benches,
    fixed_replay::benches,
    variable_replay::benches,
);

/// The size of the write buffer used by the journal.
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1_024 * 1024); // 1MB

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroU16 = NZU16!(8_192);

/// The number of pages to cache in the page cache. Make it big enough to be
/// fast, but not so big we avoid any page faults for the larger benchmarks.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Value of items_per_blob to use in the journal config.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(100_000);

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Open and return a temp fixed journal with the given config parameters and items of size ITEM_SIZE.
async fn get_fixed_journal<const ITEM_SIZE: usize>(
    context: Context,
    partition_name: &str,
    items_per_blob: NonZeroU64,
) -> FixedJournal<Context, FixedBytes<ITEM_SIZE>> {
    // Initialize the journal at the given partition.
    let journal_config = FixedConfig {
        partition: partition_name.to_string(),
        items_per_blob,
        write_buffer: WRITE_BUFFER,
        page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    };
    FixedJournal::init(context, journal_config).await.unwrap()
}

/// Append `items_to_write` random items to the given fixed journal, syncing the changes before returning.
async fn append_fixed_random_data<C, const ITEM_SIZE: usize>(journal: &mut C, items_to_write: u64)
where
    C: MutableContiguous<Item = FixedBytes<ITEM_SIZE>> + Persistable,
    C::Error: std::fmt::Debug,
{
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
    journal.sync().await.expect("failed to sync journal");
}

/// Open and return a temp variable journal with the given config parameters.
async fn get_variable_journal<const ITEM_SIZE: usize>(
    context: Context,
    partition_name: &str,
    items_per_section: NonZeroU64,
) -> VariableJournal<Context, FixedBytes<ITEM_SIZE>> {
    // Initialize the journal at the given partition.
    let journal_config = VariableConfig {
        partition: partition_name.to_string(),
        items_per_section,
        compression: None,
        codec_config: (),
        page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        write_buffer: WRITE_BUFFER,
    };
    VariableJournal::init(context, journal_config)
        .await
        .unwrap()
}
