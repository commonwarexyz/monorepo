use commonware_runtime::tokio::Context;
use commonware_storage::journal::fixed::{Config as JConfig, Journal};
use commonware_utils::array::FixedBytes;
use criterion::criterion_main;
use rand::{rngs::StdRng, RngCore, SeedableRng};

mod fixed_read_random;
mod fixed_read_sequential;
mod fixed_write;

criterion_main!(
    fixed_write::benches,
    fixed_read_random::benches,
    fixed_read_sequential::benches
);

/// Write `items_to_write` random items to a journal of items with ITEM_SIZE bytes each. The journal
/// is configured to use `items_per_blob` items per blob.
async fn write_random_journal<const ITEM_SIZE: usize>(
    context: Context,
    partition_name: &str,
    items_per_blob: u64,
    items_to_write: u64,
    prune: bool, // whether to prune to 0 items before writing
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let journal_config = JConfig {
        partition: partition_name.to_string(),
        items_per_blob,
    };

    // Initialize the journal and prune it to its empty state if requested.
    let mut journal = Journal::init(context, journal_config).await.unwrap();
    if prune {
        journal.prune(0).await.unwrap();
    }

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
    journal.sync().await.unwrap();

    journal
}

/// Get a previously initialized random journal with the given journal config parameters.
async fn get_random_journal<const ITEM_SIZE: usize>(
    context: Context,
    partition_name: &str,
    items_per_blob: u64,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let journal_config = JConfig {
        partition: partition_name.to_string(),
        items_per_blob,
    };
    Journal::init(context, journal_config).await.unwrap()
}
