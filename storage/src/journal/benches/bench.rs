use commonware_runtime::tokio::Context;
use commonware_storage::journal::fixed::{Config as JConfig, Journal};
use commonware_utils::array::FixedBytes;
use criterion::criterion_main;
use rand::{rngs::StdRng, RngCore, SeedableRng};

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

/// Append `items_to_write` random items to a journal of items with ITEM_SIZE bytes each. The journal
/// is configured to use `items_per_blob` items per blob.
async fn append_random_data<const ITEM_SIZE: usize>(
    context: Context,
    partition_name: &str,
    items_per_blob: u64,
    items_to_write: u64,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    // Initialize the journal at the given partition.
    let journal_config = JConfig {
        partition: partition_name.to_string(),
        items_per_blob,
    };
    let mut journal = Journal::init(context, journal_config).await.unwrap();

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

    journal
}
