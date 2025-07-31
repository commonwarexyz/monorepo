//! Helpers shared by the Freezer benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::freezer::{Config, Freezer};
use commonware_utils::sequence::FixedBytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Number of bytes that can be buffered before being written to disk.
const JOURNAL_WRITE_BUFFER: usize = 1024 * 1024; // 1MB

/// Target size of each journal section before creating a new one.
const JOURNAL_TARGET_SIZE: u64 = 100 * 1024 * 1024; // 100MB

/// Initial size of the table.
const TABLE_INITIAL_SIZE: u32 = 65_536;

/// Number of items added to a table entry before resize.
const TABLE_RESIZE_FREQUENCY: u8 = 4;

/// Number of items to process per chunk during resize.
const TABLE_RESIZE_CHUNK_SIZE: u32 = 1024;

/// Size of the replay buffer when scanning the table.
const TABLE_REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Partition for [Freezer] journal benchmarks.
pub const JOURNAL_PARTITION: &str = "freezer_bench_journal";

/// Partition for [Freezer] table benchmarks.
pub const TABLE_PARTITION: &str = "freezer_bench_table";

/// Fixed-length key and value types.
pub type Key = FixedBytes<64>;
pub type Val = FixedBytes<128>;

/// Concrete freezer store type for benchmarks.
pub type FreezerType = Freezer<Context, Key, Val>;

/// Open (or create) a freezer store.
pub async fn init(ctx: Context) -> FreezerType {
    let cfg = Config {
        journal_partition: JOURNAL_PARTITION.into(),
        journal_compression: None,
        journal_write_buffer: JOURNAL_WRITE_BUFFER,
        journal_target_size: JOURNAL_TARGET_SIZE,
        table_partition: TABLE_PARTITION.into(),
        table_initial_size: TABLE_INITIAL_SIZE,
        table_resize_frequency: TABLE_RESIZE_FREQUENCY,
        table_resize_chunk_size: TABLE_RESIZE_CHUNK_SIZE,
        table_replay_buffer: TABLE_REPLAY_BUFFER,
        codec_config: (),
    };
    Freezer::init(ctx, cfg).await.unwrap()
}

/// Append `count` key-value pairs with random values to freezer store and sync once.
pub async fn append_random(freezer: &mut FreezerType, count: u64) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut key_buf = [0u8; 64];
    let mut val_buf = [0u8; 128];

    let mut keys = Vec::with_capacity(count as usize);
    for _ in 0..count {
        rng.fill_bytes(&mut key_buf);
        let key = Key::new(key_buf);
        keys.push(key.clone());
        rng.fill_bytes(&mut val_buf);
        freezer.put(key, Val::new(val_buf)).await.unwrap();
    }
    freezer.sync().await.unwrap();
    keys
}
