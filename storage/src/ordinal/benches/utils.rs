//! Helpers shared by the Store benchmarks.
use commonware_runtime::tokio::Context;
use commonware_storage::store::{immutable, ordinal};
use commonware_utils::array::FixedBytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Number of bytes that can be buffered before being written to disk.
const WRITE_BUFFER: usize = 1024;

/// Number of bytes to buffer when replaying.
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Fixed-length key and value types.
pub type Key = FixedBytes<64>;
pub type Value = FixedBytes<128>;

/// Concrete immutable store type for benchmarks.
pub type Immutable = immutable::Store<Context, Key, Value>;

/// Partition prefixes for immutable store benchmarks.
pub const IMMUTABLE_JOURNAL_PARTITION: &str = "immutable_bench_journal";
pub const IMMUTABLE_METADATA_PARTITION: &str = "immutable_bench_metadata";
pub const IMMUTABLE_TABLE_PARTITION: &str = "immutable_bench_table";

/// Configuration constants for immutable store.
const IMMUTABLE_TABLE_SIZE: u32 = 16384; // 16K buckets for better distribution
const IMMUTABLE_TARGET_JOURNAL_SIZE: u64 = 100 * 1024 * 1024; // 100MB

/// Open (or create) an immutable store.
pub async fn get_immutable(ctx: Context, compression: Option<u8>) -> Immutable {
    let cfg = immutable::Config {
        journal_partition: IMMUTABLE_JOURNAL_PARTITION.into(),
        journal_compression: compression,
        metadata_partition: IMMUTABLE_METADATA_PARTITION.into(),
        table_partition: IMMUTABLE_TABLE_PARTITION.into(),
        table_size: IMMUTABLE_TABLE_SIZE,
        codec_config: (),
        write_buffer: WRITE_BUFFER,
        target_journal_size: IMMUTABLE_TARGET_JOURNAL_SIZE,
    };
    immutable::Store::init(ctx, cfg).await.unwrap()
}

/// Append `count` random key-value pairs to immutable store and sync once.
pub async fn append_random_immutable(store: &mut Immutable, count: u64) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut key_buf = [0u8; 64];
    let mut val_buf = [0u8; 128];

    let mut keys = Vec::with_capacity(count as usize);
    for _ in 0..count {
        rng.fill_bytes(&mut key_buf);
        let key = Key::new(key_buf);
        keys.push(key.clone());
        rng.fill_bytes(&mut val_buf);
        store.put(key, Value::new(val_buf)).await.unwrap();
    }
    store.sync().await.unwrap();
    keys
}

/// Partition for ordinal store benchmarks.
pub const ORDINAL_PARTITION: &str = "ordinal_bench_partition";

/// Configuration constants for ordinal store.
const ORDINAL_ITEMS_PER_BLOB: u64 = 10000;

/// Concrete ordinal store type for benchmarks.
pub type Ordinal = ordinal::Store<Context, Value>;

/// Open (or create) an ordinal store.
pub async fn get_ordinal(ctx: Context) -> Ordinal {
    let cfg = ordinal::Config {
        partition: ORDINAL_PARTITION.into(),
        items_per_blob: ORDINAL_ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER,
        replay_buffer: REPLAY_BUFFER,
    };
    ordinal::Store::init(ctx, cfg).await.unwrap()
}

/// Append `count` random index-value pairs to ordinal store and sync once.
pub async fn append_random_ordinal(store: &mut Ordinal, count: u64) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut val_buf = [0u8; 128];

    let mut indices = Vec::with_capacity(count as usize);
    for i in 0..count {
        indices.push(i);
        rng.fill_bytes(&mut val_buf);
        store.put(i, Value::new(val_buf)).unwrap();
    }
    store.sync().await.unwrap();
    indices
}

/// Create a compression label string for benchmarks.
pub fn compression_label(compression: Option<u8>) -> String {
    compression
        .map(|l| l.to_string())
        .unwrap_or_else(|| "off".into())
}
