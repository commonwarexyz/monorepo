//! Helpers shared by the Store benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::store::{immutable, ordinal};
use commonware_utils::array::FixedBytes;
use criterion::black_box;
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};

/// Number of bytes that can be buffered before being written to disk.
const WRITE_BUFFER: usize = 1024;

/// Number of bytes to buffer when replaying.
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Fixed-length key and value types.
pub type Key = FixedBytes<64>;
pub type ImmutableVal = FixedBytes<128>;
pub type OrdinalVal = FixedBytes<32>;

/// Concrete immutable store type for benchmarks.
pub type ImmutableStore = immutable::Store<Context, Key, ImmutableVal>;

/// Concrete ordinal store type for benchmarks.
pub type OrdinalStore = ordinal::Store<Context, OrdinalVal>;

/// Partition prefixes for immutable store benchmarks.
pub const IMMUTABLE_JOURNAL_PARTITION: &str = "immutable_bench_journal";
pub const IMMUTABLE_METADATA_PARTITION: &str = "immutable_bench_metadata";
pub const IMMUTABLE_TABLE_PARTITION: &str = "immutable_bench_table";

/// Configuration constants for immutable store.
const IMMUTABLE_TABLE_SIZE: u32 = 16384; // 16K buckets for better distribution
const IMMUTABLE_TARGET_JOURNAL_SIZE: u64 = 100 * 1024 * 1024; // 100MB

/// Partition for ordinal store benchmarks.
pub const ORDINAL_PARTITION: &str = "ordinal_bench_partition";

/// Configuration constants for ordinal store.
const ORDINAL_ITEMS_PER_BLOB: u64 = 10000;

/// Open (or create) an immutable store.
pub async fn get_immutable(ctx: Context, compression: Option<u8>) -> ImmutableStore {
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

/// Open (or create) an ordinal store.
pub async fn get_ordinal(ctx: Context) -> OrdinalStore {
    let cfg = ordinal::Config {
        partition: ORDINAL_PARTITION.into(),
        items_per_blob: ORDINAL_ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER,
        replay_buffer: REPLAY_BUFFER,
    };
    ordinal::Store::init(ctx, cfg).await.unwrap()
}

/// Append `count` random key-value pairs to immutable store and sync once.
pub async fn append_random_immutable(store: &mut ImmutableStore, count: u64) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut key_buf = [0u8; 64];
    let mut val_buf = [0u8; 128];

    let mut keys = Vec::with_capacity(count as usize);
    for _ in 0..count {
        rng.fill_bytes(&mut key_buf);
        let key = Key::new(key_buf);
        keys.push(key.clone());
        rng.fill_bytes(&mut val_buf);
        store.put(key, ImmutableVal::new(val_buf)).await.unwrap();
    }
    store.sync().await.unwrap();
    keys
}

/// Append `count` random index-value pairs to ordinal store and sync once.
pub async fn append_random_ordinal(store: &mut OrdinalStore, count: u64) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut val_buf = [0u8; 32];

    let mut indices = Vec::with_capacity(count as usize);
    for i in 0..count {
        indices.push(i);
        rng.fill_bytes(&mut val_buf);
        store.put(i, OrdinalVal::new(val_buf)).unwrap();
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

/// Select random keys from a vec for benchmarking.
pub fn select_keys(keys: &[Key], count: usize, items: u64) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_keys = Vec::with_capacity(count);
    for _ in 0..count {
        selected_keys.push(keys[rng.gen_range(0..items as usize)].clone());
    }
    selected_keys
}

/// Select random indices for benchmarking.
pub fn select_indices(count: usize, items: u64) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_indices = Vec::with_capacity(count);
    for _ in 0..count {
        selected_indices.push(rng.gen_range(0..items));
    }
    selected_indices
}

/// Read keys serially from an immutable store.
pub async fn read_serial_keys_immutable(store: &ImmutableStore, reads: &[Key]) {
    for k in reads {
        black_box(store.get(k).await.unwrap().unwrap());
    }
}

/// Read indices serially from an ordinal store.
pub async fn read_serial_indices_ordinal(store: &OrdinalStore, indices: &[u64]) {
    for idx in indices {
        black_box(store.get(*idx).await.unwrap().unwrap());
    }
}

/// Read keys concurrently from an immutable store.
pub async fn read_concurrent_keys_immutable(store: &ImmutableStore, reads: Vec<Key>) {
    let futures = reads.iter().map(|k| store.get(k));
    black_box(try_join_all(futures).await.unwrap());
}

/// Read indices concurrently from an ordinal store.
pub async fn read_concurrent_indices_ordinal(store: &OrdinalStore, indices: &[u64]) {
    let mut futures = Vec::with_capacity(indices.len());
    for idx in indices {
        futures.push(store.get(*idx));
    }
    black_box(try_join_all(futures).await.unwrap());
}
