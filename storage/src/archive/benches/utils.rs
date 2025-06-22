//! Helpers shared by the Archive benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::{
    archive::prunable::{Archive, Config},
    translator::TwoCap,
};
use commonware_utils::array::FixedBytes;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

/// Partition used across all archive benchmarks.
pub const PARTITION: &str = "archive_bench_partition";

/// Number of bytes that can be buffered in a section before being written to disk.
const WRITE_BUFFER: usize = 1024;

/// Section-mask that yields reasonably small blobs for local testing.
const SECTION_MASK: u64 = 0xffff_ffff_ffff_ff00u64;

/// Number of bytes to buffer when replaying.
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Fixed-length key and value types.
pub type Key = FixedBytes<64>;
pub type Val = FixedBytes<32>;

/// Concrete archive type reused by every benchmark.
pub type ArchiveType = Archive<TwoCap, Context, Key, Val>;

/// Open (or create) a fresh archive with optional compression.
///
/// The caller is responsible for closing or destroying it.
pub async fn get_archive(ctx: Context, compression: Option<u8>) -> ArchiveType {
    let cfg = Config {
        partition: PARTITION.into(),
        translator: TwoCap,
        compression,
        codec_config: (),
        section_mask: SECTION_MASK,
        write_buffer: WRITE_BUFFER,
        replay_buffer: REPLAY_BUFFER,
    };
    Archive::init(ctx, cfg).await.unwrap()
}

/// Append `count` random (index,key,value) triples and sync once.
pub async fn append_random(archive: &mut ArchiveType, count: u64) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut key_buf = [0u8; 64];
    let mut val_buf = [0u8; 32];

    let mut keys = Vec::with_capacity(count as usize);
    for i in 0..count {
        rng.fill_bytes(&mut key_buf);
        let key = Key::new(key_buf);
        keys.push(key.clone());
        rng.fill_bytes(&mut val_buf);
        archive.put(i, key, Val::new(val_buf)).await.unwrap();
    }
    archive.sync().await.unwrap();
    keys
}

// === Immutable Archive Helpers ===
use commonware_storage::{
    archive::immutable::{Archive as ImmutableArchive, Config as ImmutableConfig},
    store::{immutable, ordinal},
};

/// Partition prefixes for immutable archive benchmarks.
pub const IMMUTABLE_DATA_PARTITION: &str = "immutable_bench_data";
pub const IMMUTABLE_METADATA_PARTITION: &str = "immutable_bench_metadata";
pub const IMMUTABLE_TABLE_PARTITION: &str = "immutable_bench_table";
pub const IMMUTABLE_INDEX_PARTITION: &str = "immutable_bench_index";

/// Configuration constants for immutable archive.
const IMMUTABLE_TABLE_SIZE: u32 = 256;
const IMMUTABLE_ITEMS_PER_BLOB: u64 = 10000;
const IMMUTABLE_TARGET_JOURNAL_SIZE: u64 = 100 * 1024 * 1024; // 100MB

/// Concrete immutable archive type for benchmarks.
pub type ImmutableArchiveType = ImmutableArchive<Context, Key, Val>;

/// Open (or create) a fresh immutable archive with optional compression.
///
/// The caller is responsible for closing or destroying it.
pub async fn get_immutable_archive(ctx: Context, compression: Option<u8>) -> ImmutableArchiveType {
    let cfg = ImmutableConfig {
        immutable: immutable::Config {
            journal_partition: IMMUTABLE_DATA_PARTITION.into(),
            journal_compression: compression,
            metadata_partition: IMMUTABLE_METADATA_PARTITION.into(),
            table_partition: IMMUTABLE_TABLE_PARTITION.into(),
            table_size: IMMUTABLE_TABLE_SIZE,
            codec_config: (),
            write_buffer: WRITE_BUFFER,
            target_journal_size: IMMUTABLE_TARGET_JOURNAL_SIZE,
        },
        ordinal: ordinal::Config {
            partition: IMMUTABLE_INDEX_PARTITION.into(),
            items_per_blob: IMMUTABLE_ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        },
    };
    ImmutableArchive::init(ctx, cfg).await.unwrap()
}

/// Append `count` random (index,key,value) triples to immutable archive and sync once.
pub async fn append_random_immutable(archive: &mut ImmutableArchiveType, count: u64) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut key_buf = [0u8; 64];
    let mut val_buf = [0u8; 32];

    let mut keys = Vec::with_capacity(count as usize);
    for i in 0..count {
        rng.fill_bytes(&mut key_buf);
        let key = Key::new(key_buf);
        keys.push(key.clone());
        rng.fill_bytes(&mut val_buf);
        archive.put(i, key, Val::new(val_buf)).await.unwrap();
    }
    archive.sync().await.unwrap();
    keys
}

// === Common Imports for Benchmarks ===
use commonware_storage::identifier::Identifier;
use criterion::black_box;
use futures::future::try_join_all;

/// Create a compression label string for benchmarks.
pub fn compression_label(compression: Option<u8>) -> String {
    compression
        .map(|l| l.to_string())
        .unwrap_or_else(|| "off".into())
}

/// Create a benchmark label with the given parameters.
pub fn create_benchmark_label(module_path: &str, params: &[(&str, String)]) -> String {
    let mut label = module_path.to_string();
    for (key, value) in params {
        label.push_str(&format!("/{}={}", key, value));
    }
    label
}

// === Key Selection Helpers ===

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

// === Reading Helpers for Prunable Archive ===

/// Read keys serially from a prunable archive.
pub async fn read_serial_keys_prunable(a: &ArchiveType, reads: &[Key]) {
    for k in reads {
        black_box(a.get(Identifier::Key(k)).await.unwrap().unwrap());
    }
}

/// Read indices serially from a prunable archive.
pub async fn read_serial_indices_prunable(a: &ArchiveType, indices: &[u64]) {
    for idx in indices {
        black_box(a.get(Identifier::Index(*idx)).await.unwrap().unwrap());
    }
}

/// Read keys concurrently from a prunable archive.
pub async fn read_concurrent_keys_prunable(a: &ArchiveType, reads: Vec<Key>) {
    let futures = reads.iter().map(|k| a.get(Identifier::Key(k)));
    black_box(try_join_all(futures).await.unwrap());
}

/// Read indices concurrently from a prunable archive.
pub async fn read_concurrent_indices_prunable(a: &ArchiveType, indices: &[u64]) {
    let mut futs = Vec::with_capacity(indices.len());
    for idx in indices {
        futs.push(a.get(Identifier::Index(*idx)));
    }
    black_box(try_join_all(futs).await.unwrap());
}

// === Reading Helpers for Immutable Archive ===

/// Read keys serially from an immutable archive.
pub async fn read_serial_keys_immutable(a: &mut ImmutableArchiveType, reads: &[Key]) {
    for k in reads {
        black_box(a.get(Identifier::Key(k)).await.unwrap().unwrap());
    }
}

/// Read indices serially from an immutable archive.
pub async fn read_serial_indices_immutable(a: &mut ImmutableArchiveType, indices: &[u64]) {
    for idx in indices {
        black_box(a.get(Identifier::Index(*idx)).await.unwrap().unwrap());
    }
}

/// Read keys concurrently from an immutable archive.
pub async fn read_concurrent_keys_immutable(a: &mut ImmutableArchiveType, reads: Vec<Key>) {
    let futures = reads.iter().map(|k| a.get(Identifier::Key(k)));
    black_box(try_join_all(futures).await.unwrap());
}

/// Read indices concurrently from an immutable archive.
pub async fn read_concurrent_indices_immutable(a: &mut ImmutableArchiveType, indices: &[u64]) {
    let mut futs = Vec::with_capacity(indices.len());
    for idx in indices {
        futs.push(a.get(Identifier::Index(*idx)));
    }
    black_box(try_join_all(futs).await.unwrap());
}
