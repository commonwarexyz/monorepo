//! Helpers shared by the Archive benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::{
    archive::prunable::{Archive, Config},
    translator::TwoCap,
};
use commonware_utils::array::FixedBytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};

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
