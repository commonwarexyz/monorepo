//! Helpers shared by the Archive benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::{
    archive::{
        prunable::{Archive, Config},
        Archive as _,
    },
    translator::TwoCap,
};
use commonware_utils::array::FixedBytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Partition used across all archive benchmarks.
pub const PARTITION: &str = "archive_bench_partition";

/// Number of bytes that can be buffered in a section before being written to a
/// [commonware_runtime::Blob].
const WRITE_BUFFER: usize = 1024;

/// Number of items per section (the granularity of pruning).
const ITEMS_PER_SECTION: u64 = 1_024;

/// Number of bytes to buffer when replaying a [commonware_runtime::Blob].
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Fixed-length key and value types.
pub type Key = FixedBytes<64>;
pub type Val = FixedBytes<32>;

/// Concrete archive type reused by every benchmark.
pub type ArchiveType = Archive<TwoCap, Context, Key, Val>;

/// Open (or create) a fresh archive with optional compression.
///
/// The caller is responsible for closing or destroying it.
pub async fn init(ctx: Context, compression: Option<u8>) -> ArchiveType {
    let cfg = Config {
        partition: PARTITION.into(),
        translator: TwoCap,
        compression,
        codec_config: (),
        items_per_section: ITEMS_PER_SECTION,
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
