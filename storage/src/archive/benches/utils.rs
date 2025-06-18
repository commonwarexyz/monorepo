//! Helpers shared by the Archive benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::{
    archive::{Archive, Config},
    index::translator::TwoCap,
};
use commonware_utils::array::FixedBytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Partition used across all archive benchmarks.
pub const PARTITION: &str = "archive_bench_partition";

/// Number of buffered writes before a forced sync.
const PENDING_WRITES: usize = 1_000;

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
        pending_writes: PENDING_WRITES,
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
