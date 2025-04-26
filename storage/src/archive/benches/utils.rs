//! Helpers shared by the `archive` benchmarks.

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

/// Section-mask that yields reasonably small blobs for local testing.
const SECTION_MASK: u64 = 0xffff_ffff_ffff_ff00u64;

/// Fixed-length key and value types.
pub type Key = FixedBytes<64>;
pub type Val = FixedBytes<32>;

/// Open (or create) a fresh `Archive` with optional compression.
///
/// The archive is *destroyed* on drop by the caller — benchmarks
/// that reuse the same on-disk data should call this exactly once.
pub async fn get_archive(
    ctx: Context,
    compression: Option<u8>,
) -> Archive<TwoCap, Context, Key, (), Val> {
    let cfg = Config {
        partition: PARTITION.into(),
        translator: TwoCap,
        compression,
        codec_config: (),
        section_mask: SECTION_MASK,
        pending_writes: PENDING_WRITES,
        replay_concurrency: 4,
    };
    Archive::init(ctx, cfg).await.unwrap()
}

/// Append `count` random (index, key, value) triples to the archive
/// and `sync()` once at the end.
pub async fn append_random(archive: &mut Archive<TwoCap, Context, Key, (), Val>, count: u64) {
    let mut rng = StdRng::seed_from_u64(0);
    let mut key_buf = [0u8; 64];
    let mut val_buf = [0u8; 32];

    for i in 0..count {
        rng.fill_bytes(&mut key_buf);
        rng.fill_bytes(&mut val_buf);
        archive
            .put(i, Key::new(key_buf), Val::new(val_buf))
            .await
            .unwrap();
    }
    archive.sync().await.unwrap();
}
