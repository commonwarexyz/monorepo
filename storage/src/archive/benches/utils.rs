//! Helpers shared by the Archive benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::{
    archive::{Archive, Error},
    translator::TwoCap,
};
use commonware_utils::array::FixedBytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::future::Future;

/// Partition used across all archive benchmarks.
pub const PARTITION: &str = "archive_bench_partition";

/// Number of bytes that can be buffered in a section before being written to disk.
const WRITE_BUFFER: usize = 1024;

/// Number of items per section.
const ITEMS_PER_SECTION: u64 = 65_536;

/// Number of bytes to buffer when replaying.
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Fixed-length key and value types.
pub type Key = FixedBytes<64>;
pub type Val = FixedBytes<32>;

/// Archive factory trait to abstract over different archive implementations.
pub trait ArchiveFactory: Send + Sync + 'static {
    type Archive: Archive<Key = Key, Value = Val> + Send + Sync;

    fn init(
        context: Context,
        compression: Option<u8>,
    ) -> impl Future<Output = Result<Self::Archive, Error>> + Send;
}

/// Factory for fast prunable implementation.
pub struct PrunableArchiveFactory;

impl ArchiveFactory for PrunableArchiveFactory {
    type Archive = commonware_storage::archive::prunable::Archive<TwoCap, Context, Key, Val>;

    async fn init(context: Context, compression: Option<u8>) -> Result<Self::Archive, Error> {
        let cfg = commonware_storage::archive::prunable::Config {
            partition: PARTITION.into(),
            translator: TwoCap,
            compression,
            codec_config: (),
            items_per_section: ITEMS_PER_SECTION,
            write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        };
        commonware_storage::archive::prunable::Archive::init(context, cfg).await
    }
}

/// Factory for immutable archive implementation.
pub struct ImmutableArchiveFactory;

impl ArchiveFactory for ImmutableArchiveFactory {
    type Archive = commonware_storage::archive::immutable::Archive<Context, Key, Val>;

    async fn init(context: Context, compression: Option<u8>) -> Result<Self::Archive, Error> {
        let cfg = commonware_storage::archive::immutable::Config {
            metadata_partition: format!("{PARTITION}_metadata"),
            table_partition: format!("{PARTITION}_table"),
            table_initial_size: 131_072, // 48B per entry * 131_072 = 6MB
            table_resize_frequency: 4,
            journal_partition: format!("{PARTITION}_journal"),
            target_journal_size: 1024 * 1024 * 1024, // 1GB
            ordinal_partition: format!("{PARTITION}_ordinal"),
            compression,
            codec_config: (),
            items_per_section: ITEMS_PER_SECTION,
            write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        };
        commonware_storage::archive::immutable::Archive::init(context, cfg).await
    }
}

/// Append `count` random (index,key,value) triples and sync once.
pub async fn append_random<A: Archive<Key = Key, Value = Val>>(
    archive: &mut A,
    count: u64,
) -> Vec<Key> {
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
