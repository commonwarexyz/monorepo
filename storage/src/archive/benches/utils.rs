//! Helpers shared by the Archive benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::{
    archive::{immutable, prunable, Archive as ArchiveTrait, Identifier},
    translator::TwoCap,
};
use commonware_utils::array::FixedBytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Number of bytes that can be buffered in a section before being written to a
/// [commonware_runtime::Blob].
const WRITE_BUFFER: usize = 1024 * 1024; // 1MB

/// Number of items per section (the granularity of pruning).
const ITEMS_PER_SECTION: u64 = 1_024;

/// Number of bytes to buffer when replaying a [commonware_runtime::Blob].
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Fixed-length key and value types.
pub type Key = FixedBytes<64>;
pub type Val = FixedBytes<32>;

/// Archive variant to benchmark.
#[derive(Debug, Clone, Copy)]
pub enum Variant {
    Immutable,
    Prunable,
}

impl Variant {
    pub fn name(&self) -> &'static str {
        match self {
            Variant::Immutable => "immutable",
            Variant::Prunable => "prunable",
        }
    }
}

/// Concrete archive types
#[allow(clippy::large_enum_variant)]
pub enum Archive {
    Immutable(immutable::Archive<Context, Key, Val>),
    Prunable(prunable::Archive<TwoCap, Context, Key, Val>),
}

impl Archive {
    /// Initialize a new archive based on variant
    pub async fn init(ctx: Context, variant: Variant, compression: Option<u8>) -> Self {
        match variant {
            Variant::Immutable => {
                let cfg = immutable::Config {
                    metadata_partition: "archive_bench_metadata".into(),
                    freezer_table_partition: "archive_bench_table".into(),
                    freezer_table_initial_size: 131_072,
                    freezer_table_resize_frequency: 4,
                    freezer_table_resize_chunk_size: 1024,
                    freezer_journal_partition: "archive_bench_journal".into(),
                    freezer_journal_target_size: 1024 * 1024 * 10, // 10MB
                    freezer_journal_compression: compression,
                    ordinal_partition: "archive_bench_ordinal".into(),
                    items_per_section: ITEMS_PER_SECTION,
                    write_buffer: WRITE_BUFFER,
                    replay_buffer: REPLAY_BUFFER,
                    codec_config: (),
                };
                Archive::Immutable(immutable::Archive::init(ctx, cfg).await.unwrap())
            }
            Variant::Prunable => {
                let cfg = prunable::Config {
                    partition: "archive_bench_partition".into(),
                    translator: TwoCap,
                    compression,
                    codec_config: (),
                    items_per_section: ITEMS_PER_SECTION,
                    write_buffer: WRITE_BUFFER,
                    replay_buffer: REPLAY_BUFFER,
                };
                Archive::Prunable(prunable::Archive::init(ctx, cfg).await.unwrap())
            }
        }
    }
}

// Implement Archive trait methods for the enum
impl ArchiveTrait for Archive {
    type Key = Key;
    type Value = Val;

    async fn put(
        &mut self,
        index: u64,
        key: Key,
        value: Val,
    ) -> Result<(), commonware_storage::archive::Error> {
        match self {
            Archive::Immutable(a) => a.put(index, key, value).await,
            Archive::Prunable(a) => a.put(index, key, value).await,
        }
    }

    async fn get(
        &self,
        identifier: Identifier<'_, Key>,
    ) -> Result<Option<Val>, commonware_storage::archive::Error> {
        match self {
            Archive::Immutable(a) => a.get(identifier).await,
            Archive::Prunable(a) => a.get(identifier).await,
        }
    }

    async fn has(
        &self,
        identifier: Identifier<'_, Key>,
    ) -> Result<bool, commonware_storage::archive::Error> {
        match self {
            Archive::Immutable(a) => a.has(identifier).await,
            Archive::Prunable(a) => a.has(identifier).await,
        }
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        match self {
            Archive::Immutable(a) => a.next_gap(index),
            Archive::Prunable(a) => a.next_gap(index),
        }
    }

    async fn sync(&mut self) -> Result<(), commonware_storage::archive::Error> {
        match self {
            Archive::Immutable(a) => a.sync().await,
            Archive::Prunable(a) => a.sync().await,
        }
    }

    async fn close(self) -> Result<(), commonware_storage::archive::Error> {
        match self {
            Archive::Immutable(a) => a.close().await,
            Archive::Prunable(a) => a.close().await,
        }
    }

    async fn destroy(self) -> Result<(), commonware_storage::archive::Error> {
        match self {
            Archive::Immutable(a) => a.destroy().await,
            Archive::Prunable(a) => a.destroy().await,
        }
    }
}

/// Append `count` random (index,key,value) triples and sync once.
pub async fn append_random(archive: &mut Archive, count: u64) -> Vec<Key> {
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
