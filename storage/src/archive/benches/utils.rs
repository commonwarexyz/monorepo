//! Helpers shared by the Archive benchmarks.

use commonware_codec::config::RangeCfg;
use commonware_runtime::{buffer::PoolRef, tokio::Context};
use commonware_storage::{
    archive::{immutable, prunable, Archive as ArchiveTrait, Identifier},
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::num::NonZeroUsize;

/// Number of bytes that can be buffered in a section before being written to a
/// [commonware_runtime::Blob].
const WRITE_BUFFER: usize = 8 * 1024 * 1024; // 8MB

/// Number of items per section (the granularity of pruning).
const ITEMS_PER_SECTION: u64 = 16_384;

/// Number of bytes to buffer when replaying a [commonware_runtime::Blob].
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Page size for the index buffer pool.
const PAGE_SIZE: NonZeroUsize = NZUsize!(4_096);

/// The number of pages to cache in the buffer pool (8,192 × 4KB = 32MB).
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8_192);

/// Key type (fixed-length) and value type (variable-length for large values).
pub type Key = FixedBytes<64>;
pub type Val = Vec<u8>;

/// Size of values in bytes (64KB, representative of block data).
const VALUE_SIZE: usize = 65536;

/// Archive variant to benchmark.
#[derive(Debug, Clone, Copy)]
pub enum Variant {
    Immutable,
    Prunable,
}

impl Variant {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Immutable => "immutable",
            Self::Prunable => "prunable",
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
                    freezer_key_partition: "archive_bench_key".into(),
                    freezer_key_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    freezer_value_partition: "archive_bench_value".into(),
                    freezer_value_target_size: 128 * 1024 * 1024,
                    freezer_value_compression: compression,
                    ordinal_partition: "archive_bench_ordinal".into(),
                    items_per_section: NZU64!(ITEMS_PER_SECTION),
                    freezer_key_write_buffer: NZUsize!(WRITE_BUFFER),
                    freezer_value_write_buffer: NZUsize!(WRITE_BUFFER),
                    ordinal_write_buffer: NZUsize!(WRITE_BUFFER),
                    replay_buffer: NZUsize!(REPLAY_BUFFER),
                    codec_config: (RangeCfg::new(..), ()),
                };
                Self::Immutable(immutable::Archive::init(ctx, cfg).await.unwrap())
            }
            Variant::Prunable => {
                let cfg = prunable::Config {
                    translator: TwoCap,
                    key_partition: "archive_bench_key".into(),
                    key_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    value_partition: "archive_bench_value".into(),
                    compression,
                    codec_config: (RangeCfg::new(..), ()),
                    items_per_section: NZU64!(ITEMS_PER_SECTION),
                    key_write_buffer: NZUsize!(WRITE_BUFFER),
                    value_write_buffer: NZUsize!(WRITE_BUFFER),
                    replay_buffer: NZUsize!(REPLAY_BUFFER),
                };
                Self::Prunable(prunable::Archive::init(ctx, cfg).await.unwrap())
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
            Self::Immutable(a) => a.put(index, key, value).await,
            Self::Prunable(a) => a.put(index, key, value).await,
        }
    }

    async fn get(
        &self,
        identifier: Identifier<'_, Key>,
    ) -> Result<Option<Val>, commonware_storage::archive::Error> {
        match self {
            Self::Immutable(a) => a.get(identifier).await,
            Self::Prunable(a) => a.get(identifier).await,
        }
    }

    async fn has(
        &self,
        identifier: Identifier<'_, Key>,
    ) -> Result<bool, commonware_storage::archive::Error> {
        match self {
            Self::Immutable(a) => a.has(identifier).await,
            Self::Prunable(a) => a.has(identifier).await,
        }
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        match self {
            Self::Immutable(a) => a.next_gap(index),
            Self::Prunable(a) => a.next_gap(index),
        }
    }

    fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        match self {
            Self::Immutable(a) => a.missing_items(index, max),
            Self::Prunable(a) => a.missing_items(index, max),
        }
    }

    fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        match self {
            Self::Immutable(a) => a.ranges().collect::<Vec<_>>().into_iter(),
            Self::Prunable(a) => a.ranges().collect::<Vec<_>>().into_iter(),
        }
    }

    fn first_index(&self) -> Option<u64> {
        match self {
            Self::Immutable(a) => a.first_index(),
            Self::Prunable(a) => a.first_index(),
        }
    }

    fn last_index(&self) -> Option<u64> {
        match self {
            Self::Immutable(a) => a.last_index(),
            Self::Prunable(a) => a.last_index(),
        }
    }

    async fn sync(&mut self) -> Result<(), commonware_storage::archive::Error> {
        match self {
            Self::Immutable(a) => a.sync().await,
            Self::Prunable(a) => a.sync().await,
        }
    }

    async fn destroy(self) -> Result<(), commonware_storage::archive::Error> {
        match self {
            Self::Immutable(a) => a.destroy().await,
            Self::Prunable(a) => a.destroy().await,
        }
    }
}

/// Append `count` random (index,key,value) triples and sync once.
pub async fn append_random(archive: &mut Archive, count: u64) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut key_buf = [0u8; 64];

    let mut keys = Vec::with_capacity(count as usize);
    for i in 0..count {
        rng.fill_bytes(&mut key_buf);
        let key = Key::new(key_buf);
        keys.push(key.clone());

        let mut val_buf = vec![0u8; VALUE_SIZE];
        rng.fill_bytes(&mut val_buf);
        archive.put(i, key, val_buf).await.unwrap();
    }
    archive.sync().await.unwrap();
    keys
}
