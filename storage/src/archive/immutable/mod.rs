//! An immutable key-value store for ordered data with a minimal memory footprint.
//!
//! Data is stored in a [crate::freezer::Freezer] and a [crate::ordinal::Ordinal] to enable
//! lookups by both index and key with minimal memory overhead.
//!
//! # Uniqueness
//!
//! [Archive] assumes all stored indices are unique. Writing to an occupied index is a no-op.
//! If the same key is associated with multiple indices, there is no guarantee which value will
//! be returned.
//!
//! # Compression
//!
//! [Archive] supports compressing data before storing it on disk. This can be enabled by setting
//! the `compression` field in the `Config` struct to a valid `zstd` compression level. This setting
//! can be changed between initializations of [Archive], however, it must remain populated if any
//! data was written with compression enabled.
//!
//! # Durability and Recovery
//!
//! `put` updates the underlying [crate::freezer::Freezer] and [crate::ordinal::Ordinal]
//! eagerly, but data is not committed until `sync` succeeds. Sync stages the freezer data,
//! the ordinal data, and a single-blob commit record naming the ordinal section bits in ONE
//! atomic batch, so a crash leaves every component at the same commit. On restart, the
//! freezer recovers from its own committed state and the record's bits identify the ordinal
//! records the last sync committed. If nothing has been committed yet, initialization starts
//! from an empty archive.
//!
//! # Querying for Gaps
//!
//! [Archive] tracks gaps in the index space to enable the caller to efficiently fetch unknown keys
//! using `next_gap`. This is a very common pattern when syncing blocks in a blockchain.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::paged::CacheRef};
//! use commonware_cryptography::{Hasher as _, Sha256};
//! use commonware_storage::{
//!     archive::{
//!         Archive as _,
//!         immutable::{Archive, Config},
//!     },
//! };
//! use commonware_utils::{NZUsize, NZU16, NZU64};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create an archive
//!     let cfg = Config {
//!         metadata_partition: "metadata".into(),
//!         freezer_table_partition: "freezer-table".into(),
//!         freezer_table_initial_size: 65_536,
//!         freezer_table_resize_frequency: 4,
//!         freezer_table_resize_chunk_size: 16_384,
//!         freezer_key_partition: "freezer-key".into(),
//!         freezer_key_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
//!         freezer_value_partition: "freezer-value".into(),
//!         freezer_value_compression: Some(3),
//!         ordinal_partition: "ordinal".into(),
//!         items_per_section: NZU64!(1024),
//!         freezer_key_write_buffer: NZUsize!(1024),
//!         freezer_value_write_buffer: NZUsize!(1024),
//!         ordinal_write_buffer: NZUsize!(1024),
//!         replay_buffer: NZUsize!(1024),
//!         codec_config: (),
//!     };
//!     let mut archive = Archive::init(context, cfg).await.unwrap();
//!
//!     // Put a key
//!     archive.put(1, Sha256::hash(b"data"), 10).await.unwrap();
//!
//!     // Sync the archive
//!     archive.sync().await.unwrap();
//! });

mod storage;
use commonware_runtime::buffer::paged::CacheRef;
use std::num::{NonZeroU64, NonZeroUsize};
pub use storage::Archive;

/// Configuration for [Archive] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for the archive's commit record.
    pub metadata_partition: String,

    /// The partition to use for the archive's freezer table.
    pub freezer_table_partition: String,

    /// The size of the archive's freezer table.
    pub freezer_table_initial_size: u32,

    /// The number of items added to the freezer table before it is resized.
    pub freezer_table_resize_frequency: u8,

    /// The number of items to move during each resize operation (many may be required to complete a resize).
    pub freezer_table_resize_chunk_size: u32,

    /// The partition to use for the archive's freezer keys.
    pub freezer_key_partition: String,

    /// The page cache to use for the archive's freezer keys.
    pub freezer_key_page_cache: CacheRef,

    /// The partition to use for the archive's freezer values.
    pub freezer_value_partition: String,

    /// The compression level to use for the archive's freezer values.
    pub freezer_value_compression: Option<u8>,

    /// The partition to use for the archive's ordinal.
    pub ordinal_partition: String,

    /// The number of items each of the commit record's section bitmaps shards. This is
    /// commit-record shard granularity only: it does not affect how the ordinal stores
    /// records on disk, but it must remain constant across restarts for the stored record
    /// to translate to the same indices.
    pub items_per_section: NonZeroU64,

    /// The amount of bytes that can be buffered for the freezer key record blob before
    /// being written to a [commonware_runtime::Blob].
    pub freezer_key_write_buffer: NonZeroUsize,

    /// The amount of bytes that can be buffered for the freezer value blob before being
    /// written to a [commonware_runtime::Blob].
    pub freezer_value_write_buffer: NonZeroUsize,

    /// The amount of bytes that can be buffered for the ordinal journal before being
    /// written to a [commonware_runtime::Blob].
    pub ordinal_write_buffer: NonZeroUsize,

    /// The buffer size to use when replaying a [commonware_runtime::Blob].
    pub replay_buffer: NonZeroUsize,

    /// The [commonware_codec::Codec] configuration to use for the value stored in the archive.
    pub codec_config: C,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{Archive as ArchiveTrait, Identifier};
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Runner, Supervisor as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    #[test]
    fn test_unclean_shutdown() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                metadata_partition: "test-metadata2".into(),
                freezer_table_partition: "test-freezer-table2".into(),
                freezer_table_initial_size: 8192, // Must be power of 2
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 8192,
                freezer_key_partition: "test-freezer-key2".into(),
                freezer_key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                freezer_value_partition: "test-freezer-value2".into(),
                freezer_value_compression: Some(3),
                ordinal_partition: "test-ordinal2".into(),
                items_per_section: NZU64!(512),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config: (),
            };

            // First initialization
            let archive: Archive<_, Digest, i32> =
                Archive::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
            drop(archive);

            // Second initialization
            let mut archive = Archive::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Add some data
            let key1 = Sha256::hash(b"key1");
            let key2 = Sha256::hash(b"key2");
            archive.put(1, key1, 2000).await.unwrap();
            archive.put(2, key2, 2001).await.unwrap();

            // Sync archive to commit the record
            archive.sync().await.unwrap();
            drop(archive);

            // Re-initialize archive (should load the committed state)
            let archive = Archive::init(context.child("third"), cfg).await.unwrap();

            // Verify data persisted
            assert_eq!(
                archive
                    .get(crate::archive::Identifier::Key(&key1))
                    .await
                    .unwrap(),
                Some(2000)
            );
            assert_eq!(
                archive
                    .get(crate::archive::Identifier::Key(&key2))
                    .await
                    .unwrap(),
                Some(2001)
            );
        });
    }

    /// After a crash, the archive must restore exactly the last committed state: committed
    /// items stay reachable by both index and key, uncommitted items vanish from both, and
    /// the vanished indices can be re-put.
    fn archive_crash_consistency(runner: deterministic::Runner) {
        fn crash_cfg(pooler: &impl BufferPooler) -> Config<()> {
            Config {
                metadata_partition: "crash-metadata".into(),
                freezer_table_partition: "crash-freezer-table".into(),
                freezer_table_initial_size: 8,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 8,
                freezer_key_partition: "crash-freezer-key".into(),
                freezer_key_page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
                freezer_value_partition: "crash-freezer-value".into(),
                freezer_value_compression: None,
                ordinal_partition: "crash-ordinal".into(),
                items_per_section: NZU64!(16),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config: (),
            }
        }
        let key = |i: u64| Sha256::hash(&i.to_be_bytes());

        let (_, checkpoint) = runner.start_and_recover(|context| async move {
            let mut archive: Archive<_, Digest, i32> =
                Archive::init(context.child("first"), crash_cfg(&context))
                    .await
                    .unwrap();

            // Commit two items
            archive.put(1, key(1), 10).await.unwrap();
            archive.put(2, key(2), 20).await.unwrap();
            archive.sync().await.unwrap();

            // Add two more without committing
            archive.put(3, key(3), 30).await.unwrap();
            archive.put(4, key(4), 40).await.unwrap();
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let mut archive: Archive<_, Digest, i32> =
                Archive::init(context.child("second"), crash_cfg(&context))
                    .await
                    .unwrap();

            // Committed items are reachable by index and key
            for (index, value) in [(1u64, 10), (2, 20)] {
                assert_eq!(
                    archive.get(Identifier::Index(index)).await.unwrap(),
                    Some(value)
                );
                assert_eq!(
                    archive.get(Identifier::Key(&key(index))).await.unwrap(),
                    Some(value)
                );
                assert!(archive.has(Identifier::Index(index)).await.unwrap());
                assert!(archive.has(Identifier::Key(&key(index))).await.unwrap());
            }

            // Uncommitted items vanished from both views
            for index in [3u64, 4] {
                assert_eq!(archive.get(Identifier::Index(index)).await.unwrap(), None);
                assert_eq!(
                    archive.get(Identifier::Key(&key(index))).await.unwrap(),
                    None
                );
                assert!(!archive.has(Identifier::Index(index)).await.unwrap());
                assert!(!archive.has(Identifier::Key(&key(index))).await.unwrap());
            }

            // The vanished indices can be re-put and committed
            archive.put_sync(3, key(3), 33).await.unwrap();
            assert_eq!(archive.get(Identifier::Index(3)).await.unwrap(), Some(33));
            assert_eq!(
                archive.get(Identifier::Key(&key(3))).await.unwrap(),
                Some(33)
            );
        });
    }

    #[test]
    fn test_crash_consistency() {
        archive_crash_consistency(deterministic::Runner::default());
    }

    #[test]
    fn test_sync_empty_archive_then_restart() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                metadata_partition: "empty-metadata".into(),
                freezer_table_partition: "empty-freezer-table".into(),
                freezer_table_initial_size: 8192,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 8192,
                freezer_key_partition: "empty-freezer-key".into(),
                freezer_key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                freezer_value_partition: "empty-freezer-value".into(),
                freezer_value_compression: Some(3),
                ordinal_partition: "empty-ordinal".into(),
                items_per_section: NZU64!(512),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config: (),
            };

            // Initialize archive, sync without writing anything, then drop
            let mut archive: Archive<_, Digest, i32> =
                Archive::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
            archive.sync().await.unwrap();
            drop(archive);

            // Re-initialize -- should not fail with SectionOutOfRange(0)
            let mut archive: Archive<_, Digest, i32> =
                Archive::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();

            // Write data after restart to confirm archive is functional
            let key = Sha256::hash(b"after-restart");
            archive.put_sync(0, key, 42).await.unwrap();
            drop(archive);

            // Third init to verify persistence
            let archive: Archive<_, Digest, i32> =
                Archive::init(context.child("third"), cfg).await.unwrap();
            assert_eq!(
                archive
                    .get(crate::archive::Identifier::Key(&key))
                    .await
                    .unwrap(),
                Some(42)
            );
        });
    }
}
