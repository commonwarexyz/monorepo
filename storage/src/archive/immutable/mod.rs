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
//! [Archive] supports optional zstd compression of freezer values through
//! [Config::freezer_value_compression]. Keep the choice between `None` and `Some(_)` fixed for the
//! life of the archive. Only the compression level may change between initializations when
//! compression is enabled.
//!
//! # Durability and Recovery
//!
//! `put` updates the underlying [crate::freezer::Freezer] and [crate::ordinal::Ordinal]
//! eagerly, but data is not committed until `sync` succeeds. Sync first makes the freezer
//! and ordinal data durable, then commits metadata that names the freezer checkpoint and ordinal
//! section bits. On restart, this metadata is the source of truth: lower-layer data not described by
//! metadata is treated as uncommitted and may be removed during initialization. If no freezer
//! checkpoint has been committed yet, initialization starts from an empty archive.
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
//!         freezer_value_target_size: 1024,
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
//!     archive = archive.put(1, Sha256::hash(&[b"data"]), &10).await.unwrap();
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
    /// The partition to use for the archive's commit records: the freezer checkpoint and
    /// ordinal bitmaps that recovery uses to keep both stores consistent.
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

    /// The target size of the archive's freezer value sections.
    pub freezer_value_target_size: u64,

    /// The compression level to use for the archive's freezer values.
    pub freezer_value_compression: Option<u8>,

    /// The partition to use for the archive's ordinal.
    pub ordinal_partition: String,

    /// The number of items per section.
    ///
    /// Fixed for the life of the archive's data. Sections and their commit records are addressed
    /// by `index / items_per_section`, and [Archive::init] fails when a committed section no
    /// longer matches this value.
    pub items_per_section: NonZeroU64,

    /// The amount of bytes that can be buffered for the freezer key journal before being
    /// written to a [commonware_runtime::Blob].
    pub freezer_key_write_buffer: NonZeroUsize,

    /// The amount of bytes that can be buffered for the freezer value journal before being
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
    use crate::archive::{Archive as ArchiveTrait, Error, Identifier};
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
    use commonware_runtime::{
        Runner, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{self, FaultConfig, PartialWriteMode, WriteConfig},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, probability};
    use std::num::{NonZeroU16, NonZeroU64};

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    /// Build a configuration whose small sections spread a few records across several freezer
    /// and ordinal blobs.
    fn config(context: &deterministic::Context, items_per_section: u64) -> Config<()> {
        Config {
            metadata_partition: "destroy-metadata".into(),
            freezer_table_partition: "destroy-freezer-table".into(),
            freezer_table_initial_size: 4,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 2,
            freezer_key_partition: "destroy-freezer-key".into(),
            freezer_key_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
            freezer_value_partition: "destroy-freezer-value".into(),
            freezer_value_target_size: 64,
            freezer_value_compression: None,
            ordinal_partition: "destroy-ordinal".into(),
            items_per_section: NonZeroU64::new(items_per_section).unwrap(),
            freezer_key_write_buffer: NZUsize!(1024),
            freezer_value_write_buffer: NZUsize!(1024),
            ordinal_write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            codec_config: (),
        }
    }

    /// Reopening with a different `items_per_section` fails instead of addressing committed
    /// sections by the new size.
    #[test]
    fn test_init_rejects_changed_items_per_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let key = |index: u64| Sha256::hash(&[&index.to_be_bytes()]);

            // A partial section records its size in its bitmap.
            let archive = Archive::init(context.child("sparse"), config(&context, 4))
                .await
                .unwrap();
            let archive = archive.put(0, key(0), &0).await.unwrap();
            let archive = archive.put_sync(5, key(5), &50).await.unwrap();
            drop(archive);
            let result =
                Archive::<_, Digest, i32>::init(context.child("sparse_grown"), config(&context, 8))
                    .await;
            assert!(matches!(result, Err(Error::RecordCorrupted)), "{result:?}");
            let result = Archive::<_, Digest, i32>::init(
                context.child("sparse_shrunk"),
                config(&context, 2),
            )
            .await;
            assert!(matches!(result, Err(Error::RecordCorrupted)), "{result:?}");

            // A complete section records its size only through the length of its ordinal blob.
            Archive::<_, Digest, i32>::init(context.child("reset"), config(&context, 4))
                .await
                .unwrap()
                .destroy()
                .await
                .unwrap();
            let mut archive = Archive::init(context.child("full"), config(&context, 8))
                .await
                .unwrap();
            for index in 0..8u64 {
                archive = archive
                    .put(index, key(index), &(index as i32))
                    .await
                    .unwrap();
            }
            let archive = archive.sync().await.unwrap();
            drop(archive);
            let result =
                Archive::<_, Digest, i32>::init(context.child("full_shrunk"), config(&context, 4))
                    .await;
            assert!(matches!(result, Err(Error::Ordinal(_))), "{result:?}");
            let result =
                Archive::<_, Digest, i32>::init(context.child("full_grown"), config(&context, 16))
                    .await;
            assert!(matches!(result, Err(Error::Ordinal(_))), "{result:?}");

            // The original size still opens the complete section.
            let archive =
                Archive::<_, Digest, i32>::init(context.child("full_same"), config(&context, 8))
                    .await
                    .unwrap();
            for index in 0..8u64 {
                assert_eq!(
                    archive.get(Identifier::Index(index)).await.unwrap(),
                    Some(index as i32)
                );
            }
        });
    }

    /// A destroy interrupted at any point leaves an archive that reopens at its latest commit or
    /// empty, with index and key views agreeing, and that a retried destroy empties.
    #[test]
    fn test_interrupted_destroy_reopens() {
        let entries = || -> Vec<(u64, Digest, i32)> {
            (0..11u64)
                .map(|index| {
                    (
                        index,
                        Sha256::hash(&[&index.to_be_bytes()]),
                        index as i32 * 7,
                    )
                })
                .collect()
        };
        let mut interrupted = 0;
        for seed in 0..32u64 {
            // Retain every unsynced write across the crash, as a runtime that flushes a reopened
            // blob's pending writes would.
            let faults = FaultConfig::default().write(WriteConfig {
                failure_rate: probability!(0.0),
                retention_rate: probability!(1.0),
                mode: PartialWriteMode::Prefix,
            });
            let runner = deterministic::Runner::new(
                deterministic::Config::default()
                    .with_seed(seed)
                    .with_storage_fault_config(faults),
            );
            let (stopped, checkpoint) = runner.start_and_recover(|context| async move {
                let cfg = config(&context, 4);
                let entries = entries();

                // Commit twice so both metadata copies hold a generation, then leave a put
                // uncommitted.
                let mut archive = Archive::init(context.child("first"), cfg).await.unwrap();
                for (index, key, value) in &entries[..5] {
                    archive = archive.put(*index, *key, value).await.unwrap();
                }
                archive = archive.sync().await.unwrap();
                for (index, key, value) in &entries[5..10] {
                    archive = archive.put(*index, *key, value).await.unwrap();
                }
                archive = archive.sync().await.unwrap();
                let (index, key, value) = &entries[10];
                let archive = archive.put(*index, *key, value).await.unwrap();

                // Fail a sample of removals so destroy stops at varying depths, from the first
                // metadata blob through the freezer's own blobs.
                context.storage_fault_config().write().remove_rate = Some(probability!(0.1));
                let result = archive.destroy().await;
                context.storage_fault_config().write().remove_rate = None;
                result.is_err()
            });
            if !stopped {
                continue;
            }
            interrupted += 1;
            deterministic::Runner::from(checkpoint).start(|context| async move {
                let cfg = config(&context, 4);
                let entries = entries();

                // The reopened archive holds exactly the entries of the latest commit or none,
                // with index and key views agreeing.
                let archive = Archive::<_, Digest, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();
                let mut present = Vec::new();
                for (index, key, value) in &entries {
                    let by_index = archive.get(Identifier::Index(*index)).await.unwrap();
                    assert!(by_index.is_none_or(|stored| stored == *value));
                    assert_eq!(
                        archive.get(Identifier::Key(key)).await.unwrap(),
                        by_index,
                        "seed {seed} index {index}"
                    );
                    assert_eq!(
                        archive.has(Identifier::Index(*index)).await.unwrap(),
                        by_index.is_some()
                    );
                    assert_eq!(
                        archive.has(Identifier::Key(key)).await.unwrap(),
                        by_index.is_some()
                    );
                    if by_index.is_some() {
                        present.push(*index);
                    }
                }
                assert!(
                    [0, 10].contains(&present.len())
                        && present.iter().copied().eq(0..present.len() as u64),
                    "seed {seed} reopened with {present:?}"
                );

                // A retried destroy completes and leaves nothing behind.
                archive.destroy().await.unwrap();
                let archive = Archive::<_, Digest, i32>::init(context.child("third"), cfg)
                    .await
                    .unwrap();
                assert_eq!(archive.first_index(), None);
            });
        }
        assert!(interrupted > 0, "no seed interrupted destroy");
    }

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
                freezer_value_target_size: 1024 * 1024,
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
            let key1 = Sha256::hash(&[b"key1"]);
            let key2 = Sha256::hash(&[b"key2"]);
            archive = archive.put(1, key1, &2000).await.unwrap();
            archive = archive.put(2, key2, &2001).await.unwrap();

            // Sync archive to save the checkpoint
            let archive = archive.sync().await.unwrap();
            drop(archive);

            // Re-initialize archive (should load from checkpoint)
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
                freezer_value_target_size: 1024 * 1024,
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
            let archive: Archive<_, Digest, i32> =
                Archive::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
            let archive = archive.sync().await.unwrap();
            drop(archive);

            // Re-initialize -- should not fail with SectionOutOfRange(0)
            let archive: Archive<_, Digest, i32> =
                Archive::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();

            // Write data after restart to confirm archive is functional
            let key = Sha256::hash(&[b"after-restart"]);
            let archive = archive.put_sync(0, key, &42).await.unwrap();
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
