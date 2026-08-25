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
//! eagerly, but data is not committed until `sync` succeeds or a `start_sync` handle completes.
//! Both operations first make the freezer and ordinal data durable, then commit metadata that names
//! the freezer checkpoint and ordinal section bits. On restart, this metadata is the source of truth:
//! lower-layer data not described by metadata is treated as uncommitted and may be removed during
//! initialization. If no freezer checkpoint has been committed yet, initialization starts from an
//! empty archive.
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
//!     archive = archive.put(1, Sha256::hash(&[b"data"]), 10).await.unwrap();
//!
//!     // Sync the archive
//!     archive.sync().await.unwrap();
//! });

mod storage;
use commonware_runtime::buffer::paged::CacheRef;
use std::num::{NonZeroU64, NonZeroUsize};
pub use storage::{Archive, ReadOutcome, ReadRequest, ReadStep};

/// Configuration for [Archive] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for the archive's metadata.
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
    use crate::archive::Archive as ArchiveTrait;
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
    use commonware_runtime::{
        BufferPooler, Runner, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn start_sync_config(context: &impl BufferPooler) -> Config<()> {
        Config {
            metadata_partition: "start-sync-metadata".into(),
            freezer_table_partition: "start-sync-table".into(),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 4,
            freezer_table_resize_chunk_size: 64,
            freezer_key_partition: "start-sync-key".into(),
            freezer_key_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
            freezer_value_partition: "start-sync-value".into(),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: "start-sync-ordinal".into(),
            items_per_section: NZU64!(1),
            freezer_key_write_buffer: NZUsize!(1024),
            freezer_value_write_buffer: NZUsize!(1024),
            ordinal_write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            codec_config: (),
        }
    }

    async fn execute_read(
        archive: &Archive<deterministic::Context, Digest, i32>,
        mut request: ReadRequest<Digest>,
    ) -> Option<i32> {
        loop {
            match archive
                .read_step(request)
                .expect("read step should capture")
                .execute()
                .await
                .expect("read step should execute")
            {
                ReadOutcome::Done(value) => return value,
                ReadOutcome::Continue(next) => request = next,
            }
        }
    }

    #[test]
    fn test_read_steps_capture_key_head_and_resolve_index() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let key = Sha256::hash(&[b"key"]);
            let archive: Archive<_, Digest, i32> =
                Archive::init(context.child("storage"), start_sync_config(&context))
                    .await
                    .unwrap();
            let archive = archive.put(1, key, 10).await.unwrap();
            let captured = archive
                .read_step(ReadRequest::key(key))
                .expect("key head should capture");
            let archive = archive.put(2, key, 20).await.unwrap();

            assert!(matches!(
                captured.execute().await.unwrap(),
                ReadOutcome::Done(Some(10))
            ));
            assert_eq!(
                execute_read(&archive, ReadRequest::key(key)).await,
                Some(20)
            );
            assert_eq!(
                execute_read(&archive, ReadRequest::index(1)).await,
                Some(10)
            );
            assert_eq!(execute_read(&archive, ReadRequest::index(3)).await, None);
        });
    }

    #[test]
    fn test_read_steps_follow_resized_head_mirror() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = start_sync_config(&context);
            cfg.freezer_table_initial_size = 2;
            cfg.freezer_table_resize_frequency = 1;
            cfg.freezer_table_resize_chunk_size = 1;
            let mut archive: Archive<_, Digest, i32> =
                Archive::init(context.child("storage"), cfg).await.unwrap();
            let keys = [
                Sha256::hash(&[b"first"]),
                Sha256::hash(&[b"second"]),
                Sha256::hash(&[b"third"]),
                Sha256::hash(&[b"fourth"]),
            ];

            for (index, key) in keys.iter().copied().enumerate() {
                archive = archive.put(index as u64, key, index as i32).await.unwrap();
                archive = archive.sync().await.unwrap();
            }

            for (index, key) in keys.into_iter().enumerate() {
                assert_eq!(
                    execute_read(&archive, ReadRequest::key(key)).await,
                    Some(index as i32)
                );
            }
        });
    }

    #[test]
    fn test_start_sync_returns_ownership_and_isolates_cut() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = start_sync_config(&context);
            let first_key = Sha256::hash(&[b"first"]);
            let second_key = Sha256::hash(&[b"second"]);

            let archive: Archive<_, Digest, i32> =
                Archive::init(context.child("storage"), cfg).await.unwrap();
            let archive = archive.put(1, first_key, 10).await.unwrap();

            pending.arm();
            let (archive, handle) = archive.start_sync().await.unwrap();
            assert!(
                pending.calls() > 0,
                "start_sync must begin lower-layer durability before returning"
            );
            assert!(
                !pending.lock().is_empty(),
                "start_sync must return while lower-layer durability is pending"
            );

            let archive = archive.put(2, second_key, 20).await.unwrap();
            drive_pending_syncs(&pending, handle).await.unwrap();
            drop(archive);
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let archive: Archive<_, Digest, i32> =
                Archive::init(context.child("reopen"), start_sync_config(&context))
                    .await
                    .unwrap();
            assert_eq!(
                archive
                    .get(crate::archive::Identifier::Index(1))
                    .await
                    .unwrap(),
                Some(10)
            );
            assert_eq!(
                archive
                    .get(crate::archive::Identifier::Index(2))
                    .await
                    .unwrap(),
                None
            );
        });
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
            archive = archive.put(1, key1, 2000).await.unwrap();
            archive = archive.put(2, key2, 2001).await.unwrap();

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
            let archive = archive.put_sync(0, key, 42).await.unwrap();
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
