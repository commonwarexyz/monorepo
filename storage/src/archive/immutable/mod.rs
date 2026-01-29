//! An immutable key-value store for ordered data with a minimal memory footprint.
//!
//! Data is stored in a [crate::freezer::Freezer] and a [crate::ordinal::Ordinal] to enable
//! lookups by both index and key with minimal memory overhead.
//!
//! # Uniqueness
//!
//! [Archive] assumes all stored indexes and keys are unique. If the same key is associated with
//! multiple `indices`, there is no guarantee which value will be returned. If the key is written to
//! an existing `index`, [Archive] will return an error.
//!
//! # Compression
//!
//! [Archive] supports compressing data before storing it on disk. This can be enabled by setting
//! the `compression` field in the `Config` struct to a valid `zstd` compression level. This setting
//! can be changed between initializations of [Archive], however, it must remain populated if any
//! data was written with compression enabled.
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
//!         freezer_table_partition: "table".into(),
//!         freezer_table_initial_size: 65_536,
//!         freezer_table_resize_frequency: 4,
//!         freezer_table_resize_chunk_size: 16_384,
//!         freezer_key_partition: "key".into(),
//!         freezer_key_page_cache: CacheRef::new(NZU16!(1024), NZUsize!(10)),
//!         freezer_value_partition: "value".into(),
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
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics, Runner};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    #[test]
    fn test_unclean_shutdown() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                metadata_partition: "test_metadata2".into(),
                freezer_table_partition: "test_table2".into(),
                freezer_table_initial_size: 8192, // Must be power of 2
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 8192,
                freezer_key_partition: "test_key2".into(),
                freezer_key_page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                freezer_value_partition: "test_value2".into(),
                freezer_value_target_size: 1024 * 1024,
                freezer_value_compression: Some(3),
                ordinal_partition: "test_ordinal2".into(),
                items_per_section: NZU64!(512),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config: (),
            };

            // First initialization
            let archive: Archive<_, Digest, i32> =
                Archive::init(context.with_label("first"), cfg.clone())
                    .await
                    .unwrap();
            drop(archive);

            // Second initialization
            let mut archive = Archive::init(context.with_label("second"), cfg.clone())
                .await
                .unwrap();

            // Add some data
            let key1 = Sha256::hash(b"key1");
            let key2 = Sha256::hash(b"key2");
            archive.put(1, key1, 2000).await.unwrap();
            archive.put(2, key2, 2001).await.unwrap();

            // Sync archive to save the checkpoint
            archive.sync().await.unwrap();
            drop(archive);

            // Re-initialize archive (should load from checkpoint)
            let archive = Archive::init(context.with_label("third"), cfg)
                .await
                .unwrap();

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
}
