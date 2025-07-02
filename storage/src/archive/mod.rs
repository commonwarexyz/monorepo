//! A write-once key-value store where each key is associated with a unique index.
//!
//! [Archive] is a key-value store designed for workloads where all data is written only once and is
//! uniquely associated with both an `index` and a `key`.

use commonware_codec::Codec;
use commonware_utils::Array;
use std::future::Future;
use thiserror::Error;

pub mod immutable;
pub mod prunable;

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a, K: Array> {
    Index(u64),
    Key(&'a K),
}

/// Errors that can occur when interacting with the archive.
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("ordinal error: {0}")]
    Ordinal(#[from] crate::ordinal::Error),
    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),
    #[error("record corrupted")]
    RecordCorrupted,
    #[error("already pruned to: {0}")]
    AlreadyPrunedTo(u64),
    #[error("record too large")]
    RecordTooLarge,
}

/// A write-once key-value store where each key is associated with a unique index.
pub trait Archive {
    /// The type of the key.
    type Key: Array;

    /// The type of the value.
    type Value: Codec;

    /// Store an item in [Archive]. Both indices and keys are assumed to both be globally unique.
    ///
    /// If the index already exists, put does nothing and returns. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    fn put(
        &mut self,
        index: u64,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Error>>;

    /// Retrieve an item from [Archive].
    fn get(
        &self,
        identifier: Identifier<'_, Self::Key>,
    ) -> impl Future<Output = Result<Option<Self::Value>, Error>>;

    /// Check if an item exists in [Archive].
    fn has(
        &self,
        identifier: Identifier<'_, Self::Key>,
    ) -> impl Future<Output = Result<bool, Error>>;

    /// Retrieve the end of the current range including `index` (inclusive) and
    /// the start of the next range after `index` (if it exists).
    ///
    /// This is useful for driving backfill operations over the archive.
    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>);

    /// Sync all pending writes.
    fn sync(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Close [Archive] (and underlying storage).
    ///
    /// Any pending writes are synced prior to closing.
    fn close(self) -> impl Future<Output = Result<(), Error>>;

    /// Remove all persistent data created by this [Archive].
    fn destroy(self) -> impl Future<Output = Result<(), Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::TwoCap;
    use commonware_codec::DecodeExt;
    use commonware_macros::test_traced;
    use commonware_runtime::Runner;
    use commonware_utils::array::FixedBytes;
    use std::future::Future;

    const DEFAULT_ITEMS_PER_SECTION: u64 = 65536;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_REPLAY_BUFFER: usize = 4096;

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    /// A trait to abstract over different archive initialization methods
    trait ArchiveFactory {
        type Archive: Archive<Key = FixedBytes<64>>;

        fn init(
            context: commonware_runtime::deterministic::Context,
            compression: Option<u8>,
            items_per_section: u64,
        ) -> impl Future<Output = Result<Self::Archive, Error>>;

        fn init_with_params(
            context: commonware_runtime::deterministic::Context,
            partition: &str,
            compression: Option<u8>,
            items_per_section: u64,
        ) -> impl Future<Output = Result<Self::Archive, Error>>;
    }

    struct PrunableArchiveFactory;

    impl ArchiveFactory for PrunableArchiveFactory {
        type Archive = prunable::Archive<
            TwoCap,
            commonware_runtime::deterministic::Context,
            FixedBytes<64>,
            i32,
        >;

        async fn init(
            context: commonware_runtime::deterministic::Context,
            compression: Option<u8>,
            items_per_section: u64,
        ) -> Result<Self::Archive, Error> {
            Self::init_with_params(context, "test_partition", compression, items_per_section).await
        }

        async fn init_with_params(
            context: commonware_runtime::deterministic::Context,
            partition: &str,
            compression: Option<u8>,
            items_per_section: u64,
        ) -> Result<Self::Archive, Error> {
            let cfg = prunable::Config {
                partition: partition.into(),
                translator: TwoCap,
                compression,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                items_per_section,
            };
            prunable::Archive::init(context, cfg).await
        }
    }

    struct ImmutableArchiveFactory;

    impl ArchiveFactory for ImmutableArchiveFactory {
        type Archive =
            immutable::Archive<commonware_runtime::deterministic::Context, FixedBytes<64>, i32>;

        async fn init(
            context: commonware_runtime::deterministic::Context,
            compression: Option<u8>,
            items_per_section: u64,
        ) -> Result<Self::Archive, Error> {
            Self::init_with_params(context, "test", compression, items_per_section).await
        }

        async fn init_with_params(
            context: commonware_runtime::deterministic::Context,
            partition: &str,
            compression: Option<u8>,
            items_per_section: u64,
        ) -> Result<Self::Archive, Error> {
            let cfg = immutable::Config {
                metadata_partition: format!("{partition}_metadata"),
                journal_partition: format!("{partition}_journal"),
                ordinal_partition: format!("{partition}_ordinal"),
                compression,
                codec_config: (),
                items_per_section,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                cursor_heads: 32,
            };
            immutable::Archive::init(context, cfg).await
        }
    }

    // Generic test functions
    fn test_archive_put_get<F: ArchiveFactory>(compression: Option<u8>)
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = i32>,
    {
        use commonware_runtime::deterministic;

        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let mut archive = F::init(context.clone(), compression, DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            let index = 1u64;
            let key = test_key("testkey");
            let data = 1;

            // Has the key
            let has = archive
                .has(Identifier::Index(index))
                .await
                .expect("Failed to check key");
            assert!(!has);
            let has = archive
                .has(Identifier::Key(&key))
                .await
                .expect("Failed to check key");
            assert!(!has);

            // Put the key-data pair
            archive
                .put(index, key.clone(), data)
                .await
                .expect("Failed to put data");

            // Has the key
            let has = archive
                .has(Identifier::Index(index))
                .await
                .expect("Failed to check key");
            assert!(has);
            let has = archive
                .has(Identifier::Key(&key))
                .await
                .expect("Failed to check key");
            assert!(has);

            // Get the data back
            let retrieved = archive
                .get(Identifier::Index(index))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data);
            let retrieved = archive
                .get(Identifier::Key(&key))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data);

            // Force a sync
            archive.sync().await.expect("Failed to sync data");
        });
    }

    fn test_archive_get_nonexistent<F: ArchiveFactory>()
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = i32>,
    {
        use commonware_runtime::deterministic;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = F::init(context.clone(), None, DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            // Attempt to get an index that doesn't exist
            let index = 1u64;
            let retrieved: Option<i32> = archive
                .get(Identifier::Index(index))
                .await
                .expect("Failed to get data");
            assert!(retrieved.is_none());

            // Attempt to get a key that doesn't exist
            let key = test_key("nonexistent");
            let retrieved = archive
                .get(Identifier::Key(&key))
                .await
                .expect("Failed to get data");
            assert!(retrieved.is_none());
        });
    }

    fn test_archive_duplicate_key<F: ArchiveFactory>()
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = i32>,
    {
        use commonware_runtime::deterministic;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut archive = F::init(context.clone(), None, DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            let index = 1u64;
            let key = test_key("duplicate");
            let data1 = 1;
            let data2 = 2;

            // Put the key-data pair
            archive
                .put(index, key.clone(), data1)
                .await
                .expect("Failed to put data");

            // Put the key-data pair again (same index, should be ignored)
            archive
                .put(index, key.clone(), data2)
                .await
                .expect("Duplicate put should not fail");

            // Get the data back
            let retrieved = archive
                .get(Identifier::Index(index))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);
            let retrieved = archive
                .get(Identifier::Key(&key))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);
        });
    }

    fn test_archive_overlapping_key_basic<F: ArchiveFactory>()
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = i32>,
    {
        use commonware_runtime::deterministic;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut archive = F::init(context.clone(), None, DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            let index1 = 1u64;
            let key1 = test_key("keys1");
            let data1 = 1;
            let index2 = 2u64;
            let key2 = test_key("keys2");
            let data2 = 2;

            // Put the key-data pairs
            archive
                .put(index1, key1.clone(), data1)
                .await
                .expect("Failed to put data");
            archive
                .put(index2, key2.clone(), data2)
                .await
                .expect("Failed to put data");

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(&key1))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            let retrieved = archive
                .get(Identifier::Key(&key2))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);
        });
    }

    fn test_archive_next_gap<F: ArchiveFactory>()
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = i32>,
    {
        use commonware_runtime::deterministic;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut archive = F::init(context.clone(), None, DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different indices
            let keys = vec![
                (1u64, test_key("key1-blah"), 1),
                (10u64, test_key("key2-blah"), 2),
                (11u64, test_key("key3-blah"), 3),
                (14u64, test_key("key3-bleh"), 3),
            ];
            for (index, key, data) in &keys {
                archive
                    .put(*index, key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Check ranges
            let (current_end, start_next) = archive.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 1);

            let (current_end, start_next) = archive.next_gap(1);
            assert_eq!(current_end.unwrap(), 1);
            assert_eq!(start_next.unwrap(), 10);

            let (current_end, start_next) = archive.next_gap(10);
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(11);
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(12);
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(14);
            assert_eq!(current_end.unwrap(), 14);
            assert!(start_next.is_none());
        });
    }

    fn test_archive_compression_then_none<F: ArchiveFactory>()
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = i32>,
    {
        use commonware_runtime::deterministic;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize with compression
            let mut archive = F::init(context.clone(), Some(3), DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            // Put the key-data pair
            let index = 1u64;
            let key = test_key("testkey");
            let data = 1;
            archive
                .put(index, key.clone(), data)
                .await
                .expect("Failed to put data");

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Initialize the archive again without compression
            // Different implementations may handle this differently
            let result = F::init(context, None, DEFAULT_ITEMS_PER_SECTION).await;

            // If it succeeds, the data might not be readable
            if let Ok(archive) = result {
                let retrieved = archive.get(Identifier::Index(index)).await;
                // Either the archive fails to initialize, data is not readable, or we get a codec error
                match retrieved {
                    Ok(Some(_)) => {
                        panic!("Should not be able to read compressed data without compression")
                    }
                    Ok(None) => {} // Data not found is acceptable
                    Err(_) => {}   // Codec error when trying to read compressed data is acceptable
                }
            }
            // Otherwise it should have failed initialization
        });
    }

    fn test_archive_ranges<F: ArchiveFactory>()
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = i32>,
    {
        use commonware_runtime::deterministic;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut archive = F::init(context.clone(), None, DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different indices
            let keys = vec![
                (1u64, test_key("key1-blah"), 1),
                (10u64, test_key("key2-blah"), 2),
                (11u64, test_key("key3-blah"), 3),
                (14u64, test_key("key3-bleh"), 3),
            ];
            for (index, key, data) in &keys {
                archive
                    .put(*index, key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Check that we can get all the data
            for (index, _, data) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);
            }

            // Basic gap check
            let (current_end, start_next) = archive.next_gap(0);
            if current_end.is_none() {
                assert!(start_next.is_some());
            }
            let (current_end, start_next) = archive.next_gap(14);
            if current_end == Some(14) {
                assert!(start_next.is_none());
            }

            // Close and check again
            archive.close().await.expect("Failed to close archive");
            let archive = F::init(context, None, DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            // Verify data persistence
            for (index, _, data) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);
            }
        });
    }

    #[test_traced]
    fn test_prunable_archive_put_get_no_compression() {
        test_archive_put_get::<PrunableArchiveFactory>(None);
    }

    #[test_traced]
    fn test_prunable_archive_put_get_compression() {
        test_archive_put_get::<PrunableArchiveFactory>(Some(3));
    }

    #[test_traced]
    fn test_immutable_archive_put_get_no_compression() {
        test_archive_put_get::<ImmutableArchiveFactory>(None);
    }

    #[test_traced]
    fn test_immutable_archive_put_get_compression() {
        test_archive_put_get::<ImmutableArchiveFactory>(Some(3));
    }

    #[test_traced]
    fn test_prunable_archive_compression_then_none() {
        test_archive_compression_then_none::<PrunableArchiveFactory>();
    }

    #[test_traced]
    fn test_immutable_archive_compression_then_none() {
        test_archive_compression_then_none::<ImmutableArchiveFactory>();
    }

    #[test_traced]
    fn test_prunable_archive_get_nonexistent() {
        test_archive_get_nonexistent::<PrunableArchiveFactory>();
    }

    #[test_traced]
    fn test_immutable_archive_get_nonexistent() {
        test_archive_get_nonexistent::<ImmutableArchiveFactory>();
    }

    #[test_traced]
    fn test_prunable_archive_duplicate_key() {
        test_archive_duplicate_key::<PrunableArchiveFactory>();
    }

    #[test_traced]
    fn test_immutable_archive_duplicate_key() {
        test_archive_duplicate_key::<ImmutableArchiveFactory>();
    }

    #[test_traced]
    fn test_prunable_archive_overlapping_key_basic() {
        test_archive_overlapping_key_basic::<PrunableArchiveFactory>();
    }

    #[test_traced]
    fn test_immutable_archive_overlapping_key_basic() {
        test_archive_overlapping_key_basic::<ImmutableArchiveFactory>();
    }

    #[test_traced]
    fn test_prunable_archive_next_gap() {
        test_archive_next_gap::<PrunableArchiveFactory>();
    }

    #[test_traced]
    fn test_immutable_archive_next_gap() {
        test_archive_next_gap::<ImmutableArchiveFactory>();
    }

    #[test_traced]
    fn test_prunable_archive_ranges() {
        test_archive_ranges::<PrunableArchiveFactory>();
    }

    #[test_traced]
    fn test_immutable_archive_ranges() {
        test_archive_ranges::<ImmutableArchiveFactory>();
    }
}
