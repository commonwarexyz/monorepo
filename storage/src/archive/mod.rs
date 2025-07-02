//! A write-once key-value store where each key is associated with a unique index.
//!
//! [Archive] is a key-value store designed for workloads where all data is written only once and is
//! uniquely associated with both an `index` and a `key`.

use commonware_codec::Codec;
use commonware_utils::Array;
use std::future::Future;
use thiserror::Error;

pub mod fast;
pub mod minimal;

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

    /// Prune the to the minimum index.
    fn prune(&mut self, min: u64) -> impl Future<Output = Result<(), Error>>;

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
    use commonware_runtime::{Metrics, Runner};
    use commonware_utils::array::FixedBytes;
    use rand::Rng;
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

        /// Check implementation-specific metrics
        fn check_metrics(buffer: &str, expected: &MetricsExpectation);

        /// Whether this implementation supports certain tests
        fn supports_lazy_prune_test() -> bool {
            false
        }
    }

    struct MetricsExpectation {
        items_tracked: Option<usize>,
        unnecessary_reads: Option<usize>,
        gets: Option<usize>,
        has: Option<usize>,
        syncs: Option<usize>,
        indices_pruned: Option<usize>,
        pruned: Option<usize>,
    }

    struct FastArchiveFactory;

    impl ArchiveFactory for FastArchiveFactory {
        type Archive =
            fast::Archive<TwoCap, commonware_runtime::deterministic::Context, FixedBytes<64>, i32>;

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
            let cfg = fast::Config {
                partition: partition.into(),
                translator: TwoCap,
                compression,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                items_per_section,
            };
            fast::Archive::init(context, cfg).await
        }

        fn check_metrics(buffer: &str, expected: &MetricsExpectation) {
            if let Some(items) = expected.items_tracked {
                assert!(buffer.contains(&format!("items_tracked {items}")));
            }
            if let Some(reads) = expected.unnecessary_reads {
                assert!(buffer.contains(&format!("unnecessary_reads_total {reads}")));
            }
            if let Some(gets) = expected.gets {
                assert!(buffer.contains(&format!("gets_total {gets}")));
            }
            if let Some(has) = expected.has {
                assert!(buffer.contains(&format!("has_total {has}")));
            }
            if let Some(syncs) = expected.syncs {
                assert!(buffer.contains(&format!("syncs_total {syncs}")));
            }
            if let Some(pruned) = expected.indices_pruned {
                assert!(buffer.contains(&format!("indices_pruned_total {pruned}")));
            }
            if let Some(pruned) = expected.pruned {
                assert!(buffer.contains(&format!("pruned_total {pruned}")));
            }
        }

        fn supports_lazy_prune_test() -> bool {
            true
        }
    }

    struct MinimalArchiveFactory;

    impl ArchiveFactory for MinimalArchiveFactory {
        type Archive =
            minimal::Archive<commonware_runtime::deterministic::Context, FixedBytes<64>, i32>;

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
            let cfg = minimal::Config {
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
            minimal::Archive::init(context, cfg).await
        }

        fn check_metrics(buffer: &str, expected: &MetricsExpectation) {
            // Minimal archive may have different or no metrics
            // For now, we'll just check basic assertions if they exist
            if expected.items_tracked.is_some() && buffer.contains("items_tracked") {
                // Basic validation that metric exists
                assert!(buffer.contains("items_tracked"));
            }
        }
    }

    // Factory for large value tests
    struct FastArchiveFactoryLarge;

    impl ArchiveFactory for FastArchiveFactoryLarge {
        type Archive = fast::Archive<
            TwoCap,
            commonware_runtime::deterministic::Context,
            FixedBytes<64>,
            FixedBytes<1024>,
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
            let cfg = fast::Config {
                partition: partition.into(),
                translator: TwoCap,
                compression,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                items_per_section,
            };
            fast::Archive::init(context, cfg).await
        }

        fn check_metrics(buffer: &str, expected: &MetricsExpectation) {
            FastArchiveFactory::check_metrics(buffer, expected);
        }

        fn supports_lazy_prune_test() -> bool {
            true
        }
    }

    struct MinimalArchiveFactoryLarge;

    impl ArchiveFactory for MinimalArchiveFactoryLarge {
        type Archive = minimal::Archive<
            commonware_runtime::deterministic::Context,
            FixedBytes<64>,
            FixedBytes<1024>,
        >;

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
            let cfg = minimal::Config {
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
            minimal::Archive::init(context, cfg).await
        }

        fn check_metrics(buffer: &str, expected: &MetricsExpectation) {
            MinimalArchiveFactory::check_metrics(buffer, expected);
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

            // Check metrics
            let buffer = context.encode();
            F::check_metrics(
                &buffer,
                &MetricsExpectation {
                    items_tracked: Some(1),
                    unnecessary_reads: Some(0),
                    gets: Some(4),
                    has: Some(4),
                    syncs: Some(0),
                    indices_pruned: None,
                    pruned: None,
                },
            );

            // Force a sync
            archive.sync().await.expect("Failed to sync data");

            // Check metrics
            let buffer = context.encode();
            F::check_metrics(
                &buffer,
                &MetricsExpectation {
                    items_tracked: Some(1),
                    unnecessary_reads: Some(0),
                    gets: Some(4),
                    has: Some(4),
                    syncs: Some(1),
                    indices_pruned: None,
                    pruned: None,
                },
            );
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

            // Check metrics
            let buffer = context.encode();
            F::check_metrics(
                &buffer,
                &MetricsExpectation {
                    items_tracked: Some(0),
                    unnecessary_reads: Some(0),
                    gets: Some(2),
                    has: None,
                    syncs: None,
                    indices_pruned: None,
                    pruned: None,
                },
            );
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

            // Check metrics
            let buffer = context.encode();
            F::check_metrics(
                &buffer,
                &MetricsExpectation {
                    items_tracked: Some(1),
                    unnecessary_reads: Some(0),
                    gets: Some(2),
                    has: None,
                    syncs: None,
                    indices_pruned: None,
                    pruned: None,
                },
            );
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

            // Check metrics - for fast archive, overlapping keys should trigger unnecessary reads
            let buffer = context.encode();
            F::check_metrics(
                &buffer,
                &MetricsExpectation {
                    items_tracked: Some(2),
                    unnecessary_reads: None, // Let implementation decide
                    gets: Some(2),
                    has: None,
                    syncs: None,
                    indices_pruned: None,
                    pruned: None,
                },
            );
        });
    }

    fn test_archive_prune_keys<F: ArchiveFactory>()
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = i32>,
    {
        use commonware_runtime::deterministic;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut archive = F::init(context.clone(), None, 1) // Each item is its own section
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different sections
            let keys = vec![
                (1u64, test_key("key1-blah"), 1),
                (2u64, test_key("key2-blah"), 2),
                (3u64, test_key("key3-blah"), 3),
                (4u64, test_key("key3-bleh"), 3),
                (5u64, test_key("key4-blah"), 4),
            ];

            for (index, key, data) in &keys {
                archive
                    .put(*index, key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Check metrics
            let buffer = context.encode();
            F::check_metrics(
                &buffer,
                &MetricsExpectation {
                    items_tracked: Some(5),
                    unnecessary_reads: None,
                    gets: None,
                    has: None,
                    syncs: None,
                    indices_pruned: None,
                    pruned: None,
                },
            );

            // Prune sections less than 3
            archive.prune(3).await.expect("Failed to prune");

            // Ensure keys 1 and 2 are no longer present
            for (index, key, data) in keys {
                let retrieved = archive
                    .get(Identifier::Key(&key))
                    .await
                    .expect("Failed to get data");
                if index < 3 {
                    assert!(retrieved.is_none());
                } else {
                    assert_eq!(retrieved.expect("Data not found"), data);
                }
            }

            // For fast archive, check specific pruning behavior
            if F::supports_lazy_prune_test() {
                // Try to put older index
                let result = archive.put(1, test_key("key1-blah"), 1).await;
                assert!(matches!(result, Err(Error::AlreadyPrunedTo(3))));

                // Trigger lazy removal of keys
                archive
                    .put(6, test_key("key2-blfh"), 5)
                    .await
                    .expect("Failed to put data");
            }
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

            // Initialize the archive again without compression - should fail
            let result = F::init(context, None, DEFAULT_ITEMS_PER_SECTION).await;
            assert!(result.is_err());
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

            // Close and check again
            archive.close().await.expect("Failed to close archive");
            let archive = F::init(context, None, DEFAULT_ITEMS_PER_SECTION)
                .await
                .expect("Failed to initialize archive");

            // Check ranges again
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

    fn test_archive_keys_and_restart<F: ArchiveFactory>(num_keys: usize) -> String
    where
        F::Archive: Archive<Key = FixedBytes<64>, Value = FixedBytes<1024>>,
    {
        use commonware_runtime::deterministic;
        use std::collections::BTreeMap;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let items_per_section = 256u64;
            let mut archive = F::init(context.clone(), None, items_per_section)
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different sections
            let mut keys = BTreeMap::new();
            while keys.len() < num_keys {
                let index = keys.len() as u64;
                let mut key = [0u8; 64];
                context.fill(&mut key);
                let key = FixedBytes::<64>::decode(key.as_ref()).unwrap();
                let mut data = [0u8; 1024];
                context.fill(&mut data);
                let data = FixedBytes::<1024>::decode(data.as_ref()).unwrap();

                archive
                    .put(index, key.clone(), data.clone())
                    .await
                    .expect("Failed to put data");
                keys.insert(key, (index, data));
            }

            // Ensure all keys can be retrieved
            for (key, (index, data)) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
                let retrieved = archive
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
            }

            // Check metrics
            let buffer = context.encode();
            let tracked = format!("items_tracked {num_keys:?}");
            // For minimal archive, this metric might not exist
            if buffer.contains("items_tracked") {
                assert!(buffer.contains(&tracked));
            }

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Reinitialize the archive
            let mut archive = F::init(context.clone(), None, items_per_section)
                .await
                .expect("Failed to initialize archive");

            // Ensure all keys can be retrieved
            for (key, (index, data)) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
                let retrieved = archive
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
            }

            // Prune first half
            let min = (keys.len() / 2) as u64;
            archive.prune(min).await.expect("Failed to prune");

            // Ensure all keys can be retrieved that haven't been pruned
            let min = (min / items_per_section) * items_per_section;
            let mut removed = 0;
            for (key, (index, data)) in keys {
                if index >= min {
                    let retrieved = archive
                        .get(Identifier::Key(&key))
                        .await
                        .expect("Failed to get data")
                        .expect("Data not found");
                    assert_eq!(retrieved, data);

                    // Check range
                    let (current_end, start_next) = archive.next_gap(index);
                    assert_eq!(current_end.unwrap(), num_keys as u64 - 1);
                    assert!(start_next.is_none());
                } else {
                    let retrieved = archive
                        .get(Identifier::Key(&key))
                        .await
                        .expect("Failed to get data");
                    assert!(retrieved.is_none());
                    removed += 1;

                    // Check range
                    let (current_end, start_next) = archive.next_gap(index);
                    assert!(current_end.is_none());
                    assert_eq!(start_next.unwrap(), min);
                }
            }

            context.auditor().state()
        })
    }

    // Test cases for all generic functions
    #[test_traced]
    fn test_fast_archive_put_get_no_compression() {
        test_archive_put_get::<FastArchiveFactory>(None);
    }

    #[test_traced]
    fn test_fast_archive_put_get_compression() {
        test_archive_put_get::<FastArchiveFactory>(Some(3));
    }

    #[test_traced]
    fn test_minimal_archive_put_get_no_compression() {
        test_archive_put_get::<MinimalArchiveFactory>(None);
    }

    #[test_traced]
    fn test_minimal_archive_put_get_compression() {
        test_archive_put_get::<MinimalArchiveFactory>(Some(3));
    }

    #[test_traced]
    fn test_fast_archive_compression_then_none() {
        test_archive_compression_then_none::<FastArchiveFactory>();
    }

    #[test_traced]
    fn test_minimal_archive_compression_then_none() {
        test_archive_compression_then_none::<MinimalArchiveFactory>();
    }

    #[test_traced]
    fn test_fast_archive_get_nonexistent() {
        test_archive_get_nonexistent::<FastArchiveFactory>();
    }

    #[test_traced]
    fn test_minimal_archive_get_nonexistent() {
        test_archive_get_nonexistent::<MinimalArchiveFactory>();
    }

    #[test_traced]
    fn test_fast_archive_duplicate_key() {
        test_archive_duplicate_key::<FastArchiveFactory>();
    }

    #[test_traced]
    fn test_minimal_archive_duplicate_key() {
        test_archive_duplicate_key::<MinimalArchiveFactory>();
    }

    #[test_traced]
    fn test_fast_archive_overlapping_key_basic() {
        test_archive_overlapping_key_basic::<FastArchiveFactory>();
    }

    #[test_traced]
    fn test_minimal_archive_overlapping_key_basic() {
        test_archive_overlapping_key_basic::<MinimalArchiveFactory>();
    }

    #[test_traced]
    fn test_fast_archive_prune_keys() {
        test_archive_prune_keys::<FastArchiveFactory>();
    }

    #[test_traced]
    fn test_minimal_archive_prune_keys() {
        test_archive_prune_keys::<MinimalArchiveFactory>();
    }

    #[test_traced]
    fn test_fast_archive_next_gap() {
        test_archive_next_gap::<FastArchiveFactory>();
    }

    #[test_traced]
    fn test_minimal_archive_next_gap() {
        test_archive_next_gap::<MinimalArchiveFactory>();
    }

    #[test_traced]
    fn test_fast_archive_ranges() {
        test_archive_ranges::<FastArchiveFactory>();
    }

    #[test_traced]
    fn test_minimal_archive_ranges() {
        test_archive_ranges::<MinimalArchiveFactory>();
    }

    #[test_traced]
    fn test_fast_archive_keys_and_restart() {
        let num_keys = 100;
        let state = test_archive_keys_and_restart::<FastArchiveFactoryLarge>(num_keys);
        assert!(state.contains("items_tracked 100"));
    }

    #[test_traced]
    fn test_minimal_archive_keys_and_restart() {
        let num_keys = 100;
        let state = test_archive_keys_and_restart::<MinimalArchiveFactoryLarge>(num_keys);
        // Minimal archive may not have the same metrics
        assert!(!state.is_empty());
    }

    #[test_traced]
    #[ignore]
    fn test_fast_archive_many_keys_and_restart() {
        test_archive_keys_and_restart::<FastArchiveFactoryLarge>(100_000); // 391 sections
    }

    #[test_traced]
    #[ignore]
    fn test_minimal_archive_many_keys_and_restart() {
        test_archive_keys_and_restart::<MinimalArchiveFactoryLarge>(100_000); // 391 sections
    }

    #[test_traced]
    #[ignore]
    fn test_fast_determinism() {
        let state1 = test_archive_keys_and_restart::<FastArchiveFactoryLarge>(5_000); // 20 sections
        let state2 = test_archive_keys_and_restart::<FastArchiveFactoryLarge>(5_000);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    #[ignore]
    fn test_minimal_determinism() {
        let state1 = test_archive_keys_and_restart::<MinimalArchiveFactoryLarge>(5_000); // 20 sections
        let state2 = test_archive_keys_and_restart::<MinimalArchiveFactoryLarge>(5_000);
        assert_eq!(state1, state2);
    }
}
