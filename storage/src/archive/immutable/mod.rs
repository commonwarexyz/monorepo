//! A write-once, immutable key-value store optimized for permanent storage.
//!
//! [Archive] is a key-value store designed for workloads where all data is written only once and is
//! uniquely associated with both an `index` and a `key`. Unlike the prunable variant, this archive
//! is designed for permanent storage where data is never removed.
//!
//! Data is stored using two separate subsystems:
//! - [crate::store::immutable::Store]: Stores key-value pairs with efficient lookups
//! - [crate::store::ordinal::Store]: Maps indices to keys and maintains interval tracking
//!
//! This separation enables **single-read lookups** for key-based queries and **two-read lookups**
//! for index-based queries, while maintaining minimal memory overhead through the use of
//! persistent on-disk indexes.
//!
//! _Notably, [Archive] uses persistent hash tables and flat files with checksums, eliminating the
//! need for complex compaction or WAL mechanisms while still providing crash consistency._
//!
//! # Architecture
//!
//! [Archive] uses a two-level storage architecture:
//!
//! ```text
//! Index Query:
//!   index → [ordinal::Store] → key → [immutable::Store] → value
//!
//! Key Query:
//!   key → [immutable::Store] → value
//! ```
//!
//! # Uniqueness
//!
//! [Archive] assumes all stored indices and keys are unique. If the same key is associated with
//! multiple indices, there is no guarantee which value will be returned. If a key is written to
//! an existing index, [Archive] will skip the write and return successfully.
//!
//! # Memory Overhead
//!
//! Unlike the prunable variant which maintains in-memory indexes, [Archive] leverages on-disk
//! structures to minimize memory usage:
//! - The immutable store uses a persistent hash table with minimal in-memory caching
//! - The ordinal store uses a flat file format with direct offset calculations
//! - Only an in-memory RMap is maintained for efficient interval queries
//!
//! This design makes [Archive] suitable for very large datasets that would be impractical to
//! index entirely in memory.
//!
//! # Sync
//!
//! [Archive] flushes writes to both underlying stores when the caller invokes `sync`. The sync
//! operation is atomic across both stores to ensure consistency.
//!
//! # Single vs Two Operation Reads
//!
//! - **Key lookups**: Single disk read directly from the immutable store
//! - **Index lookups**: Two disk reads (index→key from ordinal store, then key→value from immutable store)
//!
//! This tradeoff optimizes for the common case of key-based lookups while still providing
//! efficient index-based access.
//!
//! # Crash Consistency
//!
//! Both underlying stores use checksums and careful write ordering to ensure crash consistency:
//! - The immutable store uses CRC32 checksums on all entries
//! - The ordinal store uses CRC32 checksums on each record
//! - Invalid entries are detected and handled during initialization
//!
//! # Querying for Gaps
//!
//! [Archive] tracks gaps in the index space through the ordinal store's RMap, enabling efficient
//! queries for missing indices using `next_gap`. This is particularly useful for identifying
//! missing data in sequential datasets.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_storage::{
//!     store::{immutable, ordinal},
//!     archive::{Archive as _, immutable::{Archive, Config}},
//! };
//! use commonware_utils::array::FixedBytes;
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create an archive
//!     let cfg = Config {
//!         immutable: immutable::Config {
//!             journal_partition: "archive_data".into(),
//!             journal_compression: Some(3),
//!             metadata_partition: "archive_metadata".into(),
//!             table_partition: "archive_table".into(),
//!             table_size: 65536, // 64K buckets
//!             codec_config: (),
//!             write_buffer: 1024 * 1024,
//!             target_journal_size: 100 * 1024 * 1024, // 100MB journals
//!         },
//!         ordinal: ordinal::Config {
//!             partition: "archive_index".into(),
//!             items_per_blob: 10000,
//!             write_buffer: 4096,
//!             replay_buffer: 1024 * 1024,
//!         },
//!     };
//!     let mut archive = Archive::<_, FixedBytes<32>, i32>::init(context, cfg).await.unwrap();
//!
//!     // Put a key-value pair
//!     let key = FixedBytes::new([1u8; 32]);
//!     archive.put(1, key, 42).await.unwrap();
//!
//!     // Sync to disk
//!     archive.sync().await.unwrap();
//!
//!     // Close the archive
//!     archive.close().await.unwrap();
//! });
//! ```

mod storage;

use crate::store::{immutable, ordinal};
pub use storage::Archive;
use thiserror::Error;

/// Errors that can occur when interacting with the [Archive].
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("immutable index error: {0}")]
    Immutable(#[from] immutable::Error),
    #[error("ordinal index error: {0}")]
    Ordinal(#[from] ordinal::Error),
    #[error("record corrupted")]
    RecordCorrupted,
}

/// Configuration for [Archive] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The configuration for the [immutable::Index].
    pub immutable: immutable::Config<C>,

    /// The configuration for the [ordinal::Index].
    pub ordinal: ordinal::Config,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive::Archive as _,
        identifier::Identifier,
        store::{immutable, ordinal},
    };
    use commonware_codec::DecodeExt;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics, Runner};
    use commonware_utils::array::FixedBytes;
    use rand::Rng;
    use std::collections::BTreeMap;

    const DEFAULT_TABLE_SIZE: u32 = 256;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_REPLAY_BUFFER: usize = 4096;
    const DEFAULT_ITEMS_PER_BLOB: u64 = 1000;
    const DEFAULT_TARGET_JOURNAL_SIZE: u64 = 10 * 1024 * 1024;

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    fn test_archive_put_get(compression: Option<u8>) {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                immutable: immutable::Config {
                    journal_partition: "test_archive_data".into(),
                    journal_compression: compression,
                    metadata_partition: "test_archive_metadata".into(),
                    table_partition: "test_archive_table".into(),
                    table_size: DEFAULT_TABLE_SIZE,
                    codec_config: (),
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
                },
                ordinal: ordinal::Config {
                    partition: "test_archive_index".into(),
                    items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    replay_buffer: DEFAULT_REPLAY_BUFFER,
                },
            };
            let mut archive = Archive::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
            assert!(buffer.contains("gets_total 2"), "{}", buffer);
            assert!(buffer.contains("has_total 4"), "{}", buffer);
            assert!(buffer.contains("puts_total 1"), "{}", buffer);

            // Force a sync
            archive.sync().await.expect("Failed to sync data");
        });
    }

    #[test_traced]
    fn test_archive_put_get_no_compression() {
        test_archive_put_get(None);
    }

    #[test_traced]
    fn test_archive_put_get_compression() {
        test_archive_put_get(Some(3));
    }

    #[test_traced]
    fn test_archive_duplicate_key() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                immutable: immutable::Config {
                    journal_partition: "test_archive_data".into(),
                    journal_compression: None,
                    metadata_partition: "test_archive_metadata".into(),
                    table_partition: "test_archive_table".into(),
                    table_size: DEFAULT_TABLE_SIZE,
                    codec_config: (),
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
                },
                ordinal: ordinal::Config {
                    partition: "test_archive_index".into(),
                    items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    replay_buffer: DEFAULT_REPLAY_BUFFER,
                },
            };
            let mut archive = Archive::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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

            // Put the key-data pair again (should be ignored)
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
            assert!(buffer.contains("gets_total 2"), "{}", buffer);
            assert!(buffer.contains("puts_total 2"), "{}", buffer); // Both puts are counted, even though second is ignored
        });
    }

    #[test_traced]
    fn test_archive_get_nonexistent() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                immutable: immutable::Config {
                    journal_partition: "test_archive_data".into(),
                    journal_compression: None,
                    metadata_partition: "test_archive_metadata".into(),
                    table_partition: "test_archive_table".into(),
                    table_size: DEFAULT_TABLE_SIZE,
                    codec_config: (),
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
                },
                ordinal: ordinal::Config {
                    partition: "test_archive_index".into(),
                    items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    replay_buffer: DEFAULT_REPLAY_BUFFER,
                },
            };
            let archive = Archive::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
            assert!(buffer.contains("gets_total 2"), "{}", buffer);
        });
    }

    #[test_traced]
    fn test_archive_multiple_keys() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                immutable: immutable::Config {
                    journal_partition: "test_archive_data".into(),
                    journal_compression: None,
                    metadata_partition: "test_archive_metadata".into(),
                    table_partition: "test_archive_table".into(),
                    table_size: DEFAULT_TABLE_SIZE,
                    codec_config: (),
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
                },
                ordinal: ordinal::Config {
                    partition: "test_archive_index".into(),
                    items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    replay_buffer: DEFAULT_REPLAY_BUFFER,
                },
            };
            let mut archive = Archive::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys
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

            // Retrieve all keys and verify
            for (index, key, data) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);

                let retrieved = archive
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);
            }
        });
    }

    fn test_archive_keys_and_restart(num_keys: usize) -> String {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Initialize the archive
            let cfg = Config {
                immutable: immutable::Config {
                    journal_partition: "test_archive_data".into(),
                    journal_compression: None,
                    metadata_partition: "test_archive_metadata".into(),
                    table_partition: "test_archive_table".into(),
                    table_size: DEFAULT_TABLE_SIZE,
                    codec_config: (),
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
                },
                ordinal: ordinal::Config {
                    partition: "test_archive_index".into(),
                    items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    replay_buffer: DEFAULT_REPLAY_BUFFER,
                },
            };
            let mut archive =
                Archive::<_, FixedBytes<64>, FixedBytes<1024>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize archive");

            // Insert multiple keys
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

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Reinitialize the archive
            let archive =
                Archive::<_, FixedBytes<64>, FixedBytes<1024>>::init(context.clone(), cfg)
                    .await
                    .expect("Failed to initialize archive");

            // Ensure all keys can still be retrieved after restart
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

            context.auditor().state()
        })
    }

    #[test_traced]
    #[ignore]
    fn test_archive_many_keys_and_restart() {
        test_archive_keys_and_restart(10_000);
    }

    #[test_traced]
    #[ignore]
    fn test_determinism() {
        let state1 = test_archive_keys_and_restart(1_000);
        let state2 = test_archive_keys_and_restart(1_000);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_ranges() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                immutable: immutable::Config {
                    journal_partition: "test_archive_data".into(),
                    journal_compression: None,
                    metadata_partition: "test_archive_metadata".into(),
                    table_partition: "test_archive_table".into(),
                    table_size: DEFAULT_TABLE_SIZE,
                    codec_config: (),
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
                },
                ordinal: ordinal::Config {
                    partition: "test_archive_index".into(),
                    items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    replay_buffer: DEFAULT_REPLAY_BUFFER,
                },
            };
            let mut archive = Archive::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
            let (current_end, start_next) = archive.next_gap(0).await.unwrap();
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 1);

            let (current_end, start_next) = archive.next_gap(1).await.unwrap();
            assert_eq!(current_end.unwrap(), 1);
            assert_eq!(start_next.unwrap(), 10);

            let (current_end, start_next) = archive.next_gap(10).await.unwrap();
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(11).await.unwrap();
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(12).await.unwrap();
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(14).await.unwrap();
            assert_eq!(current_end.unwrap(), 14);
            assert!(start_next.is_none());

            // Close and check again
            archive.close().await.expect("Failed to close archive");
            let archive = Archive::<_, FixedBytes<64>, i32>::init(context, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Check ranges again
            let (current_end, start_next) = archive.next_gap(0).await.unwrap();
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 1);

            let (current_end, start_next) = archive.next_gap(1).await.unwrap();
            assert_eq!(current_end.unwrap(), 1);
            assert_eq!(start_next.unwrap(), 10);

            let (current_end, start_next) = archive.next_gap(10).await.unwrap();
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(11).await.unwrap();
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(12).await.unwrap();
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(14).await.unwrap();
            assert_eq!(current_end.unwrap(), 14);
            assert!(start_next.is_none());
        });
    }
}
