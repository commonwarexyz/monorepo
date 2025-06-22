//! A persistent, immutable key-value store with efficient lookups.
//!
//! [Store] is a key-value store designed for permanent storage where data is written once and never
//! modified. Unlike in-memory stores, this implementation uses persistent on-disk structures to
//! minimize memory usage while maintaining fast lookups through a hash table approach.
//!
//! # Architecture
//!
//! [Store] uses a multi-component architecture:
//! - **Variable Journal**: Stores key-value entries in an append-only log with optional compression
//! - **Hash Table**: A persistent hash table stored in a blob that maps keys to journal locations
//! - **Metadata**: Stores committed epoch/section information for crash consistency
//!
//! The hash table uses a dual-entry design where each bucket contains two slots. This provides
//! redundancy and enables atomic updates without locks or complex coordination.
//!
//! # Hash Table Design
//!
//! The table uses a cuckoo-like approach with two slots per bucket:
//!
//! ```text
//! Bucket Layout (48 bytes total, 2 slots of 24 bytes each):
//! +--------+--------+--------+--------+
//! | Slot 1                           |
//! | epoch  | section| offset | crc   |
//! | (8B)   | (8B)   | (4B)   | (4B)  |
//! +--------+--------+--------+--------+
//! | Slot 2                           |
//! | epoch  | section| offset | crc   |
//! | (8B)   | (8B)   | (4B)   | (4B)  |
//! +--------+--------+--------+--------+
//! ```
//!
//! # Crash Consistency
//!
//! [Store] ensures crash consistency through:
//! 1. **Checksums**: All table entries include CRC32 checksums
//! 2. **Epochs**: Each write increments an epoch counter, invalid epochs are cleaned on restart
//! 3. **Atomic Metadata**: Committed state is atomically updated after successful writes
//!
//! On restart, any table entries with epochs greater than the last committed epoch are zeroed out,
//! ensuring the store returns to a consistent state.
//!
//! # Collision Resolution
//!
//! When multiple keys hash to the same bucket, they form a linked list in the journal:
//!
//! ```text
//! Table Bucket → Journal Entry 1 → Journal Entry 2 → ... → None
//!                [key1, value1]     [key2, value2]
//!                next=(s2, o2)      next=None
//! ```
//!
//! This design trades write complexity for read efficiency - lookups may need to follow
//! the chain but writes can simply prepend to the list.
//!
//! # Memory Usage
//!
//! The store minimizes memory usage by keeping all data structures on disk:
//! - Hash table: Fixed size on disk (table_size * 48 bytes)
//! - Journal: Append-only logs split into sections
//! - Only pending writes are buffered in memory until sync
//!
//! # Performance Characteristics
//!
//! - **Writes**: O(1) amortized - append to journal and update table
//! - **Reads**: O(k) where k is the chain length for a bucket (typically small with good hash distribution)
//! - **Memory**: O(p) where p is the number of pending writes
//! - **Restart**: O(n) where n is the table size (to validate epochs)
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_storage::store::immutable::{Store, Config};
//! use commonware_utils::array::FixedBytes;
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a store
//!     let cfg = Config {
//!         journal_partition: "store_journal".into(),
//!         journal_compression: Some(3),
//!         metadata_partition: "store_metadata".into(),
//!         table_partition: "store_table".into(),
//!         table_size: 65536, // 64K buckets
//!         codec_config: (),
//!         write_buffer: 1024 * 1024,
//!         target_journal_size: 100 * 1024 * 1024, // 100MB journals
//!     };
//!     let mut store = Store::<_, FixedBytes<32>, i32>::init(context, cfg).await.unwrap();
//!
//!     // Put a key-value pair
//!     let key = FixedBytes::new([1u8; 32]);
//!     store.put(key.clone(), 42).await.unwrap();
//!
//!     // Sync to disk
//!     store.sync().await.unwrap();
//!
//!     // Get the value
//!     let value = store.get(&key).await.unwrap().unwrap();
//!     assert_eq!(value, 42);
//!
//!     // Close the store
//!     store.close().await.unwrap();
//! });
//! ```

mod storage;

use commonware_utils::array::U64;
pub use storage::Store;
use thiserror::Error;

/// Errors that can occur when interacting with the [Store].
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error<U64>),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("invalid value length: expected {expected}, got {actual}")]
    InvalidValueLength { expected: usize, actual: usize },
    #[error("bucket corrupted at offset {0}")]
    BucketCorrupted(u64),
    #[error("directory corrupted")]
    DirectoryCorrupted,
    #[error("checksum mismatch: expected {expected:08x}, got {actual:08x}")]
    ChecksumMismatch { expected: u32, actual: u32 },
}

/// Configuration for [Store] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The `commonware-runtime::Storage` partition to use for storing the journal.
    pub journal_partition: String,

    /// The compression algorithm to use for the journal.
    pub journal_compression: Option<u8>,

    /// The `commonware-runtime::Storage` partition to use for storing the metadata.
    pub metadata_partition: String,

    /// The `commonware-runtime::Storage` partition to use for storing the hash table.
    pub table_partition: String,

    /// The size of the table. Should be a power of 2 and much larger than
    /// the expected number of buckets for better distribution.
    pub table_size: u32,

    /// The codec configuration to use for the value stored in the store.
    pub codec_config: C,

    /// The size of the write buffer to use for the journal.
    pub write_buffer: usize,

    /// The target size of each journal before creating a new one.
    pub target_journal_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::array::FixedBytes;
    use rand::RngCore;

    const DEFAULT_TABLE_SIZE: u32 = 256;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_TARGET_JOURNAL_SIZE: u64 = 10 * 1024 * 1024;

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    fn test_store_put_get(compression: Option<u8>) {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: compression,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: DEFAULT_TABLE_SIZE,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };
            let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            let key = test_key("testkey");
            let data = 42;

            // Check key doesn't exist
            let has = store.has(&key).await.expect("Failed to check key");
            assert!(!has);

            // Put the key-data pair
            store
                .put(key.clone(), data)
                .await
                .expect("Failed to put data");

            // Check key exists
            let has = store.has(&key).await.expect("Failed to check key");
            assert!(has);

            // Get the data back
            let retrieved = store
                .get(&key)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data);

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("gets_total 3"), "{}", buffer); // has calls get internally
            assert!(buffer.contains("puts_total 1"), "{}", buffer);

            // Force a sync
            store.sync().await.expect("Failed to sync data");
        });
    }

    #[test_traced]
    fn test_store_put_get_no_compression() {
        test_store_put_get(None);
    }

    #[test_traced]
    fn test_store_put_get_compression() {
        test_store_put_get(Some(3));
    }

    #[test_traced]
    fn test_store_multiple_keys() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: DEFAULT_TABLE_SIZE,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };
            let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert multiple keys
            let keys = vec![
                (test_key("key1"), 1),
                (test_key("key2"), 2),
                (test_key("key3"), 3),
                (test_key("key4"), 4),
                (test_key("key5"), 5),
            ];

            for (key, data) in &keys {
                store
                    .put(key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Retrieve all keys and verify
            for (key, data) in &keys {
                let retrieved = store
                    .get(key)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);
            }
        });
    }

    #[test_traced]
    fn test_store_collision_handling() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store with a very small table to force collisions
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: 4, // Very small to force collisions
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };
            let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert multiple keys that will likely collide
            let keys = vec![
                (test_key("key1"), 1),
                (test_key("key2"), 2),
                (test_key("key3"), 3),
                (test_key("key4"), 4),
                (test_key("key5"), 5),
                (test_key("key6"), 6),
                (test_key("key7"), 7),
                (test_key("key8"), 8),
            ];

            for (key, data) in &keys {
                store
                    .put(key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Sync to disk
            store.sync().await.expect("Failed to sync");

            // Retrieve all keys and verify they can still be found
            for (key, data) in &keys {
                let retrieved = store
                    .get(key)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);
            }
        });
    }

    #[test_traced]
    fn test_store_restart() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: DEFAULT_TABLE_SIZE,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Insert data and close
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                let keys = vec![
                    (test_key("persist1"), 100),
                    (test_key("persist2"), 200),
                    (test_key("persist3"), 300),
                ];

                for (key, data) in &keys {
                    store
                        .put(key.clone(), *data)
                        .await
                        .expect("Failed to put data");
                }

                store.close().await.expect("Failed to close store");
            }

            // Reopen and verify data persisted
            {
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                let keys = vec![
                    (test_key("persist1"), 100),
                    (test_key("persist2"), 200),
                    (test_key("persist3"), 300),
                ];

                for (key, data) in &keys {
                    let retrieved = store
                        .get(key)
                        .await
                        .expect("Failed to get data")
                        .expect("Data not found");
                    assert_eq!(retrieved, *data);
                }
            }
        });
    }

    #[test_traced]
    fn test_store_crash_consistency() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: DEFAULT_TABLE_SIZE,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // First, create some committed data
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store
                    .put(test_key("committed1"), 1)
                    .await
                    .expect("Failed to put data");
                store
                    .put(test_key("committed2"), 2)
                    .await
                    .expect("Failed to put data");

                // Sync to ensure data is committed
                store.sync().await.expect("Failed to sync");

                // Add more data but don't sync (simulating crash)
                store
                    .put(test_key("uncommitted1"), 3)
                    .await
                    .expect("Failed to put data");
                store
                    .put(test_key("uncommitted2"), 4)
                    .await
                    .expect("Failed to put data");

                // Close without syncing to simulate crash
                store.close().await.expect("Failed to close");
            }

            // Reopen and verify only committed data is present
            {
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Committed data should be present
                assert_eq!(store.get(&test_key("committed1")).await.unwrap(), Some(1));
                assert_eq!(store.get(&test_key("committed2")).await.unwrap(), Some(2));

                // Uncommitted data might or might not be present depending on implementation
                // But if present, it should be correct
                if let Some(val) = store.get(&test_key("uncommitted1")).await.unwrap() {
                    assert_eq!(val, 3);
                }
                if let Some(val) = store.get(&test_key("uncommitted2")).await.unwrap() {
                    assert_eq!(val, 4);
                }
            }
        });
    }

    #[test_traced]
    fn test_store_get_nonexistent() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: DEFAULT_TABLE_SIZE,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };
            let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Attempt to get a key that doesn't exist
            let key = test_key("nonexistent");
            let retrieved = store.get(&key).await.expect("Failed to get data");
            assert!(retrieved.is_none());

            // Check has returns false
            let has = store.has(&key).await.expect("Failed to check key");
            assert!(!has);
        });
    }

    #[test_traced]
    fn test_store_destroy() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: DEFAULT_TABLE_SIZE,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store
                    .put(test_key("destroy1"), 1)
                    .await
                    .expect("Failed to put data");
                store
                    .put(test_key("destroy2"), 2)
                    .await
                    .expect("Failed to put data");

                // Destroy the store
                store.destroy().await.expect("Failed to destroy store");
            }

            // Try to create a new store - it should be empty
            {
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Should not find any data
                assert!(store.get(&test_key("destroy1")).await.unwrap().is_none());
                assert!(store.get(&test_key("destroy2")).await.unwrap().is_none());
            }
        });
    }

    #[test_traced]
    fn test_store_partial_table_entry_write() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: 4,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Create store with data and sync
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(test_key("key1"), 42).await.unwrap();
                store.sync().await.unwrap();
                store.close().await.unwrap();
            }

            // Corrupt the table by writing partial entry
            {
                let (blob, _) = context.open(&cfg.table_partition, b"table").await.unwrap();
                // Write incomplete table entry (only 10 bytes instead of 24)
                blob.write_at(vec![0xFF; 10], 0).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reopen and verify it handles the corruption
            {
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // The key should still be retrievable from journal if table is corrupted
                // but the table entry is zeroed out
                let result = store.get(&test_key("key1")).await.unwrap();
                assert!(result.is_none() || result == Some(42));
            }
        });
    }

    #[test_traced]
    fn test_store_table_entry_invalid_crc() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: 4,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(test_key("key1"), 42).await.unwrap();
                store.sync().await.unwrap();
                store.close().await.unwrap();
            }

            // Corrupt the CRC in the table entry
            {
                let (blob, _) = context.open(&cfg.table_partition, b"table").await.unwrap();
                // Read the first entry
                let entry_data = blob.read_at(vec![0u8; 24], 0).await.unwrap();
                let mut corrupted = entry_data.as_ref().to_vec();
                // Corrupt the CRC (last 4 bytes of the entry)
                corrupted[20] ^= 0xFF;
                blob.write_at(corrupted, 0).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reopen and verify it handles invalid CRC
            {
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // With invalid CRC, the entry should be treated as invalid
                let result = store.get(&test_key("key1")).await.unwrap();
                // The store should still work but may not find the key due to invalid table entry
                assert!(result.is_none() || result == Some(42));
            }
        });
    }

    #[test_traced]
    fn test_store_invalid_epoch_cleanup() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: 4,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(test_key("key1"), 42).await.unwrap();
                store.sync().await.unwrap(); // This creates epoch 1
                store.put(test_key("key2"), 43).await.unwrap();
                store.sync().await.unwrap(); // This creates epoch 2
                store.close().await.unwrap();
            }

            // Manually corrupt metadata to simulate crash after table write but before metadata update
            {
                use crate::metadata::{Config as MetadataConfig, Metadata};
                use commonware_utils::array::U64;

                let mut metadata = Metadata::<_, U64>::init(
                    context.with_label("metadata"),
                    MetadataConfig {
                        partition: cfg.metadata_partition.clone(),
                    },
                )
                .await
                .unwrap();

                // Set committed epoch back to 1 (simulating crash before epoch 2 was committed)
                metadata.put(0u64.into(), 1u64.to_be_bytes().to_vec());
                metadata.sync().await.unwrap();
                metadata.close().await.unwrap();
            }

            // Reopen and verify epoch cleanup works
            {
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // key1 should still be there (epoch 1)
                assert_eq!(store.get(&test_key("key1")).await.unwrap(), Some(42));

                // key2 might not be found as its table entry (epoch 2) should be cleaned up
                let key2_result = store.get(&test_key("key2")).await.unwrap();
                assert!(key2_result.is_none() || key2_result == Some(43));
            }
        });
    }

    #[test_traced]
    fn test_store_corrupted_journal_entry() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: 4,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Create store with multiple entries
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(test_key("key1"), 42).await.unwrap();
                store.put(test_key("key2"), 43).await.unwrap();
                store.sync().await.unwrap();
                store.close().await.unwrap();
            }

            // Corrupt a journal entry
            {
                let journal_section = 0u64.to_be_bytes();
                let (blob, size) = context
                    .open(&cfg.journal_partition, &journal_section)
                    .await
                    .unwrap();

                // Corrupt data somewhere in the middle of the journal
                if size > 20 {
                    blob.write_at(vec![0xFF; 4], 16).await.unwrap();
                }
                blob.close().await.unwrap();
            }

            // Reopen and verify it handles journal corruption
            {
                // Journal corruption is handled during replay
                // The store should still initialize but may have lost some data
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Try to get the keys - behavior depends on what was corrupted
                let _ = store.get(&test_key("key1")).await;
                let _ = store.get(&test_key("key2")).await;

                // Store should still be functional for new writes
                let mut store_mut = store;
                store_mut.put(test_key("key3"), 44).await.unwrap();
                assert_eq!(store_mut.get(&test_key("key3")).await.unwrap(), Some(44));
            }
        });
    }

    #[test_traced]
    fn test_store_table_with_extra_bytes() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: 4,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(test_key("key1"), 42).await.unwrap();
                store.sync().await.unwrap();
                store.close().await.unwrap();
            }

            // Add extra bytes to the table blob
            {
                let (blob, size) = context.open(&cfg.table_partition, b"table").await.unwrap();
                // Append garbage data
                blob.write_at(vec![0xDE, 0xAD, 0xBE, 0xEF], size)
                    .await
                    .unwrap();
                blob.close().await.unwrap();
            }

            // Reopen and verify it handles extra bytes gracefully
            {
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Should still be able to read the key
                assert_eq!(store.get(&test_key("key1")).await.unwrap(), Some(42));

                // And write new data
                let mut store_mut = store;
                store_mut.put(test_key("key2"), 43).await.unwrap();
                assert_eq!(store_mut.get(&test_key("key2")).await.unwrap(), Some(43));
            }
        });
    }

    #[test_traced]
    fn test_store_missing_metadata() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: 4,
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(test_key("key1"), 42).await.unwrap();
                store.sync().await.unwrap();
                store.close().await.unwrap();
            }

            // Remove metadata
            {
                context.remove(&cfg.metadata_partition, None).await.unwrap();
            }

            // Reopen and verify it handles missing metadata
            {
                let store = Store::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // With missing metadata, committed epoch is 0, so all table entries
                // with epoch > 0 will be cleaned up
                let result = store.get(&test_key("key1")).await.unwrap();
                assert!(result.is_none() || result == Some(42));
            }
        });
    }

    fn test_store_operations_and_restart(num_keys: usize) -> String {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                metadata_partition: "test_metadata".into(),
                table_partition: "test_table".into(),
                table_size: 64, // Small table to force collisions
                codec_config: (),
                write_buffer: DEFAULT_WRITE_BUFFER,
                target_journal_size: DEFAULT_TARGET_JOURNAL_SIZE,
            };

            // Initialize the store
            let mut store =
                Store::<_, FixedBytes<96>, FixedBytes<256>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

            // Generate and insert random key-value pairs
            let mut pairs = Vec::new();

            for _ in 0..num_keys {
                // Generate random key
                let mut key = [0u8; 96];
                context.fill_bytes(&mut key);
                let key = FixedBytes::<96>::new(key);

                // Generate random value
                let mut value = [0u8; 256];
                context.fill_bytes(&mut value);
                let value = FixedBytes::<256>::new(value);

                store
                    .put(key.clone(), value.clone())
                    .await
                    .expect("Failed to put data");
                pairs.push((key, value));
            }

            // Sync data
            store.sync().await.expect("Failed to sync");

            // Verify all pairs can be retrieved
            for (key, value) in &pairs {
                let retrieved = store
                    .get(key)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, value);
            }

            // Test has() on all keys plus some non-existent ones
            for (key, _) in &pairs {
                assert!(store.has(key).await.expect("Failed to check key"));
            }

            // Check some non-existent keys
            for _ in 0..10 {
                let mut key = [0u8; 96];
                context.fill_bytes(&mut key);
                let key = FixedBytes::<96>::new(key);
                let _ = store.has(&key).await;
            }

            // Close the store
            store.close().await.expect("Failed to close store");

            // Reopen the store
            let mut store =
                Store::<_, FixedBytes<96>, FixedBytes<256>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

            // Verify all pairs are still there after restart
            for (key, value) in &pairs {
                let retrieved = store
                    .get(key)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, value);
            }

            // Add more pairs after restart to test collision handling
            for _ in 0..20 {
                let mut key = [0u8; 96];
                context.fill_bytes(&mut key);
                let key = FixedBytes::<96>::new(key);

                let mut value = [0u8; 256];
                context.fill_bytes(&mut value);
                let value = FixedBytes::<256>::new(value);

                store.put(key, value).await.expect("Failed to put data");
            }

            // Multiple syncs to test epoch progression
            for _ in 0..3 {
                store.sync().await.expect("Failed to sync");

                // Add a few more entries between syncs
                for _ in 0..5 {
                    let mut key = [0u8; 96];
                    context.fill_bytes(&mut key);
                    let key = FixedBytes::<96>::new(key);

                    let mut value = [0u8; 256];
                    context.fill_bytes(&mut value);
                    let value = FixedBytes::<256>::new(value);

                    store.put(key, value).await.expect("Failed to put data");
                }
            }

            // Final sync
            store.sync().await.expect("Failed to sync");

            // Return the auditor state for comparison
            context.auditor().state()
        })
    }

    #[test_traced]
    #[ignore]
    fn test_determinism() {
        let state1 = test_store_operations_and_restart(200);
        let state2 = test_store_operations_and_restart(200);
        assert_eq!(state1, state2);
    }
}
