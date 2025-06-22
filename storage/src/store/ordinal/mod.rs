//! A persistent, ordinal index that maps contiguous indices to fixed-size values.
//!
//! [Store] maintains a flat file where each record contains a fixed-size value and CRC checksum.
//! The file position directly corresponds to the index, eliminating the need for complex indexing
//! structures. This makes it ideal for storing sequential data where indices are contiguous or
//! mostly contiguous.
//!
//! # Design
//!
//! [Store] uses a simple flat file approach:
//! - Each record: `[V][crc32(V)]` where V is a fixed-size value
//! - Index N is at file offset: `N * RECORD_SIZE`
//! - Records are organized into blobs for better file management
//! - An in-memory RMap tracks which indices have been written
//!
//! # File Organization
//!
//! Records are grouped into blobs to avoid having too many files:
//! ```text
//! Blob 0: indices 0-999 (items_per_blob = 1000)
//! Blob 1: indices 1000-1999
//! ...
//! ```
//!
//! Each blob is named with the starting index encoded as big-endian bytes.
//!
//! # Format
//!
//! Each record in a blob:
//! ```text
//! +-------------------+--------+
//! | Value (fixed size)| CRC32  |
//! +-------------------+--------+
//! |     V bytes       | 4 bytes|
//! +-------------------+--------+
//! ```
//!
//! # Memory Usage
//!
//! The store maintains minimal in-memory state:
//! - An RMap for tracking which indices exist (for efficient `has` and `next_gap` queries)
//! - A map of open blob handles
//! - Pending writes buffer (cleared on sync)
//!
//! # Performance Characteristics
//!
//! - **Writes**: O(1) - direct offset calculation
//! - **Reads**: O(1) - direct offset calculation
//! - **Has**: O(1) - in-memory RMap lookup
//! - **Next Gap**: O(log n) - RMap range query
//! - **Restart**: O(n) where n is the number of existing records (to rebuild RMap)
//!
//! # Crash Consistency
//!
//! Each record includes a CRC32 checksum. On restart, the store validates all records
//! and rebuilds the in-memory RMap. Invalid records (corrupted or empty) are detected
//! and excluded from the index.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_storage::store::ordinal::{Store, Config};
//! use commonware_utils::array::FixedBytes;
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a store for 32-byte values
//!     let cfg = Config {
//!         partition: "ordinal_store".into(),
//!         items_per_blob: 10000,
//!         write_buffer: 4096,
//!         replay_buffer: 1024 * 1024,
//!     };
//!     let mut store = Store::<_, FixedBytes<32>>::init(context, cfg).await.unwrap();
//!
//!     // Put values at specific indices
//!     let value1 = FixedBytes::new([1u8; 32]);
//!     let value2 = FixedBytes::new([2u8; 32]);
//!     store.put(0, value1).unwrap();
//!     store.put(5, value2).unwrap();
//!
//!     // Sync to disk
//!     store.sync().await.unwrap();
//!
//!     // Check for gaps
//!     let (current_end, next_start) = store.next_gap(0);
//!     assert_eq!(current_end, Some(0));
//!     assert_eq!(next_start, Some(5));
//!
//!     // Close the store
//!     store.close().await.unwrap();
//! });
//! ```

mod storage;

pub use storage::Store;
use thiserror::Error;

/// Errors that can occur when interacting with the [Store].
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("invalid record: {0}")]
    InvalidRecord(u64),
}

/// Configuration for [Store] storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware-runtime::Storage` partition to use for storing the index.
    pub partition: String,

    /// The maximum number of items to store in each index blob.
    pub items_per_blob: u64,

    /// The size of the write buffer to use when writing to the index.
    pub write_buffer: usize,

    /// The size of the read buffer to use on restart.
    pub replay_buffer: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::array::FixedBytes;

    const DEFAULT_ITEMS_PER_BLOB: u64 = 1000;
    const DEFAULT_WRITE_BUFFER: usize = 4096;
    const DEFAULT_REPLAY_BUFFER: usize = 1024 * 1024;

    #[test_traced]
    fn test_store_put_get() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };
            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            let value = FixedBytes::new([42u8; 32]);

            // Check index doesn't exist
            assert!(!store.has(0));

            // Put the value at index 0
            store.put(0, value.clone()).expect("Failed to put data");

            // Check index exists
            assert!(store.has(0));

            // Get the value back (before sync)
            let retrieved = store
                .get(0)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, value);

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("gets_total 1"), "{}", buffer);
            assert!(buffer.contains("puts_total 1"), "{}", buffer);

            // Force a sync
            store.sync().await.expect("Failed to sync data");

            // Get the value back (after sync)
            let retrieved = store
                .get(0)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, value);
        });
    }

    #[test_traced]
    fn test_store_multiple_indices() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };
            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert multiple values at different indices
            let indices = vec![
                (0u64, FixedBytes::new([0u8; 32])),
                (5u64, FixedBytes::new([5u8; 32])),
                (10u64, FixedBytes::new([10u8; 32])),
                (100u64, FixedBytes::new([100u8; 32])),
                (1000u64, FixedBytes::new([200u8; 32])), // Different blob
            ];

            for (index, value) in &indices {
                store
                    .put(*index, value.clone())
                    .expect("Failed to put data");
            }

            // Sync to disk
            store.sync().await.expect("Failed to sync");

            // Retrieve all values and verify
            for (index, value) in &indices {
                let retrieved = store
                    .get(*index)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, value);
            }
        });
    }

    #[test_traced]
    fn test_store_sparse_indices() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100, // Smaller blobs for testing
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };
            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert sparse values
            let indices = vec![
                (0u64, FixedBytes::new([0u8; 32])),
                (99u64, FixedBytes::new([99u8; 32])), // End of first blob
                (100u64, FixedBytes::new([100u8; 32])), // Start of second blob
                (500u64, FixedBytes::new([200u8; 32])), // Start of sixth blob
            ];

            for (index, value) in &indices {
                store
                    .put(*index, value.clone())
                    .expect("Failed to put data");
            }

            // Check that intermediate indices don't exist
            assert!(!store.has(1));
            assert!(!store.has(50));
            assert!(!store.has(101));
            assert!(!store.has(499));

            // Sync and verify
            store.sync().await.expect("Failed to sync");

            for (index, value) in &indices {
                let retrieved = store
                    .get(*index)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, value);
            }
        });
    }

    #[test_traced]
    fn test_store_next_gap() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };
            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert values with gaps
            store.put(1, FixedBytes::new([1u8; 32])).unwrap();
            store.put(10, FixedBytes::new([10u8; 32])).unwrap();
            store.put(11, FixedBytes::new([11u8; 32])).unwrap();
            store.put(14, FixedBytes::new([14u8; 32])).unwrap();

            // Check gaps
            let (current_end, start_next) = store.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(1));

            let (current_end, start_next) = store.next_gap(1);
            assert_eq!(current_end, Some(1));
            assert_eq!(start_next, Some(10));

            let (current_end, start_next) = store.next_gap(10);
            assert_eq!(current_end, Some(11));
            assert_eq!(start_next, Some(14));

            let (current_end, start_next) = store.next_gap(11);
            assert_eq!(current_end, Some(11));
            assert_eq!(start_next, Some(14));

            let (current_end, start_next) = store.next_gap(12);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(14));

            let (current_end, start_next) = store.next_gap(14);
            assert_eq!(current_end, Some(14));
            assert!(start_next.is_none());
        });
    }

    #[test_traced]
    fn test_store_restart() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Insert data and close
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                let values = vec![
                    (0u64, FixedBytes::new([0u8; 32])),
                    (100u64, FixedBytes::new([100u8; 32])),
                    (1000u64, FixedBytes::new([200u8; 32])),
                ];

                for (index, value) in &values {
                    store
                        .put(*index, value.clone())
                        .expect("Failed to put data");
                }

                store.close().await.expect("Failed to close store");
            }

            // Reopen and verify data persisted
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                let values = vec![
                    (0u64, FixedBytes::new([0u8; 32])),
                    (100u64, FixedBytes::new([100u8; 32])),
                    (1000u64, FixedBytes::new([200u8; 32])),
                ];

                for (index, value) in &values {
                    let retrieved = store
                        .get(*index)
                        .await
                        .expect("Failed to get data")
                        .expect("Data not found");
                    assert_eq!(&retrieved, value);
                }

                // Check gaps are preserved
                let (current_end, start_next) = store.next_gap(0);
                assert_eq!(current_end, Some(0));
                assert_eq!(start_next, Some(100));
            }
        });
    }

    #[test_traced]
    fn test_store_invalid_record() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([42u8; 32])).unwrap();
                store.close().await.expect("Failed to close store");
            }

            // Corrupt the data
            {
                let (blob, _) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                // Corrupt the CRC by changing a byte
                blob.write_at(vec![0xFF], 32).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reopen and try to read corrupted data
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Reading corrupt record will return empty
                let result = store.get(0).await.unwrap();
                assert!(result.is_none());

                // The index should not be in the intervals after restart with corrupted data
                assert!(!store.has(0));
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
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };
            let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Attempt to get an index that doesn't exist
            let retrieved = store.get(999).await.expect("Failed to get data");
            assert!(retrieved.is_none());

            // Check has returns false
            assert!(!store.has(999));
        });
    }

    #[test_traced]
    fn test_store_destroy() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([0u8; 32])).unwrap();
                store.put(1000, FixedBytes::new([100u8; 32])).unwrap();

                // Destroy the store
                store.destroy().await.expect("Failed to destroy store");
            }

            // Try to create a new store - it should be empty
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Should not find any data
                assert!(store.get(0).await.unwrap().is_none());
                assert!(store.get(1000).await.unwrap().is_none());
                assert!(!store.has(0));
                assert!(!store.has(1000));
            }
        });
    }

    #[test_traced]
    fn test_store_partial_record_write() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([42u8; 32])).unwrap();
                store.put(1, FixedBytes::new([43u8; 32])).unwrap();
                store.close().await.expect("Failed to close store");
            }

            // Corrupt by writing partial record (only value, no CRC)
            {
                let (blob, _) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                // Overwrite second record with partial data (32 bytes instead of 36)
                blob.write_at(vec![0xFF; 32], 36).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reopen and verify it handles partial write
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // First record should be fine
                assert_eq!(
                    store.get(0).await.unwrap().unwrap(),
                    FixedBytes::new([42u8; 32])
                );

                // Second record should be detected as invalid during restart
                assert!(!store.has(1));
                assert!(store.get(1).await.unwrap().is_none());
            }
        });
    }

    #[test_traced]
    fn test_store_missing_crc() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([42u8; 32])).unwrap();
                store.close().await.expect("Failed to close store");
            }

            // Truncate the blob to remove CRC
            {
                let (blob, size) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                // Truncate to remove last 4 bytes (CRC)
                blob.truncate(size - 4).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reopen - the store should fail to initialize due to missing CRC
            {
                let result = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone()).await;

                // The current implementation doesn't handle partial records gracefully
                assert!(result.is_err());
            }
        });
    }

    #[test_traced]
    fn test_store_corrupted_value() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([42u8; 32])).unwrap();
                store.put(1, FixedBytes::new([43u8; 32])).unwrap();
                store.close().await.expect("Failed to close store");
            }

            // Corrupt the value portion of a record
            {
                let (blob, _) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                // Corrupt some bytes in the value of the first record
                blob.write_at(vec![0xFF, 0xFF, 0xFF, 0xFF], 10)
                    .await
                    .unwrap();
                blob.close().await.unwrap();
            }

            // Reopen and verify it detects corruption
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // First record should be detected as corrupted (CRC mismatch)
                assert!(!store.has(0));

                // Second record should still be valid
                assert!(store.has(1));
                assert_eq!(
                    store.get(1).await.unwrap().unwrap(),
                    FixedBytes::new([43u8; 32])
                );
            }
        });
    }

    #[test_traced]
    fn test_store_crc_corruptions() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 10, // Small blob size for testing
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data across multiple blobs
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Add values across 2 blobs
                store.put(0, FixedBytes::new([0u8; 32])).unwrap();
                store.put(5, FixedBytes::new([5u8; 32])).unwrap();
                store.put(10, FixedBytes::new([10u8; 32])).unwrap();
                store.put(15, FixedBytes::new([15u8; 32])).unwrap();
                store.close().await.expect("Failed to close store");
            }

            // Corrupt CRCs in different blobs
            {
                // Corrupt CRC in first blob
                let (blob, _) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                blob.write_at(vec![0xFF], 32).await.unwrap(); // Corrupt CRC of index 0
                blob.close().await.unwrap();

                // Corrupt value in second blob (which will invalidate CRC)
                let (blob, _) = context
                    .open("test_ordinal", &1u64.to_be_bytes())
                    .await
                    .unwrap();
                blob.write_at(vec![0xFF; 4], 5).await.unwrap(); // Corrupt value of index 10
                blob.close().await.unwrap();
            }

            // Reopen and verify handling of CRC corruptions
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Corrupted records should not be present
                assert!(!store.has(0)); // CRC corrupted
                assert!(!store.has(10)); // Value corrupted (CRC mismatch)

                // Valid records should still be accessible
                assert!(store.has(5));
                assert!(store.has(15));
                assert_eq!(
                    store.get(5).await.unwrap().unwrap(),
                    FixedBytes::new([5u8; 32])
                );
                assert_eq!(
                    store.get(15).await.unwrap().unwrap(),
                    FixedBytes::new([15u8; 32])
                );
            }
        });
    }

    #[test_traced]
    fn test_store_partial_record_fails_init() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 10, // Small blob size for testing
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data across multiple blobs
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Add values across 3 blobs
                store.put(0, FixedBytes::new([0u8; 32])).unwrap();
                store.put(5, FixedBytes::new([5u8; 32])).unwrap();
                store.put(10, FixedBytes::new([10u8; 32])).unwrap();
                store.put(15, FixedBytes::new([15u8; 32])).unwrap();
                store.put(20, FixedBytes::new([20u8; 32])).unwrap();
                store.close().await.expect("Failed to close store");
            }

            // Corrupt multiple records in different ways
            {
                // Corrupt CRC in first blob
                let (blob, _) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                blob.write_at(vec![0xFF], 32).await.unwrap(); // Corrupt CRC of index 0
                blob.close().await.unwrap();

                // Corrupt value in second blob
                // Index 10 with items_per_blob=10 means section 1
                let (blob, _) = context
                    .open("test_ordinal", &1u64.to_be_bytes())
                    .await
                    .unwrap();
                blob.write_at(vec![0xFF; 4], 5).await.unwrap(); // Corrupt value of index 10
                blob.close().await.unwrap();

                // Truncate third blob to create partial record
                // Index 20 with items_per_blob=10 means section 2
                let (blob, size) = context
                    .open("test_ordinal", &2u64.to_be_bytes())
                    .await
                    .unwrap();
                // Truncate to create partial record
                if size >= 36 {
                    blob.truncate(26).await.unwrap(); // Partial record (less than 36 bytes)
                }
                blob.close().await.unwrap();
            }

            // Reopen - the store should fail to initialize due to partial record
            {
                let result = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone()).await;

                // The current implementation doesn't handle partial records gracefully
                // during initialization, so it will fail
                assert!(result.is_err());

                // This is actually exposing a limitation in the ordinal store's
                // corruption handling compared to the journal implementation
            }
        });
    }

    #[test_traced]
    fn test_store_extra_bytes_in_blob() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([42u8; 32])).unwrap();
                store.put(1, FixedBytes::new([43u8; 32])).unwrap();
                store.close().await.expect("Failed to close store");
            }

            // Add extra bytes at the end of blob
            {
                let (blob, size) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                // Add garbage data that forms a complete but invalid record
                // This avoids partial record issues
                let mut garbage = vec![0xFF; 32]; // Invalid value
                let invalid_crc = 0xDEADBEEFu32;
                garbage.extend_from_slice(&invalid_crc.to_be_bytes());
                assert_eq!(garbage.len(), 36); // Full record size
                blob.write_at(garbage, size).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reopen and verify it handles extra bytes
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Original records should still be valid
                assert!(store.has(0));
                assert!(store.has(1));
                assert_eq!(
                    store.get(0).await.unwrap().unwrap(),
                    FixedBytes::new([42u8; 32])
                );
                assert_eq!(
                    store.get(1).await.unwrap().unwrap(),
                    FixedBytes::new([43u8; 32])
                );

                // Store should still be functional
                let mut store_mut = store;
                store_mut.put(2, FixedBytes::new([44u8; 32])).unwrap();
                assert_eq!(
                    store_mut.get(2).await.unwrap().unwrap(),
                    FixedBytes::new([44u8; 32])
                );
            }
        });
    }

    #[test_traced]
    fn test_store_corruption_at_blob_boundary() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 10, // Small size to test boundaries
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data at blob boundaries
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Add values at boundaries
                store.put(9, FixedBytes::new([9u8; 32])).unwrap(); // Last in first blob
                store.put(10, FixedBytes::new([10u8; 32])).unwrap(); // First in second blob
                store.put(19, FixedBytes::new([19u8; 32])).unwrap(); // Last in second blob
                store.put(20, FixedBytes::new([20u8; 32])).unwrap(); // First in third blob
                store.close().await.expect("Failed to close store");
            }

            // Corrupt records at boundaries
            {
                // Corrupt last record of first blob
                let (blob, _) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                let offset = 9 * 36; // 9th index * record size
                blob.write_at(vec![0xFF; 4], offset + 10).await.unwrap();
                blob.close().await.unwrap();

                // Corrupt first record of third blob
                // Index 20 with items_per_blob=10 means section 2
                let (blob, _) = context
                    .open("test_ordinal", &2u64.to_be_bytes())
                    .await
                    .unwrap();
                blob.write_at(vec![0xFF; 4], 10).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reopen and verify boundary corruption handling
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Corrupted boundary records should be invalid
                assert!(!store.has(9)); // Last of first blob
                assert!(!store.has(20)); // First of third blob

                // Records in clean blobs should be valid
                assert!(store.has(10));
                assert!(store.has(19));
                assert_eq!(
                    store.get(10).await.unwrap().unwrap(),
                    FixedBytes::new([10u8; 32])
                );
                assert_eq!(
                    store.get(19).await.unwrap().unwrap(),
                    FixedBytes::new([19u8; 32])
                );
            }
        });
    }

    #[test_traced]
    fn test_store_zero_filled_records() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: DEFAULT_ITEMS_PER_BLOB,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create blob with zero-filled space
            {
                let (blob, _) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();

                // Write zeros for several record positions
                let zeros = vec![0u8; 36 * 5]; // 5 records worth of zeros
                blob.write_at(zeros, 0).await.unwrap();

                // Write a valid record after the zeros
                let mut valid_record = vec![44u8; 32];
                let crc = crc32fast::hash(&valid_record);
                valid_record.extend_from_slice(&crc.to_be_bytes());
                blob.write_at(valid_record, 36 * 5).await.unwrap();

                blob.close().await.unwrap();
            }

            // Initialize store and verify it handles zero-filled records
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Zero-filled positions should not be considered valid
                for i in 0..5 {
                    assert!(!store.has(i));
                }

                // The valid record should be found
                assert!(store.has(5));
                assert_eq!(
                    store.get(5).await.unwrap().unwrap(),
                    FixedBytes::new([44u8; 32])
                );
            }
        });
    }
}
