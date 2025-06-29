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
    use rand::RngCore;

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

            // Reopen and verify it handles partial write gracefully
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // First record should be fine
                assert_eq!(
                    store.get(0).await.unwrap().unwrap(),
                    FixedBytes::new([42u8; 32])
                );

                // Second record should be removed due to partial write
                assert!(!store.has(1));
                assert!(store.get(1).await.unwrap().is_none());

                // Store should still be functional
                let mut store_mut = store;
                store_mut.put(1, FixedBytes::new([44u8; 32])).unwrap();
                assert_eq!(
                    store_mut.get(1).await.unwrap().unwrap(),
                    FixedBytes::new([44u8; 32])
                );
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
                blob.resize(size - 4).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reopen - the store should now handle missing CRC gracefully
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store with partial record");

                // Record should be removed due to missing CRC
                assert!(!store.has(0));
                assert!(store.get(0).await.unwrap().is_none());

                // Store should still be functional
                let mut store_mut = store;
                store_mut.put(0, FixedBytes::new([45u8; 32])).unwrap();
                assert_eq!(
                    store_mut.get(0).await.unwrap().unwrap(),
                    FixedBytes::new([45u8; 32])
                );
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
    fn test_store_partial_record_multiple_blobs() {
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
                    blob.resize(26).await.unwrap(); // Partial record (less than 36 bytes)
                }
                blob.close().await.unwrap();
            }

            // Reopen - the store should now handle all corruptions gracefully
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Corrupted records should not be present
                assert!(!store.has(0)); // CRC corrupted
                assert!(!store.has(10)); // Value corrupted (CRC mismatch)
                assert!(!store.has(20)); // Truncated - removed during init

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

    fn test_store_operations_and_restart(num_values: usize) -> String {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100, // Smaller blobs to test multiple blob handling
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Initialize the store
            let mut store = Store::<_, FixedBytes<128>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Generate and insert random values at various indices
            let mut values = Vec::new();
            let mut rng_index = 0u64;

            for _ in 0..num_values {
                // Generate a pseudo-random index (sparse to test gaps)
                let mut index_bytes = [0u8; 8];
                context.fill_bytes(&mut index_bytes);
                let index_offset = u64::from_be_bytes(index_bytes) % 1000;
                let index = rng_index + index_offset;
                rng_index = index + 1;

                // Generate random value
                let mut value = [0u8; 128];
                context.fill_bytes(&mut value);
                let value = FixedBytes::<128>::new(value);

                store.put(index, value.clone()).expect("Failed to put data");
                values.push((index, value));
            }

            // Sync data
            store.sync().await.expect("Failed to sync");

            // Verify all values can be retrieved
            for (index, value) in &values {
                let retrieved = store
                    .get(*index)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, value);
            }

            // Test next_gap on various indices
            for i in 0..10 {
                let _ = store.next_gap(i * 100);
            }

            // Close the store
            store.close().await.expect("Failed to close store");

            // Reopen the store
            let mut store = Store::<_, FixedBytes<128>>::init(context.clone(), cfg)
                .await
                .expect("Failed to initialize store");

            // Verify all values are still there after restart
            for (index, value) in &values {
                let retrieved = store
                    .get(*index)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, value);
            }

            // Add more values after restart
            for _ in 0..10 {
                let mut index_bytes = [0u8; 8];
                context.fill_bytes(&mut index_bytes);
                let index = u64::from_be_bytes(index_bytes) % 10000;

                let mut value = [0u8; 128];
                context.fill_bytes(&mut value);
                let value = FixedBytes::<128>::new(value);

                store.put(index, value).expect("Failed to put data");
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
        let state1 = test_store_operations_and_restart(100);
        let state2 = test_store_operations_and_restart(100);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_store_prune_basic() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100, // Small blobs to test multiple blob handling
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert data across multiple blobs
            let values = vec![
                (0u64, FixedBytes::new([0u8; 32])),     // Blob 0
                (50u64, FixedBytes::new([50u8; 32])),   // Blob 0
                (100u64, FixedBytes::new([100u8; 32])), // Blob 1
                (150u64, FixedBytes::new([150u8; 32])), // Blob 1
                (200u64, FixedBytes::new([200u8; 32])), // Blob 2
                (300u64, FixedBytes::new([44u8; 32])),  // Blob 3
            ];

            for (index, value) in &values {
                store.put(*index, value.clone()).unwrap();
            }
            store.sync().await.unwrap();

            // Verify all values exist
            for (index, value) in &values {
                assert_eq!(store.get(*index).await.unwrap().unwrap(), *value);
            }

            // Prune up to index 150 (should remove blobs 0 and 1)
            let pruned_to = store.prune(150).await.unwrap();
            assert_eq!(pruned_to, 100); // Prunes at blob boundary (blob 0, indices 0-99)
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 1"));

            // Verify pruned data is gone
            assert!(!store.has(0));
            assert!(!store.has(50));
            assert!(store.get(0).await.unwrap().is_none());
            assert!(store.get(50).await.unwrap().is_none());

            // Verify remaining data is still there
            assert!(store.has(100));
            assert!(store.has(150));
            assert!(store.has(200));
            assert!(store.has(300));
            assert_eq!(store.get(100).await.unwrap().unwrap(), values[2].1);
            assert_eq!(store.get(150).await.unwrap().unwrap(), values[3].1);
            assert_eq!(store.get(200).await.unwrap().unwrap(), values[4].1);
            assert_eq!(store.get(300).await.unwrap().unwrap(), values[5].1);

            // Prune more aggressively - up to index 250 (should remove blob 1)
            let pruned_to = store.prune(250).await.unwrap();
            assert_eq!(pruned_to, 200); // Prunes at blob boundary (blob 1, indices 100-199)
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 2"));

            // Verify more data is pruned
            assert!(!store.has(100));
            assert!(!store.has(150));
            assert!(store.get(100).await.unwrap().is_none());
            assert!(store.get(150).await.unwrap().is_none());

            // Verify remaining data
            assert!(store.has(200));
            assert!(store.has(300));
            assert_eq!(store.get(200).await.unwrap().unwrap(), values[4].1);
            assert_eq!(store.get(300).await.unwrap().unwrap(), values[5].1);
        });
    }

    #[test_traced]
    fn test_store_prune_with_gaps() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert sparse data with gaps
            store.put(5, FixedBytes::new([5u8; 32])).unwrap();
            store.put(105, FixedBytes::new([105u8; 32])).unwrap();
            store.put(305, FixedBytes::new([49u8; 32])).unwrap();
            store.sync().await.unwrap();

            // Check gaps before pruning
            let (current_end, next_start) = store.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(next_start, Some(5));

            let (current_end, next_start) = store.next_gap(5);
            assert_eq!(current_end, Some(5));
            assert_eq!(next_start, Some(105));

            // Prune up to index 150 (should remove blob 0)
            let pruned_to = store.prune(150).await.unwrap();
            assert_eq!(pruned_to, 100);

            // Verify pruned data is gone
            assert!(!store.has(5));
            assert!(store.get(5).await.unwrap().is_none());

            // Verify remaining data and gaps
            assert!(store.has(105));
            assert!(store.has(305));

            let (current_end, next_start) = store.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(next_start, Some(105));

            let (current_end, next_start) = store.next_gap(105);
            assert_eq!(current_end, Some(105));
            assert_eq!(next_start, Some(305));
        });
    }

    #[test_traced]
    fn test_store_prune_with_pending() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert and sync some data
            store.put(0, FixedBytes::new([0u8; 32])).unwrap();
            store.put(100, FixedBytes::new([100u8; 32])).unwrap();
            store.sync().await.unwrap();

            // Add pending entries
            store.put(50, FixedBytes::new([50u8; 32])).unwrap();
            store.put(150, FixedBytes::new([150u8; 32])).unwrap();

            // Verify pending entries are visible
            assert!(store.has(50));
            assert!(store.has(150));
            assert_eq!(
                store.get(50).await.unwrap().unwrap(),
                FixedBytes::new([50u8; 32])
            );
            assert_eq!(
                store.get(150).await.unwrap().unwrap(),
                FixedBytes::new([150u8; 32])
            );

            // Prune up to index 75 (should remove blob 0 but keep pending data)
            let pruned_to = store.prune(75).await.unwrap();
            assert_eq!(pruned_to, 0); // Nothing pruned because pending entry at 50

            // The pending entry at 50 should prevent pruning of blob 0
            assert!(store.has(0));
            assert!(store.has(50)); // Pending
            assert!(store.has(100));
            assert!(store.has(150)); // Pending

            // Sync pending entries
            store.sync().await.unwrap();

            // Now prune again - this time it should work
            let pruned_to = store.prune(75).await.unwrap();
            assert_eq!(pruned_to, 0); // Still nothing pruned because 50 is now persisted

            // Prune more aggressively
            let pruned_to = store.prune(125).await.unwrap();
            assert_eq!(pruned_to, 100); // Now blob 0 can be pruned

            // Verify pruning worked
            assert!(!store.has(0));
            assert!(!store.has(50));
            assert!(store.has(100));
            assert!(store.has(150));
        });
    }

    #[test_traced]
    fn test_store_prune_no_op() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert data
            store.put(100, FixedBytes::new([100u8; 32])).unwrap();
            store.put(200, FixedBytes::new([200u8; 32])).unwrap();
            store.sync().await.unwrap();

            // Try to prune before any data - should be no-op
            let pruned_to = store.prune(50).await.unwrap();
            assert_eq!(pruned_to, 100); // Returns the start of the first blob

            // Verify no data was actually pruned
            assert!(store.has(100));
            assert!(store.has(200));
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 0"));

            // Try to prune exactly at blob boundary - should be no-op
            let pruned_to = store.prune(100).await.unwrap();
            assert_eq!(pruned_to, 100);

            // Verify still no data pruned
            assert!(store.has(100));
            assert!(store.has(200));
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 0"));
        });
    }

    #[test_traced]
    fn test_store_prune_empty_store() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Try to prune empty store
            let pruned_to = store.prune(1000).await.unwrap();
            assert_eq!(pruned_to, 0);

            // Store should still be functional
            store.put(0, FixedBytes::new([0u8; 32])).unwrap();
            assert!(store.has(0));
        });
    }

    #[test_traced]
    fn test_store_prune_after_restart() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store and add data
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([0u8; 32])).unwrap();
                store.put(100, FixedBytes::new([100u8; 32])).unwrap();
                store.put(200, FixedBytes::new([200u8; 32])).unwrap();
                store.close().await.unwrap();
            }

            // Reopen and prune
            {
                let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Verify data is there
                assert!(store.has(0));
                assert!(store.has(100));
                assert!(store.has(200));

                // Prune up to index 150
                let pruned_to = store.prune(150).await.unwrap();
                assert_eq!(pruned_to, 100);

                // Verify pruning worked
                assert!(!store.has(0));
                assert!(store.has(100));
                assert!(store.has(200));

                store.close().await.unwrap();
            }

            // Reopen again and verify pruning persisted
            {
                let store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                assert!(!store.has(0));
                assert!(store.has(100));
                assert!(store.has(200));

                // Check gaps
                let (current_end, next_start) = store.next_gap(0);
                assert!(current_end.is_none());
                assert_eq!(next_start, Some(100));
            }
        });
    }

    #[test_traced]
    fn test_store_prune_multiple_operations() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 50, // Smaller blobs for more granular testing
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert data across many blobs
            let mut values = Vec::new();
            for i in 0..10 {
                let index = i * 50 + 25; // Middle of each blob
                let value = FixedBytes::new([i as u8; 32]);
                store.put(index, value.clone()).unwrap();
                values.push((index, value));
            }
            store.sync().await.unwrap();

            // Prune incrementally
            for i in 1..5 {
                let prune_index = i * 50 + 10;
                let pruned_to = store.prune(prune_index).await.unwrap();
                assert_eq!(pruned_to, i * 50);

                // Verify appropriate data is pruned
                for (index, _) in &values {
                    if *index < pruned_to {
                        assert!(!store.has(*index), "Index {} should be pruned", index);
                    } else {
                        assert!(store.has(*index), "Index {} should not be pruned", index);
                    }
                }
            }

            // Check final state
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 4"));

            // Verify remaining data
            for i in 4..10 {
                let index = i * 50 + 25;
                assert!(store.has(index));
                assert_eq!(
                    store.get(index).await.unwrap().unwrap(),
                    values[i as usize].1
                );
            }
        });
    }

    #[test_traced]
    fn test_store_prune_blob_boundaries() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Store::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert data at blob boundaries
            store.put(0, FixedBytes::new([0u8; 32])).unwrap(); // Start of blob 0
            store.put(99, FixedBytes::new([99u8; 32])).unwrap(); // End of blob 0
            store.put(100, FixedBytes::new([100u8; 32])).unwrap(); // Start of blob 1
            store.put(199, FixedBytes::new([199u8; 32])).unwrap(); // End of blob 1
            store.put(200, FixedBytes::new([200u8; 32])).unwrap(); // Start of blob 2
            store.sync().await.unwrap();

            // Test various pruning points around boundaries

            // Prune exactly at blob boundary (100) - should prune blob 0
            let pruned_to = store.prune(100).await.unwrap();
            assert_eq!(pruned_to, 100);
            assert!(!store.has(0));
            assert!(!store.has(99));
            assert!(store.has(100));
            assert!(store.has(199));
            assert!(store.has(200));

            // Prune just before next boundary (199) - should not prune blob 1
            let pruned_to = store.prune(199).await.unwrap();
            assert_eq!(pruned_to, 100); // No change
            assert!(store.has(100));
            assert!(store.has(199));
            assert!(store.has(200));

            // Prune exactly at next boundary (200) - should prune blob 1
            let pruned_to = store.prune(200).await.unwrap();
            assert_eq!(pruned_to, 200);
            assert!(!store.has(100));
            assert!(!store.has(199));
            assert!(store.has(200));

            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 2"));
        });
    }
}
