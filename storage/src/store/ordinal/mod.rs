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
//!     let value1 = FixedBytes::from([1u8; 32]);
//!     let value2 = FixedBytes::from([2u8; 32]);
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
    use commonware_codec::DecodeExt;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics, Runner};
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

            let value = FixedBytes::from([42u8; 32]);

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
                (0u64, FixedBytes::from([0u8; 32])),
                (5u64, FixedBytes::from([5u8; 32])),
                (10u64, FixedBytes::from([10u8; 32])),
                (100u64, FixedBytes::from([100u8; 32])),
                (1000u64, FixedBytes::from([200u8; 32])), // Different blob
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
                (0u64, FixedBytes::from([0u8; 32])),
                (99u64, FixedBytes::from([99u8; 32])), // End of first blob
                (100u64, FixedBytes::from([100u8; 32])), // Start of second blob
                (500u64, FixedBytes::from([200u8; 32])), // Start of sixth blob
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
            store.put(1, FixedBytes::from([1u8; 32])).unwrap();
            store.put(10, FixedBytes::from([10u8; 32])).unwrap();
            store.put(11, FixedBytes::from([11u8; 32])).unwrap();
            store.put(14, FixedBytes::from([14u8; 32])).unwrap();

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
                    (0u64, FixedBytes::from([0u8; 32])),
                    (100u64, FixedBytes::from([100u8; 32])),
                    (1000u64, FixedBytes::from([200u8; 32])),
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
                    (0u64, FixedBytes::from([0u8; 32])),
                    (100u64, FixedBytes::from([100u8; 32])),
                    (1000u64, FixedBytes::from([200u8; 32])),
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

                store.put(0, FixedBytes::from([42u8; 32])).unwrap();
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

                // Reading corrupted record should fail
                let result = store.get(0).await;
                assert!(matches!(result, Err(Error::InvalidRecord(0))));

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

                store.put(0, FixedBytes::from([0u8; 32])).unwrap();
                store.put(1000, FixedBytes::from([100u8; 32])).unwrap();

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
}
