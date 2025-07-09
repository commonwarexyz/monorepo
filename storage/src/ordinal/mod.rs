//! A persistent index that maps sparse indices to [commonware_utils::Array]s.
//!
//! [Ordinal] is a collection of [commonware_runtime::Blob]s containing ordered records of fixed size.
//! Because records are fixed size, file position corresponds directly to index. Unlike
//! [crate::journal::fixed::Journal], [Ordinal] supports out-of-order insertion.
//!
//! # Design
//!
//! [Ordinal] is a collection of [commonware_runtime::Blob]s where:
//! - Each record: `[V][crc32(V)]` where V is an [commonware_utils::Array]
//! - Index N is at file offset: `N * RECORD_SIZE`
//! - A [crate::rmap::RMap] tracks which indices have been written (and which are missing)
//!
//! # File Organization
//!
//! Records are grouped into blobs to avoid having too many files:
//!
//! ```text
//! Blob 0: indices 0-999
//! Blob 1: indices 1000-1999
//! ...
//! ```
//!
//! # Format
//!
//! [Ordinal] stores values in the following format:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |12 |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |          Value (Fixed Size)       |     CRC32     |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! # Performance Characteristics
//!
//! - **Writes**: O(1) - direct offset calculation
//! - **Reads**: O(1) - direct offset calculation
//! - **Has**: O(1) - in-memory lookup (via [crate::rmap::RMap])
//! - **Next Gap**: O(log n) - in-memory range query (via [crate::rmap::RMap])
//! - **Restart**: O(n) where n is the number of existing records (to rebuild [crate::rmap::RMap])
//!
//! # Atomicity
//!
//! [Ordinal] eagerly writes all new data to [commonware_runtime::Blob]s. New data, however, is not
//! synced until [Ordinal::sync] is called. As a result, data is not guaranteed to be atomically
//! persisted (i.e. shutdown before [Ordinal::sync] may lead to some writes being lost).
//!
//! _If you want atomicity for sparse writes, pair [commonware_utils::BitVec] and
//! [crate::metadata::Metadata] with [Ordinal] (use bits to indicate which items have been atomically
//! written)._
//!
//! # Recovery
//!
//! On restart, [Ordinal] validates all records using their CRC32 and rebuilds the in-memory
//! [crate::rmap::RMap]. Invalid records (corrupted or empty) are excluded from the rebuilt index.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_storage::ordinal::{Ordinal, Config};
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
//!     let mut store = Ordinal::<_, FixedBytes<32>>::init(context, cfg).await.unwrap();
//!
//!     // Put values at specific indices
//!     let value1 = FixedBytes::new([1u8; 32]);
//!     let value2 = FixedBytes::new([2u8; 32]);
//!     store.put(0, value1).await.unwrap();
//!     store.put(5, value2).await.unwrap();
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

pub use storage::Ordinal;
use thiserror::Error;

/// Errors that can occur when interacting with the [Ordinal].
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
    #[error("missing record at {0}")]
    MissingRecord(u64),
}

/// Configuration for [Ordinal] storage.
#[derive(Clone)]
pub struct Config {
    /// The [commonware_runtime::Storage] partition to use for storing the index.
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
    use commonware_utils::{array::FixedBytes, BitVec};
    use rand::RngCore;
    use std::collections::BTreeMap;

    const DEFAULT_ITEMS_PER_BLOB: u64 = 1000;
    const DEFAULT_WRITE_BUFFER: usize = 4096;
    const DEFAULT_REPLAY_BUFFER: usize = 1024 * 1024;

    #[test_traced]
    fn test_put_get() {
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
            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            let value = FixedBytes::new([42u8; 32]);

            // Check index doesn't exist
            assert!(!store.has(0));

            // Put the value at index 0
            store
                .put(0, value.clone())
                .await
                .expect("Failed to put data");

            // Check index exists
            assert!(store.has(0));

            // Get the value back (before sync)
            let retrieved = store
                .get(0)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, value);

            // Force a sync
            store.sync().await.expect("Failed to sync data");

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("gets_total 1"), "{}", buffer);
            assert!(buffer.contains("puts_total 1"), "{}", buffer);
            assert!(buffer.contains("has_total 2"), "{}", buffer);
            assert!(buffer.contains("syncs_total 1"), "{}", buffer);
            assert!(buffer.contains("pruned_total 0"), "{}", buffer);

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
    fn test_multiple_indices() {
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
            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
                    .await
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
    fn test_sparse_indices() {
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
            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
                    .await
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
    fn test_next_gap() {
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
            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert values with gaps
            store.put(1, FixedBytes::new([1u8; 32])).await.unwrap();
            store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
            store.put(11, FixedBytes::new([11u8; 32])).await.unwrap();
            store.put(14, FixedBytes::new([14u8; 32])).await.unwrap();

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
    fn test_restart() {
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
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
                        .await
                        .expect("Failed to put data");
                }

                store.close().await.expect("Failed to close store");
            }

            // Reopen and verify data persisted
            {
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
    fn test_invalid_record() {
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
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store
                    .put(0, FixedBytes::new([42u8; 32]))
                    .await
                    .expect("Failed to put data");
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
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
    fn test_get_nonexistent() {
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
            let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
    fn test_destroy() {
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
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store
                    .put(0, FixedBytes::new([0u8; 32]))
                    .await
                    .expect("Failed to put data");
                store
                    .put(1000, FixedBytes::new([100u8; 32]))
                    .await
                    .expect("Failed to put data");

                // Destroy the store
                store.destroy().await.expect("Failed to destroy store");
            }

            // Try to create a new store - it should be empty
            {
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
    fn test_partial_record_write() {
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
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store
                    .put(0, FixedBytes::new([42u8; 32]))
                    .await
                    .expect("Failed to put data");
                store
                    .put(1, FixedBytes::new([43u8; 32]))
                    .await
                    .expect("Failed to put data");
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
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
                store_mut.put(1, FixedBytes::new([44u8; 32])).await.unwrap();
                assert_eq!(
                    store_mut.get(1).await.unwrap().unwrap(),
                    FixedBytes::new([44u8; 32])
                );
            }
        });
    }

    #[test_traced]
    fn test_corrupted_value() {
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
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store
                    .put(0, FixedBytes::new([42u8; 32]))
                    .await
                    .expect("Failed to put data");
                store
                    .put(1, FixedBytes::new([43u8; 32]))
                    .await
                    .expect("Failed to put data");
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
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
    fn test_crc_corruptions() {
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
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Add values across 2 blobs
                store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
                store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
                store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
                store.put(15, FixedBytes::new([15u8; 32])).await.unwrap();
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
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
    fn test_extra_bytes_in_blob() {
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
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store
                    .put(0, FixedBytes::new([42u8; 32]))
                    .await
                    .expect("Failed to put data");
                store
                    .put(1, FixedBytes::new([43u8; 32]))
                    .await
                    .expect("Failed to put data");
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
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
                store_mut.put(2, FixedBytes::new([44u8; 32])).await.unwrap();
                assert_eq!(
                    store_mut.get(2).await.unwrap().unwrap(),
                    FixedBytes::new([44u8; 32])
                );
            }
        });
    }

    #[test_traced]
    fn test_zero_filled_records() {
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
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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

    fn test_operations_and_restart(num_values: usize) -> String {
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
            let mut store = Ordinal::<_, FixedBytes<128>>::init(context.clone(), cfg.clone())
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

                store
                    .put(index, value.clone())
                    .await
                    .expect("Failed to put data");
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
            let mut store = Ordinal::<_, FixedBytes<128>>::init(context.clone(), cfg)
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

                store.put(index, value).await.expect("Failed to put data");
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
        let state1 = test_operations_and_restart(100);
        let state2 = test_operations_and_restart(100);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_prune_basic() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100, // Small blobs to test multiple blob handling
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
                store
                    .put(*index, value.clone())
                    .await
                    .expect("Failed to put data");
            }
            store.sync().await.unwrap();

            // Verify all values exist
            for (index, value) in &values {
                assert_eq!(store.get(*index).await.unwrap().unwrap(), *value);
            }

            // Prune up to index 150 (should remove blob 0 only)
            store.prune(150).await.unwrap();
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
            store.prune(250).await.unwrap();
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
    fn test_prune_with_gaps() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert sparse data with gaps
            store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
            store.put(105, FixedBytes::new([105u8; 32])).await.unwrap();
            store.put(305, FixedBytes::new([49u8; 32])).await.unwrap();
            store.sync().await.unwrap();

            // Check gaps before pruning
            let (current_end, next_start) = store.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(next_start, Some(5));

            let (current_end, next_start) = store.next_gap(5);
            assert_eq!(current_end, Some(5));
            assert_eq!(next_start, Some(105));

            // Prune up to index 150 (should remove blob 0)
            store.prune(150).await.unwrap();

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
    fn test_prune_no_op() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert data
            store.put(100, FixedBytes::new([100u8; 32])).await.unwrap();
            store.put(200, FixedBytes::new([200u8; 32])).await.unwrap();
            store.sync().await.unwrap();

            // Try to prune before any data - should be no-op
            store.prune(50).await.unwrap();

            // Verify no data was actually pruned
            assert!(store.has(100));
            assert!(store.has(200));
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 0"));

            // Try to prune exactly at blob boundary - should be no-op
            store.prune(100).await.unwrap();

            // Verify still no data pruned
            assert!(store.has(100));
            assert!(store.has(200));
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 0"));
        });
    }

    #[test_traced]
    fn test_prune_empty_store() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Try to prune empty store
            store.prune(1000).await.unwrap();

            // Store should still be functional
            store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
            assert!(store.has(0));
        });
    }

    #[test_traced]
    fn test_prune_after_restart() {
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
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
                store.put(100, FixedBytes::new([100u8; 32])).await.unwrap();
                store.put(200, FixedBytes::new([200u8; 32])).await.unwrap();
                store.close().await.unwrap();
            }

            // Reopen and prune
            {
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Verify data is there
                assert!(store.has(0));
                assert!(store.has(100));
                assert!(store.has(200));

                // Prune up to index 150
                store.prune(150).await.unwrap();

                // Verify pruning worked
                assert!(!store.has(0));
                assert!(store.has(100));
                assert!(store.has(200));

                store.close().await.unwrap();
            }

            // Reopen again and verify pruning persisted
            {
                let store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
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
    fn test_prune_multiple_operations() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 50, // Smaller blobs for more granular testing
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert data across many blobs
            let mut values = Vec::new();
            for i in 0..10 {
                let index = i * 50 + 25; // Middle of each blob
                let value = FixedBytes::new([i as u8; 32]);
                store.put(index, value.clone()).await.unwrap();
                values.push((index, value));
            }
            store.sync().await.unwrap();

            // Prune incrementally
            for i in 1..5 {
                let prune_index = i * 50 + 10;
                store.prune(prune_index).await.unwrap();

                // Verify appropriate data is pruned
                for (index, _) in &values {
                    if *index < prune_index {
                        assert!(!store.has(*index), "Index {index} should be pruned");
                    } else {
                        assert!(store.has(*index), "Index {index} should not be pruned");
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
    fn test_prune_blob_boundaries() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert data at blob boundaries
            store.put(0, FixedBytes::new([0u8; 32])).await.unwrap(); // Start of blob 0
            store.put(99, FixedBytes::new([99u8; 32])).await.unwrap(); // End of blob 0
            store.put(100, FixedBytes::new([100u8; 32])).await.unwrap(); // Start of blob 1
            store.put(199, FixedBytes::new([199u8; 32])).await.unwrap(); // End of blob 1
            store.put(200, FixedBytes::new([200u8; 32])).await.unwrap(); // Start of blob 2
            store.sync().await.unwrap();

            // Test various pruning points around boundaries

            // Prune exactly at blob boundary (100) - should prune blob 0
            store.prune(100).await.unwrap();
            assert!(!store.has(0));
            assert!(!store.has(99));
            assert!(store.has(100));
            assert!(store.has(199));
            assert!(store.has(200));

            // Prune just before next boundary (199) - should not prune blob 1
            store.prune(199).await.unwrap();
            assert!(store.has(100));
            assert!(store.has(199));
            assert!(store.has(200));

            // Prune exactly at next boundary (200) - should prune blob 1
            store.prune(200).await.unwrap();
            assert!(!store.has(100));
            assert!(!store.has(199));
            assert!(store.has(200));

            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 2"));
        });
    }

    #[test_traced]
    fn test_prune_non_contiguous_sections() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert data in non-contiguous sections (0, 2, 5, 7)
            store.put(0, FixedBytes::new([0u8; 32])).await.unwrap(); // Section 0
            store.put(250, FixedBytes::new([50u8; 32])).await.unwrap(); // Section 2 (250/100 = 2)
            store.put(500, FixedBytes::new([44u8; 32])).await.unwrap(); // Section 5 (500/100 = 5)
            store.put(750, FixedBytes::new([45u8; 32])).await.unwrap(); // Section 7 (750/100 = 7)
            store.sync().await.unwrap();

            // Verify all data exists initially
            assert!(store.has(0));
            assert!(store.has(250));
            assert!(store.has(500));
            assert!(store.has(750));

            // Prune up to section 3 (index 300) - should remove sections 0 and 2
            store.prune(300).await.unwrap();

            // Verify correct data was pruned
            assert!(!store.has(0)); // Section 0 pruned
            assert!(!store.has(250)); // Section 2 pruned
            assert!(store.has(500)); // Section 5 remains
            assert!(store.has(750)); // Section 7 remains

            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 2"));

            // Prune up to section 6 (index 600) - should remove section 5
            store.prune(600).await.unwrap();

            // Verify section 5 was pruned
            assert!(!store.has(500)); // Section 5 pruned
            assert!(store.has(750)); // Section 7 remains

            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 3"));

            // Prune everything - should remove section 7
            store.prune(1000).await.unwrap();

            // Verify all data is gone
            assert!(!store.has(750)); // Section 7 pruned

            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 4"));
        });
    }

    #[test_traced]
    fn test_prune_removes_correct_pending() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 100,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };
            let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize store");

            // Insert and sync some data in blob 0
            store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
            store.sync().await.unwrap();

            // Add pending entries to blob 0 and blob 1
            store.put(10, FixedBytes::new([10u8; 32])).await.unwrap(); // blob 0
            store.put(110, FixedBytes::new([110u8; 32])).await.unwrap(); // blob 1

            // Verify all data is visible before pruning
            assert!(store.has(5));
            assert!(store.has(10));
            assert!(store.has(110));

            // Prune up to index 100, which should remove blob 0 (indices 0-99).
            store.prune(150).await.unwrap();

            // Verify that synced and pending entries in blob 0 are removed.
            assert!(!store.has(5));
            assert!(!store.has(10));

            // Verify that the pending entry in blob 1 remains.
            assert!(store.has(110));
            assert_eq!(
                store.get(110).await.unwrap().unwrap(),
                FixedBytes::new([110u8; 32])
            );

            // Sync the remaining pending entry and verify it's still there.
            store.sync().await.unwrap();
            assert!(store.has(110));
            assert_eq!(
                store.get(110).await.unwrap().unwrap(),
                FixedBytes::new([110u8; 32])
            );
        });
    }

    #[test_traced]
    fn test_init_with_bits_none() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 10, // Small blob size for testing
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data across multiple sections
            {
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Section 0 (indices 0-9)
                store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
                store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
                store.put(9, FixedBytes::new([9u8; 32])).await.unwrap();

                // Section 1 (indices 10-19)
                store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
                store.put(15, FixedBytes::new([15u8; 32])).await.unwrap();

                // Section 2 (indices 20-29)
                store.put(25, FixedBytes::new([25u8; 32])).await.unwrap();

                store.close().await.unwrap();
            }

            // Reinitialize with bits = None (should behave like regular init)
            {
                let store = Ordinal::<_, FixedBytes<32>>::init_with_bits(
                    context.clone(),
                    cfg.clone(),
                    None,
                )
                .await
                .expect("Failed to initialize store with bits");

                // All records should be available
                assert!(store.has(0));
                assert!(store.has(5));
                assert!(store.has(9));
                assert!(store.has(10));
                assert!(store.has(15));
                assert!(store.has(25));

                // Non-existent records should not be available
                assert!(!store.has(1));
                assert!(!store.has(11));
                assert!(!store.has(20));

                // Verify values
                assert_eq!(
                    store.get(0).await.unwrap().unwrap(),
                    FixedBytes::new([0u8; 32])
                );
                assert_eq!(
                    store.get(15).await.unwrap().unwrap(),
                    FixedBytes::new([15u8; 32])
                );
            }
        });
    }

    #[test_traced]
    fn test_init_with_bits_empty_hashmap() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 10,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data
            {
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
                store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
                store.put(20, FixedBytes::new([20u8; 32])).await.unwrap();

                store.close().await.unwrap();
            }

            // Reinitialize with empty HashMap - should skip all sections
            {
                let bits: BTreeMap<u64, &Option<BitVec>> = BTreeMap::new();
                let store = Ordinal::<_, FixedBytes<32>>::init_with_bits(
                    context.clone(),
                    cfg.clone(),
                    Some(bits),
                )
                .await
                .expect("Failed to initialize store with bits");

                // No records should be available since no sections were in the bits map
                assert!(!store.has(0));
                assert!(!store.has(10));
                assert!(!store.has(20));
            }
        });
    }

    #[test_traced]
    fn test_init_with_bits_selective_sections() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 10,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data in multiple sections
            {
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Section 0 (indices 0-9)
                for i in 0..10 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                // Section 1 (indices 10-19)
                for i in 10..20 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                // Section 2 (indices 20-29)
                for i in 20..30 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                store.close().await.unwrap();
            }

            // Reinitialize with bits for only section 1
            {
                let mut bits_map: BTreeMap<u64, &Option<BitVec>> = BTreeMap::new();

                // Create a BitVec that marks indices 12, 15, and 18 as present
                let mut bitvec = BitVec::zeroes(10);
                bitvec.set(2); // Index 12 (offset 2 in section 1)
                bitvec.set(5); // Index 15 (offset 5 in section 1)
                bitvec.set(8); // Index 18 (offset 8 in section 1)
                let bitvec_option = Some(bitvec);

                bits_map.insert(1, &bitvec_option);

                let store = Ordinal::<_, FixedBytes<32>>::init_with_bits(
                    context.clone(),
                    cfg.clone(),
                    Some(bits_map),
                )
                .await
                .expect("Failed to initialize store with bits");

                // Only specified indices from section 1 should be available
                assert!(store.has(12));
                assert!(store.has(15));
                assert!(store.has(18));

                // Other indices from section 1 should not be available
                assert!(!store.has(10));
                assert!(!store.has(11));
                assert!(!store.has(13));
                assert!(!store.has(14));
                assert!(!store.has(16));
                assert!(!store.has(17));
                assert!(!store.has(19));

                // All indices from sections 0 and 2 should not be available
                for i in 0..10 {
                    assert!(!store.has(i));
                }
                for i in 20..30 {
                    assert!(!store.has(i));
                }

                // Verify the available values
                assert_eq!(
                    store.get(12).await.unwrap().unwrap(),
                    FixedBytes::new([12u8; 32])
                );
                assert_eq!(
                    store.get(15).await.unwrap().unwrap(),
                    FixedBytes::new([15u8; 32])
                );
                assert_eq!(
                    store.get(18).await.unwrap().unwrap(),
                    FixedBytes::new([18u8; 32])
                );
            }
        });
    }

    #[test_traced]
    fn test_init_with_bits_none_option_all_records_exist() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 5,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with all records in a section
            {
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Fill section 1 completely (indices 5-9)
                for i in 5..10 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                store.close().await.unwrap();
            }

            // Reinitialize with None option for section 1 (expects all records)
            {
                let mut bits_map: BTreeMap<u64, &Option<BitVec>> = BTreeMap::new();
                let none_option: Option<BitVec> = None;
                bits_map.insert(1, &none_option);

                let store = Ordinal::<_, FixedBytes<32>>::init_with_bits(
                    context.clone(),
                    cfg.clone(),
                    Some(bits_map),
                )
                .await
                .expect("Failed to initialize store with bits");

                // All records in section 1 should be available
                for i in 5..10 {
                    assert!(store.has(i));
                    assert_eq!(
                        store.get(i).await.unwrap().unwrap(),
                        FixedBytes::new([i as u8; 32])
                    );
                }
            }
        });
    }

    #[test_traced]
    #[should_panic(expected = "Failed to initialize store with bits: MissingRecord(6)")]
    fn test_init_with_bits_none_option_missing_record_panics() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 5,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with missing record in a section
            {
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Fill section 1 partially (skip index 6)
                store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
                // Skip index 6
                store.put(7, FixedBytes::new([7u8; 32])).await.unwrap();
                store.put(8, FixedBytes::new([8u8; 32])).await.unwrap();
                store.put(9, FixedBytes::new([9u8; 32])).await.unwrap();

                store.close().await.unwrap();
            }

            // Reinitialize with None option for section 1 (expects all records)
            // This should panic because index 6 is missing
            {
                let mut bits_map: BTreeMap<u64, &Option<BitVec>> = BTreeMap::new();
                let none_option: Option<BitVec> = None;
                bits_map.insert(1, &none_option);

                let _store = Ordinal::<_, FixedBytes<32>>::init_with_bits(
                    context.clone(),
                    cfg.clone(),
                    Some(bits_map),
                )
                .await
                .expect("Failed to initialize store with bits");
            }
        });
    }

    #[test_traced]
    fn test_init_with_bits_mixed_sections() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 5,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data in multiple sections
            {
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Section 0: indices 0-4 (fill completely)
                for i in 0..5 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                // Section 1: indices 5-9 (fill partially)
                store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
                store.put(7, FixedBytes::new([7u8; 32])).await.unwrap();
                store.put(9, FixedBytes::new([9u8; 32])).await.unwrap();

                // Section 2: indices 10-14 (fill completely)
                for i in 10..15 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                store.close().await.unwrap();
            }

            // Reinitialize with mixed bits configuration
            {
                let mut bits_map: BTreeMap<u64, &Option<BitVec>> = BTreeMap::new();

                // Section 0: None option (expects all records)
                let none_option: Option<BitVec> = None;
                bits_map.insert(0, &none_option);

                // Section 1: BitVec with specific indices
                let mut bitvec1 = BitVec::zeroes(5);
                bitvec1.set(0); // Index 5
                bitvec1.set(2); // Index 7
                                // Note: not setting bit for index 9, so it should be ignored
                let bitvec1_option = Some(bitvec1);
                bits_map.insert(1, &bitvec1_option);

                // Section 2: Not in map, should be skipped entirely

                let store = Ordinal::<_, FixedBytes<32>>::init_with_bits(
                    context.clone(),
                    cfg.clone(),
                    Some(bits_map),
                )
                .await
                .expect("Failed to initialize store with bits");

                // All records from section 0 should be available
                for i in 0..5 {
                    assert!(store.has(i));
                    assert_eq!(
                        store.get(i).await.unwrap().unwrap(),
                        FixedBytes::new([i as u8; 32])
                    );
                }

                // Only specified records from section 1 should be available
                assert!(store.has(5));
                assert!(store.has(7));
                assert!(!store.has(6));
                assert!(!store.has(8));
                assert!(!store.has(9)); // Not set in bitvec

                // No records from section 2 should be available
                for i in 10..15 {
                    assert!(!store.has(i));
                }
            }
        });
    }

    #[test_traced]
    #[should_panic(expected = "Failed to initialize store with bits: MissingRecord(2)")]
    fn test_init_with_bits_corrupted_records() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_ordinal".into(),
                items_per_blob: 5,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
            };

            // Create store with data and corrupt one record
            {
                let mut store = Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize store");

                // Section 0: indices 0-4
                for i in 0..5 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                store.close().await.unwrap();
            }

            // Corrupt record at index 2
            {
                let (blob, _) = context
                    .open("test_ordinal", &0u64.to_be_bytes())
                    .await
                    .unwrap();
                // Corrupt the CRC of record at index 2
                let offset = 2 * 36 + 32; // 2 * record_size + value_size
                blob.write_at(vec![0xFF], offset).await.unwrap();
                blob.close().await.unwrap();
            }

            // Reinitialize with bits that include the corrupted record
            {
                let mut bits_map: BTreeMap<u64, &Option<BitVec>> = BTreeMap::new();

                // Create a BitVec that includes the corrupted record
                let mut bitvec = BitVec::zeroes(5);
                bitvec.set(0); // Index 0
                bitvec.set(2); // Index 2 (corrupted) - this will cause a panic
                bitvec.set(4); // Index 4
                let bitvec_option = Some(bitvec);
                bits_map.insert(0, &bitvec_option);

                let _store = Ordinal::<_, FixedBytes<32>>::init_with_bits(
                    context.clone(),
                    cfg.clone(),
                    Some(bits_map),
                )
                .await
                .expect("Failed to initialize store with bits");
            }
        });
    }
}
