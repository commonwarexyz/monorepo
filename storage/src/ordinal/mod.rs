//! A persistent index that maps sparse indices to [commonware_utils::Array]s.
//!
//! [Ordinal] stores ordered records of fixed size in a single [commonware_runtime::Blob].
//! Because records are fixed size, file position corresponds directly to index. Unlike
//! [crate::journal::contiguous::fixed::Journal], [Ordinal] supports out-of-order insertion.
//!
//! # Design
//!
//! [Ordinal] is a single [commonware_runtime::Blob] where:
//! - Each record: `[V][crc32(V)]` where V is an [commonware_utils::Array]
//! - Index N is at byte offset: `N * RECORD_SIZE`
//! - Unwritten indices are holes in the blob
//! - A [crate::rmap::RMap] tracks which indices have been written (and which are missing)
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
//! The CRC32 does not guard integrity (the storage backend verifies all reads). It distinguishes
//! written records from never-written (hole) space: out-of-order insertion leaves sparse regions
//! that read back as zeroes, which fail the CRC check.
//!
//! # Performance Characteristics
//!
//! - **Writes**: O(1) - direct offset calculation
//! - **Reads**: O(1) - direct offset calculation
//! - **Has**: O(1) - in-memory lookup (via [crate::rmap::RMap])
//! - **Next Gap**: O(log n) - in-memory range query (via [crate::rmap::RMap])
//! - **Recovery**: O(n) over committed records when `committed` is provided (`None` resets the
//!   store)
//!
//! # Atomicity
//!
//! [Ordinal] eagerly writes all new data to its [commonware_runtime::Blob]. New data, however, is
//! not synced until [Ordinal::sync] is called. As a result, data is not guaranteed to be atomically
//! persisted (i.e. shutdown before [Ordinal::sync] may lead to some writes being lost).
//!
//! _If you want atomicity for sparse writes, pair [commonware_utils::bitmap::BitMap] and
//! [crate::metadata::Metadata] with [Ordinal] (use bits to indicate which items have been atomically
//! written)._
//!
//! # Pruning
//!
//! [Ordinal::prune] forwards to the runtime's native [commonware_runtime::Blob::prune]: bytes
//! below `min * RECORD_SIZE` (capped to one past the highest written index) drop, exactly.
//! Subsequent puts below the boundary fail with [Error::IndexPruned]. The floor is a mutation,
//! not a durability point: it persists at the next sync, and a crash may regress it to the
//! last synced floor — never the reverse — so consumers re-prune after recovery.
//!
//! # Recovery
//!
//! To recover existing data, pass `Some(committed)` to [Ordinal::init], naming the indices
//! durably committed by the caller. [Ordinal] checks each committed record's CRC32 to confirm it
//! was written (a never-written hole fails the check) and adopts the set as the in-memory
//! [crate::rmap::RMap]. Missing or invalid committed records fail initialization. Stored records
//! outside `committed` are ignored (unreachable through [Ordinal]) and overwritten by future
//! puts. They are not physically removed: recovery trusts the caller's committed set, so a later
//! initialization must only name records its caller durably paired with the store's synced data
//! (see Atomicity). The storage backend guarantees per-blob atomic sync, so torn writes cannot
//! survive a crash: a blob size (or pruned floor) that is not a record multiple fails
//! initialization with [Error::Corruption]. Passing `None` removes all stored data and starts
//! empty. The removal is durable before [Ordinal::init] returns.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_storage::ordinal::{Ordinal, Config};
//! use commonware_utils::{sequence::FixedBytes, NZUsize};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a store for 32-byte values
//!     let cfg = Config {
//!         partition: "ordinal-store".into(),
//!         write_buffer: NZUsize!(4096),
//!         replay_buffer: NZUsize!(1024 * 1024),
//!     };
//!     let mut store = Ordinal::<_, FixedBytes<32>>::init(context, cfg, None).await.unwrap();
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
//!     // Sync the store
//!     store.sync().await.unwrap();
//! });
//! ```

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
mod storage;

use std::num::NonZeroUsize;
pub use storage::Ordinal;
use thiserror::Error;

/// Errors that can occur when interacting with the [Ordinal].
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("corruption detected: {0}")]
    Corruption(String),
    #[error("invalid record: {0}")]
    InvalidRecord(u64),
    #[error("missing record at {0}")]
    MissingRecord(u64),
    #[error("index overflows the maximum record offset: {0}")]
    IndexOverflow(u64),
    #[error("index pruned: {0}")]
    IndexPruned(u64),
}

/// Configuration for [Ordinal] storage.
#[derive(Clone)]
pub struct Config {
    /// The [commonware_runtime::Storage] partition to use for storing the index.
    pub partition: String,

    /// The size of the write buffer to use when writing to the index.
    pub write_buffer: NonZeroUsize,

    /// The size of the read buffer to use on restart.
    pub replay_buffer: NonZeroUsize,
}

#[cfg(test)]
mod tests {
    use super::{storage::BLOB_NAME, *};
    use crate::rmap::RMap;
    use commonware_codec::{FixedSize, Read, ReadExt, Write};
    use commonware_cryptography::Crc32;
    use commonware_formatting::hex;
    use commonware_macros::{test_group, test_traced};
    use commonware_runtime::{
        deterministic, Blob, Buf, BufMut, Metrics as _, Runner, Storage, Supervisor as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize};
    use rand::Rng;

    const DEFAULT_WRITE_BUFFER: usize = 4096;
    const DEFAULT_REPLAY_BUFFER: usize = 1024 * 1024;

    /// Size of a `FixedBytes<32>` record (value plus CRC32).
    const RECORD_SIZE: u64 = 36;

    fn test_cfg() -> Config {
        Config {
            partition: "test-ordinal".into(),
            write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
            replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
        }
    }

    #[test_traced]
    fn test_put_get() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
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
    fn test_sync_does_not_report_success_while_flush_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            store
                .put(0, FixedBytes::new([42u8; 32]))
                .await
                .expect("Failed to put data");

            // Force flush failure by injecting storage sync faults.
            context.storage_fault_config().write().sync_rate = Some(1.0);

            // Sync must observe the durability failure.
            assert!(store.sync().await.is_err(), "sync unexpectedly succeeded");
        });
    }

    #[test_traced]
    fn test_multiple_indices() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // Insert multiple values at different indices
            let indices = vec![
                (0u64, FixedBytes::new([0u8; 32])),
                (5u64, FixedBytes::new([5u8; 32])),
                (10u64, FixedBytes::new([10u8; 32])),
                (100u64, FixedBytes::new([100u8; 32])),
                (1000u64, FixedBytes::new([200u8; 32])),
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
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // Insert sparse values
            let indices = vec![
                (0u64, FixedBytes::new([0u8; 32])),
                (99u64, FixedBytes::new([99u8; 32])),
                (100u64, FixedBytes::new([100u8; 32])),
                (500u64, FixedBytes::new([200u8; 32])),
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
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
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
    fn test_missing_items() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the store
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // Test 1: Empty store - should return no items
            assert_eq!(store.missing_items(0, 5), Vec::<u64>::new());
            assert_eq!(store.missing_items(100, 10), Vec::<u64>::new());

            // Test 2: Insert values with gaps
            store.put(1, FixedBytes::new([1u8; 32])).await.unwrap();
            store.put(2, FixedBytes::new([2u8; 32])).await.unwrap();
            store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
            store.put(6, FixedBytes::new([6u8; 32])).await.unwrap();
            store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();

            // Test 3: Find missing items from the beginning
            assert_eq!(store.missing_items(0, 5), vec![0, 3, 4, 7, 8]);
            assert_eq!(store.missing_items(0, 6), vec![0, 3, 4, 7, 8, 9]);
            assert_eq!(store.missing_items(0, 7), vec![0, 3, 4, 7, 8, 9]);

            // Test 4: Find missing items from within a gap
            assert_eq!(store.missing_items(3, 3), vec![3, 4, 7]);
            assert_eq!(store.missing_items(4, 2), vec![4, 7]);

            // Test 5: Find missing items from within a range
            assert_eq!(store.missing_items(1, 3), vec![3, 4, 7]);
            assert_eq!(store.missing_items(2, 4), vec![3, 4, 7, 8]);
            assert_eq!(store.missing_items(5, 2), vec![7, 8]);

            // Test 6: Find missing items after the last range (no more gaps)
            assert_eq!(store.missing_items(11, 5), Vec::<u64>::new());
            assert_eq!(store.missing_items(100, 10), Vec::<u64>::new());

            // Test 7: Large gap scenario
            store.put(1000, FixedBytes::new([100u8; 32])).await.unwrap();

            // Gap between 10 and 1000
            let items = store.missing_items(11, 10);
            assert_eq!(items, vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);

            // Request more items than available in gap
            let items = store.missing_items(990, 15);
            assert_eq!(
                items,
                vec![990, 991, 992, 993, 994, 995, 996, 997, 998, 999]
            );

            // Test 8: After syncing (data should remain consistent)
            store.sync().await.unwrap();
            assert_eq!(store.missing_items(0, 5), vec![0, 3, 4, 7, 8]);
            assert_eq!(store.missing_items(3, 3), vec![3, 4, 7]);

            // Test 9: Far-apart sparse indices
            store.put(9999, FixedBytes::new([99u8; 32])).await.unwrap();
            store
                .put(10001, FixedBytes::new([101u8; 32]))
                .await
                .unwrap();

            let items = store.missing_items(9998, 5);
            assert_eq!(items, vec![9998, 10000]);
        });
    }

    #[test_traced]
    fn test_restart() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Insert data and close
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
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

                store.sync().await.expect("Failed to sync store");
            }

            // Reopen with the committed indices and verify the data persisted
            {
                let committed: RMap = [0u64, 100, 1000].into_iter().collect();
                let store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(committed),
                )
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
            let cfg = test_cfg();

            // Create store with data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                store
                    .put(0, FixedBytes::new([42u8; 32]))
                    .await
                    .expect("Failed to put data");
                store.sync().await.expect("Failed to sync store");
            }

            // Corrupt the data
            {
                let (blob, _) = context.open("test-ordinal", BLOB_NAME).await.unwrap();
                // Corrupt the CRC by changing a byte
                blob.write_at_sync(32, vec![0xFF]).await.unwrap();
            }

            // Reopen without committed indices, deleting the stored corrupted data.
            {
                let store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("second"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                let result = store.get(0).await.unwrap();
                assert!(result.is_none());

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
            let cfg = test_cfg();
            let store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
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
    fn test_index_overflow() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // An index whose record cannot be addressed within a u64 is rejected.
            let result = store.put(u64::MAX, FixedBytes::new([0u8; 32])).await;
            assert!(matches!(result, Err(Error::IndexOverflow(u64::MAX))));
            let result = store
                .put(u64::MAX / RECORD_SIZE, FixedBytes::new([0u8; 32]))
                .await;
            assert!(matches!(result, Err(Error::IndexOverflow(_))));

            // Reads of unaddressable indices report absence.
            assert!(store.get(u64::MAX).await.unwrap().is_none());
            assert!(!store.has(u64::MAX));

            // The store remains functional.
            store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
            assert!(store.has(0));
        });
    }

    #[test_traced]
    fn test_destroy() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
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
                let store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("second"), cfg.clone(), None)
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
            let cfg = test_cfg();

            // Create store with data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
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
                store.sync().await.expect("Failed to sync store");
            }

            // Corrupt by writing partial record (only value, no CRC)
            {
                let (blob, _) = context.open("test-ordinal", BLOB_NAME).await.unwrap();
                // Overwrite second record with partial data (32 bytes instead of 36)
                blob.write_at_sync(36, vec![0xFF; 32]).await.unwrap();
            }

            // Reopen without committed indices and verify uncommitted data is deleted.
            {
                let store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("second"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                assert!(!store.has(0));
                assert!(!store.has(1));

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
    fn test_non_multiple_blob_size_corruption() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                store
                    .put(0, FixedBytes::new([42u8; 32]))
                    .await
                    .expect("Failed to put data");
                store.sync().await.expect("Failed to sync store");
            }

            // Extend the blob by a non-record-multiple of durable junk bytes
            {
                let (blob, size) = context.open("test-ordinal", BLOB_NAME).await.unwrap();
                blob.write_at_sync(size, vec![0xFF; 10]).await.unwrap();
            }

            // Reopen with committed indices: a size that is not a record multiple is corruption
            {
                let committed: RMap = [0u64].into_iter().collect();
                let result = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(committed),
                )
                .await;
                assert!(matches!(result, Err(Error::Corruption(_))));
            }
        });
    }

    #[test_traced]
    fn test_corrupted_value() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
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
                store.sync().await.expect("Failed to sync store");
            }

            // Corrupt the value portion of a record
            {
                let (blob, _) = context.open("test-ordinal", BLOB_NAME).await.unwrap();
                // Corrupt some bytes in the value of the first record
                blob.write_at_sync(10, hex!("0xFFFFFFFF").to_vec())
                    .await
                    .unwrap();
            }

            // Reopen without committed indices and verify uncommitted data is deleted.
            {
                let store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("second"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                assert!(!store.has(0));
                assert!(!store.has(1));
            }
        });
    }

    #[test_traced]
    fn test_crc_corruptions() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with sparse data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
                store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
                store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
                store.put(15, FixedBytes::new([15u8; 32])).await.unwrap();
                store.sync().await.expect("Failed to sync store");
            }

            // Corrupt records at different offsets
            {
                let (blob, _) = context.open("test-ordinal", BLOB_NAME).await.unwrap();

                // Corrupt CRC of index 0
                blob.write_at_sync(32, vec![0xFF]).await.unwrap();

                // Corrupt value of index 10 (which will invalidate its CRC)
                blob.write_at_sync(10 * RECORD_SIZE + 5, vec![0xFF; 4])
                    .await
                    .unwrap();
            }

            // Reopen without committed indices and verify uncommitted data is deleted.
            {
                let store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("second"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                assert!(!store.has(0));
                assert!(!store.has(5));
                assert!(!store.has(10));
                assert!(!store.has(15));
            }
        });
    }

    #[test_traced]
    fn test_extra_bytes_in_blob() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
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
                store.sync().await.expect("Failed to sync store");
            }

            // Add extra bytes at the end of blob
            {
                let (blob, size) = context.open("test-ordinal", BLOB_NAME).await.unwrap();
                // Add garbage data that forms a complete but invalid record
                // This avoids partial record issues
                let mut garbage = vec![0xFF; 32]; // Invalid value
                let invalid_crc = 0xDEADBEEFu32;
                garbage.extend_from_slice(&invalid_crc.to_be_bytes());
                assert_eq!(garbage.len(), 36); // Full record size
                blob.write_at_sync(size, garbage).await.unwrap();
            }

            // Reopen without committed indices and verify uncommitted data is deleted.
            {
                let store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("second"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                assert!(!store.has(0));
                assert!(!store.has(1));

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
            let cfg = test_cfg();

            // Create blob with zero-filled space
            {
                let (blob, _) = context.open("test-ordinal", BLOB_NAME).await.unwrap();

                // Write zeros for several record positions
                let zeros = vec![0u8; 36 * 5]; // 5 records worth of zeros
                blob.write_at_sync(0, zeros).await.unwrap();

                // Write a valid record after the zeros
                let mut valid_record = vec![44u8; 32];
                let crc = Crc32::checksum(&valid_record);
                valid_record.extend_from_slice(&crc.to_be_bytes());
                blob.write_at_sync(36 * 5, valid_record).await.unwrap();
            }

            // Initialize with committed indices and verify it handles zero-filled records
            {
                let committed: RMap = [5u64].into_iter().collect();
                let store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("storage"),
                    cfg.clone(),
                    Some(committed),
                )
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
            let cfg = test_cfg();

            // Initialize the store
            let mut store =
                Ordinal::<_, FixedBytes<128>>::init(context.child("first"), cfg.clone(), None)
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

            // Sync and drop the store
            store.sync().await.expect("Failed to sync store");
            drop(store);

            // Reopen the store
            let committed: RMap = values.iter().map(|(index, _)| *index).collect();
            let mut store =
                Ordinal::<_, FixedBytes<128>>::init(context.child("second"), cfg, Some(committed))
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

    #[test_group("slow")]
    #[test_traced]
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
            let cfg = test_cfg();

            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // Insert sparse data
            let values = vec![
                (0u64, FixedBytes::new([0u8; 32])),
                (50u64, FixedBytes::new([50u8; 32])),
                (100u64, FixedBytes::new([100u8; 32])),
                (150u64, FixedBytes::new([150u8; 32])),
                (200u64, FixedBytes::new([200u8; 32])),
                (300u64, FixedBytes::new([44u8; 32])),
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

            // Prune up to index 150, exactly: everything below is gone, 150 survives.
            store.prune(150).await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 1"));

            // Verify pruned data is gone
            assert!(!store.has(0));
            assert!(!store.has(50));
            assert!(!store.has(100));
            assert!(store.get(0).await.unwrap().is_none());
            assert!(store.get(100).await.unwrap().is_none());

            // Verify remaining data is still there
            assert!(store.has(150));
            assert!(store.has(200));
            assert!(store.has(300));
            assert_eq!(store.get(150).await.unwrap().unwrap(), values[3].1);
            assert_eq!(store.get(200).await.unwrap().unwrap(), values[4].1);
            assert_eq!(store.get(300).await.unwrap().unwrap(), values[5].1);

            // Puts below the boundary fail
            let result = store.put(149, FixedBytes::new([0u8; 32])).await;
            assert!(matches!(result, Err(Error::IndexPruned(149))));

            // Prune more aggressively - up to index 250
            store.prune(250).await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 2"));

            // Verify more data is pruned
            assert!(!store.has(150));
            assert!(!store.has(200));
            assert!(store.get(150).await.unwrap().is_none());
            assert!(store.get(200).await.unwrap().is_none());

            // Verify remaining data
            assert!(store.has(300));
            assert_eq!(store.get(300).await.unwrap().unwrap(), values[5].1);
        });
    }

    #[test_traced]
    fn test_prune_with_gaps() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
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

            // Prune up to index 100
            store.prune(100).await.unwrap();

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
            let cfg = test_cfg();

            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // Insert data
            store.put(100, FixedBytes::new([100u8; 32])).await.unwrap();
            store.put(200, FixedBytes::new([200u8; 32])).await.unwrap();
            store.sync().await.unwrap();

            // Prune to zero - should be a no-op
            store.prune(0).await.unwrap();
            assert!(store.has(100));
            assert!(store.has(200));
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 0"));

            // Prune below the first index: the boundary advances (exactly) even though no
            // written records drop.
            store.prune(50).await.unwrap();
            assert!(store.has(100));
            assert!(store.has(200));
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 1"));
            let result = store.put(49, FixedBytes::new([0u8; 32])).await;
            assert!(matches!(result, Err(Error::IndexPruned(49))));
            store.put(50, FixedBytes::new([50u8; 32])).await.unwrap();

            // Re-pruning to the same boundary is a no-op
            store.prune(50).await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 1"));
        });
    }

    #[test_traced]
    fn test_prune_empty_store() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // Try to prune empty store: capped to the (empty) written range, a no-op
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
            let cfg = test_cfg();

            // Create store and add data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
                store.put(100, FixedBytes::new([100u8; 32])).await.unwrap();
                store.put(200, FixedBytes::new([200u8; 32])).await.unwrap();
                store.sync().await.unwrap();
            }

            // Reopen with the committed indices and prune
            {
                let committed: RMap = [0u64, 100, 200].into_iter().collect();
                let mut store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(committed),
                )
                .await
                .expect("Failed to initialize store");

                // Verify data is there
                assert!(store.has(0));
                assert!(store.has(100));
                assert!(store.has(200));

                // Prune up to index 150
                store.prune(150).await.unwrap();

                // Verify pruning worked (exactly: 100 precedes the boundary)
                assert!(!store.has(0));
                assert!(!store.has(100));
                assert!(store.has(200));

                store.sync().await.unwrap();
            }

            // Reopen again and verify pruning persisted
            {
                let committed: RMap = [200u64].into_iter().collect();
                let store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("third"),
                    cfg.clone(),
                    Some(committed),
                )
                .await
                .expect("Failed to initialize store");

                assert!(!store.has(0));
                assert!(!store.has(100));
                assert!(store.has(200));

                // Check gaps
                let (current_end, next_start) = store.next_gap(0);
                assert!(current_end.is_none());
                assert_eq!(next_start, Some(200));
            }

            // Naming a record below the persisted boundary fails initialization
            {
                let committed: RMap = [100u64, 200].into_iter().collect();
                let result = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("fourth"),
                    cfg.clone(),
                    Some(committed),
                )
                .await;
                assert!(matches!(result, Err(Error::MissingRecord(100))));
            }
        });
    }

    /// The directed boundary test: prune mid-store, the boundary is exact and persists across
    /// a restart once synced.
    #[test_traced]
    fn test_prune_boundary_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .unwrap();
                for i in 0..200u64 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }
                store.sync().await.unwrap();

                // A prune to an arbitrary index: the boundary is exact.
                store.prune(37).await.unwrap();
                assert!(!store.has(36));
                assert!(store.has(37));
                store.sync().await.unwrap();
            }

            // The boundary index survives the restart.
            {
                let committed: RMap = (37u64..200).collect();
                let store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(committed),
                )
                .await
                .unwrap();
                assert_eq!(
                    store.get(37).await.unwrap().unwrap(),
                    FixedBytes::new([37u8; 32])
                );
                assert_eq!(store.first_index(), Some(37));
            }

            // Naming the index just below the boundary fails initialization.
            {
                let committed: RMap = (36u64..200).collect();
                let result = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("third"),
                    cfg.clone(),
                    Some(committed),
                )
                .await;
                assert!(matches!(result, Err(Error::MissingRecord(36))));
            }
        });
    }

    /// The directed regression test: an unsynced prune regresses across a crash to the last
    /// synced floor and can be re-applied.
    #[test_traced]
    fn test_unsynced_prune_regression_and_reprune() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                    .await
                    .unwrap();
            for i in 0..200u64 {
                store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
            }
            store.sync().await.unwrap();

            // A synced prune: the floor is durable.
            store.prune(37).await.unwrap();
            store.sync().await.unwrap();

            // A further prune whose sync never lands: the boundary advances in RAM but the
            // crash below discards it.
            store.prune(150).await.unwrap();
            assert!(!store.has(149));
            assert!(store.has(150));
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg();

            // The unsynced prune regressed to the last synced floor: every record from the
            // synced boundary is still recoverable.
            let committed: RMap = (37u64..200).collect();
            let mut store = Ordinal::<_, FixedBytes<32>>::init(
                context.child("second"),
                cfg.clone(),
                Some(committed),
            )
            .await
            .unwrap();
            assert_eq!(
                store.get(37).await.unwrap().unwrap(),
                FixedBytes::new([37u8; 32])
            );
            assert_eq!(
                store.get(149).await.unwrap().unwrap(),
                FixedBytes::new([149u8; 32])
            );

            // Re-pruning after the regression works and is exact.
            store.prune(150).await.unwrap();
            assert!(!store.has(149));
            assert!(store.has(150));
            store.sync().await.unwrap();
            drop(store);

            // The re-applied boundary persists.
            let committed: RMap = (150u64..200).collect();
            let store = Ordinal::<_, FixedBytes<32>>::init(
                context.child("third"),
                cfg.clone(),
                Some(committed),
            )
            .await
            .unwrap();
            assert_eq!(store.first_index(), Some(150));
            drop(store);

            let committed: RMap = (149u64..200).collect();
            let result = Ordinal::<_, FixedBytes<32>>::init(
                context.child("fourth"),
                cfg.clone(),
                Some(committed),
            )
            .await;
            assert!(matches!(result, Err(Error::MissingRecord(149))));
        });
    }

    /// The directed sparse test: puts land above a pruned floor (including exactly at it and
    /// far beyond it) while puts below it fail.
    #[test_traced]
    fn test_sparse_puts_across_pruned_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                    .await
                    .unwrap();

            store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
            store.put(500, FixedBytes::new([77u8; 32])).await.unwrap();
            store.sync().await.unwrap();

            store.prune(100).await.unwrap();
            assert!(!store.has(10));
            assert!(store.has(500));

            // Below the floor: rejected. At the floor and above (sparsely): accepted.
            let result = store.put(50, FixedBytes::new([50u8; 32])).await;
            assert!(matches!(result, Err(Error::IndexPruned(50))));
            store.put(100, FixedBytes::new([100u8; 32])).await.unwrap();
            store.put(1000, FixedBytes::new([1u8; 32])).await.unwrap();
            store.sync().await.unwrap();
            drop(store);

            // Everything above the floor recovers.
            let committed: RMap = [100u64, 500, 1000].into_iter().collect();
            let store = Ordinal::<_, FixedBytes<32>>::init(
                context.child("second"),
                cfg.clone(),
                Some(committed),
            )
            .await
            .unwrap();
            assert_eq!(
                store.get(100).await.unwrap().unwrap(),
                FixedBytes::new([100u8; 32])
            );
            assert_eq!(
                store.get(500).await.unwrap().unwrap(),
                FixedBytes::new([77u8; 32])
            );
            assert_eq!(
                store.get(1000).await.unwrap().unwrap(),
                FixedBytes::new([1u8; 32])
            );
            assert!(!store.has(10));
            drop(store);

            // Naming a record below the floor fails initialization.
            let committed: RMap = [99u64, 100].into_iter().collect();
            let result = Ordinal::<_, FixedBytes<32>>::init(
                context.child("third"),
                cfg.clone(),
                Some(committed),
            )
            .await;
            assert!(matches!(result, Err(Error::MissingRecord(99))));
        });
    }

    #[test_traced]
    fn test_prune_multiple_operations() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // Insert sparse data
            let mut values = Vec::new();
            for i in 0..10 {
                let index = i * 50 + 25;
                let value = FixedBytes::new([i as u8; 32]);
                store.put(index, value.clone()).await.unwrap();
                values.push((index, value));
            }
            store.sync().await.unwrap();

            // Prune incrementally
            for i in 1..5 {
                let prune_index = i * 50 + 10;
                store.prune(prune_index).await.unwrap();

                // Verify appropriate data is pruned, exactly
                for (index, _) in &values {
                    if *index < prune_index {
                        assert!(!store.has(*index), "Index {index} should be pruned");
                    } else {
                        assert!(store.has(*index), "Index {index} should not be pruned");
                    }
                }
            }

            // Check final state: every prune advanced the boundary
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
    fn test_prune_removes_pending() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut store =
                Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None)
                    .await
                    .expect("Failed to initialize store");

            // Insert and sync some data
            store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
            store.sync().await.unwrap();

            // Add pending (unsynced) entries on both sides of the future boundary
            store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
            store.put(110, FixedBytes::new([110u8; 32])).await.unwrap();

            // Verify all data is visible before pruning
            assert!(store.has(5));
            assert!(store.has(10));
            assert!(store.has(110));

            // Prune up to index 50: synced and pending entries below it are removed.
            store.prune(50).await.unwrap();
            assert!(!store.has(5));
            assert!(!store.has(10));

            // The pending entry above the boundary remains.
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
    fn test_init_without_committed_deletes_existing_data() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with sparse data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
                store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
                store.put(9, FixedBytes::new([9u8; 32])).await.unwrap();
                store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
                store.put(15, FixedBytes::new([15u8; 32])).await.unwrap();
                store.put(25, FixedBytes::new([25u8; 32])).await.unwrap();

                store.sync().await.unwrap();
            }

            // Reinitialize with committed = None, deleting all stored data.
            {
                let store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("second"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                assert!(!store.has(0));
                assert!(!store.has(5));
                assert!(!store.has(9));
                assert!(!store.has(10));
                assert!(!store.has(15));
                assert!(!store.has(25));
                assert!(!store.has(1));
                assert!(!store.has(11));
                assert!(!store.has(20));
            }
        });
    }

    #[test_traced]
    fn test_init_empty_committed() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                store.put(0, FixedBytes::new([0u8; 32])).await.unwrap();
                store.put(10, FixedBytes::new([10u8; 32])).await.unwrap();
                store.put(20, FixedBytes::new([20u8; 32])).await.unwrap();

                store.sync().await.unwrap();
            }

            // Reinitialize with an empty set: a committed empty store. Stored records are
            // unreachable (but not physically removed).
            {
                let store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(RMap::new()),
                )
                .await
                .expect("Failed to initialize store");

                assert!(!store.has(0));
                assert!(!store.has(10));
                assert!(!store.has(20));
            }

            // Recovery trusts the caller's committed set: a later initialization naming the
            // stored records finds them again (nothing was removed).
            {
                let committed: RMap = [0u64].into_iter().collect();
                let store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("third"),
                    cfg.clone(),
                    Some(committed),
                )
                .await
                .expect("Failed to initialize store");
                assert!(store.has(0));
                assert!(!store.has(10));
            }
        });
    }

    #[test_traced]
    fn test_init_selective_indices() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with contiguous data
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                for i in 0..30 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                store.sync().await.unwrap();
            }

            // Reinitialize with a subset of the indices
            {
                let committed: RMap = [12u64, 15, 18].into_iter().collect();
                let store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(committed),
                )
                .await
                .expect("Failed to initialize store");

                // Only specified indices should be available
                assert!(store.has(12));
                assert!(store.has(15));
                assert!(store.has(18));

                // Other indices should not be available
                for i in (0..12).chain([13, 14, 16, 17]).chain(19..30) {
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

            // Reinitialize with a contiguous committed range
            {
                let committed: RMap = (5u64..10).collect();
                let store = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("third"),
                    cfg.clone(),
                    Some(committed),
                )
                .await
                .expect("Failed to initialize store");

                for i in 5..10 {
                    assert!(store.has(i));
                    assert_eq!(
                        store.get(i).await.unwrap().unwrap(),
                        FixedBytes::new([i as u8; 32])
                    );
                }
                assert!(!store.has(4));
                assert!(!store.has(10));
            }
        });
    }

    #[test_traced]
    fn test_init_missing_record() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with a hole at index 6
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                store.put(5, FixedBytes::new([5u8; 32])).await.unwrap();
                // Skip index 6
                store.put(7, FixedBytes::new([7u8; 32])).await.unwrap();
                store.put(8, FixedBytes::new([8u8; 32])).await.unwrap();
                store.put(9, FixedBytes::new([9u8; 32])).await.unwrap();

                store.sync().await.unwrap();
            }

            // Naming the hole fails initialization (the zeroed record fails its CRC)
            {
                let committed: RMap = (5u64..10).collect();
                let result = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(committed),
                )
                .await;
                assert!(matches!(result, Err(Error::MissingRecord(6))));
            }

            // Naming a record beyond the blob's size fails initialization
            {
                let committed: RMap = [10u64].into_iter().collect();
                let result = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("third"),
                    cfg.clone(),
                    Some(committed),
                )
                .await;
                assert!(matches!(result, Err(Error::MissingRecord(10))));
            }

            // Naming an unaddressable index fails initialization
            {
                let committed: RMap = [u64::MAX].into_iter().collect();
                let result = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("fourth"),
                    cfg.clone(),
                    Some(committed),
                )
                .await;
                assert!(matches!(result, Err(Error::MissingRecord(u64::MAX))));
            }
        });
    }

    #[test_traced]
    fn test_init_corrupted_records() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with data and corrupt one record
            {
                let mut store =
                    Ordinal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                for i in 0..5 {
                    store.put(i, FixedBytes::new([i as u8; 32])).await.unwrap();
                }

                store.sync().await.unwrap();
            }

            // Corrupt record at index 2
            {
                let (blob, _) = context.open("test-ordinal", BLOB_NAME).await.unwrap();
                // Corrupt the CRC of record at index 2
                let offset = 2 * 36 + 32; // 2 * record_size + value_size
                blob.write_at_sync(offset, vec![0xFF]).await.unwrap();
            }

            // Reinitialize naming the corrupted record
            {
                let committed: RMap = [0u64, 2, 4].into_iter().collect();
                let result = Ordinal::<_, FixedBytes<32>>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(committed),
                )
                .await;
                assert!(matches!(result, Err(Error::MissingRecord(2))));
            }
        });
    }

    /// A dummy value that will fail parsing if the value is 0.
    #[derive(Debug, PartialEq, Eq)]
    pub struct DummyValue {
        pub value: u64,
    }

    impl Write for DummyValue {
        fn write(&self, buf: &mut impl BufMut) {
            self.value.write(buf);
        }
    }

    impl Read for DummyValue {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            let value = u64::read(buf)?;
            if value == 0 {
                return Err(commonware_codec::Error::Invalid(
                    "DummyValue",
                    "value must be non-zero",
                ));
            }
            Ok(Self { value })
        }
    }

    impl FixedSize for DummyValue {
        const SIZE: usize = u64::SIZE;
    }

    #[test_traced]
    fn test_init_unparseable_record() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create store with records, including one that will fail to parse if recovered.
            {
                let mut store =
                    Ordinal::<_, DummyValue>::init(context.child("first"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                // Add records at indices 1, 2, 4
                store.put(1, DummyValue { value: 1 }).await.unwrap();
                store.put(2, DummyValue { value: 0 }).await.unwrap(); // will fail parsing
                store.put(4, DummyValue { value: 4 }).await.unwrap();

                store.sync().await.unwrap();
            }

            // Naming the unparseable record fails initialization.
            {
                let committed: RMap = [1u64, 2, 4].into_iter().collect();
                let result = Ordinal::<_, DummyValue>::init(
                    context.child("second"),
                    cfg.clone(),
                    Some(committed),
                )
                .await;
                assert!(matches!(result, Err(Error::MissingRecord(2))));
            }

            // Reinitialize without committed indices and verify uncommitted data is deleted.
            {
                let store =
                    Ordinal::<_, DummyValue>::init(context.child("third"), cfg.clone(), None)
                        .await
                        .expect("Failed to initialize store");

                assert!(!store.has(1));
                assert!(!store.has(2));
                assert!(!store.has(4));
            }
        });
    }
}
