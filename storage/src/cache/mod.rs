//! A prunable cache for ordered data with index-based lookups.
//!
//! Data is stored in [crate::journal::segmented::variable::Journal] (an append-only log) and the location of
//! written data is tracked in-memory by index to enable **single-read lookups** for cached data.
//!
//! Unlike [crate::archive::Archive], the [Cache] is optimized for simplicity and does
//! not support key-based lookups (only index-based access is provided). This makes it ideal for
//! caching sequential data where you know the exact index of the item you want to retrieve.
//!
//! # Memory Overhead
//!
//! [Cache] maintains a single in-memory map to track the location of each index item. The memory
//! used to track each item is `8 + 4 + 4` bytes (where `8` is the index, `4` is the offset, and
//! `4` is the length). This results in approximately `16` bytes of memory overhead per cached item.
//!
//! # Pruning
//!
//! [Cache] supports pruning up to a minimum `index` using the `prune` method. After `prune` is
//! called on a `section`, all interaction with a `section` less than the pruned `section` will
//! return an error. The pruning granularity is determined by `items_per_blob` in the configuration.
//!
//! # Single Operation Reads
//!
//! To enable single operation reads (i.e. reading all of an item in a single call to
//! [commonware_runtime::Blob]), [Cache] stores the length of each item in its in-memory index.
//! This ensures that reading a cached item requires only one disk operation.
//!
//! # Compression
//!
//! [Cache] supports compressing data before storing it on disk. This can be enabled by setting
//! the `compression` field in the `Config` struct to a valid `zstd` compression level. This setting
//! can be changed between initializations of [Cache], however, it must remain populated if any
//! data was written with compression enabled.
//!
//! # Querying for Gaps
//!
//! [Cache] tracks gaps in the index space to enable the caller to efficiently fetch unknown keys
//! using `next_gap`. This is a very common pattern when syncing blocks in a blockchain.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::PoolRef};
//! use commonware_storage::cache::{Cache, Config};
//! use commonware_utils::{NZUsize, NZU16, NZU64};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a cache
//!     let cfg = Config {
//!         partition: "cache".into(),
//!         compression: Some(3),
//!         codec_config: (),
//!         items_per_blob: NZU64!(1024),
//!         write_buffer: NZUsize!(1024 * 1024),
//!         replay_buffer: NZUsize!(4096),
//!         buffer_pool: PoolRef::new(NZU16!(1024), NZUsize!(10)),
//!     };
//!     let mut cache = Cache::init(context, cfg).await.unwrap();
//!
//!     // Put data at index
//!     cache.put(1, 100u32).await.unwrap();
//!
//!     // Get data by index
//!     let data: Option<u32> = cache.get(1).await.unwrap();
//!     assert_eq!(data, Some(100));
//!
//!     // Check for gaps in the index space
//!     cache.put(10, 200u32).await.unwrap();
//!     let (current_end, start_next) = cache.next_gap(5);
//!     assert!(current_end.is_none());
//!     assert_eq!(start_next, Some(10));
//!
//!     // Sync the cache
//!     cache.sync().await.unwrap();
//! });
//! ```

use commonware_runtime::buffer::PoolRef;
use std::num::{NonZeroU64, NonZeroUsize};
use thiserror::Error;

mod storage;
pub use storage::Cache;

/// Errors that can occur when interacting with the cache.
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("record corrupted")]
    RecordCorrupted,
    #[error("already pruned to: {0}")]
    AlreadyPrunedTo(u64),
    #[error("record too large")]
    RecordTooLarge,
}

/// Configuration for [Cache] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for the cache's [crate::journal] storage.
    pub partition: String,

    /// The compression level to use for the cache's [crate::journal] storage.
    pub compression: Option<u8>,

    /// The [commonware_codec::Codec] configuration to use for the value stored in the cache.
    pub codec_config: C,

    /// The number of items per section (the granularity of pruning).
    pub items_per_blob: NonZeroU64,

    /// The amount of bytes that can be buffered in a section before being written to a
    /// [commonware_runtime::Blob].
    pub write_buffer: NonZeroUsize,

    /// The buffer size to use when replaying a [commonware_runtime::Blob].
    pub replay_buffer: NonZeroUsize,

    /// The buffer pool to use for the cache's [crate::journal] storage.
    pub buffer_pool: PoolRef,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Error as JournalError;
    use commonware_macros::{test_group, test_traced};
    use commonware_runtime::{deterministic, Metrics, Runner};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::Rng;
    use std::{collections::BTreeMap, num::NonZeroU16};

    const DEFAULT_ITEMS_PER_BLOB: u64 = 65536;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_REPLAY_BUFFER: usize = 4096;
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    #[test_traced]
    fn test_cache_compression_then_none() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the cache
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: Some(3),
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(DEFAULT_ITEMS_PER_BLOB),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Put the data
            let index = 1u64;
            let data = 1;
            cache.put(index, data).await.expect("Failed to put data");

            // Sync and drop the cache
            cache.sync().await.expect("Failed to sync cache");
            drop(cache);

            // Initialize the cache again without compression
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(DEFAULT_ITEMS_PER_BLOB),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let result = Cache::<_, i32>::init(context, cfg.clone()).await;
            assert!(matches!(
                result,
                Err(Error::Journal(JournalError::Codec(_)))
            ));
        });
    }

    #[test_traced]
    fn test_cache_prune() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the cache
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(1), // no mask - each item is its own section
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Insert multiple items across different sections
            let items = vec![(1u64, 1), (2u64, 2), (3u64, 3), (4u64, 4), (5u64, 5)];
            for (index, data) in &items {
                cache.put(*index, *data).await.expect("Failed to put data");
            }
            assert_eq!(cache.first(), Some(1));

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("items_tracked 5"));

            // Prune sections less than 3
            cache.prune(3).await.expect("Failed to prune");

            // Ensure items 1 and 2 are no longer present
            for (index, data) in items {
                let retrieved = cache.get(index).await.expect("Failed to get data");
                if index < 3 {
                    assert!(retrieved.is_none());
                } else {
                    assert_eq!(retrieved.expect("Data not found"), data);
                }
            }
            assert_eq!(cache.first(), Some(3));

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("items_tracked 3"));

            // Try to prune older section
            cache.prune(2).await.expect("Failed to prune");
            assert_eq!(cache.first(), Some(3));

            // Try to prune current section again
            cache.prune(3).await.expect("Failed to prune");
            assert_eq!(cache.first(), Some(3));

            // Try to put older index
            let result = cache.put(1, 1).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedTo(3))));
        });
    }

    fn test_cache_restart(num_items: usize) -> String {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Initialize the cache
            let items_per_blob = 256u64;
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(items_per_blob),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Insert multiple items
            let mut items = BTreeMap::new();
            while items.len() < num_items {
                let index = items.len() as u64;
                let mut data = [0u8; 1024];
                context.fill(&mut data);
                items.insert(index, data);

                cache.put(index, data).await.expect("Failed to put data");
            }

            // Ensure all items can be retrieved
            for (index, data) in &items {
                let retrieved = cache
                    .get(*index)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);
            }

            // Check metrics
            let buffer = context.encode();
            let tracked = format!("items_tracked {num_items:?}");
            assert!(buffer.contains(&tracked));

            // Sync and drop the cache
            cache.sync().await.expect("Failed to sync cache");
            drop(cache);

            // Reinitialize the cache
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(items_per_blob),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::<_, [u8; 1024]>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Ensure all items can be retrieved
            for (index, data) in &items {
                let retrieved = cache
                    .get(*index)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
            }

            // Prune first half
            let min = (items.len() / 2) as u64;
            cache.prune(min).await.expect("Failed to prune");

            // Ensure all items can be retrieved that haven't been pruned
            let min = (min / items_per_blob) * items_per_blob;
            let mut removed = 0;
            for (index, data) in items {
                if index >= min {
                    let retrieved = cache
                        .get(index)
                        .await
                        .expect("Failed to get data")
                        .expect("Data not found");
                    assert_eq!(retrieved, data);
                } else {
                    let retrieved = cache.get(index).await.expect("Failed to get data");
                    assert!(retrieved.is_none());
                    removed += 1;
                }
            }

            // Check metrics
            let buffer = context.encode();
            let tracked = format!("items_tracked {:?}", num_items - removed);
            assert!(buffer.contains(&tracked));

            context.auditor().state()
        })
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_cache_many_items_and_restart() {
        test_cache_restart(100_000);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_determinism() {
        let state1 = test_cache_restart(5_000);
        let state2 = test_cache_restart(5_000);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_cache_next_gap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(DEFAULT_ITEMS_PER_BLOB),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Check first
            assert_eq!(cache.first(), None);

            // Insert values with gaps
            cache.put(1, 1).await.unwrap();
            cache.put(10, 10).await.unwrap();
            cache.put(11, 11).await.unwrap();
            cache.put(14, 14).await.unwrap();

            // Check gaps
            let (current_end, start_next) = cache.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(1));
            assert_eq!(cache.first(), Some(1));

            let (current_end, start_next) = cache.next_gap(1);
            assert_eq!(current_end, Some(1));
            assert_eq!(start_next, Some(10));

            let (current_end, start_next) = cache.next_gap(10);
            assert_eq!(current_end, Some(11));
            assert_eq!(start_next, Some(14));

            let (current_end, start_next) = cache.next_gap(11);
            assert_eq!(current_end, Some(11));
            assert_eq!(start_next, Some(14));

            let (current_end, start_next) = cache.next_gap(12);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(14));

            let (current_end, start_next) = cache.next_gap(14);
            assert_eq!(current_end, Some(14));
            assert!(start_next.is_none());
        });
    }

    #[test_traced]
    fn test_cache_missing_items() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(DEFAULT_ITEMS_PER_BLOB),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Test 1: Empty cache - should return no items
            assert_eq!(cache.first(), None);
            assert_eq!(cache.missing_items(0, 5), Vec::<u64>::new());
            assert_eq!(cache.missing_items(100, 10), Vec::<u64>::new());

            // Test 2: Insert values with gaps
            cache.put(1, 1).await.unwrap();
            cache.put(2, 2).await.unwrap();
            cache.put(5, 5).await.unwrap();
            cache.put(6, 6).await.unwrap();
            cache.put(10, 10).await.unwrap();

            // Test 3: Find missing items from the beginning
            assert_eq!(cache.missing_items(0, 5), vec![0, 3, 4, 7, 8]);
            assert_eq!(cache.missing_items(0, 6), vec![0, 3, 4, 7, 8, 9]);
            assert_eq!(cache.missing_items(0, 7), vec![0, 3, 4, 7, 8, 9]);

            // Test 4: Find missing items from within a gap
            assert_eq!(cache.missing_items(3, 3), vec![3, 4, 7]);
            assert_eq!(cache.missing_items(4, 2), vec![4, 7]);

            // Test 5: Find missing items from within a range
            assert_eq!(cache.missing_items(1, 3), vec![3, 4, 7]);
            assert_eq!(cache.missing_items(2, 4), vec![3, 4, 7, 8]);
            assert_eq!(cache.missing_items(5, 2), vec![7, 8]);

            // Test 6: Find missing items after the last range (no more gaps)
            assert_eq!(cache.missing_items(11, 5), Vec::<u64>::new());
            assert_eq!(cache.missing_items(100, 10), Vec::<u64>::new());

            // Test 7: Large gap scenario
            cache.put(1000, 1000).await.unwrap();

            // Gap between 10 and 1000
            let items = cache.missing_items(11, 10);
            assert_eq!(items, vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);

            // Request more items than available in gap
            let items = cache.missing_items(990, 15);
            assert_eq!(
                items,
                vec![990, 991, 992, 993, 994, 995, 996, 997, 998, 999]
            );

            // Test 8: After syncing (data should remain consistent)
            cache.sync().await.unwrap();
            assert_eq!(cache.missing_items(0, 5), vec![0, 3, 4, 7, 8]);
            assert_eq!(cache.missing_items(3, 3), vec![3, 4, 7]);

            // Test 9: Cross-section boundary scenario
            cache.put(DEFAULT_ITEMS_PER_BLOB - 1, 99).await.unwrap();
            cache.put(DEFAULT_ITEMS_PER_BLOB + 1, 101).await.unwrap();

            // Find missing items across section boundary
            let items = cache.missing_items(DEFAULT_ITEMS_PER_BLOB - 2, 5);
            assert_eq!(
                items,
                vec![DEFAULT_ITEMS_PER_BLOB - 2, DEFAULT_ITEMS_PER_BLOB]
            );
        });
    }

    #[test_traced]
    fn test_cache_intervals_after_restart() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(DEFAULT_ITEMS_PER_BLOB),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Insert data and sync
            {
                let mut cache = Cache::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize cache");

                cache.put(0, 0).await.expect("Failed to put data");
                cache.put(100, 100).await.expect("Failed to put data");
                cache.put(1000, 1000).await.expect("Failed to put data");

                cache.sync().await.expect("Failed to sync cache");
            }

            // Reopen and verify intervals are preserved
            {
                let cache = Cache::<_, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize cache");

                // Check gaps are preserved
                let (current_end, start_next) = cache.next_gap(0);
                assert_eq!(current_end, Some(0));
                assert_eq!(start_next, Some(100));

                let (current_end, start_next) = cache.next_gap(100);
                assert_eq!(current_end, Some(100));
                assert_eq!(start_next, Some(1000));

                // Check missing items
                let items = cache.missing_items(1, 5);
                assert_eq!(items, vec![1, 2, 3, 4, 5]);
            }
        });
    }

    #[test_traced]
    fn test_cache_intervals_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(100), // Smaller sections for easier testing
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Insert values across multiple sections
            cache.put(50, 50).await.unwrap();
            cache.put(150, 150).await.unwrap();
            cache.put(250, 250).await.unwrap();
            cache.put(350, 350).await.unwrap();

            // Check gaps before pruning
            let (current_end, start_next) = cache.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(50));

            // Prune sections less than 200
            cache.prune(200).await.expect("Failed to prune");

            // Check that pruned indices are not accessible
            assert!(!cache.has(50));
            assert!(!cache.has(150));

            // Check gaps after pruning - should not include pruned ranges
            let (current_end, start_next) = cache.next_gap(200);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(250));

            // Missing items should not include pruned ranges
            let items = cache.missing_items(200, 5);
            assert_eq!(items, vec![200, 201, 202, 203, 204]);

            // Verify remaining data is still accessible
            assert!(cache.has(250));
            assert!(cache.has(350));
            assert_eq!(cache.get(250).await.unwrap(), Some(250));
            assert_eq!(cache.get(350).await.unwrap(), Some(350));
        });
    }

    #[test_traced]
    fn test_cache_sparse_indices() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(100), // Smaller sections for testing
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Insert sparse values
            let indices = vec![
                (0u64, 0),
                (99u64, 99),   // End of first section
                (100u64, 100), // Start of second section
                (500u64, 500), // Start of sixth section
            ];

            for (index, value) in &indices {
                cache.put(*index, *value).await.expect("Failed to put data");
            }

            // Check that intermediate indices don't exist
            assert!(!cache.has(1));
            assert!(!cache.has(50));
            assert!(!cache.has(101));
            assert!(!cache.has(499));

            // Verify gap detection works correctly
            let (current_end, start_next) = cache.next_gap(50);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(99));

            let (current_end, start_next) = cache.next_gap(99);
            assert_eq!(current_end, Some(100));
            assert_eq!(start_next, Some(500));

            // Sync and verify
            cache.sync().await.expect("Failed to sync");

            for (index, value) in &indices {
                let retrieved = cache
                    .get(*index)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *value);
            }
        });
    }

    #[test_traced]
    fn test_cache_intervals_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(DEFAULT_ITEMS_PER_BLOB),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Test edge case: single item
            cache.put(42, 42).await.unwrap();

            let (current_end, start_next) = cache.next_gap(42);
            assert_eq!(current_end, Some(42));
            assert!(start_next.is_none());

            let (current_end, start_next) = cache.next_gap(41);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(42));

            let (current_end, start_next) = cache.next_gap(43);
            assert!(current_end.is_none());
            assert!(start_next.is_none());

            // Test edge case: consecutive items
            cache.put(43, 43).await.unwrap();
            cache.put(44, 44).await.unwrap();

            let (current_end, start_next) = cache.next_gap(42);
            assert_eq!(current_end, Some(44));
            assert!(start_next.is_none());

            // Test edge case: boundary values
            cache.put(u64::MAX - 1, 999).await.unwrap();

            let (current_end, start_next) = cache.next_gap(u64::MAX - 2);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(u64::MAX - 1));

            let (current_end, start_next) = cache.next_gap(u64::MAX - 1);
            assert_eq!(current_end, Some(u64::MAX - 1));
            assert!(start_next.is_none());
        });
    }

    #[test_traced]
    fn test_cache_intervals_duplicate_inserts() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_blob: NZU64!(DEFAULT_ITEMS_PER_BLOB),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Insert initial value
            cache.put(10, 10).await.unwrap();
            assert!(cache.has(10));
            assert_eq!(cache.get(10).await.unwrap(), Some(10));

            // Try to insert duplicate - should be no-op
            cache.put(10, 20).await.unwrap();
            assert!(cache.has(10));
            assert_eq!(cache.get(10).await.unwrap(), Some(10)); // Should still be original value

            // Verify intervals are correct
            let (current_end, start_next) = cache.next_gap(10);
            assert_eq!(current_end, Some(10));
            assert!(start_next.is_none());

            // Insert adjacent values
            cache.put(9, 9).await.unwrap();
            cache.put(11, 11).await.unwrap();

            // Verify intervals updated correctly
            let (current_end, start_next) = cache.next_gap(9);
            assert_eq!(current_end, Some(11));
            assert!(start_next.is_none());
        });
    }
}
