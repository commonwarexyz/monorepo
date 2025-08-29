//! A prunable cache for ordered data with index-based lookups.
//!
//! Data is stored in [crate::journal::variable::Journal] (an append-only log) and the location of
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
//! return an error. The pruning granularity is determined by `items_per_section` in the configuration.
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
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::PoolRef};
//! use commonware_storage::cache::{Cache, Config};
//! use commonware_utils::{NZUsize, NZU64};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a cache
//!     let cfg = Config {
//!         partition: "cache".into(),
//!         compression: Some(3),
//!         codec_config: (),
//!         items_per_section: NZU64!(1024),
//!         write_buffer: NZUsize!(1024 * 1024),
//!         replay_buffer: NZUsize!(4096),
//!         buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
//!     };
//!     let mut cache = Cache::init(context, cfg).await.unwrap();
//!
//!     // Put data at index
//!     cache.put(1, "cached_data").await.unwrap();
//!
//!     // Get data by index
//!     let data: Option<&str> = cache.get(1).await.unwrap();
//!     assert_eq!(data, Some("cached_data"));
//!
//!     // Close the cache (also closes the journal)
//!     cache.close().await.unwrap();
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
    pub items_per_section: NonZeroU64,

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
    use commonware_codec::{varint::UInt, EncodeSize};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::{NZUsize, NZU64};
    use rand::Rng;
    use std::collections::BTreeMap;

    const DEFAULT_ITEMS_PER_SECTION: u64 = 65536;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_REPLAY_BUFFER: usize = 4096;
    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
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
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            // Put the data
            let index = 1u64;
            let data = 1;
            cache.put(index, data).await.expect("Failed to put data");

            // Close the cache
            cache.close().await.expect("Failed to close cache");

            // Initialize the cache again without compression
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
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
    fn test_cache_record_corruption() {
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
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut cache = Cache::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache");

            let index = 1u64;
            let data = 1;

            // Put the data
            cache
                .put(index, data)
                .await
                .expect("Failed to put data");

            // Close the cache
            cache.close().await.expect("Failed to close cache");

            // Corrupt the value
            let section = (index / DEFAULT_ITEMS_PER_SECTION) * DEFAULT_ITEMS_PER_SECTION;
            let (blob, _) = context
                .open("test_partition", &section.to_be_bytes())
                .await
                .unwrap();
            let value_location = 4 /* journal size */ + UInt(1u64).encode_size() as u64 /* index */ + 4 /* value length */;
            blob.write_at(b"testdaty".to_vec(), value_location).await.unwrap();
            blob.sync().await.unwrap();

            // Initialize the cache again
            let cache = Cache::<_, i32>::init(
                context,
                Config {
                    partition: "test_partition".into(),
                    codec_config: (),
                    compression: None,
                    write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                    replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                    items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await.expect("Failed to initialize cache");

            // Check that the cache is empty
            let retrieved: Option<i32> = cache
                .get(index)
                .await
                .expect("Failed to get data");
            assert!(retrieved.is_none());
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
                items_per_section: NZU64!(1), // no mask - each item is its own section
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

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("items_tracked 3"));

            // Try to prune older section
            cache.prune(2).await.expect("Failed to prune");

            // Try to prune current section again
            cache.prune(3).await.expect("Failed to prune");

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
            let items_per_section = 256u64;
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(items_per_section),
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

            // Close the cache
            cache.close().await.expect("Failed to close cache");

            // Reinitialize the cache
            let cfg = Config {
                partition: "test_partition".into(),
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(items_per_section),
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
            let min = (min / items_per_section) * items_per_section;
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

    #[test_traced]
    #[ignore]
    fn test_cache_many_items_and_restart() {
        test_cache_restart(100_000);
    }

    #[test_traced]
    #[ignore]
    fn test_determinism() {
        let state1 = test_cache_restart(5_000);
        let state2 = test_cache_restart(5_000);
        assert_eq!(state1, state2);
    }
}
