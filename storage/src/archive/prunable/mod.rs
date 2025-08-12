//! A prunable key-value store for ordered data.
//!
//! Data is stored in [crate::journal::variable::Journal] (an append-only log) and the location of
//! written data is stored in-memory by both index and key (via [crate::index::Index]) to enable
//! **single-read lookups** for both query patterns over archived data.
//!
//! _Notably, [Archive] does not make use of compaction nor on-disk indexes (and thus has no read
//! nor write amplification during normal operation).
//!
//! # Format
//!
//! [Archive] stores data in the following format:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |12 |      ...      |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |          Index(u64)           |  Key(Fixed Size)  |     Data      |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! # Uniqueness
//!
//! [Archive] assumes all stored indexes and keys are unique. If the same key is associated with
//! multiple `indices`, there is no guarantee which value will be returned. If the key is written to
//! an existing `index`, [Archive] will return an error.
//!
//! ## Conflicts
//!
//! Because a translated representation of a key is only ever stored in memory, it is possible (and
//! expected) that two keys will eventually be represented by the same translated key. To handle this
//! case, [Archive] must check the persisted form of all conflicting keys to ensure data from the
//! correct key is returned. To support efficient checks, [Archive] (via [crate::index::Index])
//! keeps a linked list of all keys with the same translated prefix:
//!
//! ```rust
//! struct Record {
//!     index: u64,
//!
//!     next: Option<Box<Record>>,
//! }
//! ```
//!
//! _To avoid random memory reads in the common case, the in-memory index directly stores the first
//! item in the linked list instead of a pointer to the first item._
//!
//! `index` is the key to the map used to serve lookups by `index` that stores the location of data
//! in a given `Blob` (selected by `section = index & section_mask` to minimize the number of open
//! [crate::journal::variable::Journal]s):
//!
//! ```rust
//! struct Location {
//!     offset: u32,
//!     len: u32,
//! }
//! ```
//!
//! _If the [Translator] provided by the caller does not uniformly distribute keys across the key
//! space or uses a translated representation that means keys on average have many conflicts,
//! performance will degrade._
//!
//! ## Memory Overhead
//!
//! [Archive] uses two maps to enable lookups by both index and key. The memory used to track each
//! index item is `8 + 4 + 4` (where `8` is the index, `4` is the offset, and `4` is the length).
//! The memory used to track each key item is `~translated(key).len() + 16` bytes (where `16` is the
//! size of the `Record` struct). This means that an [Archive] employing a [Translator] that uses
//! the first `8` bytes of a key will use `~40` bytes to index each key.
//!
//! # Pruning
//!
//! [Archive] supports pruning up to a minimum `index` using the `prune` method. After `prune` is
//! called on a `section`, all interaction with a `section` less than the pruned `section` will
//! return an error.
//!
//! ## Lazy Index Cleanup
//!
//! Instead of performing a full iteration of the in-memory index, storing an additional in-memory
//! index per `section`, or replaying a `section` of [crate::journal::variable::Journal], [Archive]
//! lazily cleans up the [crate::index::Index] after pruning. When a new key is stored that overlaps
//! (same translated value) with a pruned key, the pruned key is removed from the in-memory index.
//!
//! # Single Operation Reads
//!
//! To enable single operation reads (i.e. reading all of an item in a single call to
//! [commonware_runtime::Blob]), [Archive] caches the length of each item in its in-memory index.
//! While it increases the footprint per key stored, the benefit of only ever performing a single
//! operation to read a key (when there are no conflicts) is worth the tradeoff.
//!
//! # Compression
//!
//! [Archive] supports compressing data before storing it on disk. This can be enabled by setting
//! the `compression` field in the `Config` struct to a valid `zstd` compression level. This setting
//! can be changed between initializations of [Archive], however, it must remain populated if any
//! data was written with compression enabled.
//!
//! # Querying for Gaps
//!
//! [Archive] tracks gaps in the index space to enable the caller to efficiently fetch unknown keys
//! using `next_gap`. This is a very common pattern when syncing blocks in a blockchain.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::PoolRef};
//! use commonware_cryptography::hash;
//! use commonware_storage::{
//!     translator::FourCap,
//!     archive::{
//!         Archive as _,
//!         prunable::{Archive, Config},
//!     },
//! };
//! use commonware_utils::{NZUsize, NZU64};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create an archive
//!     let cfg = Config {
//!         translator: FourCap,
//!         partition: "demo".into(),
//!         compression: Some(3),
//!         codec_config: (),
//!         items_per_section: NZU64!(1024),
//!         write_buffer: NZUsize!(1024 * 1024),
//!         replay_buffer: NZUsize!(4096),
//!         buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
//!     };
//!     let mut archive = Archive::init(context, cfg).await.unwrap();
//!
//!     // Put a key
//!     archive.put(1, hash(b"data"), 10).await.unwrap();
//!
//!     // Close the archive (also closes the journal)
//!     archive.close().await.unwrap();
//! });
//! ```

use crate::translator::Translator;
use commonware_runtime::buffer::PoolRef;
use std::num::{NonZeroU64, NonZeroUsize};

mod storage;
pub use storage::Archive;

/// Configuration for [Archive] storage.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// Logic to transform keys into their index representation.
    ///
    /// [Archive] assumes that all internal keys are spread uniformly across the key space.
    /// If that is not the case, lookups may be O(n) instead of O(1).
    pub translator: T,

    /// The partition to use for the archive's [crate::journal] storage.
    pub partition: String,

    /// The compression level to use for the archive's [crate::journal] storage.
    pub compression: Option<u8>,

    /// The [commonware_codec::Codec] configuration to use for the value stored in the archive.
    pub codec_config: C,

    /// The number of items per section (the granularity of pruning).
    pub items_per_section: NonZeroU64,

    /// The amount of bytes that can be buffered in a section before being written to a
    /// [commonware_runtime::Blob].
    pub write_buffer: NonZeroUsize,

    /// The buffer size to use when replaying a [commonware_runtime::Blob].
    pub replay_buffer: NonZeroUsize,

    /// The buffer pool to use for the archive's [crate::journal] storage.
    pub buffer_pool: PoolRef,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive::{Archive as _, Error, Identifier},
        journal::Error as JournalError,
        translator::{FourCap, TwoCap},
    };
    use commonware_codec::{varint::UInt, DecodeExt, EncodeSize, Error as CodecError};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
    use rand::Rng;
    use std::collections::BTreeMap;

    const DEFAULT_ITEMS_PER_SECTION: u64 = 65536;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_REPLAY_BUFFER: usize = 4096;
    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    #[test_traced]
    fn test_archive_compression_then_none() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: Some(3),
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
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

            // Initialize the archive again without compression
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let result = Archive::<_, _, FixedBytes<64>, i32>::init(context, cfg.clone()).await;
            assert!(matches!(
                result,
                Err(Error::Journal(JournalError::Codec(CodecError::EndOfBuffer)))
            ));
        });
    }

    #[test_traced]
    fn test_archive_record_corruption() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index = 1u64;
            let key = test_key("testkey");
            let data = 1;

            // Put the key-data pair
            archive
                .put(index, key.clone(), data)
                .await
                .expect("Failed to put data");

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Corrupt the value
            let section = (index / DEFAULT_ITEMS_PER_SECTION) * DEFAULT_ITEMS_PER_SECTION;
            let (blob, _) = context
                .open("test_partition", &section.to_be_bytes())
                .await
                .unwrap();
            let value_location = 4 /* journal size */ + UInt(1u64).encode_size() as u64 /* index */ + 64 + 4 /* value length */;
            blob.write_at(b"testdaty".to_vec(), value_location).await.unwrap();
            blob.sync().await.unwrap();

            // Initialize the archive again
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(
                context,
                Config {
                    partition: "test_partition".into(),
                    translator: FourCap,
                    codec_config: (),
                    compression: None,
                    write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                    replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                    items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await.expect("Failed to initialize archive");

            // Check that the archive is empty
            let retrieved: Option<i32> = archive
                .get(Identifier::Index(index))
                .await
                .expect("Failed to get data");
            assert!(retrieved.is_none());
        });
    }

    #[test_traced]
    fn test_archive_overlapping_key_basic() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index1 = 1u64;
            let key1 = test_key("keys1");
            let data1 = 1;
            let index2 = 2u64;
            let key2 = test_key("keys2");
            let data2 = 2;

            // Put the key-data pair
            archive
                .put(index1, key1.clone(), data1)
                .await
                .expect("Failed to put data");

            // Put the key-data pair
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

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(&key2))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("items_tracked 2"));
            assert!(buffer.contains("unnecessary_reads_total 1"));
            assert!(buffer.contains("gets_total 2"));
        });
    }

    #[test_traced]
    fn test_archive_overlapping_key_multiple_sections() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index1 = 1u64;
            let key1 = test_key("keys1");
            let data1 = 1;
            let index2 = 2_000_000u64;
            let key2 = test_key("keys2");
            let data2 = 2;

            // Put the key-data pair
            archive
                .put(index1, key1.clone(), data1)
                .await
                .expect("Failed to put data");

            // Put the key-data pair
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

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(&key2))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);
        });
    }

    #[test_traced]
    fn test_archive_prune_keys() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(1), // no mask - each item is its own section
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
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
            assert!(buffer.contains("items_tracked 5"));

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

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("items_tracked 3"));
            assert!(buffer.contains("indices_pruned_total 2"));
            assert!(buffer.contains("pruned_total 0")); // no lazy cleanup yet

            // Try to prune older section
            archive.prune(2).await.expect("Failed to prune");

            // Try to prune current section again
            archive.prune(3).await.expect("Failed to prune");

            // Try to put older index
            let result = archive.put(1, test_key("key1-blah"), 1).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedTo(3))));

            // Trigger lazy removal of keys
            archive
                .put(6, test_key("key2-blfh"), 5)
                .await
                .expect("Failed to put data");

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("items_tracked 4")); // lazily remove one, add one
            assert!(buffer.contains("indices_pruned_total 2"));
            assert!(buffer.contains("pruned_total 1"));
        });
    }

    fn test_archive_keys_and_restart(num_keys: usize) -> String {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Initialize the archive
            let items_per_section = 256u64;
            let cfg = Config {
                partition: "test_partition".into(),
                translator: TwoCap,
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(items_per_section),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
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
            assert!(buffer.contains(&tracked));
            assert!(buffer.contains("pruned_total 0"));

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Reinitialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: TwoCap,
                codec_config: (),
                compression: None,
                write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(items_per_section),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut archive =
                Archive::<_, _, _, FixedBytes<1024>>::init(context.clone(), cfg.clone())
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

            // Check metrics
            let buffer = context.encode();
            let tracked = format!("items_tracked {:?}", num_keys - removed);
            assert!(buffer.contains(&tracked));
            let pruned = format!("indices_pruned_total {removed}");
            assert!(buffer.contains(&pruned));
            assert!(buffer.contains("pruned_total 0")); // have not lazily removed keys yet

            context.auditor().state()
        })
    }

    #[test_traced]
    #[ignore]
    fn test_archive_many_keys_and_restart() {
        test_archive_keys_and_restart(100_000);
    }

    #[test_traced]
    #[ignore]
    fn test_determinism() {
        let state1 = test_archive_keys_and_restart(5_000);
        let state2 = test_archive_keys_and_restart(5_000);
        assert_eq!(state1, state2);
    }
}
