//! A write-once key-value store optimized for low-latency reads.
//!
//! `Archive` is a key-value store designed for workloads where all data is written only once and is
//! uniquely associated with both an `index` and a `key`.
//!
//! Data is stored in `Journal` (an append-only log) and the location of written data is stored
//! in-memory by both index and key (translated representation using a caller-provided `Translator`)
//! to enable **single-read lookups** for both query patterns over all archived data.
//!
//! _Notably, `Archive` does not make use of compaction nor on-disk indexes (and thus has no read
//! nor write amplification during normal operation)._
//!
//! # Format
//!
//! `Archive` stores data in the following format:
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
//! `Archive` assumes all stored indexes and keys are unique. If the same key is associated with
//! multiple `indices`, there is no guarantee which value will be returned. If the key is written to
//! an existing `index`, `Archive` will return an error.
//!
//! ## Conflicts
//!
//! Because a translated representation of a key is only ever stored in memory, it is possible (and
//! expected) that two keys will eventually be represented by the same translated key. To handle this
//! case, `Archive` must check the persisted form of all conflicting keys to ensure data from the
//! correct key is returned. To support efficient checks, `Archive` (via [Index](crate::index::Index))
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
//! `Journals`):
//!
//! ```rust
//! struct Location {
//!     offset: u32,
//!     len: u32,
//! }
//! ```
//!
//! _If the `Translator` provided by the caller does not uniformly distribute keys across the key
//! space or uses a translated representation that means keys on average have many conflicts,
//! performance will degrade._
//!
//! ## Memory Overhead
//!
//! `Archive` uses two maps to enable lookups by both index and key. The memory used to track each
//! index item is `8 + 4 + 4` (where `8` is the index, `4` is the offset, and `4` is the length).
//! The memory used to track each key item is `~translated(key).len() + 16` bytes (where `16` is the
//! size of the `Record` struct). This means that an `Archive` employing a `Translator` that uses
//! the first `8` bytes of a key will use `~40` bytes to index each key.
//!
//! # Sync
//!
//! `Archive` flushes writes in a given `section` (computed by `index & section_mask`) to `Storage`
//! after `pending_writes`. If the caller requires durability on a particular write, they can call
//! `sync`.
//!
//! # Pruning
//!
//! `Archive` supports pruning up to a minimum `index` using the `prune` method. After `prune` is
//! called on a `section`, all interaction with a `section` less than the pruned `section` will
//! return an error.
//!
//! ## Lazy Index Cleanup
//!
//! Instead of performing a full iteration of the in-memory index, storing an additional in-memory
//! index per `section`, or replaying a `section` of `Journal`, `Archive` lazily cleans up the
//! in-memory index after pruning. When a new key is stored that overlaps (same translated value)
//! with a pruned key, the pruned key is removed from the in-memory index.
//!
//! # Single Operation Reads
//!
//! To enable single operation reads (i.e. reading all of an item in a single call to `Blob`),
//! `Archive` caches the length of each item in its in-memory index. While it increases the
//! footprint per key stored, the benefit of only ever performing a single operation to read a key
//! (when there are no conflicts) is worth the tradeoff.
//!
//! # Compression
//!
//! `Archive` supports compressing data before storing it on disk. This can be enabled by setting
//! the `compression` field in the `Config` struct to a valid `zstd` compression level. This setting
//! can be changed between initializations of `Archive`, however, it must remain populated if any
//! data was written with compression enabled.
//!
//! # Querying for Gaps
//!
//! `Archive` tracks gaps in the index space to enable the caller to efficiently fetch unknown keys
//! using `next_gap`. This is a very common pattern when syncing blocks in a blockchain.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_cryptography::hash;
//! use commonware_storage::{
//!     index::translator::FourCap,
//!     archive::{Archive, Config},
//! };
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create an archive
//!     let cfg = Config {
//!         translator: FourCap,
//!         partition: "demo".into(),
//!         compression: Some(3),
//!         codec_config: (),
//!         section_mask: 0xffff_ffff_ffff_0000u64,
//!         pending_writes: 10,
//!         write_buffer: 1024 * 1024,
//!         replay_concurrency: 4,
//!         replay_buffer: 4096,
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

mod storage;
pub use storage::{Archive, Identifier};

pub use crate::index::Translator;
use thiserror::Error;

/// Errors that can occur when interacting with the archive.
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

/// Configuration for `Archive` storage.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// Logic to transform keys into their index representation.
    ///
    /// `Archive` assumes that all internal keys are spread uniformly across the key space.
    /// If that is not the case, lookups may be O(n) instead of O(1).
    pub translator: T,

    /// The partition to use for the archive's [crate::journal] storage.
    pub partition: String,

    /// The compression level to use for the archive's [crate::journal] storage.
    pub compression: Option<u8>,

    /// The codec configuration to use for the value stored in the archive.
    pub codec_config: C,

    /// Mask to apply to indices to determine section.
    ///
    /// This value is `index & section_mask`.
    pub section_mask: u64,

    /// The number of writes to buffer in a section before forcing a sync in the journal.
    ///
    /// If set to 0, the journal will be synced each time a new item is stored.
    pub pending_writes: usize,

    /// The amount of bytes that can be buffered in a section before being written to disk.
    pub write_buffer: usize,

    /// The number of blobs to replay concurrently on initialization.
    pub replay_concurrency: usize,

    /// The buffer size to use when replaying a blob.
    pub replay_buffer: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::translator::{FourCap, TwoCap};
    use crate::journal::Error as JournalError;
    use commonware_codec::varint::UInt;
    use commonware_codec::{DecodeExt, EncodeSize, Error as CodecError};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::array::FixedBytes;
    use rand::Rng;
    use std::collections::BTreeMap;

    const DEFAULT_SECTION_MASK: u64 = 0xffff_ffff_ffff_0000u64;
    const DEFAULT_PENDING_WRITES: usize = 10;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_REPLAY_CONCURRENCY: usize = 4;
    const DEFAULT_REPLAY_BUFFER: usize = 4096;

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
                partition: "test_partition".into(),
                translator: FourCap,
                compression,
                codec_config: (),
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
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
            assert!(buffer.contains("items_tracked 1"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 4")); // has for a key is just a get
            assert!(buffer.contains("has_total 4"));
            assert!(buffer.contains("syncs_total 0"));

            // Force a sync
            archive.sync().await.expect("Failed to sync data");

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("items_tracked 1"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 4"));
            assert!(buffer.contains("has_total 4"));
            assert!(buffer.contains("syncs_total 1"));
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
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: DEFAULT_SECTION_MASK,
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
                pending_writes: 10,
                write_buffer: 1024,
                replay_concurrency: 4,
                replay_buffer: 4096,
                section_mask: DEFAULT_SECTION_MASK,
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
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: DEFAULT_SECTION_MASK,
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
            let section = index & DEFAULT_SECTION_MASK;
            let (blob, _) = context
                .open("test_partition", &section.to_be_bytes())
                .await
                .unwrap();
            let value_location = 4 /* journal size */ + UInt(1u64).encode_size() as u64 /* index */ + 64 + 4 /* value length */;
            blob.write_at(b"testdaty".to_vec(), value_location).await.unwrap();
            blob.close().await.unwrap();

            // Initialize the archive again
            let result = Archive::<_, _, FixedBytes<64>, i32>::init(
                context,
                Config {
                    partition: "test_partition".into(),
                    translator: FourCap,
                    codec_config: (),
                    compression: None,
                    pending_writes: DEFAULT_PENDING_WRITES,
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                    replay_buffer: DEFAULT_REPLAY_BUFFER,
                    section_mask: DEFAULT_SECTION_MASK,
                },
            )
            .await;
            assert!(matches!(
                result,
                Err(Error::Journal(JournalError::ChecksumMismatch(_, _)))
            ));
        });
    }

    #[test_traced]
    fn test_archive_duplicate_key() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: None,
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
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

            // Put the key-data pair again
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
            assert!(buffer.contains("items_tracked 1"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 2"));
        });
    }

    #[test_traced]
    fn test_archive_get_nonexistent() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: None,
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let archive = Archive::init(context.clone(), cfg.clone())
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
            assert!(buffer.contains("items_tracked 0"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 2"));
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
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: DEFAULT_SECTION_MASK,
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
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: DEFAULT_SECTION_MASK,
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
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: 0xffff_ffff_ffff_ffffu64, // no mask
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
            let section_mask = 0xffff_ffff_ffff_ff00u64;
            let cfg = Config {
                partition: "test_partition".into(),
                translator: TwoCap,
                codec_config: (),
                compression: None,
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask,
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
            let tracked = format!("items_tracked {:?}", num_keys);
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
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask,
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
            let min = min & section_mask;
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
            let pruned = format!("indices_pruned_total {}", removed);
            assert!(buffer.contains(&pruned));
            assert!(buffer.contains("pruned_total 0")); // have not lazily removed keys yet

            context.auditor().state()
        })
    }

    #[test_traced]
    #[ignore]
    fn test_archive_many_keys_and_restart() {
        test_archive_keys_and_restart(100_000); // 391 sections
    }

    #[test_traced]
    #[ignore]
    fn test_determinism() {
        let state1 = test_archive_keys_and_restart(5_000); // 20 sections
        let state2 = test_archive_keys_and_restart(5_000);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_ranges() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                partition: "test_partition".into(),
                translator: FourCap,
                codec_config: (),
                compression: None,
                pending_writes: DEFAULT_PENDING_WRITES,
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_concurrency: DEFAULT_REPLAY_CONCURRENCY,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(context.clone(), cfg.clone())
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
            let (current_end, start_next) = archive.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 1);

            let (current_end, start_next) = archive.next_gap(1);
            assert_eq!(current_end.unwrap(), 1);
            assert_eq!(start_next.unwrap(), 10);

            let (current_end, start_next) = archive.next_gap(10);
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(11);
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(12);
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(14);
            assert_eq!(current_end.unwrap(), 14);
            assert!(start_next.is_none());

            // Close and check again
            archive.close().await.expect("Failed to close archive");
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Check ranges again
            let (current_end, start_next) = archive.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 1);

            let (current_end, start_next) = archive.next_gap(1);
            assert_eq!(current_end.unwrap(), 1);
            assert_eq!(start_next.unwrap(), 10);

            let (current_end, start_next) = archive.next_gap(10);
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(11);
            assert_eq!(current_end.unwrap(), 11);
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(12);
            assert!(current_end.is_none());
            assert_eq!(start_next.unwrap(), 14);

            let (current_end, start_next) = archive.next_gap(14);
            assert_eq!(current_end.unwrap(), 14);
            assert!(start_next.is_none());
        });
    }
}

#[cfg(test)]
mod range_map_tests {
    use super::storage::RangeMap;
    // BTreeMap is not directly used in every test but useful for expected values
    #[allow(unused_imports)] 
    use std::collections::BTreeMap;

    #[test]
    fn test_new() {
        let map = RangeMap::new();
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_insert_empty() {
        let mut map = RangeMap::new();
        map.insert(5);
        assert_eq!(map.get(&5), Some((5, 5)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&5, &5)]);
    }

    #[test]
    fn test_insert_isolated() {
        let mut map = RangeMap::new();
        map.insert(5);
        map.insert(10);
        assert_eq!(map.get(&5), Some((5, 5)));
        assert_eq!(map.get(&10), Some((10, 10)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&5, &5), (&10, &10)]);
    }

    #[test]
    fn test_insert_covered() {
        let mut map = RangeMap::new();
        map.insert(1);
        map.insert(2);
        map.insert(3); // Range is 1-3
        map.insert(2); // Insert value already covered
        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&2), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.iter().count(), 1);
        assert_eq!(map.iter().next(), Some((&1, &3)));
    }

    #[test]
    fn test_insert_adjacent_end() {
        let mut map = RangeMap::new();
        map.insert(1);
        map.insert(2); // Range is 1-2
        map.insert(3); // Adjacent to end
        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.iter().next(), Some((&1, &3)));
    }

    #[test]
    fn test_insert_adjacent_start() {
        let mut map = RangeMap::new();
        map.insert(2);
        map.insert(3); // Range is 2-3
        map.insert(1); // Adjacent to start
        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.iter().next(), Some((&1, &3)));
    }

    #[test]
    fn test_insert_bridge_ranges() {
        let mut map = RangeMap::new();
        map.insert(1); 
        map.insert(2); 
        assert_eq!(map.get(&1), Some((1,2)));
        map.insert(5); 
        map.insert(6); 
        assert_eq!(map.get(&5), Some((5,6)));
                       // Current: (1,2), (5,6)
        map.insert(3); // Insert 3, should become (1,3), (5,6)
        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&2), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.get(&5), Some((5, 6)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&1, &3), (&5, &6)]);
        
        map.insert(4); // Insert 4, should bridge to (1,6)
        assert_eq!(map.get(&1), Some((1, 6)));
        assert_eq!(map.get(&3), Some((1, 6)));
        assert_eq!(map.get(&4), Some((1, 6)));
        assert_eq!(map.get(&6), Some((1, 6)));
        assert_eq!(map.iter().count(), 1);
        assert_eq!(map.iter().next(), Some((&1, &6)));
    }
    
    #[test]
    fn test_insert_complex_merging_and_ordering() {
        let mut map = RangeMap::new();
        map.insert(10); // (10,10)
        map.insert(12); // (10,10), (12,12)
        map.insert(11); // (10,12)
        assert_eq!(map.get(&10), Some((10,12)));
        assert_eq!(map.get(&11), Some((10,12)));
        assert_eq!(map.get(&12), Some((10,12)));

        map.insert(15); // (10,12), (15,15)
        map.insert(13); // (10,13), (15,15)
        assert_eq!(map.get(&13), Some((10,13)));
        assert_eq!(map.get(&12), Some((10,13)));
        assert_eq!(map.get(&15), Some((15,15)));
        
        map.insert(14); // (10,15)
        assert_eq!(map.get(&10), Some((10,15)));
        assert_eq!(map.get(&14), Some((10,15)));
        assert_eq!(map.get(&15), Some((10,15)));
        assert_eq!(map.iter().count(), 1);
        assert_eq!(map.iter().next(), Some((&10, &15)));

        map.insert(5); // (5,5), (10,15)
        map.insert(7); // (5,5), (7,7), (10,15)
        map.insert(6); // (5,7), (10,15)
        assert_eq!(map.get(&5), Some((5,7)));
        assert_eq!(map.get(&6), Some((5,7)));
        assert_eq!(map.get(&7), Some((5,7)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&5,&7),(&10,&15)]);

        map.insert(9); // (5,7), (9,9), (10,15) -> should become (5,7), (9,15)
        assert_eq!(map.get(&9), Some((9,15)));
        assert_eq!(map.get(&10), Some((9,15)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&5,&7),(&9,&15)]);
        
        map.insert(8); // (5,15)
        assert_eq!(map.get(&5), Some((5,15)));
        assert_eq!(map.get(&8), Some((5,15)));
        assert_eq!(map.get(&15), Some((5,15)));
        assert_eq!(map.iter().next(), Some((&5, &15)));
    }

    #[test]
    fn test_insert_max_value() {
        let mut map = RangeMap::new();
        map.insert(u64::MAX);
        assert_eq!(map.get(&u64::MAX), Some((u64::MAX, u64::MAX)));
        map.insert(u64::MAX - 1);
        assert_eq!(map.get(&(u64::MAX -1)), Some((u64::MAX - 1, u64::MAX)));
        assert_eq!(map.get(&u64::MAX), Some((u64::MAX - 1, u64::MAX)));
    }

    #[test]
    fn test_get() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); map.insert(3); // Range 1-3
        map.insert(5); map.insert(6); // Range 5-6

        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&2), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.get(&4), None);
        assert_eq!(map.get(&5), Some((5, 6)));
        assert_eq!(map.get(&6), Some((5, 6)));
        assert_eq!(map.get(&0), None);
        assert_eq!(map.get(&7), None);
    }

    #[test]
    fn test_remove_empty() {
        let mut map = RangeMap::new();
        map.remove(1, 5);
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_remove_invalid_range() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); // 1-2
        map.remove(5, 1); // start > end, should do nothing
        assert_eq!(map.iter().next(), Some((&1,&2)));
    }

    #[test]
    fn test_remove_non_existent() {
        let mut map = RangeMap::new();
        map.insert(5); map.insert(6); // 5-6
        map.remove(1, 3); // Before existing
        assert_eq!(map.iter().next(), Some((&5, &6)));
        map.remove(8, 10); // After existing
        assert_eq!(map.iter().next(), Some((&5, &6)));
        map.remove(1,10); // Covers existing
        assert_eq!(map.iter().count(), 0);
    }
    
    #[test]
    fn test_remove_exact_match() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); map.insert(3); // 1-3
        map.insert(5); map.insert(6); // 5-6
        map.remove(1, 3);
        assert_eq!(map.get(&2), None);
        assert_eq!(map.iter().next(), Some((&5, &6)));
        map.remove(5,6);
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_remove_subset_split() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); map.insert(3); map.insert(4); map.insert(5); // 1-5
        map.remove(3, 3); // Remove 3 from 1-5 -> (1,2), (4,5)
        assert_eq!(map.get(&2), Some((1, 2)));
        assert_eq!(map.get(&3), None);
        assert_eq!(map.get(&4), Some((4, 5)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&1, &2), (&4, &5)]);

        // Reset and test another split
        let mut map2 = RangeMap::new();
        map2.insert(1); map2.insert(2); map2.insert(3); map2.insert(4); map2.insert(5); // 1-5
        map2.remove(2,4); // Remove 2-4 from 1-5 -> (1,1), (5,5)
        assert_eq!(map2.get(&1), Some((1,1)));
        assert_eq!(map2.get(&2), None);
        assert_eq!(map2.get(&3), None);
        assert_eq!(map2.get(&4), None);
        assert_eq!(map2.get(&5), Some((5,5)));
        assert_eq!(map2.iter().collect::<Vec<_>>(), vec![(&1, &1), (&5, &5)]);
    }

    #[test]
    fn test_remove_overlap_start() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); map.insert(3); map.insert(4); map.insert(5); // 1-5
        map.remove(0, 2); // Remove 0-2 from 1-5 -> (3,5)
        assert_eq!(map.get(&1), None);
        assert_eq!(map.get(&2), None);
        assert_eq!(map.get(&3), Some((3,5)));
        assert_eq!(map.iter().next(), Some((&3, &5)));
    }

    #[test]
    fn test_remove_overlap_end() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); map.insert(3); map.insert(4); map.insert(5); // 1-5
        map.remove(4, 6); // Remove 4-6 from 1-5 -> (1,3)
        assert_eq!(map.get(&3), Some((1,3)));
        assert_eq!(map.get(&4), None);
        assert_eq!(map.get(&5), None);
        assert_eq!(map.iter().next(), Some((&1, &3)));
    }

    #[test]
    fn test_remove_cover_multiple_ranges() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); // 1-2
        map.insert(4); map.insert(5); // 4-5
        map.insert(7); map.insert(8); // 7-8
        
        map.remove(3, 6); // Removes 4-5, no truncation as 3 and 6 are in gaps. (1,2), (7,8)
        assert_eq!(map.get(&2), Some((1,2)));
        assert_eq!(map.get(&4), None);
        assert_eq!(map.get(&5), None);
        assert_eq!(map.get(&7), Some((7,8)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&1,&2), (&7,&8)]);

        map.remove(0,10); // Removes all remaining ranges
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_remove_partial_overlap_multiple_ranges() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); map.insert(3);       // 1-3
        map.insert(5); map.insert(6); map.insert(7);       // 5-7
        map.insert(9); map.insert(10); map.insert(11);    // 9-11

        map.remove(2, 6); // Affects 1-3 (becomes 1-1) and 5-7 (becomes 7-7)
        assert_eq!(map.get(&1), Some((1,1)));
        assert_eq!(map.get(&2), None);
        assert_eq!(map.get(&3), None);
        assert_eq!(map.get(&5), None);
        assert_eq!(map.get(&6), None);
        assert_eq!(map.get(&7), Some((7,7)));
        assert_eq!(map.get(&9), Some((9,11)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&1,&1), (&7,&7), (&9,&11)]);
        
        // Reset and test removing all
        let mut map2 = RangeMap::new();
        map2.insert(1); map2.insert(2); map2.insert(3); 
        map2.insert(5); map2.insert(6); map2.insert(7); 
        map2.insert(9); map2.insert(10); map2.insert(11);
        map2.remove(0, 20); // remove all
        assert_eq!(map2.iter().count(), 0);
    }
    
    #[test]
    fn test_remove_touching_boundaries_no_merge() {
        let mut map = RangeMap::new();
        map.insert(0); map.insert(1); map.insert(2); // 0-2
        map.insert(4); map.insert(5); // 4-5

        // Remove range that is exactly between two existing ranges
        map.remove(3,3); 
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&0,&2), (&4,&5)]);
    }

    #[test]
    fn test_remove_max_value_ranges() {
        let mut map = RangeMap::new();
        map.insert(u64::MAX - 2); 
        map.insert(u64::MAX - 1);
        map.insert(u64::MAX); // MAX-2 to MAX
        
        map.remove(u64::MAX, u64::MAX); // Remove MAX -> (MAX-2, MAX-1)
        assert_eq!(map.get(&(u64::MAX-2)), Some((u64::MAX-2, u64::MAX-1)));
        assert_eq!(map.get(&u64::MAX), None);

        map.remove(u64::MAX - 2, u64::MAX - 2); // Remove MAX-2 -> (MAX-1, MAX-1)
        assert_eq!(map.get(&(u64::MAX-2)), None);
        assert_eq!(map.get(&(u64::MAX-1)), Some((u64::MAX-1, u64::MAX-1)));

        map.remove(u64::MAX - 1, u64::MAX -1); // Remove MAX-1 -> empty
        assert_eq!(map.iter().count(), 0);

        map.insert(u64::MAX-1);
        map.insert(u64::MAX); // MAX-1 to MAX
        map.remove(u64::MIN, u64::MAX); // Remove all
        assert_eq!(map.iter().count(), 0);
    }


    #[test]
    fn test_iter() {
        let mut map = RangeMap::new();
        assert_eq!(map.iter().next(), None);
        map.insert(5); map.insert(6); // 5-6
        map.insert(1); map.insert(2); // 1-2
        let mut iter = map.iter();
        assert_eq!(iter.next(), Some((&1, &2)));
        assert_eq!(iter.next(), Some((&5, &6)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_next_gap_empty() {
        let map = RangeMap::new();
        assert_eq!(map.next_gap(5), (None, None));
    }

    #[test]
    fn test_next_gap_single_range() {
        let mut map = RangeMap::new();
        map.insert(5); map.insert(6); map.insert(7); // 5-7
        assert_eq!(map.next_gap(4), (None, Some(5)));         // Before range
        assert_eq!(map.next_gap(5), (Some(7), None));         // Start of range
        assert_eq!(map.next_gap(6), (Some(7), None));         // Middle of range
        assert_eq!(map.next_gap(7), (Some(7), None));         // End of range
        assert_eq!(map.next_gap(8), (Some(7), None));         // After range
    }

    #[test]
    fn test_next_gap_multiple_ranges() {
        let mut map = RangeMap::new();
        map.insert(1); map.insert(2); // 1-2
        map.insert(5); map.insert(6); // 5-6
        map.insert(10);               // 10-10

        assert_eq!(map.next_gap(0), (None, Some(1)));         // Before all
        assert_eq!(map.next_gap(1), (Some(2), Some(5)));      // Start of first range
        assert_eq!(map.next_gap(2), (Some(2), Some(5)));      // End of first range
        assert_eq!(map.next_gap(3), (Some(2), Some(5)));      // Gap between 1st and 2nd
        assert_eq!(map.next_gap(4), (Some(2), Some(5)));      // Gap, closer to 2nd
        assert_eq!(map.next_gap(5), (Some(6), Some(10)));     // Start of 2nd range
        assert_eq!(map.next_gap(6), (Some(6), Some(10)));     // End of 2nd range
        assert_eq!(map.next_gap(7), (Some(6), Some(10)));     // Gap between 2nd and 3rd
        assert_eq!(map.next_gap(8), (Some(6), Some(10)));     // Gap
        assert_eq!(map.next_gap(9), (Some(6), Some(10)));     // Gap, closer to 3rd
        assert_eq!(map.next_gap(10), (Some(10), None));       // Start/End of 3rd range
        assert_eq!(map.next_gap(11), (Some(10), None));       // After all
    }
    
    #[test]
    fn test_next_gap_value_is_max() {
        let mut map = RangeMap::new();
        map.insert(u64::MAX - 5);
        map.insert(u64::MAX - 4); // MAX-5 to MAX-4
        map.insert(u64::MAX - 1);
        map.insert(u64::MAX);     // MAX-1 to MAX

        assert_eq!(map.next_gap(u64::MAX - 6), (None, Some(u64::MAX - 5)));
        assert_eq!(map.next_gap(u64::MAX - 5), (Some(u64::MAX - 4), Some(u64::MAX - 1)));
        assert_eq!(map.next_gap(u64::MAX - 4), (Some(u64::MAX - 4), Some(u64::MAX - 1)));
        assert_eq!(map.next_gap(u64::MAX - 3), (Some(u64::MAX - 4), Some(u64::MAX - 1))); // In gap
        assert_eq!(map.next_gap(u64::MAX - 2), (Some(u64::MAX - 4), Some(u64::MAX - 1))); // In gap
        assert_eq!(map.next_gap(u64::MAX - 1), (Some(u64::MAX), None));
        assert_eq!(map.next_gap(u64::MAX), (Some(u64::MAX), None));
    }
}
