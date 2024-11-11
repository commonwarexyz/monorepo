//! A write-once key-value store optimized for throughput and low-latency reads.
//!
//! `Archive` is a key-value store designed for workloads where data at a given key
//! is written once and read many times. Data is stored in `Journal` (an append-only
//! log) and truncated representations of keys are indexed in memory (using a caller-provided
//! `Translator`) to enable "single read lookups" over the entire store. Notably, `Archive`
//! does not make use of compaction nor on-disk indexes (and thus has no read nor write
//! amplification during normal operation).
//!
//! # Format
//!
//! `Archive` stores data in the following format:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |    ...    |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | Key (Fixed Size)  |    C(u32)     |   Data    |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//!
//! C = CRC32(Key)
//! ```
//!
//! _To ensure keys fetched using `Journal::get_prefix` are correctly read, the key is checksummed
//! within a `Journal` entry (although the entire entry is also checksummed by `Journal`)._
//!
//! # Uniqueness
//!
//! `Archive` assumes all stored keys are unique and only ever associated with a single `section`. If
//! the same key is written to multiple `sections`, there is no guarantee which value will be returned
//! (and no error will be returned when calling `put`). If the same key is written to the same section,
//! `Archive` will return an error. `Archive` can be checked for the existence of a key (across any `section`)
//! using the `has` method.
//!
//! ## Conflicts
//!
//! Because a truncated representation of a key is only ever stored in memory, it is possible (and expected)
//! that two keys will eventually be represented by the same truncated key. To handle this case, `Archive`
//! must check the persisted form of all conflicting keys to ensure data from the correct key is returned.
//! To support efficient checks, `Archive` keeps a linked list of all keys with the same truncated prefix:
//!
//! ```rust
//! struct Index {
//!     section: u64,
//!     offset: u32,
//!     len: u32,
//!
//!     next: Option<Box<Index>>,
//! }
//! ```
//!
//! _To avoid random memory reads in the common case, the in-memory index directly stores the first item
//! in the linked list instead of a pointer to the first item._
//!
//! If the `Translator` provided by the caller does not uniformly distribute keys across the key space or
//! uses a truncated representation that means keys on average have many conflicts, performance will degrade.
//!
//! ## Memory Overhead
//!
//! The memory used to track each key is `~truncated(key).len() + 24` bytes (where `24` is the size of the `Index`
//! struct). This means that an `Archive` employing a `Translator` that uses the first `8` bytes of a key will
//! use `32` bytes to index each key.
//!
//! # Sync
//!
//! `Archive` flushes writes in a given `section` to `Storage` after `pending_writes`. If the caller
//! requires durability on a particular write, they can `force_sync` when calling the `put` method.
//!
//! # Pruning
//!
//! `Archive` supports pruning up to a minimum `section` using the `prune` method. After `prune` is called
//! on a `section`, all interaction with a `section` less than the pruned `section` will return an error.
//!
//! ## Lazy Index Cleanup
//!
//! Instead of performing a full iteration of the in-memory index, storing an additional in-memory index
//! per `section`, or replaying a `section` of `Journal`, `Archive` lazily cleans up the in-memory index
//! after pruning. When a new key is stored that overlaps (same truncated value) with a pruned key, the
//! pruned key is removed from the in-memory index.
//!
//! # Single Operation Reads
//!
//! To enable single operation reads (i.e. reading all of an item in a single call to `Blob`), `Archive`
//! caches the length of each item in its in-memory index. While it increases the footprint per key stored, the
//! benefit of only ever performing a single operation to read a key (when there are no conflicts) is worth the
//! tradeoff.
//!
//! # Compression
//!
//! `Archive` supports compressing data before storing it on disk. This can be enabled by setting the `compression`
//! field in the `Config` struct to a valid `zstd` compression level. This setting can be changed between initializations
//! of `Archive`, however, it must remain populated if any data was written with compression enabled.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic::Executor};
//! use commonware_storage::{journal::{Journal, Config as JournalConfig}, archive::{Archive, Config, translator::FourCap}};
//! use prometheus_client::registry::Registry;
//! use std::sync::{Arc, Mutex};
//!
//! let (executor, context, _) = Executor::default();
//! executor.start(async move {
//!     // Create a journal
//!     let cfg = JournalConfig {
//!         registry: Arc::new(Mutex::new(Registry::default())),
//!         partition: "partition".to_string()
//!     };
//!     let journal = Journal::init(context, cfg).await.unwrap();
//!
//!     // Create an archive
//!     let cfg = Config {
//!         registry: Arc::new(Mutex::new(Registry::default())),
//!         key_len: 8,
//!         section_mask: 0xffff_ffff_ffff_0000u64,
//!         translator: FourCap,
//!         pending_writes: 10,
//!         replay_concurrency: 4,
//!         compression: Some(3),
//!     };
//!     let mut archive = Archive::init(journal, cfg).await.unwrap();
//!
//!     // Put a key
//!     archive.put(1, b"test-key", "data".into()).await.unwrap();
//!
//!     // Close the archive (also closes the journal)
//!     archive.close().await.unwrap();
//! });
//! ```

mod storage;
pub use storage::{Archive, Identifier};
pub mod translator;

use prometheus_client::registry::Registry;
use std::{
    hash::Hash,
    sync::{Arc, Mutex},
};
use thiserror::Error;

/// Errors that can occur when interacting with the archive.
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("record corrupted")]
    RecordCorrupted,
    #[error("duplicate index")]
    DuplicateIndex,
    #[error("already pruned to section: {0}")]
    AlreadyPrunedToSection(u64),
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("record too large")]
    RecordTooLarge,
    #[error("compression failed")]
    CompressionFailed,
    #[error("decompression failed")]
    DecompressionFailed,
}

/// Translate keys into an internal representation used in `Archive`'s
/// in-memory index.
///
/// If invoking `transform` on keys results in many conflicts, the performance
/// of `Archive` will degrade substantially.
pub trait Translator: Clone {
    type Key: Eq + Hash + Send + Sync + Clone;

    /// Transform a key into its internal representation.
    fn transform(&self, key: &[u8]) -> Self::Key;
}

/// Configuration for `Archive` storage.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Mask to apply to indices to determine section.
    ///
    /// This value is `index & section_mask`.
    pub section_mask: u64,

    /// Length of each key in bytes.
    ///
    /// `Archive` assumes that all keys are of the same length. This
    /// trick is used to store data more efficiently on disk and to substantially
    /// reduce the number of IO during initialization. If a key is provided that
    /// is not of the correct length, an error will be returned.
    pub key_len: u32,

    /// Logic to transform keys into their index representation.
    ///
    /// `Archive` assumes that all internal keys are spread uniformly across the key space.
    /// If that is not the case, lookups may be O(n) instead of O(1).
    pub translator: T,

    /// The number of writes to buffer in a section before forcing a sync in the journal.
    ///
    /// If set to 0, the journal will be synced each time a new item is stored.
    pub pending_writes: usize,

    /// The number of blobs to replay concurrently on initialization.
    pub replay_concurrency: usize,

    /// Optional compression level (using `zstd`) to apply to data before storing.
    pub compression: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{Config as JournalConfig, Error as JournalError, Journal};
    use bytes::Bytes;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Blob, Runner, Storage};
    use prometheus_client::{encoding::text::encode, registry::Registry};
    use rand::Rng;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        u64,
    };
    use translator::{FourCap, TwoCap};

    const DEFAULT_SECTION_MASK: u64 = 0xffff_ffff_ffff_0000u64;

    fn test_archive_put_get(compression: Option<u8>) {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                key_len: 7,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index = 1u64;
            let key = b"testkey";
            let data = Bytes::from("testdata");

            // Has the key
            let has = archive
                .has(Identifier::Index(index))
                .await
                .expect("Failed to check key");
            assert!(!has);
            let has = archive
                .has(Identifier::Key(key))
                .await
                .expect("Failed to check key");
            assert!(!has);

            // Put the key-data pair
            archive
                .put(index, key, data.clone())
                .await
                .expect("Failed to put data");

            // Has the key
            let has = archive
                .has(Identifier::Index(index))
                .await
                .expect("Failed to check key");
            assert!(has);
            let has = archive
                .has(Identifier::Key(key))
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
                .get(Identifier::Key(key))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data);

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 1"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 2"));
            assert!(buffer.contains("has_total 4"));
            assert!(buffer.contains("syncs_total 0"));

            // Force a sync
            archive.sync().await.expect("Failed to sync data");

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 1"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 2"));
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
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Initialize an empty journal
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                key_len: 7,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: Some(3),
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Put the key-data pair
            let index = 1u64;
            let key = b"testkey";
            let data = Bytes::from("testdata");
            archive
                .put(index, key, data.clone())
                .await
                .expect("Failed to put data");

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Initialize the archive again without compression
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                key_len: 7,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Get the data back
            let retrieved = archive
                .get(Identifier::Index(index))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_ne!(retrieved, data);
            let retrieved = archive
                .get(Identifier::Key(key))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_ne!(retrieved, data);
        });
    }

    #[test_traced]
    fn test_archive_invalid_key_length() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                key_len: 8,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index = 1u64;
            let key = b"invalidkey";
            let data = Bytes::from("invaliddata");

            // Put the key-data pair
            let result = archive.put(index, key, data).await;
            assert!(matches!(result, Err(Error::InvalidKeyLength)));

            // Get the data back
            let result = archive.get(Identifier::Key(key)).await;
            assert!(matches!(result, Err(Error::InvalidKeyLength)));

            // Has the key
            let result = archive.has(Identifier::Key(key)).await;
            assert!(matches!(result, Err(Error::InvalidKeyLength)));

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 0"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 0"));
        });
    }

    #[test_traced]
    fn test_archive_record_corruption() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Initialize an empty journal
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                key_len: 7,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index = 1u64;
            let key = b"testkey";
            let data = Bytes::from("testdata");

            // Put the key-data pair
            archive
                .put(index, key, data.clone())
                .await
                .expect("Failed to put data");

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Corrupt the value
            let section = index & DEFAULT_SECTION_MASK;
            let blob = context
                .open("test_partition", &section.to_be_bytes())
                .await
                .unwrap();
            let value_location = 4 + 8 + cfg.key_len as u64 + 4;
            blob.write_at(b"testdaty", value_location).await.unwrap();
            blob.close().await.unwrap();

            // Initialize the archive again
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");
            let archive = Archive::init(
                journal,
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    key_len: 7,
                    translator: FourCap,
                    pending_writes: 10,
                    replay_concurrency: 4,
                    compression: None,
                    section_mask: DEFAULT_SECTION_MASK,
                },
            )
            .await
            .expect("Failed to initialize archive");

            // Attempt to get the key
            let result = archive.get(Identifier::Key(key)).await;
            assert!(matches!(
                result,
                Err(Error::Journal(JournalError::ChecksumMismatch(_, _)))
            ));
        });
    }

    #[test_traced]
    fn test_archive_duplicate_key() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                key_len: 9,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index = 1u64;
            let key = b"duplicate";
            let data1 = Bytes::from("data1");
            let data2 = Bytes::from("data2");

            // Put the key-data pair
            archive
                .put(index, key, data1.clone())
                .await
                .expect("Failed to put data");

            // Put the key-data pair again
            let result = archive.put(index, key, data2.clone()).await;
            assert!(matches!(result, Err(Error::DuplicateIndex)));

            // Get the data back
            let retrieved = archive
                .get(Identifier::Index(index))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);
            let retrieved = archive
                .get(Identifier::Key(key))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 1"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 2"));
        });
    }

    #[test_traced]
    fn test_archive_get_nonexistent() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                key_len: 11,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Attempt to get an index that doesn't exist
            let index = 1u64;
            let retrieved = archive
                .get(Identifier::Index(index))
                .await
                .expect("Failed to get data");
            assert!(retrieved.is_none());

            // Attempt to get a key that doesn't exist
            let key = b"nonexistent";
            let retrieved = archive
                .get(Identifier::Key(key))
                .await
                .expect("Failed to get data");
            assert!(retrieved.is_none());

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 0"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 2"));
        });
    }

    #[test_traced]
    fn test_archive_overlapping_key() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                key_len: 5,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index1 = 1u64;
            let key1 = b"keys1";
            let data1 = Bytes::from("data1");
            let index2 = 2u64;
            let key2 = b"keys2";
            let data2 = Bytes::from("data2");

            // Put the key-data pair
            archive
                .put(index1, key1, data1.clone())
                .await
                .expect("Failed to put data");

            // Put the key-data pair
            archive
                .put(index2, key2, data2.clone())
                .await
                .expect("Failed to put data");

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(key1))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(key2))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 2"));
            assert!(buffer.contains("unnecessary_reads_total 1"));
            assert!(buffer.contains("gets_total 2"));
        });
    }

    #[test_traced]
    fn test_archive_overlapping_key_multiple_sections() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                key_len: 5,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index1 = 1u64;
            let key1 = b"keys1";
            let data1 = Bytes::from("data1");
            let index2 = 2_000_000u64;
            let key2 = b"keys2";
            let data2 = Bytes::from("data2");

            // Put the key-data pair
            archive
                .put(index1, key1, data1.clone())
                .await
                .expect("Failed to put data");

            // Put the key-data pair
            archive
                .put(index2, key2, data2.clone())
                .await
                .expect("Failed to put data");

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(key1))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(key2))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);
        });
    }

    #[test_traced]
    fn test_archive_prune_keys() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry: registry.clone(),
                key_len: 9,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: 0xffff_ffff_ffff_ffffu64, // no mask
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different sections
            let keys = vec![
                (1u64, "key1-blah", Bytes::from("data1")),
                (2u64, "key2-blah", Bytes::from("data2")),
                (3u64, "key3-blah", Bytes::from("data3")),
                (4u64, "key3-bleh", Bytes::from("data3-again")),
                (5u64, "key4-blah", Bytes::from("data4")),
            ];

            for (index, key, data) in &keys {
                archive
                    .put(*index, key.as_bytes(), data.clone())
                    .await
                    .expect("Failed to put data");
            }

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 5"));

            // Prune sections less than 3
            archive.prune(3).await.expect("Failed to prune");

            // Ensure keys 1 and 2 are no longer present
            for (index, key, data) in keys {
                let retrieved = archive
                    .get(Identifier::Key(key.as_bytes()))
                    .await
                    .expect("Failed to get data");
                if index < 3 {
                    assert!(retrieved.is_none());
                } else {
                    assert_eq!(retrieved.expect("Data not found"), data);
                }
            }

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 3"));
            assert!(buffer.contains("indices_pruned_total 2"));
            assert!(buffer.contains("keys_pruned_total 0")); // no lazy cleanup yet

            // Try to prune older section
            let result = archive.prune(2).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedToSection(3))));

            // Try to prune current section again
            let result = archive.prune(3).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedToSection(3))));

            // Trigger lazy removal of keys
            archive
                .put(6, "key2-blfh".as_bytes(), Bytes::from("data2-2"))
                .await
                .expect("Failed to put data");

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("items_tracked 4")); // lazily remove one, add one
            assert!(buffer.contains("indices_pruned_total 2"));
            assert!(buffer.contains("keys_pruned_total 1"));
        });
    }

    fn test_archive_keys_and_restart(num_keys: usize) -> String {
        // Initialize the deterministic runtime
        let (executor, mut context, auditor) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let section_mask = 0xffff_ffff_ffff_ff00u64;
            let cfg = Config {
                registry: registry.clone(),
                key_len: 32,
                translator: TwoCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different sections
            let mut keys = BTreeMap::new();
            while keys.len() < num_keys {
                let index = keys.len() as u64;
                let mut key = [0u8; 32];
                context.fill(&mut key);
                let mut data = [0u8; 1024];
                context.fill(&mut data);
                let data = Bytes::from(data.to_vec());
                archive
                    .put(index, &key, data.clone())
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
                assert_eq!(retrieved, data);
                let retrieved = archive
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, data);
            }

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            let tracked = format!("items_tracked {:?}", num_keys);
            assert!(buffer.contains(&tracked));
            assert!(buffer.contains("keys_pruned_total 0"));

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Reinitialize the archive
            let registry = Arc::new(Mutex::new(Registry::default()));
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");
            let cfg = Config {
                registry: registry.clone(),
                key_len: 32,
                translator: TwoCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Ensure all keys can be retrieved
            for (key, (index, data)) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, data);
                let retrieved = archive
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, data);
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
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            let tracked = format!("items_tracked {:?}", num_keys - removed);
            assert!(buffer.contains(&tracked));
            let pruned = format!("indices_pruned_total {}", removed);
            assert!(buffer.contains(&pruned));
            assert!(buffer.contains("keys_pruned_total 0")); // have not lazily removed keys yet
        });
        auditor.state()
    }

    #[test_traced]
    fn test_archive_many_keys_and_restart() {
        test_archive_keys_and_restart(100_000); // 391 sections
    }

    #[test_traced]
    fn test_determinism() {
        let state1 = test_archive_keys_and_restart(5_000); // 20 sections
        let state2 = test_archive_keys_and_restart(5_000);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_ranges() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                key_len: 9,
                translator: FourCap,
                pending_writes: 10,
                replay_concurrency: 4,
                compression: None,
                section_mask: DEFAULT_SECTION_MASK,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different indices
            let keys = vec![
                (1u64, "key1-blah", Bytes::from("data1")),
                (10u64, "key2-blah", Bytes::from("data2")),
                (11u64, "key3-blah", Bytes::from("data3")),
                (14u64, "key3-bleh", Bytes::from("data3-again")),
            ];
            for (index, key, data) in &keys {
                archive
                    .put(*index, key.as_bytes(), data.clone())
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

            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");
            let archive = Archive::init(journal, cfg.clone())
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
