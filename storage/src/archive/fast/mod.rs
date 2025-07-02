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
//! correct key is returned. To support efficient checks, `Archive` (via [crate::index::Index])
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
//!         items_per_section: 1024,
//!         pending_writes: 10,
//!         write_buffer: 1024 * 1024,
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
pub use crate::{
    archive::{Error, Identifier},
    translator::Translator,
};
pub use storage::Archive;

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

    /// The number of items per section.
    pub items_per_section: u64,

    /// The amount of bytes that can be buffered in a section before being written to disk.
    pub write_buffer: usize,

    /// The buffer size to use when replaying a blob.
    pub replay_buffer: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive::Archive as _, translator::FourCap};
    use commonware_codec::{varint::UInt, DecodeExt, EncodeSize};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Runner, Storage};
    use commonware_utils::array::FixedBytes;

    const DEFAULT_ITEMS_PER_SECTION: u64 = 65536;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_REPLAY_BUFFER: usize = 4096;

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    // Fast-specific tests

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
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                items_per_section: DEFAULT_ITEMS_PER_SECTION,
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
            blob.close().await.unwrap();

            // Initialize the archive again
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(
                context,
                Config {
                    partition: "test_partition".into(),
                    translator: FourCap,
                    codec_config: (),
                    compression: None,
                    write_buffer: DEFAULT_WRITE_BUFFER,
                    replay_buffer: DEFAULT_REPLAY_BUFFER,
                    items_per_section: DEFAULT_ITEMS_PER_SECTION,
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
                write_buffer: DEFAULT_WRITE_BUFFER,
                replay_buffer: DEFAULT_REPLAY_BUFFER,
                items_per_section: DEFAULT_ITEMS_PER_SECTION,
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
}
