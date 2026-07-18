//! An immutable key-value store optimized for minimal memory usage and write amplification.
//!
//! [Freezer] is a key-value store designed for permanent storage where data is written once and never
//! modified. Meant for resource-constrained environments, [Freezer] exclusively employs disk-resident
//! data structures to serve queries and avoids ever rewriting (i.e. compacting) inserted data.
//!
//! As a byproduct of the mechanisms used to satisfy these constraints, [Freezer] consistently provides
//! low latency access to recently added data (regardless of how much data has been stored) at the expense
//! of a logarithmic increase in latency for old data (increasing with the number of items stored).
//!
//! # Format
//!
//! The [Freezer] uses a three-level architecture:
//! 1. An extendible hash table (written in a single [commonware_runtime::Blob]) that maps keys to locations
//! 2. A key index journal ([crate::journal::segmented::fixed]) that stores keys and collision chain pointers
//! 3. A value journal ([crate::journal::segmented::glob]) that stores the actual values
//!
//! These journals are combined via [crate::journal::segmented::oversized], which coordinates
//! crash recovery between them.
//!
//! ```text
//! +-----------------------------------------------------------------+
//! |                           Hash Table                            |
//! |  +---------+---------+---------+---------+---------+---------+  |
//! |  | Entry 0 | Entry 1 | Entry 2 | Entry 3 | Entry 4 |   ...   |  |
//! |  +----+----+----+----+----+----+----+----+----+----+---------+  |
//! +-------|---------|---------|---------|---------|---------|-------+
//!         |         |         |         |         |         |
//!         v         v         v         v         v         v
//! +-----------------------------------------------------------------+
//! |                      Key Index Journal                          |
//! |  Section 0: [Entry 0][Entry 1][Entry 2]...                      |
//! |  Section 1: [Entry 10][Entry 11][Entry 12]...                   |
//! |  Section N: [Entry 100][Entry 101][Entry 102]...                |
//! +-------|---------|---------|---------|---------|---------|-------+
//!         |         |         |         |         |         |
//!         v         v         v         v         v         v
//! +-----------------------------------------------------------------+
//! |                        Value Journal                            |
//! |  Section 0: [Value 0][Value 1][Value 2]...                      |
//! |  Section 1: [Value 10][Value 11][Value 12]...                   |
//! |  Section N: [Value 100][Value 101][Value 102]...                |
//! +-----------------------------------------------------------------+
//! ```
//!
//! Each table entry is a single fixed-size slot holding the head of that entry's collision
//! chain. An occupancy tag distinguishes an empty slot (all zeros) from a chain head at
//! section 0, position 0. The storage backend guarantees atomic commits, so slots are
//! never torn and committed slots never reference records the journals do not hold
//! (see Recovery below).
//!
//! ```text
//! +-------------------------------------+
//! |          Hash Table Entry           |
//! +-------------------------------------+
//! | occupied:  u8                       |
//! | section:   u64                      |
//! | position:  u64                      |
//! | added:     u8                       |
//! +-------------------------------------+
//! ```
//!
//! The key index journal stores fixed-size entries containing a key, a pointer to the value in the
//! value journal, and an optional pointer to the next entry in the collision chain (for keys that
//! hash to the same table index).
//!
//! ```text
//! +-------------------------------------+
//! |        Key Index Entry              |
//! +-------------------------------------+
//! | Key:           Array                |
//! | Value Offset:  u64                  |
//! | Value Size:    u32                  |
//! | Next:          Option<(u64, u32)>   |
//! +-------------------------------------+
//! ```
//!
//! The value journal stores the actual encoded values at the offsets referenced by the key index entries.
//!
//! # Traversing Conflicts
//!
//! When multiple keys hash to the same table index, they form a linked list within the key index
//! journal. Each key index entry points to its value in the value journal:
//!
//! ```text
//! Hash Table:
//! [Index 42]         +-------------------+
//!                    | section: 2        |
//!                    | offset: 768       |
//!                    +---------+---------+
//!                              |
//! Key Index Journal:           v
//! [Section 2]        +-----------------------+
//!                    | Key: "foo"            |
//!                    | ValOff: 100           |
//!                    | ValSize: 20           |
//!                    | Next: (1, 512) -------+---+
//!                    +-----------------------+   |
//!                                                v
//! [Section 1]        +-----------------------+
//!                    | Key: "bar"            |
//!                    | ValOff: 50            |
//!                    | ValSize: 20           |
//!                    | Next: (0, 256) -------+---+
//!                    +-----------------------+   |
//!                                                v
//! [Section 0]        +-----------------------+
//!                    | Key: "baz"            |
//!                    | ValOff: 0             |
//!                    | ValSize: 20           |
//!                    | Next: None            |
//!                    +-----------------------+
//!
//! Value Journal:
//! [Section 0]        [Value: 126 @ offset 0 ]
//! [Section 1]        [Value: 84  @ offset 50]
//! [Section 2]        [Value: 42  @ offset 100]
//! ```
//!
//! New entries are prepended to the chain, becoming the new head. During lookup, the chain
//! is traversed until a matching key is found. The `added` field in the table entry tracks
//! insertions since the last resize, triggering table growth when 50% of entries have had
//! `table_resize_frequency` items added (since the last resize).
//!
//! # Extendible Hashing
//!
//! The [Freezer] uses bit-based indexing to grow the on-disk hash table without rehashing existing entries:
//!
//! ```text
//! Initial state (table_size=4, using 2 bits of hash):
//! Hash: 0b...00 -> Index 0
//! Hash: 0b...01 -> Index 1
//! Hash: 0b...10 -> Index 2
//! Hash: 0b...11 -> Index 3
//!
//! After resize (table_size=8, using 3 bits of hash):
//! Hash: 0b...000 -> Index 0 -+
//! ...                        |
//! Hash: 0b...100 -> Index 4 -+- Both map to old Index 0
//! Hash: 0b...001 -> Index 1 -+
//! ...                        |
//! Hash: 0b...101 -> Index 5 -+- Both map to old Index 1
//! ```
//!
//! When the table doubles in size:
//! 1. Each entry at index `i` splits into two entries: `i` and `i + old_size`
//! 2. The existing chain head is copied to both locations with `added=0`
//! 3. Future insertions will naturally distribute between the two entries based on their hash
//!
//! This approach ensures that entries inserted before a resize remain discoverable after the resize,
//! as the lookup algorithm checks the appropriate entry based on the current table size. As more and more
//! items are added (and resizes occur), the latency for fetching old data will increase logarithmically
//! (with the number of items stored).
//!
//! To prevent a "stall" during a single resize, the table is resized incrementally across multiple sync calls.
//! Each sync will process up to `table_resize_chunk_size` entries until the resize is complete. If there is
//! an ongoing resize when closing the [Freezer], the resize will be completed before closing.
//!
//! # Recovery
//!
//! [Freezer::init] recovers from the freezer's own committed state, which is always
//! internally consistent: [Freezer::sync] and [Freezer::sync_into] commit the
//! journals and the table atomically, so a committed slot never references a
//! missing record. The committed table length encodes the table's
//! geometry: the blob grows one slot per landed resize chunk, so a length between two
//! powers of two is a resize the freezer did not finish and initialization drops the
//! partially copied upper half (the resize restarts once triggered again).
//! Initialization then rescans the table to count entries eligible for resizing,
//! failing loudly on any slot that does not decode or that references a record the
//! journals do not hold.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::paged::CacheRef};
//! use commonware_storage::freezer::{Freezer, Config, Identifier};
//! use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a freezer
//!     let cfg = Config {
//!         key_partition: "freezer-key-index".into(),
//!         key_write_buffer: NZUsize!(1024 * 1024), // 1MB
//!         key_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
//!         value_partition: "freezer-value-journal".into(),
//!         value_compression: Some(3),
//!         value_write_buffer: NZUsize!(1024 * 1024), // 1MB
//!         value_target_size: 100 * 1024 * 1024, // 100MB
//!         table_partition: "freezer-table".into(),
//!         table_initial_size: 65_536, // ~3MB initial table size
//!         table_resize_frequency: 4, // Force resize once 4 writes to the same entry occur
//!         table_resize_chunk_size: 16_384, // ~1MB of table entries rewritten per sync
//!         table_replay_buffer: NZUsize!(1024 * 1024), // 1MB
//!         codec_config: (),
//!     };
//!     let mut freezer = Freezer::<_, FixedBytes<32>, i32>::init(context, cfg).await.unwrap();
//!
//!     // Put a key-value pair
//!     let key = FixedBytes::new([1u8; 32]);
//!     freezer.put(key.clone(), 42).await.unwrap();
//!
//!     // Sync to disk
//!     freezer.sync().await.unwrap();
//!
//!     // Get the value
//!     let value = freezer.get(Identifier::Key(&key)).await.unwrap().unwrap();
//!     assert_eq!(value, 42);
//!
//!     // Close the freezer
//!     freezer.close().await.unwrap();
//! });
//! ```

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
mod storage;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_utils::Array;
use std::num::NonZeroUsize;
pub use storage::{Cursor, Freezer};
use thiserror::Error;

/// Subject of a [Freezer::get] operation.
pub enum Identifier<'a, K: Array> {
    Cursor(Cursor),
    Key(&'a K),
}

/// Errors that can occur when interacting with the [Freezer].
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    /// The table blob length cannot describe a committed table.
    ///
    /// Table writes are slot-aligned and every committed table holds at least one slot,
    /// so this is corruption or tampering, never a state a crash can produce.
    #[error("invalid table length: {0}")]
    InvalidTableLength(u64),
    /// A table slot references a journal record that does not exist.
    ///
    /// Committed slots always reference committed journal records (the journals commit
    /// before or atomically with the table), so this is corruption or tampering, never
    /// a state a crash can produce.
    #[error("table references a missing record (section: {0}, position: {1})")]
    MissingRecord(u64, u64),
}

/// Configuration for [Freezer].
#[derive(Clone)]
pub struct Config<C> {
    /// The [commonware_runtime::Storage] partition for the key index journal.
    pub key_partition: String,

    /// The size of the write buffer for the key index journal.
    pub key_write_buffer: NonZeroUsize,

    /// The page cache for the key index journal.
    pub key_page_cache: CacheRef,

    /// The [commonware_runtime::Storage] partition for the value journal.
    pub value_partition: String,

    /// The compression level for the value journal.
    pub value_compression: Option<u8>,

    /// The size of the write buffer for the value journal.
    pub value_write_buffer: NonZeroUsize,

    /// The target size of each value journal section before creating a new one.
    pub value_target_size: u64,

    /// The [commonware_runtime::Storage] partition to use for storing the table.
    pub table_partition: String,

    /// The initial number of items in the table.
    pub table_initial_size: u32,

    /// The number of items that must be added to 50% of table entries since the last resize before
    /// the table is resized again.
    pub table_resize_frequency: u8,

    /// The number of items to move during each resize operation (many may be required to complete a resize).
    pub table_resize_chunk_size: u32,

    /// The size of the read buffer to use when scanning the table (e.g., during recovery or resize).
    pub table_replay_buffer: NonZeroUsize,

    /// The codec configuration to use for the value stored in the freezer.
    pub codec_config: C,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use commonware_formatting::hex;
    use commonware_macros::{test_group, test_traced};
    use commonware_runtime::{deterministic, Blob, Metrics as _, Runner, Storage, Supervisor as _};
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16};
    use rand::{Rng, RngExt as _};
    use std::num::NonZeroU16;

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_VALUE_TARGET_SIZE: u64 = 10 * 1024 * 1024;
    const DEFAULT_TABLE_INITIAL_SIZE: u32 = 256;
    const DEFAULT_TABLE_RESIZE_FREQUENCY: u8 = 4;
    const DEFAULT_TABLE_RESIZE_CHUNK_SIZE: u32 = 128; // force multiple chunks
    const DEFAULT_TABLE_REPLAY_BUFFER: usize = 64 * 1024; // 64KB
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn test_put_get(compression: Option<u8>) {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: compression,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to initialize freezer");

            let key = test_key("testkey");
            let data = 42;

            // Check key doesn't exist
            let value = freezer
                .get(Identifier::Key(&key))
                .await
                .expect("Failed to check key");
            assert!(value.is_none());

            // Put the key-data pair
            freezer
                .put(key.clone(), data)
                .await
                .expect("Failed to put data");

            // Get the data back
            let value = freezer
                .get(Identifier::Key(&key))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(value, data);

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("gets_total 2"), "{}", buffer);
            assert!(buffer.contains("puts_total 1"), "{}", buffer);
            assert!(buffer.contains("unnecessary_reads_total 0"), "{}", buffer);

            // Force a sync
            freezer.sync().await.expect("Failed to sync data");
        });
    }

    #[test_traced]
    fn test_put_get_no_compression() {
        test_put_get(None);
    }

    #[test_traced]
    fn test_put_get_compression() {
        test_put_get(Some(3));
    }

    #[test_traced]
    fn test_has() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("storage"), cfg)
                    .await
                    .expect("Failed to initialize freezer");

            // Absent key
            let key = test_key("testkey");
            assert!(!freezer.has(&key).await.expect("Failed to check key"));

            // Present key
            freezer
                .put(key.clone(), 42)
                .await
                .expect("Failed to put data");
            assert!(freezer.has(&key).await.expect("Failed to check key"));

            // A different key remains absent
            assert!(!freezer
                .has(&test_key("otherkey"))
                .await
                .expect("Failed to check key"));

            // Existence checks are counted as has, never as gets
            let buffer = context.encode();
            assert!(buffer.contains("has_total 3"), "{}", buffer);
            assert!(buffer.contains("gets_total 0"), "{}", buffer);
        });
    }

    #[test_traced]
    fn test_multiple_keys() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to initialize freezer");

            // Insert multiple keys
            let keys = vec![
                (test_key("key1"), 1),
                (test_key("key2"), 2),
                (test_key("key3"), 3),
                (test_key("key4"), 4),
                (test_key("key5"), 5),
            ];

            for (key, data) in &keys {
                freezer
                    .put(key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Retrieve all keys and verify
            for (key, data) in &keys {
                let retrieved = freezer
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);
            }
        });
    }

    #[test_traced]
    fn test_collision_handling() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer with a very small table to force collisions
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: 4, // Very small to force collisions
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to initialize freezer");

            // Insert multiple keys that will likely collide
            let keys = vec![
                (test_key("key1"), 1),
                (test_key("key2"), 2),
                (test_key("key3"), 3),
                (test_key("key4"), 4),
                (test_key("key5"), 5),
                (test_key("key6"), 6),
                (test_key("key7"), 7),
                (test_key("key8"), 8),
            ];

            for (key, data) in &keys {
                freezer
                    .put(key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Sync to disk
            freezer.sync().await.expect("Failed to sync");

            // Retrieve all keys and verify they can still be found
            for (key, data) in &keys {
                let retrieved = freezer
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *data);
            }

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("gets_total 8"), "{}", buffer);
            assert!(buffer.contains("unnecessary_reads_total 5"), "{}", buffer);
        });
    }

    #[test_traced]
    fn test_restart() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };

            // Insert data and close the freezer
            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                let keys = vec![
                    (test_key("persist1"), 100),
                    (test_key("persist2"), 200),
                    (test_key("persist3"), 300),
                ];

                for (key, data) in &keys {
                    freezer
                        .put(key.clone(), *data)
                        .await
                        .expect("Failed to put data");
                }

                freezer.close().await.expect("Failed to close freezer")
            };

            // Reopen and verify data persisted
            {
                let freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                let keys = vec![
                    (test_key("persist1"), 100),
                    (test_key("persist2"), 200),
                    (test_key("persist3"), 300),
                ];

                for (key, data) in &keys {
                    let retrieved = freezer
                        .get(Identifier::Key(key))
                        .await
                        .expect("Failed to get data")
                        .expect("Data not found");
                    assert_eq!(retrieved, *data);
                }
            }
        });
    }

    /// After a crash, the freezer must recover exactly its committed state: synced keys
    /// stay reachable, unsynced keys vanish.
    #[test_traced]
    fn test_crash_consistency() {
        fn crash_cfg(pooler: &impl commonware_runtime::BufferPooler) -> Config<()> {
            Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            }
        }

        // Commit two keys, write two more without syncing, then crash
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let mut freezer = Freezer::<_, FixedBytes<64>, i32>::init(
                context.child("first"),
                crash_cfg(&context),
            )
            .await
            .expect("Failed to initialize freezer");

            freezer
                .put(test_key("committed1"), 1)
                .await
                .expect("Failed to put data");
            freezer
                .put(test_key("committed2"), 2)
                .await
                .expect("Failed to put data");
            freezer.sync().await.expect("Failed to sync");

            freezer
                .put(test_key("uncommitted1"), 3)
                .await
                .expect("Failed to put data");
            freezer
                .put(test_key("uncommitted2"), 4)
                .await
                .expect("Failed to put data");
        });

        // Reopen and verify only committed data is present
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let freezer = Freezer::<_, FixedBytes<64>, i32>::init(
                context.child("second"),
                crash_cfg(&context),
            )
            .await
            .expect("Failed to initialize freezer");

            // Committed data should be present
            assert_eq!(
                freezer
                    .get(Identifier::Key(&test_key("committed1")))
                    .await
                    .unwrap(),
                Some(1)
            );
            assert_eq!(
                freezer
                    .get(Identifier::Key(&test_key("committed2")))
                    .await
                    .unwrap(),
                Some(2)
            );

            // Uncommitted data is gone
            assert_eq!(
                freezer
                    .get(Identifier::Key(&test_key("uncommitted1")))
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                freezer
                    .get(Identifier::Key(&test_key("uncommitted2")))
                    .await
                    .unwrap(),
                None
            );
        });
    }

    #[test_traced]
    fn test_destroy() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                freezer
                    .put(test_key("destroy1"), 1)
                    .await
                    .expect("Failed to put data");
                freezer
                    .put(test_key("destroy2"), 2)
                    .await
                    .expect("Failed to put data");

                // Destroy the freezer
                freezer.destroy().await.expect("Failed to destroy freezer");
            }

            // Try to create a new freezer - it should be empty
            {
                let freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                // Should not find any data
                assert!(freezer
                    .get(Identifier::Key(&test_key("destroy1")))
                    .await
                    .unwrap()
                    .is_none());
                assert!(freezer
                    .get(Identifier::Key(&test_key("destroy2")))
                    .await
                    .unwrap()
                    .is_none());
            }
        });
    }

    #[test_traced]
    fn test_table_garbage_is_loud() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                freezer.put(test_key("key1"), 42).await.unwrap();
                freezer.sync().await.unwrap();
                freezer.close().await.unwrap()
            };

            // Overwrite the first table slot with garbage. A crash cannot produce this
            // (slots are synced atomically), so it is corruption.
            {
                let (blob, _) = context.open(&cfg.table_partition, b"table").await.unwrap();
                blob.write_at_sync(0, vec![0xFF; 10]).await.unwrap();
            }

            // Reopen: garbage in committed state is loud, never repaired
            let result =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Codec(_))));
        });
    }

    #[test_traced]
    fn test_table_extra_bytes() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };

            // Create freezer with data
            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                freezer.put(test_key("key1"), 42).await.unwrap();
                freezer.sync().await.unwrap();
                freezer.close().await.unwrap()
            };

            // Add extra bytes to the table blob
            {
                let (blob, size) = context.open(&cfg.table_partition, b"table").await.unwrap();
                // Append garbage data
                blob.write_at_sync(size, hex!("0xdeadbeef").to_vec())
                    .await
                    .unwrap();
            }

            // Reopen and verify it handles extra bytes gracefully
            {
                let freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                // Should still be able to read the key
                assert_eq!(
                    freezer
                        .get(Identifier::Key(&test_key("key1")))
                        .await
                        .unwrap(),
                    Some(42)
                );

                // And write new data
                let mut freezer_mut = freezer;
                freezer_mut.put(test_key("key2"), 43).await.unwrap();
                assert_eq!(
                    freezer_mut
                        .get(Identifier::Key(&test_key("key2")))
                        .await
                        .unwrap(),
                    Some(43)
                );
            }
        });
    }

    #[test_traced]
    fn test_indexing_across_resizes() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: 2, // Very small initial size to force multiple resizes
                table_resize_frequency: 2, // Resize after 2 items per entry
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to initialize freezer");

            // Insert many keys to force multiple table resizes
            // Table will grow from 2 -> 4 -> 8 -> 16 -> 32 -> 64 -> 128 -> 256 -> 512 -> 1024
            let mut keys = Vec::new();
            for i in 0..1000 {
                let key = test_key(&format!("key{i}"));
                keys.push((key.clone(), i));

                // Force sync to ensure resize occurs ASAP
                freezer.put(key, i).await.expect("Failed to put data");
                freezer.sync().await.expect("Failed to sync");
            }

            // Verify all keys can still be found after multiple resizes
            for (key, value) in &keys {
                let retrieved = freezer
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *value, "Value mismatch for key after resizes");
            }

            // Verify metrics show resize operations occurred. Must be checked
            // before closing: dropping the freezer drops its Registered metric
            // handles, which unregisters the metrics.
            let buffer = context.encode();
            assert!(buffer.contains("first_resizes_total 8"), "{}", buffer);

            // Close and reopen to verify persistence
            freezer.close().await.expect("Failed to close");
            let freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinitialize freezer");

            // Verify all keys can still be found after restart
            for (key, value) in &keys {
                let retrieved = freezer
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *value, "Value mismatch for key after restart");
            }
        });
    }

    #[test_traced]
    fn test_insert_during_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: 2,
                table_resize_frequency: 1,
                table_resize_chunk_size: 1, // Process one at a time
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("storage"), cfg.clone())
                    .await
                    .unwrap();

            // Insert keys to trigger resize
            // key0 -> entry 0, key2 -> entry 1
            freezer.put(test_key("key0"), 0).await.unwrap();
            freezer.put(test_key("key2"), 1).await.unwrap();
            freezer.sync().await.unwrap(); // should start resize

            // Verify resize started
            assert!(freezer.resizing().is_some());

            // Insert during resize (to first entry)
            // key6 -> entry 0
            freezer.put(test_key("key6"), 2).await.unwrap();
            assert!(context.encode().contains("unnecessary_writes_total 1"));
            assert_eq!(freezer.resizable(), 3);

            // Insert another key (to unmodified entry)
            // key3 -> entry 1
            freezer.put(test_key("key3"), 3).await.unwrap();
            assert!(context.encode().contains("unnecessary_writes_total 1"));
            assert_eq!(freezer.resizable(), 3);

            // Verify resize completed
            freezer.sync().await.unwrap();
            assert!(freezer.resizing().is_none());
            assert_eq!(freezer.resizable(), 2);

            // More inserts
            // key4 -> entry 1, key7 -> entry 0
            freezer.put(test_key("key4"), 4).await.unwrap();
            freezer.put(test_key("key7"), 5).await.unwrap();
            freezer.sync().await.unwrap();

            // Another resize should've started
            assert!(freezer.resizing().is_some());

            // Verify all can be retrieved during resize
            let keys = ["key0", "key2", "key6", "key3", "key4", "key7"];
            for (i, k) in keys.iter().enumerate() {
                assert_eq!(
                    freezer.get(Identifier::Key(&test_key(k))).await.unwrap(),
                    Some(i as i32)
                );
            }

            // Sync until resize completes
            while freezer.resizing().is_some() {
                freezer.sync().await.unwrap();
            }

            // Ensure no entries are considered resizable
            assert_eq!(freezer.resizable(), 0);
        });
    }

    #[test_traced]
    fn test_resize_after_startup() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: 2,
                table_resize_frequency: 1,
                table_resize_chunk_size: 1, // Process one at a time
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };

            // Create freezer and then shutdown uncleanly
            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();

                // Insert keys to trigger resize
                // key0 -> entry 0, key2 -> entry 1
                freezer.put(test_key("key0"), 0).await.unwrap();
                freezer.put(test_key("key2"), 1).await.unwrap();
                freezer.sync().await.unwrap();

                // Verify resize started
                assert!(freezer.resizing().is_some());
            }

            // Reopen freezer
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();
            assert_eq!(freezer.resizable(), 1);
            assert_eq!(freezer.resizing(), None);

            // Verify the resize restarts from the recovered table.
            freezer.sync().await.unwrap();
            assert_eq!(freezer.resizing(), Some(1));

            // Run until resize completes
            while freezer.resizing().is_some() {
                freezer.sync().await.unwrap();
            }

            // Ensure no entries are considered resizable
            assert_eq!(freezer.resizable(), 0);
        });
    }

    fn test_operations_and_restart(num_keys: usize) -> String {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: 128, // Force multiple journal sections
                table_partition: "test-table".into(),
                table_initial_size: 8,     // Small table to force collisions
                table_resize_frequency: 2, // Force resize frequently
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            let mut freezer = Freezer::<_, FixedBytes<96>, FixedBytes<256>>::init(
                context.child("init").with_attribute("index", 1),
                cfg.clone(),
            )
            .await
            .expect("Failed to initialize freezer");

            // Generate and insert random key-value pairs
            let mut pairs = Vec::new();

            for _ in 0..num_keys {
                // Generate random key
                let mut key = [0u8; 96];
                context.fill_bytes(&mut key);
                let key = FixedBytes::<96>::new(key);

                // Generate random value
                let mut value = [0u8; 256];
                context.fill_bytes(&mut value);
                let value = FixedBytes::<256>::new(value);

                // Store the key-value pair
                freezer
                    .put(key.clone(), value.clone())
                    .await
                    .expect("Failed to put data");
                pairs.push((key, value));

                // Randomly sync to test resizing
                if context.random_bool(0.1) {
                    freezer.sync().await.expect("Failed to sync");
                }
            }

            // Sync data
            freezer.sync().await.expect("Failed to sync");

            // Verify all pairs can be retrieved
            for (key, value) in &pairs {
                let retrieved = freezer
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, value);
            }

            // Test get() on all keys
            for (key, _) in &pairs {
                assert!(freezer
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to check key")
                    .is_some());
            }

            // Check some non-existent keys
            for _ in 0..10 {
                let mut key = [0u8; 96];
                context.fill_bytes(&mut key);
                let key = FixedBytes::<96>::new(key);
                assert!(freezer
                    .get(Identifier::Key(&key))
                    .await
                    .expect("Failed to check key")
                    .is_none());
            }

            // Close the freezer
            freezer.close().await.expect("Failed to close freezer");

            // Reopen the freezer
            let mut freezer = Freezer::<_, FixedBytes<96>, FixedBytes<256>>::init(
                context.child("init").with_attribute("index", 2),
                cfg.clone(),
            )
            .await
            .expect("Failed to initialize freezer");

            // Verify all pairs are still there after restart
            for (key, value) in &pairs {
                let retrieved = freezer
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, value);
            }

            // Add more pairs after restart to test collision handling
            for _ in 0..20 {
                let mut key = [0u8; 96];
                context.fill_bytes(&mut key);
                let key = FixedBytes::<96>::new(key);

                let mut value = [0u8; 256];
                context.fill_bytes(&mut value);
                let value = FixedBytes::<256>::new(value);

                freezer.put(key, value).await.expect("Failed to put data");
            }

            // Multiple syncs to test commit progression
            for _ in 0..3 {
                freezer.sync().await.expect("Failed to sync");

                // Add a few more entries between syncs
                for _ in 0..5 {
                    let mut key = [0u8; 96];
                    context.fill_bytes(&mut key);
                    let key = FixedBytes::<96>::new(key);

                    let mut value = [0u8; 256];
                    context.fill_bytes(&mut value);
                    let value = FixedBytes::<256>::new(value);

                    freezer.put(key, value).await.expect("Failed to put data");
                }
            }

            // Final sync
            freezer.sync().await.expect("Failed to sync");

            // Return the auditor state for comparison
            context.auditor().state()
        })
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_determinism() {
        let state1 = test_operations_and_restart(1_000);
        let state2 = test_operations_and_restart(1_000);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_put_multiple_updates() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_target_size: DEFAULT_VALUE_TARGET_SIZE,
                table_partition: "test-table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: NZUsize!(DEFAULT_TABLE_REPLAY_BUFFER),
                codec_config: (),
            };
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to initialize freezer");

            let key = test_key("key1");

            freezer
                .put(key.clone(), 1)
                .await
                .expect("Failed to put data");
            freezer
                .put(key.clone(), 2)
                .await
                .expect("Failed to put data");
            freezer.sync().await.expect("Failed to sync");
            assert_eq!(
                freezer
                    .get(Identifier::Key(&key))
                    .await
                    .expect("Failed to get data")
                    .unwrap(),
                2
            );
        });
    }
}
