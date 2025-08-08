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
//! The [Freezer] uses a two-level architecture: an extendible hash table (written in a single [commonware_runtime::Blob])
//! that maps keys to locations and a [crate::journal::variable::Journal] that stores key-value data.
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
//! |                             Journal                             |
//! |  Section 0: [Record 0][Record 1][Record 2]...                   |
//! |  Section 1: [Record 10][Record 11][Record 12]...                |
//! |  Section N: [Record 100][Record 101][Record 102]...             |
//! +-----------------------------------------------------------------+
//! ```
//!
//! The table uses two fixed-size slots per entry to ensure consistency during updates. Each slot
//! contains an epoch number that monotonically increases with each sync operation. During reads,
//! the slot with the higher epoch is selected (provided it's not greater than the last committed
//! epoch), ensuring consistency even if the system crashed during a write.
//!
//! ```text
//! +-------------------------------------+
//! |          Hash Table Entry           |
//! +-------------------------------------+
//! |     Slot 0      |      Slot 1       |
//! +-----------------+-------------------+
//! | epoch:    u64   | epoch:    u64     |
//! | section:  u64   | section:  u64     |
//! | offset:   u32   | offset:   u32     |
//! | added:    u8    | added:    u8      |
//! +-----------------+-------------------+
//! | CRC32:    u32   | CRC32:    u32     |
//! +-----------------+-------------------+
//! ```
//!
//! The journal stores variable-sized records, each containing a key-value pair and an optional pointer
//! to the next record in the collision chain (for keys that hash to the same table index).
//!
//! ```text
//! +-------------------------------------+
//! |           Journal Record            |
//! +-------------------------------------+
//! | Key:   Array                        |
//! | Value: Codec                        |
//! | Next:  Option<(u64, u32)>           |
//! +-------------------------------------+
//! ```
//!
//! # Traversing Conflicts
//!
//! When multiple keys hash to the same table index, they form a linked list within the journal:
//!
//! ```text
//! Hash Table:
//! [Index 42]      +-------------------+
//!                 | section: 2        |
//!                 | offset: 768       |
//!                 +---------+---------+
//!                           |
//! Journal:                  v
//! [Section 2]     +-----+------------+-----+-----+-----+-----+-----+-----+
//!                 | ... | Key: "foo" | ... | ... | ... | ... | ... | ... |
//!                 |     | Value: 42  |     |     |     |     |     |     |
//!                 |     | Next:(1,512)---+ |     |     |     |     |     |
//!                 +-----+------------+---+-+-----+-----+-----+-----+-----+
//!                                        |
//!                                        v
//! [Section 1]     +-----+-----+-----+------------+-----+-----+-----+-----+
//!                 | ... | ... | ... | Key: "bar" | ... | ... | ... | ... |
//!                 |     |     |     | Value: 84  |     |     |     |     |
//!                 |     |     | +---| Next:(0,256)     |     |     |     |
//!                 +-----+-----+-+---+------------+-----+-----+-----+-----+
//!                               |
//!                               v
//! [Section 0]     +-----+------------+-----+-----+-----+-----+-----+-----+
//!                 | ... | Key: "baz" | ... | ... | ... | ... | ... | ... |
//!                 |     | Value: 126 |     |     |     |     |     |     |
//!                 |     | Next: None |     |     |     |     |     |     |
//!                 +-----+------------+-----+-----+-----+-----+-----+-----+
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
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_storage::freezer::{Freezer, Config, Identifier};
//! use commonware_utils::sequence::FixedBytes;
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a freezer
//!     let cfg = Config {
//!         journal_partition: "freezer_journal".into(),
//!         journal_compression: Some(3),
//!         journal_write_buffer: 1024 * 1024, // 1MB
//!         journal_target_size: 100 * 1024 * 1024, // 100MB
//!         table_partition: "freezer_table".into(),
//!         table_initial_size: 65_536, // ~3MB initial table size
//!         table_resize_frequency: 4, // Force resize once 4 writes to the same entry occur
//!         table_resize_chunk_size: 16_384, // ~1MB of table entries rewritten per sync
//!         table_replay_buffer: 1024 * 1024, // 1MB
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

mod storage;
use commonware_utils::Array;
pub use storage::{Checkpoint, Cursor, Freezer};
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
}

/// Configuration for [Freezer].
#[derive(Clone)]
pub struct Config<C> {
    /// The [commonware_runtime::Storage] partition to use for storing the journal.
    pub journal_partition: String,

    /// The compression level to use for the [crate::journal::variable::Journal].
    pub journal_compression: Option<u8>,

    /// The size of the write buffer to use for the journal.
    pub journal_write_buffer: usize,

    /// The target size of each journal before creating a new one.
    pub journal_target_size: u64,

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
    pub table_replay_buffer: usize,

    /// The codec configuration to use for the value stored in the freezer.
    pub codec_config: C,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::sequence::FixedBytes;
    use rand::{Rng, RngCore};

    const DEFAULT_JOURNAL_WRITE_BUFFER: usize = 1024;
    const DEFAULT_JOURNAL_TARGET_SIZE: u64 = 10 * 1024 * 1024;
    const DEFAULT_TABLE_INITIAL_SIZE: u32 = 256;
    const DEFAULT_TABLE_RESIZE_FREQUENCY: u8 = 4;
    const DEFAULT_TABLE_RESIZE_CHUNK_SIZE: u32 = 128; // force multiple chunks
    const DEFAULT_TABLE_REPLAY_BUFFER: usize = 64 * 1024; // 64KB

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    fn test_put_get(compression: Option<u8>) {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: compression,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };
            let mut freezer = Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
    fn test_multiple_keys() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };
            let mut freezer = Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: 4, // Very small to force collisions
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };
            let mut freezer = Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };

            // Insert data and close the freezer
            let checkpoint = {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
                let freezer = Freezer::<_, FixedBytes<64>, i32>::init_with_checkpoint(
                    context.clone(),
                    cfg.clone(),
                    Some(checkpoint),
                )
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

    #[test_traced]
    fn test_crash_consistency() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };

            // First, create some committed data and close the freezer
            let checkpoint = {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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

                // Sync to ensure data is committed
                freezer.sync().await.expect("Failed to sync");

                // Add more data but don't sync (simulating crash)
                freezer
                    .put(test_key("uncommitted1"), 3)
                    .await
                    .expect("Failed to put data");
                freezer
                    .put(test_key("uncommitted2"), 4)
                    .await
                    .expect("Failed to put data");

                // Close without syncing to simulate crash
                freezer.close().await.expect("Failed to close")
            };

            // Reopen and verify only committed data is present
            {
                let freezer = Freezer::<_, FixedBytes<64>, i32>::init_with_checkpoint(
                    context.clone(),
                    cfg.clone(),
                    Some(checkpoint),
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

                // Uncommitted data might or might not be present depending on implementation
                // But if present, it should be correct
                if let Some(val) = freezer
                    .get(Identifier::Key(&test_key("uncommitted1")))
                    .await
                    .unwrap()
                {
                    assert_eq!(val, 3);
                }
                if let Some(val) = freezer
                    .get(Identifier::Key(&test_key("uncommitted2")))
                    .await
                    .unwrap()
                {
                    assert_eq!(val, 4);
                }
            }
        });
    }

    #[test_traced]
    fn test_destroy() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };
            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
                let freezer = Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
    fn test_partial_table_entry_write() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the freezer
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };
            let checkpoint = {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                freezer.put(test_key("key1"), 42).await.unwrap();
                freezer.sync().await.unwrap();
                freezer.close().await.unwrap()
            };

            // Corrupt the table by writing partial entry
            {
                let (blob, _) = context.open(&cfg.table_partition, b"table").await.unwrap();
                // Write incomplete table entry (only 10 bytes instead of 24)
                blob.write_at(vec![0xFF; 10], 0).await.unwrap();
                blob.sync().await.unwrap();
            }

            // Reopen and verify it handles the corruption
            {
                let freezer = Freezer::<_, FixedBytes<64>, i32>::init_with_checkpoint(
                    context.clone(),
                    cfg.clone(),
                    Some(checkpoint),
                )
                .await
                .expect("Failed to initialize freezer");

                // The key should still be retrievable from journal if table is corrupted
                // but the table entry is zeroed out
                let result = freezer
                    .get(Identifier::Key(&test_key("key1")))
                    .await
                    .unwrap();
                assert!(result.is_none() || result == Some(42));
            }
        });
    }

    #[test_traced]
    fn test_table_entry_invalid_crc() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };

            // Create freezer with data
            let checkpoint = {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                        .await
                        .expect("Failed to initialize freezer");

                freezer.put(test_key("key1"), 42).await.unwrap();
                freezer.sync().await.unwrap();
                freezer.close().await.unwrap()
            };

            // Corrupt the CRC in the index entry
            {
                let (blob, _) = context.open(&cfg.table_partition, b"table").await.unwrap();
                // Read the first entry
                let entry_data = blob.read_at(vec![0u8; 24], 0).await.unwrap();
                let mut corrupted = entry_data.as_ref().to_vec();
                // Corrupt the CRC (last 4 bytes of the entry)
                corrupted[20] ^= 0xFF;
                blob.write_at(corrupted, 0).await.unwrap();
                blob.sync().await.unwrap();
            }

            // Reopen and verify it handles invalid CRC
            {
                let freezer = Freezer::<_, FixedBytes<64>, i32>::init_with_checkpoint(
                    context.clone(),
                    cfg.clone(),
                    Some(checkpoint),
                )
                .await
                .expect("Failed to initialize freezer");

                // With invalid CRC, the entry should be treated as invalid
                let result = freezer
                    .get(Identifier::Key(&test_key("key1")))
                    .await
                    .unwrap();
                // The freezer should still work but may not find the key due to invalid table entry
                assert!(result.is_none() || result == Some(42));
            }
        });
    }

    #[test_traced]
    fn test_table_extra_bytes() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: DEFAULT_TABLE_INITIAL_SIZE,
                table_resize_frequency: DEFAULT_TABLE_RESIZE_FREQUENCY,
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };

            // Create freezer with data
            let checkpoint = {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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
                blob.write_at(vec![0xDE, 0xAD, 0xBE, 0xEF], size)
                    .await
                    .unwrap();
                blob.sync().await.unwrap();
            }

            // Reopen and verify it handles extra bytes gracefully
            {
                let freezer = Freezer::<_, FixedBytes<64>, i32>::init_with_checkpoint(
                    context.clone(),
                    cfg.clone(),
                    Some(checkpoint),
                )
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
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: 2, // Very small initial size to force multiple resizes
                table_resize_frequency: 2, // Resize after 2 items per entry
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };
            let mut freezer = Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
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

            // Close and reopen to verify persistence
            let checkpoint = freezer.close().await.expect("Failed to close");
            let freezer = Freezer::<_, FixedBytes<64>, i32>::init_with_checkpoint(
                context.clone(),
                cfg.clone(),
                Some(checkpoint),
            )
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

            // Verify metrics show resize operations occurred
            let buffer = context.encode();
            assert!(buffer.contains("resizes_total 8"), "{}", buffer);
        });
    }

    #[test_traced]
    fn test_insert_during_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: 2,
                table_resize_frequency: 1,
                table_resize_chunk_size: 1, // Process one at a time
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };
            let mut freezer = Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Insert keys to trigger resize
            freezer.put(test_key("key0"), 0).await.unwrap();
            freezer.put(test_key("key1"), 1).await.unwrap();
            freezer.sync().await.unwrap(); // should start resize

            // Verify resize started
            assert!(freezer.resizing().is_some());

            // Insert during resize (to first entry)
            freezer.put(test_key("key2"), 2).await.unwrap();
            assert!(context.encode().contains("unnecessary_writes_total 1"));
            assert_eq!(freezer.resizable(), 3);

            // Insert another key (to unmodified entry)
            freezer.put(test_key("key3"), 3).await.unwrap();
            assert!(context.encode().contains("unnecessary_writes_total 1"));
            assert_eq!(freezer.resizable(), 3);

            // Verify resize completed
            freezer.sync().await.unwrap();
            assert!(freezer.resizing().is_none());
            assert_eq!(freezer.resizable(), 2);

            // More inserts
            freezer.put(test_key("key4"), 4).await.unwrap();
            freezer.put(test_key("key5"), 5).await.unwrap();
            freezer.sync().await.unwrap();

            // Another resize should've started
            assert!(freezer.resizing().is_some());

            // Verify all can be retrieved during resize
            for i in 0..6 {
                let key = test_key(&format!("key{i}"));
                assert_eq!(freezer.get(Identifier::Key(&key)).await.unwrap(), Some(i));
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
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: DEFAULT_JOURNAL_TARGET_SIZE,
                table_partition: "test_table".into(),
                table_initial_size: 2,
                table_resize_frequency: 1,
                table_resize_chunk_size: 1, // Process one at a time
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };

            // Create freezer and then shutdown uncleanly
            let checkpoint = {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.clone(), cfg.clone())
                        .await
                        .unwrap();

                // Insert keys to trigger resize
                freezer.put(test_key("key0"), 0).await.unwrap();
                freezer.put(test_key("key1"), 1).await.unwrap();
                let checkpoint = freezer.sync().await.unwrap();

                // Verify resize started
                assert!(freezer.resizing().is_some());

                checkpoint
            };

            // Reopen freezer
            let mut freezer = Freezer::<_, FixedBytes<64>, i32>::init_with_checkpoint(
                context.clone(),
                cfg.clone(),
                Some(checkpoint),
            )
            .await
            .unwrap();
            assert_eq!(freezer.resizable(), 1);

            // Verify resize starts immediately (1 key will have 0 added but 1
            // will still have 1)
            freezer.sync().await.unwrap();
            assert!(freezer.resizing().is_some());

            // Run until resize completes
            while freezer.resizing().is_some() {
                freezer.sync().await.unwrap();
            }

            // Ensure no entries are considered resizable
            assert_eq!(freezer.resizable(), 0);
        });
    }

    fn test_operations_and_restart(num_keys: usize) -> String {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Initialize the freezer
            let cfg = Config {
                journal_partition: "test_journal".into(),
                journal_compression: None,
                journal_write_buffer: DEFAULT_JOURNAL_WRITE_BUFFER,
                journal_target_size: 128, // Force multiple journal sections
                table_partition: "test_table".into(),
                table_initial_size: 8,     // Small table to force collisions
                table_resize_frequency: 2, // Force resize frequently
                table_resize_chunk_size: DEFAULT_TABLE_RESIZE_CHUNK_SIZE,
                table_replay_buffer: DEFAULT_TABLE_REPLAY_BUFFER,
                codec_config: (),
            };
            let mut freezer =
                Freezer::<_, FixedBytes<96>, FixedBytes<256>>::init(context.clone(), cfg.clone())
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
                if context.gen_bool(0.1) {
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
            let checkpoint = freezer.close().await.expect("Failed to close freezer");

            // Reopen the freezer
            let mut freezer = Freezer::<_, FixedBytes<96>, FixedBytes<256>>::init_with_checkpoint(
                context.clone(),
                cfg.clone(),
                Some(checkpoint),
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

            // Multiple syncs to test epoch progression
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

    #[test_traced]
    #[ignore]
    fn test_determinism() {
        let state1 = test_operations_and_restart(1_000);
        let state2 = test_operations_and_restart(1_000);
        assert_eq!(state1, state2);
    }
}
