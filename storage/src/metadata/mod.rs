//! A key-value store optimized for atomically committing a small collection of metadata.
//!
//! `Metadata` is a key-value store optimized for tracking a small collection of metadata
//! that allows multiple updates to be committed in a single batch. It is commonly used with
//! a variety of other underlying storage systems to persist application state across restarts.
//!
//! # Format
//!
//! Data stored in `Metadata` is serialized as a sequence of key-value pairs in either a
//! "left" or "right" blob:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 |    ...    | 8 | 9 |10 |11 |12 |13 |14 |15 |16 |  ...  |50 |...|90 |91 |92 |93 |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |    Version (u64)  |  Key1 (u32)   | Len(V1) (u32) |    Value1     |...|  CRC32(u32)   |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//!
//! Len(V1) = Length of Value1
//! ... = Other key-value pairs (Key2|VLen2|Value2, Key3|VLen3|Value3, ...)
//! ```
//!
//! _To ensure the integrity of the data, a CRC32 checksum is appended to the end of the blob.
//! This ensures that partial writes are detected before any data is relied on._
//!
//! # Atomic Updates
//!
//! To provide support for atomic updates, `Metadata` maintains two blobs: a "left" and a "right"
//! blob. When a new update is committed, it is written to the "older" of the two blobs (indicated
//! by the version persisted). Writes to `Storage` are not atomic and may only complete partially,
//! so we only overwrite the "newer" blob once the "older" blob has been synced (otherwise, we would
//! not be guaranteed to recover the latest complete state from disk on restart as half of a blob
//! could be old data and half new data).
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_storage::metadata::{Metadata, Config};
//! use commonware_utils::array::U64;
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a store
//!     let mut metadata = Metadata::init(context, Config{
//!         partition: "partition".to_string()
//!     }).await.unwrap();
//!
//!     // Store metadata
//!     metadata.put(U64::new(1), "hello".into());
//!     metadata.put(U64::new(2), "world".into());
//!
//!     // Sync the metadata store (batch write changes)
//!     metadata.sync().await.unwrap();
//!
//!     // Retrieve some metadata
//!     let value = metadata.get(&U64::new(1));
//!
//!     // Close the store
//!     metadata.close().await.unwrap();
//! });
//! ```

mod storage;
use commonware_utils::Array;
pub use storage::Metadata;
use thiserror::Error;

/// Errors that can occur when interacting with `Metadata`.
#[derive(Debug, Error)]
pub enum Error<K: Array> {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("blob too large: {0}")]
    BlobTooLarge(u64),
    #[error("value too big: {0}")]
    ValueTooBig(K),
}

/// Configuration for `Metadata` storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware_runtime::Storage` partition to
    /// use for storing metadata.
    pub partition: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::array::U64;

    #[test_traced]
    fn test_put_get_clear() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Get a key that doesn't exist
            let key = U64::new(42);
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 0"));

            // Put a key
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Get the key
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &hello);

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 1"));

            // Close the metadata store
            metadata.close().await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 1"));
            assert!(buffer.contains("keys 1"));

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 1"));

            // Get the key
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &hello);

            // Test clearing the metadata store
            metadata.clear();
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 0"));

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_multi_sync() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Put a key
            let key = U64::new(42);
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 1"));
            assert!(buffer.contains("keys 1"));

            // Put an overlapping key and a new key
            let world = b"world".to_vec();
            metadata.put(key.clone(), world.clone());
            let key2 = U64::new(43);
            let foo = b"foo".to_vec();
            metadata.put(key2.clone(), foo.clone());

            // Close the metadata store
            metadata.close().await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 2"));
            assert!(buffer.contains("keys 2"));

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 2"));

            // Get the key
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &world);
            let value = metadata.get(&key2).unwrap();
            assert_eq!(value, &foo);

            // Remove the key
            metadata.remove(&key);

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 1"));
            assert!(buffer.contains("keys 1"));

            // Close the metadata store
            metadata.close().await.unwrap();

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 1"));

            // Get the key
            let value = metadata.get(&key);
            assert!(value.is_none());
            let value = metadata.get(&key2).unwrap();
            assert_eq!(value, &foo);

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_recover_corrupted_one() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Put a key
            let key = U64::new(42);
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Put an overlapping key and a new key
            let world = b"world".to_vec();
            metadata.put(key.clone(), world.clone());
            let key2 = U64::new(43);
            let foo = b"foo".to_vec();
            metadata.put(key2, foo.clone());

            // Close the metadata store
            metadata.close().await.unwrap();

            // Corrupt the metadata store
            let (blob, _) = context.open("test", b"left").await.unwrap();
            blob.write_at(b"corrupted".to_vec(), 0).await.unwrap();
            blob.close().await.unwrap();

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Get the key (falls back to non-corrupt)
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &hello);

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_recover_corrupted_both() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Put a key
            let key = U64::new(42);
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Put an overlapping key and a new key
            let world = b"world".to_vec();
            metadata.put(key.clone(), world.clone());
            let key2 = U64::new(43);
            let foo = b"foo".to_vec();
            metadata.put(key2, foo.clone());

            // Close the metadata store
            metadata.close().await.unwrap();

            // Corrupt the metadata store
            let (blob, _) = context.open("test", b"left").await.unwrap();
            blob.write_at(b"corrupted".to_vec(), 0).await.unwrap();
            blob.close().await.unwrap();
            let (blob, _) = context.open("test", b"right").await.unwrap();
            blob.write_at(b"corrupted".to_vec(), 0).await.unwrap();
            blob.close().await.unwrap();

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Get the key (falls back to non-corrupt)
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 0"));

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_recover_corrupted_truncate() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Put a key
            let key = U64::new(42);
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Put an overlapping key and a new key
            let world = b"world".to_vec();
            metadata.put(key.clone(), world.clone());
            let key2 = U64::new(43);
            let foo = b"foo".to_vec();
            metadata.put(key2, foo.clone());

            // Close the metadata store
            metadata.close().await.unwrap();

            // Corrupt the metadata store
            let (blob, len) = context.open("test", b"left").await.unwrap();
            blob.resize(len - 8).await.unwrap();
            blob.close().await.unwrap();

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Get the key (falls back to non-corrupt)
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &hello);

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_recover_corrupted_short() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Put a key
            let key = U64::new(42);
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Put an overlapping key and a new key
            let world = b"world".to_vec();
            metadata.put(key.clone(), world.clone());
            let key2 = U64::new(43);
            let foo = b"foo".to_vec();
            metadata.put(key2, foo.clone());

            // Close the metadata store
            metadata.close().await.unwrap();

            // Corrupt the metadata store
            let (blob, _) = context.open("test", b"left").await.unwrap();
            blob.resize(5).await.unwrap();
            blob.close().await.unwrap();

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Get the key (falls back to non-corrupt)
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &hello);

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let key = U64::new(42);
            let hello = b"hello".to_vec();
            {
                // Create a metadata store
                let cfg = Config {
                    partition: "test".to_string(),
                };
                let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

                // Put a key
                metadata.put(key.clone(), hello.clone());

                // Drop metadata before sync
            }

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Get the key
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 0"));

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_value_too_big_error() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Create a value that exceeds u32::MAX bytes
            let value = vec![0u8; (u32::MAX as usize) + 1];
            metadata.put(U64::new(1), value);

            // Assert
            let result = metadata.sync().await;
            assert!(matches!(result, Err(Error::ValueTooBig(_))));

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_diff_optimization() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Put initial keys with large values
            for i in 0..50 {
                metadata.put(U64::new(i), vec![i as u8; 1000]);
            }

            // First sync - writes everything
            metadata.sync().await.unwrap();

            // Test 1: No changes sync - should still write due to version increment
            metadata.sync().await.unwrap();

            // Test 2: Modify one key in the middle
            metadata.put(U64::new(25), vec![255u8; 1000]);
            metadata.sync().await.unwrap();

            // Test 3: Add a new key at the end
            metadata.put(U64::new(50), vec![200u8; 1000]);
            metadata.sync().await.unwrap();

            // Test 4: Remove a key in the middle
            metadata.remove(&U64::new(25));
            metadata.sync().await.unwrap();

            // Test 5: Modify multiple scattered keys
            metadata.put(U64::new(5), vec![100u8; 1000]);
            metadata.put(U64::new(20), vec![101u8; 1000]);
            metadata.put(U64::new(35), vec![102u8; 1000]);
            metadata.sync().await.unwrap();

            // Close and reopen to verify data integrity
            metadata.close().await.unwrap();
            let cfg = Config {
                partition: "test".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Verify final state
            assert!(metadata.get(&U64::new(25)).is_none());
            assert_eq!(metadata.get(&U64::new(5)).unwrap(), &vec![100u8; 1000]);
            assert_eq!(metadata.get(&U64::new(20)).unwrap(), &vec![101u8; 1000]);
            assert_eq!(metadata.get(&U64::new(35)).unwrap(), &vec![102u8; 1000]);
            assert_eq!(metadata.get(&U64::new(50)).unwrap(), &vec![200u8; 1000]);

            // Verify keys that shouldn't have changed
            assert_eq!(metadata.get(&U64::new(0)).unwrap(), &vec![0u8; 1000]);
            assert_eq!(metadata.get(&U64::new(49)).unwrap(), &vec![49u8; 1000]);

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_diff_edge_cases() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test edge case 1: Empty metadata sync
            let cfg = Config {
                partition: "test1".to_string(),
            };
            let mut metadata: Metadata<_, U64> =
                Metadata::init(context.clone(), cfg).await.unwrap();
            metadata.sync().await.unwrap();
            metadata.sync().await.unwrap(); // Second sync with no changes
            metadata.close().await.unwrap();

            // Test edge case 2: Single key metadata
            let cfg = Config {
                partition: "test2".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();
            metadata.put(U64::new(0), vec![42u8; 10]);
            metadata.sync().await.unwrap();

            // Change the single key
            metadata.put(U64::new(0), vec![43u8; 10]);
            metadata.sync().await.unwrap();

            metadata.destroy().await.unwrap();

            // Test edge case 3: Keys with varying sizes
            let cfg = Config {
                partition: "test3".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Add keys with different sizes
            metadata.put(U64::new(0), vec![0u8; 10]);
            metadata.put(U64::new(1), vec![1u8; 100]);
            metadata.put(U64::new(2), vec![2u8; 1000]);
            metadata.sync().await.unwrap();

            // Change middle key to different size
            metadata.put(U64::new(1), vec![1u8; 50]);
            metadata.sync().await.unwrap();

            // Verify data integrity
            metadata.close().await.unwrap();
            let cfg = Config {
                partition: "test3".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();
            assert_eq!(metadata.get(&U64::new(0)).unwrap(), &vec![0u8; 10]);
            assert_eq!(metadata.get(&U64::new(1)).unwrap(), &vec![1u8; 50]);
            assert_eq!(metadata.get(&U64::new(2)).unwrap(), &vec![2u8; 1000]);

            metadata.destroy().await.unwrap();

            // Test edge case 4: Alternating blob writes
            let cfg = Config {
                partition: "test4".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Multiple syncs to test alternating blob usage
            for i in 0..5 {
                metadata.put(U64::new(i), vec![i as u8; 100]);
                metadata.sync().await.unwrap();
            }

            // Verify all data is preserved
            for i in 0..5 {
                assert_eq!(metadata.get(&U64::new(i)).unwrap(), &vec![i as u8; 100]);
            }

            metadata.destroy().await.unwrap();
        });
    }
}
