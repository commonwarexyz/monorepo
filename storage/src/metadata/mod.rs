//! A key-value store optimized for atomically committing a small collection of metadata.
//!
//! [Metadata] is a key-value store optimized for tracking a small collection of metadata
//! that allows multiple updates to be committed in a single batch. It is commonly used with
//! a variety of other underlying storage systems to persist application state across restarts.
//!
//! # Format
//!
//! Data stored in [Metadata] is serialized as a sequence of key-value pairs in either a
//! "left" or "right" blob:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 |    ...    | 8 | 9 |10 |11 |12 |13 |14 |15 |16 |  ...  |50 |...|90 |91 |92 |93 |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |    Version (u64)  |      Key1     |              Value1           |...|  CRC32(u32)   |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! _To ensure the integrity of the data, a CRC32 checksum is appended to the end of the blob.
//! This ensures that partial writes are detected before any data is relied on._
//!
//! # Atomic Updates
//!
//! To provide support for atomic updates, [Metadata] maintains two blobs: a "left" and a "right"
//! blob. When a new update is committed, it is written to the "older" of the two blobs (indicated
//! by the version persisted). Writes to [commonware_runtime::Blob] are not atomic and may only
//! complete partially, so we only overwrite the "newer" blob once the "older" blob has been synced
//! (otherwise, we would not be guaranteed to recover the latest complete state from disk on
//! restart as half of a blob could be old data and half new data).
//!
//! # Delta Writes
//!
//! If the set of keys and the length of values are stable, [Metadata] will only write an update's
//! delta to disk (rather than rewriting the entire metadata). This makes [Metadata] a great choice
//! for maintaining even large collections of data (with the majority rarely modified).
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic};
//! use commonware_storage::metadata::{Metadata, Config};
//! use commonware_utils::sequence::U64;
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a store
//!     let mut metadata = Metadata::init(context, Config{
//!         partition: "partition".to_string(),
//!         codec_config: ((0..).into(), ()),
//!     }).await.unwrap();
//!
//!     // Store metadata
//!     metadata.put(U64::new(1), b"hello".to_vec());
//!     metadata.put(U64::new(2), b"world".to_vec());
//!
//!     // Sync the metadata store (batch write changes)
//!     metadata.sync().await.unwrap();
//!
//!     // Retrieve some metadata
//!     let value = metadata.get(&U64::new(1)).unwrap();
//!
//!     // Close the store
//!     metadata.close().await.unwrap();
//! });
//! ```

mod storage;
pub use storage::Metadata;
use thiserror::Error;

/// Errors that can occur when interacting with [Metadata].
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("blob too large: {0}")]
    BlobTooLarge(u64),
}

/// Configuration for [Metadata] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The [commonware_runtime::Storage] partition to use for storing metadata.
    pub partition: String,

    /// The codec configuration to use for the value stored in the metadata.
    pub codec_config: C,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::sequence::U64;
    use rand::{Rng, RngCore};

    #[test_traced]
    fn test_put_get_clear() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Get a key that doesn't exist
            let key = U64::new(42);
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 0"));
            assert!(buffer.contains("sync_overwrites_total 0"));
            assert!(buffer.contains("keys 0"));

            // Put a key
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Get the key
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &hello);

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 0"));
            assert!(buffer.contains("sync_overwrites_total 0"));
            assert!(buffer.contains("keys 1"));

            // Close the metadata store
            metadata.close().await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 1"));
            assert!(buffer.contains("sync_overwrites_total 0"));
            assert!(buffer.contains("keys 1"));

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 0"));
            assert!(buffer.contains("sync_overwrites_total 0"));
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
            assert!(buffer.contains("sync_rewrites_total 1"));
            assert!(buffer.contains("sync_overwrites_total 0"));
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
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Put a key
            let key = U64::new(42);
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 1"));
            assert!(buffer.contains("sync_overwrites_total 0"));
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
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 0"));
            assert!(buffer.contains("keys 2"));

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 0"));
            assert!(buffer.contains("sync_overwrites_total 0"));
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
            assert!(buffer.contains("sync_rewrites_total 1"));
            assert!(buffer.contains("sync_overwrites_total 0"));
            assert!(buffer.contains("keys 1"));

            // Close the metadata store
            metadata.close().await.unwrap();

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 0"));
            assert!(buffer.contains("sync_overwrites_total 0"));
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
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

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
                codec_config: ((0..).into(), ()),
            };
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

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
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

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
                codec_config: ((0..).into(), ()),
            };
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Get the key (falls back to non-corrupt)
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 0"));
            assert!(buffer.contains("sync_overwrites_total 0"));
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
                codec_config: ((0..).into(), ()),
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
                codec_config: ((0..).into(), ()),
            };
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

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
                codec_config: ((0..).into(), ()),
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
                codec_config: ((0..).into(), ()),
            };
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

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
                    codec_config: ((0..).into(), ()),
                };
                let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

                // Put a key
                metadata.put(key.clone(), hello.clone());

                // Drop metadata before sync
            }

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Get the key
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 0"));
            assert!(buffer.contains("sync_overwrites_total 0"));
            assert!(buffer.contains("keys 0"));

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    #[should_panic(expected = "usize value is larger than u32")]
    fn test_value_too_big_error() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Create a value that exceeds u32::MAX bytes
            let value = vec![0u8; (u32::MAX as usize) + 1];
            metadata.put(U64::new(1), value);

            // Assert
            metadata.sync().await.unwrap();
        });
    }

    #[test_traced]
    fn test_delta_writes() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Put initial keys
            for i in 0..100 {
                metadata.put(U64::new(i), vec![i as u8; 100]);
            }

            // First sync - should write everything to the first blob
            //
            // 100 keys * (8 bytes for key + 1 byte for len + 100 bytes for value) + 8 bytes for version + 4 bytes for checksum
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 1"), "{buffer}");
            assert!(buffer.contains("sync_overwrites_total 0"), "{buffer}");
            assert!(
                buffer.contains("runtime_storage_write_bytes_total 10912"),
                "{buffer}",
            );

            // Modify just one key
            metadata.put(U64::new(51), vec![0xff; 100]);

            // Sync again - should write everything to the second blob
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"), "{buffer}");
            assert!(buffer.contains("sync_overwrites_total 0"), "{buffer}");
            assert!(
                buffer.contains("runtime_storage_write_bytes_total 21824"),
                "{buffer}",
            );

            // Sync again - should write only diff from the first blob
            //
            // 1 byte for len + 100 bytes for value + 8 byte for version + 4 bytes for checksum
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"), "{buffer}");
            assert!(buffer.contains("sync_overwrites_total 1"), "{buffer}");
            assert!(
                buffer.contains("runtime_storage_write_bytes_total 21937"),
                "{buffer}",
            );

            // Sync again - should write only diff from the second blob
            //
            // 8 byte for version + 4 bytes for checksum
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"), "{buffer}");
            assert!(buffer.contains("sync_overwrites_total 2"), "{buffer}");
            assert!(
                buffer.contains("runtime_storage_write_bytes_total 21949"),
                "{buffer}",
            );

            // Remove a key - should rewrite everything
            //
            // 99 keys * (8 bytes for key + 1 bytes for len + 100 bytes for value) + 8 bytes for version + 4 bytes for checksum
            metadata.remove(&U64::new(51));
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 3"), "{buffer}");
            assert!(buffer.contains("sync_overwrites_total 2"), "{buffer}");
            assert!(
                buffer.contains("runtime_storage_write_bytes_total 32752"),
                "{buffer}"
            );

            // Sync again - should also rewrite
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 4"), "{buffer}");
            assert!(buffer.contains("sync_overwrites_total 2"), "{buffer}");
            assert!(
                buffer.contains("runtime_storage_write_bytes_total 43555"),
                "{buffer}"
            );

            // Modify in-place - should overwrite
            //
            // 1 byte for len + 100 bytes for value + 8 byte for version + 4 bytes for checksum
            metadata.put(U64::new(50), vec![0xff; 100]);
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 4"), "{buffer}");
            assert!(buffer.contains("sync_overwrites_total 3"), "{buffer}");
            assert!(
                buffer.contains("runtime_storage_write_bytes_total 43668"),
                "{buffer}"
            );

            // Clean up
            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sync_with_no_changes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Put initial data
            metadata.put(U64::new(1), b"hello".to_vec());
            metadata.sync().await.unwrap();

            // Sync again with no changes - will rewrite because key_order_changed is recent
            // (on startup, key_order_changed is set to next_version)
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 0"));

            // Sync again - now key order is stable, should do overwrite
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 1"));

            // Sync again - should continue doing overwrites
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 2"));

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_mut_marks_modified() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Put initial data
            metadata.put(U64::new(1), b"hello".to_vec());
            metadata.sync().await.unwrap();

            // Sync again to ensure both blobs are populated
            metadata.sync().await.unwrap();

            // Use get_mut to modify value
            let value = metadata.get_mut(&U64::new(1)).unwrap();
            value[0] = b'H';

            // Sync should detect the modification and do a rewrite (due to recent key_order_changed)
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 1"));

            // Restart the metadata store
            metadata.close().await.unwrap();
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context, cfg)
                .await
                .unwrap();

            // Verify the change persisted
            let value = metadata.get(&U64::new(1)).unwrap();
            assert_eq!(value[0], b'H');

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_mixed_operation_sequences() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            let key = U64::new(1);

            // Test: put -> remove -> put same key
            metadata.put(key.clone(), b"first".to_vec());
            metadata.remove(&key);
            metadata.put(key.clone(), b"second".to_vec());
            metadata.sync().await.unwrap();
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, b"second");

            // Test: put -> get_mut -> remove -> put
            metadata.put(key.clone(), b"third".to_vec());
            let value = metadata.get_mut(&key).unwrap();
            value[0] = b'T';
            metadata.remove(&key);
            metadata.put(key.clone(), b"fourth".to_vec());
            metadata.sync().await.unwrap();
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, b"fourth");

            // Restart the metadata store
            metadata.close().await.unwrap();
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context, cfg)
                .await
                .unwrap();

            // Verify the changes persisted
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, b"fourth");

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_overwrite_vs_rewrite() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Set up initial data
            metadata.put(U64::new(1), vec![1; 10]);
            metadata.put(U64::new(2), vec![2; 10]);
            metadata.sync().await.unwrap();

            // Same size modification before both blobs are populated
            metadata.put(U64::new(1), vec![0xFF; 10]);
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 0"));

            // Let key order stabilize with another sync
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 1"));

            // Same size modification after both blobs are populated - should overwrite
            metadata.put(U64::new(1), vec![0xAA; 10]);
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 2"));

            // Different size modification - should rewrite
            metadata.put(U64::new(1), vec![0xFF; 20]);
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 3"));
            assert!(buffer.contains("sync_overwrites_total 2"));

            // Add new key - should rewrite (key order changed)
            metadata.put(U64::new(3), vec![3; 10]);
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 4"));
            assert!(buffer.contains("sync_overwrites_total 2"));

            // Stabilize key order
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 5"));
            assert!(buffer.contains("sync_overwrites_total 2"));

            // Modify existing key with same size - should overwrite after stabilized
            metadata.put(U64::new(2), vec![0xAA; 10]);
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 5"));
            assert!(buffer.contains("sync_overwrites_total 3"));

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_blob_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Start with large data
            for i in 0..10 {
                metadata.put(U64::new(i), vec![i as u8; 100]);
            }
            metadata.sync().await.unwrap();

            // Stabilize key order
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 2"));
            assert!(buffer.contains("sync_overwrites_total 0"));

            // Remove most data to make blob smaller
            for i in 1..10 {
                metadata.remove(&U64::new(i));
            }
            metadata.sync().await.unwrap();

            // Verify the remaining data is still accessible
            let value = metadata.get(&U64::new(0)).unwrap();
            assert_eq!(value.len(), 100);
            assert_eq!(value[0], 0);

            // Check that sync properly handles blob resizing
            let buffer = context.encode();
            assert!(buffer.contains("sync_rewrites_total 3"));
            assert!(buffer.contains("sync_overwrites_total 0"));

            // Restart the metadata store
            metadata.close().await.unwrap();
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context, cfg)
                .await
                .unwrap();

            // Verify the changes persisted
            let value = metadata.get(&U64::new(0)).unwrap();
            assert_eq!(value.len(), 100);
            assert_eq!(value[0], 0);

            // Verify the removed keys are not present
            for i in 1..10 {
                assert!(metadata.get(&U64::new(i)).is_none());
            }

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_clear_and_repopulate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Initial data
            metadata.put(U64::new(1), b"first".to_vec());
            metadata.put(U64::new(2), b"second".to_vec());
            metadata.sync().await.unwrap();

            // Clear everything
            metadata.clear();
            metadata.sync().await.unwrap();

            // Verify empty
            assert!(metadata.get(&U64::new(1)).is_none());
            assert!(metadata.get(&U64::new(2)).is_none());

            // Restart the metadata store
            metadata.close().await.unwrap();
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context, cfg)
                .await
                .unwrap();

            // Verify the changes persisted
            assert!(metadata.get(&U64::new(1)).is_none());
            assert!(metadata.get(&U64::new(2)).is_none());

            // Repopulate with different data
            metadata.put(U64::new(3), b"third".to_vec());
            metadata.put(U64::new(4), b"fourth".to_vec());
            metadata.sync().await.unwrap();

            // Verify new data
            assert_eq!(metadata.get(&U64::new(3)).unwrap(), b"third");
            assert_eq!(metadata.get(&U64::new(4)).unwrap(), b"fourth");
            assert!(metadata.get(&U64::new(1)).is_none());
            assert!(metadata.get(&U64::new(2)).is_none());

            metadata.destroy().await.unwrap();
        });
    }

    fn test_metadata_operations_and_restart(num_operations: usize) -> String {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = Config {
                partition: "test_determinism".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Perform a series of deterministic operations
            for i in 0..num_operations {
                let key = U64::new(i as u64);
                let mut value = vec![0u8; 64];
                context.fill_bytes(&mut value);
                metadata.put(key, value);

                // Sync occasionally
                if context.gen_bool(0.1) {
                    metadata.sync().await.unwrap();
                }

                // Update some existing keys
                if context.gen_bool(0.1) {
                    let selected_index = context.gen_range(0..=i);
                    let update_key = U64::new(selected_index as u64);
                    let mut new_value = vec![0u8; 64];
                    context.fill_bytes(&mut new_value);
                    metadata.put(update_key, new_value);
                }

                // Remove some keys
                if context.gen_bool(0.1) {
                    let selected_index = context.gen_range(0..=i);
                    let remove_key = U64::new(selected_index as u64);
                    metadata.remove(&remove_key);
                }

                // Use get_mut occasionally
                if context.gen_bool(0.1) {
                    let selected_index = context.gen_range(0..=i);
                    let mut_key = U64::new(selected_index as u64);
                    if let Some(value) = metadata.get_mut(&mut_key) {
                        if !value.is_empty() {
                            value[0] = value[0].wrapping_add(1);
                        }
                    }
                }
            }
            metadata.sync().await.unwrap();

            // Destroy the metadata store
            metadata.destroy().await.unwrap();

            context.auditor().state()
        })
    }

    #[test_traced]
    #[ignore]
    fn test_determinism() {
        let state1 = test_metadata_operations_and_restart(1_000);
        let state2 = test_metadata_operations_and_restart(1_000);
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_keys_iterator() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Add some keys with different prefixes
            metadata.put(U64::new(0x1000), b"value1".to_vec());
            metadata.put(U64::new(0x1001), b"value2".to_vec());
            metadata.put(U64::new(0x1002), b"value3".to_vec());
            metadata.put(U64::new(0x2000), b"value4".to_vec());
            metadata.put(U64::new(0x2001), b"value5".to_vec());
            metadata.put(U64::new(0x3000), b"value6".to_vec());

            // Test iterating over all keys
            let all_keys: Vec<_> = metadata.keys(None).cloned().collect();
            assert_eq!(all_keys.len(), 6);
            assert!(all_keys.contains(&U64::new(0x1000)));
            assert!(all_keys.contains(&U64::new(0x3000)));

            // Test iterating with prefix 0x10
            let prefix = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
            let prefix_keys: Vec<_> = metadata.keys(Some(&prefix)).cloned().collect();
            assert_eq!(prefix_keys.len(), 3);
            assert!(prefix_keys.contains(&U64::new(0x1000)));
            assert!(prefix_keys.contains(&U64::new(0x1001)));
            assert!(prefix_keys.contains(&U64::new(0x1002)));
            assert!(!prefix_keys.contains(&U64::new(0x2000)));

            // Test iterating with prefix 0x20
            let prefix = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20];
            let prefix_keys: Vec<_> = metadata.keys(Some(&prefix)).cloned().collect();
            assert_eq!(prefix_keys.len(), 2);
            assert!(prefix_keys.contains(&U64::new(0x2000)));
            assert!(prefix_keys.contains(&U64::new(0x2001)));

            // Test with non-matching prefix
            let prefix = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
            let prefix_keys: Vec<_> = metadata.keys(Some(&prefix)).cloned().collect();
            assert_eq!(prefix_keys.len(), 0);

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_remove_prefix() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Add some keys with different prefixes
            metadata.put(U64::new(0x1000), b"value1".to_vec());
            metadata.put(U64::new(0x1001), b"value2".to_vec());
            metadata.put(U64::new(0x1002), b"value3".to_vec());
            metadata.put(U64::new(0x2000), b"value4".to_vec());
            metadata.put(U64::new(0x2001), b"value5".to_vec());
            metadata.put(U64::new(0x3000), b"value6".to_vec());

            // Check initial metrics
            let buffer = context.encode();
            assert!(buffer.contains("keys 6"));

            // Remove keys with prefix 0x10
            let prefix = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
            metadata.remove_prefix(&prefix);

            // Check metrics after removal
            let buffer = context.encode();
            assert!(buffer.contains("keys 3"));

            // Verify remaining keys
            assert!(metadata.get(&U64::new(0x1000)).is_none());
            assert!(metadata.get(&U64::new(0x1001)).is_none());
            assert!(metadata.get(&U64::new(0x1002)).is_none());
            assert!(metadata.get(&U64::new(0x2000)).is_some());
            assert!(metadata.get(&U64::new(0x2001)).is_some());
            assert!(metadata.get(&U64::new(0x3000)).is_some());

            // Sync and reopen to ensure persistence
            metadata.sync().await.unwrap();
            metadata.close().await.unwrap();
            let cfg = Config {
                partition: "test".to_string(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Verify keys are still removed after restart
            assert!(metadata.get(&U64::new(0x1000)).is_none());
            assert!(metadata.get(&U64::new(0x2000)).is_some());
            assert_eq!(metadata.keys(None).count(), 3);

            // Remove non-existing prefix
            let prefix = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
            metadata.remove_prefix(&prefix);

            // Remove all remaining keys
            let prefix = vec![]; // Empty prefix matches all
            metadata.remove_prefix(&prefix);
            assert_eq!(metadata.keys(None).count(), 0);

            metadata.destroy().await.unwrap();
        });
    }
}
