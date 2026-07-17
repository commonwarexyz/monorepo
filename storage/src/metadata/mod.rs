//! A key-value store optimized for atomically committing a small collection of metadata.
//!
//! [Metadata] is a key-value store optimized for tracking a small collection of metadata
//! that commits multiple updates in a single atomic write. It is commonly used with
//! a variety of other underlying storage systems to persist application state across restarts.
//!
//! # Format
//!
//! Data is stored in a single blob as a sequence of codec-encoded key-value pairs in key
//! order, rewritten wholesale on every sync:
//!
//! ```text
//! +---------+-----------+---------+-----------+-----+
//! |   Key1  |   Value1  |   Key2  |   Value2  | ... |
//! +---------+-----------+---------+-----------+-----+
//! ```
//!
//! The storage backend's atomic per-blob sync makes each rewrite an old-state-or-new-state
//! transition, so no slot redundancy, versioning, or checksums are needed. An empty blob is
//! an empty store. Any other content must decode exactly or initialization fails with
//! [Error::Corruption].
//!
//! # Batching
//!
//! [Metadata::sync] commits alone. [Metadata::sync_into] stages the same rewrite with a
//! caller-provided [commonware_runtime::WriteBatch] so it lands atomically with writes to
//! other structures.
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
//!     let mut metadata = Metadata::init(context, Config {
//!         partition: "partition".into(),
//!         codec_config: ((0..).into(), ()),
//!     }).await.unwrap();
//!
//!     // Store metadata
//!     metadata.put(U64::new(1), b"hello".to_vec());
//!     metadata.put(U64::new(2), b"world".to_vec());
//!
//!     // Sync the metadata store (commit all changes atomically)
//!     metadata.sync().await.unwrap();
//!
//!     // Retrieve some metadata
//!     let value = metadata.get(&U64::new(1)).unwrap();
//!
//! });
//! ```

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
mod storage;
pub use storage::Metadata;
use thiserror::Error;

/// Errors that can occur when interacting with [Metadata].
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("corrupt metadata: {0}")]
    Corruption(commonware_codec::Error),
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
    use commonware_formatting::hex;
    use commonware_macros::{test_group, test_traced};
    use commonware_runtime::{
        deterministic, Batchable as _, Blob, Metrics as _, Runner, Storage, Supervisor as _,
        WriteBatch as _,
    };
    use commonware_utils::sequence::U64;
    use rand::{Rng, RngExt as _};

    #[test_traced]
    fn test_put_get_clear() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg)
                .await
                .unwrap();

            // Get a key that doesn't exist
            let key = U64::new(42);
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("first_syncs_total 0"));
            assert!(buffer.contains("first_keys 0"));

            // Put a key
            let hello = b"hello".to_vec();
            metadata.put(key.clone(), hello.clone());

            // Get the key
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &hello);

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("first_syncs_total 0"));
            assert!(buffer.contains("first_keys 1"));

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("first_syncs_total 1"));
            assert!(buffer.contains("first_keys 1"));

            // Reopen the metadata store
            drop(metadata);
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("second_syncs_total 0"));
            assert!(buffer.contains("second_keys 1"));

            // Get the key
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, &hello);

            // Test clearing the metadata store
            metadata.clear();
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("second_keys 0"));

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_put_returns_previous_value() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg)
                .await
                .unwrap();

            let key = U64::new(42);

            // First put returns None (no previous value)
            let previous = metadata.put(key.clone(), b"first".to_vec());
            assert!(previous.is_none());

            // Second put returns the previous value
            let previous = metadata.put(key.clone(), b"second".to_vec());
            assert_eq!(previous, Some(b"first".to_vec()));

            // Third put returns the previous value
            let previous = metadata.put(key.clone(), b"third".to_vec());
            assert_eq!(previous, Some(b"second".to_vec()));

            // Current value is the latest
            assert_eq!(metadata.get(&key), Some(&b"third".to_vec()));

            // Different key returns None
            let other_key = U64::new(99);
            let previous = metadata.put(other_key.clone(), b"other".to_vec());
            assert!(previous.is_none());

            // Sync and verify persistence
            metadata.sync().await.unwrap();
            drop(metadata);

            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // After restart, put still returns previous value
            let previous = metadata.put(key.clone(), b"fourth".to_vec());
            assert_eq!(previous, Some(b"third".to_vec()));

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
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg)
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
            assert!(buffer.contains("first_syncs_total 1"));
            assert!(buffer.contains("first_keys 1"));

            // Put an overlapping key and a new key
            let world = b"world".to_vec();
            metadata.put(key.clone(), world.clone());
            let key2 = U64::new(43);
            let foo = b"foo".to_vec();
            metadata.put(key2.clone(), foo.clone());

            // Sync the metadata store
            metadata.sync().await.unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("first_syncs_total 2"));
            assert!(buffer.contains("first_keys 2"));

            // Reopen the metadata store
            drop(metadata);
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("second_syncs_total 0"));
            assert!(buffer.contains("second_keys 2"));

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
            assert!(buffer.contains("second_syncs_total 1"));
            assert!(buffer.contains("second_keys 1"));

            // Reopen the metadata store
            drop(metadata);
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("third"), cfg)
                .await
                .unwrap();

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("third_syncs_total 0"));
            assert!(buffer.contains("third_keys 1"));

            // Get the key
            let value = metadata.get(&key);
            assert!(value.is_none());
            let value = metadata.get(&key2).unwrap();
            assert_eq!(value, &foo);

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_undecodable_blob_is_corruption() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store with some persisted state
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
            metadata
                .put_sync(U64::new(42), b"hello".to_vec())
                .await
                .unwrap();
            drop(metadata);

            // Truncate the blob mid-value so the record no longer decodes
            let (blob, len) = context.open("test", b"data").await.unwrap();
            blob.resize(len - 1).await.unwrap();
            blob.sync().await.unwrap();

            // Reopening must report corruption
            let result = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
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
                    partition: "test".into(),
                    codec_config: ((0..).into(), ()),
                };
                let mut metadata = Metadata::init(context.child("first"), cfg).await.unwrap();

                // Put a key
                metadata.put(key.clone(), hello.clone());

                // Drop metadata before sync
            }

            // Reopen the metadata store
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // Get the key
            let value = metadata.get(&key);
            assert!(value.is_none());

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("second_syncs_total 0"));
            assert!(buffer.contains("second_keys 0"));

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
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::init(context.child("storage"), cfg).await.unwrap();

            // Create a value that exceeds u32::MAX bytes
            let value = vec![0u8; (u32::MAX as usize) + 1];
            metadata.put(U64::new(1), value);

            // Assert
            metadata.sync().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sync_with_no_changes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();

            // Put initial data
            metadata
                .put_sync(U64::new(1), b"hello".to_vec())
                .await
                .unwrap();

            // Sync again with no changes - should write nothing
            metadata.sync().await.unwrap();
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("first_syncs_total 1"));

            // Restart the metadata store and verify the no-op left durable state
            drop(metadata);
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();
            assert_eq!(metadata.get(&U64::new(1)).unwrap(), b"hello");

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_mut_marks_modified() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();

            // Put initial data
            metadata
                .put_sync(U64::new(1), b"hello".to_vec())
                .await
                .unwrap();

            // Use get_mut to modify value
            let value = metadata.get_mut(&U64::new(1)).unwrap();
            value[0] = b'H';

            // Sync should detect the modification and write
            metadata.sync().await.unwrap();
            let buffer = context.encode();
            assert!(buffer.contains("first_syncs_total 2"));

            // Restart the metadata store
            drop(metadata);
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // Verify the change persisted
            let value = metadata.get(&U64::new(1)).unwrap();
            assert_eq!(value[0], b'H');

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sync_into_joins_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_a = Config {
                partition: "test-a".into(),
                codec_config: ((0..).into(), ()),
            };
            let cfg_b = Config {
                partition: "test-b".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut a = Metadata::<_, U64, Vec<u8>>::init(context.child("a"), cfg_a.clone())
                .await
                .unwrap();
            let mut b = Metadata::<_, U64, Vec<u8>>::init(context.child("b"), cfg_b.clone())
                .await
                .unwrap();
            a.put(U64::new(1), b"alpha".to_vec());
            b.put(U64::new(2), b"beta".to_vec());

            // Stage both stores' rewrites in ONE batch and commit once
            let mut batch = context.batch().await.unwrap();
            a.sync_into(&mut batch).await.unwrap();
            b.sync_into(&mut batch).await.unwrap();
            batch.apply_sync().await.unwrap();
            drop(a);
            drop(b);

            // Both stores recover the committed state
            let a = Metadata::<_, U64, Vec<u8>>::init(context.child("a2"), cfg_a)
                .await
                .unwrap();
            let b = Metadata::<_, U64, Vec<u8>>::init(context.child("b2"), cfg_b)
                .await
                .unwrap();
            assert_eq!(a.get(&U64::new(1)).unwrap(), b"alpha");
            assert_eq!(b.get(&U64::new(2)).unwrap(), b"beta");

            a.destroy().await.unwrap();
            b.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_mixed_operation_sequences() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();

            let key = U64::new(1);

            // Test: put -> remove -> put same key
            metadata.put(key.clone(), b"first".to_vec());
            metadata.remove(&key);
            metadata
                .put_sync(key.clone(), b"second".to_vec())
                .await
                .unwrap();
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, b"second");

            // Test: put -> get_mut -> remove -> put
            metadata.put(key.clone(), b"third".to_vec());
            let value = metadata.get_mut(&key).unwrap();
            value[0] = b'T';
            metadata.remove(&key);
            metadata
                .put_sync(key.clone(), b"fourth".to_vec())
                .await
                .unwrap();
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, b"fourth");

            // Restart the metadata store
            drop(metadata);
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // Verify the changes persisted
            let value = metadata.get(&key).unwrap();
            assert_eq!(value, b"fourth");

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_blob_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();

            // Start with large data
            for i in 0..10 {
                metadata.put(U64::new(i), vec![i as u8; 100]);
            }
            metadata.sync().await.unwrap();

            // Remove most data to make blob smaller
            for i in 1..10 {
                metadata.remove(&U64::new(i));
            }
            metadata.sync().await.unwrap();

            // Verify the remaining data is still accessible
            let value = metadata.get(&U64::new(0)).unwrap();
            assert_eq!(value.len(), 100);
            assert_eq!(value[0], 0);

            // Restart the metadata store
            drop(metadata);
            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // Verify the shrinking rewrite persisted
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
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();

            // Initial data
            metadata.put(U64::new(1), b"first".to_vec());
            metadata
                .put_sync(U64::new(2), b"second".to_vec())
                .await
                .unwrap();

            // Clear everything
            metadata.clear();
            metadata.sync().await.unwrap();

            // Verify empty
            assert!(metadata.get(&U64::new(1)).is_none());
            assert!(metadata.get(&U64::new(2)).is_none());

            // Restart the metadata store
            drop(metadata);
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // Verify the changes persisted
            assert!(metadata.get(&U64::new(1)).is_none());
            assert!(metadata.get(&U64::new(2)).is_none());

            // Repopulate with different data
            metadata.put(U64::new(3), b"third".to_vec());
            metadata
                .put_sync(U64::new(4), b"fourth".to_vec())
                .await
                .unwrap();

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
                partition: "test-determinism".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("storage"), cfg.clone())
                    .await
                    .unwrap();

            // Perform a series of deterministic operations
            for i in 0..num_operations {
                let key = U64::new(i as u64);
                let mut value = vec![0u8; 64];
                context.fill_bytes(&mut value);
                metadata.put(key, value);

                // Sync occasionally
                if context.random_bool(0.1) {
                    metadata.sync().await.unwrap();
                }

                // Update some existing keys
                if context.random_bool(0.1) {
                    let selected_index = context.random_range(0..=i);
                    let update_key = U64::new(selected_index as u64);
                    let mut new_value = vec![0u8; 64];
                    context.fill_bytes(&mut new_value);
                    metadata.put(update_key, new_value);
                }

                // Remove some keys
                if context.random_bool(0.1) {
                    let selected_index = context.random_range(0..=i);
                    let remove_key = U64::new(selected_index as u64);
                    metadata.remove(&remove_key);
                }

                // Use get_mut occasionally
                if context.random_bool(0.1) {
                    let selected_index = context.random_range(0..=i);
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

    #[test_group("slow")]
    #[test_traced]
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
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("storage"), cfg)
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
            let all_keys: Vec<_> = metadata.keys().cloned().collect();
            assert_eq!(all_keys.len(), 6);
            assert!(all_keys.contains(&U64::new(0x1000)));
            assert!(all_keys.contains(&U64::new(0x3000)));

            // Test iterating with prefix 0x10
            let prefix = hex!("0x00000000000010");
            let prefix_keys: Vec<_> = metadata
                .keys()
                .filter(|k| k.as_ref().starts_with(&prefix))
                .cloned()
                .collect();
            assert_eq!(prefix_keys.len(), 3);
            assert!(prefix_keys.contains(&U64::new(0x1000)));
            assert!(prefix_keys.contains(&U64::new(0x1001)));
            assert!(prefix_keys.contains(&U64::new(0x1002)));
            assert!(!prefix_keys.contains(&U64::new(0x2000)));

            // Test iterating with prefix 0x20
            let prefix = hex!("0x00000000000020");
            let prefix_keys: Vec<_> = metadata
                .keys()
                .filter(|k| k.as_ref().starts_with(&prefix))
                .cloned()
                .collect();
            assert_eq!(prefix_keys.len(), 2);
            assert!(prefix_keys.contains(&U64::new(0x2000)));
            assert!(prefix_keys.contains(&U64::new(0x2001)));

            // Test with non-matching prefix
            let prefix = hex!("0x00000000000040");
            let prefix_keys: Vec<_> = metadata
                .keys()
                .filter(|k| k.as_ref().starts_with(&prefix))
                .cloned()
                .collect();
            assert_eq!(prefix_keys.len(), 0);

            metadata.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_retain() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a metadata store
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("first"), cfg)
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
            assert!(buffer.contains("first_keys 6"));

            // Remove keys with prefix 0x10
            let prefix = hex!("0x00000000000010");
            metadata.retain(|k, _| !k.as_ref().starts_with(&prefix));

            // Check metrics after removal
            let buffer = context.encode();
            assert!(buffer.contains("first_keys 3"));

            // Verify remaining keys
            assert!(metadata.get(&U64::new(0x1000)).is_none());
            assert!(metadata.get(&U64::new(0x1001)).is_none());
            assert!(metadata.get(&U64::new(0x1002)).is_none());
            assert!(metadata.get(&U64::new(0x2000)).is_some());
            assert!(metadata.get(&U64::new(0x2001)).is_some());
            assert!(metadata.get(&U64::new(0x3000)).is_some());

            // Sync and reopen to ensure persistence
            metadata.sync().await.unwrap();
            drop(metadata);
            let cfg = Config {
                partition: "test".into(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();

            // Verify keys are still removed after restart
            assert!(metadata.get(&U64::new(0x1000)).is_none());
            assert!(metadata.get(&U64::new(0x2000)).is_some());
            assert_eq!(metadata.keys().count(), 3);

            // Remove non-existing prefix
            let prefix = hex!("0x00000000000040");
            metadata.retain(|k, _| !k.as_ref().starts_with(&prefix));

            // Remove all remaining keys
            metadata.retain(|_, _| false);
            assert_eq!(metadata.keys().count(), 0);

            metadata.destroy().await.unwrap();
        });
    }
}
