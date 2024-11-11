//! An append-only log for storing arbitrary data.
//!
//! `Journal` is an append-only log for storing arbitrary data on disk with
//! the support for serving checksummed data by an arbitrary offset. It can be used
//! on its own to persist streams of data for later replay (serving as a backing store
//! for some in-memory data structure) or as a building block for a more complex
//! construction that prescribes some meaning to offsets in the log.
//!
//! # Format
//!
//! Data stored in `Journal` is persisted in one of many `Blobs` within a caller-provided
//! `partition`. The particular `Blob` in which data is stored is identified by a `section`
//! number (`u64`). Within a `section`, data is appended to the end of each `Blob` in chunks of
//! the following format:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 |    ...    | 8 | 9 |10 |11 |
//! +---+---+---+---+---+---+---+---+---+---+---+
//! |   Size (u32)  |   Data    |    C(u32)     |
//! +---+---+---+---+---+---+---+---+---+---+---+
//!
//! C = CRC32(Data)
//! ```
//!
//! _To ensure data returned by `Journal` is correct, a checksum (CRC32) is stored at the end of
//! each item. If the checksum of the read data does not match the stored checksum, an error is
//! returned. This checksum is only verified when data is accessed and not at startup (which
//! would require reading all data in `Journal`)._
//!
//! # Open Blobs
//!
//! `Journal` uses 1 `Blob` per `section` to store data. All `Blobs` in a given `partition` are
//! kept open during the lifetime of `Journal`. If the caller wishes to bound the number of open
//! `Blobs`, they should group data into fewer `sections` and/or prune unused `sections`.
//!
//! # Offset Alignment
//!
//! In practice, `Journal` users won't store `u64::MAX` bytes of data in a given `section` (the max
//! `Offset` provided by `Blob`). To reduce the memory usage for tracking offsets within `Journal`, offsets
//! are thus `u32` (4 bytes) and aligned to 16 bytes. This means that the maximum size of any `section`
//! is `u32::MAX * 17 = ~70GB` bytes (the last offset item can store up to `u32::MAX` bytes). If more data
//! is written to a `section` past this max, an `OffsetOverflow` error is returned.
//!
//! # Sync
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. It is up to the caller
//! to determine when to force pending data to be written to `Storage` using the `sync` method. When calling
//! `close`, all pending data is automatically synced and any open blobs are closed.
//!
//! # Pruning
//!
//! All data appended to `Journal` must be assigned to some `section` (`u64`). This assignment
//! allows the caller to prune data from `Journal` by specifying a minimum `section` number. This could
//! be used, for example, by some blockchain application to prune old blocks.
//!
//! # Replay
//!
//! During application initialization, it is very common to replay data from `Journal` to recover
//! some in-memory state. `Journal` is heavily optimized for this pattern and provides a `replay` method
//! that iterates over multiple `sections` concurrently in a single stream.
//!
//! ## Skip Reads
//!
//! Some applications may only want to read the first `n` bytes of each item during `replay`. This can be
//! done by providing a `prefix` parameter to the `replay` method. If `prefix` is provided, `Journal` will only
//! return the first `prefix` bytes of each item and "skip ahead" to the next item (computing the offset
//! using the read `size` value).
//!
//! _Reading only the `prefix` bytes of an item makes it impossible to compute the checksum
//! of an item. It is up to the caller to ensure these reads are safe._
//!
//! # Exact Reads
//!
//! To allow for items to be fetched in a single disk operation, `Journal` allows callers to specify
//! an `exact` parameter to the `get` method. This `exact` parameter must be cached by the caller (provided
//! during `replay`) and usage of an incorrect `exact` value will result in undefined behavior.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic::Executor};
//! use commonware_storage::journal::{Journal, Config};
//! use prometheus_client::registry::Registry;
//! use std::sync::{Arc, Mutex};
//!
//! let (executor, context, _) = Executor::default();
//! executor.start(async move {
//!     // Create a journal
//!     let mut journal = Journal::init(context, Config{
//!         registry: Arc::new(Mutex::new(Registry::default())),
//!         partition: "partition".to_string()
//!     }).await.unwrap();
//!
//!     // Append data to the journal
//!     journal.append(1, "data".into()).await.unwrap();
//!
//!     // Close the journal
//!     journal.close().await.unwrap();
//! });
//! ```

mod storage;
pub use storage::Journal;

use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Errors that can occur when interacting with `Journal`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("checksum mismatch: expected={0} actual={1}")]
    ChecksumMismatch(u32, u32),
    #[error("item too large: size={0}")]
    ItemTooLarge(usize),
    #[error("already pruned to section: {0}")]
    AlreadyPrunedToSection(u64),
    #[error("usize too small")]
    UsizeTooSmall,
    #[error("offset overflow")]
    OffsetOverflow,
    #[error("unexpected size: expected={0} actual={1}")]
    UnexpectedSize(u32, u32),
}

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// The `commonware-runtime::Storage` partition to use
    /// for storing journal blobs.
    pub partition: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, Bytes};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Blob, Error as RError, Runner, Storage};
    use futures::{pin_mut, StreamExt};
    use prometheus_client::encoding::text::encode;

    #[test_traced]
    fn test_journal_append_and_read() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Initialize the journal
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };
            let index = 1u64;
            let data = Bytes::from("Test data");
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append an item to the journal
            journal
                .append(index, data.clone())
                .await
                .expect("Failed to append data");

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 1"));

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };
            let mut journal = Journal::init(context, cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            let stream = journal
                .replay(1, None)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, full_len, item)) => {
                        assert_eq!(full_len as usize, item.len());
                        items.push((blob_index, item))
                    }
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }

            // Verify that the item was replayed correctly
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].0, index);
            assert_eq!(items[0].1, data);

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 1"));
        });
    }

    #[test_traced]
    fn test_journal_multiple_appends_and_reads() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append multiple items to different blobs
            let data_items = vec![
                (1u64, Bytes::from("Data for blob 1")),
                (1u64, Bytes::from("Data for blob 1, second item")),
                (2u64, Bytes::from("Data for blob 2")),
                (3u64, Bytes::from("Data for blob 3")),
            ];
            for (index, data) in &data_items {
                journal
                    .append(*index, data.clone())
                    .await
                    .expect("Failed to append data");
                journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 3"));
            assert!(buffer.contains("synced_total 4"));

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            {
                let stream = journal
                    .replay(2, None)
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, full_len, item)) => {
                            assert_eq!(full_len as usize, item.len());
                            items.push((blob_index, item))
                        }
                        Err(err) => panic!("Failed to read item: {}", err),
                    }
                }
            }

            // Verify that all items were replayed correctly
            assert_eq!(items.len(), data_items.len());
            for ((expected_index, expected_data), (actual_index, actual_data)) in
                data_items.iter().zip(items.iter())
            {
                assert_eq!(actual_index, expected_index);
                assert_eq!(actual_data, expected_data);
            }

            // Replay just first bytes
            {
                let stream = journal
                    .replay(2, Some(4))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((_, _, full_len, item)) => {
                            assert_eq!(item, Bytes::from("Data"));
                            assert!(full_len as usize > item.len());
                        }
                        Err(err) => panic!("Failed to read item: {}", err),
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_journal_prune_blobs() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items to multiple blobs
            for index in 1u64..=5u64 {
                let data = Bytes::from(format!("Data for blob {}", index));
                journal
                    .append(index, data)
                    .await
                    .expect("Failed to append data");
                journal.sync(index).await.expect("Failed to sync blob");
            }

            // Add one item out-of-order
            let data = Bytes::from("Data for blob 2, second item");
            journal
                .append(2u64, data)
                .await
                .expect("Failed to append data");
            journal.sync(2u64).await.expect("Failed to sync blob");

            // Prune blobs with indices less than 3
            journal.prune(3).await.expect("Failed to prune blobs");

            // Prune again with a section less than the previous one
            let result = journal.prune(2).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedToSection(3))));

            // Prune again with the same section
            let result = journal.prune(3).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedToSection(3))));

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("pruned_total 2"));

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            {
                let stream = journal
                    .replay(1, None)
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {}", err),
                    }
                }
            }

            // Verify that items from blobs 1 and 2 are not present
            assert_eq!(items.len(), 3);
            let expected_indices = [3u64, 4u64, 5u64];
            for (item, expected_index) in items.iter().zip(expected_indices.iter()) {
                assert_eq!(item.0, *expected_index);
            }

            // Prune all blobs
            journal.prune(6).await.expect("Failed to prune blobs");

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Ensure no remaining blobs exist
            //
            // Note: We don't remove the partition, so this does not error
            // and instead returns an empty list of blobs.
            assert!(context
                .scan(&cfg.partition)
                .await
                .expect("Failed to list blobs")
                .is_empty());
        });
    }

    #[test_traced]
    fn test_journal_with_invalid_blob_name() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };

            // Manually create a blob with an invalid name (not 8 bytes)
            let invalid_blob_name = b"invalid"; // Less than 8 bytes
            let blob = context
                .open(&cfg.partition, invalid_blob_name)
                .await
                .expect("Failed to create blob with invalid name");
            blob.close().await.expect("Failed to close blob");

            // Attempt to initialize the journal
            let result = Journal::init(context, cfg).await;

            // Expect an error
            assert!(matches!(result, Err(Error::InvalidBlobName(_))));
        });
    }

    fn journal_read_size_missing(exact: Option<u32>) {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };

            // Manually create a blob with incomplete size data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write incomplete size data (less than 4 bytes)
            let incomplete_data = vec![0x00, 0x01]; // Less than 4 bytes
            blob.write_at(&incomplete_data, 0)
                .await
                .expect("Failed to write incomplete data");
            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal
                .replay(1, exact)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_size_missing_no_exact() {
        journal_read_size_missing(None);
    }

    #[test_traced]
    fn test_journal_read_size_missing_with_exact() {
        journal_read_size_missing(Some(1));
    }

    fn journal_read_item_missing(exact: Option<u32>) {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };

            // Manually create a blob with missing item data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write size but no item data
            let item_size: u32 = 10; // Size of the item
            let mut buf = Vec::new();
            buf.put_u32(item_size);
            let data = [2u8; 5];
            buf.put_slice(&data);
            blob.write_at(&buf, 0)
                .await
                .expect("Failed to write item size");
            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal
                .replay(1, exact)
                .await
                .expect("unable to setup replay");

            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_item_missing_no_exact() {
        journal_read_item_missing(None);
    }

    #[test_traced]
    fn test_journal_read_item_missing_with_exact() {
        journal_read_item_missing(Some(1));
    }

    #[test_traced]
    fn test_journal_read_checksum_missing() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };

            // Manually create a blob with missing checksum
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Prepare item data
            let item_data = b"Test data";
            let item_size = item_data.len() as u32;

            // Write size
            let mut offset = 0;
            blob.write_at(&item_size.to_be_bytes(), offset)
                .await
                .expect("Failed to write item size");
            offset += 4;

            // Write item data
            blob.write_at(item_data, offset)
                .await
                .expect("Failed to write item data");
            // Do not write checksum (omit it)

            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            //
            // This will truncate the leftover bytes from our manual write.
            let stream = journal
                .replay(1, None)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_checksum_mismatch() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };

            // Manually create a blob with incorrect checksum
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Prepare item data
            let item_data = b"Test data";
            let item_size = item_data.len() as u32;
            let incorrect_checksum: u32 = 0xDEADBEEF;

            // Write size
            let mut offset = 0;
            blob.write_at(&item_size.to_be_bytes(), offset)
                .await
                .expect("Failed to write item size");
            offset += 4;

            // Write item data
            blob.write_at(item_data, offset)
                .await
                .expect("Failed to write item data");
            offset += item_data.len() as u64;

            // Write incorrect checksum
            blob.write_at(&incorrect_checksum.to_be_bytes(), offset)
                .await
                .expect("Failed to write incorrect checksum");

            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal
                .replay(1, None)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => {
                        assert!(matches!(err, Error::ChecksumMismatch(_, _)));
                        return;
                    }
                }
            }
            panic!("expected checksum mismatch error");
        });
    }

    #[test_traced]
    fn test_journal_handling_truncated_data() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append 1 item to the first index
            journal
                .append(1, Bytes::from("Valid data"))
                .await
                .expect("Failed to append data");

            // Append multiple items to the second index
            let data_items = vec![
                (2u64, Bytes::from("Valid data")),
                (2u64, Bytes::from("Valid data, second item")),
                (2u64, Bytes::from("Valid data, third item")),
            ];
            for (index, data) in &data_items {
                journal
                    .append(*index, data.clone())
                    .await
                    .expect("Failed to append data");
                journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Manually corrupt the end of the second blob
            let blob = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let blob_len = blob.len().await.expect("Failed to get blob length");
            blob.truncate(blob_len - 4)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::new();
            let stream = journal
                .replay(1, None)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, Bytes::from("Valid data"));
            assert_eq!(items[1].0, data_items[0].0);
            assert_eq!(items[1].1, data_items[0].1);
            assert_eq!(items[2].0, data_items[1].0);
            assert_eq!(items[2].1, data_items[1].1);
        });
    }

    // Define `MockBlob` that returns an offset length that should overflow
    #[derive(Clone)]
    struct MockBlob {
        len: u64,
    }

    impl Blob for MockBlob {
        async fn len(&self) -> Result<u64, commonware_runtime::Error> {
            // Return a length that will cause offset overflow
            Ok(self.len)
        }

        async fn read_at(&self, _buf: &mut [u8], _offset: u64) -> Result<(), RError> {
            Ok(())
        }

        async fn write_at(&self, _buf: &[u8], _offset: u64) -> Result<(), RError> {
            Ok(())
        }

        async fn truncate(&self, _len: u64) -> Result<(), RError> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), RError> {
            Ok(())
        }

        async fn close(self) -> Result<(), RError> {
            Ok(())
        }
    }

    // Define `MockStorage` that returns `MockBlob`
    #[derive(Clone)]
    struct MockStorage {
        len: u64,
    }

    impl Storage<MockBlob> for MockStorage {
        async fn open(&self, _partition: &str, _name: &[u8]) -> Result<MockBlob, RError> {
            Ok(MockBlob { len: self.len })
        }

        async fn remove(&self, _partition: &str, _name: Option<&[u8]>) -> Result<(), RError> {
            Ok(())
        }

        async fn scan(&self, _partition: &str) -> Result<Vec<Vec<u8>>, RError> {
            Ok(vec![])
        }
    }

    // Define the `INDEX_ALIGNMENT` again explicitly to ensure we catch any accidental
    // changes to the value
    const INDEX_ALIGNMENT: u64 = 16;

    #[test_traced]
    fn test_journal_large_offset() {
        // Initialize the deterministic runtime
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            // Create journal
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "partition".to_string(),
            };
            let runtime = MockStorage {
                len: u32::MAX as u64 * INDEX_ALIGNMENT, // can store up to u32::Max at the last offset
            };
            let mut journal = Journal::init(runtime, cfg).await.unwrap();

            // Append data
            let data = Bytes::from("Test data");
            let result = journal
                .append(1, data)
                .await
                .expect("Failed to append data");
            assert_eq!(result, u32::MAX);
        });
    }

    #[test_traced]
    fn test_journal_offset_overflow() {
        // Initialize the deterministic runtime
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            // Create journal
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "partition".to_string(),
            };
            let runtime = MockStorage {
                len: u32::MAX as u64 * INDEX_ALIGNMENT + 1,
            };
            let mut journal = Journal::init(runtime, cfg).await.unwrap();

            // Append data
            let data = Bytes::from("Test data");
            let result = journal.append(1, data).await;
            assert!(matches!(result, Err(Error::OffsetOverflow)));
        });
    }
}
