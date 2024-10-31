//! An append-only log for storing arbitrary data.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic::Executor};
//! use commonware_storage::journal::{Journal, Config};
//!
//! let (executor, context, _) = Executor::default();
//! executor.start(async move {
//!     // Create a journal
//!     let mut journal = Journal::init(context, Config{
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

use commonware_runtime::Error as RError;
use thiserror::Error;

/// Errors that can occur when interacting with the journal.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] RError),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("blob corrupt")]
    BlobCorrupt,
    #[error("item too large: size={0}")]
    ItemTooLarge(usize),
}

/// Configuration for `journal` storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware-runtime::Storage` partition to use
    /// for storing journal blobs.
    pub partition: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Blob, Runner, Storage};
    use futures::{pin_mut, StreamExt};

    #[test_traced]
    fn test_journal_append_and_read() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Initialize the journal
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

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            let stream = journal.replay();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }

            // Verify that the item was replayed correctly
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].0, index);
            assert_eq!(items[0].1, data);
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

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            let stream = journal.replay();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
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

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            {
                let stream = journal.replay();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, item)) => items.push((blob_index, item)),
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
        let (executor, mut context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with an invalid name (not 8 bytes)
            let invalid_blob_name = b"invalid"; // Less than 8 bytes
            let mut blob = context
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

    #[test_traced]
    fn test_journal_read_size_missing() {
        // Initialize the deterministic runtime
        let (executor, mut context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with incomplete size data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let mut blob = context
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
            let stream = journal.replay();
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_item_missing() {
        // Initialize the deterministic runtime
        let (executor, mut context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with missing item data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let mut blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write size but no item data
            let item_size: u32 = 10; // Size of the item
            blob.write_at(&item_size.to_be_bytes(), 0)
                .await
                .expect("Failed to write item size");
            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal.replay();
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_checksum_missing() {
        // Initialize the deterministic runtime
        let (executor, mut context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with missing checksum
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let mut blob = context
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
            let stream = journal.replay();
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_checksum_mismatch() {
        // Initialize the deterministic runtime
        let (executor, mut context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with incorrect checksum
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let mut blob = context
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
            offset += item_data.len();

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
            let stream = journal.replay();
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_handling_truncated_data() {
        // Initialize the deterministic runtime
        let (executor, mut context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
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
            let mut blob = context
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
            let stream = journal.replay();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, item)) => items.push((blob_index, item)),
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
}
