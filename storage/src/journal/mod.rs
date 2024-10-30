//! TBD

mod disk;

pub use disk::Journal;

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
}

#[derive(Clone)]
pub struct Config {
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
                partition: "test_partition".to_string(),
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
                partition: "test_partition".to_string(),
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
                partition: "test_partition".to_string(),
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

            // Verify that items from blobs 1 and 2 are not present
            assert_eq!(items.len(), 3);
            let expected_indices = [3u64, 4u64, 5u64];
            for (item, expected_index) in items.iter().zip(expected_indices.iter()) {
                assert_eq!(item.0, *expected_index);
            }
        });
    }

    #[test_traced]
    fn test_journal_handling_corrupted_data() {
        // Initialize the deterministic runtime
        let (executor, mut context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".to_string(),
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

            // Manually corrupt the blob 1st blob
            let corrupt_data = vec![0xFF; 10];
            let mut blob = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.write_at(&corrupt_data, 0)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

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
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].0, data_items[0].0);
            assert_eq!(items[0].1, data_items[0].1);
            assert_eq!(items[1].0, data_items[1].0);
            assert_eq!(items[1].1, data_items[1].1);
        });
    }
}
