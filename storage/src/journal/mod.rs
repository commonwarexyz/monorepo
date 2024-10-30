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
    use commonware_runtime::{deterministic::Executor, Runner};
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
            {
                let mut journal = Journal::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

                // Append an item to the journal
                journal
                    .append(index, data.clone())
                    .await
                    .expect("Failed to append data");

                // Sync the blob to storage
                journal.sync(index).await.expect("Failed to sync blob");
            }

            // Re-initialize the journal to simulate a restart
            {
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
            }
        });
    }

    // #[test]
    // fn test_journal_prune() {
    //     // Initialize the deterministic runtime
    //     let (executor, mut context, _auditor) = Executor::default();

    //     // Start the test within the executor
    //     executor.start(async move {
    //         // Create a journal configuration
    //         let cfg = Config {
    //             partition: "test_partition".to_string(),
    //             ..Default::default()
    //         };

    //         // Initialize the journal
    //         let mut journal = Journal::init(context.clone(), cfg.clone())
    //             .await
    //             .expect("Failed to initialize journal");

    //         // Append items with different indices
    //         for index in 1u64..=5 {
    //             let data = Bytes::from(format!("Data {}", index));
    //             journal
    //                 .append(index, data)
    //                 .await
    //                 .expect("Failed to append data");
    //         }

    //         // Prune blobs with index less than 3
    //         journal.prune(3).await.expect("Failed to prune blobs");

    //         // Verify that blobs with index 1 and 2 are removed
    //         let blobs = journal.blobs.keys().cloned().collect::<Vec<u64>>();
    //         assert_eq!(blobs, vec![3, 4, 5]);
    //     });
    // }

    // #[test]
    // fn test_journal_corruption_handling() {
    //     // Initialize the deterministic runtime
    //     let (executor, mut context, _auditor) = Executor::default();

    //     // Start the test within the executor
    //     executor.start(async move {
    //         // Create a journal configuration
    //         let cfg = Config {
    //             partition: "test_partition".to_string(),
    //             ..Default::default()
    //         };

    //         // Initialize the journal
    //         let mut journal = Journal::init(context.clone(), cfg.clone())
    //             .await
    //             .expect("Failed to initialize journal");

    //         // Append an item to the journal
    //         let index = 1u64;
    //         let data = Bytes::from("Test data");
    //         journal
    //             .append(index, data.clone())
    //             .await
    //             .expect("Failed to append data");

    //         // Manually corrupt the blob
    //         if let Some(blob) = journal.blobs.get_mut(&index) {
    //             // Overwrite the first 4 bytes (size field)
    //             blob.write_at(&[0xFF, 0xFF, 0xFF, 0xFF], 0)
    //                 .await
    //                 .expect("Failed to corrupt blob");
    //             blob.sync().await.expect("Failed to sync corrupted blob");
    //         }

    //         // Re-initialize the journal to simulate a restart
    //         let mut journal = Journal::init(context.clone(), cfg.clone())
    //             .await
    //             .expect("Failed to re-initialize journal");

    //         // Attempt to replay the journal
    //         let result = journal.replay(|_, _| true).await;

    //         // Verify that a BlobCorrupt error is returned
    //         assert!(matches!(result, Err(Error::BlobCorrupt)));
    //     });
    // }

    // #[test]
    // fn test_journal_multiple_blobs() {
    //     // Initialize the deterministic runtime
    //     let (executor, mut context, _auditor) = Executor::default();

    //     // Start the test within the executor
    //     executor.start(async move {
    //         // Create a journal configuration
    //         let cfg = Config {
    //             partition: "test_partition".to_string(),
    //             ..Default::default()
    //         };

    //         // Initialize the journal
    //         let mut journal = Journal::init(context.clone(), cfg.clone())
    //             .await
    //             .expect("Failed to initialize journal");

    //         // Append items to multiple blobs
    //         let indices = vec![1u64, 2u64, 3u64];
    //         for &index in &indices {
    //             let data = Bytes::from(format!("Data for blob {}", index));
    //             journal
    //                 .append(index, data)
    //                 .await
    //                 .expect("Failed to append data");
    //         }

    //         // Sync all blobs
    //         for &index in &indices {
    //             journal.sync(index).await.expect("Failed to sync blob");
    //         }

    //         // Re-initialize the journal to simulate a restart
    //         let mut journal = Journal::init(context.clone(), cfg.clone())
    //             .await
    //             .expect("Failed to re-initialize journal");

    //         // Replay the journal and collect items
    //         let mut items = Vec::new();
    //         journal
    //             .replay(|blob_index, item| {
    //                 items.push((blob_index, item));
    //                 true
    //             })
    //             .await
    //             .expect("Failed to replay journal");

    //         // Verify that all items were replayed correctly
    //         assert_eq!(items.len(), indices.len());
    //         for (i, &index) in indices.iter().enumerate() {
    //             assert_eq!(items[i].0, index);
    //             assert_eq!(items[i].1, Bytes::from(format!("Data for blob {}", index)));
    //         }
    //     });
    // }
}
