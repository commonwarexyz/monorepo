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
}
