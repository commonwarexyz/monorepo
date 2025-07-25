use crate::{marshal::ingress::Orchestrator, Block};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::array::{FixedBytes, U64};
use futures::{channel::mpsc, StreamExt};
use tracing::{debug, error, info};

pub struct Finalizer<B, R>
where
    B: Block,
    R: Spawner + Clock + Metrics + Storage,
{
    // Metadata store that stores the last indexed height.
    metadata: Metadata<R, FixedBytes<1>, U64>,

    // Orchestrator that stores the finalized blocks.
    orchestrator: Orchestrator<B>,

    // Notifier to indicate that the finalized blocks have been updated and should be re-queried.
    notifier_rx: mpsc::Receiver<()>,
}

impl<B, R> Finalizer<B, R>
where
    B: Block,
    R: Spawner + Clock + Metrics + Storage,
{
    /// Initialize the finalizer.
    pub async fn new(
        context: R,
        partition_prefix: String,
        orchestrator: Orchestrator<B>,
        notifier_rx: mpsc::Receiver<()>,
    ) -> Self {
        // Initialize metadata
        let metadata = Metadata::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}-metadata"),
                codec_config: (),
            },
        )
        .await
        .expect("Failed to initialize metadata");

        Self {
            metadata,
            orchestrator,
            notifier_rx,
        }
    }

    /// Run the finalizer.
    pub async fn run(mut self) {
        // Initialize last indexed from metadata store.
        // If the key does not exist, we assume the genesis block (height 0) has been indexed.
        let latest_key = FixedBytes::new([0u8]);
        let mut height = self.metadata.get(&latest_key).map_or(0, |x| x.to_u64());

        // Index all finalized blocks.
        //
        // If using state sync, this is not necessary.
        loop {
            // Check if the next block is available
            height += 1;
            if let Some(block) = self.orchestrator.get(height).await {
                // Sanity-check that the block height matches the expected height.
                assert!(block.height() == height, "block height mismatch");

                // In an application that maintains state, you would compute the state transition function here.
                //
                // After an unclean shutdown (where the finalizer metadata is not synced after some height is processed by the application),
                // it is possible that the application may be asked to process a block it has already seen (which it can simply ignore).

                // Update finalizer metadata.
                //
                // If we updated the finalizer metadata before the application applied its state transition function, an unclean
                // shutdown could put the application in an unrecoverable state where the last indexed height (the height we
                // start processing at after restart) is ahead of the application's last processed height (requiring the application
                // to process a non-contiguous log). For the same reason, the application should sync any cached disk changes after processing
                // its state transition function to ensure that the application can continue processing from the the last synced indexed height
                // (on restart).
                if let Err(e) = self
                    .metadata
                    .put_sync(latest_key.clone(), height.into())
                    .await
                {
                    error!("Failed to update metadata: {e}");
                    return;
                }

                // Update the latest indexed
                info!(height, "indexed finalized block");

                // Update last view processed (if we have a finalization for this block)
                self.orchestrator
                    .processed(height, block.commitment())
                    .await;
                continue;
            }

            // Try to connect to our latest handled block (may not exist finalizations for some heights)
            self.orchestrator.repair(height).await;

            // If nothing to do, wait for some message from someone that the finalized store was updated
            debug!(height, "waiting to index finalized block");
            let _ = self.notifier_rx.next().await;
        }
    }
}
