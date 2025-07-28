use crate::{marshal::ingress::orchestrator::Orchestrator, Block, Reporter};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::array::{FixedBytes, U64};
use futures::{channel::mpsc, StreamExt};
use tracing::{debug, error};

/// Requests the finalized blocks (in order) from the orchestrator, sends them to the application,
/// waits for confirmation that the application has processed the block.
///
/// Stores the highest height for which the application has processed. This allows resuming
/// processing from the last processed height after a restart.
pub struct Finalizer<B: Block, R: Spawner + Clock + Metrics + Storage, Z: Reporter<Activity = B>> {
    // Application that processes the finalized blocks.
    application: Z,

    // Orchestrator that stores the finalized blocks.
    orchestrator: Orchestrator<B>,

    // Notifier to indicate that the finalized blocks have been updated and should be re-queried.
    notifier_rx: mpsc::Receiver<()>,

    // Metadata store that stores the last indexed height.
    metadata: Metadata<R, FixedBytes<1>, U64>,
}

impl<B: Block, R: Spawner + Clock + Metrics + Storage, Z: Reporter<Activity = B>>
    Finalizer<B, R, Z>
{
    /// Initialize the finalizer.
    pub async fn new(
        context: R,
        partition_prefix: String,
        application: Z,
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
            application,
            orchestrator,
            notifier_rx,
            metadata,
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

                // Send the block to the application.
                //
                // Once it responds, we can both update the metadata and notify the orchestrator.
                //
                // After an unclean shutdown (where the finalizer metadata is not synced after some
                // height is processed by the application), it is possible that the application may
                // be asked to process a block it has already seen (which it can simply ignore).

                // Send the block to the application.
                let commitment = block.commitment();
                self.application.report(block).await;

                // Update metadata.
                if let Err(e) = self
                    .metadata
                    .put_sync(latest_key.clone(), height.into())
                    .await
                {
                    error!("Failed to update metadata: {e}");
                    return;
                }

                // Update last view processed (if we have a finalization for this block)
                self.orchestrator.processed(height, commitment).await;

                // Loop again without waiting for a notification (there may be more to process)
                continue;
            }

            // We've reached a height at which we have no (finalized) block.
            // Notify the orchestrator that we're trying to access this block.
            // It may be the case that the block is not finalized yet, or that there is a gap.
            self.orchestrator.repair(height).await;

            // Wait for a notification that the orchestrator has updated the finalized blocks.
            debug!(height, "waiting to index finalized block");
            let _ = self.notifier_rx.next().await;
        }
    }
}
