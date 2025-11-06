use crate::{
    marshal::{ingress::orchestrator::Orchestrator, Update},
    Block, Reporter,
};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{fixed_bytes, sequence::FixedBytes};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use tracing::{debug, error};

// The key used to store the last indexed height in the metadata store.
const LATEST_KEY: FixedBytes<1> = fixed_bytes!("00");

/// Requests the finalized blocks (in order) from the orchestrator, sends them to the application,
/// waits for confirmation that the application has processed the block.
///
/// Stores the highest height for which the application has processed. This allows resuming
/// processing from the last processed height after a restart.
pub struct Finalizer<
    B: Block,
    R: Spawner + Clock + Metrics + Storage,
    Z: Reporter<Activity = Update<B>>,
> {
    context: ContextCell<R>,

    // Application that processes the finalized blocks.
    application: Z,

    // Orchestrator that stores the finalized blocks.
    orchestrator: Orchestrator<B>,

    // Notifier to indicate that the finalized blocks have been updated and should be re-queried.
    notifier_rx: mpsc::Receiver<()>,

    // Metadata store that stores the last indexed height.
    metadata: Metadata<R, FixedBytes<1>, u64>,
}

impl<B: Block, R: Spawner + Clock + Metrics + Storage, Z: Reporter<Activity = Update<B>>>
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
        .expect("failed to initialize metadata");

        Self {
            context: ContextCell::new(context),
            application,
            orchestrator,
            notifier_rx,
            metadata,
        }
    }

    /// Start the finalizer.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    /// Run the finalizer, which continuously fetches and processes finalized blocks.
    async fn run(mut self) {
        // Initialize last indexed from metadata store.
        // If the key does not exist, we assume the genesis block (height 0) has been indexed.
        let mut latest = *self.metadata.get(&LATEST_KEY).unwrap_or(&0);

        // The main loop to process finalized blocks. This loop will hot-spin until a block is
        // available, at which point it will process it and continue. If a block is not available,
        // it will request a repair and wait for a notification of an update before retrying.
        loop {
            // The next height to process is the next height after the last processed height.
            let height = latest + 1;

            // Attempt to get the next block from the orchestrator.
            if let Some(block) = self.orchestrator.get(height).await {
                // Sanity-check that the block height is the one we expect.
                assert!(block.height() == height, "block height mismatch");

                // Send the block to the application.
                //
                // After an unclean shutdown (where the finalizer metadata is not synced after some
                // height is processed by the application), it is possible that the application may
                // be asked to process a block it has already seen (which it can simply ignore).
                let commitment = block.commitment();
                let (ack_tx, ack_rx) = oneshot::channel();
                self.application.report(Update::Block(block, ack_tx)).await;
                if let Err(e) = ack_rx.await {
                    error!(?e, height, "application did not acknowledge block");
                    return;
                }

                // Record that we have processed up through this height.
                latest = height;
                if let Err(e) = self.metadata.put_sync(LATEST_KEY.clone(), latest).await {
                    error!(?e, "failed to update metadata");
                    return;
                }

                // Notify the orchestrator that the block has been processed.
                self.orchestrator.processed(height, commitment).await;

                // Loop again without waiting for a notification (there may be more to process).
                continue;
            }

            // We've reached a height at which we have no (finalized) block.
            // It may be the case that the block is not finalized yet, or that there is a gap.
            // Notify the orchestrator that we're trying to access this block.
            self.orchestrator.repair(height).await;

            // Wait for a notification from the orchestrator that new blocks are available.
            debug!(height, "waiting to index finalized block");
            let Some(()) = self.notifier_rx.next().await else {
                error!("orchestrator closed, shutting down");
                return;
            };
        }
    }
}
