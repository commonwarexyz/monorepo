use crate::{marshal::ingress::Orchestrator, Block};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::array::{FixedBytes, U64};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::gauge::Gauge;
use std::marker::PhantomData;
use tracing::{debug, error, info};

pub struct Finalizer<B, R>
where
    B: Block,
    R: Spawner + Clock + Metrics + Storage,
{
    metadata: Metadata<R, FixedBytes<1>, U64>,
    contiguous_height: Gauge,
    orchestrator: Orchestrator<B>,
    finalizer_receiver: mpsc::Receiver<()>,
    _digest: PhantomData<B::Digest>,
}

impl<B, R> Finalizer<B, R>
where
    B: Block,
    R: Spawner + Clock + Metrics + Storage,
{
    pub fn new(
        metadata: Metadata<R, FixedBytes<1>, U64>,
        contiguous_height: Gauge,
        orchestrator: Orchestrator<B>,
        finalizer_receiver: mpsc::Receiver<()>,
    ) -> Self {
        Self {
            metadata,
            contiguous_height,
            orchestrator,
            finalizer_receiver,
            _digest: PhantomData,
        }
    }

    pub async fn run(mut self) {
        // Initialize last indexed from metadata store
        let latest_key = FixedBytes::new([0u8]);
        let mut last_indexed = if let Some(bytes) = self.metadata.get(&latest_key) {
            bytes
                .to_vec()
                .try_into()
                .map(u64::from_be_bytes)
                .unwrap_or(0)
        } else {
            0
        };

        // Index all finalized blocks.
        //
        // If using state sync, this is not necessary.
        loop {
            // Check if the next block is available
            let next = last_indexed + 1;
            if let Some(block) = self.orchestrator.get(next).await {
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
                    .put_sync(latest_key.clone(), next.into())
                    .await
                {
                    error!("Failed to update metadata: {e}");
                    return;
                }

                // Update the latest indexed
                self.contiguous_height.set(next as i64);
                last_indexed = next;
                info!(height = next, "indexed finalized block");

                // Update last view processed (if we have a finalization for this block)
                self.orchestrator.processed(next, block.commitment()).await;
                continue;
            }

            // Try to connect to our latest handled block (may not exist finalizations for some heights)
            if self.orchestrator.repair(next).await {
                continue;
            }

            // If nothing to do, wait for some message from someone that the finalized store was updated
            debug!(height = next, "waiting to index finalized block");
            let _ = self.finalizer_receiver.next().await;
        }
    }
}
