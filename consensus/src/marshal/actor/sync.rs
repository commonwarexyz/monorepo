use super::{Actor, PendingAck, LATEST_KEY};
use crate::{
    marshal::{
        ingress::handler::Request,
        store::{Blocks, Certificates},
        Update,
    },
    simplex::{scheme::Scheme, types::Finalization},
    types::{Epoch, Epocher, Height, Round},
    Block, Reporter,
};
use commonware_broadcast::buffered;
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    PublicKey,
};
use commonware_parallel::Strategy;
use commonware_resolver::Resolver;
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata;
use commonware_utils::{Acknowledgement, BoxedError};
use futures::try_join;
use rand_core::CryptoRngCore;
use tracing::debug;

impl<E, B, P, FC, FB, ES, T, K, R, App, A> Actor<E, B, P, FC, FB, ES, T, K, R, App, A>
where
    E: CryptoRngCore + Spawner + Metrics + Clock + Storage,
    B: Block,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Commitment>>,
    FC: Certificates<Commitment = B::Commitment, Scheme = P::Scheme>,
    FB: Blocks<Block = B>,
    ES: Epocher,
    T: Strategy,
    K: PublicKey,
    R: Resolver<Key = Request<B>, PublicKey = <P::Scheme as CertificateScheme>::PublicKey>,
    App: Reporter<Activity = Update<B, A>>,
    A: Acknowledgement,
{
    /// Attempt to dispatch the next finalized block to the application if ready.
    pub(super) async fn try_dispatch_block(&mut self, application: &mut App) {
        if self.pending_ack.is_some() {
            return;
        }

        let next_height = self.last_processed_height.next();
        let Some(block) = self.get_finalized_block(next_height).await else {
            return;
        };
        assert_eq!(
            block.height(),
            next_height,
            "finalized block height mismatch"
        );

        let (height, commitment) = (block.height(), block.commitment());
        let (ack, ack_waiter) = A::handle();
        application.report(Update::Block(block, ack)).await;
        self.pending_ack.replace(PendingAck {
            height,
            commitment,
            receiver: ack_waiter,
        });
    }

    /// Handle acknowledgement from the application that a block has been processed.
    pub(super) async fn handle_block_processed(
        &mut self,
        height: Height,
        commitment: B::Commitment,
        resolver: &mut R,
    ) -> Result<(), metadata::Error> {
        // Update the processed height
        self.set_processed_height(height, resolver).await?;

        // Cancel any useless requests
        resolver.cancel(Request::<B>::Block(commitment)).await;

        if let Some(finalization) = self.get_finalization_by_height(height).await {
            // Trail the previous processed finalized block by the timeout
            let lpr = self.last_processed_round;
            let prune_round = Round::new(
                lpr.epoch(),
                lpr.view().saturating_sub(self.view_retention_timeout),
            );

            // Prune archives
            self.cache.prune(prune_round).await;

            // Update the last processed round
            let round = finalization.round();
            self.last_processed_round = round;

            // Cancel useless requests
            resolver
                .retain(Request::<B>::Notarized { round }.predicate())
                .await;
        }

        Ok(())
    }

    /// Add a finalized block, and optionally a finalization, to the archive, and
    /// attempt to identify + repair any gaps in the archive.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn finalize(
        &mut self,
        height: Height,
        commitment: B::Commitment,
        block: B,
        finalization: Option<Finalization<P::Scheme, B::Commitment>>,
        application: &mut App,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
    ) {
        self.store_finalization(height, commitment, block, finalization, application)
            .await;

        self.try_repair_gaps(buffer, resolver, application).await;
    }

    /// Add a finalized block, and optionally a finalization, to the archive.
    ///
    /// After persisting the block, attempt to dispatch the next contiguous block to the
    /// application.
    pub(super) async fn store_finalization(
        &mut self,
        height: Height,
        commitment: B::Commitment,
        block: B,
        finalization: Option<Finalization<P::Scheme, B::Commitment>>,
        application: &mut App,
    ) {
        self.notify_subscribers(commitment, &block).await;

        // Extract round before finalization is moved into try_join
        let round = finalization.as_ref().map(|f| f.round());

        // In parallel, update the finalized blocks and finalizations archives
        if let Err(e) = try_join!(
            // Update the finalized blocks archive
            async {
                self.finalized_blocks.put(block).await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            // Update the finalizations archive (if provided)
            async {
                if let Some(finalization) = finalization {
                    self.finalizations_by_height
                        .put(height, commitment, finalization)
                        .await
                        .map_err(Box::new)?;
                }
                Ok::<_, BoxedError>(())
            }
        ) {
            panic!("failed to finalize: {e}");
        }

        // Update metrics and send tip update to application
        if let Some(round) = round.filter(|_| height > self.tip) {
            application
                .report(Update::Tip(round, height, commitment))
                .await;
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        self.try_dispatch_block(application).await;
    }

    /// Attempt to repair any identified gaps in the finalized blocks archive. The total
    /// number of missing heights that can be repaired at once is bounded by `self.max_repair`,
    /// though multiple gaps may be spanned.
    pub(super) async fn try_repair_gaps(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        application: &mut App,
    ) {
        let start = self.last_processed_height.next();
        'cache_repair: loop {
            let (gap_start, Some(gap_end)) = self.finalized_blocks.next_gap(start) else {
                // No gaps detected
                return;
            };

            // Attempt to repair the gap backwards from the end of the gap, using
            // blocks from our local storage.
            let Some(mut cursor) = self.get_finalized_block(gap_end).await else {
                panic!("gapped block missing that should exist: {gap_end}");
            };

            // Compute the lower bound of the recursive repair. `gap_start` is `Some`
            // if `start` is not in a gap. We add one to it to ensure we don't
            // re-persist it to the database in the repair loop below.
            let gap_start = gap_start.map(|s| s.next()).unwrap_or(start);

            // Iterate backwards, repairing blocks as we go.
            while cursor.height() > gap_start {
                let commitment = cursor.parent();
                if let Some(block) = self.find_block(buffer, commitment).await {
                    let finalization = self.cache.get_finalization_for(commitment).await;
                    self.store_finalization(
                        block.height(),
                        commitment,
                        block.clone(),
                        finalization,
                        application,
                    )
                    .await;
                    debug!(height = %block.height(), "repaired block");
                    cursor = block;
                } else {
                    // Request the next missing block digest
                    resolver.fetch(Request::<B>::Block(commitment)).await;
                    break 'cache_repair;
                }
            }
        }

        // Request any finalizations for missing items in the archive, up to
        // the `max_repair` quota. This may help shrink the size of the gap
        // closest to the application's processed height if finalizations
        // for the requests' heights exist. If not, we rely on the recursive
        // digest fetches above.
        let missing_items = self
            .finalized_blocks
            .missing_items(start, self.max_repair.get());
        let requests = missing_items
            .into_iter()
            .map(|height| Request::<B>::Finalized { height })
            .collect::<Vec<_>>();
        if !requests.is_empty() {
            resolver.fetch_all(requests).await
        }
    }

    /// Sets the processed height in storage, metrics, and in-memory state. Also cancels any
    /// outstanding requests below the new processed height.
    pub(super) async fn set_processed_height(
        &mut self,
        height: Height,
        resolver: &mut R,
    ) -> Result<(), metadata::Error> {
        self.application_metadata
            .put_sync(LATEST_KEY, height)
            .await?;
        self.last_processed_height = height;
        let _ = self
            .processed_height
            .try_set(self.last_processed_height.get());

        // Cancel any existing requests below the new floor.
        resolver
            .retain(Request::<B>::Finalized { height }.predicate())
            .await;

        Ok(())
    }
}
