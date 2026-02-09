use super::Actor;
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
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::archive::Identifier as ArchiveID;
use commonware_utils::{channel::fallible::OneshotExt, Acknowledgement, BoxedError};
use futures::try_join;
use rand_core::CryptoRngCore;
use std::sync::Arc;
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
    /// Returns a scheme suitable for verifying certificates at the given epoch.
    ///
    /// Prefers a certificate verifier if available, otherwise falls back
    /// to the scheme for the given epoch.
    pub(super) fn get_scheme_certificate_verifier(&self, epoch: Epoch) -> Option<Arc<P::Scheme>> {
        self.provider.all().or_else(|| self.provider.scoped(epoch))
    }

    /// Notify any subscribers for the given commitment with the provided block.
    pub(super) async fn notify_subscribers(&mut self, commitment: B::Commitment, block: &B) {
        if let Some(mut bs) = self.block_subscriptions.remove(&commitment) {
            for subscriber in bs.subscribers.drain(..) {
                subscriber.send_lossy(block.clone());
            }
        }
    }

    /// Add a verified block to the prunable archive.
    pub(super) async fn cache_verified(
        &mut self,
        round: Round,
        commitment: B::Commitment,
        block: B,
    ) {
        self.notify_subscribers(commitment, &block).await;
        self.cache.put_verified(round, commitment, block).await;
    }

    /// Add a notarized block to the prunable archive.
    pub(super) async fn cache_block(&mut self, round: Round, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block).await;
        self.cache.put_block(round, commitment, block).await;
    }

    /// Get a finalized block from the immutable archive.
    pub(super) async fn get_finalized_block(&mut self, height: Height) -> Option<B> {
        match self
            .finalized_blocks
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(block) => block,
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive by height.
    pub(super) async fn get_finalization_by_height(
        &mut self,
        height: Height,
    ) -> Option<Finalization<P::Scheme, B::Commitment>> {
        match self
            .finalizations_by_height
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization: {e}"),
        }
    }

    /// Get the latest finalized block information (height and commitment tuple).
    ///
    /// Blocks are only finalized directly with a finalization or indirectly via a descendant
    /// block's finalization. Thus, the highest known finalized block must itself have a direct
    /// finalization.
    ///
    /// We return the height and commitment using the highest known finalization that we know the
    /// block height for. While it's possible that we have a later finalization, if we do not have
    /// the full block for that finalization, we do not know it's height and therefore it would not
    /// yet be found in the `finalizations_by_height` archive. While not checked explicitly, we
    /// should have the associated block (in the `finalized_blocks` archive) for the information
    /// returned.
    pub(super) async fn get_latest(&mut self) -> Option<(Height, B::Commitment, Round)> {
        let height = self.finalizations_by_height.last_index()?;
        let finalization = self
            .get_finalization_by_height(height)
            .await
            .expect("finalization missing");
        Some((height, finalization.proposal.payload, finalization.round()))
    }

    /// Looks for a block anywhere in local storage.
    pub(super) async fn find_block(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        commitment: B::Commitment,
    ) -> Option<B> {
        // Check buffer.
        if let Some(block) = buffer.get(None, commitment, None).await.into_iter().next() {
            return Some(block);
        }
        // Check verified / notarized blocks via cache manager.
        if let Some(block) = self.cache.find_block(commitment).await {
            return Some(block);
        }
        // Check finalized blocks.
        match self.finalized_blocks.get(ArchiveID::Key(&commitment)).await {
            Ok(block) => block, // may be None
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Prunes finalized blocks and certificates below the given height.
    pub(super) async fn prune_finalized_archives(
        &mut self,
        height: Height,
    ) -> Result<(), BoxedError> {
        try_join!(
            async {
                self.finalized_blocks
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
        )?;
        Ok(())
    }

    /// Looks for a block locally and returns it if found. If not found, issues
    /// a fetch request to the resolver and returns `None`.
    pub(super) async fn find_block_or_fetch(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        commitment: B::Commitment,
        request: Request<B>,
    ) -> Option<B> {
        if let Some(block) = self.find_block(buffer, commitment).await {
            return Some(block);
        }
        debug!(?commitment, "block missing, fetching");
        resolver.fetch(request).await;
        None
    }
}
