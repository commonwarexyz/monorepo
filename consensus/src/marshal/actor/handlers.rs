use super::{Actor, BlockSubscription, Error};
use crate::{
    marshal::{
        ingress::{handler::Request, mailbox::Identifier as BlockID},
        store::{Blocks, Certificates},
        Update,
    },
    simplex::{
        scheme::Scheme,
        types::{Finalization, Notarization},
    },
    types::{Epoch, Epocher, Height, Round},
    Block, Reporter,
};
use bytes::Bytes;
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    PublicKey,
};
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_resolver::Resolver;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::archive::Identifier as ArchiveID;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    Acknowledgement, BoxedError,
};
use rand_core::CryptoRngCore;
use std::collections::btree_map::Entry;
use tracing::{debug, error, warn};

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
    pub(super) async fn handle_get_info(
        &mut self,
        identifier: BlockID<B::Commitment>,
        response: oneshot::Sender<Option<(Height, B::Commitment)>>,
    ) {
        let info = match identifier {
            // TODO: Instead of pulling out the entire block, determine the
            // height directly from the archive by mapping the commitment to
            // the index, which is the same as the height.
            BlockID::Commitment(commitment) => self
                .finalized_blocks
                .get(ArchiveID::Key(&commitment))
                .await
                .ok()
                .flatten()
                .map(|b| (b.height(), commitment)),
            BlockID::Height(height) => self
                .finalizations_by_height
                .get(ArchiveID::Index(height.get()))
                .await
                .ok()
                .flatten()
                .map(|f| (height, f.proposal.payload)),
            BlockID::Latest => self.get_latest().await.map(|(h, c, _)| (h, c)),
        };
        response.send_lossy(info);
    }

    pub(super) async fn handle_get_block(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        identifier: BlockID<B::Commitment>,
        response: oneshot::Sender<Option<B>>,
    ) {
        match identifier {
            BlockID::Commitment(commitment) => {
                let result = self.find_block(buffer, commitment).await;
                response.send_lossy(result);
            }
            BlockID::Height(height) => {
                let result = self.get_finalized_block(height).await;
                response.send_lossy(result);
            }
            BlockID::Latest => {
                let block = match self.get_latest().await {
                    Some((_, commitment, _)) => self.find_block(buffer, commitment).await,
                    None => None,
                };
                response.send_lossy(block);
            }
        }
    }

    pub(super) async fn handle_hint_finalized(
        &mut self,
        resolver: &mut R,
        height: Height,
        targets: commonware_utils::vec::NonEmptyVec<<P::Scheme as CertificateScheme>::PublicKey>,
    ) {
        // Skip if height is at or below the floor
        if height <= self.last_processed_height {
            return;
        }

        // Skip if finalization is already available locally
        if self.get_finalization_by_height(height).await.is_some() {
            return;
        }

        // Trigger a targeted fetch via the resolver
        let request = Request::<B>::Finalized { height };
        resolver.fetch_targeted(request, targets).await;
    }

    pub(super) async fn handle_subscribe(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        round: Option<Round>,
        commitment: B::Commitment,
        response: oneshot::Sender<B>,
    ) {
        // Check for block locally
        if let Some(block) = self.find_block(buffer, commitment).await {
            response.send_lossy(block);
            return;
        }

        // We don't have the block locally, so fetch the block from the network
        // if we have an associated view. If we only have the digest, don't make
        // the request as we wouldn't know when to drop it, and the request may
        // never complete if the block is not finalized.
        if let Some(round) = round {
            if round < self.last_processed_round {
                // At this point, we have failed to find the block locally, and
                // we know that its round is less than the last processed round.
                // This means that something else was finalized in that round,
                // so we drop the response to indicate that the block may never
                // be available.
                return;
            }
            // Attempt to fetch the block (with notarization) from the resolver.
            // If this is a valid view, this request should be fine to keep open
            // until resolution or pruning (even if the oneshot is canceled).
            debug!(?round, ?commitment, "requested block missing");
            resolver.fetch(Request::<B>::Notarized { round }).await;
        }

        // Register subscriber
        debug!(?round, ?commitment, "registering subscriber");
        match self.block_subscriptions.entry(commitment) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(response);
            }
            Entry::Vacant(entry) => {
                let (tx, rx) = oneshot::channel();
                buffer.subscribe_prepared(None, commitment, None, tx).await;
                let aborter = self
                    .waiters
                    .push(async move { (commitment, rx.await.expect("buffer subscriber closed")) });
                entry.insert(BlockSubscription {
                    subscribers: vec![response],
                    _aborter: aborter,
                });
            }
        }
    }

    pub(super) async fn handle_proposed(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        round: Round,
        block: B,
    ) {
        self.cache_verified(round, block.commitment(), block.clone())
            .await;
        let _peers = buffer.broadcast(Recipients::All, block).await;
    }

    pub(super) async fn handle_notarization(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        notarization: Notarization<P::Scheme, B::Commitment>,
    ) {
        let round = notarization.round();
        let commitment = notarization.proposal.payload;

        self.cache
            .put_notarization(round, commitment, notarization.clone())
            .await;

        if let Some(block) = self
            .find_block_or_fetch(
                buffer,
                resolver,
                commitment,
                Request::<B>::Notarized { round },
            )
            .await
        {
            self.cache_block(round, commitment, block).await;
        }
    }

    pub(super) async fn handle_finalization(
        &mut self,
        application: &mut App,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        finalization: Finalization<P::Scheme, B::Commitment>,
    ) {
        let round = finalization.round();
        let commitment = finalization.proposal.payload;
        self.cache
            .put_finalization(round, commitment, finalization.clone())
            .await;

        if let Some(block) = self
            .find_block_or_fetch(
                buffer,
                resolver,
                commitment,
                Request::<B>::Block(commitment),
            )
            .await
        {
            let height = block.height();
            self.finalize(
                height,
                commitment,
                block,
                Some(finalization),
                application,
                buffer,
                resolver,
            )
            .await;
            debug!(?round, %height, "finalized block stored");
        }
    }

    pub(super) async fn handle_set_floor(
        &mut self,
        resolver: &mut R,
        height: Height,
    ) -> Result<(), Error> {
        if self.last_processed_height >= height {
            warn!(
                %height,
                existing = %self.last_processed_height,
                "floor not updated, lower than existing"
            );
            return Ok(());
        }

        self.set_processed_height(height, resolver).await?;

        // Drop the pending acknowledgement, if one exists. We must do this to prevent
        // an in-process block from being processed that is below the new floor
        // updating `last_processed_height`.
        self.pending_ack = None.into();

        self.prune_finalized_archives(height)
            .await
            .map_err(Error::Storage)?;
        Ok(())
    }

    pub(super) async fn handle_prune(&mut self, height: Height) -> Result<(), Error> {
        if height > self.last_processed_height {
            warn!(%height, floor = %self.last_processed_height, "prune height above floor, ignoring");
            return Ok(());
        }

        self.prune_finalized_archives(height)
            .await
            .map_err(Error::Storage)?;
        Ok(())
    }

    pub(super) async fn handle_ack_completed(
        &mut self,
        application: &mut App,
        resolver: &mut R,
        height: Height,
        commitment: B::Commitment,
        result: Result<(), BoxedError>,
    ) -> Result<(), Error> {
        match result {
            Ok(()) => {
                self.handle_block_processed(height, commitment, resolver)
                    .await?;
                self.try_dispatch_block(application).await;
            }
            Err(e) => {
                error!(?e, %height, "application did not acknowledge block");
                return Err(Error::Application(e));
            }
        }
        Ok(())
    }

    pub(super) async fn handle_resolver_produce(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        key: Request<B>,
        response: oneshot::Sender<Bytes>,
    ) {
        match key {
            Request::Block(commitment) => {
                self.produce_block(buffer, commitment, response).await;
            }
            Request::Finalized { height } => {
                self.produce_finalization(height, response).await;
            }
            Request::Notarized { round } => {
                self.produce_notarization(buffer, round, response).await;
            }
        }
    }

    async fn produce_block(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        commitment: B::Commitment,
        response: oneshot::Sender<Bytes>,
    ) {
        let Some(block) = self.find_block(buffer, commitment).await else {
            debug!(?commitment, "block missing on request");
            return;
        };
        response.send_lossy(block.encode());
    }

    async fn produce_finalization(&mut self, height: Height, response: oneshot::Sender<Bytes>) {
        let Some(finalization) = self.get_finalization_by_height(height).await else {
            debug!(%height, "finalization missing on request");
            return;
        };
        let Some(block) = self.get_finalized_block(height).await else {
            debug!(%height, "finalized block missing on request");
            return;
        };
        response.send_lossy((finalization, block).encode());
    }

    async fn produce_notarization(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        round: Round,
        response: oneshot::Sender<Bytes>,
    ) {
        let Some(notarization) = self.cache.get_notarization(round).await else {
            debug!(?round, "notarization missing on request");
            return;
        };
        let commitment = notarization.proposal.payload;
        let Some(block) = self.find_block(buffer, commitment).await else {
            debug!(?commitment, "block missing on request");
            return;
        };
        response.send_lossy((notarization, block).encode());
    }

    pub(super) async fn deliver_block(
        &mut self,
        application: &mut App,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        commitment: B::Commitment,
        value: Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let Ok(block) = B::decode_cfg(value.as_ref(), &self.block_codec_config) else {
            response.send_lossy(false);
            return;
        };
        if block.commitment() != commitment {
            response.send_lossy(false);
            return;
        }

        let height = block.height();
        let finalization = self.cache.get_finalization_for(commitment).await;
        self.finalize(
            height,
            commitment,
            block,
            finalization,
            application,
            buffer,
            resolver,
        )
        .await;
        debug!(?commitment, %height, "received block");
        response.send_lossy(true);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn deliver_finalization(
        &mut self,
        context: &mut E,
        application: &mut App,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        height: Height,
        value: Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let Some(bounds) = self.epocher.containing(height) else {
            response.send_lossy(false);
            return;
        };
        let Some(scheme) = self.get_scheme_certificate_verifier(bounds.epoch()) else {
            response.send_lossy(false);
            return;
        };

        let Ok((finalization, block)) = <(Finalization<P::Scheme, B::Commitment>, B)>::decode_cfg(
            value,
            &(
                scheme.certificate_codec_config(),
                self.block_codec_config.clone(),
            ),
        ) else {
            response.send_lossy(false);
            return;
        };

        if block.height() != height
            || finalization.proposal.payload != block.commitment()
            || !finalization.verify(context, &scheme, &self.strategy)
        {
            response.send_lossy(false);
            return;
        }

        debug!(%height, "received finalization");
        response.send_lossy(true);
        self.finalize(
            height,
            block.commitment(),
            block,
            Some(finalization),
            application,
            buffer,
            resolver,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn deliver_notarization(
        &mut self,
        context: &mut E,
        application: &mut App,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        round: Round,
        value: Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let Some(scheme) = self.get_scheme_certificate_verifier(round.epoch()) else {
            response.send_lossy(false);
            return;
        };

        let Ok((notarization, block)) = <(Notarization<P::Scheme, B::Commitment>, B)>::decode_cfg(
            value,
            &(
                scheme.certificate_codec_config(),
                self.block_codec_config.clone(),
            ),
        ) else {
            response.send_lossy(false);
            return;
        };

        if notarization.round() != round
            || notarization.proposal.payload != block.commitment()
            || !notarization.verify(context, &scheme, &self.strategy)
        {
            response.send_lossy(false);
            return;
        }

        response.send_lossy(true);
        let commitment = block.commitment();
        debug!(?round, ?commitment, "received notarization");

        // If there exists a finalization certificate for this block, we
        // should finalize it. While not necessary, this could finalize
        // the block faster in the case where a notarization then a
        // finalization is received via the consensus engine and we
        // resolve the request for the notarization before we resolve
        // the request for the block.
        let height = block.height();
        if let Some(finalization) = self.cache.get_finalization_for(commitment).await {
            self.finalize(
                height,
                commitment,
                block.clone(),
                Some(finalization),
                application,
                buffer,
                resolver,
            )
            .await;
        }

        self.cache_block(round, commitment, block).await;
        self.cache
            .put_notarization(round, commitment, notarization)
            .await;
    }
}
