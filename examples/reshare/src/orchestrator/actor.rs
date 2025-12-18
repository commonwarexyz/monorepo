//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{Block, EpochProvider, Provider},
    orchestrator::{Mailbox, Message},
    BLOCKS_PER_EPOCH,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    marshal,
    simplex::{
        self,
        elector::Config as Elector,
        scheme,
        types::{Certificate, Context},
    },
    types::{Epoch, ViewDelta},
    utils::last_block_in_epoch,
    Automaton, Relay,
};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, certificate::Scheme, Hasher, Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::mux::{Builder, MuxHandle, Muxer},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Quota, Spawner,
    Storage,
};
use commonware_utils::{NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, marker::PhantomData, time::Duration};
use tracing::{debug, info, warn};

/// Configuration for the orchestrator.
pub struct Config<B, V, C, H, A, S, L>
where
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
    S: Scheme,
    L: Elector<S>,
{
    pub oracle: B,
    pub application: A,
    pub provider: Provider<S, C>,
    pub marshal: marshal::Mailbox<S, Block<H, C, V>>,

    pub namespace: Vec<u8>,
    pub muxer_size: usize,
    pub mailbox_size: usize,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,

    pub _phantom: PhantomData<L>,
}

pub struct Actor<E, B, V, C, H, A, S, L>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
    S: Scheme,
    L: Elector<S>,
    Provider<S, C>: EpochProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<V, C::PublicKey>>,
    application: A,

    oracle: B,
    marshal: marshal::Mailbox<S, Block<H, C, V>>,
    provider: Provider<S, C>,

    namespace: Vec<u8>,
    muxer_size: usize,
    partition_prefix: String,
    pool_ref: PoolRef,
    _phantom: PhantomData<L>,
}

impl<E, B, V, C, H, A, S, L> Actor<E, B, V, C, H, A, S, L>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
    S: scheme::Scheme<H::Digest, PublicKey = C::PublicKey>,
    L: Elector<S>,
    Provider<S, C>: EpochProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    pub fn new(
        context: E,
        config: Config<B, V, C, H, A, S, L>,
    ) -> (Self, Mailbox<V, C::PublicKey>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        let pool_ref = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                application: config.application,
                oracle: config.oracle,
                marshal: config.marshal,
                provider: config.provider,
                namespace: config.namespace,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
                pool_ref,
                _phantom: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        votes: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        orchestrator: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(votes, certificates, resolver, orchestrator).await
        )
    }

    async fn run(
        mut self,
        (vote_sender, vote_receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        (certificate_sender, certificate_receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        (resolver_sender, resolver_receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        (mut orchestrator_sender, mut orchestrator_receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        // Start muxers for each physical channel used by consensus
        let (mux, mut vote_mux, mut vote_backup) = Muxer::builder(
            self.context.with_label("vote_mux"),
            vote_sender,
            vote_receiver,
            self.muxer_size,
        )
        .with_backup()
        .build();
        mux.start();
        let (mux, mut certificate_mux, mut certificate_global_sender) = Muxer::builder(
            self.context.with_label("certificate_mux"),
            certificate_sender,
            certificate_receiver,
            self.muxer_size,
        )
        .with_global_sender()
        .build();
        mux.start();
        let (mux, mut resolver_mux) = Muxer::new(
            self.context.with_label("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.muxer_size,
        );
        mux.start();

        // Wait for instructions to transition epochs.
        let mut engines = BTreeMap::new();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping orchestrator");
            },
            message = vote_backup.next() => {
                // If a message is received in an unregistered sub-channel in the vote network,
                // attempt to forward the orchestrator for the epoch.
                let Some((their_epoch, (from, _))) = message else {
                    warn!("vote mux backup channel closed, shutting down orchestrator");
                    break;
                };
                let their_epoch = Epoch::new(their_epoch);
                let Some(our_epoch) = engines.keys().last().copied() else {
                    debug!(%their_epoch, ?from, "received message from unregistered epoch with no known epochs");
                    continue;
                };
                if their_epoch <= our_epoch {
                    debug!(%their_epoch, %our_epoch, ?from, "received message from past epoch");
                    continue;
                }

                // If we're not in the committee of the latest epoch we know about and we observe another
                // participant that is ahead of us, send a message on the orchestrator channel to prompt
                // them to send us the finalization of the epoch boundary block for our latest known epoch.
                let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, our_epoch);
                if self.marshal.get_finalization(boundary_height).await.is_some() {
                    // Only request the orchestrator if we don't already have it.
                    continue;
                };
                debug!(
                    %their_epoch,
                    ?from,
                    "received backup message from future epoch, requesting orchestrator"
                );

                // Send the request to the orchestrator. This operation is best-effort.
                if orchestrator_sender.send(
                    Recipients::One(from),
                    our_epoch.encode().freeze(),
                    true
                ).await.is_err() {
                    warn!("failed to send orchestrator request, shutting down orchestrator");
                    break;
                }
            },
            message = orchestrator_receiver.recv() => {
                let Ok((from, bytes)) = message else {
                    warn!("orchestrator channel closed, shutting down orchestrator");
                    break;
                };
                let epoch = match Epoch::decode(bytes.as_ref()) {
                    Ok(epoch) => epoch,
                    Err(err) => {
                        debug!(?err, ?from, "failed to decode epoch from orchestrator request");
                        self.oracle.block(from).await;
                        continue;
                    }
                };

                // Fetch the finalization certificate for the last block within the subchannel's epoch.
                // If the node is state synced, marshal may not have the finalization locally, and the
                // peer will need to fetch it from another node on the network.
                let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, epoch);
                let Some(finalization) = self.marshal.get_finalization(boundary_height).await else {
                    debug!(%epoch, ?from, "missing finalization for old epoch");
                    continue;
                };
                debug!(
                    %epoch,
                    boundary_height,
                    ?from,
                    "received message on vote network from old epoch. forwarding orchestrator"
                );

                // Forward the finalization to the sender. This operation is best-effort.
                //
                // TODO (#2032): Send back to orchestrator for direct insertion into marshal.
                let message = Certificate::<S, H::Digest>::Finalization(finalization);
                if certificate_global_sender
                    .send(
                        epoch.get(),
                        Recipients::One(from),
                        message.encode().freeze(),
                        false,
                    )
                    .await.is_err() {
                        warn!("failed to forward finalization, shutting down orchestrator");
                        break;
                    }
            },
            transition = self.mailbox.next() => {
                let Some(transition) = transition else {
                    warn!("mailbox closed, shutting down orchestrator");
                    break;
                };

                match transition {
                    Message::Enter(transition) => {
                        // If the epoch is already in the map, ignore.
                        if engines.contains_key(&transition.epoch) {
                            warn!(epoch = %transition.epoch, "entered existing epoch");
                            continue;
                        }

                        // Register the new signing scheme with the scheme provider.
                        let scheme = self.provider.scheme_for_epoch(&transition);
                        assert!(self.provider.register(transition.epoch, scheme.clone()));

                        // Enter the new epoch.
                        let engine = self
                            .enter_epoch(
                                transition.epoch,
                                scheme,
                                &mut vote_mux,
                                &mut certificate_mux,
                                &mut resolver_mux,
                            )
                            .await;
                        engines.insert(transition.epoch, engine);

                        info!(epoch = %transition.epoch, "entered epoch");
                    }
                    Message::Exit(epoch) => {
                        // Remove the engine and abort it.
                        let Some(engine) = engines.remove(&epoch) else {
                            warn!(%epoch, "exited non-existent epoch");
                            continue;
                        };
                        engine.abort();

                        // Unregister the signing scheme for the epoch.
                        assert!(self.provider.unregister(&epoch));

                        info!(%epoch, "exited epoch");
                    }
                }
            },
        }
    }

    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        scheme: S,
        vote_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
        certificate_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
        resolver_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
    ) -> Handle<()> {
        // Start the new engine
        let elector = L::default();
        let engine = simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            simplex::Config {
                scheme,
                elector,
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: self.marshal.clone(),
                partition: format!("{}_consensus_{}", self.partition_prefix, epoch),
                mailbox_size: 1024,
                epoch,
                namespace: self.namespace.clone(),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(256),
                skip_timeout: ViewDelta::new(10),
                fetch_concurrent: 32,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                buffer_pool: self.pool_ref.clone(),
            },
        );

        // Create epoch-specific subchannels
        let vote = vote_mux.register(epoch.get()).await.unwrap();
        let certificate = certificate_mux.register(epoch.get()).await.unwrap();
        let resolver = resolver_mux.register(epoch.get()).await.unwrap();

        engine.start(vote, certificate, resolver)
    }
}
