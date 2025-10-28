//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{Block, EpochSchemeProvider, SchemeProvider},
    orchestrator::{Mailbox, Message},
    BLOCKS_PER_EPOCH,
};
use commonware_codec::{varint::UInt, DecodeExt, Encode};
use commonware_consensus::{
    marshal,
    simplex::{
        self,
        signing_scheme::Scheme,
        types::{Context, Voter},
    },
    types::Epoch,
    utils::last_block_in_epoch,
    Automaton, Relay,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Hasher, Signer};
use commonware_macros::select;
use commonware_p2p::{
    utils::mux::{Builder, GlobalSender, MuxHandle, Muxer},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_utils::{NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota, RateLimiter};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, time::Duration};
use tracing::{debug, info, warn};

/// Configuration for the orchestrator.
pub struct Config<B, V, C, H, A, S>
where
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
    S: Scheme,
{
    pub oracle: B,
    pub application: A,
    pub scheme_provider: SchemeProvider<S, C>,
    pub marshal: marshal::Mailbox<S, Block<H, C, V>>,

    pub namespace: Vec<u8>,
    pub muxer_size: usize,
    pub mailbox_size: usize,
    pub rate_limit: governor::Quota,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,
}

pub struct Actor<E, B, V, C, H, A, S>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
    S: Scheme,
    SchemeProvider<S, C>: EpochSchemeProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<V, C::PublicKey>>,
    application: A,

    oracle: B,
    marshal: marshal::Mailbox<S, Block<H, C, V>>,
    scheme_provider: SchemeProvider<S, C>,

    namespace: Vec<u8>,
    muxer_size: usize,
    partition_prefix: String,
    rate_limit: governor::Quota,
    pool_ref: PoolRef,
}

impl<E, B, V, C, H, A, S> Actor<E, B, V, C, H, A, S>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
    S: Scheme<PublicKey = C::PublicKey>,
    SchemeProvider<S, C>: EpochSchemeProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    pub fn new(context: E, config: Config<B, V, C, H, A, S>) -> (Self, Mailbox<V, C::PublicKey>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        let pool_ref = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                application: config.application,
                oracle: config.oracle,
                marshal: config.marshal,
                scheme_provider: config.scheme_provider,
                namespace: config.namespace,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
                rate_limit: config.rate_limit,
                pool_ref,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        pending: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        recovered: (
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
            self.run(pending, recovered, resolver, orchestrator).await
        )
    }

    async fn run(
        mut self,
        (pending_sender, pending_receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        (recovered_sender, recovered_receiver): (
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
        let (mux, mut pending_mux, mut pending_backup) = Muxer::builder(
            self.context.with_label("pending_mux"),
            pending_sender,
            pending_receiver,
            self.muxer_size,
        )
        .with_backup()
        .build();
        mux.start();
        let (mux, mut recovered_mux, mut recovered_global_sender) = Muxer::builder(
            self.context.with_label("recovered_mux"),
            recovered_sender,
            recovered_receiver,
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

        // Create rate limiter for boundary finalizations
        let rate_limiter = RateLimiter::hashmap_with_clock(self.rate_limit, &self.context);

        // Wait for instructions to transition epochs.
        let mut engines = BTreeMap::new();
        loop {
            select! {
                message = pending_backup.next() => {
                    // If a message is received in an unregistered sub-channel in the pending network,
                    // attempt to forward the boundary finalization for the epoch.
                    let Some((their_epoch, (from, _))) = message else {
                        warn!("pending mux backup channel closed, shutting down orchestrator");
                        break;
                    };
                    let Some(our_epoch) = engines.keys().last().copied() else {
                        debug!(their_epoch, ?from, "received message from unregistered epoch with no known epochs");
                        continue;
                    };
                    if their_epoch <= our_epoch {
                        debug!(their_epoch, our_epoch, ?from, "received message from past epoch");
                        continue;
                    }

                    // If we're not in the committee of the latest epoch we know about and we observe another
                    // participant that is ahead of us, send a message on the global pending channel to prompt
                    // them to send us the finalization of the epoch boundary block for our latest known epoch.
                    // If we do not directly ask, we will never receive the finalization, since our consensus engine
                    // may never send messages over the pending channel for that epoch.
                    if rate_limiter.check_key(&from).is_err() {
                        continue;
                    }
                    let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, our_epoch);
                    if self.marshal.get_finalization(boundary_height).await.is_some() {
                        // Only request the boundary finalization if we don't already have it.
                        continue;
                    };
                    debug!(
                        their_epoch,
                        ?from,
                        "received backup message from future epoch, requesting boundary finalization"
                    );

                    let _ = orchestrator_sender.send(
                        Recipients::One(from),
                        UInt(our_epoch).encode().freeze(),
                        true
                    ).await;
                },
                message = orchestrator_receiver.recv() => {
                    let Ok((from, bytes)) = message else {
                        warn!("boundary finalization channel closed, shutting down orchestrator");
                        break;
                    };
                    let epoch = match UInt::<Epoch>::decode(bytes.as_ref()) {
                        Ok(epoch) => epoch,
                        Err(err) => {
                            debug!(?err, ?from, "failed to decode epoch from boundary finalization request");
                            self.oracle.block(from).await;
                            continue;
                        }
                    };
                    Self::forward_finalization(
                        from,
                        epoch.0,
                        &mut self.marshal,
                        &mut recovered_global_sender,
                    ).await;
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
                                warn!(epoch = transition.epoch, "entered existing epoch");
                                continue;
                            }

                            // Register the new signing scheme with the scheme provider.
                            let scheme = self.scheme_provider.scheme_for_epoch(&transition);
                            assert!(self.scheme_provider.register(transition.epoch, scheme.clone()));

                            // Enter the new epoch.
                            let engine = self
                                .enter_epoch(
                                    transition.epoch,
                                    scheme,
                                    &mut pending_mux,
                                    &mut recovered_mux,
                                    &mut resolver_mux,
                                )
                                .await;
                            engines.insert(transition.epoch, engine);

                            info!(epoch = transition.epoch, "entered epoch");
                        }
                        Message::Exit(epoch) => {
                            // Remove the engine and abort it.
                            let Some(engine) = engines.remove(&epoch) else {
                                warn!(epoch, "exited non-existent epoch");
                                continue;
                            };
                            engine.abort();

                            // Unregister the signing scheme for the epoch.
                            assert!(self.scheme_provider.unregister(&epoch));

                            info!(epoch, "exited epoch");
                        }
                    }
                },
            }
        }
    }

    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        scheme: S,
        pending_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
        recovered_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
        resolver_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
    ) -> Handle<()> {
        // Start the new engine
        let engine = simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            simplex::Config {
                scheme,
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
                activity_timeout: 10,
                skip_timeout: 5,
                max_fetch_count: 32,
                fetch_concurrent: 2,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                buffer_pool: self.pool_ref.clone(),
            },
        );

        // Create epoch-specific subchannels
        let pending_sc = pending_mux.register(epoch).await.unwrap();
        let recovered_sc = recovered_mux.register(epoch).await.unwrap();
        let resolver_sc = resolver_mux.register(epoch).await.unwrap();

        engine.start(pending_sc, recovered_sc, resolver_sc)
    }

    /// Fetches a finalization certificate from the boundary block of the given epoch and forwards it to
    /// the given [GlobalSender].
    ///
    /// If the message fails to be sent, `None` is returned to indicate that the orchestrator should shut down.
    async fn forward_finalization(
        from: C::PublicKey,
        epoch: Epoch,
        marshal: &mut marshal::Mailbox<S, Block<H, C, V>>,
        recovered_global_sender: &mut GlobalSender<impl Sender<PublicKey = C::PublicKey>>,
    ) {
        // Fetch the finalization certificate for the last block within the subchannel's epoch.
        // If the node is state synced, marshal may not have the finalization locally, and the
        // peer will need to fetch it from another node on the network.
        let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, epoch);
        let Some(finalization) = marshal.get_finalization(boundary_height).await else {
            debug!(epoch, ?from, "missing finalization for old epoch");
            return;
        };
        debug!(
            epoch,
            boundary_height,
            ?from,
            "received message on pending network from old epoch. forwarding boundary finalization"
        );

        // Forward the finalization to the sender. This operation is best-effort.
        let message = Voter::<S, H::Digest>::Finalization(finalization);
        let _ = recovered_global_sender
            .send(
                epoch,
                Recipients::One(from),
                message.encode().freeze(),
                false,
            )
            .await;
    }
}
