//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{Block, EpochSchemeProvider, SchemeProvider},
    orchestrator::ingress::{
        handler::{self, Handler},
        mailbox::{self, Mailbox},
    },
    BLOCKS_PER_EPOCH,
};
use commonware_codec::{Encode, Read as _};
use commonware_consensus::{
    marshal,
    simplex::{
        self,
        signing_scheme::Scheme,
        types::{Context, Finalization},
    },
    types::{Epoch, ViewDelta},
    utils::last_block_in_epoch,
    Automaton, Epochable, Relay,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Hasher, Signer};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::{
        mux::{Builder, MuxHandle, Muxer},
        requester,
    },
    Blocker, Manager, Receiver, Sender,
};
use commonware_resolver::{p2p as resolver_p2p, Resolver};
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
pub struct Config<B, M, V, C, H, A, S>
where
    B: Blocker<PublicKey = C::PublicKey>,
    M: Manager<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
    S: Scheme,
{
    pub oracle: B,
    pub manager: M,
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

pub struct Actor<E, B, M, V, C, H, A, S>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    M: Manager<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
    S: Scheme,
    SchemeProvider<S, C>: EpochSchemeProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<mailbox::Message<V, C::PublicKey>>,
    application: A,

    oracle: B,
    manager: M,
    marshal: marshal::Mailbox<S, Block<H, C, V>>,
    scheme_provider: SchemeProvider<S, C>,

    namespace: Vec<u8>,
    muxer_size: usize,
    partition_prefix: String,
    rate_limit: governor::Quota,
    pool_ref: PoolRef,
}

impl<E, B, M, V, C, H, A, S> Actor<E, B, M, V, C, H, A, S>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    M: Manager<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
    S: Scheme<PublicKey = C::PublicKey>,
    SchemeProvider<S, C>: EpochSchemeProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    pub fn new(
        context: E,
        config: Config<B, M, V, C, H, A, S>,
    ) -> (Self, Mailbox<V, C::PublicKey>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        let pool_ref = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                application: config.application,
                oracle: config.oracle,
                manager: config.manager,
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
        orchestrator: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        // Start muxers for each physical channel used by consensus
        let (mux, mut pending_mux, mut pending_backup) = Muxer::builder(
            self.context.with_label("pending_mux"),
            vote_sender,
            vote_receiver,
            self.muxer_size,
        )
        .with_backup()
        .build();
        mux.start();
        let (mux, mut recovered_mux) = Muxer::builder(
            self.context.with_label("recovered_mux"),
            certificate_sender,
            certificate_receiver,
            self.muxer_size,
        )
        .build();
        mux.start();
        let (mux, mut resolver_mux) = Muxer::new(
            self.context.with_label("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.muxer_size,
        );
        mux.start();

        // Create rate limiter for orchestrators
        let rate_limiter = RateLimiter::hashmap_with_clock(self.rate_limit, self.context.clone());

        // Create handler channel for finalization requests
        let (handler_tx, mut handler_rx) = mpsc::channel(16);
        let handler = Handler::new(handler_tx);

        // Create resolver engine for finalization fetching
        let (resolver_engine, mut finalization_resolver) = resolver_p2p::Engine::new(
            self.context.with_label("finalization_resolver"),
            resolver_p2p::Config {
                manager: self.manager.clone(),
                blocker: self.oracle.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: 16,
                requester_config: requester::Config {
                    me: None,
                    rate_limit: Quota::per_second(NZU32!(5)),
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(5),
                },
                fetch_retry_timeout: Duration::from_millis(500),
                priority_requests: true,
                priority_responses: true,
            },
        );
        resolver_engine.start(orchestrator);

        // Track the current epoch we're fetching finalization for
        let mut fetching_epoch: Option<Epoch> = None;

        // Wait for instructions to transition epochs.
        let mut engines = BTreeMap::new();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping orchestrator");
            },
            message = pending_backup.next() => {
                // If a message is received in an unregistered sub-channel in the pending network,
                // attempt to forward the orchestrator for the epoch.
                let Some((their_epoch, (from, _))) = message else {
                    warn!("pending mux backup channel closed, shutting down orchestrator");
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
                if rate_limiter.check_key(&from).is_err() {
                    continue;
                }

                // Check if we already have the finalization before trying to issue a request.
                let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, our_epoch);
                if self.marshal.get_finalization(boundary_height).await.is_some() {
                    continue;
                }

                debug!(
                    %their_epoch,
                    %our_epoch,
                    %boundary_height,
                    ?from,
                    "received backup message from future epoch, requesting boundary finalization"
                );

                // Add the peer as a target for this epoch's finalization
                // fetch_targeted adds to existing targets if already in progress
                if fetching_epoch != Some(our_epoch) {
                    fetching_epoch = Some(our_epoch);
                }
                finalization_resolver.fetch_targeted(our_epoch, vec![from]).await;
            },
            handler_message = handler_rx.next() => {
                let Some(message) = handler_message else {
                    warn!("handler channel closed, shutting down orchestrator");
                    break;
                };

                match message {
                    handler::Message::Deliver { epoch, value, response } => {
                        // Look up the scheme to decode and verify the certificate
                        let Some(scheme) = self.scheme_provider.get_certificate_verifier(epoch) else {
                            debug!(%epoch, "no scheme available for epoch");
                            let _ = response.send(false);
                            continue;
                        };

                        // Decode the finalization
                        let finalization = match Finalization::<S, H::Digest>::read_cfg(
                            &mut value.as_ref(),
                            &scheme.certificate_codec_config(),
                        ) {
                            Ok(f) => f,
                            Err(err) => {
                                debug!(?err, %epoch, "failed to decode finalization");
                                let _ = response.send(false);
                                continue;
                            }
                        };

                        // Verify epoch matches
                        if finalization.epoch() != epoch {
                            debug!(%epoch, actual = %finalization.epoch(), "epoch mismatch in finalization");
                            let _ = response.send(false);
                            continue;
                        }

                        // Verify the certificate
                        if !finalization.verify(&mut self.context, &scheme, &self.namespace) {
                            debug!(%epoch, "finalization certificate verification failed");
                            let _ = response.send(false);
                            continue;
                        }

                        debug!(%epoch, "verified requested finalization certificate, injecting into marshal");
                        let _ = response.send(true);

                        // Inject finalization into marshal and clear fetch state
                        self.marshal.finalization(finalization).await;
                        fetching_epoch = None;
                        finalization_resolver.clear().await;
                    }
                    handler::Message::Produce { epoch, response } => {
                        // Look up the finalization for this epoch
                        let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, epoch);
                        match self.marshal.get_finalization(boundary_height).await {
                            Some(finalization) => {
                                debug!(%epoch, "serving finalization");
                                let _ = response.send(finalization.encode().freeze());
                            }
                            None => {
                                debug!(%epoch, "missing finalization for requested epoch");
                                // Don't send anything - resolver will handle as error
                                drop(response);
                            }
                        }
                    }
                }
            },
            transition = self.mailbox.next() => {
                let Some(transition) = transition else {
                    warn!("mailbox closed, shutting down orchestrator");
                    break;
                };

                match transition {
                    mailbox::Message::Enter(transition) => {
                        // If the epoch is already in the map, ignore.
                        if engines.contains_key(&transition.epoch) {
                            warn!(epoch = %transition.epoch, "entered existing epoch");
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

                        info!(epoch = %transition.epoch, "entered epoch");
                    }
                    mailbox::Message::Exit(epoch) => {
                        // Clean up resolver state
                        fetching_epoch = None;
                        finalization_resolver.clear().await;

                        // Remove the engine and abort it.
                        let Some(engine) = engines.remove(&epoch) else {
                            warn!(%epoch, "exited non-existent epoch");
                            continue;
                        };
                        engine.abort();

                        // Unregister the signing scheme for the epoch.
                        assert!(self.scheme_provider.unregister(&epoch));

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
                activity_timeout: ViewDelta::new(256),
                skip_timeout: ViewDelta::new(10),
                fetch_concurrent: 32,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                buffer_pool: self.pool_ref.clone(),
            },
        );

        // Create epoch-specific subchannels
        let pending_sc = pending_mux.register(epoch.get()).await.unwrap();
        let recovered_sc = recovered_mux.register(epoch.get()).await.unwrap();
        let resolver_sc = resolver_mux.register(epoch.get()).await.unwrap();

        engine.start(pending_sc, recovered_sc, resolver_sc)
    }
}
