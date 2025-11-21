//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{Block, EpochSchemeProvider, SchemeProvider},
    orchestrator::{EpochRequest, Mailbox, Message, OrchestratorMessage},
    BLOCKS_PER_EPOCH,
};
use commonware_codec::{Encode, EncodeSize, Read, ReadExt};
use commonware_consensus::{
    marshal,
    simplex::{self, signing_scheme::Scheme, types::Context},
    types::{Epoch, ViewDelta},
    utils::last_block_in_epoch,
    Automaton, Relay,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Hasher, Signer};
use commonware_macros::select;
use commonware_p2p::{
    utils::mux::{Builder, MuxHandle, Muxer},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_utils::{NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota, RateLimiter};
use rand::{CryptoRng, Rng};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

const FINALIZATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for the orchestrator.
pub struct Config<B, V, C, H, A, S>
where
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
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
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
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
    finalization_requests: BTreeMap<Epoch, (C::PublicKey, Instant)>,
}

impl<E, B, V, C, H, A, S> Actor<E, B, V, C, H, A, S>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest, C::PublicKey>, Digest = H::Digest>
        + Relay<Digest = H::Digest>,
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
                finalization_requests: BTreeMap::new(),
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
        let (mux, mut recovered_mux) = Muxer::builder(
            self.context.with_label("recovered_mux"),
            recovered_sender,
            recovered_receiver,
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

        // Wait for instructions to transition epochs.
        let mut engines = BTreeMap::new();
        loop {
            select! {
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

                    if let Entry::Occupied(entry) = self.finalization_requests.entry(our_epoch) {
                        if entry.get().1.elapsed() > FINALIZATION_REQUEST_TIMEOUT {
                            // Previous in-flight request timed out, remove it.
                            entry.remove();
                        } else {
                            // In-flight request exists and is recent.
                            continue;
                        }
                    }

                    // If we're not in the committee of the latest epoch we know about and we observe another
                    // participant that is ahead of us, send a message on the orchestrator channel to prompt
                    // them to send us the finalization of the epoch boundary block for our latest known epoch.
                    if rate_limiter.check_key(&from).is_err() {
                        continue;
                    }
                    let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, our_epoch);
                    if self.marshal.get_finalization(boundary_height).await.is_some() {
                        // Only request the finalization from the peer's orchestrator if we don't already have it.
                        continue;
                    };

                    debug!(
                        %their_epoch,
                        %our_epoch,
                        %boundary_height,
                        ?from,
                        "received backup message from future epoch, requesting boundary finalization"
                    );

                    // Send a request to the peer's orchestrator to get the finalization for our latest epoch.
                    let request =
                        OrchestratorMessage::<S, H::Digest>::Request(EpochRequest { epoch: our_epoch });

                    // Track this request.
                    self.finalization_requests.insert(our_epoch, (from.clone(), Instant::now()));

                    if orchestrator_sender.send(
                        Recipients::One(from),
                        request.encode().freeze(),
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

                    // Peek the discriminant and epoch
                    let mut peek_reader = bytes.as_ref();
                    let discriminant = match <u8>::read(&mut peek_reader) {
                        Ok(d) => d,
                        Err(err) => {
                            debug!(?err, ?from, "failed to decode discriminant from orchestrator message");
                            self.oracle.block(from).await;
                            continue;
                        }
                    };
                    let epoch = match Epoch::read(&mut peek_reader) {
                        Ok(epoch) => epoch,
                        Err(err) => {
                            info!(?err, ?from, "failed to decode epoch from orchestrator message");
                            self.oracle.block(from).await;
                            continue;
                        }
                    };

                    // Decode the message based on discriminant
                    let message = if discriminant == 0 {
                        // Request doesn't need certificate config - just epoch
                        match OrchestratorMessage::<S, H::Digest>::Request(EpochRequest { epoch }) {
                            msg => {
                                // Verify we consumed the right amount of bytes
                                let expected_size = 1 + epoch.encode_size();
                                if bytes.len() != expected_size {
                                    info!(?from, %epoch, actual = bytes.len(), expected = expected_size, "invalid request size");
                                    self.oracle.block(from).await;
                                    continue;
                                }
                                msg
                            }
                        }
                    } else if discriminant == 1 {
                        // Response needs scheme to decode certificate
                        let Some(scheme) = self.scheme_provider.get_certificate_verifier(epoch) else {
                            info!(%epoch, ?from, "no scheme available for epoch");
                            continue;
                        };
                        let certificate_cfg = scheme.certificate_codec_config();

                        match OrchestratorMessage::<S, H::Digest>::read_cfg(
                            &mut bytes.as_ref(),
                            &certificate_cfg,
                        ) {
                            Ok(msg) => msg,
                            Err(err) => {
                                info!(?err, ?from, %epoch, "failed to decode orchestrator response");
                                self.oracle.block(from).await;
                                continue;
                            }
                        }
                    } else {
                        info!(?from, discriminant, "invalid orchestrator message discriminant");
                        self.oracle.block(from).await;
                        continue;
                    };

                    match message {
                        OrchestratorMessage::Request(request) => {
                            info!(
                                epoch = %request.epoch,
                                ?from,
                                "[REQUEST] received orchestrator request for epoch boundary finalization"
                            );

                            // Fetch the finalization certificate for the last block within the epoch.
                            // If the node is state synced, marshal may not have the finalization locally.
                            let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, request.epoch);
                            let Some(finalization) = self.marshal.get_finalization(boundary_height).await else {
                                info!(epoch = %request.epoch, ?from, "[REQUEST] missing finalization for requested epoch");
                                continue;
                            };
                            info!(
                                epoch = %request.epoch,
                                boundary_height,
                                ?from,
                                "[RESPONSE] fetched finalization, sending orchestrator response"
                            );

                            // Send the response back to the requester
                            let response = OrchestratorMessage::Response(crate::orchestrator::EpochResponse {
                                epoch: request.epoch,
                                finalization,
                            });
                            if orchestrator_sender
                                .send(
                                    Recipients::One(from),
                                    response.encode().freeze(),
                                    true,
                                )
                                .await
                                .is_err()
                            {
                                warn!("failed to send orchestrator response, shutting down orchestrator");
                                break;
                            }
                        }
                        OrchestratorMessage::Response(response) => {
                            info!(
                                epoch = %response.epoch,
                                ?from,
                                "[RESPONSE] received orchestrator response with finalization"
                            );

                            // Validate that we actually requested this finalization
                            if !self.finalization_requests.remove(&response.epoch).is_some() { // &(from.clone(), response.epoch)) {
                                info!(%epoch, ?from, "[RESPONSE] received unsolicited finalization response, blocking peer");
                                self.oracle.block(from).await;
                                continue;
                            }
                            info!(epoch = %response.epoch, ?from, "[RESPONSE] validated pending request");

                            // Validate that the finalization's epoch matches what we requested
                            let finalization_epoch = response.finalization.proposal.round.epoch();
                            if finalization_epoch != response.epoch {
                                info!(
                                    requested_epoch = %response.epoch,
                                    finalization_epoch = %finalization_epoch,
                                    ?from,
                                    "[RESPONSE] received finalization for wrong epoch, blocking peer"
                                );
                                self.oracle.block(from).await;
                                continue;
                            }
                            info!(epoch = %response.epoch, ?from, "[RESPONSE] validated finalization epoch matches");

                            // Look up the scheme to verify the certificate
                            let Some(scheme) = self.scheme_provider.get_certificate_verifier(response.epoch) else {
                                info!(epoch = %response.epoch, ?from, "[RESPONSE] no scheme available to verify certificate");
                                continue;
                            };

                            // Verify the certificate
                            info!(epoch = %response.epoch, ?from, "[RESPONSE] verifying certificate");
                            if !response.finalization.verify(
                                &mut self.context,
                                &scheme,
                                &self.namespace,
                            ) {
                                info!(
                                    epoch = %response.epoch,
                                    ?from,
                                    "[RESPONSE] received finalization with invalid certificate, blocking peer"
                                );
                                self.oracle.block(from).await;
                                continue;
                            }

                            info!(
                                epoch = %response.epoch,
                                ?from,
                                "[RESPONSE] certificate verified, injecting finalization into marshal"
                            );

                            // Inject the finalization directly into marshal
                            self.marshal.finalization(response.finalization).await;

                            info!(epoch = %response.epoch, ?from, "[RESPONSE] finalization injected into marshal");
                        }
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
                        Message::Exit(epoch) => {
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
