//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{Block, EpochSchemeProvider, SchemeProvider},
    orchestrator::{finalization_tracker::FinalizationTracker, ingress, wire, Mailbox},
    BLOCKS_PER_EPOCH,
};
use commonware_codec::Encode;
use commonware_consensus::{
    marshal,
    simplex::{self, signing_scheme::Scheme, types::Context},
    types::{Epoch, ViewDelta},
    utils::last_block_in_epoch,
    Automaton, Relay,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Hasher, Signer};
use commonware_macros::select_loop;
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
use std::{collections::BTreeMap, time::Duration};
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
    mailbox: mpsc::Receiver<ingress::Message<V, C::PublicKey>>,
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

        // Create finalization tracker for managing epoch boundary finalization requests
        let (mut finalization_tracker, mut tracker_events) = FinalizationTracker::new(
            self.context.with_label("finalization_tracker"),
            FINALIZATION_REQUEST_TIMEOUT,
        );

        // Wait for instructions to transition epochs.
        let mut engines = BTreeMap::new();
        select_loop! {
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

                // Try to queue a request for this peer. Returns false if a request is
                // already in-flight (peer is queued for later) or if the peer is a duplicate.
                if !finalization_tracker.try_request(our_epoch, from.clone()) {
                    continue;
                }

                debug!(
                    %their_epoch,
                    %our_epoch,
                    %boundary_height,
                    ?from,
                    "received backup message from future epoch, requesting boundary finalization"
                );

                // Send a request to the peer's orchestrator to get the finalization for our latest epoch.
                let request = wire::Message::<S, H::Digest>::Request(our_epoch);

                if orchestrator_sender
                    .send(Recipients::One(from.clone()), request.encode().freeze(), true)
                    .await
                    .is_err()
                {
                    warn!("failed to send orchestrator request, shutting down orchestrator");
                    break;
                }

                // Mark the request as sent
                finalization_tracker.mark_sent(our_epoch, from);
            },
            message = orchestrator_receiver.recv() => {
                let Ok((from, bytes)) = message else {
                    warn!("orchestrator channel closed, shutting down orchestrator");
                    break;
                };

                // Decode the orchestrator wire message
                let message = match wire::Message::<S, H::Digest>::read_staged(
                    &mut bytes.as_ref(),
                    &self.scheme_provider,
                ) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        debug!(?from, "no scheme available to decode response");
                        continue;
                    }
                    Err(err) => {
                        debug!(?err, ?from, "received malformed response, blocking peer");
                        self.oracle.block(from).await;
                        continue;
                    }
                };

                match message {
                    wire::Message::Request(epoch) => {
                        let Some(our_epoch) = engines.keys().last().copied() else {
                            debug!(%epoch, ?from, "received orchestrator request with no known epochs");
                            continue;
                        };

                        // A peer should never request finalization for an epoch we don't know about.
                        // If they're asking for a future epoch, they're either buggy or malicious.
                        if epoch > our_epoch {
                            debug!(%epoch, %our_epoch, ?from, "received orchestrator request for future epoch, blocking peer");
                            self.oracle.block(from).await;
                            continue;
                        }

                        // Fetch the finalization certificate for the last block within the epoch.
                        // If the node is state synced, marshal may not have the finalization locally, and the
                        // peer will need to fetch it from another node on the network.
                        let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, epoch);
                        let Some(finalization) = self.marshal.get_finalization(boundary_height).await else {
                            debug!(%epoch, ?from, "missing finalization for requested epoch");
                            continue;
                        };

                        debug!(
                            %epoch,
                            boundary_height,
                            ?from,
                            "sending finalization to orchestrator"
                        );

                        // Send the response back to the peer
                        let response = wire::Message::Response(epoch, finalization);
                        if orchestrator_sender
                            .send(Recipients::One(from), response.encode().freeze(), true)
                            .await
                            .is_err()
                        {
                            warn!("failed to send orchestrator response, shutting down orchestrator");
                            break;
                        }
                    }
                    wire::Message::Response(epoch, finalization) => {
                        // Check if we have a pending request for this finalization. We
                        // don't block on mismatches since they can occur when responses
                        // arrive after the request timed out and we moved on to a
                        // different peer.
                        //
                        // If successful, this also cancels the timeout for this request.
                        if !finalization_tracker.handle_response(epoch, &from) {
                            debug!(
                                %epoch,
                                ?from,
                                "received finalization with no matching request, ignoring"
                            );
                            continue;
                        }

                        // Look up the scheme to verify the certificate
                        let Some(scheme) = self.scheme_provider.get_certificate_verifier(epoch) else {
                            debug!(%epoch, ?from, "no scheme available to verify certificate");
                            continue;
                        };

                        // Verify the certificate
                        if !finalization.verify(
                            &mut self.context,
                            &scheme,
                            &self.namespace,
                        ) {
                            debug!(
                                %epoch,
                                ?from,
                                "received finalization with invalid certificate, blocking peer"
                            );
                            self.oracle.block(from).await;
                            continue;
                        }

                        debug!(
                            %epoch,
                            ?from,
                            "verified requested finalization certificate, injecting finalization into marshal"
                        );

                        self.marshal.finalization(finalization).await;
                        finalization_tracker.clear();
                    }
                }
            },
            transition = self.mailbox.next() => {
                let Some(transition) = transition else {
                    warn!("mailbox closed, shutting down orchestrator");
                    break;
                };

                match transition {
                    ingress::Message::Enter(transition) => {
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
                    ingress::Message::Exit(epoch) => {
                        // Clean up finalization tracker state (cancels any pending timeout).
                        finalization_tracker.clear();

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
            epoch = tracker_events.next() => {
                // Timeout fired - try next peer
                let Some(epoch) = epoch else {
                    warn!("finalization tracker closed, shutting down orchestrator");
                    break;
                };

                // Check if we're still tracking this epoch (cleared if finalization received)
                if !finalization_tracker.is_tracking(epoch) {
                    continue;
                }

                // Get the next peer to try
                let Some(peer) = finalization_tracker.next_peer() else {
                    debug!(%epoch, "finalization request timed out but no more peers to try");
                    continue;
                };

                debug!(%epoch, ?peer, "retrying finalization request after timeout");

                // Send request to next peer
                let request = wire::Message::<S, H::Digest>::Request(epoch);

                if orchestrator_sender
                    .send(Recipients::One(peer.clone()), request.encode().freeze(), true)
                    .await
                    .is_err()
                {
                    warn!("failed to send orchestrator request, shutting down orchestrator");
                    break;
                }

                finalization_tracker.mark_sent(epoch, peer);
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
