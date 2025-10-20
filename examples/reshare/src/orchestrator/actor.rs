//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{Block, Scheme, SchemeProvider},
    orchestrator::{Mailbox, Message},
    BLOCKS_PER_EPOCH,
};
use commonware_codec::Encode;
use commonware_consensus::{
    marshal,
    simplex::{
        self,
        types::{Context, Voter},
    },
    types::Epoch,
    utils::last_block_in_epoch,
    Automaton, Relay,
};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::Variant},
    Hasher, Signer,
};
use commonware_macros::select;
use commonware_p2p::{
    utils::mux::{Builder, MuxHandle, Muxer},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_utils::{set::Set, NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, time::Duration};
use tracing::{debug, error, info, warn};

/// Configuration for the orchestrator.
pub struct Config<B, V, C, H, A>
where
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    pub oracle: B,
    pub signer: C,
    pub application: A,
    pub scheme_provider: SchemeProvider<V>,
    pub marshal: marshal::Mailbox<Scheme<V>, Block<H, C, V>>,

    pub namespace: Vec<u8>,
    pub muxer_size: usize,
    pub mailbox_size: usize,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,
}

pub struct Actor<E, B, V, C, H, A>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<V, C::PublicKey>>,
    signer: C,
    application: A,

    oracle: B,
    marshal: marshal::Mailbox<Scheme<V>, Block<H, C, V>>,
    scheme_provider: SchemeProvider<V>,

    namespace: Vec<u8>,
    muxer_size: usize,
    partition_prefix: String,
    pool_ref: PoolRef,
}

impl<E, B, V, C, H, A> Actor<E, B, V, C, H, A>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    pub fn new(context: E, config: Config<B, V, C, H, A>) -> (Self, Mailbox<V, C::PublicKey>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        let pool_ref = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                signer: config.signer,
                application: config.application,
                oracle: config.oracle,
                marshal: config.marshal,
                scheme_provider: config.scheme_provider,
                namespace: config.namespace,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
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
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(pending, recovered, resolver,).await)
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

        // Wait for instructions to transition epochs.
        let mut engines = BTreeMap::new();
        loop {
            select! {
                message = pending_backup.next() => {
                    // If a message is received in an unregistered sub-channel in the recovered or pending network,
                    // attempt to forward the boundary finalization for the epoch.

                    let Some((epoch, (from, _))) = message else {
                        warn!("recovered/pending mux backup channel closed, shutting down orchestrator");
                        break;
                    };
                    let Some(latest_epoch) = engines.keys().last().copied() else {
                        debug!(epoch, ?from, "received message from unregistered epoch with no known epochs");
                        continue;
                    };
                    if epoch as u64 >= latest_epoch {
                        // The sender is operating in a newer epoch or the current, ignore. We cannot block them,
                        // since they may be validly ahead.
                        debug!(epoch, ?from, "received backup message from current or future epoch");
                        continue;
                    }

                    // Fetch the finalization certificate for the last block within the subchannel's epoch.
                    // If the node is state synced, marshal may not have the finalization locally, and the
                    // peer will need to fetch it from another node on the network.
                    let boundary_height = last_block_in_epoch(BLOCKS_PER_EPOCH, epoch as u64);
                    let Some(finalization) = self.marshal.get_finalization(boundary_height).await else {
                        debug!(epoch, ?from, "missing finalization for old epoch");
                        continue;
                    };

                    debug!(
                        epoch,
                        boundary_height,
                        ?from,
                        "received message on recovery/pending network from old epoch. forwarding boundary finalization"
                    );

                    // Forward the finalization to the sender. This operation is best-effort.
                    let message = Voter::<Scheme<V>, H::Digest>::Finalization(finalization);
                    if let Err(err) = recovered_global_sender.send(
                        epoch,
                        Recipients::One(from),
                        message.encode().freeze(),
                        true
                    ).await {
                        error!(?err, "failed to forward boundary finalization to peer - muxer shut down");
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
                                continue;
                            }

                            // Enter the new epoch.
                            let engine = self
                                .enter_epoch(
                                    transition.epoch,
                                    transition.poly,
                                    transition.share,
                                    transition.participants,
                                    &mut pending_mux,
                                    &mut recovered_mux,
                                    &mut resolver_mux,
                                )
                                .await;
                            engines.insert(transition.epoch, engine);

                            info!(transition.epoch, "entered new epoch");
                        }
                        Message::Exit(epoch) => {
                            // Remove all entries with key less than or equal to the requested exit epoch.
                            let epochs_to_remove: Vec<_> = engines
                                .keys()
                                .take_while(|k| **k <= epoch)
                                .copied()
                                .collect();

                            // Abort all engines for the epochs to remove.
                            for epoch in epochs_to_remove {
                                let engine = engines.remove(&epoch).unwrap();
                                engine.abort();

                                // Unregister the signing scheme for the epoch.
                                if !self.scheme_provider.unregister(&epoch) {
                                    warn!(epoch, "unregistered non-existent signing scheme for epoch");
                                }

                                info!(epoch, "exited epoch");
                            }
                        }
                    }
                },
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        polynomial: Public<V>,
        share: Option<group::Share>,
        participants: Set<C::PublicKey>,
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
        let scheme = if let Some(share) = share {
            Scheme::<V>::new(participants.as_ref(), &polynomial, share)
        } else {
            Scheme::<V>::verifier(participants.as_ref(), &polynomial)
        };

        // Register the new signing scheme with the scheme provider
        if !self.scheme_provider.register(epoch, scheme.clone()) {
            warn!(epoch, "registered duplicate signing scheme for epoch");
        }

        let engine = simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            simplex::Config {
                crypto: self.signer.clone(),
                participants,
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
        let pending_sc = pending_mux.register(epoch as u32).await.unwrap();
        let recovered_sc = recovered_mux.register(epoch as u32).await.unwrap();
        let resolver_sc = resolver_mux.register(epoch as u32).await.unwrap();

        engine.start(pending_sc, recovered_sc, resolver_sc)
    }
}
