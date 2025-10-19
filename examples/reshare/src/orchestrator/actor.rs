//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{Block, Scheme, SchemeProvider},
    orchestrator::{Mailbox, Message},
};
use commonware_consensus::{
    marshal,
    simplex::{self, signing_scheme::Scheme as _, types::Context},
    types::Epoch,
    Automaton, Relay,
};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::Variant},
    Hasher, Signer,
};
use commonware_p2p::{
    utils::mux::{MuxHandle, Muxer},
    Blocker, Receiver, Sender,
};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_utils::{set::Set, NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, time::Duration};
use tracing::{info, warn};

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
        let (mux, mut pending_mux) = Muxer::new(
            self.context.with_label("pending_mux"),
            pending_sender,
            pending_receiver,
            self.muxer_size,
        );
        mux.start();
        let (mux, mut recovered_mux) = Muxer::new(
            self.context.with_label("recovered_mux"),
            recovered_sender,
            recovered_receiver,
            self.muxer_size,
        );
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
        while let Some(transition) = self.mailbox.next().await {
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
