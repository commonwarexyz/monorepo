//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{Block, Supervisor},
    orchestrator::{ingress::EpochTransition, Mailbox},
};
use commonware_consensus::{
    marshal,
    threshold_simplex::{self, types::Context},
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
use std::time::Duration;
use tracing::info;

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
    pub marshal: marshal::Mailbox<V, Block<H, C, V>>,

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
    mailbox: mpsc::Receiver<EpochTransition<V, C::PublicKey>>,
    signer: C,
    application: A,

    oracle: B,
    marshal: marshal::Mailbox<V, Block<H, C, V>>,

    namespace: Vec<u8>,
    muxer_size: usize,
    partition_prefix: String,
    pool_ref: PoolRef,

    engine: Option<Handle<()>>,
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
                namespace: config.namespace,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
                pool_ref,
                engine: None,
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
        let mut current_epoch = None;
        while let Some(transition) = self.mailbox.next().await {
            if current_epoch.is_some_and(|epoch| transition.epoch <= epoch) {
                continue;
            }
            current_epoch = Some(transition.epoch);

            // Enter the new epoch.
            self.enter_epoch(
                transition.epoch,
                transition.poly,
                transition.share,
                transition.participants,
                &mut pending_mux,
                &mut recovered_mux,
                &mut resolver_mux,
            )
            .await;
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
    ) {
        // Stop the previous consensus engine, if there is one.
        if let Some(engine) = self.engine.take() {
            engine.abort();
        }

        // Start the new engine
        let supervisor = Supervisor::<V, C::PublicKey>::new(polynomial, participants.into(), share);
        let engine = threshold_simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            threshold_simplex::Config {
                crypto: self.signer.clone(),
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: self.marshal.clone(),
                supervisor,
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

        let engine_handle = engine.start(pending_sc, recovered_sc, resolver_sc);
        self.engine = Some(engine_handle);

        info!(epoch, "entered new epoch");
    }
}
