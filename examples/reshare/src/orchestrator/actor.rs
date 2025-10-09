//! Consensus engine orchestrator for epoch transitions.

use crate::{
    application::{genesis_block, Block, Supervisor},
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
    Committable, Hasher, PrivateKey,
};
use commonware_p2p::{
    authenticated::discovery::Oracle,
    utils::mux::{MuxHandle, Muxer},
    Receiver, Sender,
};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, tokio, ContextCell, Handle, Metrics, Spawner,
};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::Quota;
use std::time::Duration;
use tracing::info;

const METADATA_KEY: FixedBytes<1> = FixedBytes::new([0u8]);

/// Configuration for the orchestrator.
pub struct Config<V, C, H, A>
where
    V: Variant,
    C: PrivateKey,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    pub oracle: Oracle<C::PublicKey>,
    pub signer: C,
    pub application: A,
    pub marshal: marshal::Mailbox<V, Block<H, C, V>>,

    pub namespace: Vec<u8>,
    pub validators: Vec<C::PublicKey>,
    pub muxer_size: usize,
    pub mailbox_size: usize,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,
}

pub struct Actor<V, C, H, A>
where
    V: Variant,
    C: PrivateKey,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    context: ContextCell<tokio::Context>,
    mailbox: mpsc::Receiver<EpochTransition<V, H, C::PublicKey>>,
    signer: C,
    application: A,

    oracle: Oracle<C::PublicKey>,
    marshal: marshal::Mailbox<V, Block<H, C, V>>,

    namespace: Vec<u8>,
    validators: Vec<C::PublicKey>,
    muxer_size: usize,
    partition_prefix: String,

    epoch: Epoch,
    engine: Option<Handle<()>>,
}

impl<V, C, H, A> Actor<V, C, H, A>
where
    V: Variant,
    C: PrivateKey,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    pub fn new(
        context: tokio::Context,
        config: Config<V, C, H, A>,
    ) -> (Self, Mailbox<V, H, C::PublicKey>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                signer: config.signer,
                application: config.application,
                oracle: config.oracle,
                marshal: config.marshal,
                namespace: config.namespace,
                validators: config.validators,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
                epoch: 0,
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
        initial_participants: Vec<C::PublicKey>,
        initial_poly: Public<V>,
        initial_share: Option<group::Share>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                pending,
                recovered,
                resolver,
                initial_participants,
                initial_poly,
                initial_share
            )
            .await
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
        initial_participants: Vec<C::PublicKey>,
        initial_poly: Public<V>,
        initial_share: Option<group::Share>,
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

        let mut metadata = Metadata::init(
            self.context.with_label("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", self.partition_prefix),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize orchestrator metadata");

        // Register all possible validators
        self.oracle.register(0, self.validators.clone()).await;

        // Enter the initial epoch
        let (initial_epoch, initial_seed) = metadata
            .get(&METADATA_KEY)
            .cloned()
            .unwrap_or((0, genesis_block::<H, C, V>().commitment()));
        self.enter_epoch(
            initial_epoch,
            initial_seed,
            initial_poly,
            initial_share,
            initial_participants,
            &mut metadata,
            &mut pending_mux,
            &mut recovered_mux,
            &mut resolver_mux,
        )
        .await;

        // Wait for instructions to transition epochs.
        while let Some(transition) = self.mailbox.next().await {
            if transition.epoch <= self.epoch {
                continue;
            }

            // Enter the new epoch.
            self.enter_epoch(
                transition.epoch,
                transition.seed,
                transition.poly,
                transition.share,
                transition.participants,
                &mut metadata,
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
        seed: H::Digest,
        polynomial: Public<V>,
        share: Option<group::Share>,
        participants: Vec<C::PublicKey>,
        metadata: &mut Metadata<ContextCell<tokio::Context>, FixedBytes<1>, (Epoch, H::Digest)>,
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
        let _ = metadata.put_sync(METADATA_KEY, (epoch, seed)).await;
        self.epoch = epoch;

        // Stop the previous consensus engine, if there is one.
        if let Some(engine) = self.engine.take() {
            engine.abort();
        }

        let supervisor = Supervisor::<V, C::PublicKey>::new(polynomial, participants, share);
        let engine = threshold_simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            threshold_simplex::Config {
                crypto: self.signer.clone(),
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: self.marshal.clone(),
                supervisor,
                partition: format!("consensus_{}_{}", self.signer.public_key(), epoch),
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
                buffer_pool: PoolRef::new(NZUsize!(16_384), NZUsize!(10_000)),
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
