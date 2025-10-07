use std::time::Duration;

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
    bls12381::primitives::{group, poly::Public, variant::MinSig},
    Hasher, PrivateKey,
};
use commonware_p2p::{
    authenticated::discovery::Oracle,
    utils::mux::{MuxHandle, Muxer},
    Receiver, Sender,
};
use commonware_runtime::{buffer::PoolRef, tokio, Handle, Metrics, Spawner};
use commonware_utils::{NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::Quota;

/// Configuration for the orchestrator.
pub struct Config<C, H, A>
where
    C: PrivateKey,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    pub oracle: Oracle<C::PublicKey>,
    pub signer: C,
    pub application: A,
    pub marshal: marshal::Mailbox<MinSig, Block<H, C, MinSig>>,

    pub namespace: Vec<u8>,
    pub validators: Vec<C::PublicKey>,
    pub muxer_size: usize,
    pub mailbox_size: usize,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,
}

pub struct Actor<C, H, A>
where
    C: PrivateKey,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    context: tokio::Context,
    mailbox: mpsc::Receiver<EpochTransition<H>>,
    signer: C,
    application: A,

    oracle: Oracle<C::PublicKey>,
    marshal: marshal::Mailbox<MinSig, Block<H, C, MinSig>>,

    namespace: Vec<u8>,
    validators: Vec<C::PublicKey>,
    muxer_size: usize,
    partition_prefix: String,

    epoch: Epoch,
    engine: Option<Handle<()>>,
}

impl<C, H, A> Actor<C, H, A>
where
    C: PrivateKey,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest> + Relay<Digest = H::Digest>,
{
    pub fn new(context: tokio::Context, config: Config<C, H, A>) -> (Self, Mailbox<H>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);

        (
            Self {
                context,
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
        initial_poly: Public<MinSig>,
        initial_share: group::Share,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(
            pending,
            recovered,
            resolver,
            initial_poly,
            initial_share,
        ))
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
        initial_poly: Public<MinSig>,
        initial_share: group::Share,
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

        // Register all possible validators
        self.oracle.register(0, self.validators.clone()).await;

        // Enter the initial epoch
        // TODO: Recover from metadata on restarts.
        self.enter_epoch(
            0,
            H::empty(),
            initial_poly,
            initial_share,
            &mut pending_mux,
            &mut recovered_mux,
            &mut resolver_mux,
        )
        .await;

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
                &mut pending_mux,
                &mut recovered_mux,
                &mut resolver_mux,
            )
            .await;
        }
    }

    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        _: H::Digest,
        polynomial: Public<MinSig>,
        share: group::Share,
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
        // TODO: Persist metadata; not restart-resistant yet.
        self.epoch = epoch;

        // Stop the previous consensus engine, if there is one.
        if let Some(engine) = self.engine.take() {
            engine.abort();
        }

        let supervisor = Supervisor::new(polynomial, self.validators.clone(), share);
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

        tracing::info!(epoch, "ENTERED NEW EPOCH 🚨");
    }
}
