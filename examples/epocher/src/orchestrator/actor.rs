use super::{Config, Mailbox, Message};
use crate::types::block::Block;
use commonware_consensus::{
    marshal,
    threshold_simplex::{self, types::Context},
    types::{Epoch, View},
    Automaton, Relay, ThresholdSupervisor,
};
use commonware_cryptography::{
    bls12381::primitives::{group, variant::Variant},
    sha256, Signer,
};
use commonware_p2p::{
    authenticated::discovery::Oracle,
    utils::mux::{MuxHandle, Muxer},
    Receiver, Sender,
};
use commonware_runtime::{buffer::PoolRef, Clock, Handle, Metrics, Spawner, Storage};
use commonware_utils::{NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use rand::{CryptoRng, Rng};
use std::time::Duration;

type D = sha256::Digest;

/// Orchestrator actor.
pub struct Orchestrator<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    C: Signer,
    V: Variant,
    A: Automaton<Context = Context<D>, Digest = D, Epoch = Epoch> + Relay<Digest = D>,
    S: ThresholdSupervisor<
        Index = View,
        PublicKey = C::PublicKey,
        Identity = V::Public,
        Seed = V::Signature,
        Polynomial = Vec<V::Public>,
        Share = group::Share,
    >,
> {
    context: E,
    signer: C,
    application: A,
    supervisor: S,
    oracle: Oracle<E, C::PublicKey>,
    marshal: marshal::Mailbox<V, Block>,

    mailbox: mpsc::Receiver<Message>,

    // Configuration
    namespace: Vec<u8>,
    validators: Vec<C::PublicKey>,
    muxer_size: usize,

    // State
    epoch: Epoch,
    consensus_engine: Option<Handle<()>>,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
        C: Signer,
        V: Variant,
        A: Automaton<Context = Context<D>, Digest = D, Epoch = Epoch> + Relay<Digest = D>,
        S: ThresholdSupervisor<
            Index = View,
            PublicKey = C::PublicKey,
            Identity = V::Public,
            Seed = V::Signature,
            Polynomial = Vec<V::Public>,
            Share = group::Share,
        >,
    > Orchestrator<E, C, V, A, S>
{
    pub fn new(context: E, cfg: Config<E, C, V, A, S>) -> (Self, Mailbox) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                signer: cfg.signer,
                application: cfg.application,
                supervisor: cfg.supervisor,
                oracle: cfg.oracle,
                marshal: cfg.marshal,

                mailbox: rx,
                namespace: cfg.namespace,
                validators: cfg.validators,
                muxer_size: cfg.muxer_size,

                epoch: 0,
                consensus_engine: None,
            },
            Mailbox::new(tx),
        )
    }

    pub fn start(
        mut self,
        p: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        rc: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        rs: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(p, rc, rs))
    }

    pub async fn run(
        mut self,
        (p_s, p_r): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        (rc_s, rc_r): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        (rs_s, rs_r): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        // Start muxers for each physical channel used by consensus
        let (mux, mut p_mux) = Muxer::new(
            self.context.with_label("pending-mux"),
            p_s,
            p_r,
            self.muxer_size,
        );
        mux.start();
        let (mux, mut rc_mux) = Muxer::new(
            self.context.with_label("recovered-mux"),
            rc_s,
            rc_r,
            self.muxer_size,
        );
        mux.start();
        let (mux, mut rs_mux) = Muxer::new(
            self.context.with_label("resolver-mux"),
            rs_s,
            rs_r,
            self.muxer_size,
        );
        mux.start();

        // Enter initial epoch.
        self.enter_epoch(0, &mut p_mux, &mut rc_mux, &mut rs_mux)
            .await;

        // Keep waiting for epoch updates.
        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::EnterEpoch { epoch } => {
                    if epoch <= self.epoch {
                        continue;
                    }
                    self.enter_epoch(epoch, &mut p_mux, &mut rc_mux, &mut rs_mux)
                        .await;
                }
            }
        }
    }

    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        p_mux: &mut MuxHandle<
            E,
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
        rc_mux: &mut MuxHandle<
            E,
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
        rs_mux: &mut MuxHandle<
            E,
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
    ) {
        // Stop previous engine.
        if let Some(engine) = self.consensus_engine.take() {
            engine.abort();
        }

        // Register authorized peers for this epoch (for discovery)
        self.oracle.register(epoch, self.validators.clone()).await;

        // Initialize consensus engine for this epoch
        let engine = threshold_simplex::Engine::new(
            self.context.with_label(&format!("engine-epoch-{epoch}")),
            threshold_simplex::Config {
                crypto: self.signer.clone(),
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: self.marshal.clone(),
                supervisor: self.supervisor.clone(),
                partition: format!("epocher-consensus-{}-{}", self.signer.public_key(), epoch),
                compression: Some(3),
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
        let p_sc = p_mux.register(epoch as u32).await.unwrap();
        let rc_sc = rc_mux.register(epoch as u32).await.unwrap();
        let rs_sc = rs_mux.register(epoch as u32).await.unwrap();

        // Start consensus
        let engine_handle = engine.start(p_sc, rc_sc, rs_sc);
        self.consensus_engine = Some(engine_handle);
    }
}
