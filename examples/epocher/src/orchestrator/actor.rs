use super::{Config, Mailbox, Message};
use crate::{
    forwarder::Forwarder,
    orchestrator::EpochCert,
    types::block::{Block, GENESIS_BLOCK},
};
use commonware_codec::EncodeFixed;
use commonware_consensus::{
    marshal,
    threshold_simplex::{
        self,
        types::{Activity, Context},
    },
    types::Epoch,
    Automaton, Relay, Reporter, Reporters,
};
use commonware_cryptography::{
    bls12381::primitives::{group, poly, variant::MinSig},
    sha256, Committable, Signer,
};
use commonware_p2p::{
    authenticated::discovery::Oracle,
    utils::mux::{MuxHandle, Muxer},
    Receiver, Sender,
};
use commonware_runtime::{buffer::PoolRef, Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use rand::{rngs::StdRng, seq::SliceRandom, CryptoRng, Rng, SeedableRng};
use std::time::Duration;
use tracing::info;

const METADATA_KEY: FixedBytes<1> = FixedBytes::new([0u8]);

type D = sha256::Digest;

/// Orchestrator actor.
pub struct Orchestrator<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    C: Signer,
    A: Automaton<Context = Context<D>, Digest = D> + Relay<Digest = D>,
> {
    context: E,
    signer: C,
    application: A,
    polynomial: poly::Public<MinSig>,
    shares: Vec<group::Share>,
    oracle: Oracle<E, C::PublicKey>,
    marshal: marshal::Mailbox<MinSig, Block>,

    mailbox: mpsc::Receiver<Message>,

    // Configuration
    namespace: Vec<u8>,
    validators: Vec<C::PublicKey>,
    muxer_size: usize,
    indexers: Vec<String>,
    partition_prefix: String,

    // State
    epoch: Epoch,
    consensus_engine: Option<Handle<()>>,

    // Metadata store for persisting latest epoch/seed
    metadata: Option<Metadata<E, FixedBytes<1>, (Epoch, sha256::Digest)>>,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
        C: Signer,
        A: Automaton<Context = Context<D>, Digest = D> + Relay<Digest = D>,
    > Orchestrator<E, C, A>
{
    pub fn new(context: E, cfg: Config<E, C, A>) -> (Self, Mailbox) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                signer: cfg.signer,
                application: cfg.application,
                polynomial: cfg.polynomial,
                shares: cfg.shares,
                oracle: cfg.oracle,
                marshal: cfg.marshal,

                mailbox: rx,
                namespace: cfg.namespace,
                validators: cfg.validators,
                muxer_size: cfg.muxer_size,
                indexers: cfg.indexers,
                partition_prefix: cfg.partition_prefix,

                epoch: 0,
                consensus_engine: None,

                metadata: None,
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

        // Initialize metadata store
        let metadata = Metadata::init(
            self.context.with_label("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", self.partition_prefix),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize orchestrator metadata");
        self.metadata = Some(metadata);

        // Register all possible validators (ensures all validators receive consensus messages)
        self.oracle.register(0, self.validators.clone()).await;

        // Enter initial epoch using recovered metadata if present; otherwise use genesis seed.
        // Recover last epoch/seed from metadata
        let (initial_epoch, initial_seed) = self
            .metadata
            .as_ref()
            .and_then(|m| m.get(&METADATA_KEY).cloned())
            .unwrap_or((0, GENESIS_BLOCK.commitment()));
        self.enter_epoch(
            initial_epoch,
            initial_seed,
            &mut p_mux,
            &mut rc_mux,
            &mut rs_mux,
        )
        .await;

        // Keep waiting for epoch updates.
        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::EpochTransition(cert) => {
                    // Skip if already entered this epoch.
                    if cert.epoch() <= self.epoch {
                        continue;
                    }

                    // Send the finalization to marshal which can help it catch up if behind.
                    let finalization = match &cert {
                        EpochCert::Single(f0) => f0.clone(),
                        EpochCert::Double(_f1, f2) => f2.clone(),
                    };
                    self.marshal
                        .report(Activity::Finalization(finalization))
                        .await;

                    // Enter the epoch.
                    self.enter_epoch(
                        cert.epoch(),
                        cert.seed(),
                        &mut p_mux,
                        &mut rc_mux,
                        &mut rs_mux,
                    )
                    .await;
                }
            }
        }
    }

    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        seed: sha256::Digest,
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
        // Persist latest epoch and seed via metadata
        let _ = self
            .metadata
            .as_mut()
            .unwrap()
            .put_sync(METADATA_KEY, (epoch, seed))
            .await;
        self.epoch = epoch;

        // Stop previous engine.
        if let Some(engine) = self.consensus_engine.take() {
            engine.abort();
        }

        // Select 4 participants deterministically using the provided seed
        let mut shuffled = self.validators.clone();
        let mut rng = StdRng::from_seed(seed.encode_fixed());
        shuffled.shuffle(&mut rng);
        let mut participants = shuffled.into_iter().take(4).collect::<Vec<_>>();
        participants.sort();
        info!("epoch {epoch} participants: {:?}", participants);

        // Build per-epoch supervisor from selected participants; if not selected, do nothing
        let my_pk = self.signer.public_key();
        let share = participants
            .iter()
            .position(|pk| pk == &my_pk)
            .map(|i| self.shares[i].clone());
        let supervisor =
            crate::supervisor::Supervisor::new(self.polynomial.clone(), participants, share);

        // Initialize consensus engine for this epoch
        let indexers = self.indexers.clone();
        let engine = threshold_simplex::Engine::new(
            self.context.with_label(&format!("engine-epoch-{epoch}")),
            threshold_simplex::Config {
                crypto: self.signer.clone(),
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: Reporters::from((
                    self.marshal.clone(),
                    Forwarder::new(self.marshal.clone(), indexers),
                )),
                supervisor,
                partition: format!("epocher-consensus-{}-{}", self.signer.public_key(), epoch),
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

        info!(epoch, "orchestrator: registered epoch-specific subchannels");

        // Start consensus
        let engine_handle = engine.start(p_sc, rc_sc, rs_sc);
        self.consensus_engine = Some(engine_handle);
    }
}
