//! Service engine for `commonware-dkg` validators.

use crate::{
    application::{self, Block, Supervisor},
    dkg,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{self, ingress::handler, SigningSchemeProvider},
    threshold_simplex::{self, signing_scheme::ed25519::Scheme},
    Reporters,
};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant,
    ed25519::{PrivateKey, PublicKey},
    Hasher, Signer,
};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_utils::{quorum, NZUsize, NZU32, NZU64};
use futures::{channel::mpsc, future::try_join_all};
use governor::{clock::Clock as GClock, Quota};
use rand::{CryptoRng, Rng};
use std::{num::NonZero, time::Duration};
use tracing::{error, warn};

const MAILBOX_SIZE: usize = 10;
const DEQUE_SIZE: usize = 10;
const ACTIVITY_TIMEOUT: u64 = 256;
const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_JOURNAL_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_JOURNAL_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024); // 8MB
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024); // 1MB
const BUFFER_POOL_PAGE_SIZE: NonZero<usize> = NZUsize!(4_096); // 4KB
const BUFFER_POOL_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
const MAX_REPAIR: u64 = 20;

pub struct Config<B>
where
    B: Blocker<PublicKey = PublicKey>,
{
    pub signer: PrivateKey,
    pub blocker: B,
    pub namespace: Vec<u8>,

    pub active_participants: Vec<PublicKey>,
    pub partition_prefix: String,
    pub freezer_table_initial_size: u32,
}

pub struct Engine<E, B, H, V>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = PublicKey>,
    H: Hasher,
    V: Variant,
{
    context: ContextCell<E>,
    config: Config<B>,
    application: application::Actor<E, H, PrivateKey, V>,
    application_mailbox: application::Mailbox<H, PrivateKey, V>,
    dkg: dkg::Actor<E, H, PrivateKey, V>,
    dkg_mailbox: dkg::Mailbox<H, PrivateKey, V>,
    buffer: buffered::Engine<E, PublicKey, Block<H, PrivateKey, V>>,
    buffered_mailbox: buffered::Mailbox<PublicKey, Block<H, PrivateKey, V>>,
    marshal: marshal::Actor<E, Block<H, PrivateKey, V>, Supervisor<PrivateKey>, Scheme>,
    marshal_mailbox: marshal::Mailbox<Scheme, Block<H, PrivateKey, V>>,
    consensus_engine: threshold_simplex::Engine<
        E,
        PrivateKey,
        Scheme,
        B,
        H::Digest,
        application::Mailbox<H, PrivateKey, V>,
        application::Mailbox<H, PrivateKey, V>,
        marshal::Mailbox<Scheme, Block<H, PrivateKey, V>>,
    >,
}

impl<E, B, H, V> Engine<E, B, H, V>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = PublicKey>,
    H: Hasher,
    V: Variant,
{
    pub async fn new(context: E, config: Config<B>) -> Self {
        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
        let threshold = quorum(config.active_participants.len() as u32) as usize;

        let (dkg, dkg_mailbox) = dkg::Actor::init(
            context.with_label("dkg"),
            dkg::Config {
                signer: config.signer.clone(),
                num_participants: config.active_participants.len(),
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: config.partition_prefix.clone(),
                log_items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                locations_items_per_blob: IMMUTABLE_ITEMS_PER_SECTION,
                buffer_pool: buffer_pool.clone(),
            },
        )
        .await;

        let (application, application_mailbox) =
            application::Actor::new(context.with_label("application"), MAILBOX_SIZE);

        let (buffer, buffered_mailbox) = buffered::Engine::new(
            context.with_label("buffer"),
            buffered::Config {
                public_key: config.signer.public_key(),
                mailbox_size: MAILBOX_SIZE,
                deque_size: DEQUE_SIZE,
                priority: true,
                codec_config: threshold,
            },
        );

        let supervisor = Supervisor::new(config.signer.clone(), config.active_participants.clone());
        let (marshal, marshal_mailbox) = marshal::Actor::init(
            context.with_label("marshal"),
            marshal::Config {
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention_timeout: ACTIVITY_TIMEOUT
                    .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                namespace: config.namespace.clone(),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                immutable_items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                freezer_table_initial_size: config.freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                max_repair: MAX_REPAIR,
                signing_provider: supervisor.clone(),
                block_codec_config: threshold,
                _marker: std::marker::PhantomData,
            },
        )
        .await;

        let consensus_engine = threshold_simplex::Engine::new(
            context.with_label("consensus_engine"),
            threshold_simplex::Config {
                crypto: config.signer.clone(),
                blocker: config.blocker.clone(),
                automaton: application_mailbox.clone(),
                relay: application_mailbox.clone(),
                reporter: marshal_mailbox.clone(),
                partition: format!("consensus_{}", config.signer.public_key()),
                mailbox_size: 1024,
                epoch: 0,
                namespace: config.namespace.clone(),
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
                buffer_pool,
                participants: config.active_participants.clone(),
                signing: supervisor.for_epoch(0).unwrap(),
            },
        );

        Self {
            context: ContextCell::new(context),
            config,
            application,
            application_mailbox,
            dkg,
            dkg_mailbox,
            buffer,
            buffered_mailbox,
            marshal,
            marshal_mailbox,
            consensus_engine,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn start(
        mut self,
        pending: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        backfill_network: (
            mpsc::Receiver<handler::Message<Block<H, PrivateKey, V>>>,
            commonware_resolver::p2p::Mailbox<handler::Request<Block<H, PrivateKey, V>>>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                pending,
                recovered,
                resolver,
                broadcast,
                dkg,
                backfill_network
            )
            .await
        )
    }

    #[allow(clippy::type_complexity)]
    async fn run(
        self,
        pending: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        backfill_network: (
            mpsc::Receiver<handler::Message<Block<H, PrivateKey, V>>>,
            commonware_resolver::p2p::Mailbox<handler::Request<Block<H, PrivateKey, V>>>,
        ),
    ) {
        let finalized_reporter =
            Reporters::from((self.application_mailbox, self.dkg_mailbox.clone()));
        let dkg_handle = self.dkg.start(
            self.config.active_participants.clone(),
            self.config.active_participants,
            dkg,
        );

        let application_handle = self
            .application
            .start(self.marshal_mailbox, self.dkg_mailbox);
        let buffer_handle = self.buffer.start(broadcast);
        let marshal_handle =
            self.marshal
                .start(finalized_reporter, self.buffered_mailbox, backfill_network);
        let consensus_handle = self.consensus_engine.start(pending, recovered, resolver);

        if let Err(e) = try_join_all(vec![
            dkg_handle,
            application_handle,
            buffer_handle,
            marshal_handle,
            consensus_handle,
        ])
        .await
        {
            error!(?e, "task failed");
        } else {
            warn!("engine stopped");
        }
    }
}
