//! Service engine for `commonware-reshare` validators.

use crate::{
    application::{self, Block, Scheme, SchemeProvider},
    dkg, orchestrator, BLOCKS_PER_EPOCH,
};
use commonware_broadcast::buffered;
use commonware_consensus::marshal::{self, ingress::handler};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::Variant},
    Hasher, Signer,
};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_utils::{quorum, union, NZUsize, NZU64};
use futures::{channel::mpsc, future::try_join_all};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use std::{marker::PhantomData, num::NonZero};
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

pub struct Config<C, B, V>
where
    C: Signer,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
{
    pub signer: C,
    pub blocker: B,
    pub namespace: Vec<u8>,

    pub polynomial: Public<V>,
    pub share: Option<group::Share>,
    pub active_participants: Vec<C::PublicKey>,
    pub inactive_participants: Vec<C::PublicKey>,
    pub num_participants_per_epoch: usize,
    pub dkg_rate_limit: governor::Quota,

    pub partition_prefix: String,
    pub freezer_table_initial_size: u32,
}

pub struct Engine<E, C, B, H, V>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    C: Signer,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
{
    context: ContextCell<E>,
    config: Config<C, B, V>,
    dkg: dkg::Actor<E, H, C, V>,
    dkg_mailbox: dkg::Mailbox<H, C, V>,
    application: application::Actor<E, H, C, V>,
    buffer: buffered::Engine<E, C::PublicKey, Block<H, C, V>>,
    buffered_mailbox: buffered::Mailbox<C::PublicKey, Block<H, C, V>>,
    marshal: marshal::Actor<E, Block<H, C, V>, SchemeProvider<V>, Scheme<V>>,
    marshal_mailbox: marshal::Mailbox<Scheme<V>, Block<H, C, V>>,
    orchestrator: orchestrator::Actor<E, B, V, C, H, application::Mailbox<H>>,
    orchestrator_mailbox: orchestrator::Mailbox<V, C::PublicKey>,
    _phantom: core::marker::PhantomData<(E, C, H, V)>,
}

impl<E, C, B, H, V> Engine<E, C, B, H, V>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    C: Signer,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
{
    pub async fn new(context: E, config: Config<C, B, V>) -> Self {
        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
        let consensus_namespace = union(&config.namespace, b"_CONSENSUS");
        let dkg_namespace = union(&config.namespace, b"_DKG");
        let threshold = quorum(config.num_participants_per_epoch as u32) as usize;

        let (dkg, dkg_mailbox) = dkg::Actor::init(
            context.with_label("dkg"),
            dkg::Config {
                namespace: dkg_namespace,
                signer: config.signer.clone(),
                num_participants_per_epoch: config.num_participants_per_epoch,
                mailbox_size: MAILBOX_SIZE,
                rate_limit: config.dkg_rate_limit,
                partition_prefix: config.partition_prefix.clone(),
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

        let scheme_provider = SchemeProvider::default();

        let (marshal, marshal_mailbox) = marshal::Actor::init(
            context.with_label("marshal"),
            marshal::Config {
                scheme_provider: scheme_provider.clone(),
                epoch_length: BLOCKS_PER_EPOCH,
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention_timeout: ACTIVITY_TIMEOUT
                    .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                namespace: consensus_namespace.clone(),
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
                block_codec_config: threshold,
                max_repair: MAX_REPAIR,
                _marker: PhantomData,
            },
        )
        .await;

        let (orchestrator, orchestrator_mailbox) = orchestrator::Actor::new(
            context.with_label("orchestrator"),
            orchestrator::Config {
                oracle: config.blocker.clone(),
                signer: config.signer.clone(),
                application: application_mailbox.clone(),
                scheme_provider,
                marshal: marshal_mailbox.clone(),
                namespace: consensus_namespace,
                muxer_size: MAILBOX_SIZE,
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}_consensus", config.partition_prefix),
            },
        );

        Self {
            context: ContextCell::new(context),
            config,
            dkg,
            dkg_mailbox,
            application,
            buffer,
            buffered_mailbox,
            marshal,
            marshal_mailbox,
            orchestrator,
            orchestrator_mailbox,
            _phantom: core::marker::PhantomData,
        }
    }

    #[allow(clippy::type_complexity)]
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
        broadcast: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        backfill_network: (
            mpsc::Receiver<handler::Message<Block<H, C, V>>>,
            commonware_resolver::p2p::Mailbox<handler::Request<Block<H, C, V>>>,
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
        broadcast: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        backfill_network: (
            mpsc::Receiver<handler::Message<Block<H, C, V>>>,
            commonware_resolver::p2p::Mailbox<handler::Request<Block<H, C, V>>>,
        ),
    ) {
        let dkg_handle = self.dkg.start(
            self.config.polynomial,
            self.config.share,
            self.config.active_participants,
            self.config.inactive_participants,
            self.orchestrator_mailbox,
            dkg,
        );
        let application_handle = self
            .application
            .start(self.marshal_mailbox, self.dkg_mailbox.clone());
        let buffer_handle = self.buffer.start(broadcast);
        let marshal_handle =
            self.marshal
                .start(self.dkg_mailbox, self.buffered_mailbox, backfill_network);
        let orchestrator_handle = self.orchestrator.start(pending, recovered, resolver);

        if let Err(e) = try_join_all(vec![
            dkg_handle,
            application_handle,
            buffer_handle,
            marshal_handle,
            orchestrator_handle,
        ])
        .await
        {
            error!(?e, "task failed");
        } else {
            warn!("engine stopped");
        }
    }
}
