//! Service engine for `commonware-reshare` validators.

use crate::{
    application::{Application, Block, EpochSchemeProvider, SchemeProvider},
    dkg::{self, UpdateCallBack},
    orchestrator,
    setup::PeerConfig,
    BLOCKS_PER_EPOCH,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    application::marshaled::Marshaled,
    marshal::{self, ingress::handler},
    simplex::{signing_scheme::Scheme, types::Finalization},
    types::ViewDelta,
};
use commonware_cryptography::{
    bls12381::{
        dkg::Output,
        primitives::{group, variant::Variant},
    },
    Hasher, Signer,
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_storage::archive::immutable;
use commonware_utils::{ordered::Set, union, NZUsize, NZU32, NZU64};
use futures::{channel::mpsc, future::try_join_all};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use std::{marker::PhantomData, num::NonZero, time::Instant};
use tracing::{error, info, warn};

const MAILBOX_SIZE: usize = 10;
const DEQUE_SIZE: usize = 10;
const ACTIVITY_TIMEOUT: ViewDelta = ViewDelta::new(256);
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
const MAX_REPAIR: NonZero<usize> = NZUsize!(50);

pub struct Config<C, P, B, V>
where
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    C: Signer,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
{
    pub signer: C,
    pub manager: P,
    pub blocker: B,
    pub namespace: Vec<u8>,
    pub output: Option<Output<V, C::PublicKey>>,
    pub share: Option<group::Share>,
    pub peer_config: PeerConfig<C::PublicKey>,
    pub partition_prefix: String,
    pub freezer_table_initial_size: u32,
}

pub struct Engine<E, C, P, B, H, V, S>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    C: Signer,
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    S: Scheme<PublicKey = C::PublicKey>,
    SchemeProvider<S, C>: EpochSchemeProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    context: ContextCell<E>,
    config: Config<C, P, B, V>,
    dkg: dkg::Actor<E, P, H, C, V>,
    dkg_mailbox: dkg::Mailbox<H, C, V>,
    buffer: buffered::Engine<E, C::PublicKey, Block<H, C, V>>,
    buffered_mailbox: buffered::Mailbox<C::PublicKey, Block<H, C, V>>,
    #[allow(clippy::type_complexity)]
    marshal: marshal::Actor<
        E,
        Block<H, C, V>,
        SchemeProvider<S, C>,
        S,
        immutable::Archive<E, H::Digest, Finalization<S, H::Digest>>,
        immutable::Archive<E, H::Digest, Block<H, C, V>>,
    >,
    #[allow(clippy::type_complexity)]
    orchestrator: orchestrator::Actor<
        E,
        B,
        V,
        C,
        H,
        Marshaled<E, S, Application<E, S, H, C, V>, Block<H, C, V>>,
        S,
    >,
    orchestrator_mailbox: orchestrator::Mailbox<V, C::PublicKey>,
    _phantom: core::marker::PhantomData<(E, C, H, V)>,
}

impl<E, C, P, B, H, V, S> Engine<E, C, P, B, H, V, S>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    C: Signer,
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    S: Scheme<PublicKey = C::PublicKey>,
    SchemeProvider<S, C>: EpochSchemeProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    pub async fn new(context: E, config: Config<C, P, B, V>) -> Self {
        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
        let consensus_namespace = union(&config.namespace, b"_CONSENSUS");
        let num_participants = NZU32!(config.peer_config.max_participants_per_round());

        let (dkg, dkg_mailbox) = dkg::Actor::init(
            context.with_label("dkg"),
            dkg::Config {
                manager: config.manager.clone(),
                signer: config.signer.clone(),
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: config.partition_prefix.clone(),
                peer_config: config.peer_config.clone(),
            },
        )
        .await;

        let (buffer, buffered_mailbox) = buffered::Engine::new(
            context.with_label("buffer"),
            buffered::Config {
                public_key: config.signer.public_key(),
                mailbox_size: MAILBOX_SIZE,
                deque_size: DEQUE_SIZE,
                priority: true,
                codec_config: num_participants,
            },
        );

        // Initialize finalizations by height
        let start = Instant::now();
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: config.freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_partition: format!(
                    "{}-finalizations-by-height-freezer-journal",
                    config.partition_prefix
                ),
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        // Initialize finalized blocks archive
        let start = Instant::now();
        let finalized_blocks = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalized_blocks-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: config.freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_partition: format!(
                    "{}-finalized_blocks-freezer-journal",
                    config.partition_prefix
                ),
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: num_participants,
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let scheme_provider = SchemeProvider::new(config.signer.clone());
        let (marshal, marshal_mailbox) = marshal::Actor::init(
            context.with_label("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                scheme_provider: scheme_provider.clone(),
                epoch_length: BLOCKS_PER_EPOCH,
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention_timeout: ViewDelta::new(
                    ACTIVITY_TIMEOUT
                        .get()
                        .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                ),
                namespace: consensus_namespace.clone(),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                buffer_pool: buffer_pool.clone(),
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                block_codec_config: num_participants,
                max_repair: MAX_REPAIR,
                _marker: PhantomData,
            },
        )
        .await;

        let application = Marshaled::new(
            context.with_label("application"),
            Application::new(dkg_mailbox.clone()),
            marshal_mailbox.clone(),
            BLOCKS_PER_EPOCH,
        );

        let (orchestrator, orchestrator_mailbox) = orchestrator::Actor::new(
            context.with_label("orchestrator"),
            orchestrator::Config {
                oracle: config.blocker.clone(),
                application,
                scheme_provider,
                marshal: marshal_mailbox,
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
            buffer,
            buffered_mailbox,
            marshal,
            orchestrator,
            orchestrator_mailbox,
            _phantom: core::marker::PhantomData,
        }
    }

    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn start(
        mut self,
        votes: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        certificates: (
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
        orchestrator: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        marshal: (
            mpsc::Receiver<handler::Message<Block<H, C, V>>>,
            commonware_resolver::p2p::Mailbox<handler::Request<Block<H, C, V>>, C::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                votes,
                certificates,
                resolver,
                broadcast,
                dkg,
                orchestrator,
                marshal,
                callback
            )
            .await
        )
    }

    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    async fn run(
        self,
        votes: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        certificates: (
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
        orchestrator: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        marshal: (
            mpsc::Receiver<handler::Message<Block<H, C, V>>>,
            commonware_resolver::p2p::Mailbox<handler::Request<Block<H, C, V>>, C::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) {
        let dkg_handle = self.dkg.start(
            self.config.output,
            self.config.share,
            self.orchestrator_mailbox,
            dkg,
            callback,
        );
        let buffer_handle = self.buffer.start(broadcast);
        let marshal_handle = self
            .marshal
            .start(self.dkg_mailbox, self.buffered_mailbox, marshal);
        let orchestrator_handle =
            self.orchestrator
                .start(votes, certificates, resolver, orchestrator);

        if let Err(e) = try_join_all(vec![
            dkg_handle,
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
