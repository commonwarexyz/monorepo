//! Service engine for `commonware-reshare` validators.

use crate::{
    application::{Application, Block, EpochProvider, Provider},
    dkg::{self, UpdateCallBack},
    orchestrator,
    setup::PeerConfig,
    BLOCKS_PER_EPOCH,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    application::marshaled::Marshaled,
    marshal::{self, ingress::handler},
    simplex::{elector::Config as Elector, scheme::Scheme, types::Finalization},
    types::{FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    bls12381::{
        dkg::Output,
        primitives::{group, variant::Variant},
    },
    Hasher, Signer,
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics,
    Network, Spawner, Storage,
};
use commonware_storage::archive::immutable;
use commonware_utils::{channel::mpsc, union, NZUsize, NZU16, NZU32, NZU64};
use futures::future::try_join_all;
use rand_core::CryptoRngCore;
use std::{
    marker::PhantomData,
    num::{NonZero, NonZeroU16},
    time::Instant,
};
use tracing::{error, info, warn};

const MAILBOX_SIZE: usize = 1024;
const DEQUE_SIZE: usize = 10;
const ACTIVITY_TIMEOUT: ViewDelta = ViewDelta::new(256);
const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024); // 8MB
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024); // 1MB
const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(4_096); // 4KB
const PAGE_CACHE_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
const MAX_REPAIR: NonZero<usize> = NZUsize!(50);

pub struct Config<C, P, B, V, T>
where
    P: Manager<PublicKey = C::PublicKey>,
    C: Signer,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    T: Strategy,
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
    pub strategy: T,
}

pub struct Engine<E, C, P, B, H, V, S, L, T>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network,
    C: Signer,
    P: Manager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    S: Scheme<H::Digest, PublicKey = C::PublicKey>,
    L: Elector<S>,
    T: Strategy,
    Provider<S, C>: EpochProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    context: ContextCell<E>,
    config: Config<C, P, B, V, T>,
    dkg: dkg::Actor<E, P, H, C, V>,
    dkg_mailbox: dkg::Mailbox<H, C, V>,
    buffer: buffered::Engine<E, C::PublicKey, Block<H, C, V>>,
    buffered_mailbox: buffered::Mailbox<C::PublicKey, Block<H, C, V>>,
    #[allow(clippy::type_complexity)]
    marshal: marshal::Actor<
        E,
        Block<H, C, V>,
        Provider<S, C>,
        immutable::Archive<E, H::Digest, Finalization<S, H::Digest>>,
        immutable::Archive<E, H::Digest, Block<H, C, V>>,
        FixedEpocher,
        T,
    >,
    #[allow(clippy::type_complexity)]
    orchestrator: orchestrator::Actor<
        E,
        B,
        V,
        C,
        H,
        Marshaled<E, S, Application<E, S, H, C, V>, Block<H, C, V>, FixedEpocher>,
        S,
        L,
        T,
    >,
    orchestrator_mailbox: orchestrator::Mailbox<V, C::PublicKey>,
}

impl<E, C, P, B, H, V, S, L, T> Engine<E, C, P, B, H, V, S, L, T>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network,
    C: Signer,
    P: Manager<PublicKey = C::PublicKey>,
    B: Blocker<PublicKey = C::PublicKey>,
    H: Hasher,
    V: Variant,
    S: Scheme<H::Digest, PublicKey = C::PublicKey>,
    L: Elector<S>,
    T: Strategy,
    Provider<S, C>: EpochProvider<Variant = V, PublicKey = C::PublicKey, Scheme = S>,
{
    pub async fn new(context: E, config: Config<C, P, B, V, T>) -> Self {
        let page_cache = CacheRef::from_pooler(&context, PAGE_CACHE_PAGE_SIZE, PAGE_CACHE_CAPACITY);
        let consensus_namespace = union(&config.namespace, b"_CONSENSUS");
        let num_participants = NZU32!(config.peer_config.max_participants_per_round());

        let (dkg, dkg_mailbox) = dkg::Actor::new(
            context.with_label("dkg"),
            dkg::Config {
                manager: config.manager.clone(),
                signer: config.signer.clone(),
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: config.partition_prefix.clone(),
                peer_config: config.peer_config.clone(),
            },
        );

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
                freezer_key_partition: format!(
                    "{}-finalizations-by-height-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalizations-by-height-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
                freezer_value_compression: FREEZER_VALUE_COMPRESSION,
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: REPLAY_BUFFER,
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_write_buffer: WRITE_BUFFER,
                ordinal_write_buffer: WRITE_BUFFER,
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
                freezer_key_partition: format!(
                    "{}-finalized_blocks-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
                freezer_value_compression: FREEZER_VALUE_COMPRESSION,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: num_participants,
                replay_buffer: REPLAY_BUFFER,
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_write_buffer: WRITE_BUFFER,
                ordinal_write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        // Create the certificate verifier from the initial output (if available).
        // This allows epoch-independent certificate verification after the DKG is complete.
        let certificate_verifier = config.output.as_ref().and_then(|output| {
            <Provider<S, C> as EpochProvider>::certificate_verifier(&consensus_namespace, output)
        });
        let provider = Provider::new(
            consensus_namespace.clone(),
            config.signer.clone(),
            certificate_verifier,
        );

        let (marshal, marshal_mailbox, _processed_height) = marshal::Actor::init(
            context.with_label("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention_timeout: ViewDelta::new(
                    ACTIVITY_TIMEOUT
                        .get()
                        .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                ),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                page_cache: page_cache.clone(),
                replay_buffer: REPLAY_BUFFER,
                key_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                block_codec_config: num_participants,
                max_repair: MAX_REPAIR,
                max_pending_acks: NZUsize!(16),
                strategy: config.strategy.clone(),
            },
        )
        .await;

        let application = Marshaled::new(
            context.with_label("application"),
            Application::new(dkg_mailbox.clone()),
            marshal_mailbox.clone(),
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );

        let (orchestrator, orchestrator_mailbox) = orchestrator::Actor::new(
            context.with_label("orchestrator"),
            orchestrator::Config {
                oracle: config.blocker.clone(),
                application,
                provider,
                marshal: marshal_mailbox,
                strategy: config.strategy.clone(),
                muxer_size: MAILBOX_SIZE,
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}_consensus", config.partition_prefix),
                _phantom: PhantomData,
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
        let orchestrator_handle = self.orchestrator.start(votes, certificates, resolver);

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
