//! `validator` subcommand: run one settlement-chain validator.
//!
//! The assembly is modeled on the reshare example's validator with the
//! simplest launchable committee: a fixed BLS threshold committee dealt once
//! by [`crate::chain::setup`] (reshare's trusted-bootstrap path without
//! continuous resharing). The certificate scheme never rotates, so one epoch
//! spans the whole chain and a [`ConstantProvider`] replaces the orchestrator
//! and dkg actors. Continuous resharing is a drop-in from the reshare
//! example: replace the constant provider and the direct simplex engine with
//! its orchestrator, probe, and reshare actors.

use crate::{
    chain::{
        app::{App, Finalized, initial_sync_target},
        da, ingress, query,
        registry::{self, RegistryView},
        setup::{NetworkConfig, NodeConfig, read_genesis},
        types::{Block, Database},
    },
    protocol::committee,
};
use clap::Args;
use commonware_broadcast::buffered;
use commonware_clearing::bajillion::admission::bls12381 as clearing_bls;
use commonware_consensus::{
    Reporters,
    marshal::{
        self, core::Actor as MarshalActor, resolver::p2p as marshal_resolver, standard::Deferred,
    },
    simplex::{
        self, SkipBudget,
        config::{ForwardPolicy, SkipPolicy},
        elector::RoundRobin,
    },
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    Digestible as _, Sha256,
    bls12381::primitives::{
        sharing::{Mode, ModeVersion},
        variant::MinSig,
    },
    certificate::ConstantProvider,
    ed25519,
};
use commonware_glue::stateful::{
    Config as StatefulConfig, Stateful, SyncPlan, db::SyncEngineConfig,
};
use commonware_macros::boxed;
use commonware_p2p::{Manager, TrackedPeers, authenticated::discovery};
use commonware_parallel::Sequential;
use commonware_runtime::{Handle, Quota, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    archive::prunable, journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::full::Config as MerkleConfig, translator::TwoCap,
};
use commonware_utils::{NZU16, NZU32, NZU64, NZUsize, ordered::Set};
use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};
use tracing::error;

/// Threshold certificate scheme for consensus votes and certificates.
pub(crate) type Scheme =
    simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>;

/// Globally unique namespace for every message signed by the chain.
pub(crate) const NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_CHAIN";

/// The fixed committee never rotates, so one epoch spans the whole chain.
pub(crate) const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);

/// Maximum entries accepted in the committee participant set.
pub(crate) const MAX_PARTICIPANTS: NonZeroU32 = NZU32!(64);

/// Share derivation mode used by the trusted dealer.
pub(crate) const SHARING_MODE: Mode = Mode::NonZeroCounter;

/// Newest sharing mode version this binary accepts.
pub(crate) const MAX_SUPPORTED_MODE: ModeVersion = ModeVersion::v0();

/// P2P channel carrying simplex votes.
pub(crate) const VOTE_CHANNEL: u64 = 0;

/// P2P channel carrying simplex certificates.
pub(crate) const CERTIFICATE_CHANNEL: u64 = 1;

/// P2P channel for simplex resolver traffic.
pub(crate) const RESOLVER_CHANNEL: u64 = 2;

/// P2P channel for marshal block backfill.
pub(crate) const BACKFILL_CHANNEL: u64 = 3;

/// P2P channel for proposed block broadcast.
pub(crate) const BROADCAST_CHANNEL: u64 = 4;

/// P2P channel carrying settlement transaction gossip.
pub(crate) const SETTLEMENT_TX_CHANNEL: u64 = 5;

/// P2P channel carrying settlement dealing dissemination and votes.
pub(crate) const SETTLEMENT_DA_CHANNEL: u64 = 6;

/// Mailbox capacity for every actor.
pub(crate) const MAILBOX_SIZE: NonZeroUsize = NZUsize!(100);

/// Per-peer message quota for every P2P channel.
pub(crate) const MESSAGE_RATE: Quota = Quota::per_second(NZU32!(128));

/// Maximum P2P message size in bytes.
pub(crate) const MAX_MESSAGE_SIZE: u32 = 4 * 1024 * 1024;

/// Page size for storage page caches.
pub(crate) const PAGE_SIZE: NonZeroU16 = NZU16!(1024);

/// Number of pages held by each page cache.
pub(crate) const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16);

/// Buffer size for journal replay and writes.
pub(crate) const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);

/// Maximum transactions retained in each deployment's ingress class.
pub(crate) const INGRESS_CAPACITY: NonZeroUsize = NZUsize!(64);

/// Encoded bytes retained per ingress class, sufficient for any one valid
/// transaction. Two classes per deployment and one native class bound the
/// aggregate payload to 129 MiB at the 64-deployment registry limit.
pub(crate) const INGRESS_BYTES: NonZeroUsize = NZUsize!(crate::chain::types::MAX_TX_BYTES);

/// Finalized blocks a drained transaction stays leased before re-offer.
pub(crate) const INGRESS_LEASE: u64 = 10;

/// Settlement QMDB config with partitions derived from `prefix`.
pub(crate) fn db_config(
    prefix: &str,
    page_cache: CacheRef,
) -> commonware_storage::qmdb::current::VariableConfig<TwoCap, ((), ()), Sequential> {
    commonware_storage::qmdb::current::VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-chain-mmr-journal"),
            metadata_partition: format!("{prefix}-chain-mmr-metadata"),
            items_per_blob: NZU64!(4_096),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: format!("{prefix}-chain-log-journal"),
            items_per_section: NZU64!(4_096),
            compression: None,
            codec_config: ((), ()),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{prefix}-chain-grafted-metadata"),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(1_024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

/// QMDB state sync engine tuning.
pub(crate) const fn sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: NZU64!(16),
        apply_batch_size: NZU64!(64),
        max_outstanding_requests: 8,
        update_channel_size: NZUsize!(256),
        max_retained_roots: 8,
    }
}

/// State sync source that never answers.
///
/// Peer state sync is disabled for the demo: a late joiner replays finalized
/// blocks through marshal backfill instead. Serving QMDB operations to peers
/// is a drop-in from the reshare example's qmdb resolver actor.
#[derive(Clone)]
pub(crate) struct NoopResolver;

impl commonware_storage::qmdb::sync::Source for NoopResolver {
    type Family = commonware_storage::mmr::Family;
    type Digest = commonware_cryptography::sha256::Digest;
    type Op = commonware_storage::qmdb::any::ordered::variable::Operation<
        commonware_storage::mmr::Family,
        crate::chain::types::StateKey,
        crate::chain::state::Record,
    >;
    type Error = std::convert::Infallible;

    fn serve<'a>(
        &'a self,
        _: commonware_storage::qmdb::sync::Request<Self::Family>,
    ) -> impl std::future::Future<
        Output = Result<
            (
                commonware_storage::qmdb::sync::Response<Self::Family, Self::Op, Self::Digest>,
                commonware_storage::qmdb::sync::FeedbackTx,
            ),
            Self::Error,
        >,
    > + Send
    + 'a {
        std::future::pending()
    }
}

impl<E> commonware_glue::stateful::db::AttachableResolver<crate::chain::types::Qmdb<E>>
    for NoopResolver
where
    E: commonware_storage::Context + commonware_runtime::Spawner,
{
    async fn attach_database(&self, _: Database<E>) {}
}

/// Start a validator node.
#[derive(Args)]
pub struct Validator {
    /// Validator node directory containing config, genesis, and storage.
    #[arg(long, default_value = "./data/validator-0")]
    pub node_dir: PathBuf,
}

/// Start every validator actor and run until one stops.
#[boxed]
pub async fn run(context: tokio::Context, args: Validator) {
    let node = NodeConfig::load(&args.node_dir).expect("failed to load node config");
    let network = NetworkConfig::load(&args.node_dir).expect("failed to load network config");
    network.validate().expect("invalid network config");
    let genesis_output = read_genesis(&args.node_dir).expect("genesis is required");
    let local = node.public_key();
    let partition_prefix = "validator";
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

    let registry = RegistryView::new(genesis_output.native.deployments.clone());
    let mut bootstrappers = network.bootstrappers(&local);
    for operator in &network.operators {
        bootstrappers.push((operator.public_key.clone(), operator.dial.into()));
    }
    let max_peers_per_set = NonZeroUsize::new(
        network
            .participants
            .len()
            .checked_add(genesis_output.native.max_deployments as usize)
            .expect("bounded peer capacity"),
    )
    .expect("the committee is nonempty");

    // The fixed committee signs under one scheme for the life of the chain.
    let scheme = Scheme::signer(
        NAMESPACE,
        genesis_output.players().clone(),
        genesis_output.public().clone(),
        node.share.clone(),
    )
    .expect("the dealt share must match the genesis committee");
    let provider = ConstantProvider::new(scheme.clone());

    let mut p2p_config = discovery::Config::local(
        node.signing_key.clone(),
        &[NAMESPACE, b"_P2P"].concat(),
        node.listen,
        node.dial,
        bootstrappers,
        max_peers_per_set,
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    let (mut p2p, mut oracle) = discovery::Network::new(context.child("network"), p2p_config);
    let vote_network = p2p.register(VOTE_CHANNEL, MESSAGE_RATE);
    let certificate_network = p2p.register(CERTIFICATE_CHANNEL, MESSAGE_RATE);
    let resolver_network = p2p.register(RESOLVER_CHANNEL, MESSAGE_RATE);
    let backfill_network = p2p.register(BACKFILL_CHANNEL, MESSAGE_RATE);
    let broadcast_network = p2p.register(BROADCAST_CHANNEL, MESSAGE_RATE);
    let settlement_tx_network = p2p.register(SETTLEMENT_TX_CHANNEL, MESSAGE_RATE);
    let settlement_da_network = p2p.register(SETTLEMENT_DA_CHANNEL, MESSAGE_RATE);

    let _ = oracle.track(
        0,
        TrackedPeers::new(
            Set::from_iter_dedup(network.participants.iter().cloned()),
            Set::from_iter_dedup(
                registry
                    .entries()
                    .into_iter()
                    .map(|entry| entry.network_key),
            ),
        ),
    );
    let p2p_handle = p2p.start();

    // Marshal resolver.
    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: local.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size: MAILBOX_SIZE,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        backfill_network,
    );

    // Buffered broadcast engine.
    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: local.clone(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: 16,
            priority: false,
            codec_config: (),
            peer_provider: oracle.clone(),
        },
    );
    let broadcast_handle = broadcast_engine.start(broadcast_network);

    // Prunable archives backing marshal.
    let archive_config = |name: &str| prunable::Config {
        translator: TwoCap,
        key_partition: format!("{partition_prefix}-{name}-key"),
        key_page_cache: page_cache.clone(),
        value_partition: format!("{partition_prefix}-{name}-value"),
        compression: None,
        codec_config: (),
        items_per_section: NZU64!(1_024),
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    };
    let finalizations_by_height = prunable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config("finalizations"),
    )
    .await
    .expect("failed to initialize finalizations archive");
    let finalized_blocks =
        prunable::Archive::init(context.child("finalized_blocks"), archive_config("blocks"))
            .await
            .expect("failed to initialize blocks archive");

    // Genesis block shared by every validator.
    let genesis_block = Block::genesis(
        network.participants[0].clone(),
        genesis_output.native.chain_id(),
        genesis_output.timestamp,
        initial_sync_target::<tokio::Context>(),
    );

    let startup = context.child("stateful_startup");
    let plan = SyncPlan::init(&startup, partition_prefix).await;
    let _ = plan.should_state_sync(false);

    // Marshal actor.
    let (marshal_actor, marshal, floor) = MarshalActor::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(EPOCH_LENGTH),
            start: plan.marshal_start(genesis_block.clone()),
            partition_prefix: partition_prefix.to_string(),
            mailbox_size: MAILBOX_SIZE,
            view_retention: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(1_024),
            page_cache: page_cache.clone(),
            replay_buffer: IO_BUFFER_SIZE,
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            block_codec_config: (),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;

    // Transaction ingress.
    let (ingress_actor, ingress_mailbox) = ingress::Actor::new(
        context.child("ingress"),
        ingress::Config {
            mailbox_size: NZUsize!(64),
            capacity: INGRESS_CAPACITY,
            bytes: INGRESS_BYTES,
            lease: INGRESS_LEASE,
            retention: INGRESS_LEASE
                .checked_mul(4)
                .expect("ingress retention fits u64"),
        },
        registry.clone(),
    );

    // Stateful actor wrapping the settlement application.
    let finalized = Finalized::default();
    let application: App<Scheme, ingress::Mailbox> = App::new(
        genesis_block.clone(),
        genesis_output.timing(),
        genesis_output.native.clone(),
        finalized.clone(),
    );
    let (stateful_actor, stateful_mailbox) = Stateful::init(
        context.child("stateful"),
        StatefulConfig {
            application,
            db_config: db_config(partition_prefix, page_cache.clone()),
            provider: ingress_mailbox.clone(),
            marshal: (marshal.clone(), floor),
            mailbox_size: MAILBOX_SIZE,
            plan,
            resolvers: NoopResolver,
            sync_config: sync_config(),
            prune_config: None,
        },
    );

    // Deferred wrapper and marshal startup. The ingress mailbox rides the
    // reporter stream to retire included transactions.
    let deferred = Deferred::new(
        context.child("deferred"),
        stateful_mailbox.clone(),
        marshal.clone(),
        FixedEpocher::new(EPOCH_LENGTH),
    );
    let reporters = Reporters::from((stateful_mailbox.clone(), ingress_mailbox.clone()));
    let marshal_handle = marshal_actor.start(reporters, buffer, resolver);
    let stateful_handle = stateful_actor.start();

    // Sealing actor on the settlement DA channel: the validator's clearing
    // committee identity is the dealt BLS key from setup, separate material
    // from its consensus threshold share. The genesis validator list names
    // the query servers a missing canonical dealing is fetched from.
    let db: Database<tokio::Context> = stateful_mailbox.subscribe_databases().await;
    let ingress_handle = ingress_actor.start(
        settlement_tx_network,
        db.clone(),
        finalized.clone(),
        genesis_output.native.clone(),
        genesis_output.timing(),
        Set::from_iter_dedup(network.participants.iter().cloned()),
    );
    let registry_handle = registry::watch(
        context.child("registry"),
        db.clone(),
        genesis_output.native.clone(),
        registry.clone(),
        oracle.clone(),
        Set::from_iter_dedup(network.participants.iter().cloned()),
    );
    let clearing = clearing_bls::Scheme::signer(
        committee().expect("the demo committee is statically valid"),
        node.clearing.clone(),
    )
    .expect("the dealt clearing key must be in the committee");
    let (sealer, sealer_mailbox) = da::Sealer::new(
        context.child("sealer"),
        da::Config {
            scheme: clearing,
            registry,
            db: db.clone(),
            partition: format!("{partition_prefix}-dealings"),
            validators: genesis_output.validators.clone(),
            fetch_timeout: Duration::from_secs(2),
        },
    );
    let sealer_handle = sealer.start(settlement_da_network);

    // Certified query server over the applied database, serving evidence
    // from the sealer's retained dealings.
    let query_handle = query::start(
        context.child("query"),
        query::Config {
            address: node.query,
            db,
            finalized,
            marshal: marshal.clone(),
            ingress: ingress_mailbox,
            sealer: Some(sealer_mailbox),
        },
    );

    // Simplex engine over the fixed committee.
    let engine = simplex::Engine::new(
        context.child("simplex"),
        simplex::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker: oracle.clone(),
            automaton: deferred.clone(),
            relay: deferred,
            reporter: marshal.clone(),
            strategy: Sequential,
            partition: format!("{partition_prefix}-simplex"),
            mailbox_size: NZUsize!(3),
            epoch: Epoch::zero(),
            floor: simplex::config::Floor::Genesis(genesis_block.digest()),
            replay_buffer: IO_BUFFER_SIZE,
            write_buffer: IO_BUFFER_SIZE,
            page_cache,
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_millis(500),
            view_retention: ViewDelta::new(10),
            skip: SkipPolicy::Enabled {
                timeout: Duration::from_secs(5),
                budget: SkipBudget::Participants,
            },
            fetch_timeout: Duration::from_secs(2),
            forward: ForwardPolicy::Disabled,
            track_historical_votes: false,
        },
    );
    let engine_handle = engine.start(vote_network, certificate_network, resolver_network);

    if let Err(err) = Handle::select([
        p2p_handle,
        broadcast_handle,
        ingress_handle,
        marshal_handle,
        stateful_handle,
        sealer_handle,
        registry_handle,
        query_handle,
        engine_handle,
    ])
    .await
    {
        error!(?err, "validator task failed");
    }
}
