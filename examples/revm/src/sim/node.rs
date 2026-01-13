//! Node wiring for the tokio runtime simulation.
//!
//! Each node runs:
//! - a marshal instance (block dissemination, backfill, and finalized block delivery), and
//! - a threshold-simplex engine instance that orders opaque digests.

use super::{
    demo, simplex, ThresholdScheme, BLOCK_CODEC_MAX_CALLDATA, BLOCK_CODEC_MAX_TXS,
    CHANNEL_BACKFILL, CHANNEL_BLOCKS, CHANNEL_CERTS, CHANNEL_RESOLVER, CHANNEL_VOTES, MAILBOX_SIZE,
};
use crate::{
    application::{self, DomainEvent},
    FinalizationEvent,
};
use anyhow::Context as _;
use commonware_broadcast::buffered;
use commonware_consensus::{
    application::marshaled::Marshaled,
    marshal,
    simplex::elector::Random,
    types::{Epoch, FixedEpocher, ViewDelta},
    Reporters,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519};
use commonware_p2p::simulated;
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::PoolRef, tokio, Metrics as _, Spawner};
use commonware_storage::archive::immutable;
use commonware_utils::{NZUsize, NZU16, NZU32, NZU64};
use futures::{channel::mpsc, StreamExt as _};
use governor::Quota;
use std::{sync::Arc, time::Duration};

type Peer = ed25519::PublicKey;
type ChannelSender = simulated::Sender<Peer, tokio::Context>;
type ChannelReceiver = simulated::Receiver<Peer>;

// This example keeps everything in a single epoch for simplicity. The `Marshaled` wrapper also
// supports epoch boundaries, but exercising that logic is out-of-scope for this demo.
const EPOCH_LENGTH: u64 = u64::MAX;

#[derive(Clone)]
struct ConstantSchemeProvider(Arc<ThresholdScheme>);

impl commonware_cryptography::certificate::Provider for ConstantSchemeProvider {
    type Scope = Epoch;
    type Scheme = ThresholdScheme;

    fn scoped(&self, _epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        Some(self.0.clone())
    }

    fn all(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.0.clone())
    }
}

impl From<ThresholdScheme> for ConstantSchemeProvider {
    fn from(scheme: ThresholdScheme) -> Self {
        Self(Arc::new(scheme))
    }
}

struct NodeChannels {
    /// Channel pair used for voting traffic.
    votes: (ChannelSender, ChannelReceiver),
    /// Channel pair used for certificate gossip.
    certs: (ChannelSender, ChannelReceiver),
    /// Channel pair used for resolver/backfill control requests.
    resolver: (ChannelSender, ChannelReceiver),
    /// Channel pair used for full block broadcast.
    blocks: (ChannelSender, ChannelReceiver),
    /// Channel pair used for marshal backfill responses.
    backfill: (ChannelSender, ChannelReceiver),
}

struct NodeInit<'a> {
    /// Position of the node within the simulated committee.
    index: usize,
    /// Validator identity key for network registrations.
    public_key: Peer,
    /// Threshold signing scheme assigned to this node.
    scheme: ThresholdScheme,
    /// Per-channel rate limit quota.
    quota: Quota,
    /// Buffer pool used for all storage/journal operations.
    buffer_pool: PoolRef,
    /// Channel to drive finalization reporting back to the harness.
    finalized_tx: mpsc::UnboundedSender<FinalizationEvent>,
    /// Shared demo transfer configuration/state.
    demo: &'a demo::DemoTransfer,
}

struct MarshalStart<M> {
    /// Node index used for naming partitions/metrics.
    index: usize,
    /// Node identity key used for network links.
    public_key: Peer,
    /// Control channel used to register and rate-limit transport channels.
    control: simulated::Control<Peer, tokio::Context>,
    /// P2P manager holding the oracle/peering state.
    manager: M,
    /// Threshold signing scheme for this node.
    scheme: ThresholdScheme,
    /// Buffer pool that backs all storage archives.
    buffer_pool: PoolRef,
    /// Codec settings for block serialization.
    block_codec_config: crate::types::BlockCfg,
    /// Channels used for block broadcasts.
    blocks: (ChannelSender, ChannelReceiver),
    /// Channels used for marshal backfill requests/responses.
    backfill: (ChannelSender, ChannelReceiver),
    /// Application-level reporter that observes finalized blocks.
    application: application::FinalizedReporter<tokio::Context>,
}

/// Spawn all nodes (application + consensus) for a simulation run.
pub(super) async fn start_all_nodes(
    context: &tokio::Context,
    oracle: &mut simulated::Oracle<ed25519::PublicKey, tokio::Context>,
    participants: &[ed25519::PublicKey],
    schemes: &[ThresholdScheme],
    demo: &demo::DemoTransfer,
) -> anyhow::Result<(
    Vec<application::NodeHandle<tokio::Context>>,
    mpsc::UnboundedReceiver<FinalizationEvent>,
)> {
    // Per-channel rate limit used by the simulated P2P transport in this example.
    let quota = Quota::per_second(NZU32!(1_000));
    let buffer_pool = PoolRef::new(NZU16!(16_384), NZUsize!(10_000));

    let (finalized_tx, finalized_rx) = mpsc::unbounded::<FinalizationEvent>();
    let mut nodes = Vec::with_capacity(participants.len());

    for (i, pk) in participants.iter().cloned().enumerate() {
        let handle = start_node(
            context,
            oracle,
            NodeInit {
                index: i,
                public_key: pk,
                scheme: schemes[i].clone(),
                quota,
                buffer_pool: buffer_pool.clone(),
                finalized_tx: finalized_tx.clone(),
                demo,
            },
        )
        .await?;
        nodes.push(handle);
    }

    Ok((nodes, finalized_rx))
}

/// Initialize and run a single node (QMDB/state + marshal + simplex engine).
async fn start_node(
    context: &tokio::Context,
    oracle: &mut simulated::Oracle<Peer, tokio::Context>,
    init: NodeInit<'_>,
) -> anyhow::Result<application::NodeHandle<tokio::Context>> {
    let NodeInit {
        index,
        public_key,
        scheme,
        quota,
        buffer_pool,
        finalized_tx,
        demo,
    } = init;

    let mut control = oracle.control(public_key.clone());
    let blocker = control.clone();

    let NodeChannels {
        votes,
        certs,
        resolver,
        blocks,
        backfill,
    } = register_channels(&mut control, quota).await?;

    let block_cfg = block_codec_cfg();
    let state = application::LedgerView::init(
        context.with_label(&format!("state_{index}")),
        buffer_pool.clone(),
        format!("revm-qmdb-{index}"),
        demo.alloc.clone(),
    )
    .await
    .context("init qmdb")?;

    let ledger = application::LedgerService::new(state.clone());
    let mut domain_events = ledger.subscribe();
    let finalized_tx_clone = finalized_tx.clone();
    let node_id = index as u32;
    let event_context = context.clone();
    event_context.spawn(move |_| async move {
        while let Some(event) = domain_events.next().await {
            if let DomainEvent::SnapshotPersisted(digest) = event {
                let _ = finalized_tx_clone.unbounded_send((node_id, digest));
            }
        }
    });
    let handle = application::NodeHandle::new(ledger.clone(), context.clone());
    let app =
        application::RevmApplication::<ThresholdScheme>::new(BLOCK_CODEC_MAX_TXS, state.clone());

    let finalized_reporter = application::FinalizedReporter::new(ledger.clone(), context.clone());

    let marshal_mailbox = start_marshal(
        context,
        MarshalStart {
            index,
            public_key: public_key.clone(),
            control: control.clone(),
            manager: oracle.manager(),
            scheme: scheme.clone(),
            buffer_pool: buffer_pool.clone(),
            block_codec_config: block_cfg,
            blocks,
            backfill,
            application: finalized_reporter,
        },
    )
    .await?;

    // Adapt the application to simplex by delegating full-block dissemination/backfill to marshal.
    let epocher = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
    let marshaled = Marshaled::new(
        context.with_label(&format!("marshaled_{index}")),
        app,
        marshal_mailbox.clone(),
        epocher,
    );

    let seed_reporter = application::SeedReporter::<MinSig>::new(ledger.clone());
    // Feed both the application-specific reporter (seed hashing) and marshal itself with simplex
    // activity (notarizations/finalizations).
    let reporter = Reporters::from((seed_reporter, marshal_mailbox.clone()));

    // Submit the demo transfer before starting consensus so the first leader can
    // include it without relying on a hardcoded "height == 1" rule.
    let _ = handle.submit_tx(demo.tx.clone()).await;

    let engine = simplex::Engine::new(
        context.with_label(&format!("engine_{index}")),
        simplex::Config {
            scheme,
            elector: Random,
            blocker,
            automaton: marshaled.clone(),
            relay: marshaled,
            reporter,
            strategy: Sequential,
            partition: format!("revm-{index}"),
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            leader_timeout: Duration::from_secs(1),
            notarization_timeout: Duration::from_secs(2),
            nullify_retry: Duration::from_secs(5),
            fetch_timeout: Duration::from_secs(1),
            activity_timeout: ViewDelta::new(20),
            skip_timeout: ViewDelta::new(10),
            fetch_concurrent: 8,
            buffer_pool,
        },
    );
    engine.start(votes, certs, resolver);

    Ok(handle)
}

/// Register the simulated transport channels for a node with the oracle.
async fn register_channels(
    control: &mut simulated::Control<Peer, tokio::Context>,
    quota: Quota,
) -> anyhow::Result<NodeChannels> {
    let votes = control
        .register(CHANNEL_VOTES, quota)
        .await
        .context("register votes channel")?;
    let certs = control
        .register(CHANNEL_CERTS, quota)
        .await
        .context("register certs channel")?;
    let resolver = control
        .register(CHANNEL_RESOLVER, quota)
        .await
        .context("register resolver channel")?;
    let blocks = control
        .register(CHANNEL_BLOCKS, quota)
        .await
        .context("register blocks channel")?;
    let backfill = control
        .register(CHANNEL_BACKFILL, quota)
        .await
        .context("register backfill channel")?;

    Ok(NodeChannels {
        votes,
        certs,
        resolver,
        blocks,
        backfill,
    })
}

/// Default block codec configuration for REVM transactions.
const fn block_codec_cfg() -> crate::types::BlockCfg {
    crate::types::BlockCfg {
        max_txs: BLOCK_CODEC_MAX_TXS,
        tx: crate::types::TxCfg {
            max_calldata_bytes: BLOCK_CODEC_MAX_CALLDATA,
        },
    }
}

/// Wire up the marshal actor for block dissemination/backfill and finalized reporting.
async fn start_marshal<M>(
    context: &tokio::Context,
    start: MarshalStart<M>,
) -> anyhow::Result<marshal::Mailbox<ThresholdScheme, crate::Block>>
where
    M: commonware_p2p::Manager<PublicKey = Peer>,
{
    let MarshalStart {
        index,
        public_key,
        control,
        manager,
        scheme,
        buffer_pool,
        block_codec_config,
        blocks,
        backfill,
        application,
    } = start;

    // Marshal wires together:
    // - a best-effort broadcast for blocks,
    // - a request/response resolver for ancestor backfill, and
    // - local archives for finalized blocks and certificates.
    let ctx = context.with_label(&format!("marshal_{index}"));
    let partition_prefix = format!("revm-marshal-{index}");
    let scheme_provider = ConstantSchemeProvider::from(scheme.clone());

    let resolver_cfg = marshal::resolver::p2p::Config {
        public_key: public_key.clone(),
        manager,
        blocker: control.clone(),
        mailbox_size: MAILBOX_SIZE,
        initial: Duration::from_millis(200),
        timeout: Duration::from_millis(200),
        fetch_retry_timeout: Duration::from_millis(100),
        priority_requests: false,
        priority_responses: false,
    };
    let resolver = marshal::resolver::p2p::init(&ctx, resolver_cfg, backfill);

    let broadcast_cfg = buffered::Config {
        public_key: public_key.clone(),
        mailbox_size: MAILBOX_SIZE,
        deque_size: 10,
        priority: false,
        codec_config: block_codec_config,
    };
    let (broadcast_engine, buffer) =
        buffered::Engine::<_, Peer, crate::Block>::new(ctx.with_label("broadcast"), broadcast_cfg);
    broadcast_engine.start(blocks);

    let finalizations_by_height = immutable::Archive::init(
        ctx.with_label("finalizations_by_height"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
            freezer_table_partition: format!("{partition_prefix}-finalizations-by-height-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{partition_prefix}-finalizations-by-height-freezer-key"),
            freezer_key_buffer_pool: buffer_pool.clone(),
            freezer_value_partition: format!("{partition_prefix}-finalizations-by-height-freezer-value"),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
            items_per_section: NZU64!(10),
            freezer_key_write_buffer: NZUsize!(1024 * 1024),
            freezer_value_write_buffer: NZUsize!(1024 * 1024),
            ordinal_write_buffer: NZUsize!(1024 * 1024),
            replay_buffer: NZUsize!(1024 * 1024),
            codec_config: <ThresholdScheme as commonware_cryptography::certificate::Scheme>::certificate_codec_config_unbounded(),
        },
    )
    .await
    .context("init finalizations archive")?;

    let finalized_blocks = immutable::Archive::init(
        ctx.with_label("finalized_blocks"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
            freezer_table_partition: format!("{partition_prefix}-finalized-blocks-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{partition_prefix}-finalized-blocks-freezer-key"),
            freezer_key_buffer_pool: buffer_pool.clone(),
            freezer_value_partition: format!("{partition_prefix}-finalized-blocks-freezer-value"),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalized-blocks-ordinal"),
            items_per_section: NZU64!(10),
            freezer_key_write_buffer: NZUsize!(1024 * 1024),
            freezer_value_write_buffer: NZUsize!(1024 * 1024),
            ordinal_write_buffer: NZUsize!(1024 * 1024),
            replay_buffer: NZUsize!(1024 * 1024),
            codec_config: block_codec_config,
        },
    )
    .await
    .context("init blocks archive")?;

    let epocher = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
    let (actor, mailbox, _last_processed_height) = marshal::Actor::init(
        ctx.clone(),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: scheme_provider,
            epocher,
            partition_prefix,
            mailbox_size: MAILBOX_SIZE,
            view_retention_timeout: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(10),
            buffer_pool,
            replay_buffer: NZUsize!(1024 * 1024),
            key_write_buffer: NZUsize!(1024 * 1024),
            value_write_buffer: NZUsize!(1024 * 1024),
            block_codec_config,
            max_repair: NZUsize!(16),
            strategy: Sequential,
        },
    )
    .await;
    actor.start(application, buffer, resolver);
    Ok(mailbox)
}
