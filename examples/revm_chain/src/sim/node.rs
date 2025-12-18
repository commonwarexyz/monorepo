//! Node wiring for the deterministic simulation.
//!
//! Each node runs:
//! - a marshal instance (block dissemination, backfill, and finalized block delivery), and
//! - a threshold-simplex engine instance that orders opaque digests.

use super::{
    demo, simplex, ThresholdScheme, BLOCK_CODEC_MAX_CALLDATA, BLOCK_CODEC_MAX_TXS,
    CHANNEL_BACKFILL, CHANNEL_BLOCKS, CHANNEL_CERTS, CHANNEL_RESOLVER, CHANNEL_VOTES, MAILBOX_SIZE,
};
use crate::{application, consensus};
use anyhow::Context as _;
use commonware_broadcast::buffered;
use commonware_consensus::{
    application::marshaled::Marshaled,
    marshal,
    types::{Epoch, ViewDelta},
    Reporters,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519};
use commonware_p2p::{simulated, utils::requester};
use commonware_runtime::{buffer::PoolRef, deterministic, Metrics as _};
use commonware_storage::archive::immutable;
use commonware_utils::{NZUsize, NZU32, NZU64};
use futures::channel::mpsc;
use governor::Quota;
use std::{sync::Arc, time::Duration};

type Peer = ed25519::PublicKey;
type ChannelSender = simulated::Sender<Peer>;
type ChannelReceiver = simulated::Receiver<Peer>;

// This example keeps everything in a single epoch for simplicity. The `Marshaled` wrapper also
// supports epoch boundaries, but exercising that logic is out-of-scope for this demo.
const EPOCH_LENGTH: u64 = u64::MAX;

#[derive(Clone)]
struct ConstantSchemeProvider(Arc<ThresholdScheme>);

impl marshal::SchemeProvider for ConstantSchemeProvider {
    type Scheme = ThresholdScheme;

    fn scheme(&self, _epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        Some(self.0.clone())
    }

    fn certificate_verifier(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.0.clone())
    }
}

impl From<ThresholdScheme> for ConstantSchemeProvider {
    fn from(scheme: ThresholdScheme) -> Self {
        Self(Arc::new(scheme))
    }
}

struct NodeChannels {
    votes: (ChannelSender, ChannelReceiver),
    certs: (ChannelSender, ChannelReceiver),
    resolver: (ChannelSender, ChannelReceiver),
    blocks: (ChannelSender, ChannelReceiver),
    backfill: (ChannelSender, ChannelReceiver),
}

struct NodeInit<'a> {
    index: usize,
    public_key: Peer,
    scheme: ThresholdScheme,
    quota: Quota,
    buffer_pool: PoolRef,
    finalized_tx: mpsc::UnboundedSender<consensus::FinalizationEvent>,
    demo: &'a demo::DemoTransfer,
}

struct MarshalStart<M> {
    index: usize,
    public_key: Peer,
    control: simulated::Control<Peer>,
    manager: M,
    scheme: ThresholdScheme,
    buffer_pool: PoolRef,
    block_codec_config: crate::types::BlockCfg,
    blocks: (ChannelSender, ChannelReceiver),
    backfill: (ChannelSender, ChannelReceiver),
    application: application::FinalizedReporter,
}

/// Spawn all nodes (application + consensus) for a simulation run.
pub(super) async fn start_all_nodes(
    context: &deterministic::Context,
    oracle: &mut simulated::Oracle<ed25519::PublicKey>,
    participants: &[ed25519::PublicKey],
    schemes: &[ThresholdScheme],
    demo: &demo::DemoTransfer,
) -> anyhow::Result<(
    Vec<application::NodeHandle>,
    mpsc::UnboundedReceiver<consensus::FinalizationEvent>,
)> {
    // Per-channel rate limit used by the simulated P2P transport in this example.
    let quota = Quota::per_second(NZU32!(1_000));
    let buffer_pool = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

    let (finalized_tx, finalized_rx) = mpsc::unbounded::<consensus::FinalizationEvent>();
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

async fn start_node(
    context: &deterministic::Context,
    oracle: &mut simulated::Oracle<Peer>,
    init: NodeInit<'_>,
) -> anyhow::Result<application::NodeHandle> {
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
    let state = application::Shared::new(demo.alloc.clone());

    let handle = application::NodeHandle::new(state.clone());
    let app =
        application::RevmApplication::<ThresholdScheme>::new(BLOCK_CODEC_MAX_TXS, state.clone());

    let finalized_reporter =
        application::FinalizedReporter::new(index as u32, state.clone(), finalized_tx);

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
    let marshaled = Marshaled::new(
        context.with_label(&format!("marshaled_{index}")),
        app,
        marshal_mailbox.clone(),
        EPOCH_LENGTH,
    );

    let seed_reporter = application::SeedReporter::<MinSig>::new(state.clone());
    // Feed both the application-specific reporter (seed hashing) and marshal itself with simplex
    // activity (notarizations/finalizations).
    let reporter = Reporters::from((seed_reporter, marshal_mailbox.clone()));

    // Submit the deterministic demo transfer before starting consensus so the first leader can
    // include it without relying on a hardcoded "height == 1" rule.
    let _ = handle.submit_tx(demo.tx.clone()).await;

    let engine = simplex::Engine::new(
        context.with_label(&format!("engine_{index}")),
        simplex::Config {
            scheme,
            blocker,
            automaton: marshaled.clone(),
            relay: marshaled,
            reporter,
            partition: format!("revm-chain-{index}"),
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            namespace: b"revm-chain-consensus".to_vec(),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            leader_timeout: Duration::from_millis(50),
            notarization_timeout: Duration::from_millis(100),
            nullify_retry: Duration::from_millis(200),
            fetch_timeout: Duration::from_millis(200),
            activity_timeout: ViewDelta::new(10),
            skip_timeout: ViewDelta::new(5),
            fetch_concurrent: 16,
            fetch_rate_per_peer: Quota::per_second(NZU32!(10)),
            buffer_pool,
        },
    );
    engine.start(votes, certs, resolver);

    Ok(handle)
}

async fn register_channels(
    control: &mut simulated::Control<Peer>,
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

const fn block_codec_cfg() -> crate::types::BlockCfg {
    crate::types::BlockCfg {
        max_txs: BLOCK_CODEC_MAX_TXS,
        tx: crate::types::TxCfg {
            max_calldata_bytes: BLOCK_CODEC_MAX_CALLDATA,
        },
    }
}

async fn start_marshal<M>(
    context: &deterministic::Context,
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
    let partition_prefix = format!("revm-chain-marshal-{index}");
    let scheme_provider = ConstantSchemeProvider::from(scheme.clone());

    let resolver_cfg = marshal::resolver::p2p::Config {
        public_key: public_key.clone(),
        manager,
        blocker: control.clone(),
        mailbox_size: MAILBOX_SIZE,
        requester_config: requester::Config {
            me: Some(public_key.clone()),
            rate_limit: Quota::per_second(NZU32!(10)),
            initial: Duration::from_millis(200),
            timeout: Duration::from_millis(200),
        },
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
            freezer_journal_partition: format!("{partition_prefix}-finalizations-by-height-freezer-journal"),
            freezer_journal_target_size: 1024,
            freezer_journal_compression: None,
            freezer_journal_buffer_pool: buffer_pool.clone(),
            ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
            items_per_section: NZU64!(10),
            codec_config: <ThresholdScheme as commonware_consensus::simplex::signing_scheme::Scheme>::certificate_codec_config_unbounded(),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
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
            freezer_journal_partition: format!(
                "{partition_prefix}-finalized-blocks-freezer-journal"
            ),
            freezer_journal_target_size: 1024,
            freezer_journal_compression: None,
            freezer_journal_buffer_pool: buffer_pool.clone(),
            ordinal_partition: format!("{partition_prefix}-finalized-blocks-ordinal"),
            items_per_section: NZU64!(10),
            codec_config: block_codec_config,
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
        },
    )
    .await
    .context("init blocks archive")?;

    let (actor, mailbox) = marshal::Actor::init(
        ctx.clone(),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            scheme_provider,
            epoch_length: EPOCH_LENGTH,
            partition_prefix,
            mailbox_size: MAILBOX_SIZE,
            view_retention_timeout: ViewDelta::new(10),
            namespace: b"revm-chain-marshal".to_vec(),
            prunable_items_per_section: NZU64!(10),
            buffer_pool,
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            block_codec_config,
            max_repair: NZUsize!(16),
            _marker: std::marker::PhantomData,
        },
    )
    .await;
    actor.start(application, buffer, resolver);
    Ok(mailbox)
}
