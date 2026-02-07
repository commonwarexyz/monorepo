use super::config::{
    ChannelReceiver, ChannelSender, Peer, ThresholdScheme, EPOCH_LENGTH, MAILBOX_SIZE,
};
use crate::{
    application::FinalizedReporter,
    domain::{Block, BlockCfg},
};
use anyhow::Context as _;
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal,
    types::{Epoch, FixedEpocher},
};
use commonware_p2p::simulated;
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, tokio, Metrics as _};
use commonware_storage::archive::immutable;
use commonware_utils::{NZUsize, NZU64};
use std::{sync::Arc, time::Duration};

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

pub(super) struct MarshalStart<M> {
    /// Node index used for naming partitions/metrics.
    pub(super) index: usize,
    /// Base prefix used for marshal partitions.
    pub(super) partition_prefix: String,
    /// Node identity key used for network links.
    pub(super) public_key: Peer,
    /// Control channel used to register and rate-limit transport channels.
    pub(super) control: simulated::Control<Peer, tokio::Context>,
    /// P2P manager holding the transport/peering state.
    pub(super) manager: M,
    /// Threshold signing scheme for this node.
    pub(super) scheme: ThresholdScheme,
    /// Page cache that backs all storage archives.
    pub(super) page_cache: CacheRef,
    /// Codec settings for block serialization.
    pub(super) block_codec_config: BlockCfg,
    /// Channels used for block broadcasts.
    pub(super) blocks: (ChannelSender, ChannelReceiver),
    /// Channels used for marshal backfill requests/responses.
    pub(super) backfill: (ChannelSender, ChannelReceiver),
    /// Application-level reporter that observes finalized blocks.
    pub(super) application: FinalizedReporter,
}

/// Wire up the marshal actor for block dissemination/backfill and finalized reporting.
pub(super) async fn start_marshal<M>(
    context: &tokio::Context,
    start: MarshalStart<M>,
) -> anyhow::Result<marshal::Mailbox<ThresholdScheme, Block>>
where
    M: commonware_p2p::Manager<PublicKey = Peer>,
{
    let MarshalStart {
        index,
        partition_prefix,
        public_key,
        control,
        manager,
        scheme,
        page_cache,
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
    let partition_prefix = format!("{partition_prefix}-marshal-{index}");
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
        buffered::Engine::<_, Peer, Block>::new(ctx.with_label("broadcast"), broadcast_cfg);
    broadcast_engine.start(blocks);

    let finalizations_by_height = immutable::Archive::init(
        ctx.with_label("finalizations_by_height"),
        immutable::Config {
            metadata_partition: format!(
                "{partition_prefix}-finalizations-by-height-metadata"
            ),
            freezer_table_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-table"
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-key"
            ),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-value"
            ),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!(
                "{partition_prefix}-finalizations-by-height-ordinal"
            ),
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
            freezer_key_page_cache: page_cache.clone(),
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
            view_retention_timeout: commonware_consensus::types::ViewDelta::new(10),
            prunable_items_per_section: NZU64!(10),
            page_cache,
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
