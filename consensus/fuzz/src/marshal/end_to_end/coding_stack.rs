//! Coding-variant validator and engine setup for the multi-node liveness
//! runner, generic over the consensus scheme.
//!
//! Mirrors the standard stack in [`super::twins::stack`], with two differences
//! the coding variant requires: shard dissemination replaces the buffered
//! broadcast engine on the block channel, and the Simplex automaton/relay is
//! the [`Marshaled`] wrapper (whose consensus payload is a `Commitment` rather
//! than a `Sha256Digest`).

use super::{
    ENGINE_CERTIFICATE, ENGINE_RESOLVER, ENGINE_VOTE,
    app::{AlwaysAcceptBlockBuilderApp, DeliveryReporter},
    twins::{PublicKeyOf, SchemeOf},
};
use crate::SimplexCertificateMock;

/// The coding liveness target runs on the cheap certificate mock.
pub(crate) type P = SimplexCertificateMock;
use commonware_coding::{CodecConfig, ReedSolomon};
use commonware_consensus::{
    marshal::{
        Config, Start,
        coding::{
            Coding, Marshaled, MarshaledConfig, shards,
            types::{CodedBlock, hash_context},
        },
        core::{Actor, Mailbox},
        mocks::{
            application::Application,
            block::Block as MockBlock,
            harness::{
                BLOCKS_PER_EPOCH, GENESIS_CODING_CONFIG, PAGE_CACHE_SIZE, PAGE_SIZE, TEST_QUOTA,
                make_coding_genesis_block,
            },
        },
        resolver::p2p as resolver,
    },
    simplex::{
        Engine, Floor, ForwardingPolicy, config, elector::Config as ElectorConfig,
        types::Context as SimplexContext,
    },
    types::{Delta, Epoch, FixedEpocher, ViewDelta, coding::Commitment},
};
use commonware_cryptography::{
    Digestible as _, Sha256,
    certificate::{ConstantProvider, Verifier as _},
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::Oracle;
use commonware_parallel::Sequential;
use commonware_runtime::{Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::archive::immutable;
use commonware_utils::{NZU64, NZUsize};
use std::{num::NonZeroUsize, time::Duration};

/// Consensus context for the coding variant: the payload is a `Commitment`.
pub(crate) type CodingCtx = SimplexContext<Commitment, PublicKeyOf<P>>;

/// Application block carried by the coding stack.
pub(crate) type CodingB = MockBlock<Sha256Digest, CodingCtx>;

/// Marshal variant for the coding stack.
pub(crate) type CodingVariant = Coding<CodingB, ReedSolomon<Sha256>, Sha256, PublicKeyOf<P>>;

/// Erasure-coded block the marshal actor stores; the raw [`CodingB`] is what
/// marshal delivers to the application sink.
pub(crate) type CodingCoded = CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>;

/// Shard dissemination mailbox handed to the marshal actor and the engine.
pub(crate) type ShardsMailbox =
    shards::Mailbox<CodingB, ReedSolomon<Sha256>, Sha256, PublicKeyOf<P>>;

/// One coding validator: the marshal mailbox, the delivery sink, and the shard
/// mailbox the engine needs to disseminate and reconstruct blocks.
pub(crate) struct CodingValidator {
    pub(crate) mailbox: Mailbox<SchemeOf<P>, CodingVariant>,
    pub(crate) application: Application<CodingB>,
    pub(crate) shards: ShardsMailbox,
}

/// Builds one coding validator's marshal actor, resolver, and shard engine.
///
/// Mirrors [`super::twins::stack::setup_validator`] except that the block
/// channel carries shards rather than buffered blocks.
pub(crate) async fn setup_validator_coding(
    context: deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    provider: ConstantProvider<SchemeOf<P>, Epoch>,
    genesis: CodingCoded,
    max_pending_acks: NonZeroUsize,
    validator_idx: usize,
) -> CodingValidator {
    let application = Application::<CodingB>::manual_ack();
    let acknowledger = application.clone();
    context.child("acknowledger").spawn(move |_| async move {
        loop {
            acknowledger.acknowledged().await;
        }
    });
    let delivery_reporter = DeliveryReporter::new(
        validator_idx,
        application.clone(),
        Some(max_pending_acks),
        "marshal-coding-liveness".into(),
    );
    let config = Config {
        provider: provider.clone(),
        epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        start: Start::Genesis(genesis),
        mailbox_size: NZUsize!(100),
        view_retention: ViewDelta::new(10),
        max_repair: NZUsize!(10),
        max_pending_acks,
        block_codec_config: (),
        partition_prefix: format!("validator-{validator}"),
        prunable_items_per_section: NZU64!(10),
        replay_buffer: NZUsize!(1024),
        key_write_buffer: NZUsize!(1024),
        value_write_buffer: NZUsize!(1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
    };

    let control = oracle.control(validator.clone());
    let backfill = control.register(1, TEST_QUOTA).await.unwrap();
    let resolver = resolver::init(
        context.child("resolver"),
        resolver::Config {
            public_key: validator.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        backfill,
    );

    // Coding disseminates shards on the block channel instead of whole blocks.
    let shard_config: shards::Config<_, _, _, _, _, Sha256, _, _> = shards::Config {
        scheme_provider: provider,
        blocker: oracle.control(validator.clone()),
        shard_codec_cfg: CodecConfig {
            maximum_shard_size: 1024 * 1024,
        },
        block_codec_cfg: (),
        strategy: Sequential,
        mailbox_size: NZUsize!(10),
        peer_buffer_size: NZUsize!(64),
        background_channel_capacity: NZUsize!(1024),
        peer_provider: oracle.manager(),
    };
    let (shard_engine, shard_mailbox) = shards::Engine::new(context.child("shards"), shard_config);
    let network = control.register(2, TEST_QUOTA).await.unwrap();
    shard_engine.start(network);

    let finalizations_by_height = immutable::Archive::init(
        context.child("finalizations_by_height"),
        immutable::Config {
            metadata_partition: format!(
                "{}-finalizations-by-height-metadata",
                config.partition_prefix
            ),
            freezer_table_partition: format!(
                "{}-finalizations-by-height-freezer-table",
                config.partition_prefix
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{}-finalizations-by-height-freezer-key",
                config.partition_prefix
            ),
            freezer_key_page_cache: config.page_cache.clone(),
            freezer_value_partition: format!(
                "{}-finalizations-by-height-freezer-value",
                config.partition_prefix
            ),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!(
                "{}-finalizations-by-height-ordinal",
                config.partition_prefix
            ),
            items_per_section: NZU64!(10),
            codec_config: SchemeOf::<P>::certificate_codec_config_unbounded(),
            replay_buffer: config.replay_buffer,
            freezer_key_write_buffer: config.key_write_buffer,
            freezer_value_write_buffer: config.value_write_buffer,
            ordinal_write_buffer: config.key_write_buffer,
        },
    )
    .await
    .expect("failed to initialize finalizations by height archive");
    let finalized_blocks = immutable::Archive::init(
        context.child("finalized_blocks"),
        immutable::Config {
            metadata_partition: format!("{}-finalized-blocks-metadata", config.partition_prefix),
            freezer_table_partition: format!(
                "{}-finalized-blocks-freezer-table",
                config.partition_prefix
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{}-finalized-blocks-freezer-key",
                config.partition_prefix
            ),
            freezer_key_page_cache: config.page_cache.clone(),
            freezer_value_partition: format!(
                "{}-finalized-blocks-freezer-value",
                config.partition_prefix
            ),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{}-finalized-blocks-ordinal", config.partition_prefix),
            items_per_section: NZU64!(10),
            codec_config: config.block_codec_config,
            replay_buffer: config.replay_buffer,
            freezer_key_write_buffer: config.key_write_buffer,
            freezer_value_write_buffer: config.value_write_buffer,
            ordinal_write_buffer: config.key_write_buffer,
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive");

    let (actor, mailbox, _) = Actor::init(
        context.child("actor"),
        finalizations_by_height,
        finalized_blocks,
        config,
    )
    .await;
    actor.start(delivery_reporter, shard_mailbox.clone(), resolver);

    CodingValidator {
        mailbox,
        application,
        shards: shard_mailbox,
    }
}

/// Starts the Simplex engine for one coding validator.
///
/// The automaton and relay are the [`Marshaled`] wrapper, so the consensus
/// payload is a `Commitment` reconstructed from disseminated shards.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_engine_coding<EC>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    scheme: SchemeOf<P>,
    elector: EC,
    provider: ConstantProvider<SchemeOf<P>, Epoch>,
    marshal_mailbox: Mailbox<SchemeOf<P>, CodingVariant>,
    shards: ShardsMailbox,
    genesis_commitment: Commitment,
    forwarding: ForwardingPolicy,
) where
    EC: ElectorConfig<SchemeOf<P>> + Clone + Send + 'static,
{
    let control = oracle.control(validator.clone());
    let vote = control.register(ENGINE_VOTE, TEST_QUOTA).await.unwrap();
    let certificate = control
        .register(ENGINE_CERTIFICATE, TEST_QUOTA)
        .await
        .unwrap();
    let resolver = control.register(ENGINE_RESOLVER, TEST_QUOTA).await.unwrap();

    let marshaled = Marshaled::new(
        context.child("marshaled"),
        MarshaledConfig {
            application: AlwaysAcceptBlockBuilderApp::<CodingCtx, SchemeOf<P>>::default(),
            marshal: marshal_mailbox.clone(),
            shards,
            scheme_provider: provider,
            strategy: Sequential,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        },
    );
    let engine = Engine::new(
        context.child("engine"),
        config::Config {
            blocker: oracle.control(validator.clone()),
            scheme,
            elector,
            automaton: marshaled.clone(),
            relay: marshaled,
            reporter: marshal_mailbox,
            partition: format!("engine-{validator}"),
            mailbox_size: NZUsize!(1024),
            epoch: Epoch::zero(),
            floor: Floor::Genesis(genesis_commitment),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            view_retention: Delta::new(10),
            skip_timeout: Duration::from_secs(11),
            fetch_concurrent: NZUsize!(1),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
            forwarding,
        },
    );
    engine.start(vote, certificate, resolver);
}

/// Genesis coded block shared by every coding validator and by the consensus
/// floor, so view-1 proposals link to the block marshal already holds.
pub(crate) fn coding_genesis() -> CodingCoded {
    let inner = make_coding_genesis_block();
    let commitment = Commitment::from((
        inner.digest(),
        inner.digest(),
        hash_context::<Sha256, _>(&inner.context),
        GENESIS_CODING_CONFIG,
    ));
    CodedBlock::new_trusted(inner, commitment)
}
