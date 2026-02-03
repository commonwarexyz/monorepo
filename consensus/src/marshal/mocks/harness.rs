//! Test harness for marshal variants.
//!
//! This module provides a trait-based abstraction that allows writing tests once
//! and running them against both the standard and coding marshal variants.

use crate::{
    marshal::{
        coding::{
            shards,
            types::{coding_config_for_participants, CodedBlock, Shard},
            Coding,
        },
        config::Config,
        core::{Actor, Mailbox},
        mocks::{application::Application, block::Block},
        resolver::p2p as resolver,
        standard::Standard,
        Identifier,
    },
    simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Activity, Context, Finalization, Finalize, Notarization, Notarize, Proposal},
    },
    types::{CodingCommitment, Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
    Heightable, Reporter,
};
use commonware_broadcast::buffered;
use commonware_coding::{CodecConfig, ReedSolomon};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk,
    certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
    ed25519::{PrivateKey, PublicKey},
    sha256::{Digest as Sha256Digest, Sha256},
    Committable, Digest as DigestTrait, Digestible, Hasher as _, Signer,
};
use commonware_p2p::{
    simulated::{self, Link, Network, Oracle},
    Manager,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Clock, Metrics, Quota, Runner};
use commonware_storage::{
    archive::{immutable, prunable},
    translator::EightCap,
};
use commonware_utils::{vec::NonEmptyVec, NZUsize, Participant, NZU16, NZU64};
use futures::StreamExt;
use rand::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use std::{
    collections::BTreeMap,
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};
use tracing::info;

// Common type aliases
pub type D = Sha256Digest;
pub type K = PublicKey;
pub type Ctx = Context<D, K>;
pub type B = Block<D, Ctx>;
pub type V = MinPk;
pub type S = bls12381_threshold_vrf::Scheme<K, V>;
pub type P = ConstantProvider<S, Epoch>;

// Coding variant type aliases (uses CodingCommitment in context)
pub type CodingCtx = Context<CodingCommitment, K>;
pub type CodingB = Block<D, CodingCtx>;

// Common test constants
pub const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
pub const NAMESPACE: &[u8] = b"test";
pub const NUM_VALIDATORS: u32 = 4;
pub const QUORUM: u32 = 3;
pub const NUM_BLOCKS: u64 = 160;
pub const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(20);
pub const LINK: Link = Link {
    latency: Duration::from_millis(100),
    jitter: Duration::from_millis(1),
    success_rate: 1.0,
};
pub const UNRELIABLE_LINK: Link = Link {
    latency: Duration::from_millis(200),
    jitter: Duration::from_millis(50),
    success_rate: 0.7,
};
pub const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// Default leader key for tests.
pub fn default_leader() -> K {
    PrivateKey::from_seed(0).public_key()
}

/// Create a raw test block with a derived context.
pub fn make_raw_block(parent: D, height: Height, timestamp: u64) -> B {
    let parent_view = height
        .previous()
        .map(|h| View::new(h.get()))
        .unwrap_or(View::zero());
    let context = Ctx {
        round: Round::new(Epoch::zero(), View::new(height.get())),
        leader: default_leader(),
        parent: (parent_view, parent),
    };
    B::new::<Sha256>(context, parent, height, timestamp)
}

/// Setup network for tests.
pub fn setup_network(
    context: deterministic::Context,
    tracked_peer_sets: Option<usize>,
) -> Oracle<K, deterministic::Context> {
    let (network, oracle) = Network::new(
        context.with_label("network"),
        simulated::Config {
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets,
        },
    );
    network.start();
    oracle
}

/// Setup network links between peers.
pub async fn setup_network_links(
    oracle: &mut Oracle<K, deterministic::Context>,
    peers: &[K],
    link: Link,
) {
    for p1 in peers.iter() {
        for p2 in peers.iter() {
            if p2 == p1 {
                continue;
            }
            let _ = oracle.add_link(p1.clone(), p2.clone(), link.clone()).await;
        }
    }
}

/// Result of setting up a validator.
pub struct ValidatorSetup<H: TestHarness> {
    pub application: Application<H::ApplicationBlock>,
    pub mailbox: Mailbox<S, H::Variant>,
    pub extra: H::ValidatorExtra,
    pub height: Height,
}

/// Per-validator handle for test operations.
pub struct ValidatorHandle<H: TestHarness> {
    pub mailbox: Mailbox<S, H::Variant>,
    pub extra: H::ValidatorExtra,
}

impl<H: TestHarness> Clone for ValidatorHandle<H> {
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
            extra: self.extra.clone(),
        }
    }
}

/// A test harness that abstracts over marshal variant differences.
pub trait TestHarness: 'static + Sized {
    /// The application block type.
    /// Note: We require `Digestible<Digest = D>` so generic test functions can use
    /// `subscribe_by_digest` which expects the block's digest type.
    type ApplicationBlock: crate::Block + Digestible<Digest = D> + Clone + Send + 'static;

    /// The marshal variant type.
    type Variant: crate::marshal::core::Variant<
        ApplicationBlock = Self::ApplicationBlock,
        Commitment = Self::Commitment,
    >;

    /// The block type used in test operations.
    type TestBlock: Heightable + Clone + Send;

    /// Additional per-validator state (e.g., shards mailbox for coding).
    type ValidatorExtra: Clone + Send;

    /// The commitment type for consensus certificates.
    type Commitment: DigestTrait;

    /// Setup a single validator with all necessary infrastructure.
    fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> impl Future<Output = ValidatorSetup<Self>> + Send;

    /// Create a test block from parent and height.
    fn make_test_block(
        parent: D,
        height: Height,
        timestamp: u64,
        num_participants: u16,
    ) -> Self::TestBlock;

    /// Get the commitment from a test block.
    fn commitment(block: &Self::TestBlock) -> Self::Commitment;

    /// Get the digest from a test block.
    fn digest(block: &Self::TestBlock) -> D;

    /// Get the height from a test block.
    fn height(block: &Self::TestBlock) -> Height;

    /// Propose a block (broadcast to network).
    fn propose(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
        participants: &[K],
    ) -> impl Future<Output = ()> + Send;

    /// Mark a block as verified.
    fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
        all_handles: &mut [ValidatorHandle<Self>],
    ) -> impl Future<Output = ()> + Send;

    /// Create a finalization certificate.
    fn make_finalization(
        proposal: Proposal<Self::Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Finalization<S, Self::Commitment>;

    /// Create a notarization certificate.
    fn make_notarization(
        proposal: Proposal<Self::Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Notarization<S, Self::Commitment>;

    /// Report a finalization to the mailbox.
    fn report_finalization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        finalization: Finalization<S, Self::Commitment>,
    ) -> impl Future<Output = ()> + Send;

    /// Report a notarization to the mailbox.
    fn report_notarization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        notarization: Notarization<S, Self::Commitment>,
    ) -> impl Future<Output = ()> + Send;

    /// Get the timeout duration for the finalize test.
    fn finalize_timeout() -> Duration;

    /// Setup validator for pruning test with prunable archives.
    #[allow(clippy::type_complexity)]
    fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[S],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> impl Future<
        Output = (
            Mailbox<S, Self::Variant>,
            Self::ValidatorExtra,
            Application<Self::ApplicationBlock>,
        ),
    > + Send;

    /// Verify a block for the pruning test (simpler than full verify).
    fn verify_for_prune(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
        participants: &[K],
    ) -> impl Future<Output = ()> + Send;
}

// =============================================================================
// Standard Harness Implementation
// =============================================================================

/// Standard variant test harness.
pub struct StandardHarness;

impl TestHarness for StandardHarness {
    type ApplicationBlock = B;
    type Variant = Standard<B>;
    type TestBlock = B;
    type ValidatorExtra = ();
    type Commitment = D;

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> ValidatorSetup<Self> {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        let control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            manager: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(&context, resolver_cfg, backfill);

        let broadcast_config = buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
        };
        let (broadcast_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);
        let network = control.register(2, TEST_QUOTA).await.unwrap();
        broadcast_engine.start(network);

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
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

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
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{}-finalized_blocks-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
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
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let (actor, mailbox, height) = Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<B>::default();
        actor.start(application.clone(), buffer, resolver);

        ValidatorSetup {
            application,
            mailbox,
            extra: (),
            height,
        }
    }

    fn make_test_block(parent: D, height: Height, timestamp: u64, _num_participants: u16) -> B {
        make_raw_block(parent, height, timestamp)
    }

    fn commitment(block: &B) -> D {
        block.digest()
    }

    fn digest(block: &B) -> D {
        block.digest()
    }

    fn height(block: &B) -> Height {
        block.height()
    }

    async fn propose(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &B,
        _participants: &[K],
    ) {
        handle.mailbox.proposed(round, block.clone(), ()).await;
    }

    async fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &B,
        _all_handles: &mut [ValidatorHandle<Self>],
    ) {
        handle.mailbox.verified(round, block.clone()).await;
    }

    fn make_finalization(proposal: Proposal<D>, schemes: &[S], quorum: u32) -> Finalization<S, D> {
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
    }

    fn make_notarization(proposal: Proposal<D>, schemes: &[S], quorum: u32) -> Notarization<S, D> {
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        finalization: Finalization<S, D>,
    ) {
        mailbox.report(Activity::Finalization(finalization)).await;
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        notarization: Notarization<S, D>,
    ) {
        mailbox.report(Activity::Notarization(notarization)).await;
    }

    fn finalize_timeout() -> Duration {
        Duration::from_secs(600)
    }

    async fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[S],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> (
        Mailbox<S, Self::Variant>,
        Self::ValidatorExtra,
        Application<B>,
    ) {
        let control = oracle.control(validator.clone());
        let provider = ConstantProvider::new(schemes[0].clone());
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            block_codec_config: (),
            partition_prefix: partition_prefix.to_string(),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: page_cache.clone(),
            strategy: Sequential,
        };

        let backfill = control.register(0, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            manager: oracle.manager(),
            blocker: control.clone(),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(&context, resolver_cfg, backfill);

        let broadcast_config = buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
        };
        let (broadcast_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);
        let network = control.register(1, TEST_QUOTA).await.unwrap();
        broadcast_engine.start(network);

        let finalizations_by_height = prunable::Archive::init(
            context.with_label("finalizations_by_height"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{}-finalizations-by-height-key", partition_prefix),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{}-finalizations-by-height-value", partition_prefix),
                compression: None,
                codec_config: S::certificate_codec_config_unbounded(),
                items_per_section: NZU64!(10),
                key_write_buffer: config.key_write_buffer,
                value_write_buffer: config.value_write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");

        let finalized_blocks = prunable::Archive::init(
            context.with_label("finalized_blocks"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{}-finalized-blocks-key", partition_prefix),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{}-finalized-blocks-value", partition_prefix),
                compression: None,
                codec_config: config.block_codec_config,
                items_per_section: NZU64!(10),
                key_write_buffer: config.key_write_buffer,
                value_write_buffer: config.value_write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        let (actor, mailbox, _) = Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<B>::default();
        actor.start(application.clone(), buffer, resolver);

        (mailbox, (), application)
    }

    async fn verify_for_prune(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &B,
        _participants: &[K],
    ) {
        handle.mailbox.verified(round, block.clone()).await;
    }
}

// =============================================================================
// Coding Harness Implementation
// =============================================================================

/// Coding variant test harness.
pub struct CodingHarness;

type CodingVariant = Coding<CodingB, ReedSolomon<Sha256>, K>;
type ShardsMailbox = shards::Mailbox<CodingB, S, ReedSolomon<Sha256>, K>;

/// Genesis blocks use a special coding config that doesn't actually encode.
pub const GENESIS_CODING_CONFIG: commonware_coding::Config = commonware_coding::Config {
    minimum_shards: 0,
    extra_shards: 0,
};

/// Create a genesis CodingCommitment (all zeros for digests, genesis config).
pub fn genesis_commitment() -> CodingCommitment {
    CodingCommitment::from((
        D::EMPTY,
        D::EMPTY,
        Sha256Digest::EMPTY,
        GENESIS_CODING_CONFIG,
    ))
}

/// Create a test block with a CodingCommitment-based context.
pub fn make_coding_block(context: CodingCtx, parent: D, height: Height, timestamp: u64) -> CodingB {
    CodingB::new::<Sha256>(context, parent, height, timestamp)
}

impl TestHarness for CodingHarness {
    type ApplicationBlock = CodingB;
    type Variant = CodingVariant;
    type TestBlock = CodedBlock<CodingB, ReedSolomon<Sha256>>;
    type ValidatorExtra = ShardsMailbox;
    type Commitment = CodingCommitment;

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> ValidatorSetup<Self> {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        let control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            manager: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(&context, resolver_cfg, backfill);

        let broadcast_config = buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: CodecConfig {
                maximum_shard_size: 1024 * 1024,
            },
        };
        let (broadcast_engine, buffer) =
            buffered::Engine::<_, _, Shard<ReedSolomon<Sha256>, Sha256>>::new(
                context.clone(),
                broadcast_config,
            );
        let network = control.register(2, TEST_QUOTA).await.unwrap();
        broadcast_engine.start(network);

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
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

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
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{}-finalized_blocks-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
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
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let (shard_engine, shard_mailbox) =
            shards::Engine::new(context.clone(), buffer, (), config.mailbox_size, Sequential);
        shard_engine.start();

        let (actor, mailbox, height) = Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<CodingB>::default();
        actor.start(application.clone(), shard_mailbox.clone(), resolver);

        ValidatorSetup {
            application,
            mailbox,
            extra: shard_mailbox,
            height,
        }
    }

    fn make_test_block(
        parent: D,
        height: Height,
        timestamp: u64,
        num_participants: u16,
    ) -> CodedBlock<CodingB, ReedSolomon<Sha256>> {
        let parent_view = height
            .previous()
            .map(|h| View::new(h.get()))
            .unwrap_or(View::zero());
        let parent_commitment = CodingCommitment::from((
            parent,
            parent,
            Sha256Digest::EMPTY,
            coding_config_for_participants(num_participants),
        ));
        let context = CodingCtx {
            round: Round::new(Epoch::zero(), View::new(height.get())),
            leader: default_leader(),
            parent: (parent_view, parent_commitment),
        };
        let raw = CodingB::new::<Sha256>(context, parent, height, timestamp);
        let coding_config = coding_config_for_participants(num_participants);
        CodedBlock::new(raw, coding_config, &Sequential)
    }

    fn commitment(block: &CodedBlock<CodingB, ReedSolomon<Sha256>>) -> CodingCommitment {
        block.commitment()
    }

    fn digest(block: &CodedBlock<CodingB, ReedSolomon<Sha256>>) -> D {
        block.digest()
    }

    fn height(block: &CodedBlock<CodingB, ReedSolomon<Sha256>>) -> Height {
        block.height()
    }

    async fn propose(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &CodedBlock<CodingB, ReedSolomon<Sha256>>,
        participants: &[K],
    ) {
        // Notify the marshal which handles caching and shard broadcast
        handle
            .mailbox
            .proposed(round, block.clone(), participants.to_vec())
            .await;
    }

    async fn verify(
        _handle: &mut ValidatorHandle<Self>,
        _round: Round,
        block: &CodedBlock<CodingB, ReedSolomon<Sha256>>,
        all_handles: &mut [ValidatorHandle<Self>],
    ) {
        // Ask each peer to validate their received shards
        for (i, h) in all_handles.iter_mut().enumerate() {
            let _recv = h
                .extra
                .subscribe_shard_validity(block.commitment(), Participant::new(i as u32))
                .await;
        }
    }

    fn make_finalization(
        proposal: Proposal<CodingCommitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Finalization<S, CodingCommitment> {
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
    }

    fn make_notarization(
        proposal: Proposal<CodingCommitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Notarization<S, CodingCommitment> {
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        finalization: Finalization<S, CodingCommitment>,
    ) {
        mailbox.report(Activity::Finalization(finalization)).await;
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        notarization: Notarization<S, CodingCommitment>,
    ) {
        mailbox.report(Activity::Notarization(notarization)).await;
    }

    fn finalize_timeout() -> Duration {
        Duration::from_secs(900)
    }

    async fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[S],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> (
        Mailbox<S, Self::Variant>,
        Self::ValidatorExtra,
        Application<CodingB>,
    ) {
        let control = oracle.control(validator.clone());
        let provider = ConstantProvider::new(schemes[0].clone());
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            block_codec_config: (),
            partition_prefix: partition_prefix.to_string(),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: page_cache.clone(),
            strategy: Sequential,
        };

        let backfill = control.register(0, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            manager: oracle.manager(),
            blocker: control.clone(),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(&context, resolver_cfg, backfill);

        let broadcast_config = buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: CodecConfig {
                maximum_shard_size: 1024 * 1024,
            },
        };
        let (broadcast_engine, buffer) =
            buffered::Engine::<_, _, Shard<ReedSolomon<Sha256>, Sha256>>::new(
                context.clone(),
                broadcast_config,
            );
        let network = control.register(1, TEST_QUOTA).await.unwrap();
        broadcast_engine.start(network);

        let (shard_engine, shard_mailbox) = shards::Engine::<_, S, _, _, CodingB, K, _>::new(
            context.clone(),
            buffer,
            (),
            config.mailbox_size,
            Sequential,
        );
        shard_engine.start();

        let finalizations_by_height = prunable::Archive::init(
            context.with_label("finalizations_by_height"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{}-finalizations-by-height-key", partition_prefix),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{}-finalizations-by-height-value", partition_prefix),
                compression: None,
                codec_config: S::certificate_codec_config_unbounded(),
                items_per_section: NZU64!(10),
                key_write_buffer: config.key_write_buffer,
                value_write_buffer: config.value_write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");

        let finalized_blocks = prunable::Archive::init(
            context.with_label("finalized_blocks"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{}-finalized-blocks-key", partition_prefix),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{}-finalized-blocks-value", partition_prefix),
                compression: None,
                codec_config: config.block_codec_config,
                items_per_section: NZU64!(10),
                key_write_buffer: config.key_write_buffer,
                value_write_buffer: config.value_write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        let (actor, mailbox, _) = Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<CodingB>::default();
        actor.start(application.clone(), shard_mailbox.clone(), resolver);

        (mailbox, shard_mailbox, application)
    }

    async fn verify_for_prune(
        handle: &mut ValidatorHandle<Self>,
        _round: Round,
        block: &CodedBlock<CodingB, ReedSolomon<Sha256>>,
        participants: &[K],
    ) {
        handle
            .extra
            .proposed(block.clone(), participants.to_vec())
            .await;
    }
}

// =============================================================================
// Generic Test Functions
// =============================================================================

/// Run the finalization test with the given parameters.
pub fn finalize<H: TestHarness>(seed: u64, link: Link, quorum_sees_finalization: bool) -> String {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(H::finalize_timeout())),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), Some(3));
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let mut applications = BTreeMap::new();
        let mut handles = Vec::new();

        let mut manager = oracle.manager();
        manager
            .update(0, participants.clone().try_into().unwrap())
            .await;

        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            applications.insert(validator.clone(), setup.application);
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        setup_network_links(&mut oracle, &participants, link.clone()).await;

        let mut blocks = Vec::new();
        let mut parent = Sha256::hash(b"");
        for i in 1..=NUM_BLOCKS {
            let block = H::make_test_block(parent, Height::new(i), i, participants.len() as u16);
            parent = H::digest(&block);
            blocks.push(block);
        }

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        blocks.shuffle(&mut context);

        for block in blocks.iter() {
            let height = H::height(block);
            assert!(
                !height.is_zero(),
                "genesis block should not have been generated"
            );

            let bounds = epocher.containing(height).unwrap();
            let round = Round::new(bounds.epoch(), View::new(height.get()));

            let actor_index: usize = (height.get() % (NUM_VALIDATORS as u64)) as usize;
            let mut handle = handles[actor_index].clone();
            H::propose(&mut handle, round, block, &participants).await;
            H::verify(&mut handle, round, block, &mut handles).await;

            context.sleep(link.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(height.previous().unwrap().get()),
                payload: H::commitment(block),
            };
            let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let fin = H::make_finalization(proposal, &schemes, QUORUM);
            if quorum_sees_finalization {
                let do_finalize = context.gen_bool(0.2);
                for (i, h) in handles
                    .iter_mut()
                    .choose_multiple(&mut context, NUM_VALIDATORS as usize)
                    .iter_mut()
                    .enumerate()
                {
                    if (do_finalize && i < QUORUM as usize)
                        || height.get() == NUM_BLOCKS
                        || height == bounds.last()
                    {
                        H::report_finalization(&mut h.mailbox, fin.clone()).await;
                    }
                }
            } else {
                for h in handles.iter_mut() {
                    if context.gen_bool(0.2)
                        || height.get() == NUM_BLOCKS
                        || height == bounds.last()
                    {
                        H::report_finalization(&mut h.mailbox, fin.clone()).await;
                    }
                }
            }
        }

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            if applications.len() != NUM_VALIDATORS as usize {
                continue;
            }
            finished = true;
            for app in applications.values() {
                if app.blocks().len() != NUM_BLOCKS as usize {
                    finished = false;
                    break;
                }
                let Some((height, _)) = app.tip() else {
                    finished = false;
                    break;
                };
                if height.get() < NUM_BLOCKS {
                    finished = false;
                    break;
                }
            }
        }

        context.auditor().state()
    })
}

/// Test sync height floor.
pub fn sync_height_floor<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xFF)
            .with_timeout(Some(Duration::from_secs(300))),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), Some(3));
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let mut applications = BTreeMap::new();
        let mut handles = Vec::new();

        let mut manager = oracle.manager();
        manager
            .update(0, participants.clone().try_into().unwrap())
            .await;

        // Skip first validator
        for (i, validator) in participants.iter().enumerate().skip(1) {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            applications.insert(validator.clone(), setup.application);
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        setup_network_links(&mut oracle, &participants[1..], LINK).await;

        let mut blocks = Vec::new();
        let mut parent = Sha256::hash(b"");
        for i in 1..=NUM_BLOCKS {
            let block = H::make_test_block(parent, Height::new(i), i, participants.len() as u16);
            parent = H::digest(&block);
            blocks.push(block);
        }

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);

        for block in blocks.iter() {
            let height = H::height(block);
            assert!(
                !height.is_zero(),
                "genesis block should not have been generated"
            );

            let bounds = epocher.containing(height).unwrap();
            let round = Round::new(bounds.epoch(), View::new(height.get()));

            let actor_index: usize = (height.get() % (applications.len() as u64)) as usize;
            let mut handle = handles[actor_index].clone();
            H::propose(&mut handle, round, block, &participants).await;
            H::verify(&mut handle, round, block, &mut handles).await;

            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(height.previous().unwrap().get()),
                payload: H::commitment(block),
            };
            let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let fin = H::make_finalization(proposal, &schemes, QUORUM);
            for h in handles.iter_mut() {
                H::report_finalization(&mut h.mailbox, fin.clone()).await;
            }
        }

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            finished = true;
            for app in applications.values().skip(1) {
                if app.blocks().len() != NUM_BLOCKS as usize {
                    finished = false;
                    break;
                }
                let Some((height, _)) = app.tip() else {
                    finished = false;
                    break;
                };
                if height.get() < NUM_BLOCKS {
                    finished = false;
                    break;
                }
            }
        }

        // Create the first validator now
        let validator = participants.first().unwrap();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app = setup.application;
        let mut mailbox = setup.mailbox;

        setup_network_links(&mut oracle, &participants, LINK).await;

        const NEW_SYNC_FLOOR: u64 = 100;
        let second_handle = &mut handles[1];
        let latest_finalization = second_handle
            .mailbox
            .get_finalization(Height::new(NUM_BLOCKS))
            .await
            .unwrap();

        mailbox.set_floor(Height::new(NEW_SYNC_FLOOR)).await;
        H::report_finalization(&mut mailbox, latest_finalization).await;

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            finished = true;
            if app.blocks().len() != (NUM_BLOCKS - NEW_SYNC_FLOOR) as usize {
                finished = false;
                continue;
            }
            let Some((height, _)) = app.tip() else {
                finished = false;
                continue;
            };
            if height.get() < NUM_BLOCKS {
                finished = false;
                continue;
            }
        }

        for height in 1..=NUM_BLOCKS {
            let block = mailbox
                .get_block(Identifier::Height(Height::new(height)))
                .await;
            if height <= NEW_SYNC_FLOOR {
                assert!(block.is_none());
            } else {
                assert_eq!(block.unwrap().height().get(), height);
            }
        }
    })
}

/// Test pruning of finalized archives.
pub fn prune_finalized_archives<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new().with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|mut context| async move {
        let oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let validator = participants[0].clone();
        let partition_prefix = format!("prune-test-{}", validator.clone());
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);

        let init_marshal = |ctx: deterministic::Context| {
            let validator = validator.clone();
            let schemes = schemes.clone();
            let partition_prefix = partition_prefix.clone();
            let page_cache = page_cache.clone();
            let oracle = &oracle;
            async move {
                H::setup_prunable_validator(
                    ctx,
                    oracle,
                    validator,
                    &schemes,
                    &partition_prefix,
                    page_cache,
                )
                .await
            }
        };

        let (mut mailbox, extra, application) = init_marshal(context.with_label("init")).await;
        let _ = extra; // Used by CodingHarness, silence warning for StandardHarness

        let mut parent = Sha256::hash(b"");
        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        for i in 1..=20u64 {
            let block = H::make_test_block(parent, Height::new(i), i, NUM_VALIDATORS as u16);
            let commitment = H::commitment(&block);
            parent = H::digest(&block);
            let bounds = epocher.containing(Height::new(i)).unwrap();
            let round = Round::new(bounds.epoch(), View::new(i));

            let mut handle = ValidatorHandle {
                mailbox: mailbox.clone(),
                extra: extra.clone(),
            };
            H::verify_for_prune(&mut handle, round, &block, &participants).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut mailbox, finalization).await;
        }

        while application.blocks().len() < 20 {
            context.sleep(Duration::from_millis(10)).await;
        }

        for i in 1..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should exist before pruning"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_some(),
                "finalization {i} should exist before pruning"
            );
        }

        mailbox.prune(Height::new(25)).await;
        context.sleep(Duration::from_millis(50)).await;
        for i in 1..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should still exist after pruning above floor"
            );
        }

        mailbox.prune(Height::new(10)).await;
        context.sleep(Duration::from_millis(100)).await;
        for i in 1..10u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should be pruned"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should be pruned"
            );
        }

        for i in 10..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should still exist after pruning"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_some(),
                "finalization {i} should still exist after pruning"
            );
        }

        mailbox.prune(Height::new(20)).await;
        context.sleep(Duration::from_millis(100)).await;
        for i in 10..20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should be pruned after second prune"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should be pruned after second prune"
            );
        }

        assert!(
            mailbox.get_block(Height::new(20)).await.is_some(),
            "block 20 should still exist"
        );
        assert!(
            mailbox.get_finalization(Height::new(20)).await.is_some(),
            "finalization 20 should still exist"
        );

        drop(mailbox);
        drop(extra);
        let (mut mailbox, _extra, _application) = init_marshal(context.with_label("restart")).await;

        for i in 1..20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should still be pruned after restart"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should still be pruned after restart"
            );
        }

        assert!(
            mailbox.get_block(Height::new(20)).await.is_some(),
            "block 20 should still exist after restart"
        );
        assert!(
            mailbox.get_finalization(Height::new(20)).await.is_some(),
            "finalization 20 should still exist after restart"
        );
    })
}

/// Test basic block subscription delivery.
pub fn subscribe_basic_block_delivery<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let block = H::make_test_block(parent, Height::new(1), 1, participants.len() as u16);
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        let subscription_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(1))), digest)
            .await;

        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(1)),
            &block,
            &participants,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(1)),
            &block,
            &mut handles,
        )
        .await;

        let proposal = Proposal {
            round: Round::new(Epoch::zero(), View::new(1)),
            parent: View::zero(),
            payload: commitment,
        };
        let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handle.mailbox, notarization).await;

        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
        H::report_finalization(&mut handle.mailbox, finalization).await;

        let received_block = subscription_rx.await.unwrap();
        assert_eq!(received_block.digest(), digest);
        assert_eq!(received_block.height().get(), 1);
    })
}

/// Test multiple subscriptions.
pub fn subscribe_multiple_subscriptions<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let block1 = H::make_test_block(parent, Height::new(1), 1, participants.len() as u16);
        let block2 = H::make_test_block(
            H::digest(&block1),
            Height::new(2),
            2,
            participants.len() as u16,
        );
        let digest1 = H::digest(&block1);
        let digest2 = H::digest(&block2);

        let sub1_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(1))), digest1)
            .await;
        let sub2_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(2))), digest2)
            .await;
        let sub3_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(1))), digest1)
            .await;

        for (view, block) in [(1u64, &block1), (2, &block2)] {
            let round = Round::new(Epoch::zero(), View::new(view));
            H::propose(&mut handle, round, block, &participants).await;
            H::verify(&mut handle, round, block, &mut handles).await;

            let proposal = Proposal {
                round,
                parent: View::new(view.checked_sub(1).unwrap()),
                payload: H::commitment(block),
            };
            let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        let received1_sub1 = sub1_rx.await.unwrap();
        let received2 = sub2_rx.await.unwrap();
        let received1_sub3 = sub3_rx.await.unwrap();

        assert_eq!(received1_sub1.digest(), digest1);
        assert_eq!(received2.digest(), digest2);
        assert_eq!(received1_sub3.digest(), digest1);
        assert_eq!(received1_sub1.height().get(), 1);
        assert_eq!(received2.height().get(), 2);
        assert_eq!(received1_sub3.height().get(), 1);
    })
}

/// Test canceled subscriptions.
pub fn subscribe_canceled_subscriptions<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let block1 = H::make_test_block(parent, Height::new(1), 1, participants.len() as u16);
        let block2 = H::make_test_block(
            H::digest(&block1),
            Height::new(2),
            2,
            participants.len() as u16,
        );
        let digest1 = H::digest(&block1);
        let digest2 = H::digest(&block2);

        let sub1_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(1))), digest1)
            .await;
        let sub2_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(2))), digest2)
            .await;

        drop(sub1_rx);

        for (view, block) in [(1u64, &block1), (2, &block2)] {
            let round = Round::new(Epoch::zero(), View::new(view));
            H::propose(&mut handle, round, block, &participants).await;
            H::verify(&mut handle, round, block, &mut handles).await;

            let proposal = Proposal {
                round,
                parent: View::new(view.checked_sub(1).unwrap()),
                payload: H::commitment(block),
            };
            let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        let received2 = sub2_rx.await.unwrap();
        assert_eq!(received2.digest(), digest2);
        assert_eq!(received2.height().get(), 2);
    })
}

/// Test blocks from different sources.
pub fn subscribe_blocks_from_different_sources<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let n = participants.len() as u16;
        let block1 = H::make_test_block(parent, Height::new(1), 1, n);
        let block2 = H::make_test_block(H::digest(&block1), Height::new(2), 2, n);
        let block3 = H::make_test_block(H::digest(&block2), Height::new(3), 3, n);
        let block4 = H::make_test_block(H::digest(&block3), Height::new(4), 4, n);
        let block5 = H::make_test_block(H::digest(&block4), Height::new(5), 5, n);

        let sub1_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block1))
            .await;
        let sub2_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block2))
            .await;
        let sub3_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block3))
            .await;
        let sub4_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block4))
            .await;
        let sub5_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block5))
            .await;

        // Block1: Broadcasted by the actor
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(1)),
            &block1,
            &participants,
        )
        .await;
        context.sleep(Duration::from_millis(20)).await;

        let received1 = sub1_rx.await.unwrap();
        assert_eq!(received1.digest(), H::digest(&block1));
        assert_eq!(received1.height().get(), 1);

        // Block2: Verified by the actor
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(2)),
            &block2,
            &participants,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(2)),
            &block2,
            &mut handles,
        )
        .await;

        let received2 = sub2_rx.await.unwrap();
        assert_eq!(received2.digest(), H::digest(&block2));
        assert_eq!(received2.height().get(), 2);

        // Block3: Notarized by the actor
        let proposal3 = Proposal {
            round: Round::new(Epoch::zero(), View::new(3)),
            parent: View::new(2),
            payload: H::commitment(&block3),
        };
        let notarization3 = H::make_notarization(proposal3.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handle.mailbox, notarization3).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(3)),
            &block3,
            &participants,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(3)),
            &block3,
            &mut handles,
        )
        .await;

        let received3 = sub3_rx.await.unwrap();
        assert_eq!(received3.digest(), H::digest(&block3));
        assert_eq!(received3.height().get(), 3);

        // Block4: Finalized by the actor
        let finalization4 = H::make_finalization(
            Proposal {
                round: Round::new(Epoch::zero(), View::new(4)),
                parent: View::new(3),
                payload: H::commitment(&block4),
            },
            &schemes,
            QUORUM,
        );
        H::report_finalization(&mut handle.mailbox, finalization4).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(4)),
            &block4,
            &participants,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(4)),
            &block4,
            &mut handles,
        )
        .await;

        let received4 = sub4_rx.await.unwrap();
        assert_eq!(received4.digest(), H::digest(&block4));
        assert_eq!(received4.height().get(), 4);

        // Block5: Finalized by the actor with notarization
        let proposal5 = Proposal {
            round: Round::new(Epoch::zero(), View::new(5)),
            parent: View::new(4),
            payload: H::commitment(&block5),
        };
        let notarization5 = H::make_notarization(proposal5.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handle.mailbox, notarization5).await;
        let finalization5 = H::make_finalization(proposal5, &schemes, QUORUM);
        H::report_finalization(&mut handle.mailbox, finalization5).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(5)),
            &block5,
            &participants,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(5)),
            &block5,
            &mut handles,
        )
        .await;

        let received5 = sub5_rx.await.unwrap();
        assert_eq!(received5.digest(), H::digest(&block5));
        assert_eq!(received5.height().get(), 5);
    })
}

/// Test basic get_info queries for present and missing data.
pub fn get_info_basic_queries_present_and_missing<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no latest
        assert!(handle.mailbox.get_info(Identifier::Latest).await.is_none());

        // Before finalization, specific height returns None
        assert!(handle.mailbox.get_info(Height::new(1)).await.is_none());

        // Create and verify a block, then finalize it
        let parent = Sha256::hash(b"");
        let block = H::make_test_block(parent, Height::new(1), 1, participants.len() as u16);
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);
        let round = Round::new(Epoch::zero(), View::new(1));

        H::propose(&mut handle, round, &block, &participants).await;
        context.sleep(LINK.latency).await;

        let proposal = Proposal {
            round,
            parent: View::zero(),
            payload: commitment,
        };
        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
        H::report_finalization(&mut handle.mailbox, finalization).await;

        // Latest should now be the finalized block
        assert_eq!(
            handle.mailbox.get_info(Identifier::Latest).await,
            Some((Height::new(1), digest))
        );

        // Height 1 now present
        assert_eq!(
            handle.mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );

        // Commitment should map to its height
        assert_eq!(
            handle.mailbox.get_info(&digest).await,
            Some((Height::new(1), digest))
        );

        // Missing height
        assert!(handle.mailbox.get_info(Height::new(2)).await.is_none());

        // Missing commitment
        let missing = Sha256::hash(b"missing");
        assert!(handle.mailbox.get_info(&missing).await.is_none());
    })
}

/// Test get_info latest progression with multiple finalizations.
pub fn get_info_latest_progression_multiple_finalizations<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        let mut parent = Sha256::hash(b"");
        let mut digests = Vec::new();

        for i in 1..=5u64 {
            let block = H::make_test_block(parent, Height::new(i), i, participants.len() as u16);
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block, &participants).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            // Latest should always point to most recently finalized
            assert_eq!(
                handle.mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(i), digest))
            );

            parent = digest;
            digests.push(digest);
        }

        // Verify each height is accessible
        for (i, digest) in digests.iter().enumerate() {
            let height = Height::new(i as u64 + 1);
            assert_eq!(
                handle.mailbox.get_info(height).await,
                Some((height, *digest))
            );
        }
    })
}

/// Test get_block by height and latest.
pub fn get_block_by_height_and_latest<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no blocks
        assert!(handle
            .mailbox
            .get_block(Identifier::Height(Height::new(1)))
            .await
            .is_none());
        assert!(handle.mailbox.get_block(Identifier::Latest).await.is_none());

        let mut parent = Sha256::hash(b"");
        let mut blocks = Vec::new();

        for i in 1..=3u64 {
            let block = H::make_test_block(parent, Height::new(i), i, participants.len() as u16);
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block, &participants).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
            blocks.push((digest, block));
        }

        // Verify each block by height
        for (i, (digest, _block)) in blocks.iter().enumerate() {
            let height = Height::new(i as u64 + 1);
            let fetched = handle
                .mailbox
                .get_block(Identifier::Height(height))
                .await
                .unwrap();
            assert_eq!(fetched.digest(), *digest);
            assert_eq!(fetched.height(), height);
        }

        // Latest should be last block
        let latest = handle.mailbox.get_block(Identifier::Latest).await.unwrap();
        assert_eq!(latest.digest(), blocks[2].0);
        assert_eq!(latest.height(), Height::new(3));

        // Missing height
        assert!(handle
            .mailbox
            .get_block(Identifier::Height(Height::new(10)))
            .await
            .is_none());
    })
}

/// Test get_block by commitment from various sources.
pub fn get_block_by_commitment_from_sources_and_missing<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Create and finalize a block
        let parent = Sha256::hash(b"");
        let block = H::make_test_block(parent, Height::new(1), 1, participants.len() as u16);
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);
        let round = Round::new(Epoch::zero(), View::new(1));

        H::propose(&mut handle, round, &block, &participants).await;
        context.sleep(LINK.latency).await;

        let proposal = Proposal {
            round,
            parent: View::zero(),
            payload: commitment,
        };
        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
        H::report_finalization(&mut handle.mailbox, finalization).await;

        // Get by commitment
        let fetched = handle.mailbox.get_block(&digest).await.unwrap();
        assert_eq!(fetched.digest(), digest);
        assert_eq!(fetched.height(), Height::new(1));

        // Missing commitment
        let missing = Sha256::hash(b"missing");
        assert!(handle.mailbox.get_block(&missing).await.is_none());
    })
}

/// Test get_finalization by height.
pub fn get_finalization_by_height<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no finalization
        assert!(handle
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .is_none());

        let mut parent = Sha256::hash(b"");

        for i in 1..=3u64 {
            let block = H::make_test_block(parent, Height::new(i), i, participants.len() as u16);
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block, &participants).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal.clone(), &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            // Verify finalization is retrievable
            let fin = handle
                .mailbox
                .get_finalization(Height::new(i))
                .await
                .unwrap();
            assert_eq!(fin.proposal.payload, commitment);
            assert_eq!(fin.round().view(), View::new(i));

            parent = digest;
        }

        // Missing height
        assert!(handle
            .mailbox
            .get_finalization(Height::new(10))
            .await
            .is_none());
    })
}

/// Test hint_finalized triggers fetch.
pub fn hint_finalized_triggers_fetch<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(42)
            .with_timeout(Some(Duration::from_secs(60))),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), Some(3));
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        // Register the initial peer set
        let mut manager = oracle.manager();
        manager
            .update(0, participants.clone().try_into().unwrap())
            .await;

        // Set up two validators
        let setup0 = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            participants[0].clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app0 = setup0.application;
        let mut handle0 = ValidatorHandle {
            mailbox: setup0.mailbox,
            extra: setup0.extra,
        };

        let setup1 = H::setup_validator(
            context.with_label("validator_1"),
            &mut oracle,
            participants[1].clone(),
            ConstantProvider::new(schemes[1].clone()),
        )
        .await;
        let mut handle1: ValidatorHandle<H> = ValidatorHandle {
            mailbox: setup1.mailbox,
            extra: setup1.extra,
        };

        // Add links between validators
        setup_network_links(&mut oracle, &participants[..2], LINK).await;

        // Validator 0: Create and finalize blocks 1-5
        let mut parent = Sha256::hash(b"");
        for i in 1..=5u64 {
            let block = H::make_test_block(parent, Height::new(i), i, participants.len() as u16);
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::new(0), View::new(i));

            H::propose(&mut handle0, round, &block, &participants).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle0.mailbox, finalization).await;

            parent = digest;
        }

        // Wait for validator 0 to process all blocks
        while app0.blocks().len() < 5 {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Validator 1 should not have block 5 yet
        assert!(handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .is_none());

        // Validator 1: hint that block 5 is finalized, targeting validator 0
        handle1
            .mailbox
            .hint_finalized(Height::new(5), NonEmptyVec::new(participants[0].clone()))
            .await;

        // Wait for the fetch to complete
        while handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .is_none()
        {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Verify validator 1 now has the finalization
        let finalization = handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .expect("finalization should be fetched");
        assert_eq!(finalization.proposal.round.view(), View::new(5));
    })
}

/// Test ancestry stream.
pub fn ancestry_stream<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Finalize blocks at heights 1-5
        let mut parent = Sha256::hash(b"");
        for i in 1..=5u64 {
            let block = H::make_test_block(parent, Height::new(i), i, participants.len() as u16);
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block, &participants).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
        }

        // Stream from latest -> height 1
        let (_, commitment) = handle.mailbox.get_info(Identifier::Latest).await.unwrap();
        let ancestry = handle.mailbox.ancestry((None, commitment)).await.unwrap();
        let blocks = ancestry.collect::<Vec<_>>().await;

        // Ensure correct delivery order: 5,4,3,2,1
        assert_eq!(blocks.len(), 5);
        (0..5).for_each(|i| {
            assert_eq!(blocks[i].height().get(), 5 - i as u64);
        });
    })
}

/// Test finalize same height different views.
pub fn finalize_same_height_different_views<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        // Set up two validators
        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate().take(2) {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        // Create block at height 1
        let parent = Sha256::hash(b"");
        let block = H::make_test_block(parent, Height::new(1), 1, participants.len() as u16);
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        // Both validators receive the block
        for handle in handles.iter_mut() {
            H::propose(
                handle,
                Round::new(Epoch::new(0), View::new(1)),
                &block,
                &participants,
            )
            .await;
        }
        context.sleep(LINK.latency).await;

        // Validator 0: Finalize with view 1
        let proposal_v1 = Proposal {
            round: Round::new(Epoch::new(0), View::new(1)),
            parent: View::new(0),
            payload: commitment,
        };
        let notarization_v1 = H::make_notarization(proposal_v1.clone(), &schemes, QUORUM);
        let finalization_v1 = H::make_finalization(proposal_v1.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handles[0].mailbox, notarization_v1.clone()).await;
        H::report_finalization(&mut handles[0].mailbox, finalization_v1.clone()).await;

        // Validator 1: Finalize with view 2 (simulates receiving finalization from different view)
        let proposal_v2 = Proposal {
            round: Round::new(Epoch::new(0), View::new(2)), // Different view
            parent: View::new(0),
            payload: commitment, // Same block
        };
        let notarization_v2 = H::make_notarization(proposal_v2.clone(), &schemes, QUORUM);
        let finalization_v2 = H::make_finalization(proposal_v2.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handles[1].mailbox, notarization_v2.clone()).await;
        H::report_finalization(&mut handles[1].mailbox, finalization_v2.clone()).await;

        // Wait for finalization processing
        context.sleep(Duration::from_millis(100)).await;

        // Verify both validators stored the block correctly
        let block0 = handles[0].mailbox.get_block(Height::new(1)).await.unwrap();
        let block1 = handles[1].mailbox.get_block(Height::new(1)).await.unwrap();
        assert_eq!(block0.digest(), digest);
        assert_eq!(block1.digest(), digest);

        // Verify both validators have finalizations stored
        let fin0 = handles[0]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        let fin1 = handles[1]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();

        // Verify the finalizations have the expected different views
        assert_eq!(fin0.proposal.payload, commitment);
        assert_eq!(fin0.round().view(), View::new(1));
        assert_eq!(fin1.proposal.payload, commitment);
        assert_eq!(fin1.round().view(), View::new(2));

        // Both validators can retrieve block by height
        assert_eq!(
            handles[0].mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );
        assert_eq!(
            handles[1].mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );

        // Test that a validator receiving BOTH finalizations handles it correctly
        H::report_finalization(&mut handles[0].mailbox, finalization_v2.clone()).await;
        H::report_finalization(&mut handles[1].mailbox, finalization_v1.clone()).await;
        context.sleep(Duration::from_millis(100)).await;

        // Validator 0 should still have the original finalization (v1)
        let fin0_after = handles[0]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        assert_eq!(fin0_after.round().view(), View::new(1));

        // Validator 1 should still have the original finalization (v2)
        let fin1_after = handles[1]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        assert_eq!(fin1_after.round().view(), View::new(2));
    })
}

/// Test init processed height.
pub fn init_processed_height<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let validator = participants[0].clone();

        // First session: create validator and finalize some blocks
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app = setup.application;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };
        let initial_height = setup.height;

        // Initially should be zero (no blocks processed)
        assert_eq!(initial_height, Height::zero());

        // Finalize blocks 1-5
        let mut parent = Sha256::hash(b"");
        for i in 1..=5u64 {
            let block = H::make_test_block(parent, Height::new(i), i, participants.len() as u16);
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block, &participants).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
        }

        // Wait for application to process all blocks
        while app.blocks().len() < 5 {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Drop the handle to simulate shutdown
        drop(handle);

        // Second session: create new validator instance, should recover processed height
        let setup2 = H::setup_validator(
            context.with_label("validator_0_restart"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let recovered_height = setup2.height;

        // Should have recovered to height 5
        assert_eq!(recovered_height, Height::new(5));
    })
}

/// Test broadcast caches block.
pub fn broadcast_caches_block<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        // Set up one validator
        let validator = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Create block at height 1
        let parent = Sha256::hash(b"");
        let block = H::make_test_block(parent, Height::new(1), 1, participants.len() as u16);
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        // Broadcast the block
        H::propose(
            &mut handle,
            Round::new(Epoch::new(0), View::new(1)),
            &block,
            &participants,
        )
        .await;

        // Ensure the block is cached and retrievable
        handle
            .mailbox
            .get_block(&digest)
            .await
            .expect("block should be cached after broadcast");

        // Restart marshal, removing any in-memory cache
        let setup2 = H::setup_validator(
            context.with_label("validator_0_restart"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle2: ValidatorHandle<H> = ValidatorHandle {
            mailbox: setup2.mailbox,
            extra: setup2.extra,
        };

        // Put a notarization into the cache to re-initialize the ephemeral cache for the
        // first epoch.
        let notarization = H::make_notarization(
            Proposal {
                round: Round::new(Epoch::new(0), View::new(1)),
                parent: View::new(0),
                payload: commitment,
            },
            &schemes,
            QUORUM,
        );
        H::report_notarization(&mut handle2.mailbox, notarization).await;

        // Ensure the block is cached and retrievable
        handle2
            .mailbox
            .get_block(&digest)
            .await
            .expect("block should be cached after broadcast");
    })
}
