//! Test harness for marshal variants.
//!
//! This module provides a trait-based abstraction that allows writing tests once
//! and running them against both the standard and coding marshal variants.

use crate::{
    marshal::{
        coding::{
            shards,
            types::{coding_config_for_participants, CodedBlock},
            Coding,
        },
        config::Config,
        core::{Actor, ConsensusEngine, Mailbox, MinimmitConsensus, SimplexConsensus},
        mocks::{application::Application, block::Block},
        resolver::p2p as resolver,
        standard::{StandardMinimmit, StandardSimplex},
    },
    minimmit::{
        scheme::bls12381_threshold as minimmit_bls12381_threshold,
        types::{
            Activity as MinActivity, Finalization as MinFinalization, MNotarization,
            Notarize as MNotarize, Proposal as MinProposal,
        },
    },
    simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Activity, Context, Finalization, Finalize, Notarization, Notarize, Proposal},
    },
    types::{coding::Commitment, Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    Block as _, CertifiableBlock as _, Heightable, Reporter,
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
    Provider,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics, Quota};
use commonware_storage::{
    archive::{immutable, prunable},
    translator::EightCap,
};
use commonware_utils::{Faults, M5f1, N5f1, NZUsize, NZU16, NZU64};
use std::{
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
pub type MS = minimmit_bls12381_threshold::Scheme<K, V>;
pub type MP = ConstantProvider<MS, Epoch>;

// Coding variant type aliases (uses Commitment in context)
pub type CodingCtx = Context<Commitment, K>;
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
    pub mailbox: Mailbox<H::Variant>,
    pub extra: H::ValidatorExtra,
    pub height: Height,
}

/// Per-validator handle for test operations.
pub struct ValidatorHandle<H: TestHarness> {
    pub mailbox: Mailbox<H::Variant>,
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

    /// Signing scheme used by this harness.
    type Scheme: commonware_cryptography::certificate::Scheme<PublicKey = K> + Clone;

    /// Consensus engine used by this harness.
    type Consensus: ConsensusEngine<
        Scheme = Self::Scheme,
        Commitment = Self::Commitment,
        Notarization = Self::Notarization,
        Finalization = Self::Finalization,
    >;

    /// The marshal variant type.
    type Variant: crate::marshal::core::Variant<
        ApplicationBlock = Self::ApplicationBlock,
        Commitment = Self::Commitment,
        Consensus = Self::Consensus,
    >;

    /// The block type used in test operations.
    type TestBlock: Heightable + Clone + Send;

    /// Additional per-validator state (e.g., shards mailbox for coding).
    type ValidatorExtra: Clone + Send;

    /// The commitment type for consensus certificates.
    type Commitment: DigestTrait;

    /// Notarization type used by this consensus harness.
    type Notarization: Clone;

    /// Finalization type used by this consensus harness.
    type Finalization: Clone;

    /// Proposal type used by this consensus harness.
    type Proposal: Clone;

    /// Number of validators to use for generic harness-driven tests.
    fn num_validators() -> u32 {
        NUM_VALIDATORS
    }

    /// Quorum used for generic harness-driven tests.
    fn quorum() -> u32 {
        QUORUM
    }

    /// Build a deterministic test fixture for this harness.
    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        validators: u32,
    ) -> Fixture<Self::Scheme>;

    /// Setup a single validator with all necessary infrastructure.
    fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: ConstantProvider<Self::Scheme, Epoch>,
    ) -> impl Future<Output = ValidatorSetup<Self>> + Send;

    /// Setup a single validator with custom acknowledgement pipeline settings.
    fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: ConstantProvider<Self::Scheme, Epoch>,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> impl Future<Output = ValidatorSetup<Self>> + Send;

    /// Create a test block from parent and height.
    fn genesis_parent_commitment() -> Self::Commitment;

    /// Create a test block from parent and height.
    fn make_test_block(
        parent: D,
        parent_commitment: Self::Commitment,
        height: Height,
        timestamp: u64,
        num_participants: u16,
    ) -> Self::TestBlock;

    /// Get the commitment from a test block.
    fn commitment(block: &Self::TestBlock) -> Self::Commitment;

    /// Get the parent commitment from a test block.
    fn parent_commitment(block: &Self::TestBlock) -> Self::Commitment;

    /// Get the digest from a test block.
    fn digest(block: &Self::TestBlock) -> D;

    /// Get the height from a test block.
    fn height(block: &Self::TestBlock) -> Height;

    /// Propose a block (broadcast to network).
    fn propose(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) -> impl Future<Output = ()> + Send;

    /// Mark a block as verified.
    fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) -> impl Future<Output = ()> + Send;

    /// Create a finalization certificate.
    fn make_finalization(
        proposal: Self::Proposal,
        schemes: &[Self::Scheme],
        quorum: u32,
    ) -> Self::Finalization;

    /// Create a notarization certificate.
    fn make_notarization(
        proposal: Self::Proposal,
        schemes: &[Self::Scheme],
        quorum: u32,
    ) -> Self::Notarization;

    /// Create a consensus proposal from canonical fields.
    fn make_proposal(
        round: Round,
        parent: View,
        parent_commitment: Self::Commitment,
        payload: Self::Commitment,
    ) -> Self::Proposal;

    /// Returns the committed payload from a finalization.
    fn finalization_payload(finalization: &Self::Finalization) -> Self::Commitment;

    /// Returns the round from a finalization.
    fn finalization_round(finalization: &Self::Finalization) -> Round;

    /// Report a finalization to the mailbox.
    fn report_finalization(
        mailbox: &mut Mailbox<Self::Variant>,
        finalization: Self::Finalization,
    ) -> impl Future<Output = ()> + Send;

    /// Report a notarization to the mailbox.
    fn report_notarization(
        mailbox: &mut Mailbox<Self::Variant>,
        notarization: Self::Notarization,
    ) -> impl Future<Output = ()> + Send;

    /// Get the timeout duration for the finalize test.
    fn finalize_timeout() -> Duration;

    /// Setup validator for pruning test with prunable archives.
    #[allow(clippy::type_complexity)]
    fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[Self::Scheme],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> impl Future<
        Output = (
            Mailbox<Self::Variant>,
            Self::ValidatorExtra,
            Application<Self::ApplicationBlock>,
        ),
    > + Send;
}

// =============================================================================
// Standard Harness Implementation
// =============================================================================

/// Standard variant test harness.
pub struct StandardSimplexHarness;

impl TestHarness for StandardSimplexHarness {
    type ApplicationBlock = B;
    type Scheme = S;
    type Consensus = SimplexConsensus<S, D>;
    type Variant = StandardSimplex<B, S>;
    type TestBlock = B;
    type ValidatorExtra = ();
    type Commitment = D;
    type Proposal = Proposal<D>;
    type Notarization = Notarization<S, D>;
    type Finalization = Finalization<S, D>;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        validators: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_threshold_vrf::fixture::<V, _>(context, namespace, validators)
    }

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: ConstantProvider<Self::Scheme, Epoch>,
    ) -> ValidatorSetup<Self> {
        Self::setup_validator_with(
            context,
            oracle,
            validator,
            provider,
            NZUsize!(1),
            Application::default(),
        )
        .await
    }

    async fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: ConstantProvider<Self::Scheme, Epoch>,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> ValidatorSetup<Self> {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks,
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        let control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            provider: oracle.manager(),
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
            peer_set_subscription: oracle.manager().subscribe().await,
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
                codec_config: Self::Scheme::certificate_codec_config_unbounded(),
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
        actor.start(application.clone(), buffer, resolver);

        ValidatorSetup {
            application,
            mailbox,
            extra: (),
            height,
        }
    }

    fn genesis_parent_commitment() -> D {
        Sha256::hash(b"")
    }

    fn make_test_block(
        parent: D,
        _parent_commitment: D,
        height: Height,
        timestamp: u64,
        _num_participants: u16,
    ) -> B {
        make_raw_block(parent, height, timestamp)
    }

    fn commitment(block: &B) -> D {
        block.digest()
    }

    fn parent_commitment(block: &B) -> D {
        block.parent()
    }

    fn digest(block: &B) -> D {
        block.digest()
    }

    fn make_proposal(
        round: Round,
        parent: View,
        _parent_commitment: D,
        commitment: D,
    ) -> Self::Proposal {
        Proposal {
            round,
            parent,
            payload: commitment,
        }
    }

    fn height(block: &B) -> Height {
        block.height()
    }

    async fn propose(handle: &mut ValidatorHandle<Self>, round: Round, block: &B) {
        handle.mailbox.proposed(round, block.clone()).await;
    }

    async fn verify(handle: &mut ValidatorHandle<Self>, round: Round, block: &B) {
        handle.mailbox.verified(round, block.clone()).await;
    }

    fn make_finalization(
        proposal: Self::Proposal,
        schemes: &[Self::Scheme],
        quorum: u32,
    ) -> Self::Finalization {
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
    }

    fn make_notarization(
        proposal: Self::Proposal,
        schemes: &[Self::Scheme],
        quorum: u32,
    ) -> Self::Notarization {
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
    }

    fn finalization_payload(finalization: &Self::Finalization) -> Self::Commitment {
        finalization.proposal.payload
    }

    fn finalization_round(finalization: &Self::Finalization) -> Round {
        finalization.round()
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<Self::Variant>,
        finalization: Self::Finalization,
    ) {
        mailbox.report(Activity::Finalization(finalization)).await;
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<Self::Variant>,
        notarization: Self::Notarization,
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
        schemes: &[Self::Scheme],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> (Mailbox<Self::Variant>, Self::ValidatorExtra, Application<B>) {
        let control = oracle.control(validator.clone());
        let provider = ConstantProvider::new(schemes[0].clone());
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
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
            provider: oracle.manager(),
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
            peer_set_subscription: oracle.manager().subscribe().await,
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
                codec_config: Self::Scheme::certificate_codec_config_unbounded(),
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
}

/// Standard variant test harness wired to minimmit consensus.
pub struct StandardMinimmitHarness;

impl TestHarness for StandardMinimmitHarness {
    type ApplicationBlock = B;
    type Scheme = MS;
    type Consensus = MinimmitConsensus<MS, D>;
    type Variant = StandardMinimmit<B, MS>;
    type TestBlock = B;
    type ValidatorExtra = ();
    type Commitment = D;
    type Proposal = MinProposal<D>;
    type Notarization = MNotarization<MS, D>;
    type Finalization = MinFinalization<MS, D>;

    fn num_validators() -> u32 {
        6
    }

    fn quorum() -> u32 {
        M5f1::quorum(Self::num_validators())
    }

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        validators: u32,
    ) -> Fixture<Self::Scheme> {
        minimmit_bls12381_threshold::fixture::<V, _>(context, namespace, validators)
    }

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: ConstantProvider<Self::Scheme, Epoch>,
    ) -> ValidatorSetup<Self> {
        Self::setup_validator_with(
            context,
            oracle,
            validator,
            provider,
            NZUsize!(1),
            Application::default(),
        )
        .await
    }

    async fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: ConstantProvider<Self::Scheme, Epoch>,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> ValidatorSetup<Self> {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks,
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        let control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            provider: oracle.manager(),
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
            peer_set_subscription: oracle.manager().subscribe().await,
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
                codec_config: Self::Scheme::certificate_codec_config_unbounded(),
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
        actor.start(application.clone(), buffer, resolver);

        ValidatorSetup {
            application,
            mailbox,
            extra: (),
            height,
        }
    }

    fn genesis_parent_commitment() -> D {
        Sha256::hash(b"")
    }

    fn make_test_block(
        parent: D,
        _parent_commitment: D,
        height: Height,
        timestamp: u64,
        _num_participants: u16,
    ) -> B {
        make_raw_block(parent, height, timestamp)
    }

    fn commitment(block: &B) -> D {
        block.digest()
    }

    fn parent_commitment(block: &B) -> D {
        block.parent()
    }

    fn digest(block: &B) -> D {
        block.digest()
    }

    fn make_proposal(
        round: Round,
        parent: View,
        parent_commitment: D,
        commitment: D,
    ) -> Self::Proposal {
        MinProposal::new(round, parent, parent_commitment, commitment)
    }

    fn height(block: &B) -> Height {
        block.height()
    }

    async fn propose(handle: &mut ValidatorHandle<Self>, round: Round, block: &B) {
        handle.mailbox.proposed(round, block.clone()).await;
    }

    async fn verify(handle: &mut ValidatorHandle<Self>, round: Round, block: &B) {
        handle.mailbox.verified(round, block.clone()).await;
    }

    fn make_finalization(
        proposal: Self::Proposal,
        schemes: &[Self::Scheme],
        _quorum: u32,
    ) -> Self::Finalization {
        let l_quorum = N5f1::quorum(schemes.len()) as usize;
        let notarizes: Vec<_> = schemes
            .iter()
            .take(l_quorum)
            .map(|scheme| MNotarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        MinFinalization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
    }

    fn make_notarization(
        proposal: Self::Proposal,
        schemes: &[Self::Scheme],
        quorum: u32,
    ) -> Self::Notarization {
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| MNotarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        MNotarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
    }

    fn finalization_payload(finalization: &Self::Finalization) -> Self::Commitment {
        finalization.proposal.payload
    }

    fn finalization_round(finalization: &Self::Finalization) -> Round {
        finalization.round()
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<Self::Variant>,
        finalization: Self::Finalization,
    ) {
        mailbox
            .report(MinActivity::Finalization(finalization))
            .await;
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<Self::Variant>,
        notarization: Self::Notarization,
    ) {
        mailbox
            .report(MinActivity::MNotarization(notarization))
            .await;
    }

    fn finalize_timeout() -> Duration {
        Duration::from_secs(600)
    }

    async fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[Self::Scheme],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> (
        Mailbox<Self::Variant>,
        Self::ValidatorExtra,
        Application<Self::ApplicationBlock>,
    ) {
        let control = oracle.control(validator.clone());
        let provider = ConstantProvider::new(schemes[0].clone());
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
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
            provider: oracle.manager(),
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
            peer_set_subscription: oracle.manager().subscribe().await,
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
                codec_config: Self::Scheme::certificate_codec_config_unbounded(),
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
}

// =============================================================================
// Coding Harness Implementation
// =============================================================================

// =============================================================================
// Coding Harness Implementation
// =============================================================================

/// Coding variant test harness.
pub struct CodingHarness;

type CodingVariant = Coding<CodingB, ReedSolomon<Sha256>, Sha256, K, S>;
type ShardsMailbox = shards::Mailbox<CodingB, ReedSolomon<Sha256>, Sha256, K>;

/// Genesis blocks use a special coding config that doesn't actually encode.
pub const GENESIS_CODING_CONFIG: commonware_coding::Config = commonware_coding::Config {
    minimum_shards: NZU16!(1),
    extra_shards: NZU16!(1),
};

/// Create a genesis Commitment (all zeros for digests, genesis config).
pub fn genesis_commitment() -> Commitment {
    Commitment::from((
        D::EMPTY,
        D::EMPTY,
        Sha256Digest::EMPTY,
        GENESIS_CODING_CONFIG,
    ))
}

/// Create a test block with a Commitment-based context.
pub fn make_coding_block(context: CodingCtx, parent: D, height: Height, timestamp: u64) -> CodingB {
    CodingB::new::<Sha256>(context, parent, height, timestamp)
}

impl TestHarness for CodingHarness {
    type ApplicationBlock = CodingB;
    type Scheme = S;
    type Consensus = SimplexConsensus<S, Commitment>;
    type Variant = CodingVariant;
    type TestBlock = CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>;
    type ValidatorExtra = ShardsMailbox;
    type Commitment = Commitment;
    type Proposal = Proposal<Commitment>;
    type Notarization = Notarization<S, Commitment>;
    type Finalization = Finalization<S, Commitment>;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        validators: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_threshold_vrf::fixture::<V, _>(context, namespace, validators)
    }

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> ValidatorSetup<Self> {
        Self::setup_validator_with(
            context,
            oracle,
            validator,
            provider,
            NZUsize!(1),
            Application::default(),
        )
        .await
    }

    async fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> ValidatorSetup<Self> {
        let config = Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks,
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        let control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            provider: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(&context, resolver_cfg, backfill);

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

        let shard_config: shards::Config<_, _, _, _, Sha256, _, _> = shards::Config {
            scheme_provider: provider.clone(),
            blocker: oracle.control(validator.clone()),
            shard_codec_cfg: CodecConfig {
                maximum_shard_size: 1024 * 1024,
            },
            block_codec_cfg: (),
            strategy: Sequential,
            mailbox_size: 10,
            peer_buffer_size: NZUsize!(64),
            background_channel_capacity: 1024,
            peer_set_subscription: oracle.manager().subscribe().await,
        };
        let (shard_engine, shard_mailbox) = shards::Engine::new(context.clone(), shard_config);
        let network = control.register(2, TEST_QUOTA).await.unwrap();
        shard_engine.start(network);

        let (actor, mailbox, height) = Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
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
        parent_commitment: Commitment,
        height: Height,
        timestamp: u64,
        num_participants: u16,
    ) -> CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256> {
        let parent_view = height
            .previous()
            .map(|h| View::new(h.get()))
            .unwrap_or(View::zero());
        let context = CodingCtx {
            round: Round::new(Epoch::zero(), View::new(height.get())),
            leader: default_leader(),
            parent: (parent_view, parent_commitment),
        };
        let raw = CodingB::new::<Sha256>(context, parent, height, timestamp);
        let coding_config = coding_config_for_participants(num_participants);
        CodedBlock::new(raw, coding_config, &Sequential)
    }

    fn genesis_parent_commitment() -> Commitment {
        genesis_commitment()
    }

    fn commitment(block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>) -> Commitment {
        block.commitment()
    }

    fn parent_commitment(block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>) -> Commitment {
        block.context().parent.1
    }

    fn digest(block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>) -> D {
        block.digest()
    }

    fn make_proposal(
        round: Round,
        parent: View,
        _parent_commitment: Commitment,
        commitment: Commitment,
    ) -> Self::Proposal {
        Proposal {
            round,
            parent,
            payload: commitment,
        }
    }

    fn height(block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>) -> Height {
        block.height()
    }

    async fn propose(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>,
    ) {
        handle.mailbox.proposed(round, block.clone()).await;
    }

    async fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>,
    ) {
        handle.mailbox.verified(round, block.clone()).await;
    }

    fn make_finalization(
        proposal: Self::Proposal,
        schemes: &[S],
        quorum: u32,
    ) -> Self::Finalization {
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
    }

    fn make_notarization(
        proposal: Self::Proposal,
        schemes: &[S],
        quorum: u32,
    ) -> Self::Notarization {
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
    }

    fn finalization_payload(finalization: &Self::Finalization) -> Self::Commitment {
        finalization.proposal.payload
    }

    fn finalization_round(finalization: &Self::Finalization) -> Round {
        finalization.round()
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<Self::Variant>,
        finalization: Self::Finalization,
    ) {
        mailbox.report(Activity::Finalization(finalization)).await;
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<Self::Variant>,
        notarization: Self::Notarization,
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
        Mailbox<Self::Variant>,
        Self::ValidatorExtra,
        Application<CodingB>,
    ) {
        let control = oracle.control(validator.clone());
        let provider = ConstantProvider::new(schemes[0].clone());
        let config = Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
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
            provider: oracle.manager(),
            blocker: control.clone(),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(&context, resolver_cfg, backfill);

        let shard_config: shards::Config<_, _, _, _, Sha256, _, _> = shards::Config {
            scheme_provider: provider.clone(),
            blocker: oracle.control(validator.clone()),
            shard_codec_cfg: CodecConfig {
                maximum_shard_size: 1024 * 1024,
            },
            block_codec_cfg: (),
            strategy: Sequential,
            mailbox_size: 10,
            peer_buffer_size: NZUsize!(64),
            background_channel_capacity: 1024,
            peer_set_subscription: oracle.manager().subscribe().await,
        };
        let (shard_engine, shard_mailbox) = shards::Engine::new(context.clone(), shard_config);
        let network = control.register(1, TEST_QUOTA).await.unwrap();
        shard_engine.start(network);

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
}
