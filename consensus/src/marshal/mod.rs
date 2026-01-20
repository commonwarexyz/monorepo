//! Ordered delivery of finalized blocks.
//!
//! # Architecture
//!
//! The core of the module is the [actor::Actor]. It marshals the finalized blocks into order by:
//!
//! - Receiving uncertified blocks from a broadcast mechanism
//! - Receiving notarizations and finalizations from consensus
//! - Reconstructing a total order of finalized blocks
//! - Providing a backfill mechanism for missing blocks
//!
//! The actor interacts with four main components:
//! - [crate::Reporter]: Receives ordered, finalized blocks at-least-once
//! - [crate::simplex]: Provides consensus messages
//! - Application: Provides verified blocks
//! - [commonware_broadcast::buffered]: Provides uncertified blocks received from the network
//! - [commonware_resolver::Resolver]: Provides a backfill mechanism for missing blocks
//!
//! # Design
//!
//! ## Delivery
//!
//! The actor will deliver a block to the reporter at-least-once. The reporter should be prepared to
//! handle duplicate deliveries. However the blocks will be in order.
//!
//! ## Finalization
//!
//! The actor uses a view-based model to track the state of the chain. Each view corresponds
//! to a potential block in the chain. The actor will only finalize a block (and its ancestors)
//! if it has a corresponding finalization from consensus.
//!
//! _It is possible that there may exist multiple finalizations for the same block in different views. Marshal
//! only concerns itself with verifying a valid finalization exists for a block, not that a specific finalization
//! exists. This means different Marshals may have different finalizations for the same block persisted to disk._
//!
//! ## Backfill
//!
//! The actor provides a backfill mechanism for missing blocks. If the actor notices a gap in its
//! knowledge of finalized blocks, it will request the missing blocks from its peers. This ensures
//! that the actor can catch up to the rest of the network if it falls behind.
//!
//! ## Storage
//!
//! The actor uses a combination of internal and external ([`store::Certificates`], [`store::Blocks`]) storage
//! to store blocks and finalizations. Internal storage is used to store data that is only needed for a short
//! period of time, such as unverified blocks or notarizations. External storage is used to
//! store data that needs to be persisted indefinitely, such as finalized blocks.
//!
//! Marshal will store all blocks after a configurable starting height (or, floor) onward.
//! This allows for state sync from a specific height rather than from genesis. When
//! updating the starting height, marshal will attempt to prune blocks in external storage
//! that are no longer needed, if the backing [`store::Blocks`] supports pruning.
//!
//! _Setting a configurable starting height will prevent others from backfilling blocks below said height. This
//! feature is only recommended for applications that support state sync (i.e., those that don't require full
//! block history to participate in consensus)._
//!
//! ## Limitations and Future Work
//!
//! - Only works with [crate::simplex] rather than general consensus.
//! - Assumes at-most one notarization per view, incompatible with some consensus protocols.
//! - Uses [`broadcast::buffered`](`commonware_broadcast::buffered`) for broadcasting and receiving
//!   uncertified blocks from the network.

pub mod actor;
pub use actor::Actor;
pub mod cache;
pub mod config;
pub use config::Config;
pub mod consensus;
pub use consensus::{MarshalActivity, MarshalConsensus, MarshalFinalization, MarshalNotarization};
pub mod ingress;
pub use ingress::mailbox::Mailbox;
pub mod resolver;
pub mod store;

use crate::{
    types::{Height, Round},
    Block,
};
use commonware_utils::{acknowledgement::Exact, Acknowledgement};

/// An update reported to the application, either a new finalized tip or a finalized block.
///
/// Finalized tips are reported as soon as known, whether or not we hold all blocks up to that height.
/// Finalized blocks are reported to the application in monotonically increasing order (no gaps permitted).
#[derive(Clone, Debug)]
pub enum Update<B: Block, A: Acknowledgement = Exact> {
    /// A new finalized tip and the finalization round.
    Tip(Round, Height, B::Commitment),
    /// A new finalized block and an [Acknowledgement] for the application to signal once processed.
    ///
    /// To ensure all blocks are delivered at least once, marshal waits to mark a block as delivered
    /// until the application explicitly acknowledges the update. If the [Acknowledgement] is dropped before
    /// handling, marshal will exit (assuming the application is shutting down).
    ///
    /// Because the [Acknowledgement] is clonable, the application can pass [Update] to multiple consumers
    /// (and marshal will only consider the block delivered once all consumers have acknowledged it).
    Block(B, A),
}

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::{
        actor,
        config::Config,
        consensus::{MarshalConsensus, MarshalFinalization},
        mocks::{application::Application, block::Block},
        resolver::p2p as resolver,
    };
    use crate::{
        application::marshaled::Marshaled,
        marshal::ingress::mailbox::{AncestorStream, Identifier},
        minimmit::{
            scheme::bls12381_threshold as minimmit_bls12381_threshold,
            types::{
                Activity as MinimmitActivity, Finalization as MinimmitFinalization, MNotarization,
                MinimmitConsensus, Notarize as MinimmitNotarize, Proposal as MinimmitProposal,
            },
        },
        simplex::{
            scheme::bls12381_threshold::vrf as simplex_bls12381_threshold,
            types::{
                Activity as SimplexActivity, Context, Finalization as SimplexFinalization,
                Finalize as SimplexFinalize, Notarization as SimplexNotarization,
                Notarize as SimplexNotarize, Proposal as SimplexProposal, SimplexConsensus,
            },
        },
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
        Automaton, CertifiableAutomaton, Heightable, Reporter, VerifyingApplication,
    };
    use commonware_broadcast::buffered;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk,
        certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
        ed25519::{PrivateKey, PublicKey},
        sha256::{Digest as Sha256Digest, Sha256},
        Committable, Digestible, Hasher as _, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        simulated::{self, Link, Network, Oracle},
        Manager,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Quota, Runner};
    use commonware_storage::{
        archive::{immutable, prunable},
        translator::EightCap,
    };
    use commonware_utils::{vec::NonEmptyVec, NZUsize, NZU16, NZU64};
    use futures::StreamExt;
    use rand::{
        seq::{IteratorRandom, SliceRandom},
        Rng,
    };
    use std::{
        collections::BTreeMap,
        num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
        time::{Duration, Instant},
    };
    use tracing::info;

    type D = Sha256Digest;
    type K = PublicKey;
    type Ctx = crate::simplex::types::Context<D, K>;
    type B = Block<D, Ctx>;
    type V = MinPk;

    // Simplex types
    type SimplexS = simplex_bls12381_threshold::Scheme<K, V>;
    type SimplexP = ConstantProvider<SimplexS, Epoch>;
    type SimplexC = SimplexConsensus<SimplexS, D>;

    // Minimmit types
    type MinimmitS = minimmit_bls12381_threshold::Scheme<K, V>;
    type MinimmitP = ConstantProvider<MinimmitS, Epoch>;
    type MinimmitC = MinimmitConsensus<MinimmitS, D>;

    /// Trait for abstracting over consensus protocol specifics in tests.
    ///
    /// This allows tests to be parameterized over different consensus implementations
    /// (simplex, minimmit) while sharing the same test logic.
    trait ConsensusTestHarness: Sized {
        /// The consensus marker type implementing MarshalConsensus.
        type Consensus: MarshalConsensus<Digest = D, Scheme = Self::Scheme>;

        /// The signing scheme type.
        type Scheme: commonware_cryptography::certificate::Scheme<PublicKey = K>;

        /// The provider type for the scheme.
        type Provider: commonware_cryptography::certificate::Provider<Scheme = Self::Scheme, Scope = Epoch>
            + Clone
            + Send
            + Sync
            + 'static;

        /// Creates a fixture with the given number of validators.
        fn fixture(
            context: &mut deterministic::Context,
            namespace: &[u8],
            n: u32,
        ) -> Fixture<Self::Scheme>;

        /// Creates a provider from a scheme.
        fn provider(scheme: Self::Scheme) -> Self::Provider;

        /// Returns the L-quorum (finalization quorum) for n validators.
        ///
        /// For simplex, this is n-f where n=3f+1 (so L-quorum = 2f+1 for n=4 is 3).
        /// For minimmit, this is n-f where n=5f+1 (so L-quorum = n-f for n=4 is 4).
        fn l_quorum(n: u32) -> u32;

        /// Returns the codec config for the notarization type.
        fn notarization_codec_config(
        ) -> <<Self::Consensus as MarshalConsensus>::Notarization as commonware_codec::Read>::Cfg;

        /// Returns the codec config for the finalization type.
        fn finalization_codec_config(
        ) -> <<Self::Consensus as MarshalConsensus>::Finalization as commonware_codec::Read>::Cfg;

        /// Creates a notarization from a proposal.
        fn make_notarization(
            round: Round,
            parent_view: View,
            parent_payload: D,
            payload: D,
            schemes: &[Self::Scheme],
            quorum: u32,
        ) -> <Self::Consensus as MarshalConsensus>::Notarization;

        /// Creates a finalization from a proposal.
        fn make_finalization(
            round: Round,
            parent_view: View,
            parent_payload: D,
            payload: D,
            schemes: &[Self::Scheme],
            quorum: u32,
        ) -> <Self::Consensus as MarshalConsensus>::Finalization;

        /// Wraps a notarization in an Activity for reporting.
        fn notarization_activity(
            notarization: <Self::Consensus as MarshalConsensus>::Notarization,
        ) -> <Self::Consensus as MarshalConsensus>::Activity;

        /// Wraps a finalization in an Activity for reporting.
        fn finalization_activity(
            finalization: <Self::Consensus as MarshalConsensus>::Finalization,
        ) -> <Self::Consensus as MarshalConsensus>::Activity;

        /// Returns the certificate codec config for unbounded certificates.
        fn certificate_codec_config_unbounded(
        ) -> <<Self::Consensus as MarshalConsensus>::Finalization as commonware_codec::Read>::Cfg;
    }

    /// Simplex consensus test harness implementation.
    struct SimplexHarness;

    impl ConsensusTestHarness for SimplexHarness {
        type Consensus = SimplexC;
        type Scheme = SimplexS;
        type Provider = SimplexP;

        fn fixture(
            context: &mut deterministic::Context,
            namespace: &[u8],
            n: u32,
        ) -> Fixture<Self::Scheme> {
            simplex_bls12381_threshold::fixture::<V, _>(context, namespace, n)
        }

        fn provider(scheme: Self::Scheme) -> Self::Provider {
            ConstantProvider::new(scheme)
        }

        fn l_quorum(n: u32) -> u32 {
            // Simplex uses N3f1 model: f = (n-1)/3, L-quorum = n-f
            use commonware_utils::Faults;
            commonware_utils::N3f1::quorum(n)
        }

        fn notarization_codec_config(
        ) -> <<Self::Consensus as MarshalConsensus>::Notarization as commonware_codec::Read>::Cfg
        {
            SimplexS::certificate_codec_config_unbounded()
        }

        fn finalization_codec_config(
        ) -> <<Self::Consensus as MarshalConsensus>::Finalization as commonware_codec::Read>::Cfg
        {
            SimplexS::certificate_codec_config_unbounded()
        }

        fn make_notarization(
            round: Round,
            parent_view: View,
            _parent_payload: D, // Simplex doesn't use parent_payload in proposals
            payload: D,
            schemes: &[Self::Scheme],
            quorum: u32,
        ) -> SimplexNotarization<SimplexS, D> {
            let proposal = SimplexProposal {
                round,
                parent: parent_view,
                payload,
            };
            let notarizes: Vec<_> = schemes
                .iter()
                .take(quorum as usize)
                .map(|scheme| SimplexNotarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            SimplexNotarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
        }

        fn make_finalization(
            round: Round,
            parent_view: View,
            _parent_payload: D,
            payload: D,
            schemes: &[Self::Scheme],
            quorum: u32,
        ) -> SimplexFinalization<SimplexS, D> {
            let proposal = SimplexProposal {
                round,
                parent: parent_view,
                payload,
            };
            let finalizes: Vec<_> = schemes
                .iter()
                .take(quorum as usize)
                .map(|scheme| SimplexFinalize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            SimplexFinalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
        }

        fn notarization_activity(
            notarization: SimplexNotarization<SimplexS, D>,
        ) -> SimplexActivity<SimplexS, D> {
            SimplexActivity::Notarization(notarization)
        }

        fn finalization_activity(
            finalization: SimplexFinalization<SimplexS, D>,
        ) -> SimplexActivity<SimplexS, D> {
            SimplexActivity::Finalization(finalization)
        }

        fn certificate_codec_config_unbounded(
        ) -> <<Self::Consensus as MarshalConsensus>::Finalization as commonware_codec::Read>::Cfg
        {
            SimplexS::certificate_codec_config_unbounded()
        }
    }

    /// Minimmit consensus test harness implementation.
    struct MinimmitHarness;

    impl ConsensusTestHarness for MinimmitHarness {
        type Consensus = MinimmitC;
        type Scheme = MinimmitS;
        type Provider = MinimmitP;

        fn fixture(
            context: &mut deterministic::Context,
            namespace: &[u8],
            n: u32,
        ) -> Fixture<Self::Scheme> {
            minimmit_bls12381_threshold::fixture::<V, _>(context, namespace, n)
        }

        fn provider(scheme: Self::Scheme) -> Self::Provider {
            ConstantProvider::new(scheme)
        }

        fn l_quorum(n: u32) -> u32 {
            // Minimmit uses N5f1 model: f = (n-1)/5, L-quorum = n-f
            use commonware_utils::Faults;
            commonware_utils::N5f1::quorum(n)
        }

        fn notarization_codec_config(
        ) -> <<Self::Consensus as MarshalConsensus>::Notarization as commonware_codec::Read>::Cfg
        {
            MinimmitS::certificate_codec_config_unbounded()
        }

        fn finalization_codec_config(
        ) -> <<Self::Consensus as MarshalConsensus>::Finalization as commonware_codec::Read>::Cfg
        {
            MinimmitS::certificate_codec_config_unbounded()
        }

        fn make_notarization(
            round: Round,
            parent_view: View,
            parent_payload: D,
            payload: D,
            schemes: &[Self::Scheme],
            quorum: u32,
        ) -> MNotarization<MinimmitS, D> {
            let proposal = MinimmitProposal {
                round,
                parent: parent_view,
                parent_payload,
                payload,
            };
            let notarizes: Vec<_> = schemes
                .iter()
                .take(quorum as usize)
                .map(|scheme| MinimmitNotarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            MNotarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
        }

        fn make_finalization(
            round: Round,
            parent_view: View,
            parent_payload: D,
            payload: D,
            schemes: &[Self::Scheme],
            _quorum: u32,
        ) -> MinimmitFinalization<MinimmitS, D> {
            // In minimmit, finalization is achieved through L consecutive notarizations,
            // not separate finalize votes like simplex. Finalization uses notarize votes.
            // L-quorum for N5f1 model is n-f, which for n=4 is 4 (all validators).
            let proposal = MinimmitProposal {
                round,
                parent: parent_view,
                parent_payload,
                payload,
            };
            // Use L-quorum (n-f) for finalization, ignoring the quorum parameter
            let l_quorum = Self::l_quorum(schemes.len() as u32) as usize;
            let notarizes: Vec<_> = schemes
                .iter()
                .take(l_quorum)
                .map(|scheme| MinimmitNotarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            MinimmitFinalization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
        }

        fn notarization_activity(
            notarization: MNotarization<MinimmitS, D>,
        ) -> MinimmitActivity<MinimmitS, D> {
            MinimmitActivity::MNotarization(notarization)
        }

        fn finalization_activity(
            finalization: MinimmitFinalization<MinimmitS, D>,
        ) -> MinimmitActivity<MinimmitS, D> {
            MinimmitActivity::Finalization(finalization)
        }

        fn certificate_codec_config_unbounded(
        ) -> <<Self::Consensus as MarshalConsensus>::Finalization as commonware_codec::Read>::Cfg
        {
            MinimmitS::certificate_codec_config_unbounded()
        }
    }

    /// Default leader key for tests.
    fn default_leader() -> K {
        PrivateKey::from_seed(0).public_key()
    }

    /// Create a test block with a derived context.
    ///
    /// The context is constructed with:
    /// - Round: epoch 0, view = height
    /// - Leader: default (all zeros)
    /// - Parent: (view = height - 1, commitment = parent)
    fn make_block(parent: D, height: Height, timestamp: u64) -> B {
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

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const NAMESPACE: &[u8] = b"test";
    const NUM_VALIDATORS: u32 = 4;
    const QUORUM: u32 = 3;
    const NUM_BLOCKS: u64 = 160;
    const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(20);
    const LINK: Link = Link {
        latency: Duration::from_millis(100),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    const UNRELIABLE_LINK: Link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(50),
        success_rate: 0.7,
    };
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    async fn setup_validator<H: ConsensusTestHarness>(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: H::Provider,
    ) -> (
        Application<B>,
        crate::marshal::ingress::mailbox::Mailbox<H::Consensus, B>,
        Height,
    ) {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            block_codec_config: (),
            notarization_codec_config: H::notarization_codec_config(),
            finalization_codec_config: H::finalization_codec_config(),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        // Create the resolver
        let control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
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

        // Create a buffered broadcast engine and get its mailbox
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
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{}-finalizations-by-height-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_buffer_pool: config.buffer_pool.clone(),
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
                codec_config: H::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        // Initialize finalized blocks
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
                freezer_key_buffer_pool: config.buffer_pool.clone(),
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

        let (actor, mailbox, processed_height) = actor::Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<B>::default();

        // Start the application
        actor.start(application.clone(), buffer, resolver);

        (application, mailbox, processed_height)
    }

    fn setup_network(
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

    async fn setup_network_links(
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

    // ==================== Simplex Tests ====================

    #[test_traced("WARN")]
    fn test_finalize_good_links_simplex() {
        for seed in 0..5 {
            let result1 = finalize::<SimplexHarness>(seed, LINK, false);
            let result2 = finalize::<SimplexHarness>(seed, LINK, false);
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_bad_links_simplex() {
        for seed in 0..5 {
            let result1 = finalize::<SimplexHarness>(seed, UNRELIABLE_LINK, false);
            let result2 = finalize::<SimplexHarness>(seed, UNRELIABLE_LINK, false);
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_good_links_quorum_sees_finalization_simplex() {
        for seed in 0..5 {
            let result1 = finalize::<SimplexHarness>(seed, LINK, true);
            let result2 = finalize::<SimplexHarness>(seed, LINK, true);
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("DEBUG")]
    fn test_finalize_bad_links_quorum_sees_finalization_simplex() {
        for seed in 0..5 {
            let result1 = finalize::<SimplexHarness>(seed, UNRELIABLE_LINK, true);
            let result2 = finalize::<SimplexHarness>(seed, UNRELIABLE_LINK, true);
            assert_eq!(result1, result2);
        }
    }

    // ==================== Minimmit Tests ====================

    #[test_traced("WARN")]
    fn test_finalize_good_links_minimmit() {
        for seed in 0..5 {
            let result1 = finalize::<MinimmitHarness>(seed, LINK, false);
            let result2 = finalize::<MinimmitHarness>(seed, LINK, false);
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_bad_links_minimmit() {
        for seed in 0..5 {
            let result1 = finalize::<MinimmitHarness>(seed, UNRELIABLE_LINK, false);
            let result2 = finalize::<MinimmitHarness>(seed, UNRELIABLE_LINK, false);
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_good_links_quorum_sees_finalization_minimmit() {
        for seed in 0..5 {
            let result1 = finalize::<MinimmitHarness>(seed, LINK, true);
            let result2 = finalize::<MinimmitHarness>(seed, LINK, true);
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("DEBUG")]
    fn test_finalize_bad_links_quorum_sees_finalization_minimmit() {
        for seed in 0..5 {
            let result1 = finalize::<MinimmitHarness>(seed, UNRELIABLE_LINK, true);
            let result2 = finalize::<MinimmitHarness>(seed, UNRELIABLE_LINK, true);
            assert_eq!(result1, result2);
        }
    }

    // ==================== Generic Test Functions ====================

    fn finalize<H: ConsensusTestHarness>(
        seed: u64,
        link: Link,
        quorum_sees_finalization: bool,
    ) -> String {
        let runner = deterministic::Runner::new(
            deterministic::Config::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(600))),
        );
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), Some(3));
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Initialize applications and actors
            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();

            // Register the initial peer set.
            let mut manager = oracle.manager();
            manager
                .update(0, participants.clone().try_into().unwrap())
                .await;
            for (i, validator) in participants.iter().enumerate() {
                let (application, actor, _processed_height) = setup_validator::<H>(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    H::provider(schemes[i].clone()),
                )
                .await;
                applications.insert(validator.clone(), application);
                actors.push(actor);
            }

            // Add links between all peers
            setup_network_links(&mut oracle, &participants, link.clone()).await;

            // Generate blocks, skipping the genesis block.
            // We need to track parent payloads for minimmit compatibility.
            let mut blocks = Vec::<B>::new();
            let mut parent_payloads = BTreeMap::<Height, D>::new();
            let genesis_digest = Sha256::hash(b"");
            parent_payloads.insert(Height::new(0), genesis_digest);

            let mut parent = genesis_digest;
            for i in 1..=NUM_BLOCKS {
                let block = make_block(parent, Height::new(i), i);
                parent = block.digest();
                parent_payloads.insert(Height::new(i), parent);
                blocks.push(block);
            }

            // Broadcast and finalize blocks in random order
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            blocks.shuffle(&mut context);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(
                    !height.is_zero(),
                    "genesis block should not have been generated"
                );

                // Calculate the epoch and round for the block
                let bounds = epocher.containing(height).unwrap();
                let round = Round::new(bounds.epoch(), View::new(height.get()));
                let parent_view = View::new(height.previous().unwrap().get());
                let parent_payload = *parent_payloads.get(&height.previous().unwrap()).unwrap();
                let payload = block.digest();

                // Broadcast block by one validator
                let actor_index: usize = (height.get() % (NUM_VALIDATORS as u64)) as usize;
                let mut actor = actors[actor_index].clone();
                actor.proposed(round, block.clone()).await;
                actor.verified(round, block.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the block before continuing.
                context.sleep(link.latency).await;

                // Notarize block by the validator that broadcasted it
                let notarization = H::make_notarization(
                    round,
                    parent_view,
                    parent_payload,
                    payload,
                    &schemes,
                    QUORUM,
                );
                actor.report(H::notarization_activity(notarization)).await;

                // Finalize block by all validators
                // Always finalize 1) the last block in each epoch 2) the last block in the chain.
                let fin = H::make_finalization(
                    round,
                    parent_view,
                    parent_payload,
                    payload,
                    &schemes,
                    QUORUM,
                );
                if quorum_sees_finalization {
                    // If `quorum_sees_finalization` is set, ensure at least `QUORUM` sees a finalization 20%
                    // of the time.
                    let do_finalize = context.gen_bool(0.2);
                    for (i, actor) in actors
                        .iter_mut()
                        .choose_multiple(&mut context, NUM_VALIDATORS as usize)
                        .iter_mut()
                        .enumerate()
                    {
                        if (do_finalize && i < QUORUM as usize)
                            || height == Height::new(NUM_BLOCKS)
                            || height == bounds.last()
                        {
                            actor.report(H::finalization_activity(fin.clone())).await;
                        }
                    }
                } else {
                    // If `quorum_sees_finalization` is not set, finalize randomly with a 20% chance for each
                    // individual participant.
                    for actor in actors.iter_mut() {
                        if context.gen_bool(0.2)
                            || height == Height::new(NUM_BLOCKS)
                            || height == bounds.last()
                        {
                            actor.report(H::finalization_activity(fin.clone())).await;
                        }
                    }
                }
            }

            // Check that all applications received all blocks.
            let mut finished = false;
            while !finished {
                // Avoid a busy loop
                context.sleep(Duration::from_secs(1)).await;

                // If not all validators have finished, try again
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
                    if height < Height::new(NUM_BLOCKS) {
                        finished = false;
                        break;
                    }
                }
            }

            // Return state
            context.auditor().state()
        })
    }

    #[test_traced("WARN")]
    fn test_sync_height_floor_simplex() {
        sync_height_floor::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_sync_height_floor_minimmit() {
        sync_height_floor::<MinimmitHarness>();
    }

    fn sync_height_floor<H: ConsensusTestHarness>() {
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
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Initialize applications and actors
            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();

            // Register the initial peer set.
            let mut manager = oracle.manager();
            manager
                .update(0, participants.clone().try_into().unwrap())
                .await;
            for (i, validator) in participants.iter().enumerate().skip(1) {
                let (application, actor, _processed_height) = setup_validator::<H>(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    H::provider(schemes[i].clone()),
                )
                .await;
                applications.insert(validator.clone(), application);
                actors.push(actor);
            }

            // Add links between all peers except for the first, to guarantee
            // the first peer does not receive any blocks during broadcast.
            setup_network_links(&mut oracle, &participants[1..], LINK).await;

            // Generate blocks, skipping the genesis block.
            let mut blocks = Vec::<B>::new();
            let mut parent_payloads = BTreeMap::<Height, D>::new();
            let genesis_digest = Sha256::hash(b"");
            parent_payloads.insert(Height::new(0), genesis_digest);

            let mut parent = genesis_digest;
            for i in 1..=NUM_BLOCKS {
                let block = make_block(parent, Height::new(i), i);
                parent = block.digest();
                parent_payloads.insert(Height::new(i), parent);
                blocks.push(block);
            }

            // Broadcast and finalize blocks
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(
                    !height.is_zero(),
                    "genesis block should not have been generated"
                );

                // Calculate the epoch and round for the block
                let bounds = epocher.containing(height).unwrap();
                let round = Round::new(bounds.epoch(), View::new(height.get()));
                let parent_view = View::new(height.previous().unwrap().get());
                let parent_payload = *parent_payloads.get(&height.previous().unwrap()).unwrap();
                let payload = block.digest();

                // Broadcast block by one validator
                let actor_index: usize = (height.get() % (applications.len() as u64)) as usize;
                let mut actor = actors[actor_index].clone();
                actor.proposed(round, block.clone()).await;
                actor.verified(round, block.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the block before continuing.
                context.sleep(LINK.latency).await;

                // Notarize block by the validator that broadcasted it
                let notarization = H::make_notarization(
                    round,
                    parent_view,
                    parent_payload,
                    payload,
                    &schemes,
                    QUORUM,
                );
                actor.report(H::notarization_activity(notarization)).await;

                // Finalize block by all validators except for the first.
                let fin = H::make_finalization(
                    round,
                    parent_view,
                    parent_payload,
                    payload,
                    &schemes,
                    QUORUM,
                );
                for actor in actors.iter_mut() {
                    actor.report(H::finalization_activity(fin.clone())).await;
                }
            }

            // Check that all applications (except for the first) received all blocks.
            let mut finished = false;
            while !finished {
                // Avoid a busy loop
                context.sleep(Duration::from_secs(1)).await;

                // If not all validators have finished, try again
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
                    if height < Height::new(NUM_BLOCKS) {
                        finished = false;
                        break;
                    }
                }
            }

            // Create the first validator now that all blocks have been finalized by the others.
            let validator = participants.first().unwrap();
            let (app, mut actor, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                validator.clone(),
                H::provider(schemes[0].clone()),
            )
            .await;

            // Add links between all peers, including the first.
            setup_network_links(&mut oracle, &participants, LINK).await;

            const NEW_SYNC_FLOOR: u64 = 100;
            let second_actor = &mut actors[1];
            let latest_finalization = second_actor
                .get_finalization(Height::new(NUM_BLOCKS))
                .await
                .unwrap();

            // Set the sync height floor of the first actor to block #100.
            actor.set_floor(Height::new(NEW_SYNC_FLOOR)).await;

            // Notify the first actor of the latest finalization to the first actor to trigger backfill.
            // The sync should only reach the sync height floor.
            actor
                .report(H::finalization_activity(latest_finalization))
                .await;

            // Wait until the first actor has backfilled to the sync height floor.
            let mut finished = false;
            while !finished {
                // Avoid a busy loop
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
                if height < Height::new(NUM_BLOCKS) {
                    finished = false;
                    continue;
                }
            }

            // Check that the first actor has blocks from NEW_SYNC_FLOOR onward, but not before.
            for height in 1..=NUM_BLOCKS {
                let block = actor
                    .get_block(Identifier::Height(Height::new(height)))
                    .await;
                if height <= NEW_SYNC_FLOOR {
                    assert!(block.is_none());
                } else {
                    assert_eq!(block.unwrap().height(), Height::new(height));
                }
            }
        })
    }

    #[test_traced("WARN")]
    fn test_prune_finalized_archives_simplex() {
        prune_finalized_archives::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_prune_finalized_archives_minimmit() {
        prune_finalized_archives::<MinimmitHarness>();
    }

    fn prune_finalized_archives<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::new(
            deterministic::Config::new().with_timeout(Some(Duration::from_secs(120))),
        );
        runner.start(|mut context| async move {
            let oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let validator = participants[0].clone();
            let partition_prefix = format!("prune-test-{}", validator.clone());
            let buffer_pool = PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
            let control = oracle.control(validator.clone());

            // Helper function to initialize marshal with prunable archives
            async fn init_marshal_inner<H2: ConsensusTestHarness>(
                ctx: deterministic::Context,
                validator: K,
                schemes: Vec<H2::Scheme>,
                partition_prefix: String,
                buffer_pool: PoolRef,
                control: commonware_p2p::simulated::Control<K, deterministic::Context>,
                oracle_manager: commonware_p2p::simulated::Manager<K, deterministic::Context>,
            ) -> (
                crate::marshal::ingress::mailbox::Mailbox<H2::Consensus, B>,
                Application<B>,
            ) {
                let provider = H2::provider(schemes[0].clone());
                let config = Config {
                    provider,
                    epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                    mailbox_size: 100,
                    view_retention_timeout: ViewDelta::new(10),
                    max_repair: NZUsize!(10),
                    block_codec_config: (),
                    notarization_codec_config: H2::notarization_codec_config(),
                    finalization_codec_config: H2::finalization_codec_config(),
                    partition_prefix: partition_prefix.clone(),
                    prunable_items_per_section: NZU64!(10),
                    replay_buffer: NZUsize!(1024),
                    key_write_buffer: NZUsize!(1024),
                    value_write_buffer: NZUsize!(1024),
                    buffer_pool: buffer_pool.clone(),
                    strategy: Sequential,
                };

                // Create resolver
                let backfill = control.register(0, TEST_QUOTA).await.unwrap();
                let resolver_cfg = resolver::Config {
                    public_key: validator.clone(),
                    manager: oracle_manager,
                    blocker: control.clone(),
                    mailbox_size: config.mailbox_size,
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(100),
                    priority_requests: false,
                    priority_responses: false,
                };
                let resolver = resolver::init(&ctx, resolver_cfg, backfill);

                // Create buffered broadcast engine
                let broadcast_config = buffered::Config {
                    public_key: validator.clone(),
                    mailbox_size: config.mailbox_size,
                    deque_size: 10,
                    priority: false,
                    codec_config: (),
                };
                let (broadcast_engine, buffer) =
                    buffered::Engine::new(ctx.clone(), broadcast_config);
                let network = control.register(1, TEST_QUOTA).await.unwrap();
                broadcast_engine.start(network);

                // Initialize prunable archives
                let finalizations_by_height = prunable::Archive::init(
                    ctx.with_label("finalizations_by_height"),
                    prunable::Config {
                        translator: EightCap,
                        key_partition: format!("{}-finalizations-by-height-key", partition_prefix),
                        key_buffer_pool: buffer_pool.clone(),
                        value_partition: format!(
                            "{}-finalizations-by-height-value",
                            partition_prefix
                        ),
                        compression: None,
                        codec_config: H2::certificate_codec_config_unbounded(),
                        items_per_section: NZU64!(10),
                        key_write_buffer: config.key_write_buffer,
                        value_write_buffer: config.value_write_buffer,
                        replay_buffer: config.replay_buffer,
                    },
                )
                .await
                .expect("failed to initialize finalizations by height archive");

                let finalized_blocks = prunable::Archive::init(
                    ctx.with_label("finalized_blocks"),
                    prunable::Config {
                        translator: EightCap,
                        key_partition: format!("{}-finalized-blocks-key", partition_prefix),
                        key_buffer_pool: buffer_pool.clone(),
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

                let (actor, mailbox, _processed_height) = actor::Actor::init(
                    ctx.clone(),
                    finalizations_by_height,
                    finalized_blocks,
                    config,
                )
                .await;
                let application = Application::<B>::default();
                actor.start(application.clone(), buffer, resolver);

                (mailbox, application)
            }

            // Initial setup
            let (mut mailbox, application) = init_marshal_inner::<H>(
                context.with_label("init"),
                validator.clone(),
                schemes.clone(),
                partition_prefix.clone(),
                buffer_pool.clone(),
                control.clone(),
                oracle.manager(),
            )
            .await;

            // Finalize blocks 1-20
            let mut parent_payloads = BTreeMap::<Height, D>::new();
            let genesis_digest = Sha256::hash(b"");
            parent_payloads.insert(Height::new(0), genesis_digest);

            let mut parent = genesis_digest;
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            for i in 1..=20u64 {
                let block = make_block(parent, Height::new(i), i);
                let commitment = block.digest();
                parent_payloads.insert(Height::new(i), commitment);
                let bounds = epocher.containing(Height::new(i)).unwrap();
                let round = Round::new(bounds.epoch(), View::new(i));
                let parent_view = View::new(i - 1);
                let parent_payload = *parent_payloads.get(&Height::new(i - 1)).unwrap();

                mailbox.verified(round, block.clone()).await;
                let finalization = H::make_finalization(
                    round,
                    parent_view,
                    parent_payload,
                    commitment,
                    &schemes,
                    QUORUM,
                );
                mailbox.report(H::finalization_activity(finalization)).await;

                parent = commitment;
            }

            // Wait for application to process all blocks
            // After this, last_processed_height will be 20
            while application.blocks().len() < 20 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Verify all blocks are accessible before pruning
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

            // All blocks should still be accessible (prune was ignored)
            mailbox.prune(Height::new(25)).await;
            context.sleep(Duration::from_millis(50)).await;
            for i in 1..=20u64 {
                assert!(
                    mailbox.get_block(Height::new(i)).await.is_some(),
                    "block {i} should still exist after pruning above floor"
                );
            }

            // Pruning at height 10 should prune blocks below 10 (heights 1-9)
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

            // Blocks at or above prune height (10-20) should still be accessible
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

            // Pruning at height 20 should prune blocks 10-19
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

            // Block 20 should still be accessible
            assert!(
                mailbox.get_block(Height::new(20)).await.is_some(),
                "block 20 should still exist"
            );
            assert!(
                mailbox.get_finalization(Height::new(20)).await.is_some(),
                "finalization 20 should still exist"
            );

            // Restart to verify pruning persisted to storage (not just in-memory)
            drop(mailbox);
            let (mut mailbox, _application) = init_marshal_inner::<H>(
                context.with_label("restart"),
                validator.clone(),
                schemes.clone(),
                partition_prefix.clone(),
                buffer_pool.clone(),
                control.clone(),
                oracle.manager(),
            )
            .await;

            // Verify blocks 1-19 are still pruned after restart
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

            // Verify block 20 persisted correctly after restart
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

    #[test_traced("WARN")]
    fn test_subscribe_basic_block_delivery_simplex() {
        subscribe_basic_block_delivery::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_subscribe_basic_block_delivery_minimmit() {
        subscribe_basic_block_delivery::<MinimmitHarness>();
    }

    fn subscribe_basic_block_delivery<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor, _processed_height) = setup_validator::<H>(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    H::provider(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let genesis_digest = Sha256::hash(b"");
            let block = make_block(genesis_digest, Height::new(1), 1);
            let commitment = block.digest();

            let subscription_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(1))), commitment)
                .await;

            actor
                .verified(Round::new(Epoch::new(0), View::new(1)), block.clone())
                .await;

            let round = Round::new(Epoch::new(0), View::new(1));
            let notarization = H::make_notarization(
                round,
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            actor.report(H::notarization_activity(notarization)).await;

            let finalization = H::make_finalization(
                round,
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(finalization)).await;

            let received_block = subscription_rx.await.unwrap();
            assert_eq!(received_block.digest(), block.digest());
            assert_eq!(received_block.height(), Height::new(1));
        })
    }

    #[test_traced("WARN")]
    fn test_subscribe_multiple_subscriptions_simplex() {
        subscribe_multiple_subscriptions::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_subscribe_multiple_subscriptions_minimmit() {
        subscribe_multiple_subscriptions::<MinimmitHarness>();
    }

    fn subscribe_multiple_subscriptions<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor, _processed_height) = setup_validator::<H>(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    H::provider(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let genesis_digest = Sha256::hash(b"");
            let block1 = make_block(genesis_digest, Height::new(1), 1);
            let block2 = make_block(block1.digest(), Height::new(2), 2);
            let commitment1 = block1.digest();
            let commitment2 = block2.digest();

            let sub1_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(1))), commitment1)
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(2))), commitment2)
                .await;
            let sub3_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(1))), commitment1)
                .await;

            actor
                .verified(Round::new(Epoch::new(0), View::new(1)), block1.clone())
                .await;
            actor
                .verified(Round::new(Epoch::new(0), View::new(2)), block2.clone())
                .await;

            // Track parent payloads for minimmit compatibility
            let parent_payloads = [genesis_digest, commitment1];
            for (i, (view, block)) in [(1u64, block1.clone()), (2u64, block2.clone())]
                .into_iter()
                .enumerate()
            {
                let view = View::new(view);
                let round = Round::new(Epoch::zero(), view);
                let parent_view = view.previous().unwrap();
                let parent_payload = parent_payloads[i];
                let payload = block.digest();

                let notarization = H::make_notarization(
                    round,
                    parent_view,
                    parent_payload,
                    payload,
                    &schemes,
                    QUORUM,
                );
                actor.report(H::notarization_activity(notarization)).await;

                let finalization = H::make_finalization(
                    round,
                    parent_view,
                    parent_payload,
                    payload,
                    &schemes,
                    QUORUM,
                );
                actor.report(H::finalization_activity(finalization)).await;
            }

            let received1_sub1 = sub1_rx.await.unwrap();
            let received2 = sub2_rx.await.unwrap();
            let received1_sub3 = sub3_rx.await.unwrap();

            assert_eq!(received1_sub1.digest(), block1.digest());
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received1_sub3.digest(), block1.digest());
            assert_eq!(received1_sub1.height(), Height::new(1));
            assert_eq!(received2.height(), Height::new(2));
            assert_eq!(received1_sub3.height(), Height::new(1));
        })
    }

    #[test_traced("WARN")]
    fn test_subscribe_canceled_subscriptions_simplex() {
        subscribe_canceled_subscriptions::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_subscribe_canceled_subscriptions_minimmit() {
        subscribe_canceled_subscriptions::<MinimmitHarness>();
    }

    fn subscribe_canceled_subscriptions<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor, _processed_height) = setup_validator::<H>(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    H::provider(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let genesis_digest = Sha256::hash(b"");
            let block1 = make_block(genesis_digest, Height::new(1), 1);
            let block2 = make_block(block1.digest(), Height::new(2), 2);
            let commitment1 = block1.digest();
            let commitment2 = block2.digest();

            let sub1_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(1))), commitment1)
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(2))), commitment2)
                .await;

            drop(sub1_rx);

            actor
                .verified(Round::new(Epoch::new(0), View::new(1)), block1.clone())
                .await;
            actor
                .verified(Round::new(Epoch::new(0), View::new(2)), block2.clone())
                .await;

            // Track parent payloads for minimmit compatibility
            let parent_payloads = [genesis_digest, commitment1];
            for (i, (view, block)) in [(1u64, block1.clone()), (2u64, block2.clone())]
                .into_iter()
                .enumerate()
            {
                let view = View::new(view);
                let round = Round::new(Epoch::zero(), view);
                let parent_view = view.previous().unwrap();
                let parent_payload = parent_payloads[i];
                let payload = block.digest();

                let notarization = H::make_notarization(
                    round,
                    parent_view,
                    parent_payload,
                    payload,
                    &schemes,
                    QUORUM,
                );
                actor.report(H::notarization_activity(notarization)).await;

                let finalization = H::make_finalization(
                    round,
                    parent_view,
                    parent_payload,
                    payload,
                    &schemes,
                    QUORUM,
                );
                actor.report(H::finalization_activity(finalization)).await;
            }

            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), Height::new(2));
        })
    }

    #[test_traced("WARN")]
    fn test_subscribe_blocks_from_different_sources_simplex() {
        subscribe_blocks_from_different_sources::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_subscribe_blocks_from_different_sources_minimmit() {
        subscribe_blocks_from_different_sources::<MinimmitHarness>();
    }

    fn subscribe_blocks_from_different_sources<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor, _processed_height) = setup_validator::<H>(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    H::provider(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let genesis_digest = Sha256::hash(b"");
            let block1 = make_block(genesis_digest, Height::new(1), 1);
            let block2 = make_block(block1.digest(), Height::new(2), 2);
            let block3 = make_block(block2.digest(), Height::new(3), 3);
            let block4 = make_block(block3.digest(), Height::new(4), 4);
            let block5 = make_block(block4.digest(), Height::new(5), 5);

            let sub1_rx = actor.subscribe(None, block1.digest()).await;
            let sub2_rx = actor.subscribe(None, block2.digest()).await;
            let sub3_rx = actor.subscribe(None, block3.digest()).await;
            let sub4_rx = actor.subscribe(None, block4.digest()).await;
            let sub5_rx = actor.subscribe(None, block5.digest()).await;

            // Block1: Broadcasted by the actor
            actor
                .proposed(Round::new(Epoch::zero(), View::new(1)), block1.clone())
                .await;
            context.sleep(Duration::from_millis(20)).await;

            // Block1: delivered
            let received1 = sub1_rx.await.unwrap();
            assert_eq!(received1.digest(), block1.digest());
            assert_eq!(received1.height(), Height::new(1));

            // Block2: Verified by the actor
            actor
                .verified(Round::new(Epoch::new(0), View::new(2)), block2.clone())
                .await;

            // Block2: delivered
            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), Height::new(2));

            // Block3: Notarized by the actor
            let notarization3 = H::make_notarization(
                Round::new(Epoch::new(0), View::new(3)),
                View::new(2),
                block2.digest(),
                block3.digest(),
                &schemes,
                QUORUM,
            );
            actor.report(H::notarization_activity(notarization3)).await;
            actor
                .verified(Round::new(Epoch::new(0), View::new(3)), block3.clone())
                .await;

            // Block3: delivered
            let received3 = sub3_rx.await.unwrap();
            assert_eq!(received3.digest(), block3.digest());
            assert_eq!(received3.height(), Height::new(3));

            // Block4: Finalized by the actor
            let finalization4 = H::make_finalization(
                Round::new(Epoch::new(0), View::new(4)),
                View::new(3),
                block3.digest(),
                block4.digest(),
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(finalization4)).await;
            actor
                .verified(Round::new(Epoch::new(0), View::new(4)), block4.clone())
                .await;

            // Block4: delivered
            let received4 = sub4_rx.await.unwrap();
            assert_eq!(received4.digest(), block4.digest());
            assert_eq!(received4.height(), Height::new(4));

            // Block5: Broadcasted by a remote node (different actor)
            let remote_actor = &mut actors[1].clone();
            remote_actor
                .proposed(Round::new(Epoch::zero(), View::new(5)), block5.clone())
                .await;
            context.sleep(Duration::from_millis(20)).await;

            // Block5: delivered
            let received5 = sub5_rx.await.unwrap();
            assert_eq!(received5.digest(), block5.digest());
            assert_eq!(received5.height(), Height::new(5));
        })
    }

    #[test_traced("WARN")]
    fn test_get_info_basic_queries_present_and_missing_simplex() {
        get_info_basic_queries_present_and_missing::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_get_info_basic_queries_present_and_missing_minimmit() {
        get_info_basic_queries_present_and_missing::<MinimmitHarness>();
    }

    fn get_info_basic_queries_present_and_missing<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Single validator actor
            let me = participants[0].clone();
            let (_application, mut actor, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                H::provider(schemes[0].clone()),
            )
            .await;

            // Initially, no latest
            assert!(actor.get_info(Identifier::Latest).await.is_none());

            // Before finalization, specific height returns None
            assert!(actor.get_info(Height::new(1)).await.is_none());

            // Create and verify a block, then finalize it
            let genesis_digest = Sha256::hash(b"");
            let block = make_block(genesis_digest, Height::new(1), 1);
            let digest = block.digest();
            let round = Round::new(Epoch::new(0), View::new(1));
            actor.verified(round, block.clone()).await;

            let finalization = H::make_finalization(
                round,
                View::new(0),
                genesis_digest,
                digest,
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(finalization)).await;

            // Latest should now be the finalized block
            assert_eq!(
                actor.get_info(Identifier::Latest).await,
                Some((Height::new(1), digest))
            );

            // Height 1 now present
            assert_eq!(
                actor.get_info(Height::new(1)).await,
                Some((Height::new(1), digest))
            );

            // Commitment should map to its height
            assert_eq!(
                actor.get_info(&digest).await,
                Some((Height::new(1), digest))
            );

            // Missing height
            assert!(actor.get_info(Height::new(2)).await.is_none());

            // Missing commitment
            let missing = Sha256::hash(b"missing");
            assert!(actor.get_info(&missing).await.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_get_info_latest_progression_multiple_finalizations_simplex() {
        get_info_latest_progression_multiple_finalizations::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_get_info_latest_progression_multiple_finalizations_minimmit() {
        get_info_latest_progression_multiple_finalizations::<MinimmitHarness>();
    }

    fn get_info_latest_progression_multiple_finalizations<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Single validator actor
            let me = participants[0].clone();
            let (_application, mut actor, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                H::provider(schemes[0].clone()),
            )
            .await;

            // Initially none
            assert!(actor.get_info(Identifier::Latest).await.is_none());

            // Build and finalize heights 1..=3
            let genesis_digest = Sha256::hash(b"");
            let block1 = make_block(genesis_digest, Height::new(1), 1);
            let d1 = block1.digest();
            actor
                .verified(Round::new(Epoch::new(0), View::new(1)), block1.clone())
                .await;
            let f1 = H::make_finalization(
                Round::new(Epoch::new(0), View::new(1)),
                View::new(0),
                genesis_digest,
                d1,
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(f1)).await;
            let latest = actor.get_info(Identifier::Latest).await;
            assert_eq!(latest, Some((Height::new(1), d1)));

            let block2 = make_block(d1, Height::new(2), 2);
            let d2 = block2.digest();
            actor
                .verified(Round::new(Epoch::new(0), View::new(2)), block2.clone())
                .await;
            let f2 = H::make_finalization(
                Round::new(Epoch::new(0), View::new(2)),
                View::new(1),
                d1,
                d2,
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(f2)).await;
            let latest = actor.get_info(Identifier::Latest).await;
            assert_eq!(latest, Some((Height::new(2), d2)));

            let block3 = make_block(d2, Height::new(3), 3);
            let d3 = block3.digest();
            actor
                .verified(Round::new(Epoch::new(0), View::new(3)), block3.clone())
                .await;
            let f3 = H::make_finalization(
                Round::new(Epoch::new(0), View::new(3)),
                View::new(2),
                d2,
                d3,
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(f3)).await;
            let latest = actor.get_info(Identifier::Latest).await;
            assert_eq!(latest, Some((Height::new(3), d3)));
        })
    }

    #[test_traced("WARN")]
    fn test_get_block_by_height_and_latest_simplex() {
        get_block_by_height_and_latest::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_get_block_by_height_and_latest_minimmit() {
        get_block_by_height_and_latest::<MinimmitHarness>();
    }

    fn get_block_by_height_and_latest<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (application, mut actor, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                H::provider(schemes[0].clone()),
            )
            .await;

            // Before any finalization, GetBlock::Latest should be None
            let latest_block = actor.get_block(Identifier::Latest).await;
            assert!(latest_block.is_none());
            assert!(application.tip().is_none());

            // Finalize a block at height 1
            let genesis_digest = Sha256::hash(b"");
            let block = make_block(genesis_digest, Height::new(1), 1);
            let commitment = block.digest();
            let round = Round::new(Epoch::new(0), View::new(1));
            actor.verified(round, block.clone()).await;
            let finalization = H::make_finalization(
                round,
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(finalization)).await;

            // Get by height
            let by_height = actor
                .get_block(Height::new(1))
                .await
                .expect("missing block by height");
            assert_eq!(by_height.height(), Height::new(1));
            assert_eq!(by_height.digest(), commitment);
            assert_eq!(application.tip(), Some((Height::new(1), commitment)));

            // Get by latest
            let by_latest = actor
                .get_block(Identifier::Latest)
                .await
                .expect("missing block by latest");
            assert_eq!(by_latest.height(), Height::new(1));
            assert_eq!(by_latest.digest(), commitment);

            // Missing height
            let by_height = actor.get_block(Height::new(2)).await;
            assert!(by_height.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_get_block_by_commitment_from_sources_and_missing_simplex() {
        get_block_by_commitment_from_sources_and_missing::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_get_block_by_commitment_from_sources_and_missing_minimmit() {
        get_block_by_commitment_from_sources_and_missing::<MinimmitHarness>();
    }

    fn get_block_by_commitment_from_sources_and_missing<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                H::provider(schemes[0].clone()),
            )
            .await;

            // 1) From cache via verified
            let genesis_digest = Sha256::hash(b"");
            let ver_block = make_block(genesis_digest, Height::new(1), 1);
            let ver_commitment = ver_block.digest();
            let round1 = Round::new(Epoch::new(0), View::new(1));
            actor.verified(round1, ver_block.clone()).await;
            let got = actor
                .get_block(&ver_commitment)
                .await
                .expect("missing block from cache");
            assert_eq!(got.digest(), ver_commitment);

            // 2) From finalized archive
            let fin_block = make_block(ver_commitment, Height::new(2), 2);
            let fin_commitment = fin_block.digest();
            let round2 = Round::new(Epoch::new(0), View::new(2));
            actor.verified(round2, fin_block.clone()).await;
            let finalization = H::make_finalization(
                round2,
                View::new(1),
                ver_commitment,
                fin_commitment,
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(finalization)).await;
            let got = actor
                .get_block(&fin_commitment)
                .await
                .expect("missing block from finalized archive");
            assert_eq!(got.digest(), fin_commitment);
            assert_eq!(got.height(), Height::new(2));

            // 3) Missing commitment
            let missing = Sha256::hash(b"definitely-missing");
            let missing_block = actor.get_block(&missing).await;
            assert!(missing_block.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_get_finalization_by_height_simplex() {
        get_finalization_by_height::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_get_finalization_by_height_minimmit() {
        get_finalization_by_height::<MinimmitHarness>();
    }

    fn get_finalization_by_height<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                H::provider(schemes[0].clone()),
            )
            .await;

            // Before any finalization, get_finalization should be None
            let finalization = actor.get_finalization(Height::new(1)).await;
            assert!(finalization.is_none());

            // Finalize a block at height 1
            let genesis_digest = Sha256::hash(b"");
            let block = make_block(genesis_digest, Height::new(1), 1);
            let commitment = block.digest();
            let round = Round::new(Epoch::new(0), View::new(1));
            actor.verified(round, block.clone()).await;
            let finalization = H::make_finalization(
                round,
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            actor.report(H::finalization_activity(finalization)).await;

            // Get finalization by height
            let finalization = actor
                .get_finalization(Height::new(1))
                .await
                .expect("missing finalization by height");
            assert_eq!(finalization.parent(), View::new(0));
            assert_eq!(
                finalization.round(),
                Round::new(Epoch::new(0), View::new(1))
            );
            assert_eq!(finalization.payload(), commitment);

            assert!(actor.get_finalization(Height::new(2)).await.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_hint_finalized_triggers_fetch_simplex() {
        hint_finalized_triggers_fetch::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_hint_finalized_triggers_fetch_minimmit() {
        hint_finalized_triggers_fetch::<MinimmitHarness>();
    }

    fn hint_finalized_triggers_fetch<H: ConsensusTestHarness>() {
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
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Register the initial peer set
            let mut manager = oracle.manager();
            manager
                .update(0, participants.clone().try_into().unwrap())
                .await;

            // Set up two validators
            let (app0, mut actor0, _) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                participants[0].clone(),
                H::provider(schemes[0].clone()),
            )
            .await;
            let (_app1, mut actor1, _) = setup_validator::<H>(
                context.with_label("validator_1"),
                &mut oracle,
                participants[1].clone(),
                H::provider(schemes[1].clone()),
            )
            .await;

            // Add links between validators
            setup_network_links(&mut oracle, &participants[..2], LINK).await;

            // Validator 0: Create and finalize blocks 1-5
            let mut parent_payloads = BTreeMap::<Height, D>::new();
            let genesis_digest = Sha256::hash(b"");
            parent_payloads.insert(Height::new(0), genesis_digest);
            let mut parent = genesis_digest;
            for i in 1..=5u64 {
                let block = make_block(parent, Height::new(i), i);
                let commitment = block.digest();
                parent_payloads.insert(Height::new(i), commitment);
                let round = Round::new(Epoch::new(0), View::new(i));
                let parent_payload = *parent_payloads.get(&Height::new(i - 1)).unwrap();

                actor0.verified(round, block.clone()).await;
                let finalization = H::make_finalization(
                    round,
                    View::new(i - 1),
                    parent_payload,
                    commitment,
                    &schemes,
                    QUORUM,
                );
                actor0.report(H::finalization_activity(finalization)).await;

                parent = commitment;
            }

            // Wait for validator 0 to process all blocks
            while app0.blocks().len() < 5 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Validator 1 should not have block 5 yet
            assert!(actor1.get_finalization(Height::new(5)).await.is_none());

            // Validator 1: hint that block 5 is finalized, targeting validator 0
            actor1
                .hint_finalized(Height::new(5), NonEmptyVec::new(participants[0].clone()))
                .await;

            // Wait for the fetch to complete
            while actor1.get_finalization(Height::new(5)).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Verify validator 1 now has the finalization
            let finalization = actor1
                .get_finalization(Height::new(5))
                .await
                .expect("finalization should be fetched");
            assert_eq!(finalization.round().view(), View::new(5));
        })
    }

    #[test_traced("WARN")]
    fn test_ancestry_stream_simplex() {
        ancestry_stream::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_ancestry_stream_minimmit() {
        ancestry_stream::<MinimmitHarness>();
    }

    fn ancestry_stream<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                H::provider(schemes[0].clone()),
            )
            .await;

            // Finalize blocks at heights 1-5
            let mut parent_payloads = BTreeMap::<Height, D>::new();
            let genesis_digest = Sha256::hash(b"");
            parent_payloads.insert(Height::new(0), genesis_digest);
            let mut parent = genesis_digest;
            for i in 1..=5u64 {
                let block = make_block(parent, Height::new(i), i);
                let commitment = block.digest();
                parent_payloads.insert(Height::new(i), commitment);
                let round = Round::new(Epoch::new(0), View::new(i));
                let parent_payload = *parent_payloads.get(&Height::new(i - 1)).unwrap();
                actor.verified(round, block.clone()).await;
                let finalization = H::make_finalization(
                    round,
                    View::new(i - 1),
                    parent_payload,
                    commitment,
                    &schemes,
                    QUORUM,
                );
                actor.report(H::finalization_activity(finalization)).await;

                parent = block.digest();
            }

            // Stream from latest -> height 1
            let (_, commitment) = actor.get_info(Identifier::Latest).await.unwrap();
            let ancestry = actor.ancestry((None, commitment)).await.unwrap();
            let blocks = ancestry.collect::<Vec<_>>().await;

            // Ensure correct delivery order: 5,4,3,2,1
            assert_eq!(blocks.len(), 5);
            (0..5).for_each(|i| {
                assert_eq!(blocks[i].height(), Height::new(5 - i as u64));
            });
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_invalid_ancestry_simplex() {
        marshaled_rejects_invalid_ancestry::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_invalid_ancestry_minimmit() {
        marshaled_rejects_invalid_ancestry::<MinimmitHarness>();
    }

    fn marshaled_rejects_invalid_ancestry<H: ConsensusTestHarness>() {
        #[derive(Clone)]
        struct MockVerifyingApp<C: MarshalConsensus> {
            genesis: B,
            _marker: std::marker::PhantomData<C>,
        }

        impl<C: MarshalConsensus<Digest = D>> crate::Application<deterministic::Context>
            for MockVerifyingApp<C>
        {
            type Block = B;
            type Context = Context<D, K>;
            type Consensus = C;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::Consensus, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl<C: MarshalConsensus<Digest = D>> VerifyingApplication<deterministic::Context>
            for MockVerifyingApp<C>
        {
            async fn verify(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::Consensus, Self::Block>,
            ) -> bool {
                // Ancestry verification occurs entirely in `Marshaled`.
                true
            }
        }

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_base_app, marshal, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                H::provider(schemes[0].clone()),
            )
            .await;

            // Create genesis block
            let genesis = make_block(Sha256::hash(b""), Height::zero(), 0);

            // Wrap with Marshaled verifier
            let mock_app = MockVerifyingApp::<H::Consensus> {
                genesis: genesis.clone(),
                _marker: std::marker::PhantomData,
            };
            let mut marshaled = Marshaled::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Test case 1: Non-contiguous height
            //
            // We need both blocks in the same epoch.
            // With BLOCKS_PER_EPOCH=20: epoch 0 is heights 0-19, epoch 1 is heights 20-39
            //
            // Store honest parent at height 21 (epoch 1)
            let honest_parent = make_block(
                genesis.commitment(),
                Height::new(BLOCKS_PER_EPOCH.get() + 1),
                1000,
            );
            let parent_commitment = honest_parent.commitment();
            let parent_round = Round::new(Epoch::new(1), View::new(21));
            marshal
                .clone()
                .verified(parent_round, honest_parent.clone())
                .await;

            // Byzantine proposer broadcasts malicious block at height 35
            // In reality this would come via buffered broadcast, but for test simplicity
            // we call broadcast() directly which makes it available for subscription
            let malicious_block = make_block(
                parent_commitment,
                Height::new(BLOCKS_PER_EPOCH.get() + 15),
                2000,
            );
            let malicious_commitment = malicious_block.commitment();
            marshal
                .clone()
                .proposed(
                    Round::new(Epoch::new(1), View::new(35)),
                    malicious_block.clone(),
                )
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 35
            let byzantine_round = Round::new(Epoch::new(1), View::new(35));
            let byzantine_context = Context {
                round: byzantine_round,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

            // Marshaled.certify() should reject the malicious block
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 35) from marshal based on digest
            // 3. Validate height is contiguous (fail)
            // 4. Return false
            let _ = marshaled
                .verify(byzantine_context, malicious_commitment)
                .await
                .await;
            let verify = marshaled
                .certify(byzantine_round, malicious_commitment)
                .await;

            assert!(
                !verify.await.unwrap(),
                "Byzantine block with non-contiguous heights should be rejected"
            );

            // Test case 2: Mismatched parent commitment
            //
            // Create another malicious block with correct height but invalid parent commitment
            let malicious_block = make_block(
                genesis.commitment(),
                Height::new(BLOCKS_PER_EPOCH.get() + 2),
                3000,
            );
            let malicious_commitment = malicious_block.commitment();
            marshal
                .clone()
                .proposed(
                    Round::new(Epoch::new(1), View::new(22)),
                    malicious_block.clone(),
                )
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 22
            let byzantine_round = Round::new(Epoch::new(1), View::new(22));
            let byzantine_context = Context {
                round: byzantine_round,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

            // Marshaled.certify() should reject the malicious block
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 22) from marshal based on digest
            // 3. Validate height is contiguous
            // 3. Validate parent commitment matches (fail)
            // 4. Return false
            let _ = marshaled
                .verify(byzantine_context, malicious_commitment)
                .await
                .await;
            let verify = marshaled
                .certify(byzantine_round, malicious_commitment)
                .await;

            assert!(
                !verify.await.unwrap(),
                "Byzantine block with mismatched parent commitment should be rejected"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_finalize_same_height_different_views_simplex() {
        finalize_same_height_different_views::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_finalize_same_height_different_views_minimmit() {
        finalize_same_height_different_views::<MinimmitHarness>();
    }

    fn finalize_same_height_different_views<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Set up two validators
            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate().take(2) {
                let (_app, actor, _processed_height) = setup_validator::<H>(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    H::provider(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }

            // Create block at height 1
            let genesis_digest = Sha256::hash(b"");
            let block = make_block(genesis_digest, Height::new(1), 1);
            let commitment = block.digest();

            // Both validators verify the block
            actors[0]
                .verified(Round::new(Epoch::new(0), View::new(1)), block.clone())
                .await;
            actors[1]
                .verified(Round::new(Epoch::new(0), View::new(1)), block.clone())
                .await;

            // Validator 0: Finalize with view 1
            let notarization_v1 = H::make_notarization(
                Round::new(Epoch::new(0), View::new(1)),
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            let finalization_v1 = H::make_finalization(
                Round::new(Epoch::new(0), View::new(1)),
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            actors[0]
                .report(H::notarization_activity(notarization_v1.clone()))
                .await;
            actors[0]
                .report(H::finalization_activity(finalization_v1.clone()))
                .await;

            // Validator 1: Finalize with view 2 (simulates receiving finalization from different view)
            // This could happen during epoch transitions where the same block gets finalized
            // with different views by different validators.
            let notarization_v2 = H::make_notarization(
                Round::new(Epoch::new(0), View::new(2)),
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            let finalization_v2 = H::make_finalization(
                Round::new(Epoch::new(0), View::new(2)),
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            actors[1]
                .report(H::notarization_activity(notarization_v2.clone()))
                .await;
            actors[1]
                .report(H::finalization_activity(finalization_v2.clone()))
                .await;

            // Wait for finalization processing
            context.sleep(Duration::from_millis(100)).await;

            // Verify both validators stored the block correctly
            let block0 = actors[0].get_block(Height::new(1)).await.unwrap();
            let block1 = actors[1].get_block(Height::new(1)).await.unwrap();
            assert_eq!(block0, block);
            assert_eq!(block1, block);

            // Verify both validators have finalizations stored
            let fin0 = actors[0].get_finalization(Height::new(1)).await.unwrap();
            let fin1 = actors[1].get_finalization(Height::new(1)).await.unwrap();

            // Verify the finalizations have the expected different views
            assert_eq!(fin0.payload(), block.commitment());
            assert_eq!(fin0.round().view(), View::new(1));
            assert_eq!(fin1.payload(), block.commitment());
            assert_eq!(fin1.round().view(), View::new(2));

            // Both validators can retrieve block by height
            assert_eq!(
                actors[0].get_info(Height::new(1)).await,
                Some((Height::new(1), commitment))
            );
            assert_eq!(
                actors[1].get_info(Height::new(1)).await,
                Some((Height::new(1), commitment))
            );

            // Test that a validator receiving BOTH finalizations handles it correctly
            // (the second one should be ignored since archive ignores duplicates for same height)
            actors[0]
                .report(H::finalization_activity(finalization_v2.clone()))
                .await;
            actors[1]
                .report(H::finalization_activity(finalization_v1.clone()))
                .await;
            context.sleep(Duration::from_millis(100)).await;

            // Validator 0 should still have the original finalization (v1)
            let fin0_after = actors[0].get_finalization(Height::new(1)).await.unwrap();
            assert_eq!(fin0_after.round().view(), View::new(1));

            // Validator 1 should still have the original finalization (v2)
            let fin0_after = actors[1].get_finalization(Height::new(1)).await.unwrap();
            assert_eq!(fin0_after.round().view(), View::new(2));
        })
    }

    #[test_traced("WARN")]
    fn test_init_processed_height_simplex() {
        init_processed_height::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_init_processed_height_minimmit() {
        init_processed_height::<MinimmitHarness>();
    }

    fn init_processed_height<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Test 1: Fresh init should return processed height 0
            let me = participants[0].clone();
            let (application, mut actor, initial_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                H::provider(schemes[0].clone()),
            )
            .await;
            assert_eq!(initial_height, Height::zero());

            // Process multiple blocks (1, 2, 3)
            let mut parent_payloads = BTreeMap::<Height, D>::new();
            let genesis_digest = Sha256::hash(b"");
            parent_payloads.insert(Height::new(0), genesis_digest);
            let mut parent = genesis_digest;
            let mut blocks = Vec::new();
            for i in 1..=3u64 {
                let block = make_block(parent, Height::new(i), i);
                let commitment = block.digest();
                parent_payloads.insert(Height::new(i), commitment);
                let round = Round::new(Epoch::new(0), View::new(i));
                let parent_payload = *parent_payloads.get(&Height::new(i - 1)).unwrap();

                actor.verified(round, block.clone()).await;
                let finalization = H::make_finalization(
                    round,
                    View::new(i - 1),
                    parent_payload,
                    commitment,
                    &schemes,
                    QUORUM,
                );
                actor.report(H::finalization_activity(finalization)).await;

                blocks.push(block);
                parent = commitment;
            }

            // Wait for application to process all blocks
            while application.blocks().len() < 3 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Set marshal's processed height to 3
            actor.set_floor(Height::new(3)).await;
            context.sleep(Duration::from_millis(10)).await;

            // Verify application received all blocks
            assert_eq!(application.blocks().len(), 3);
            assert_eq!(
                application.tip(),
                Some((Height::new(3), blocks[2].digest()))
            );

            // Test 2: Restart with marshal processed height = 3
            let (_restart_application, _restart_actor, restart_height) = setup_validator::<H>(
                context.with_label("validator_0_restart"),
                &mut oracle,
                me,
                H::provider(schemes[0].clone()),
            )
            .await;

            assert_eq!(restart_height, Height::new(3));
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_unsupported_epoch_simplex() {
        marshaled_rejects_unsupported_epoch::<SimplexHarness>();
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_unsupported_epoch_minimmit() {
        marshaled_rejects_unsupported_epoch::<MinimmitHarness>();
    }

    fn marshaled_rejects_unsupported_epoch<H: ConsensusTestHarness>() {
        #[derive(Clone)]
        struct MockVerifyingApp<C: MarshalConsensus> {
            genesis: B,
            _marker: std::marker::PhantomData<C>,
        }

        impl<C: MarshalConsensus<Digest = D>> crate::Application<deterministic::Context>
            for MockVerifyingApp<C>
        {
            type Block = B;
            type Context = Context<D, K>;
            type Consensus = C;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::Consensus, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl<C: MarshalConsensus<Digest = D>> VerifyingApplication<deterministic::Context>
            for MockVerifyingApp<C>
        {
            async fn verify(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::Consensus, Self::Block>,
            ) -> bool {
                true
            }
        }

        #[derive(Clone)]
        struct LimitedEpocher {
            inner: FixedEpocher,
            max_epoch: u64,
        }

        impl Epocher for LimitedEpocher {
            fn containing(&self, height: Height) -> Option<crate::types::EpochInfo> {
                let bounds = self.inner.containing(height)?;
                if bounds.epoch().get() > self.max_epoch {
                    None
                } else {
                    Some(bounds)
                }
            }

            fn first(&self, epoch: Epoch) -> Option<Height> {
                if epoch.get() > self.max_epoch {
                    None
                } else {
                    self.inner.first(epoch)
                }
            }

            fn last(&self, epoch: Epoch) -> Option<Height> {
                if epoch.get() > self.max_epoch {
                    None
                } else {
                    self.inner.last(epoch)
                }
            }
        }

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_base_app, marshal, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                H::provider(schemes[0].clone()),
            )
            .await;

            let genesis = make_block(Sha256::hash(b""), Height::zero(), 0);

            let mock_app = MockVerifyingApp::<H::Consensus> {
                genesis: genesis.clone(),
                _marker: std::marker::PhantomData,
            };
            let limited_epocher = LimitedEpocher {
                inner: FixedEpocher::new(BLOCKS_PER_EPOCH),
                max_epoch: 0,
            };
            let mut marshaled =
                Marshaled::new(context.clone(), mock_app, marshal.clone(), limited_epocher);

            // Create a parent block at height 19 (last block in epoch 0, which is supported)
            let parent = make_block(genesis.commitment(), Height::new(19), 1000);
            let parent_commitment = parent.commitment();
            let parent_round = Round::new(Epoch::new(0), View::new(19));
            marshal.clone().verified(parent_round, parent).await;

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let block = make_block(parent_commitment, Height::new(20), 2000);
            let block_commitment = block.commitment();
            marshal
                .clone()
                .proposed(Round::new(Epoch::new(1), View::new(20)), block)
                .await;

            context.sleep(Duration::from_millis(10)).await;

            let unsupported_round = Round::new(Epoch::new(1), View::new(20));
            let unsupported_context = Context {
                round: unsupported_round,
                leader: me.clone(),
                parent: (View::new(19), parent_commitment),
            };

            let verify_result = marshaled
                .verify(unsupported_context, block_commitment)
                .await
                .await;

            assert!(
                !verify_result.unwrap(),
                "Block in unsupported epoch should be rejected"
            );
        })
    }

    /// Regression test for verification task cleanup.
    ///
    /// Verifies that certifying blocks out of order works correctly. When multiple
    /// blocks are verified at different views, certifying a higher-view block should
    /// not interfere with certifying a lower-view block that was verified earlier.
    ///
    /// Scenario:
    /// 1. Verify block A at view V
    /// 2. Verify block B at view V+K
    /// 3. Certify block B at view V+K
    /// 4. Certify block A at view V - should succeed
    #[test_traced("INFO")]
    fn test_certify_lower_view_after_higher_view_simplex() {
        certify_lower_view_after_higher_view::<SimplexHarness>();
    }

    #[test_traced("INFO")]
    fn test_certify_lower_view_after_higher_view_minimmit() {
        certify_lower_view_after_higher_view::<MinimmitHarness>();
    }

    fn certify_lower_view_after_higher_view<H: ConsensusTestHarness>() {
        #[derive(Clone)]
        struct MockVerifyingApp<C: MarshalConsensus> {
            genesis: B,
            _marker: std::marker::PhantomData<C>,
        }

        impl<C: MarshalConsensus<Digest = D>> crate::Application<deterministic::Context>
            for MockVerifyingApp<C>
        {
            type Block = B;
            type Context = Context<D, K>;
            type Consensus = C;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::Consensus, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl<C: MarshalConsensus<Digest = D>> VerifyingApplication<deterministic::Context>
            for MockVerifyingApp<C>
        {
            async fn verify(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::Consensus, Self::Block>,
            ) -> bool {
                true
            }
        }

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_base_app, marshal, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                H::provider(schemes[0].clone()),
            )
            .await;

            let genesis = make_block(Sha256::hash(b""), Height::zero(), 0);

            let mock_app = MockVerifyingApp::<H::Consensus> {
                genesis: genesis.clone(),
                _marker: std::marker::PhantomData,
            };
            let mut marshaled = Marshaled::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Create parent block at height 1
            let parent = make_block(genesis.commitment(), Height::new(1), 100);
            let parent_commitment = parent.commitment();
            let parent_round = Round::new(Epoch::new(0), View::new(1));
            marshal.clone().verified(parent_round, parent).await;

            // Block A at view 5 (height 2) - create with context matching what verify will receive
            let round_a = Round::new(Epoch::new(0), View::new(5));
            let context_a = Context {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a =
                B::new::<Sha256>(context_a.clone(), parent_commitment, Height::new(2), 200);
            let commitment_a = block_a.commitment();
            marshal.clone().proposed(round_a, block_a).await;

            // Block B at view 10 (height 2, different block same height - could happen with
            // different proposers or re-proposals)
            let round_b = Round::new(Epoch::new(0), View::new(10));
            let context_b = Context {
                round: round_b,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_b =
                B::new::<Sha256>(context_b.clone(), parent_commitment, Height::new(2), 300);
            let commitment_b = block_b.commitment();
            marshal.clone().proposed(round_b, block_b).await;

            context.sleep(Duration::from_millis(10)).await;

            // Step 1: Verify block A at view 5
            let _ = marshaled.verify(context_a, commitment_a).await.await;

            // Step 2: Verify block B at view 10
            let _ = marshaled.verify(context_b, commitment_b).await.await;

            // Step 3: Certify block B at view 10 FIRST
            let certify_b = marshaled.certify(round_b, commitment_b).await;
            assert!(
                certify_b.await.unwrap(),
                "Block B certification should succeed"
            );

            // Step 4: Certify block A at view 5 - should succeed
            let certify_a = marshaled.certify(round_a, commitment_a).await;

            // Use select with timeout to detect never-resolving receiver
            select! {
                result = certify_a => {
                    assert!(
                        result.unwrap(),
                        "Block A certification should succeed"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("Block A certification timed out");
                },
            }
        })
    }

    /// Regression test for re-proposal validation in optimistic_verify.
    ///
    /// Verifies that:
    /// 1. Valid re-proposals at epoch boundaries are accepted
    /// 2. Invalid re-proposals (not at epoch boundary) are rejected
    ///
    /// A re-proposal occurs when the parent commitment equals the block being verified,
    /// meaning the same block is being proposed again in a new view.
    #[test_traced("INFO")]
    fn test_marshaled_reproposal_validation_simplex() {
        marshaled_reproposal_validation::<SimplexHarness>();
    }

    #[test_traced("INFO")]
    fn test_marshaled_reproposal_validation_minimmit() {
        marshaled_reproposal_validation::<MinimmitHarness>();
    }

    fn marshaled_reproposal_validation<H: ConsensusTestHarness>() {
        #[derive(Clone)]
        struct MockVerifyingApp<C: MarshalConsensus> {
            genesis: B,
            _marker: std::marker::PhantomData<C>,
        }

        impl<C: MarshalConsensus<Digest = D>> crate::Application<deterministic::Context>
            for MockVerifyingApp<C>
        {
            type Block = B;
            type Context = Context<D, K>;
            type Consensus = C;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::Consensus, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl<C: MarshalConsensus<Digest = D>> VerifyingApplication<deterministic::Context>
            for MockVerifyingApp<C>
        {
            async fn verify(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::Consensus, Self::Block>,
            ) -> bool {
                true
            }
        }

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_base_app, marshal, _processed_height) = setup_validator::<H>(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                H::provider(schemes[0].clone()),
            )
            .await;

            let genesis = make_block(Sha256::hash(b""), Height::zero(), 0);

            let mock_app = MockVerifyingApp::<H::Consensus> {
                genesis: genesis.clone(),
                _marker: std::marker::PhantomData,
            };
            let mut marshaled = Marshaled::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Build a chain up to the epoch boundary (height 19 is the last block in epoch 0
            // with BLOCKS_PER_EPOCH=20, since epoch 0 covers heights 0-19)
            let mut parent = genesis.commitment();
            let mut last_view = View::zero();
            for i in 1..BLOCKS_PER_EPOCH.get() {
                let round = Round::new(Epoch::new(0), View::new(i));
                let ctx = Context {
                    round,
                    leader: me.clone(),
                    parent: (last_view, parent),
                };
                let block = B::new::<Sha256>(ctx.clone(), parent, Height::new(i), i * 100);
                marshal.clone().verified(round, block.clone()).await;
                parent = block.commitment();
                last_view = View::new(i);
            }

            // Create the epoch boundary block (height 19, last block in epoch 0)
            let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
            let boundary_round = Round::new(Epoch::new(0), View::new(boundary_height.get()));
            let boundary_context = Context {
                round: boundary_round,
                leader: me.clone(),
                parent: (last_view, parent),
            };
            let boundary_block = B::new::<Sha256>(
                boundary_context.clone(),
                parent,
                boundary_height,
                boundary_height.get() * 100,
            );
            let boundary_commitment = boundary_block.commitment();
            marshal
                .clone()
                .verified(boundary_round, boundary_block.clone())
                .await;

            // Make the boundary block available for subscription
            marshal
                .clone()
                .proposed(boundary_round, boundary_block.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Test 1: Valid re-proposal at epoch boundary should be accepted
            // Re-proposal context: parent commitment equals the block being verified
            // Re-proposals happen within the same epoch when the parent is the last block
            let reproposal_round = Round::new(Epoch::new(0), View::new(20));
            let reproposal_context = Context {
                round: reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_commitment), // Parent IS the boundary block
            };

            // Call verify (which calls optimistic_verify internally via Automaton trait)
            let verify_result = marshaled
                .verify(reproposal_context.clone(), boundary_commitment)
                .await
                .await;
            assert!(
                verify_result.unwrap(),
                "Valid re-proposal at epoch boundary should be accepted"
            );

            // Test 2: Invalid re-proposal (not at epoch boundary) should be rejected
            // Create a block at height 10 (not at epoch boundary)
            let non_boundary_height = Height::new(10);
            let non_boundary_round = Round::new(Epoch::new(0), View::new(10));
            let non_boundary_context = Context {
                round: non_boundary_round,
                leader: me.clone(),
                parent: (View::new(9), parent),
            };
            let non_boundary_block = B::new::<Sha256>(
                non_boundary_context.clone(),
                parent,
                non_boundary_height,
                1000,
            );
            let non_boundary_commitment = non_boundary_block.commitment();

            // Make the non-boundary block available
            marshal
                .clone()
                .proposed(non_boundary_round, non_boundary_block.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Attempt to re-propose the non-boundary block
            let invalid_reproposal_round = Round::new(Epoch::new(0), View::new(15));
            let invalid_reproposal_context = Context {
                round: invalid_reproposal_round,
                leader: me.clone(),
                parent: (View::new(10), non_boundary_commitment),
            };

            let verify_result = marshaled
                .verify(invalid_reproposal_context, non_boundary_commitment)
                .await
                .await;
            assert!(
                !verify_result.unwrap(),
                "Invalid re-proposal (not at epoch boundary) should be rejected"
            );

            // Test 3: Re-proposal with mismatched epoch should be rejected
            // This is a regression test - re-proposals must be in the same epoch as the block.
            let cross_epoch_reproposal_round = Round::new(Epoch::new(1), View::new(20));
            let cross_epoch_reproposal_context = Context {
                round: cross_epoch_reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_commitment),
            };

            let verify_result = marshaled
                .verify(cross_epoch_reproposal_context, boundary_commitment)
                .await
                .await;
            assert!(
                !verify_result.unwrap(),
                "Re-proposal with mismatched epoch should be rejected"
            );

            // Test 4: Certify-only path for re-proposal (no prior verify call)
            // This tests the crash recovery scenario where a validator needs to certify
            // a re-proposal without having called verify first.
            let certify_only_round = Round::new(Epoch::new(0), View::new(21));
            let certify_result = marshaled
                .certify(certify_only_round, boundary_commitment)
                .await
                .await;
            assert!(
                certify_result.unwrap(),
                "Certify-only path for re-proposal should succeed"
            );

            // Test 5: Certify-only path for a normal block (no prior verify call)
            // Build a normal block (not at epoch boundary) and test certify without verify.
            // Use genesis as the parent since we don't have finalized blocks at other heights.
            let normal_height = Height::new(1);
            let normal_round = Round::new(Epoch::new(0), View::new(100));
            let genesis_commitment = genesis.commitment();

            let normal_context = Context {
                round: normal_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_commitment),
            };
            let normal_block = B::new::<Sha256>(
                normal_context.clone(),
                genesis_commitment,
                normal_height,
                500,
            );
            let normal_commitment = normal_block.commitment();
            marshal
                .clone()
                .proposed(normal_round, normal_block.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Certify without calling verify first
            let certify_result = marshaled
                .certify(normal_round, normal_commitment)
                .await
                .await;
            assert!(
                certify_result.unwrap(),
                "Certify-only path for normal block should succeed"
            );
        })
    }

    #[test_traced("INFO")]
    fn test_broadcast_caches_block_simplex() {
        broadcast_caches_block::<SimplexHarness>();
    }

    #[test_traced("INFO")]
    fn test_broadcast_caches_block_minimmit() {
        broadcast_caches_block::<MinimmitHarness>();
    }

    fn broadcast_caches_block<H: ConsensusTestHarness>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = H::fixture(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Set up one validator
            let (i, validator) = participants.iter().enumerate().next().unwrap();
            let mut actor = setup_validator::<H>(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                H::provider(schemes[i].clone()),
            )
            .await
            .1;

            // Create block at height 1
            let genesis_digest = Sha256::hash(b"");
            let block = make_block(genesis_digest, Height::new(1), 1);
            let commitment = block.digest();

            // Broadcast the block
            actor
                .proposed(Round::new(Epoch::new(0), View::new(1)), block.clone())
                .await;

            // Ensure the block is cached and retrievable; This should hit the in-memory cache
            // via `buffered::Mailbox`.
            actor
                .get_block(&commitment)
                .await
                .expect("block should be cached after broadcast");

            // Restart marshal, removing any in-memory cache
            let mut actor = setup_validator::<H>(
                context.with_label(&format!("validator_{i}_restart")),
                &mut oracle,
                validator.clone(),
                H::provider(schemes[i].clone()),
            )
            .await
            .1;

            // Put a notarization into the cache to re-initialize the ephemeral cache for the
            // first epoch. Without this, the marshal cannot determine the epoch of the block being fetched,
            // so it won't look to restore the cache for the epoch.
            let notarization = H::make_notarization(
                Round::new(Epoch::new(0), View::new(1)),
                View::new(0),
                genesis_digest,
                commitment,
                &schemes,
                QUORUM,
            );
            actor.report(H::notarization_activity(notarization)).await;

            // Ensure the block is cached and retrievable
            let fetched = actor
                .get_block(&commitment)
                .await
                .expect("block should be cached after broadcast");
            assert_eq!(fetched, block);
        });
    }
}
