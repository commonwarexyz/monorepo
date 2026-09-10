//! Standard variant for Marshal.
//!
//! # Overview
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.
//!
//! # Components
//!
//! - [`Standard`]: The variant marker type that configures marshal for full-block broadcast.
//! - [`Deferred`]: Deferred-verification wrapper that enforces epoch boundaries and
//!   coordinates with the marshal actor.
//! - [`Inline`]: Inline-verification wrapper for applications whose blocks do not
//!   implement [`crate::CertifiableBlock`].
//!
//! # Usage
//!
//! The standard variant uses the core [`crate::marshal::core::Actor`] and
//! [`crate::marshal::core::Mailbox`] with [`Standard`] as the variant type parameter.
//! Blocks are broadcast through [`commonware_broadcast::buffered`].
//!
//! # When to Use
//!
//! Prefer this variant when block sizes are small enough that shipping full blocks
//! to every peer is acceptable or if participants have sufficiently powerful networking
//! and want to avoid encoding / decoding overhead.

commonware_macros::stability_scope!(ALPHA {
    mod deferred;
    pub use deferred::Deferred;

    mod inline;
    pub use inline::Inline;

    mod relay;
    mod validation;
});

mod variant;
pub use variant::Standard;

#[cfg(test)]
mod tests {
    use super::{Deferred, Inline, Standard, relay};
    use crate::{
        Automaton, CertifiableAutomaton, Heightable, Relay, Reporter,
        marshal::{
            Identifier, Update,
            application::gates::{GateOutcome, Gates},
            config::{Config, Start},
            core::{Actor, Mailbox, cache, durability::Durable as _},
            mocks::{
                application::Application,
                harness::{
                    self, B, BLOCKS_PER_EPOCH, Ctx, D, DeferredHarness, InlineHarness, LINK,
                    NAMESPACE, NUM_VALIDATORS, PAGE_CACHE_SIZE, PAGE_SIZE, QUORUM, S,
                    StandardHarness, TEST_QUOTA, TestHarness, UNRELIABLE_LINK, V, ValidatorHandle,
                    default_leader, make_raw_block, setup_network_links,
                    setup_network_with_participants,
                },
                store::{Op, Recording},
                verifying::MockVerifyingApp,
            },
            resolver::handler,
        },
        simplex::{
            self, Plan,
            config::{ForwardPolicy, SkipBudget, SkipPolicy},
            elector::{Config as _, Elector as _, RoundRobin, RoundRobinElector},
            scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
            types::{
                Certificate, Finalization, Notarization, Notarize, Nullification, Nullify,
                Proposal, Vote,
            },
        },
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
    };
    use bytes::{BufMut, Bytes};
    use commonware_actor::{Feedback, mailbox};
    use commonware_broadcast::Broadcaster as _;
    use commonware_codec::{Buf, DecodeExt as _, Encode, FixedSize, Read, Write};
    use commonware_cryptography::{
        Digestible, Hasher as _,
        certificate::{ConstantProvider, Provider, Scoped, Verifier as _, mocks::Fixture},
        ed25519::PublicKey,
        sha256::Sha256,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::{Manager as _, Receiver as _, Recipients, Sender as _};
    use commonware_parallel::Sequential;
    use commonware_resolver::{Consumer, Delivery, Fetch, Resolver};
    use commonware_runtime::{
        Clock, Metrics, Quota, Runner, Spawner, Supervisor as _, buffer::paged::CacheRef,
        deterministic, utils::reschedule,
    };
    use commonware_storage::{
        archive::{Archive as _, immutable, prunable},
        metadata::{self, Metadata},
        translator::{EightCap, TwoCap},
    };
    use commonware_utils::{
        Acknowledgement as _, NZU64, NZUsize,
        acknowledgement::Exact,
        channel::{fallible::OneshotExt, mpsc, oneshot, oneshot::error::TryRecvError},
        non_empty,
        ordered::{Quorum as _, Set},
        probability,
        sequence::U64,
        sync::Mutex,
        vec::NonEmptyVec,
    };
    use futures::{FutureExt as _, StreamExt as _};
    use std::{
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        sync::{
            Arc, Weak,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[derive(Clone)]
    struct VerifierProvider {
        scheme: Arc<S>,
    }

    impl VerifierProvider {
        fn new(scheme: S) -> Self {
            Self {
                scheme: Arc::new(scheme),
            }
        }
    }

    impl Provider for VerifierProvider {
        type Scope = Epoch;
        type Scheme = S;

        fn scoped(&self, _: Epoch) -> Option<Scoped<S>> {
            Some(Scoped::verifier(self.scheme.clone()))
        }
    }

    #[test_traced("WARN")]
    fn test_standard_acquire_fetches_by_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let buffer = RecordingBuffer::default();
            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "standard-provider-parent-commitment",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(buffer),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            let parent = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let child = make_raw_block(parent.digest(), Height::new(2), 200);
            let subscription = mailbox.acquire(child.parent);

            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                buffer.commitment_subscription_count(),
                1,
                "acquisition should use the standard parent commitment"
            );
            drop(subscription);
        });
    }

    fn assert_finalize_deterministic<H: TestHarness>(
        seed: u64,
        link: commonware_p2p::simulated::Link,
        quorum_sees_finalization: bool,
    ) {
        let r1 = harness::finalize::<H>(seed, link.clone(), quorum_sees_finalization);
        let r2 = harness::finalize::<H>(seed, link, quorum_sees_finalization);
        assert_eq!(r1, r2);
    }

    fn assert_hailstorm_deterministic<H: TestHarness>(seed: u64) {
        let r1 = harness::hailstorm::<H>(seed, 4, 4, 1, LINK);
        let r2 = harness::hailstorm::<H>(seed, 4, 4, 1, LINK);
        assert_eq!(r1, r2);
    }

    fn assert_hailstorm_multi_deterministic<H: TestHarness>(seed: u64) {
        let r1 = harness::hailstorm::<H>(seed, 4, 4, 2, LINK);
        let r2 = harness::hailstorm::<H>(seed, 4, 4, 2, LINK);
        assert_eq!(r1, r2);
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_finalize_good_links() {
        for seed in 0..5 {
            assert_finalize_deterministic::<InlineHarness>(seed, LINK, false);
            assert_finalize_deterministic::<DeferredHarness>(seed, LINK, false);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_finalize_bad_links() {
        for seed in 0..5 {
            assert_finalize_deterministic::<InlineHarness>(seed, UNRELIABLE_LINK, false);
            assert_finalize_deterministic::<DeferredHarness>(seed, UNRELIABLE_LINK, false);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            assert_finalize_deterministic::<InlineHarness>(seed, LINK, true);
            assert_finalize_deterministic::<DeferredHarness>(seed, LINK, true);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            assert_finalize_deterministic::<InlineHarness>(seed, UNRELIABLE_LINK, true);
            assert_finalize_deterministic::<DeferredHarness>(seed, UNRELIABLE_LINK, true);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_hailstorm_restarts() {
        for seed in 0..2 {
            assert_hailstorm_deterministic::<InlineHarness>(seed);
            assert_hailstorm_deterministic::<DeferredHarness>(seed);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_hailstorm_multi_restarts() {
        for seed in 0..2 {
            assert_hailstorm_multi_deterministic::<InlineHarness>(seed);
            assert_hailstorm_multi_deterministic::<DeferredHarness>(seed);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_ack_pipeline_backlog() {
        harness::ack_pipeline_backlog::<InlineHarness>();
        harness::ack_pipeline_backlog::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_ack_pipeline_backlog_persists_on_restart() {
        harness::ack_pipeline_backlog_persists_on_restart::<InlineHarness>();
        harness::ack_pipeline_backlog_persists_on_restart::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_genesis_emitted_once() {
        harness::genesis_emitted_once::<InlineHarness>();
        harness::genesis_emitted_once::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_proposed_success_implies_recoverable_after_restart() {
        harness::proposed_success_implies_recoverable_after_restart::<InlineHarness>(0..16);
        harness::proposed_success_implies_recoverable_after_restart::<DeferredHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_standard_verified_success_implies_recoverable_after_restart() {
        harness::verified_success_implies_recoverable_after_restart::<InlineHarness>(0..16);
        harness::verified_success_implies_recoverable_after_restart::<DeferredHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_standard_certify_persists_equivocated_block() {
        harness::certify_persists_equivocated_block::<InlineHarness>();
        harness::certify_persists_equivocated_block::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_verified_after_restart_reverify_same_round_implies_recoverable() {
        harness::verified_after_restart_reverify_same_round_implies_recoverable::<InlineHarness>();
        harness::verified_after_restart_reverify_same_round_implies_recoverable::<DeferredHarness>(
        );
    }

    #[test_traced("WARN")]
    fn test_standard_certify_after_restart_reverify_same_round_implies_recoverable() {
        harness::certify_after_restart_reverify_same_round_implies_recoverable::<InlineHarness>();
        harness::certify_after_restart_reverify_same_round_implies_recoverable::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_certified_success_implies_recoverable_after_restart() {
        harness::certified_success_implies_recoverable_after_restart::<InlineHarness>(0..16);
        harness::certified_success_implies_recoverable_after_restart::<DeferredHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_standard_certify_at_later_view_survives_earlier_view_pruning() {
        harness::certify_at_later_view_survives_earlier_view_pruning::<InlineHarness>();
        harness::certify_at_later_view_survives_earlier_view_pruning::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_delivery_visibility_implies_recoverable_after_restart() {
        harness::delivery_visibility_implies_recoverable_after_restart::<InlineHarness>(0..16);
        harness::delivery_visibility_implies_recoverable_after_restart::<DeferredHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_standard_sync_height_floor() {
        harness::sync_height_floor::<InlineHarness>();
        harness::sync_height_floor::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_reject_stale_block_delivery_after_floor_update() {
        harness::reject_stale_block_delivery_after_floor_update::<InlineHarness>();
        harness::reject_stale_block_delivery_after_floor_update::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_prune_finalized_archives() {
        harness::prune_finalized_archives::<InlineHarness>();
        harness::prune_finalized_archives::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_basic_block_delivery() {
        harness::subscribe_basic_block_delivery::<InlineHarness>();
        harness::subscribe_basic_block_delivery::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_multiple_subscriptions() {
        harness::subscribe_multiple_subscriptions::<InlineHarness>();
        harness::subscribe_multiple_subscriptions::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_canceled_subscriptions() {
        harness::subscribe_canceled_subscriptions::<InlineHarness>();
        harness::subscribe_canceled_subscriptions::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_blocks_from_different_sources() {
        harness::subscribe_blocks_from_different_sources::<InlineHarness>();
        harness::subscribe_blocks_from_different_sources::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_info_basic_queries_present_and_missing() {
        harness::get_info_basic_queries_present_and_missing::<InlineHarness>();
        harness::get_info_basic_queries_present_and_missing::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_info_latest_progression_multiple_finalizations() {
        harness::get_info_latest_progression_multiple_finalizations::<InlineHarness>();
        harness::get_info_latest_progression_multiple_finalizations::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_block_by_height_and_latest() {
        harness::get_block_by_height_and_latest::<InlineHarness>();
        harness::get_block_by_height_and_latest::<DeferredHarness>();
    }

    // Directly writes blocks and finalizations into the storage archives
    // used by the marshal, bypassing the normal finalization flow. This lets
    // us manufacture inconsistent on-disk state (a finalization without
    // its corresponding block) to simulate crash-recovery scenarios.
    async fn seed_inconsistent_restart_state(
        context: deterministic::Context,
        partition_prefix: &str,
        blocks: &[B],
        finalizations: &[(Height, Finalization<S, D>)],
    ) {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let replay_buffer = NonZeroUsize::new(1024).unwrap();
        let write_buffer = NonZeroUsize::new(1024).unwrap();
        let items_per_section = NonZeroU64::new(10).unwrap();

        let mut finalizations_by_height = immutable::Archive::init(
            context.child("seed_finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
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
                ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
                items_per_section,
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer,
                freezer_key_write_buffer: write_buffer,
                freezer_value_write_buffer: write_buffer,
                ordinal_write_buffer: write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations archive for seeded restart state");

        let mut finalized_blocks = immutable::Archive::init(
            context.child("seed_finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalized_blocks-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalized_blocks-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-finalized_blocks-freezer-key"),
                freezer_key_page_cache: page_cache,
                freezer_value_partition: format!(
                    "{partition_prefix}-finalized_blocks-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalized_blocks-ordinal"),
                items_per_section,
                codec_config: (),
                replay_buffer,
                freezer_key_write_buffer: write_buffer,
                freezer_value_write_buffer: write_buffer,
                ordinal_write_buffer: write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive for seeded restart state");

        for block in blocks {
            finalized_blocks = finalized_blocks
                .put(block.height().get(), block.digest(), block)
                .await
                .expect("failed to seed finalized block");
        }
        finalized_blocks
            .sync()
            .await
            .expect("failed to sync seeded finalized blocks");

        for (height, finalization) in finalizations {
            finalizations_by_height = finalizations_by_height
                .put(height.get(), finalization.proposal.payload, finalization)
                .await
                .expect("failed to seed finalization");
        }
        finalizations_by_height
            .sync()
            .await
            .expect("failed to sync seeded finalizations");
    }

    async fn seed_processed_height(
        context: deterministic::Context,
        partition_prefix: &str,
        height: Height,
    ) {
        let mut metadata: Metadata<deterministic::Context, U64, Height> = Metadata::init(
            context.child("seed_application_metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}-application-metadata"),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize application metadata for seeded restart state");
        metadata.put(U64::new(0xFF), height);
        metadata
            .sync()
            .await
            .expect("failed to sync seeded application metadata");
    }

    // Writes a block directly into the cache's per-epoch notarized storage,
    // simulating a block that was notarized but never finalized before a crash.
    async fn seed_cache_block(
        context: deterministic::Context,
        partition_prefix: &str,
        epoch: Epoch,
        view: View,
        block: &B,
    ) {
        let cache_prefix = format!("{partition_prefix}-cache");
        let replay_buffer = NonZeroUsize::new(1024).unwrap();
        let write_buffer = NonZeroUsize::new(1024).unwrap();

        let mut metadata: Metadata<deterministic::Context, u8, (Epoch, Epoch)> = Metadata::init(
            context.child("seed_cache_metadata"),
            metadata::Config {
                partition: format!("{cache_prefix}-metadata"),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize cache metadata");
        metadata.put(0, (epoch, epoch));
        metadata
            .sync()
            .await
            .expect("failed to sync cache metadata");

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let notarized: prunable::Archive<TwoCap, deterministic::Context, D, B> =
            prunable::Archive::init(
                context.child("seed_notarized"),
                prunable::Config {
                    translator: TwoCap,
                    metadata_partition: format!("{cache_prefix}-cache-{epoch}-notarized-metadata"),
                    key_partition: format!("{cache_prefix}-cache-{epoch}-notarized-key"),
                    key_page_cache: page_cache,
                    value_partition: format!("{cache_prefix}-cache-{epoch}-notarized-value"),
                    items_per_section: NonZeroU64::new(10).unwrap(),
                    compression: None,
                    codec_config: (),
                    replay_buffer,
                    key_write_buffer: write_buffer,
                    value_write_buffer: write_buffer,
                },
            )
            .await
            .expect("failed to initialize notarized blocks archive");
        notarized
            .put_sync(view.get(), block.digest(), block)
            .await
            .expect("failed to seed notarized block");
    }

    // Verifies that a validator whose finalized-blocks archive is missing
    // the block at the tip (has finalization for height 2 but only block 1)
    // fetches the missing block from a peer on restart.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_trailing_missing_finalized_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(3),
                participants.clone(),
            )
            .await;
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();
            let peer_validator = participants[1].clone();

            // Build chain: genesis -> block_one -> block_two
            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    StandardHarness::commitment(&block_two),
                ),
                &schemes,
                3,
            );

            // Give the peer all blocks so it can serve them during repair.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.child("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(1)), block_one.clone())
                    .await
            );

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), block_two.clone())
                    .await
            );
            StandardHarness::report_finalization(&mut peer_mailbox, finalization_two.clone()).await;
            context.sleep(Duration::from_millis(200)).await;

            // Seed inconsistent state: has block_one but only a finalization
            // (no block data) for height 2.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one],
                &[(Height::new(2), finalization_two)],
            )
            .await;

            // Start the recovering validator and verify initial state.
            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through all blocks sequentially. Block 2 must be
            // repaired from the peer before it can be dispatched.
            for expected_height in 1..=2 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies that a validator missing an internal block (has blocks 1 and 3
    // but not 2, with finalizations for both 2 and 3) fetches the gap from a
    // peer on restart.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_internal_missing_finalized_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(3),
                participants.clone(),
            )
            .await;
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();
            let peer_validator = participants[1].clone();

            // Build chain: genesis -> block_one -> block_two -> block_three
            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let block_three = make_raw_block(block_two.digest(), Height::new(3), 300);
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    StandardHarness::commitment(&block_two),
                ),
                &schemes,
                3,
            );
            let finalization_three = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(3)),
                    View::new(2),
                    StandardHarness::commitment(&block_three),
                ),
                &schemes,
                3,
            );

            // Give the peer all blocks so it can serve them during repair.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.child("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(1)), block_one.clone())
                    .await
            );

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), block_two.clone())
                    .await
            );

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(3)), block_three.clone())
                    .await
            );
            StandardHarness::report_finalization(&mut peer_mailbox, finalization_two.clone()).await;
            StandardHarness::report_finalization(&mut peer_mailbox, finalization_three.clone())
                .await;
            context.sleep(Duration::from_millis(200)).await;

            // Seed inconsistent state: has blocks 1 and 3 but is missing
            // block 2 (an internal gap in the finalized chain).
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one, block_three.clone()],
                &[
                    (Height::new(2), finalization_two),
                    (Height::new(3), finalization_three),
                ],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through all three blocks sequentially. Block 2 must be
            // repaired from the peer before it can be dispatched.
            for expected_height in 1..=3 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies that a block persisted at a height beyond the last finalization
    // is still surfaced via get_block and dispatched to the application. This
    // can happen if a crash occurs after persisting the block but before
    // persisting its finalization.
    #[test_traced("WARN")]
    fn test_standard_restart_surfaces_block_without_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(3),
                participants.clone(),
            )
            .await;
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();

            // Build chain: genesis -> block_one -> block_two
            // Only block_one gets a finalization; block_two is an orphan.
            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_one = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    StandardHarness::commitment(&block_one),
                ),
                &schemes,
                3,
            );

            // Seed state: both blocks persisted, but only block_one has a
            // finalization. block_two is a block without a corresponding
            // finalization row.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one.clone(), block_two.clone()],
                &[(Height::new(1), finalization_one)],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;

            // The tip tracks the highest finalization, not the highest block.
            assert_eq!(
                recovering.mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(1), block_one.digest())),
                "latest tip should be derived from the highest stored finalization"
            );
            assert_eq!(
                recovering.mailbox.get_block(Height::new(2)).await,
                Some(block_two.clone().into()),
                "block without a finalization row should still be queryable by height"
            );
            assert_eq!(
                recovering.mailbox.get_info(Height::new(2)).await,
                Some((Height::new(2), block_two.digest())),
                "block info should fall back to the finalized-block archive"
            );

            // Walk the application through sequential acks. Even though
            // block_two has no finalization, it is still dispatched because
            // its block data exists in the archive.
            assert_eq!(recovering.application.acknowledged().await, Height::zero());
            for expected_height in 1..=2 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies repair when many trailing blocks are missing. Seed state has
    // only block_one's data but finalizations for heights 1-5. The recovering
    // validator must fetch blocks 2-5 from the peer.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_multiple_trailing_missing_finalized_blocks() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(3),
                participants.clone(),
            )
            .await;
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();
            let peer_validator = participants[1].clone();

            // Build a 5-block chain.
            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let block_three = make_raw_block(block_two.digest(), Height::new(3), 300);
            let block_four = make_raw_block(block_three.digest(), Height::new(4), 400);
            let block_five = make_raw_block(block_four.digest(), Height::new(5), 500);

            let mut finalizations = Vec::new();
            let blocks = [
                &block_one,
                &block_two,
                &block_three,
                &block_four,
                &block_five,
            ];
            for (i, block) in blocks.iter().enumerate() {
                let view = View::new(block.height().get());
                let parent_view = if i == 0 {
                    View::zero()
                } else {
                    View::new(blocks[i - 1].height().get())
                };
                finalizations.push(StandardHarness::make_finalization(
                    Proposal::new(
                        Round::new(Epoch::zero(), view),
                        parent_view,
                        StandardHarness::commitment(block),
                    ),
                    &schemes,
                    3,
                ));
            }

            // Give the peer all blocks and finalizations.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.child("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;
            for (i, block) in blocks.iter().enumerate() {
                assert!(
                    peer_mailbox
                        .verified(
                            Round::new(Epoch::zero(), View::new(block.height().get())),
                            (*block).clone(),
                        )
                        .await
                );
                StandardHarness::report_finalization(&mut peer_mailbox, finalizations[i].clone())
                    .await;
            }
            context.sleep(Duration::from_millis(200)).await;

            // Seed inconsistent state: only block_one persisted but all 5
            // finalizations exist, leaving blocks 2-5 missing.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one],
                &finalizations
                    .iter()
                    .enumerate()
                    .map(|(i, f)| (Height::new(i as u64 + 1), f.clone()))
                    .collect::<Vec<_>>(),
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through all five blocks sequentially. Blocks 2-5 must be
            // repaired from the peer before they can be dispatched.
            for expected_height in 1..=5 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies repair when the finalized tip is far ahead of the last stored
    // block and only the tip has a direct finalization. This forces recovery to
    // walk the chain backwards by block commitment for more than `max_repair`
    // missing heights.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_large_pending_tip_by_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(120));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(3),
                participants.clone(),
            )
            .await;
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();
            let peer_validator = participants[1].clone();
            let pending_tip = 18;

            let mut blocks = Vec::new();
            let mut parent = Sha256::hash(&[b""]);
            for height in 1..=pending_tip {
                let block = make_raw_block(parent, Height::new(height), height * 100);
                parent = block.digest();
                blocks.push(block);
            }
            let tip_block = blocks.last().expect("tip block exists");
            let tip_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(pending_tip)),
                    View::new(pending_tip - 1),
                    StandardHarness::commitment(tip_block),
                ),
                &schemes,
                QUORUM,
            );

            // Give the peer every block, but the recovering validator will only
            // know the tip finalization. The repair loop must fetch blocks
            // 18 down to 2 by commitment.
            let peer_mailbox = StandardHarness::setup_validator(
                context.child("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;
            for block in blocks.iter() {
                assert!(
                    peer_mailbox
                        .verified(
                            Round::new(Epoch::zero(), View::new(block.height().get())),
                            block.clone(),
                        )
                        .await
                );
            }
            context.sleep(Duration::from_millis(200)).await;

            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[blocks[0].clone()],
                &[(Height::new(pending_tip), tip_finalization)],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;

            for _ in 0..100 {
                if recovering.application.tip().map(|(height, _)| height)
                    == Some(Height::new(pending_tip))
                {
                    break;
                }
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                recovering.application.tip().map(|(height, _)| height),
                Some(Height::new(pending_tip)),
                "restart should surface the pending finalized tip before all blocks are repaired"
            );

            assert_eq!(recovering.application.acknowledged().await, Height::zero());
            for expected_height in 1..=pending_tip {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }

            for height in [2, 10, pending_tip] {
                let block = recovering
                    .mailbox
                    .get_block(Height::new(height))
                    .await
                    .unwrap_or_else(|| panic!("block {height} should be recoverable"));
                assert_eq!(block.digest(), blocks[(height - 1) as usize].digest());
            }
        });
    }

    // Verifies that when all finalized blocks are already present on disk,
    // restart completes normally with no repair needed. Acts as a baseline
    // to confirm the repair logic is a no-op in the consistent case.
    #[test_traced("WARN")]
    fn test_standard_restart_no_trailing_finalizations_is_noop() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(3),
                participants.clone(),
            )
            .await;
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_one = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    StandardHarness::commitment(&block_one),
                ),
                &schemes,
                3,
            );
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    StandardHarness::commitment(&block_two),
                ),
                &schemes,
                3,
            );

            // Seed fully consistent state: both blocks and both finalizations.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one.clone(), block_two.clone()],
                &[
                    (Height::new(1), finalization_one),
                    (Height::new(2), finalization_two),
                ],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through sequential acks to confirm no repair was needed.
            for expected_height in 1..=2 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies that trailing repair can source a missing block from the local
    // cache (notarized storage) instead of fetching from a peer. This covers
    // the case where a block was notarized and cached but the finalized-blocks
    // archive was not updated before a crash.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_trailing_block_from_local_cache() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            // No network links: forces repair to rely on local cache only.
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(3),
                participants.clone(),
            )
            .await;

            let recovering_validator = participants[0].clone();

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    StandardHarness::commitment(&block_two),
                ),
                &schemes,
                3,
            );

            let partition_prefix = format!("validator-{recovering_validator}");

            // Seed block_two into the cache's notarized storage so the
            // recovering validator can find it locally during trailing repair,
            // without needing a peer to serve it.
            seed_cache_block(
                context.child("storage"),
                &partition_prefix,
                Epoch::zero(),
                View::new(2),
                &block_two,
            )
            .await;

            // Seed inconsistent state: block_one in the finalized archive,
            // finalization for height 2 but no block_two in the archive.
            // block_two only exists in the cache's notarized storage.
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one],
                &[(Height::new(2), finalization_two)],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through both blocks to confirm repair recovered them.
            for expected_height in 1..=2 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies that cache::Manager::load_persisted_epochs re-opens epoch
    // archives from disk, making blocks written in a prior session findable
    // via find_block after restart.
    #[test_traced("WARN")]
    fn test_cache_load_persisted_epochs_finds_blocks() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let prefix = "test-cache";
            let make_cfg = || cache::Config {
                partition_prefix: prefix.to_string(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NonZeroUsize::new(1024).unwrap(),
                key_write_buffer: NonZeroUsize::new(1024).unwrap(),
                value_write_buffer: NonZeroUsize::new(1024).unwrap(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            let block = Arc::new(make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100));
            let digest = block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Write a block into the cache.
            {
                let mgr = cache::Manager::<_, Standard<B>, S>::init(
                    context.child("write"),
                    make_cfg(),
                    (),
                )
                .await;
                let (_mgr, handle) = mgr.put_notarized(round, digest, &block).await;
                handle.await.expect("failed to sync block");
            }

            // Re-init the cache (simulating restart). find_block should fail
            // before loading persisted epochs.
            let mut mgr =
                cache::Manager::<_, Standard<B>, S>::init(context.child("read"), make_cfg(), ())
                    .await;
            assert_eq!(
                mgr.find_block_matching(digest, |_| true).await,
                None,
                "cache should not find block before loading persisted epochs"
            );

            mgr = mgr.load_persisted_epochs().await;
            assert_eq!(
                mgr.find_block_matching(digest, |_| true).await,
                Some(block),
                "cache should find block after loading persisted epochs"
            );
        });
    }

    // The certify barrier folds in notarization durability via
    // `start_sync_notarizations`: the handle it returns covers a notarization
    // write accepted earlier (whose own handle was dropped unawaited), so
    // awaiting the barrier guarantees the certificate is recoverable.
    #[test_traced("WARN")]
    fn test_cache_start_sync_notarizations_covers_prior_write() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let prefix = "test-cache-notarizations";
            let make_cfg = || cache::Config {
                partition_prefix: prefix.to_string(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NonZeroUsize::new(1024).unwrap(),
                key_write_buffer: NonZeroUsize::new(1024).unwrap(),
                value_write_buffer: NonZeroUsize::new(1024).unwrap(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let digest = block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));
            let notarization = StandardHarness::make_notarization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            {
                let mgr = cache::Manager::<_, Standard<B>, S>::init(
                    context.child("write"),
                    make_cfg(),
                    (),
                )
                .await;
                let (mgr, handle) = mgr.put_notarization(round, digest, &notarization).await;
                drop(handle);
                let (_mgr, sync) = mgr.start_sync_notarizations(round).await;
                sync.await.expect("failed to sync notarizations");
            }

            let mgr =
                cache::Manager::<_, Standard<B>, S>::init(context.child("read"), make_cfg(), ())
                    .await;
            let mgr = mgr.load_persisted_epochs().await;
            assert!(
                mgr.get_notarization(round).await.is_some(),
                "notarization covered by the barrier must be durable"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_get_block_by_commitment_from_sources_and_missing() {
        harness::get_block_by_commitment_from_sources_and_missing::<InlineHarness>();
        harness::get_block_by_commitment_from_sources_and_missing::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_finalization_by_height() {
        harness::get_finalization_by_height::<InlineHarness>();
        harness::get_finalization_by_height::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_blocks_forward_range() {
        harness::blocks_forward_range::<InlineHarness>();
        harness::blocks_forward_range::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_same_height_different_views() {
        harness::finalize_same_height_different_views::<InlineHarness>();
        harness::finalize_same_height_different_views::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_init_processed_height() {
        harness::init_processed_height::<InlineHarness>();
        harness::init_processed_height::<DeferredHarness>();
    }

    #[test_traced("INFO")]
    fn test_standard_broadcast_caches_block() {
        harness::broadcast_caches_block::<InlineHarness>();
        harness::broadcast_caches_block::<DeferredHarness>();
    }

    #[test_traced("INFO")]
    fn test_standard_rejects_block_delivery_below_floor() {
        harness::reject_stale_block_delivery_after_floor_update::<InlineHarness>();
        harness::reject_stale_block_delivery_after_floor_update::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_buffered_block_installs_floor_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            // No links are added, so the resolver fetch started by `set_floor`
            // can never complete. The anchor can only arrive through the buffer.
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let app = setup.application;
            let mailbox = setup.mailbox;
            let buffer = setup.extra;

            // Build a chain whose tip is the floor anchor.
            const ANCHOR_HEIGHT: u64 = 5;
            let mut parent = Sha256::hash(&[b""]);
            let mut anchor = None;
            for i in 1..=ANCHOR_HEIGHT {
                let block = make_raw_block(parent, Height::new(i), i);
                parent = block.digest();
                anchor = Some(block);
            }
            let anchor = anchor.unwrap();

            // Subscribe to the anchor, creating a buffer-backed waiter.
            let subscription = mailbox.acquire(anchor.digest());

            // Set a floor whose anchor block is not yet available locally.
            let round = Round::new(Epoch::zero(), View::new(ANCHOR_HEIGHT));
            let finalization = StandardHarness::make_finalization(
                Proposal {
                    round,
                    parent: View::new(ANCHOR_HEIGHT - 1),
                    payload: anchor.digest(),
                },
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(finalization);

            // Barrier: mailbox messages are FIFO, so this confirms `set_floor`
            // recorded a pending anchor before the buffer delivers the block.
            assert!(
                mailbox
                    .get_block(Identifier::Height(Height::new(ANCHOR_HEIGHT)))
                    .await
                    .is_none()
            );

            // Deliver the anchor through the broadcast buffer, completing the waiter.
            let _ = buffer.broadcast(Recipients::All, anchor.clone());

            // The waiter must wake the subscriber.
            let received = subscription.await.unwrap();
            assert_eq!(received.digest(), anchor.digest());

            // The waiter must also install the floor anchor and resume dispatch.
            while !app.blocks().contains_key(&Height::new(ANCHOR_HEIGHT)) {
                context.sleep(Duration::from_millis(50)).await;
            }
            let (tip_height, tip_digest) = app.tip().unwrap();
            assert_eq!(tip_height, Height::new(ANCHOR_HEIGHT));
            assert_eq!(tip_digest, anchor.digest());
            let stored = mailbox
                .get_block(Identifier::Height(Height::new(ANCHOR_HEIGHT)))
                .await
                .unwrap();
            assert_eq!(stored.digest(), anchor.digest());
        })
    }

    #[test_traced("WARN")]
    fn test_standard_floor_preserves_registered_subscriptions() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            // No links are added. Network fetches cannot complete. Waiters
            // resolve only through the buffer or closure.
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let mailbox = setup.mailbox;
            let buffer = setup.extra;

            // Build a chain whose tip is the floor anchor.
            const ANCHOR_HEIGHT: u64 = 5;
            let mut parent = Sha256::hash(&[b""]);
            let mut anchor = None;
            for i in 1..=ANCHOR_HEIGHT {
                let block = make_raw_block(parent, Height::new(i), i);
                parent = block.digest();
                anchor = Some(block);
            }
            let anchor = anchor.unwrap();
            let anchor_round = Round::new(Epoch::zero(), View::new(ANCHOR_HEIGHT));

            // Independent callers wait for the same commitment while unrelated
            // application progress advances the floor.
            let missing = make_raw_block(Sha256::hash(&[b"missing-parent"]), Height::new(2), 999);
            let missing_digest = missing.digest();
            let mut first = mailbox.acquire(missing_digest);
            let mut second = mailbox.acquire(missing_digest);

            // The anchor subscription resolves when the block arrives.
            let anchor_wait = mailbox.acquire(anchor.digest());

            // Install the floor and deliver the anchor through the buffer.
            let finalization = StandardHarness::make_finalization(
                Proposal {
                    round: anchor_round,
                    parent: View::new(ANCHOR_HEIGHT - 1),
                    payload: anchor.digest(),
                },
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(finalization);
            let _ = buffer.broadcast(Recipients::All, anchor.clone());
            let received = anchor_wait.await.unwrap();
            assert_eq!(received.digest(), anchor.digest());

            // Wait until processed progress passes the unavailable block's height.
            while mailbox.get_processed_height().await != Some(Height::new(ANCHOR_HEIGHT)) {
                context.sleep(Duration::from_millis(50)).await;
            }

            // Parent availability determines subscription lifetime.
            assert!(matches!(first.try_recv(), Err(TryRecvError::Empty)));
            assert!(matches!(second.try_recv(), Err(TryRecvError::Empty)));
            // A new caller joins acquisition even after progress passed its height.
            let mut late_first = mailbox.acquire(missing_digest);
            let _ = mailbox.get_processed_height().await;
            assert!(matches!(late_first.try_recv(), Err(TryRecvError::Empty)));
            // Later local availability satisfies every registered caller.
            let _ = buffer.broadcast(Recipients::All, missing.clone());
            assert_eq!(first.await.unwrap().digest(), missing_digest);
            assert_eq!(second.await.unwrap().digest(), missing_digest);
            assert_eq!(late_first.await.unwrap().digest(), missing_digest);
        })
    }

    #[test_traced("WARN")]
    fn test_standard_resolver_floor_anchor_install_wakes_subscriber() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let victim = participants[0].clone();
            let server = participants[1].clone();
            let peers = vec![victim.clone(), server.clone()];
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                peers.clone(),
            )
            .await;

            let victim_setup = StandardHarness::setup_validator(
                context.child("victim"),
                &mut oracle,
                victim.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let server_setup = StandardHarness::setup_validator(
                context.child("server"),
                &mut oracle,
                server.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;
            let app = victim_setup.application;
            let mailbox = victim_setup.mailbox;
            let mut server_handle: ValidatorHandle<StandardHarness> = ValidatorHandle {
                mailbox: server_setup.mailbox,
                extra: server_setup.extra,
            };

            // Build a chain whose tip is the floor anchor.
            const ANCHOR_HEIGHT: u64 = 5;
            let mut parent = Sha256::hash(&[b""]);
            let mut anchor = None;
            for i in 1..=ANCHOR_HEIGHT {
                let block = make_raw_block(parent, Height::new(i), i);
                parent = block.digest();
                anchor = Some(block);
            }
            let anchor = anchor.unwrap();
            let round = Round::new(Epoch::zero(), View::new(ANCHOR_HEIGHT));

            // The server caches the anchor so it can serve the resolver fetch.
            StandardHarness::propose(&mut server_handle, round, &anchor).await;

            // Subscribe while the anchor is unavailable on the victim.
            let subscription = mailbox.acquire(anchor.digest());

            // Record a pending floor anchor and start the resolver fetch.
            let finalization = StandardHarness::make_finalization(
                Proposal {
                    round,
                    parent: View::new(ANCHOR_HEIGHT - 1),
                    payload: anchor.digest(),
                },
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(finalization);

            // Barrier: mailbox messages are FIFO, so this confirms `set_floor`
            // recorded the pending anchor.
            assert!(
                mailbox
                    .get_block(Identifier::Height(Height::new(ANCHOR_HEIGHT)))
                    .await
                    .is_none()
            );

            // Links come up only now, so the anchor can only arrive through
            // the resolver fetch started by `set_floor`.
            setup_network_links(&mut oracle, &peers, LINK).await;

            // The delivery installs the floor anchor and must wake subscribers.
            let received = select! {
                result = subscription => {
                    result.expect("subscription should receive the floor anchor")
                },
                _ = context.sleep(Duration::from_secs(10)) => {
                    panic!("subscriber not woken by installed anchor delivery");
                },
            };
            assert_eq!(received.digest(), anchor.digest());

            // The install resumed dispatch at the anchor.
            while !app.blocks().contains_key(&Height::new(ANCHOR_HEIGHT)) {
                context.sleep(Duration::from_millis(50)).await;
            }
            let (tip_height, tip_digest) = app.tip().unwrap();
            assert_eq!(tip_height, Height::new(ANCHOR_HEIGHT));
            assert_eq!(tip_digest, anchor.digest());
        })
    }

    #[test_traced("WARN")]
    fn test_standard_below_floor_anchor_delivery_wakes_subscriber() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let victim = participants[0].clone();
            let server = participants[1].clone();
            let peers = vec![victim.clone(), server.clone()];
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                peers.clone(),
            )
            .await;

            let victim_setup = StandardHarness::setup_validator(
                context.child("victim"),
                &mut oracle,
                victim.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let server_setup = StandardHarness::setup_validator(
                context.child("server"),
                &mut oracle,
                server.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;
            let app = victim_setup.application;
            let mut mailbox = victim_setup.mailbox;
            let mut server_handle: ValidatorHandle<StandardHarness> = ValidatorHandle {
                mailbox: server_setup.mailbox,
                extra: server_setup.extra,
            };

            // Advance the victim's processed floor to height 3 on the canonical chain.
            let mut parent = Sha256::hash(&[b""]);
            let mut canonical = Vec::new();
            for i in 1..=3u64 {
                let block = make_raw_block(parent, Height::new(i), i);
                parent = block.digest();
                canonical.push(block);
            }
            for block in &canonical {
                let height = block.height();
                let round = Round::new(Epoch::zero(), View::new(height.get()));
                assert!(mailbox.verified(round, block.clone()).await);
                let finalization = StandardHarness::make_finalization(
                    Proposal {
                        round,
                        parent: View::new(height.get() - 1),
                        payload: block.digest(),
                    },
                    &schemes,
                    QUORUM,
                );
                StandardHarness::report_finalization(&mut mailbox, finalization).await;
            }
            while !app.blocks().contains_key(&Height::new(3)) {
                context.sleep(Duration::from_millis(50)).await;
            }

            // A conflicting finalization commits to a fork block at a height at
            // or below the processed floor (only reachable when a Byzantine
            // quorum double-finalizes).
            let fork = make_raw_block(canonical[0].digest(), Height::new(2), 999);
            let fork_round = Round::new(Epoch::zero(), View::new(4));

            // The server caches the fork block so it can serve the resolver fetch.
            StandardHarness::propose(&mut server_handle, fork_round, &fork).await;

            // Subscribe while the fork block is unavailable on the victim.
            let subscription = mailbox.acquire(fork.digest());

            // Record a pending floor anchor for the unavailable fork block and
            // start the resolver fetch.
            let fork_finalization = StandardHarness::make_finalization(
                Proposal {
                    round: fork_round,
                    parent: View::new(1),
                    payload: fork.digest(),
                },
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(fork_finalization);

            // Barrier: mailbox messages are FIFO, so this confirms `set_floor`
            // recorded the pending anchor.
            assert!(mailbox.get_block(&fork.digest()).await.is_none());

            // Links come up only now, so the fork block can only arrive through
            // the resolver fetch started by `set_floor`.
            setup_network_links(&mut oracle, &peers, LINK).await;

            // The delivery takes the at-or-below-floor branch, which must still
            // wake subscribers waiting on the block.
            let received = select! {
                result = subscription => {
                    result.expect("subscription should receive the floor anchor")
                },
                _ = context.sleep(Duration::from_secs(10)) => {
                    panic!("subscriber not woken by below-floor anchor delivery");
                },
            };
            assert_eq!(received.digest(), fork.digest());

            // The pending floor was consumed, so dispatch continues on the
            // canonical chain.
            let next = make_raw_block(canonical[2].digest(), Height::new(4), 4);
            let next_round = Round::new(Epoch::zero(), View::new(5));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal {
                    round: next_round,
                    parent: View::new(3),
                    payload: next.digest(),
                },
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, next_finalization).await;
            while !app.blocks().contains_key(&Height::new(4)) {
                context.sleep(Duration::from_millis(50)).await;
            }
        })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WrapperKind {
        Inline,
        Deferred,
    }

    fn wrapper_kinds() -> [WrapperKind; 2] {
        [WrapperKind::Inline, WrapperKind::Deferred]
    }

    type Runtime = deterministic::Context;
    type App = MockVerifyingApp<B, S>;
    type InlineWrapper = Inline<Runtime, S, App, B, FixedEpocher>;
    type DeferredWrapper = Deferred<Runtime, S, App, B, FixedEpocher>;

    #[derive(Clone)]
    enum Wrapper {
        Inline(InlineWrapper),
        Deferred(DeferredWrapper),
    }

    impl Wrapper {
        fn new(
            kind: WrapperKind,
            context: Runtime,
            app: App,
            marshal: Mailbox<S, Standard<B>>,
        ) -> Self {
            match kind {
                WrapperKind::Inline => Self::Inline(Inline::new(
                    context,
                    app,
                    marshal,
                    FixedEpocher::new(BLOCKS_PER_EPOCH),
                )),
                WrapperKind::Deferred => Self::Deferred(Deferred::new(
                    context,
                    app,
                    marshal,
                    FixedEpocher::new(BLOCKS_PER_EPOCH),
                )),
            }
        }

        fn kind(&self) -> WrapperKind {
            match self {
                Self::Inline(_) => WrapperKind::Inline,
                Self::Deferred(_) => WrapperKind::Deferred,
            }
        }

        async fn propose(&mut self, context: Ctx, ancestry: Arc<[D]>) -> oneshot::Receiver<D> {
            match self {
                Self::Inline(inline) => inline.propose(context, ancestry).await,
                Self::Deferred(deferred) => deferred.propose(context, ancestry).await,
            }
        }

        async fn verify(
            &mut self,
            context: Ctx,
            digest: D,
            ancestry: Arc<[D]>,
        ) -> oneshot::Receiver<bool> {
            match self {
                Self::Inline(inline) => inline.verify(context, digest, ancestry).await,
                Self::Deferred(deferred) => deferred.verify(context, digest, ancestry).await,
            }
        }

        async fn certify(
            &mut self,
            round: Round,
            digest: D,
            ancestry: Arc<[D]>,
        ) -> oneshot::Receiver<bool> {
            match self {
                Self::Inline(inline) => inline.certify(round, digest, ancestry).await,
                Self::Deferred(deferred) => deferred.certify(round, digest, ancestry).await,
            }
        }
    }

    impl Automaton for Wrapper {
        type Context = Ctx;
        type Digest = D;

        async fn propose(
            &mut self,
            context: Self::Context,
            ancestry: Arc<[D]>,
        ) -> oneshot::Receiver<Self::Digest> {
            Self::propose(self, context, ancestry).await
        }

        async fn verify(
            &mut self,
            context: Self::Context,
            digest: Self::Digest,
            ancestry: Arc<[D]>,
        ) -> oneshot::Receiver<bool> {
            Self::verify(self, context, digest, ancestry).await
        }
    }

    impl CertifiableAutomaton for Wrapper {
        async fn certify(
            &mut self,
            round: Round,
            digest: Self::Digest,
            ancestry: Arc<[D]>,
        ) -> oneshot::Receiver<bool> {
            Self::certify(self, round, digest, ancestry).await
        }
    }

    impl Relay for Wrapper {
        type Digest = D;
        type PublicKey = PublicKey;
        type Plan = Plan<PublicKey>;

        fn broadcast(&mut self, digest: Self::Digest, plan: Self::Plan) -> Feedback {
            match self {
                Self::Inline(inline) => inline.broadcast(digest, plan),
                Self::Deferred(deferred) => deferred.broadcast(digest, plan),
            }
        }
    }

    fn pending_conflicting_verify_does_not_poison_certification(kind: WrapperKind) {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(
                &mut context,
                NAMESPACE,
                NUM_VALIDATORS,
            );
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;
            let setup = StandardHarness::setup_validator(
                context.child("validator"),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let buffer = setup.extra;

            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let certified_round = Round::new(Epoch::zero(), View::new(1));
            let certified_block = B::new::<Sha256>(
                Ctx {
                    round: certified_round,
                    leader: participants[0].clone(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            let certified_digest = certified_block.digest();
            assert!(marshal.verified(certified_round, certified_block).await);

            let skipped_round = Round::new(Epoch::zero(), View::new(2));
            let skipped_block = B::new::<Sha256>(
                Ctx {
                    round: skipped_round,
                    leader: participants[1].clone(),
                    parent: (View::new(1), certified_digest),
                },
                certified_digest,
                Height::new(2),
                200,
            );
            let skipped_digest = skipped_block.digest();
            assert!(marshal.verified(skipped_round, skipped_block).await);

            let round = Round::new(Epoch::zero(), View::new(3));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: participants[1].clone(),
                    parent: (View::new(2), skipped_digest),
                },
                skipped_digest,
                Height::new(3),
                300,
            );
            let digest = block.digest();
            let conflicting_context = Ctx {
                round,
                leader: participants[1].clone(),
                parent: (View::new(1), certified_digest),
            };
            let mut wrapper = Wrapper::new(
                kind,
                context.child("wrapper"),
                MockVerifyingApp::new(),
                marshal,
            );

            // `verify` registers the gate synchronously but cannot resolve it
            // until the leader's block arrives. A notarization can arrive in
            // this window, causing Simplex's sole `certify` request to consume
            // and await that still-pending gate.
            let verify_rx = wrapper.verify(conflicting_context, digest, Arc::from([genesis.digest(), certified_digest])).await;
            let certify_rx = wrapper.certify(round, digest, Arc::from([genesis.digest(), certified_digest, skipped_digest])).await;
            assert!(
                buffer
                    .broadcast(Recipients::Some(vec![]), block)
                    .accepted(),
                "candidate broadcast should be accepted"
            );

            select! {
                result = verify_rx => {
                    assert!(
                        !result.expect("verify result missing"),
                        "{kind:?}: the conflicting proposal must be rejected"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("{kind:?}: conflicting verification did not resolve");
                },
            }
            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "{kind:?}: pending certification must not adopt the conflicting verification verdict"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("{kind:?}: pending certification did not resolve");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_inline_pending_conflicting_verify_does_not_poison_certification() {
        pending_conflicting_verify_does_not_poison_certification(WrapperKind::Inline);
    }

    #[test_traced("WARN")]
    fn test_deferred_pending_conflicting_verify_does_not_poison_certification() {
        pending_conflicting_verify_does_not_poison_certification(WrapperKind::Deferred);
    }

    fn scripted_byzantine_parent_equivocation(kind: WrapperKind) {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(
                &mut context,
                NAMESPACE,
                NUM_VALIDATORS,
            );
            // At epoch 0, round-robin elects participant 3 for view 3. Pin the
            // mapping: with a different leader the scripted proposal never
            // reaches verify, and certification would pass through the no-gate
            // recovery path with or without a poisoned gate.
            let byzantine = participants[3].clone();
            let victim = participants[1].clone();
            let observer = participants[0].clone();
            let elector: RoundRobinElector<S> =
                RoundRobin::<Sha256>::default().build(schemes[1].participants());
            assert_eq!(
                schemes[1]
                    .participants()
                    .key(elector.elect(Round::new(Epoch::zero(), View::new(3)), None)),
                Some(&byzantine),
            );

            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;
            let setup = StandardHarness::setup_validator(
                context.child("marshal"),
                &mut oracle,
                victim.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;
            let mut marshal = setup.mailbox;
            let buffer = setup.extra;

            // Start Simplex from a finalized view 1, then skip view 2. The
            // victim may therefore accept a view-3 proposal naming view 1,
            // while validators that certified view 2 build on view 2.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let floor_round = Round::new(Epoch::zero(), View::new(1));
            let floor_block = B::new::<Sha256>(
                Ctx {
                    round: floor_round,
                    leader: byzantine.clone(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            let floor_digest = floor_block.digest();
            assert!(marshal.verified(floor_round, floor_block).await);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(floor_round, View::zero(), floor_digest),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut marshal, floor_finalization.clone()).await;

            let skipped_round = Round::new(Epoch::zero(), View::new(2));
            let skipped_block = B::new::<Sha256>(
                Ctx {
                    round: skipped_round,
                    leader: participants[3].clone(),
                    parent: (View::new(1), floor_digest),
                },
                floor_digest,
                Height::new(2),
                200,
            );
            let skipped_digest = skipped_block.digest();
            assert!(marshal.verified(skipped_round, skipped_block).await);

            let round = Round::new(Epoch::zero(), View::new(3));
            let embedded_context = Ctx {
                round,
                leader: byzantine.clone(),
                parent: (View::new(2), skipped_digest),
            };
            let block = B::new::<Sha256>(
                embedded_context,
                skipped_digest,
                Height::new(3),
                300,
            );
            let digest = block.digest();
            assert!(
                buffer
                    .broadcast(Recipients::Some(vec![]), block)
                    .accepted(),
                "candidate broadcast should be accepted"
            );

            // Channels 1 and 2 are owned by marshal. Keep the three Simplex
            // channels separate, register the Byzantine peer as the scripted
            // sender, and tap the observer's vote receiver.
            let victim_control = oracle.control(victim.clone());
            let vote_network = victim_control.register(3, TEST_QUOTA).await.unwrap();
            let certificate_network = victim_control.register(4, TEST_QUOTA).await.unwrap();
            let resolver_network = victim_control.register(5, TEST_QUOTA).await.unwrap();
            let byzantine_control = oracle.control(byzantine.clone());
            let (mut byzantine_vote_sender, _byzantine_vote_receiver) =
                byzantine_control.register(3, TEST_QUOTA).await.unwrap();
            let (mut byzantine_certificate_sender, _byzantine_certificate_receiver) =
                byzantine_control.register(4, TEST_QUOTA).await.unwrap();
            let _byzantine_resolver = byzantine_control.register(5, TEST_QUOTA).await.unwrap();
            let (_observer_vote_sender, mut observer_vote_receiver) = oracle
                .control(observer)
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            setup_network_links(&mut oracle, &participants, LINK).await;

            let wrapper = Wrapper::new(
                kind,
                context.child("wrapper"),
                MockVerifyingApp::new(),
                marshal.clone(),
            );
            let engine = simplex::Engine::new(
                context.child("simplex"),
                simplex::config::Config {
                    scheme: schemes[1].clone(),
                    elector: RoundRobin::<Sha256>::default(),
                    blocker: oracle.control(victim.clone()),
                    automaton: wrapper.clone(),
                    relay: wrapper,
                    reporter: marshal,
                    strategy: Sequential,
                    partition: format!("scripted-equivocation-{kind:?}"),
                    mailbox_size: NZUsize!(128),
                    epoch: Epoch::zero(),
                    floor: simplex::config::Floor::Finalized(floor_finalization),
                    replay_buffer: NZUsize!(1024),
                    write_buffer: NZUsize!(1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    leader_timeout: Duration::from_secs(2),
                    certification_timeout: Duration::from_secs(4),
                    timeout_retry: Duration::from_secs(3),
                    view_retention: ViewDelta::new(10),
                    skip: SkipPolicy::Enabled {
                        timeout: Duration::from_secs(6),
                        budget: SkipBudget::Participants,
                    },
                    fetch_timeout: Duration::from_secs(1),
                    forward: ForwardPolicy::Disabled,
                    track_historical_votes: false,
                },
            );
            let _engine = engine.start(vote_network, certificate_network, resolver_network);

            let nullifies: Vec<_> = [0usize, 2, 3]
                .into_iter()
                .map(|index| Nullify::sign::<D>(&schemes[index], skipped_round).unwrap())
                .collect();
            let nullification =
                Nullification::from_nullifies(&schemes[0], non_empty![@&nullifies], &Sequential).unwrap();
            byzantine_certificate_sender.send(
                Recipients::One(victim.clone()),
                Certificate::<S, D>::Nullification(nullification).encode(),
                true,
            );
            context.sleep(Duration::from_millis(250)).await;

            // The Byzantine leader reuses the honest block commitment in a
            // conflicting header that declares the older certified parent.
            let bad_proposal = Proposal::new(round, View::new(1), digest);
            let good_proposal = Proposal::new(round, View::new(2), digest);
            assert_eq!(bad_proposal.payload, good_proposal.payload);
            assert_ne!(bad_proposal, good_proposal);
            let bad_vote = Notarize::sign(&schemes[3], bad_proposal).unwrap();
            byzantine_vote_sender.send(
                Recipients::One(victim.clone()),
                Vote::<S, D>::Notarize(bad_vote).encode(),
                true,
            );

            // InvalidProposal is the deterministic barrier proving that the
            // conflicting header reached verify and was rejected before the
            // honest notarization arrives.
            select! {
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("{kind:?}: victim did not reject the conflicting proposal");
                },
                result = async {
                    loop {
                        let (_, message) = observer_vote_receiver.recv().await.unwrap();
                        let vote = Vote::<S, D>::decode(message).unwrap();
                        if matches!(vote, Vote::Nullify(ref nullify) if nullify.round == round) {
                            break;
                        }
                    }
                } => result,
            }
            context.sleep(Duration::from_millis(250)).await;

            // The selected parent certificate reaches Simplex after rejection of
            // the conflicting header. Its body is already available in Marshal.
            let parent_notarization = StandardHarness::make_notarization(
                Proposal::new(skipped_round, View::new(1), skipped_digest),
                &schemes,
                QUORUM,
            );
            byzantine_certificate_sender.send(
                Recipients::One(victim.clone()),
                Certificate::<S, D>::Notarization(parent_notarization).encode(),
                true,
            );

            // The Byzantine validator and the other two honest validators
            // notarize the header naming view 2 without the victim's vote.
            let good_votes: Vec<_> = [0usize, 2, 3]
                .into_iter()
                .map(|index| Notarize::sign(&schemes[index], good_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&schemes[0], non_empty![@&good_votes], &Sequential).unwrap();
            byzantine_certificate_sender.send(
                Recipients::One(victim),
                Certificate::<S, D>::Notarization(notarization).encode(),
                true,
            );

            // Certification is single-shot. The victim already nullified view
            // 3, so same-term vote safety correctly prevents a finalize vote.
            // Successful certification must instead advance it to view 4,
            // where the silent leader eventually causes a new nullify vote.
            let next_round = Round::new(Epoch::zero(), View::new(4));
            select! {
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("{kind:?}: victim did not advance after certification");
                },
                result = async {
                    loop {
                        let (_, message) = observer_vote_receiver.recv().await.unwrap();
                        let vote = Vote::<S, D>::decode(message).unwrap();
                        if matches!(vote, Vote::Nullify(ref nullify) if nullify.round == next_round) {
                            break;
                        }
                    }
                } => result,
            }
        });
    }

    #[test_traced("WARN")]
    fn test_inline_scripted_byzantine_parent_equivocation() {
        scripted_byzantine_parent_equivocation(WrapperKind::Inline);
    }

    #[test_traced("WARN")]
    fn test_deferred_scripted_byzantine_parent_equivocation() {
        scripted_byzantine_parent_equivocation(WrapperKind::Deferred);
    }

    #[test_traced("WARN")]
    fn test_standard_certify_first_block_fetches_genesis_parent() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let round = Round::new(Epoch::zero(), View::new(1));
                let block_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::zero(), genesis.digest()),
                };
                let block =
                    B::new::<Sha256>(block_context.clone(), genesis.digest(), Height::new(1), 100);
                let digest = block.digest();
                assert!(marshal.verified(round, block).await);

                context.sleep(Duration::from_millis(10)).await;

                let verify_result = wrapper
                    .verify(block_context, digest, Arc::from([genesis.digest()]))
                    .await
                    .await
                    .expect("verify result missing");
                assert!(
                    verify_result,
                    "{kind:?}: height-1 block should verify with genesis as parent"
                );

                let certify_result = wrapper
                    .certify(round, digest, Arc::from([genesis.digest()]))
                    .await
                    .await
                    .expect("certify result missing");
                assert!(
                    certify_result,
                    "{kind:?}: height-1 block should certify with genesis as parent"
                );
            });
        }
    }

    #[test_traced("WARN")]
    fn test_standard_verify_missing_candidate_fetches_until_canceled() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let me = participants[0].clone();

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let (marshal, buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("missing-candidate-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    Some(RecordingBuffer::default()),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
                )
                .await;
                let buffer = buffer.expect("buffer was provided");
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let round = Round::new(Epoch::zero(), View::new(1));
                let consensus_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::zero(), genesis.digest()),
                };
                let missing = Sha256::hash(&[b"missing candidate"]);
                let mut verify = wrapper.verify(consensus_context, missing, Arc::from([genesis.digest()])).await;

                context.sleep(Duration::from_millis(50)).await;
                assert!(
                    buffer.commitment_subscription_count() > 0,
                    "{kind:?}: unavailable candidate verification must register a local wait"
                );
                assert!(
                    resolver.fetches().iter().any(|fetch| matches!((&fetch.key, &fetch.subscriber), (handler::Key::Block(commitment), handler::Annotation::Subscription) if *commitment == missing)),
                    "{kind:?}: unavailable candidate verification must fetch its exact commitment"
                );
                assert!(
                    matches!(
                        verify.try_recv(),
                        Err(commonware_utils::channel::oneshot::error::TryRecvError::Empty)
                    ),
                    "{kind:?}: unavailable candidate verification must remain pending"
                );

                drop(verify);
                context.sleep(Duration::from_millis(10)).await;
                assert!(
                    resolver.active_fetches().is_empty(),
                    "{kind:?}: canceling the final waiter must cancel acquisition"
                );
            });
        }
    }

    /// Certification acquires and persists a recovered consensus commitment when
    /// its local gate and durable body are absent after an unclean shutdown.
    #[test_traced("WARN")]
    fn test_standard_certify_missing_candidate_fetches_by_commitment() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let me = participants[0].clone();

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let (marshal, buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("missing-certify-candidate-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    Some(RecordingBuffer::default()),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
                )
                .await;
                let buffer = buffer.expect("buffer was provided");
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let round = Round::new(Epoch::zero(), View::new(1));
                let block_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::zero(), genesis.digest()),
                };
                let block = B::new::<Sha256>(block_context, genesis.digest(), Height::new(1), 100);
                let digest = block.digest();
                resolver.respond_to_next_fetch(block.encode());
                let certify = wrapper
                    .certify(round, digest, Arc::from([genesis.digest()]))
                    .await;

                let result = certify.await.expect("certify result missing");
                assert!(
                    result,
                    "{kind:?}: fetched notarized candidate should certify"
                );
                assert!(
                    resolver.wait_for_delivery_response().await,
                    "{kind:?}: block delivery should validate"
                );
                assert!(
                    resolver.fetches().iter().any(|fetch| matches!(
                        (&fetch.key, &fetch.subscriber),
                        (
                            handler::Key::Block(commitment),
                            handler::Annotation::Subscription,
                        ) if *commitment == digest
                    )),
                    "{kind:?}: certify should fetch the candidate commitment"
                );

                assert!(
                    buffer.commitment_subscription_count() > 0,
                    "{kind:?}: unavailable candidate certification must register a local wait"
                );
            });
        }
    }

    struct CertificationCase {
        wrapper: Wrapper,
        marshal: Mailbox<S, Standard<B>>,
        buffer: RecordingBuffer,
        resolver: RecordingResolver,
        block_context: Ctx,
        block: B,
    }

    async fn certification_case(
        context: &mut Runtime,
        kind: WrapperKind,
        partition_prefix: String,
    ) -> CertificationCase {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(context, NAMESPACE, NUM_VALIDATORS);
        let me = participants[0].clone();

        let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
        let (marshal, buffer, resolver, _) = start_standard_actor(
            context.child("validator"),
            &partition_prefix,
            ConstantProvider::new(schemes[0].clone()),
            Application::<B>::manual_ack(),
            Some(RecordingBuffer::default()),
            Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
        )
        .await;
        let buffer = buffer.expect("buffer was provided");
        let wrapper = Wrapper::new(
            kind,
            context.child("wrapper"),
            MockVerifyingApp::new(),
            marshal.clone(),
        );

        let round = Round::new(Epoch::zero(), View::new(1));
        let block_context = Ctx {
            round,
            leader: me,
            parent: (View::zero(), genesis.digest()),
        };
        let block = B::new::<Sha256>(block_context.clone(), genesis.digest(), Height::new(1), 100);

        CertificationCase {
            wrapper,
            marshal,
            buffer,
            resolver,
            block_context,
            block,
        }
    }

    /// Concurrent verification and certification share candidate acquisition and
    /// both complete when its exact body arrives.
    #[test_traced("WARN")]
    fn test_standard_certify_shares_pending_verification_fetch() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let mut case =
                    certification_case(&mut context, kind, format!("certify-bumps-fetch-{kind:?}"))
                        .await;
                let round = case.block_context.round;
                let digest = case.block.digest();

                case.resolver.respond_to_next_fetch(case.block.encode());
                let block_context = case.block_context.clone();
                let ancestry = Arc::from([block_context.parent.1]);
                let verify_rx = case
                    .wrapper
                    .verify(block_context, digest, Arc::clone(&ancestry))
                    .await;
                let certify_rx = case.wrapper.certify(round, digest, ancestry).await;

                select! {
                    result = verify_rx => {
                        assert!(
                            result.expect("verify resolves"),
                            "{kind:?}: verify should accept the fetched block"
                        );
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "{kind:?}: verify must resolve after candidate acquisition"
                        );
                    },
                }
                select! {
                    result = certify_rx => {
                        assert!(
                            result.expect("certify resolves"),
                            "{kind:?}: certify should succeed via the shared gate"
                        );
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("{kind:?}: certify must resolve through shared acquisition");
                    },
                }

                assert!(
                    case.resolver.fetches().iter().any(|fetch| matches!(
                        (&fetch.key, &fetch.subscriber),
                        (
                            handler::Key::Block(commitment),
                            handler::Annotation::Subscription,
                        ) if *commitment == digest
                    )),
                    "{kind:?}: certify must share the exact candidate fetch with verify"
                );
            });
        }
    }

    /// Pending verification owns an acquired body across buffer eviction while
    /// certification waits for the same verification gate.
    #[test_traced("WARN")]
    fn test_standard_certify_retains_transient_buffer_hit_through_eviction() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let mut case = certification_case(
                    &mut context,
                    kind,
                    format!("certify-transient-buffer-{kind:?}"),
                )
                .await;
                let round = case.block_context.round;
                let digest = case.block.digest();
                case.buffer.insert_transient(case.block.clone());

                // The next lookup returns ownership while removing the buffer entry, modeling
                // same-peer cache pressure.
                let block_context = case.block_context.clone();
                let verify_rx = case
                    .wrapper
                    .verify(
                        block_context,
                        digest,
                        Arc::from([case.block_context.parent.1]),
                    )
                    .await;
                let certify_rx = case
                    .wrapper
                    .certify(round, digest, Arc::from([case.block_context.parent.1]))
                    .await;

                // The mailbox barrier follows acquisition of the transient body.
                case.marshal.get_processed_height().await;
                assert!(
                    !case.buffer.contains(digest),
                    "{kind:?}: the buffered block must be evicted before verification completes"
                );

                select! {
                    result = verify_rx => {
                        assert!(
                            result.expect("verify resolves"),
                            "{kind:?}: verify should retain and accept the transient block"
                        );
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "{kind:?}: verify must survive transient buffer eviction"
                        );
                    },
                }
                select! {
                    result = certify_rx => {
                        assert!(
                            result.expect("certify resolves"),
                            "{kind:?}: certify should succeed via the shared verification gate"
                        );
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("{kind:?}: certify must survive transient buffer eviction");
                    },
                }
            });
        }
    }

    /// Regression: if consensus drops the optimistic verify receiver before the
    /// block arrives, the registered deferred task can close. Certification must
    /// not return that stale receiver as its final result; it should recover the
    /// notarized block and certify through the embedded-context path.
    #[test_traced("WARN")]
    fn test_standard_deferred_certify_falls_back_after_canceled_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let (marshal, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "deferred-certify-canceled-verify",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut wrapper = Wrapper::new(
                WrapperKind::Deferred,
                context.child("wrapper"),
                mock_app,
                marshal.clone(),
            );

            let round = Round::new(Epoch::zero(), View::new(1));
            let block_context = Ctx {
                round,
                leader: me,
                parent: (View::zero(), genesis.digest()),
            };
            let block =
                B::new::<Sha256>(block_context.clone(), genesis.digest(), Height::new(1), 100);
            let digest = block.digest();

            let verify_rx = wrapper
                .verify(block_context, digest, Arc::from([genesis.digest()]))
                .await;
            drop(verify_rx);
            context.sleep(Duration::from_millis(10)).await;

            resolver.respond_to_next_fetch(block.encode());
            let certify_rx = wrapper
                .certify(round, digest, Arc::from([genesis.digest()]))
                .await;

            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "certify should recover after canceled optimistic verify"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should recover after canceled optimistic verify");
                },
            }
            assert!(
                resolver.wait_for_delivery_response().await,
                "block delivery should validate"
            );
            assert!(
                resolver.fetches().iter().any(|fetch| matches!(
                    (&fetch.key, &fetch.subscriber),
                    (
                        handler::Key::Block(commitment),
                            handler::Annotation::Subscription,
                        ) if *commitment == digest
                )),
                "certify must recover by fetching the candidate commitment"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_verify_height_lie_parent_fetch_uses_commitment() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let me = participants[0].clone();

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let (marshal, _buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("height-lie-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    Some(RecordingBuffer::default()),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
                )
                .await;
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent =
                    B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 100);
                let parent_digest = parent.digest();

                let child_round = Round::new(Epoch::zero(), View::new(2));
                let child_context = Ctx {
                    round: child_round,
                    leader: me,
                    parent: (View::new(1), parent_digest),
                };
                let child =
                    B::new::<Sha256>(child_context.clone(), parent_digest, Height::new(3), 200);
                let child_digest = child.digest();
                assert!(marshal.verified(child_round, child).await);

                let verify = wrapper.verify(child_context, child_digest, Arc::from([genesis.digest(), parent_digest])).await;
                wait_until(
                    &context,
                    Duration::from_secs(5),
                    "exact parent commitment fetch",
                    || {
                        resolver.fetches().iter().any(|fetch| {
                            matches!(
                                fetch.key,
                                handler::Key::Block(commitment) if commitment == parent_digest
                            ) && matches!(
                                fetch.subscriber,
                                handler::Annotation::Subscription
                            )
                        })
                    },
                )
                .await;

                assert!(resolver.fetches().iter().all(|fetch| {
                    matches!(fetch.key, handler::Key::Block(commitment) if commitment == parent_digest)
                        && matches!(fetch.subscriber, handler::Annotation::Subscription)
                }), "{kind:?}: malicious child height must not select a different parent");

                assert!(marshal.verified(parent_round, parent).await);
                let verify_result = verify.await.expect("verify result missing");
                if kind == WrapperKind::Inline {
                    assert!(
                        !verify_result,
                        "inline verify should reject non-contiguous ancestry"
                    );
                } else {
                    assert!(
                        verify_result,
                        "deferred verify should optimistically pass pre-checks"
                    );
                    let certify = wrapper.certify(child_round, child_digest, Arc::from([genesis.digest(), parent_digest])).await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should reject non-contiguous ancestry"
                    );
                }
            });
        }
    }

    #[test_traced("WARN")]
    fn test_standard_verify_parent_fetch_invalid_first_retries() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let victim = participants[0].clone();
                let malicious = participants[1].clone();
                let honest = participants[2].clone();

                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(2),
                    [victim.clone(), malicious.clone()],
                )
                .await;
                setup_network_links(
                    &mut oracle,
                    &[victim.clone(), malicious.clone()],
                    LINK,
                )
                .await;

                let victim_setup = StandardHarness::setup_validator(
                    context.child("victim").with_attribute("index", 0),
                    &mut oracle,
                    victim.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let victim_mailbox = victim_setup.mailbox;

                let honest_setup = StandardHarness::setup_validator(
                    context.child("honest").with_attribute("index", 2),
                    &mut oracle,
                    honest.clone(),
                    ConstantProvider::new(schemes[2].clone()),
                )
                .await;
                let mut honest_mailbox = honest_setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: victim.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent =
                    B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 100);
                let parent_digest = parent.digest();

                let parent_proposal = Proposal::new(parent_round, View::zero(), parent_digest);
                let parent_notarization =
                    StandardHarness::make_notarization(parent_proposal, &schemes, QUORUM);
                assert!(honest_mailbox.verified(parent_round, parent.clone()).await);
                StandardHarness::report_notarization(&mut honest_mailbox, parent_notarization)
                    .await;
                assert!(honest_mailbox.get_block(&parent_digest).await.is_some());

                let malicious_backfill = oracle
                    .control(malicious.clone())
                    .register(1, Quota::per_second(NonZeroU32::MAX))
                    .await
                    .unwrap();
                let (malicious_engine, _malicious_mailbox) = commonware_resolver::p2p::Engine::new(
                    context.child("malicious_resolver"),
                    commonware_resolver::p2p::Config {
                        peer_provider: oracle.manager(),
                        blocker: oracle.control(malicious.clone()),
                        consumer: NoopConsumer,
                        producer: StaticProducer::new(
                            handler::Key::Block(parent_digest),
                            Bytes::from_static(b"not a valid block"),
                        ),
                        mailbox_size: NZUsize!(100),
                        me: Some(malicious.clone()),
                        timeout: Duration::from_secs(2),
                        fetch_retry_timeout: Duration::from_millis(100),
                        priority_requests: false,
                        priority_responses: false,
                    },
                );
                malicious_engine.start(malicious_backfill);

                let child_round = Round::new(Epoch::zero(), View::new(2));
                let child_context = Ctx {
                    round: child_round,
                    leader: victim.clone(),
                    parent: (View::new(1), parent_digest),
                };
                let child =
                    B::new::<Sha256>(child_context.clone(), parent_digest, Height::new(2), 200);
                let child_digest = child.digest();
                assert!(victim_mailbox.verified(child_round, child).await);

                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper = Wrapper::new(
                    kind,
                    context.child("wrapper"),
                    mock_app,
                    victim_mailbox.clone(),
                );
                let verify = wrapper.verify(child_context, child_digest, Arc::from([genesis.digest(), parent_digest])).await;
                let verify_or_certify = if kind == WrapperKind::Deferred {
                    let optimistic = verify.await.expect("verify result missing");
                    assert!(optimistic, "deferred verify should optimistically succeed");
                    wrapper.certify(child_round, child_digest, Arc::from([genesis.digest(), parent_digest])).await
                } else {
                    verify
                };

                let start = context.current();
                loop {
                    let blocked = oracle.blocked().await.unwrap();
                    if blocked
                        .iter()
                        .any(|(blocker, blocked)| blocker == &victim && blocked == &malicious)
                    {
                        break;
                    }
                    if context.current().duration_since(start).unwrap_or_default()
                        > Duration::from_secs(5)
                    {
                        panic!("{kind:?}: malicious peer was not blocked");
                    }
                    context.sleep(Duration::from_millis(10)).await;
                }

                oracle
                    .add_link(victim.clone(), honest.clone(), LINK)
                    .await
                    .unwrap();
                oracle
                    .add_link(honest.clone(), victim.clone(), LINK)
                    .await
                    .unwrap();
                let mut manager = oracle.manager();
                manager.track(1, Set::from_iter_dedup([honest.clone()]));

                select! {
                    result = verify_or_certify => {
                        assert!(
                            result.expect("verification result missing"),
                            "{kind:?}: verification should retry against the honest peer and complete"
                        );
                    },
                    _ = context.sleep(Duration::from_secs(10)) => {
                        panic!("{kind:?}: verification did not complete after honest retry");
                    },
                }

                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked
                        .iter()
                        .any(|(blocker, blocked)| blocker == &victim && blocked == &malicious),
                    "{kind:?}: malicious peer should remain blocked"
                );
            });
        }
    }

    async fn verified_chain(
        marshal: &Mailbox<S, Standard<B>>,
        genesis: &B,
        tip: Height,
    ) -> Arc<[D]> {
        let mut commitments = vec![genesis.digest()];
        for height in 1..=tip.get() {
            let parent = *commitments.last().unwrap();
            let round = Round::new(Epoch::zero(), View::new(height));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::new(height - 1), parent),
                },
                parent,
                Height::new(height),
                height * 100,
            );
            commitments.push(block.digest());
            assert!(marshal.verified(round, block).await);
        }
        commitments.into()
    }

    #[test_traced("WARN")]
    fn test_propose_paths() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper = Wrapper::new(
                    kind,
                    context.child("wrapper_under_test"),
                    mock_app,
                    marshal.clone(),
                );

                // Non-boundary propose should drop the response because mock app cannot build.
                let non_boundary_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(1)),
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let proposal_rx = wrapper
                    .propose(non_boundary_context, Arc::from([genesis.digest()]))
                    .await;
                assert!(
                    proposal_rx.await.is_err(),
                    "{kind:?}: proposal should be dropped when application returns no block"
                );
                assert!(
                    context
                        .encode()
                        .contains("wrapper_under_test_build_duration_count 0"),
                    "{kind:?}: failed application builds should not be timed"
                );

                // Boundary propose should re-propose the parent block even if the app cannot build.
                let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
                let selected = verified_chain(&marshal, &genesis, boundary_height).await;
                let boundary_digest = *selected.last().unwrap();

                context.sleep(Duration::from_millis(10)).await;

                let reproposal_round =
                    Round::new(Epoch::zero(), View::new(boundary_height.get() + 1));
                let reproposal_context = Ctx {
                    round: reproposal_round,
                    leader: me,
                    parent: (View::new(boundary_height.get()), boundary_digest),
                };
                let reproposal_rx = wrapper
                    .propose(reproposal_context, Arc::clone(&selected))
                    .await;
                assert_eq!(
                    reproposal_rx.await.expect("reproposal result missing"),
                    boundary_digest,
                    "{kind:?}: epoch-boundary proposal should re-propose parent digest"
                );

                // The re-proposal registers a certification gate whose durability
                // certify awaits before the finalize vote.
                let certify_rx = wrapper
                    .certify(reproposal_round, boundary_digest, Arc::clone(&selected))
                    .await;
                assert!(
                    certify_rx.await.expect("certify result missing"),
                    "{kind:?}: certify must succeed for the re-proposed boundary block"
                );
                assert!(
                    marshal.get_verified(reproposal_round).await.is_some(),
                    "{kind:?}: re-proposed boundary block must be stored at the re-proposal round"
                );
            });
        }
    }

    #[test_traced("WARN")]
    fn test_verify_reproposal_validation() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
                let selected = verified_chain(&marshal, &genesis, boundary_height).await;
                let boundary_digest = *selected.last().unwrap();

                context.sleep(Duration::from_millis(10)).await;

                // Valid re-proposal: boundary block in the same epoch.
                let valid_reproposal_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(boundary_height.get() + 1)),
                    leader: me.clone(),
                    parent: (View::new(boundary_height.get()), boundary_digest),
                };
                assert!(
                    wrapper
                        .verify(
                            valid_reproposal_context,
                            boundary_digest,
                            Arc::clone(&selected)
                        )
                        .await
                        .await
                        .expect("verify result missing"),
                    "{kind:?}: boundary re-proposal should be accepted"
                );

                // Invalid re-proposal: non-boundary block.
                let non_boundary_height = Height::new(10);
                let non_boundary_digest = selected[non_boundary_height.get() as usize];
                let non_boundary_selected: Arc<[D]> =
                    selected[..=non_boundary_height.get() as usize].into();

                // Attempt to re-propose a non-boundary block.
                let invalid_reproposal_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(15)),
                    leader: me.clone(),
                    parent: (View::new(non_boundary_height.get()), non_boundary_digest),
                };
                assert!(
                    !wrapper
                        .verify(
                            invalid_reproposal_context,
                            non_boundary_digest,
                            non_boundary_selected
                        )
                        .await
                        .await
                        .expect("verify result missing"),
                    "{kind:?}: non-boundary re-proposal should be rejected"
                );

                // Invalid re-proposal: cross-epoch context.
                let cross_epoch_context = Ctx {
                    round: Round::new(Epoch::new(1), View::new(boundary_height.get() + 1)),
                    leader: me,
                    parent: (View::new(boundary_height.get()), boundary_digest),
                };
                assert!(
                    !wrapper
                        .verify(cross_epoch_context, boundary_digest, Arc::clone(&selected))
                        .await
                        .await
                        .expect("verify result missing"),
                    "{kind:?}: cross-epoch re-proposal should be rejected"
                );

                if wrapper.kind() == WrapperKind::Deferred {
                    // Deferred-only crash-recovery path: certify without prior verify.
                    let certify_only_round = Round::new(Epoch::zero(), View::new(21));
                    let certify_result = wrapper
                        .certify(certify_only_round, boundary_digest, Arc::clone(&selected))
                        .await
                        .await;
                    assert!(
                        certify_result.expect("certify result missing"),
                        "deferred certify-only path for re-proposal should succeed"
                    );
                }
            });
        }
    }

    #[test_traced("WARN")]
    fn test_verify_rejects_invalid_ancestry() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                // Test case 1: non-contiguous height.
                // Malformed block: parent is genesis but height skips from 0 to 2.
                let malformed_round = Round::new(Epoch::zero(), View::new(2));
                let malformed_context = Ctx {
                    round: malformed_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let malformed_block = B::new::<Sha256>(
                    malformed_context.clone(),
                    genesis.digest(),
                    Height::new(2),
                    200,
                );
                let malformed_digest = malformed_block.digest();

                assert!(
                    marshal
                        .clone()
                        .verified(malformed_round, malformed_block)
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                let malformed_verify = wrapper
                    .verify(
                        malformed_context.clone(),
                        malformed_digest,
                        Arc::from([genesis.digest()]),
                    )
                    .await
                    .await
                    .expect("verify result missing");
                if kind == WrapperKind::Inline {
                    // Inline verifies fully in `verify`.
                    assert!(
                        !malformed_verify,
                        "inline verify should reject non-contiguous ancestry"
                    );
                } else {
                    // Deferred verify is optimistic; final verdict is observed in `certify`.
                    assert!(
                        malformed_verify,
                        "deferred verify should optimistically pass pre-checks"
                    );
                    let certify = wrapper
                        .certify(
                            malformed_round,
                            malformed_digest,
                            Arc::from([genesis.digest()]),
                        )
                        .await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should reject non-contiguous ancestry"
                    );
                }

                // Test case 2: mismatched parent commitment with contiguous heights.
                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent =
                    B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 300);
                let parent_digest = parent.digest();
                assert!(marshal.verified(parent_round, parent).await);

                let mismatch_round = Round::new(Epoch::zero(), View::new(3));
                let mismatched_context = Ctx {
                    round: mismatch_round,
                    leader: me,
                    parent: (View::new(1), parent_digest),
                };
                let mismatched_block = B::new::<Sha256>(
                    mismatched_context.clone(),
                    genesis.digest(),
                    Height::new(2),
                    400,
                );
                let mismatched_digest = mismatched_block.digest();

                assert!(
                    marshal
                        .clone()
                        .verified(mismatch_round, mismatched_block)
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                let mismatch_verify = wrapper
                    .verify(
                        mismatched_context,
                        mismatched_digest,
                        Arc::from([genesis.digest(), parent_digest]),
                    )
                    .await
                    .await
                    .expect("verify result missing");
                if kind == WrapperKind::Inline {
                    // Inline returns the full verification result directly.
                    assert!(
                        !mismatch_verify,
                        "inline verify should reject mismatched parent digest"
                    );
                } else {
                    // Deferred reports optimistic success and relies on `certify`.
                    assert!(
                        mismatch_verify,
                        "deferred verify should optimistically pass pre-checks"
                    );
                    let certify = wrapper
                        .certify(
                            mismatch_round,
                            mismatched_digest,
                            Arc::from([genesis.digest(), parent_digest]),
                        )
                        .await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should reject mismatched parent digest"
                    );
                }
            });
        }
    }

    #[test_traced("WARN")]
    fn test_application_verify_failure() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } =
                    bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
                let mut oracle = setup_network_with_participants(context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> =
                    MockVerifyingApp::with_verify_result(false);
                let mut wrapper = Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                // 1) Set up a valid parent so structural checks can pass.
                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent = B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 100);
                let parent_digest = parent.digest();
                assert!(marshal.verified(parent_round, parent).await);

                // 2) Publish a valid child; only application-level verification should fail.
                let round = Round::new(Epoch::zero(), View::new(2));
                let verify_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::new(1), parent_digest),
                };
                let block = B::new::<Sha256>(verify_context.clone(), parent_digest, Height::new(2), 200);
                let digest = block.digest();
                assert!(marshal.verified(round, block).await);

                context.sleep(Duration::from_millis(10)).await;

                // 3) Compare wrapper behavior:
                //    - Inline fails in `verify`.
                //    - Deferred returns optimistic success and fails in `certify`.
                let verify_result = wrapper
                    .verify(verify_context, digest, Arc::from([genesis.digest(), parent_digest]))
                    .await
                    .await
                    .expect("verify result missing");
                if kind == WrapperKind::Inline {
                    assert!(
                        !verify_result,
                        "inline verify should return application-level failure"
                    );
                } else {
                    assert!(
                        verify_result,
                        "deferred verify should pass pre-checks and schedule deferred verification"
                    );
                    let certify = wrapper.certify(round, digest, Arc::from([genesis.digest(), parent_digest])).await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should propagate deferred application verification failure"
                    );
                }
            });
        }
    }

    // The sync failure surfaces when `verified` awaits the durable-sync handle, which
    // applies the fatal policy: panic rather than resolve a recoverable verdict.
    #[test_traced("WARN")]
    #[should_panic(expected = "failed to sync verified")]
    fn test_mailbox_verified_sync_failure_panics() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;
            let me = participants[0].clone();

            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                application.clone(),
            )
            .await;
            let marshal = setup.mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());
            context.sleep(Duration::from_millis(10)).await;

            // Sync failures are fatal to the local storage state. They must not be
            // converted into a `false` certification/verification verdict.
            context.storage_fault_config().write().sync_rate = Some(probability!(1.0));

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            // `verified` awaits the durable-sync handle internally; a storage sync
            // failure must panic here (fatal), never resolve to a recoverable verdict.
            let _ = marshal.verified(round, block).await;
        });
    }

    // Twin of `test_mailbox_verified_sync_failure_panics` for the certify barrier:
    // `certified` awaits the composed block + notarization sync handle.
    #[test_traced("WARN")]
    #[should_panic(expected = "failed to sync certified")]
    fn test_mailbox_certified_sync_failure_panics() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;
            let me = participants[0].clone();

            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                application.clone(),
            )
            .await;
            let marshal = setup.mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());
            context.sleep(Duration::from_millis(10)).await;

            context.storage_fault_config().write().sync_rate = Some(probability!(1.0));

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            let _ = marshal.certified(round, block).await;
        });
    }

    // A notarization's durable sync is observed by the actor's sync pool rather than
    // a consensus caller. The fatal policy must still apply: a sync failure panics
    // the actor instead of being silently swallowed.
    #[test_traced("WARN")]
    #[should_panic(expected = "failed to sync notarization")]
    fn test_notarization_sync_failure_panics() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;
            let me = participants[0].clone();

            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                application.clone(),
            )
            .await;
            let mut mailbox = setup.mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());
            context.sleep(Duration::from_millis(10)).await;

            context.storage_fault_config().write().sync_rate = Some(probability!(1.0));

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            let notarization = StandardHarness::make_notarization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_notarization(&mut mailbox, notarization).await;

            // The failure surfaces asynchronously when the pool observes the sync.
            context.sleep(Duration::from_secs(5)).await;
        });
    }

    // A certified block that the verified archive already holds is not re-written to
    // the notarized archive; the verified archive's sync handle vouches for it. The
    // block must still be recoverable after an unclean restart.
    #[test_traced("WARN")]
    fn test_certified_covered_by_verified_write_recoverable_after_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;
            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let actor_handle = setup.actor_handle;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            let digest = block.digest();

            // The verified write records the round's digest, so the subsequent
            // certified delivery for the same block skips the notarized-archive
            // copy and leans on the verified archive's durability.
            assert!(marshal.verified(round, block.clone()).await);
            assert!(marshal.certified(round, block).await);

            actor_handle.abort();
            drop(marshal);

            let setup2 = StandardHarness::setup_validator(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            assert!(
                marshal2.get_block(&digest).await.is_some(),
                "certified block covered by a verified write must survive restart"
            );
        });
    }

    async fn deliver_acquisition_test_block(
        resolver: &RecordingResolver,
        fetch: FetchRecord,
        block: &B,
    ) {
        assert_eq!(
            fetch.key,
            handler::Key::Block(StandardHarness::commitment(block))
        );
        let (response, response_rx) = oneshot::channel();
        assert!(
            resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: fetch.key,
                        subscribers: NonEmptyVec::new((fetch.subscriber, tracing::Span::none())),
                    },
                    value: block.encode(),
                    response,
                })
                .accepted()
        );
        assert!(
            response_rx
                .await
                .expect("exact block delivery response missing")
        );
    }

    #[test_traced("WARN")]
    fn test_standard_acquire_coalesces_and_cancels_last_caller_while_idle() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let (mailbox, buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "acquire-shared-idle-cancel",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::default(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.unwrap();
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(mailbox.get_processed_height().await, Some(Height::zero()));
            let commitment = Sha256::hash(&[b"shared-acquisition"]);
            let first = mailbox.acquire(commitment);
            let mut second = mailbox.acquire(commitment);
            assert!(mailbox.get_block(&commitment).await.is_none());
            assert_eq!(buffer.commitment_subscription_count(), 1);
            let is_acquisition = |fetch: &FetchRecord| {
                fetch.key == handler::Key::Block(commitment)
                    && fetch.subscriber == handler::Annotation::Subscription
            };
            assert_eq!(
                resolver
                    .fetches()
                    .iter()
                    .filter(|f| is_acquisition(f))
                    .count(),
                1
            );

            // Only cancellation can wake cleanup after this point: neither mailbox
            // traffic nor a block arrival can hide a missing cancellation wakeup.
            drop(first);
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(second.try_recv(), Err(TryRecvError::Empty)));
            assert_eq!(
                resolver
                    .active_fetches()
                    .iter()
                    .filter(|f| is_acquisition(f))
                    .count(),
                1
            );
            assert!(!buffer.commitment_subscriptions.lock()[0].is_closed());
            drop(second);
            wait_until(
                &context,
                Duration::from_secs(1),
                "idle acquisition cancellation",
                || {
                    !resolver.active_fetches().iter().any(is_acquisition)
                        && buffer.commitment_subscriptions.lock()[0].is_closed()
                },
            )
            .await;
            assert_eq!(
                resolver
                    .fetches()
                    .iter()
                    .filter(|f| is_acquisition(f))
                    .count(),
                1
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_prefetch_direct_transfer_preserves_cancellation_ownership() {
        const PARTITION: &str = "prefetch-direct-transfer";
        deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let (finalizations, blocks) = prunable_finalized_stores(&context, PARTITION).await;
            let mut config = test_config(&context, PARTITION,
                ConstantProvider::new(schemes[0].clone()), NZUsize!(1));
            config.max_repair = NZUsize!(1);
            let (actor, mailbox, _) = Actor::init(
                context.child("actor"), finalizations, blocks, config,
            ).await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let buffer = RecordingBuffer::default();
            let application = Application::<B>::manual_ack();
            let _actor = actor.start(application.clone(), buffer.clone(),
                (resolver_rx, resolver.clone()));
            wait_until(&context, Duration::from_secs(1), "held genesis acknowledgement", || {
                application.pending_ack_heights() == vec![Height::zero()]
            }).await;
            let _ = mailbox.get_processed_height().await;

            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let first = make_raw_block(genesis.digest(), Height::new(1), 100);
            let first_key = handler::Key::Block(first.digest());
            let second = Sha256::hash(&[b"queued behind first prefetch"]);
            let second_key = handler::Key::Block(second);
            let old = mailbox.prefetch(Arc::from([first.digest(), second]), 0..2);
            wait_until(&context, Duration::from_secs(1), "first speculative request", || {
                resolver.active_fetches().iter().any(|fetch| fetch.key == first_key)
            }).await;
            assert!(!resolver.fetches().iter().any(|fetch| fetch.key == second_key));

            let mut direct = mailbox.acquire(first.digest());
            wait_until(&context, Duration::from_secs(1), "direct claim releases speculative capacity", || {
                resolver.active_fetches().iter().any(|fetch| fetch.key == second_key)
            }).await;
            let duplicate = mailbox.prefetch(Arc::from([first.digest()]), 0..1);
            let _ = mailbox.get_processed_height().await;
            assert_eq!(resolver.fetches().iter().filter(|fetch| fetch.key == first_key).count(), 1);

            // Both lease closures are the only actor inputs until the second
            // request is retired; the first request now belongs to its caller.
            drop(old);
            drop(duplicate);
            wait_until(&context, Duration::from_secs(1), "old leases release only speculative request", || {
                !resolver.active_fetches().iter().any(|fetch| fetch.key == second_key)
            }).await;
            assert!(matches!(direct.try_recv(), Err(TryRecvError::Empty)));
            assert!(!buffer.commitment_subscriptions.lock()[0].is_closed());
            let fetch = resolver.active_fetches().into_iter()
                .find(|fetch| fetch.key == first_key).expect("direct request canceled by old lease");
            assert_eq!(fetch.subscriber, handler::Annotation::Subscription);
            deliver_acquisition_test_block(&resolver, fetch, &first).await;
            select! {
                result = direct => assert_eq!(result.unwrap().digest(), first.digest()),
                _ = context.sleep(Duration::from_secs(1)) => panic!("direct caller did not receive its block"),
            }

            let inverse = Sha256::hash(&[b"direct before speculative lease"]);
            let inverse_key = handler::Key::Block(inverse);
            let direct = mailbox.acquire(inverse);
            wait_until(&context, Duration::from_secs(1), "inverse direct request", || {
                resolver.active_fetches().iter().any(|fetch| fetch.key == inverse_key)
            }).await;
            let old = mailbox.prefetch(Arc::from([inverse]), 0..1);
            let _ = mailbox.get_processed_height().await;
            assert_eq!(resolver.fetches().iter().filter(|fetch| fetch.key == inverse_key).count(), 1);

            // A best-effort lease cannot extend a direct caller's lifetime.
            // No mailbox traffic or body delivery drives cancellation here.
            drop(direct);
            wait_until(&context, Duration::from_secs(1), "last direct caller cancels despite lease", || {
                !resolver.active_fetches().iter().any(|fetch| fetch.key == inverse_key)
                    && buffer.commitment_subscriptions.lock().iter().all(|sender| sender.is_closed())
            }).await;

            let mut renewed = mailbox.prefetch(Arc::from([inverse]), 0..1);
            wait_until(&context, Duration::from_secs(1), "renewed speculative request", || {
                resolver.active_fetches().iter().any(|fetch| fetch.key == inverse_key)
            }).await;
            assert_eq!(resolver.fetches().iter().filter(|fetch| fetch.key == inverse_key).count(), 2);
            drop(old);
            context.sleep(Duration::from_millis(100)).await;
            assert!(resolver.active_fetches().iter().any(|fetch| fetch.key == inverse_key));
            assert!(matches!(renewed.try_recv(), Err(TryRecvError::Empty)));
            drop(renewed);
            wait_until(&context, Duration::from_secs(1), "renewed lease owns cancellation", || {
                !resolver.active_fetches().iter().any(|fetch| fetch.key == inverse_key)
            }).await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_acquire_cancellation_preserves_shared_finality_request() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let application = Application::<B>::manual_ack();
            let (mut mailbox, buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "acquire-cancel-preserves-finality",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.clone().into()),
            )
            .await;
            let buffer = buffer.unwrap();
            assert_eq!(application.acknowledged().await, Height::zero());
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            let commitment = StandardHarness::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(1));
            let acquisition = mailbox.acquire(commitment);
            StandardHarness::report_finalization(
                &mut mailbox,
                StandardHarness::make_finalization(
                    Proposal::new(round, View::zero(), commitment),
                    &schemes,
                    QUORUM,
                ),
            )
            .await;
            let is_finality = |fetch: &FetchRecord| {
                fetch.key == handler::Key::Block(commitment)
                    && fetch.subscriber == handler::Annotation::Round(round)
            };
            let is_acquisition = |fetch: &FetchRecord| {
                fetch.key == handler::Key::Block(commitment)
                    && fetch.subscriber == handler::Annotation::Subscription
            };
            wait_until(
                &context,
                Duration::from_secs(1),
                "shared acquisition and finality",
                || {
                    let active = resolver.active_fetches();
                    active.iter().any(is_finality) && active.iter().any(is_acquisition)
                },
            )
            .await;
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(buffer.commitment_subscription_count(), 1);
            assert!(!buffer.commitment_subscriptions.lock()[0].is_closed());

            drop(acquisition);
            wait_until(
                &context,
                Duration::from_secs(1),
                "independent finality retention",
                || {
                    let active = resolver.active_fetches();
                    active.iter().any(is_finality)
                        && !active.iter().any(is_acquisition)
                        && buffer.commitment_subscriptions.lock()[0].is_closed()
                },
            )
            .await;
            let fetch = resolver
                .active_fetches()
                .into_iter()
                .find(is_finality)
                .unwrap();
            deliver_acquisition_test_block(&resolver, fetch, &block).await;
            wait_until(
                &context,
                Duration::from_secs(1),
                "finalized body after acquisition cancellation",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;
            assert_eq!(application.blocks()[&Height::new(1)].digest(), commitment);
            assert_eq!(
                mailbox
                    .get_finalization(Height::new(1))
                    .await
                    .unwrap()
                    .proposal
                    .payload,
                commitment
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_finalized_waiter_survives_sibling_cancel_and_gap_repair_with_held_ack() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let application = Application::<B>::manual_ack();
            let (mut mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "finalized-waiter-gap-held-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.clone().into()),
            ).await;
            assert_eq!(application.acknowledged().await, Height::zero());
            let first_round = Round::new(Epoch::zero(), View::new(1));
            let first = make_raw_block(genesis.digest(), Height::new(1), 100);
            assert!(mailbox.verified(first_round, first.clone()).await);
            StandardHarness::report_finalization(&mut mailbox,
                StandardHarness::make_finalization(
                    Proposal::new(first_round, View::zero(), StandardHarness::commitment(&first)),
                    &schemes, QUORUM,
                ),
            ).await;
            wait_until(&context, Duration::from_secs(1), "held height one ack", || {
                application.pending_ack_heights() == vec![Height::new(1)]
            }).await;
            let missing = make_raw_block(first.digest(), Height::new(2), 200);
            let upper = make_raw_block(missing.digest(), Height::new(3), 300);
            let fetches_before = resolver.fetches().len();
            let canceled = mailbox.finalized(Height::new(2));
            let mut survivor = mailbox.finalized(Height::new(2));
            assert!(mailbox.get_block(Height::new(2)).await.is_none());
            assert_eq!(resolver.fetches().len(), fetches_before);
            drop(canceled);
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(survivor.try_recv(), Err(TryRecvError::Empty)));

            let upper_round = Round::new(Epoch::zero(), View::new(3));
            assert!(mailbox.verified(upper_round, upper.clone()).await);
            StandardHarness::report_finalization(&mut mailbox,
                StandardHarness::make_finalization(
                    Proposal::new(upper_round, View::new(2), StandardHarness::commitment(&upper)),
                    &schemes, QUORUM,
                ),
            ).await;
            let is_repair = |fetch: &FetchRecord| {
                fetch.key == handler::Key::Block(StandardHarness::commitment(&missing))
                    && fetch.subscriber == handler::Annotation::Height(Height::new(2))
            };
            wait_until(&context, Duration::from_secs(1), "missing parent repair", || {
                resolver.active_fetches().iter().any(is_repair)
            }).await;
            assert!(matches!(survivor.try_recv(), Err(TryRecvError::Empty)));
            assert!(mailbox.get_block(Height::new(2)).await.is_none());
            assert_eq!(application.pending_ack_heights(), vec![Height::new(1)]);
            let fetch = resolver.active_fetches().into_iter().find(is_repair).unwrap();
            deliver_acquisition_test_block(&resolver, fetch, &missing).await;
            select! {
                result = survivor => {
                    assert_eq!(result.expect("finalized sibling canceled survivor").digest(), missing.digest());
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("gap repair did not wake preregistered finalized-height waiter");
                },
            }
            assert_eq!(mailbox.get_processed_height().await, Some(Height::zero()));
            assert_eq!(application.pending_ack_heights(), vec![Height::new(1)]);
            assert!(!application.blocks().contains_key(&Height::new(2)));
            assert_eq!(mailbox.get_block(Height::new(2)).await.unwrap().digest(), missing.digest());
        });
    }

    /// Recorded `send` call on the [`RecordingBuffer`].
    type BufferSend = (Round, Arc<B>, Recipients<PublicKey>);

    /// A buffer that records each `send` invocation, keeps subscriptions open,
    /// and optionally serves locally inserted blocks.
    #[derive(Clone, Default)]
    struct RecordingBuffer {
        blocks: Arc<Mutex<Vec<B>>>,
        last_handed: Arc<Mutex<Option<Weak<B>>>>,
        evict_on_next_hit: Arc<Mutex<bool>>,
        commitment_subscriptions: Arc<Mutex<Vec<oneshot::Sender<Arc<B>>>>>,
        sends: Arc<Mutex<Vec<BufferSend>>>,
    }

    impl RecordingBuffer {
        fn insert(&self, block: B) {
            self.blocks.lock().push(block);
        }

        fn insert_transient(&self, block: B) {
            self.insert(block);
            *self.evict_on_next_hit.lock() = true;
        }

        fn contains(&self, digest: D) -> bool {
            self.blocks
                .lock()
                .iter()
                .any(|block| block.digest() == digest)
        }

        fn find(&self, digest: D) -> Option<Arc<B>> {
            let mut blocks = self.blocks.lock();
            let index = blocks.iter().position(|block| block.digest() == digest)?;
            let block = if std::mem::take(&mut *self.evict_on_next_hit.lock()) {
                blocks.remove(index)
            } else {
                blocks[index].clone()
            };
            let block = Arc::new(block);
            *self.last_handed.lock() = Some(Arc::downgrade(&block));
            Some(block)
        }

        /// Weak reference to the last block `find` handed to marshal.
        fn last_handed(&self) -> Option<Weak<B>> {
            self.last_handed.lock().clone()
        }

        fn sends(&self) -> Vec<BufferSend> {
            self.sends.lock().clone()
        }

        fn commitment_subscription_count(&self) -> usize {
            self.commitment_subscriptions.lock().len()
        }
    }

    impl crate::marshal::core::Buffer<Standard<B>> for RecordingBuffer {
        type PublicKey = PublicKey;

        async fn find_by_digest(&self, digest: D) -> Option<Arc<B>> {
            self.find(digest)
        }

        async fn find_by_commitment(&self, commitment: D) -> Option<Arc<B>> {
            self.find(commitment)
        }

        fn subscribe_by_commitment(&self, _commitment: D) -> Option<oneshot::Receiver<Arc<B>>> {
            let (sender, receiver) = oneshot::channel();
            self.commitment_subscriptions.lock().push(sender);
            Some(receiver)
        }

        fn retire(&self, _update: crate::marshal::core::Retirement<D>) {}

        fn send(&self, round: Round, block: Arc<B>, recipients: Recipients<PublicKey>) {
            self.sends.lock().push((round, block, recipients));
        }
    }

    /// Recorded `fetch` call on the [`RecordingResolver`].
    type FetchRecord = Fetch<handler::Key<D>, handler::Annotation>;

    /// A resolver that records each fetch invocation; other methods are no-ops.
    ///
    /// `_keepalive` optionally retains a resolver-message sender so the
    /// actor's corresponding receiver stays alive when nothing else owns it.
    #[derive(Clone, Default)]
    struct RecordingResolver {
        fetches: Arc<Mutex<Vec<FetchRecord>>>,
        active_fetches: Arc<Mutex<Vec<FetchRecord>>>,
        retains: Arc<Mutex<usize>>,
        auto_delivery: Arc<Mutex<Option<Bytes>>>,
        delivery_responses: Arc<Mutex<Vec<oneshot::Receiver<bool>>>>,
        sender: Option<mailbox::Sender<handler::Message<D>>>,
    }

    impl RecordingResolver {
        fn holding(metrics: impl Metrics) -> (handler::Receiver<D>, Self) {
            let (sender, receiver) = mailbox::new(metrics, NZUsize!(100));
            (
                handler::Receiver::new(receiver),
                Self {
                    fetches: Arc::new(Mutex::new(Vec::new())),
                    active_fetches: Arc::new(Mutex::new(Vec::new())),
                    retains: Arc::new(Mutex::new(0)),
                    auto_delivery: Arc::new(Mutex::new(None)),
                    delivery_responses: Arc::new(Mutex::new(Vec::new())),
                    sender: Some(sender),
                },
            )
        }

        fn record_fetch(&self, fetch: FetchRecord) {
            self.fetches.lock().push(fetch.clone());
            self.active_fetches.lock().push(fetch.clone());
            let Some(value) = self.auto_delivery.lock().take() else {
                return;
            };
            let Some(sender) = &self.sender else {
                return;
            };
            let (response, response_rx) = oneshot::channel();
            self.delivery_responses.lock().push(response_rx);
            let _ = sender.enqueue(handler::Message::Deliver {
                delivery: Delivery {
                    key: fetch.key,
                    subscribers: NonEmptyVec::new((fetch.subscriber, tracing::Span::none())),
                },
                value,
                response,
            });
        }

        fn respond_to_next_fetch(&self, value: Bytes) {
            let replaced = self.auto_delivery.lock().replace(value);
            assert!(
                replaced.is_none(),
                "recording resolver already has an automatic delivery"
            );
        }

        async fn wait_for_delivery_response(&self) -> bool {
            let response = self
                .delivery_responses
                .lock()
                .pop()
                .expect("delivery response missing");
            response.await.expect("delivery response sender dropped")
        }

        fn fetches(&self) -> Vec<FetchRecord> {
            self.fetches.lock().clone()
        }

        fn active_fetches(&self) -> Vec<FetchRecord> {
            self.active_fetches.lock().clone()
        }

        fn retain_count(&self) -> usize {
            *self.retains.lock()
        }

        fn enqueue(&self, message: handler::Message<D>) -> Feedback {
            self.sender
                .as_ref()
                .expect("recording resolver sender missing")
                .enqueue(message)
        }
    }

    impl Resolver for RecordingResolver {
        type Key = handler::Key<D>;
        type Subscriber = handler::Annotation;

        fn fetch<F>(&mut self, fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            self.record_fetch(fetch.into());
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            for fetch in fetches {
                self.record_fetch(fetch.into());
            }
            Feedback::Ok
        }

        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            self.active_fetches
                .lock()
                .retain(|fetch| predicate(&fetch.key, &fetch.subscriber));
            *self.retains.lock() += 1;
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct NoopConsumer;

    impl Consumer for NoopConsumer {
        type Key = handler::Key<D>;
        type Value = Bytes;
        type Subscriber = handler::Annotation;
        type Outcome = bool;

        fn deliver(
            &mut self,
            _delivery: Delivery<Self::Key, Self::Subscriber>,
            _value: Self::Value,
        ) -> oneshot::Receiver<bool> {
            let (sender, receiver) = oneshot::channel();
            sender.send_lossy(false);
            receiver
        }
    }

    #[derive(Clone)]
    struct StaticProducer {
        key: handler::Key<D>,
        value: Bytes,
    }

    impl StaticProducer {
        fn new(key: handler::Key<D>, value: Bytes) -> Self {
            Self { key, value }
        }
    }

    impl commonware_resolver::p2p::Producer for StaticProducer {
        type Key = handler::Key<D>;

        fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
            let (sender, receiver) = oneshot::channel();
            if key == self.key {
                sender.send_lossy(self.value.clone());
            }
            receiver
        }
    }

    /// Poll `cond` on a 10ms tick until it returns true, panicking on timeout.
    async fn wait_until<F: FnMut() -> bool>(
        context: &deterministic::Context,
        deadline: Duration,
        label: &str,
        mut cond: F,
    ) {
        let start = context.current();
        while !cond() {
            if context.current().duration_since(start).unwrap_or_default() > deadline {
                panic!("{label} did not hold within {deadline:?}");
            }
            context.sleep(Duration::from_millis(10)).await;
        }
    }

    /// A reporter that signals when application delivery starts and holds the
    /// block acknowledgement open.
    #[derive(Clone)]
    struct HoldingBlockReporter {
        started: Arc<Mutex<Option<oneshot::Sender<Height>>>>,
        pending: Arc<Mutex<Vec<Exact>>>,
        min_signal_height: Height,
    }

    impl HoldingBlockReporter {
        fn new() -> (Self, oneshot::Receiver<Height>) {
            Self::new_from(Height::zero())
        }

        fn new_after(height: Height) -> (Self, oneshot::Receiver<Height>) {
            Self::new_from(height.next())
        }

        fn new_from(min_signal_height: Height) -> (Self, oneshot::Receiver<Height>) {
            let (started_tx, started_rx) = oneshot::channel();
            (
                Self {
                    started: Arc::new(Mutex::new(Some(started_tx))),
                    pending: Arc::new(Mutex::new(Vec::new())),
                    min_signal_height,
                },
                started_rx,
            )
        }
    }

    impl Reporter for HoldingBlockReporter {
        type Activity = Update<B>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            match activity {
                Update::Block(block, ack) => {
                    if block.height() < self.min_signal_height {
                        ack.acknowledge();
                        return Feedback::Ok;
                    }
                    if let Some(started) = self.started.lock().take() {
                        started.send_lossy(block.height());
                    }
                    self.pending.lock().push(ack);
                }
                Update::Tip(_, _, _) => {}
            }
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct ApplicationReporter {
        updates: mpsc::UnboundedSender<Update<B>>,
    }

    impl Reporter for ApplicationReporter {
        type Activity = Update<B>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if self.updates.send(activity).is_ok() {
                Feedback::Ok
            } else {
                Feedback::Closed
            }
        }
    }

    async fn start_standard_actor<R, Buf, P>(
        context: deterministic::Context,
        partition_prefix: &str,
        provider: P,
        application: R,
        buffer: Option<Buf>,
        start: Start<S, D, Arc<B>>,
    ) -> (
        Mailbox<S, Standard<B>>,
        Option<Buf>,
        RecordingResolver,
        commonware_runtime::Handle<()>,
    )
    where
        R: Reporter<Activity = Update<B>>,
        P: Provider<Scope = Epoch, Scheme = S>,
        Buf: crate::marshal::core::Buffer<Standard<B>, PublicKey = PublicKey> + Clone,
    {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start,
            mailbox_size: NZUsize!(100),
            view_retention: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            block_codec_config: (),
            partition_prefix: partition_prefix.to_string(),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-key"
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
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
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalized_blocks-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalized_blocks-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-finalized_blocks-freezer-key"),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{partition_prefix}-finalized_blocks-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalized_blocks-ordinal"),
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
        let (resolver_rx, resolver) = RecordingResolver::holding(context.child("mailbox"));
        let actor_handle = if let Some(buffer) = buffer.clone() {
            actor.start(application, buffer, (resolver_rx, resolver.clone()))
        } else {
            actor.start_unbuffered(application, (resolver_rx, resolver.clone()))
        };
        (mailbox, buffer, resolver, actor_handle)
    }

    #[test_traced("WARN")]
    fn test_standard_application_shutdown_redelivers_pending_ack_after_restart() {
        const PARTITION_PREFIX: &str = "application-shutdown-with-pending-ack";
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        let first_run = |mut context: deterministic::Context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let provider = ConstantProvider::new(schemes[0].clone());
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);

            // Model an application that handles genesis normally, then owns the first
            // non-genesis acknowledgement while its work remains in flight.
            let (updates, mut application_mailbox) = mpsc::unbounded_channel::<Update<B>>();
            let (delivered, delivery) = oneshot::channel();
            let application_handle = context.child("application").spawn(move |_| async move {
                let mut delivered = Some(delivered);
                while let Some(update) = application_mailbox.recv().await {
                    let Update::Block(block, acknowledgement) = update else {
                        continue;
                    };
                    if block.height() == Height::zero() {
                        acknowledgement.acknowledge();
                        continue;
                    }

                    delivered
                        .take()
                        .expect("normal block should only be delivered once")
                        .send_lossy(block.height());

                    // Keep the acknowledgement in the suspended future so aborting this task
                    // exercises application-owned cancellation during shutdown.
                    std::future::pending::<()>().await;
                    acknowledgement.acknowledge();
                }
            });

            // Retain marshal's mailbox, buffer, and resolver until the exit assertion so no other
            // input closing can account for the actor's exit.
            let (mut mailbox, _buffer, _resolver, marshal_handle) = start_standard_actor(
                context.child("validator"),
                PARTITION_PREFIX,
                provider.clone(),
                ApplicationReporter { updates },
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.clone().into()),
            )
            .await;

            // Deliver a normal finalized block and wait until the application owns its
            // acknowledgement before beginning shutdown.
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_digest = block.digest();
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(round, block).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            assert_eq!(
                delivery.await.expect("normal block should be delivered"),
                Height::new(1)
            );

            // Drop the application first; the pending acknowledgement must stop marshal cleanly.
            application_handle.abort();
            let _ = application_handle.await;
            marshal_handle
                .await
                .expect("application shutdown should stop marshal cleanly");

            (provider, genesis, block_digest)
        };

        // Shut down with a pending acknowledgement, then recover the runtime.
        let ((provider, genesis, block_digest), checkpoint) = runner.start_and_recover(first_run);
        deterministic::Runner::from(checkpoint).start(move |context| async move {
            // The canceled acknowledgement must leave the processed floor behind the block so the
            // recovered application receives the same finalized block again.
            let restart_application = Application::<B>::manual_ack();
            let (_mailbox, _buffer, _resolver, _marshal_handle) = start_standard_actor(
                context.child("validator").with_attribute("restart", 0),
                PARTITION_PREFIX,
                provider,
                restart_application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.into()),
            )
            .await;
            select! {
                height = restart_application.acknowledged() => {
                    assert_eq!(height, Height::new(1));
                    assert_eq!(
                        restart_application
                            .blocks()
                            .get(&height)
                            .expect("redelivered block must be recorded")
                            .digest(),
                        block_digest,
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("unacknowledged block was not redelivered after restart");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_actor_starts_without_buffer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let (mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "standard-no-buffer",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                None::<RecordingBuffer>,
                Start::Genesis(genesis.clone().into()),
            )
            .await;

            let stored_genesis = mailbox
                .get_block(Identifier::Height(Height::zero()))
                .await
                .expect("genesis should be available without a buffer");
            assert_eq!(stored_genesis.digest(), genesis.digest());

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            let digest = block.digest();
            assert!(mailbox.verified(round, block).await);
            mailbox.forward(
                round,
                digest,
                Recipients::Some(vec![participants[1].clone()]),
            );
            let verified = mailbox
                .get_verified(round)
                .await
                .expect("verified block should remain available without a buffer");
            assert_eq!(verified.digest(), digest);
        });
    }

    #[test_traced("WARN")]
    #[should_panic(expected = "floor finalization must verify")]
    fn test_standard_start_floor_rejects_invalid_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let Fixture {
                schemes: wrong_schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (application, _started_rx) = HoldingBlockReporter::new();
            let (_mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "start-floor-invalid",
                ConstantProvider::new(wrong_schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Floor(floor_finalization),
            )
            .await;
            context.sleep(Duration::from_secs(1)).await;
        });
    }

    #[test_traced("WARN")]
    #[should_panic(expected = "floor finalization must verify")]
    fn test_standard_set_floor_rejects_invalid_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let Fixture {
                schemes: wrong_schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-invalid",
                ConstantProvider::new(wrong_schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            mailbox.set_floor(floor_finalization);
            context.sleep(Duration::from_secs(1)).await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_start_floor_fetches_async_and_serves_requests() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (application, mut started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "start-floor-async",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Floor(floor_finalization),
            )
            .await;

            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            let served = make_raw_block(Sha256::hash(&[b"served-parent"]), Height::new(1), 100);
            let served_round = Round::new(Epoch::zero(), View::new(1));
            assert!(mailbox.verified(served_round, served.clone()).await);
            let (response, response_rx) = oneshot::channel();
            resolver.enqueue(handler::Message::Produce {
                key: handler::Key::Block(StandardHarness::commitment(&served)),
                response,
            });
            assert_eq!(response_rx.await.unwrap(), served.encode());

            let next = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_round = Round::new(Epoch::zero(), View::new(6));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(next_round, View::new(5), StandardHarness::commitment(&next)),
                &schemes,
                QUORUM,
            );
            let mut mailbox_for_report = mailbox.clone();
            StandardHarness::report_finalization(&mut mailbox_for_report, next_finalization).await;
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(started_rx.try_recv(), Err(TryRecvError::Empty)));

            assert!(mailbox.verified(floor_round, floor_block).await);
            assert_eq!(started_rx.await.unwrap(), Height::new(5));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_start_floor_applies_local_anchor_without_fetch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block =
                make_raw_block(Sha256::hash(&[b"local-floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let buffer = RecordingBuffer::default();
            buffer.insert(floor_block.clone());

            let (application, started_rx) = HoldingBlockReporter::new();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "start-floor-local-anchor",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(buffer),
                Start::Floor(floor_finalization),
            )
            .await;
            let mut mailbox = mailbox;

            wait_until(
                &context,
                Duration::from_secs(5),
                "local floor anchor application",
                || resolver.retain_count() >= 2,
            )
            .await;
            assert!(
                resolver.fetches().is_empty(),
                "local startup floor anchor must not be fetched"
            );
            assert_eq!(
                mailbox.get_block(Height::new(5)).await.unwrap().digest(),
                floor_block.digest()
            );

            let next = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_round = Round::new(Epoch::zero(), View::new(6));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(next_round, View::new(5), StandardHarness::commitment(&next)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, next_finalization).await;
            assert_eq!(started_rx.await.unwrap(), Height::new(5));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_start_floor_height_one_without_metadata_delivers_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "start-floor-height-one-without-metadata";

            let floor_round = Round::new(Epoch::zero(), View::new(1));
            let floor_block =
                make_raw_block(Sha256::hash(&[b"genesis-parent"]), Height::new(1), 100);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::zero(),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let blocks = [floor_block.clone()];
            let finalizations = [(Height::new(1), floor_finalization.clone())];
            seed_inconsistent_restart_state(
                context.child("seed_restart_state"),
                partition_prefix,
                &blocks,
                &finalizations,
            )
            .await;

            let (application, started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let (_mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Floor(floor_finalization),
            )
            .await;

            select! {
                height = started_rx => {
                    assert_eq!(
                        height.expect("floor anchor delivery signal missing"),
                        Height::new(1),
                        "height-one startup floor must be delivered without prior metadata"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("height-one startup floor was not delivered");
                },
            }
            assert!(
                resolver.fetches().is_empty(),
                "stored startup floor anchor must not be fetched"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_holds_dispatch_until_anchor_arrives() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (application, mut started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-holds-dispatch",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;

            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            let next = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_round = Round::new(Epoch::zero(), View::new(6));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(next_round, View::new(5), StandardHarness::commitment(&next)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, next_finalization).await;
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(started_rx.try_recv(), Err(TryRecvError::Empty)));

            let floor_fetch = resolver
                .fetches()
                .into_iter()
                .find(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&floor_block)
                    )
                })
                .expect("floor fetch missing");
            let (response, response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: floor_fetch.key,
                            subscribers: NonEmptyVec::new((
                                floor_fetch.subscriber,
                                tracing::Span::none()
                            )),
                        },
                        value: floor_block.encode(),
                        response,
                    })
                    .accepted()
            );
            assert!(
                response_rx.await.expect("delivery response missing"),
                "floor block delivery should validate"
            );

            assert_eq!(started_rx.await.unwrap(), Height::new(5));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_floor_jump_ignores_stale_application_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "floor-jump-ignores-stale-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(&[b"block1-parent"]), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            // The anchor is not local yet, so SetFloor must install a pending
            // floor before the old height 1 ack can be released.
            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            assert!(mailbox.verified(floor_round, floor_block.clone()).await);
            assert_eq!(
                mailbox
                    .get_block(Height::new(5))
                    .await
                    .expect("floor block missing")
                    .digest(),
                floor_block.digest()
            );

            // The unacknowledged anchor owns the dispatch floor at height 4.
            assert_eq!(mailbox.get_processed_height().await, Some(Height::new(4)));
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            context.sleep(Duration::from_millis(100)).await;

            assert_eq!(
                mailbox.get_processed_height().await,
                Some(Height::new(4)),
                "stale pre-floor ack must not lower the processed height floor"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_local_floor_jump_ignores_stale_application_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let buffer = RecordingBuffer::default();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "local-floor-jump-ignores-stale-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(buffer.clone()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(&[b"block1-parent"]), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block =
                make_raw_block(Sha256::hash(&[b"local-floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            // The anchor is already local, so this covers the immediate
            // install path where no pending-anchor fetch is started.
            buffer.insert(floor_block.clone());
            mailbox.set_floor(floor_finalization);
            assert_eq!(
                mailbox
                    .get_block(Height::new(5))
                    .await
                    .expect("floor block missing")
                    .digest(),
                floor_block.digest()
            );
            assert!(
                resolver.fetches().is_empty(),
                "local floor anchor must not be fetched"
            );

            // The unacknowledged anchor owns the dispatch floor at height 4.
            assert_eq!(mailbox.get_processed_height().await, Some(Height::new(4)));
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            context.sleep(Duration::from_millis(100)).await;

            assert_eq!(
                mailbox.get_processed_height().await,
                Some(Height::new(4)),
                "stale pre-floor ack must not lower a locally installed floor"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_repairs_gap_after_anchor_arrives() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-repairs-gap-after-anchor",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;

            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            let missing = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let later = make_raw_block(missing.digest(), Height::new(7), 700);
            let later_round = Round::new(Epoch::zero(), View::new(7));
            assert!(mailbox.verified(later_round, later.clone()).await);
            let later_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    later_round,
                    View::new(6),
                    StandardHarness::commitment(&later),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, later_finalization).await;
            assert!(mailbox.get_finalization(Height::new(7)).await.is_some());
            assert!(
                resolver.fetches().iter().all(|fetch| {
                    !matches!(
                        (&fetch.key, &fetch.subscriber),
                        (
                            handler::Key::Block(commitment),
                            handler::Annotation::Height(height)
                        ) if *commitment == missing.digest() && *height == Height::new(6)
                    )
                }),
                "gap repair must wait until the floor anchor is resolved"
            );

            assert!(mailbox.verified(floor_round, floor_block).await);
            wait_until(
                &context,
                Duration::from_secs(5),
                "missing post-floor parent fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            (&fetch.key, &fetch.subscriber),
                            (
                                handler::Key::Block(commitment),
                                handler::Annotation::Height(height)
                            ) if *commitment == missing.digest() && *height == Height::new(6)
                        )
                    })
                },
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_local_floor_anchor_resumes_gap_repair() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            let next_round = Round::new(Epoch::zero(), View::new(6));
            let next_block = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    next_round,
                    View::new(5),
                    StandardHarness::commitment(&next_block),
                ),
                &schemes,
                QUORUM,
            );

            let partition_prefix = "local-floor-anchor-resumes-gap-repair";
            seed_inconsistent_restart_state(
                context.child("storage"),
                partition_prefix,
                &[],
                &[(Height::new(6), next_finalization)],
            )
            .await;

            let (application, _started_rx) = HoldingBlockReporter::new();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Floor(floor_finalization),
            )
            .await;

            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            assert!(mailbox.verified(floor_round, floor_block).await);
            wait_until(
                &context,
                Duration::from_secs(5),
                "gap repair after local floor anchor",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&next_block)
                        )
                    })
                },
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_newer_pending_floor_supersedes_older_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let (application, mut started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-supersedes-pending",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;

            let old_floor_round = Round::new(Epoch::zero(), View::new(5));
            let old_floor_block =
                make_raw_block(Sha256::hash(&[b"old-floor-parent"]), Height::new(5), 500);
            let old_floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    old_floor_round,
                    View::new(4),
                    StandardHarness::commitment(&old_floor_block),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(old_floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "old floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&old_floor_block)
                        )
                    })
                },
            )
            .await;

            let new_floor_round = Round::new(Epoch::zero(), View::new(7));
            let new_floor_block =
                make_raw_block(Sha256::hash(&[b"new-floor-parent"]), Height::new(7), 700);
            let new_floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    new_floor_round,
                    View::new(6),
                    StandardHarness::commitment(&new_floor_block),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(new_floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "new floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&new_floor_block)
                        )
                    })
                },
            )
            .await;

            let old_next_round = Round::new(Epoch::zero(), View::new(6));
            let old_next = make_raw_block(old_floor_block.digest(), Height::new(6), 600);
            assert!(mailbox.verified(old_next_round, old_next.clone()).await);
            let old_next_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    old_next_round,
                    View::new(5),
                    StandardHarness::commitment(&old_next),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, old_next_finalization).await;
            assert!(mailbox.get_finalization(Height::new(6)).await.is_some());

            let new_next_round = Round::new(Epoch::zero(), View::new(8));
            let new_next = make_raw_block(new_floor_block.digest(), Height::new(8), 800);
            assert!(mailbox.verified(new_next_round, new_next.clone()).await);
            let new_next_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    new_next_round,
                    View::new(7),
                    StandardHarness::commitment(&new_next),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, new_next_finalization).await;
            assert!(mailbox.get_finalization(Height::new(8)).await.is_some());

            let old_floor_fetch = resolver
                .fetches()
                .into_iter()
                .find(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&old_floor_block)
                    )
                })
                .expect("old floor fetch missing");
            let (response, response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: old_floor_fetch.key,
                            subscribers: NonEmptyVec::new((
                                old_floor_fetch.subscriber,
                                tracing::Span::none()
                            )),
                        },
                        value: old_floor_block.encode(),
                        response,
                    })
                    .accepted()
            );
            assert!(
                response_rx
                    .await
                    .expect("old floor delivery response missing"),
                "old floor block delivery should validate"
            );
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(started_rx.try_recv(), Err(TryRecvError::Empty)));

            let new_floor_fetch = resolver
                .fetches()
                .into_iter()
                .find(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&new_floor_block)
                    )
                })
                .expect("new floor fetch missing");
            let (response, response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: new_floor_fetch.key,
                            subscribers: NonEmptyVec::new((
                                new_floor_fetch.subscriber,
                                tracing::Span::none()
                            )),
                        },
                        value: new_floor_block.encode(),
                        response,
                    })
                    .accepted()
            );
            assert!(
                response_rx
                    .await
                    .expect("new floor delivery response missing"),
                "new floor block delivery should validate"
            );
            assert_eq!(started_rx.await.unwrap(), Height::new(7));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_applies_buffered_anchor_on_notarization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_proposal = Proposal::new(
                floor_round,
                View::new(4),
                StandardHarness::commitment(&floor_block),
            );
            let floor_finalization =
                StandardHarness::make_finalization(floor_proposal.clone(), &schemes, QUORUM);
            let (application, mut started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let buffer = RecordingBuffer::default();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-buffered-anchor-notarization",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(buffer.clone()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;

            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            let next = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_round = Round::new(Epoch::zero(), View::new(6));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(next_round, View::new(5), StandardHarness::commitment(&next)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, next_finalization).await;
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(started_rx.try_recv(), Err(TryRecvError::Empty)));

            buffer.insert(floor_block);
            let floor_notarization =
                StandardHarness::make_notarization(floor_proposal, &schemes, QUORUM);
            StandardHarness::report_notarization(&mut mailbox, floor_notarization).await;
            assert_eq!(started_rx.await.unwrap(), Height::new(5));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_pending_floor_drops_in_flight_ack_before_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "pending-floor-drops-in-flight-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(&[b"block1-parent"]), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"stale-floor"]), Height::zero(), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            // Keep the anchor missing so SetFloor has to wait on a pending
            // floor fetch while the height 1 application ack is in flight.
            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "stale floor fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            // Finalize the successor while the pending floor is waiting. It
            // should not dispatch until the anchor is installed.
            let block2_round = Round::new(Epoch::zero(), View::new(2));
            let block2 = make_raw_block(block1.digest(), Height::new(2), 200);
            let block2_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block2_round,
                    View::new(1),
                    StandardHarness::commitment(&block2),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block2_round, block2).await);
            StandardHarness::report_finalization(&mut mailbox, block2_finalization).await;
            assert!(mailbox.get_finalization(Height::new(2)).await.is_some());
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(application.pending_ack_heights(), vec![Height::new(1)]);

            // This ack is released while the anchor is still unknown. The
            // pending floor should have removed it from the active waiters.
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            context.sleep(Duration::from_millis(100)).await;

            // Once the anchor arrives, dispatch restarts at the floor
            // successor instead of treating the stale ack as progress.
            assert!(mailbox.verified(floor_round, floor_block).await);
            select! {
                height = application.acknowledged() => {
                    assert_eq!(
                        height,
                        Height::new(1),
                        "floor install must ignore acks released while the anchor is pending"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("pending floor anchor did not restart dispatch at its successor");
                },
            }
            assert_eq!(application.acknowledged().await, Height::new(2));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_local_floor_below_in_flight_keeps_pending_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "local-floor-below-in-flight-keeps-pending-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.clone().into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&genesis),
                ),
                &schemes,
                QUORUM,
            );

            // The genesis anchor is already local and below the in-flight
            // height 1 ack, so applying it must not touch pending acks.
            mailbox.set_floor(floor_finalization);
            assert!(mailbox.get_block(Height::zero()).await.is_some());

            assert_eq!(
                application.pending_ack_heights(),
                vec![Height::new(1)],
                "local floor below the in-flight block must not clear or duplicate its ack"
            );

            let retain_before_ack = resolver.retain_count();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            wait_until(
                &context,
                Duration::from_secs(5),
                "first ack processed",
                || resolver.retain_count() > retain_before_ack,
            )
            .await;
            assert!(application.pending_ack_heights().is_empty());
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_below_processed_height_preserves_in_flight_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-below-processed-height-preserves-in-flight-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.clone().into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let retain_before_block1_ack = resolver.retain_count();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            wait_until(
                &context,
                Duration::from_secs(5),
                "first ack processed",
                || resolver.retain_count() > retain_before_block1_ack,
            )
            .await;

            let block2_round = Round::new(Epoch::zero(), View::new(2));
            let block2 = make_raw_block(block1.digest(), Height::new(2), 200);
            let block2_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block2_round,
                    View::new(1),
                    StandardHarness::commitment(&block2),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block2_round, block2).await);
            StandardHarness::report_finalization(&mut mailbox, block2_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "second block dispatch",
                || application.pending_ack_heights() == vec![Height::new(2)],
            )
            .await;

            // Keep a round-bound resolver request live so the stale floor's
            // round-floor side effect is covered separately from ack handling.
            let stale_floor_round = Round::new(Epoch::zero(), View::new(5));
            let missing = Sha256::hash(&[b"missing-before-stale-lower-floor"]);
            StandardHarness::report_finalization(
                &mut mailbox.clone(),
                StandardHarness::make_finalization(
                    Proposal::new(stale_floor_round, View::zero(), missing),
                    &schemes,
                    QUORUM,
                ),
            )
            .await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound fetch before stale lower floor",
                || {
                    resolver.active_fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment) if commitment == missing
                        )
                    })
                },
            )
            .await;

            let stale_floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    stale_floor_round,
                    View::new(4),
                    StandardHarness::commitment(&genesis),
                ),
                &schemes,
                QUORUM,
            );

            // This lower local anchor is already behind processed height. It
            // may advance the round floor, but must leave height 2 in flight.
            mailbox.set_floor(stale_floor_finalization);
            assert!(mailbox.get_block(Height::zero()).await.is_some());

            assert_eq!(
                application.pending_ack_heights(),
                vec![Height::new(2)],
                "stale lower floor must not clear or duplicate in-flight acks"
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "stale lower floor round-bound prune",
                || {
                    resolver.active_fetches().iter().all(|fetch| {
                        !matches!(
                            fetch.key,
                            handler::Key::Block(commitment) if commitment == missing
                        )
                    })
                },
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_same_height_floor_anchor_keeps_pending_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "same-height-floor-keeps-pending-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(&[b"block1-parent"]), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let retain_before_ack = resolver.retain_count();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            wait_until(
                &context,
                Duration::from_secs(5),
                "first ack processed",
                || resolver.retain_count() > retain_before_ack,
            )
            .await;

            let block2_round = Round::new(Epoch::zero(), View::new(2));
            let block2 = make_raw_block(block1.digest(), Height::new(2), 200);
            let block2_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block2_round,
                    View::new(1),
                    StandardHarness::commitment(&block2),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block2_round, block2).await);
            StandardHarness::report_finalization(&mut mailbox, block2_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "second block dispatch",
                || application.pending_ack_heights() == vec![Height::new(2)],
            )
            .await;

            let same_height_round = Round::new(Epoch::zero(), View::new(5));
            let same_height_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    same_height_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(same_height_finalization);
            assert!(mailbox.get_block(Height::new(1)).await.is_some());

            assert_eq!(
                application.pending_ack_heights(),
                vec![Height::new(2)],
                "same-height floor anchor must not clear or duplicate in-flight acks"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_stale_floor_anchor_advances_round_floor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "stale-floor-anchor-round-floor",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block_round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b"processed-parent"]), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block_round,
                    View::zero(),
                    StandardHarness::commitment(&block),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block_round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            assert_eq!(application.acknowledged().await, Height::new(1));

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let missing = Sha256::hash(&[b"missing-before-stale-floor"]);
            StandardHarness::report_finalization(
                &mut mailbox.clone(),
                StandardHarness::make_finalization(
                    Proposal::new(floor_round, View::zero(), missing),
                    &schemes,
                    QUORUM,
                ),
            )
            .await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound fetch before stale floor",
                || {
                    resolver.active_fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment) if commitment == missing
                        )
                    })
                },
            )
            .await;

            let stale_floor = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::zero(),
                    StandardHarness::commitment(&block),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(stale_floor);
            wait_until(
                &context,
                Duration::from_secs(5),
                "stale floor round-bound prune",
                || {
                    resolver.active_fetches().iter().all(|fetch| {
                        !matches!(
                            fetch.key,
                            handler::Key::Block(commitment) if commitment == missing
                        )
                    })
                },
            )
            .await;

            let fetches_before = resolver.fetches().len();
            StandardHarness::report_finalization(
                &mut mailbox.clone(),
                StandardHarness::make_finalization(
                    Proposal::new(
                        floor_round,
                        View::zero(),
                        Sha256::hash(&[b"missing-after-stale-floor"]),
                    ),
                    &schemes,
                    QUORUM,
                ),
            )
            .await;
            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "stale floor anchor must apply its round floor to future fetches"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_floor_anchor_uses_parent_digest_as_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "standard-floor-parent-digest-commitment",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_context = Ctx {
                round: parent_round,
                leader: me.clone(),
                parent: (
                    View::zero(),
                    StandardHarness::genesis_parent_commitment(NUM_VALIDATORS as u16),
                ),
            };
            let parent =
                B::new::<Sha256>(parent_context, Sha256::hash(&[b""]), Height::new(1), 100);

            let floor_round = Round::new(Epoch::zero(), View::new(2));
            let bad_context = Ctx {
                round: floor_round,
                leader: me,
                parent: (
                    View::new(1),
                    StandardHarness::genesis_parent_commitment(NUM_VALIDATORS as u16),
                ),
            };
            let floor_block = B::new::<Sha256>(bad_context, parent.digest(), Height::new(2), 200);
            assert_ne!(floor_block.parent, floor_block.context.parent.1);

            // Standard commitments are digests, so the generic floor-anchor
            // parent check uses the block's parent digest. Context-parent
            // mismatches are rejected by the standard verification wrappers.
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(1),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            resolver.respond_to_next_fetch(floor_block.encode());
            mailbox.set_floor(finalization);

            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || !resolver.fetches().is_empty(),
            )
            .await;
            assert!(
                resolver.wait_for_delivery_response().await,
                "floor block delivery should be accepted at the resolver boundary"
            );

            assert!(
                mailbox.get_block(Height::new(2)).await.is_some(),
                "standard floor anchor should be archived using its parent digest"
            );
            assert!(
                mailbox.get_finalization(Height::new(2)).await.is_some(),
                "standard floor finalization should be archived by height"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_block_delivery_wakes_commitment_subscriber() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "block-delivery-wakes-subscriber",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            let subscription = mailbox.acquire(block.digest());

            wait_until(
                &context,
                Duration::from_secs(5),
                "commitment request",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            (&fetch.key, &fetch.subscriber),
                            (
                                handler::Key::Block(commitment),
                                handler::Annotation::Subscription,
                            ) if *commitment == block.digest()
                        )
                    })
                },
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: handler::Key::Block(block.digest()),
                            subscribers: NonEmptyVec::new((
                                handler::Annotation::Subscription,
                                tracing::Span::none(),
                            )),
                        },
                        value: block.encode(),
                        response,
                    })
                    .accepted()
            );
            assert!(
                response_rx.await.expect("delivery response missing"),
                "block delivery should validate"
            );

            select! {
                result = subscription => {
                    let delivered = result.expect("block subscription should resolve");
                    assert_eq!(delivered.digest(), block.digest());
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("block delivery did not wake block subscriber");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_finalized_commitment_delivery_survives_recovery() {
        const PARTITION_PREFIX: &str = "finalized-delivery-verify-only";

        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        let (fixture, checkpoint) = runner.start_and_recover(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let height = Height::new(1);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), height, 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);
            let verifier = schemes[0].clone();
            let application = Application::<B>::manual_ack();

            let (mailbox, _buffer, resolver, actor_handle) = start_standard_actor(
                context.child("validator"),
                PARTITION_PREFIX,
                VerifierProvider::new(verifier.clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            StandardHarness::report_finalization(&mut mailbox.clone(), finalization.clone()).await;
            let _ = mailbox.get_processed_height().await;
            let (response, response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: handler::Key::Block(block.digest()),
                            subscribers: NonEmptyVec::new((
                                handler::Annotation::Height(height),
                                tracing::Span::none(),
                            )),
                        },
                        value: block.encode(),
                        response,
                    })
                    .accepted()
            );
            assert!(
                response_rx.await.expect("delivery response missing"),
                "body matching the locally finalized commitment should be accepted"
            );
            assert_eq!(application.acknowledged().await, Height::zero());
            assert_eq!(application.acknowledged().await, height);
            assert_eq!(
                application.blocks().get(&height).unwrap().digest(),
                block.digest()
            );

            actor_handle.abort();
            drop(mailbox);
            (verifier, block, finalization)
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let (verifier, block, finalization) = fixture;
            let (mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("recovered"),
                PARTITION_PREFIX,
                VerifierProvider::new(verifier),
                Application::<B>::default(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            let recovered_block = mailbox
                .get_block(Height::new(1))
                .await
                .expect("delivered finalized block must be durable");
            assert_eq!(recovered_block.digest(), block.digest());
            let recovered_finalization = mailbox
                .get_finalization(Height::new(1))
                .await
                .expect("delivered finalization must be durable");
            assert_eq!(recovered_finalization.proposal, finalization.proposal);
        });
    }

    #[test_traced("WARN")]
    fn test_standard_processed_round_skips_fetch_and_preserves_subscription() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);
            let application = Application::<B>::manual_ack();
            let (mailbox, buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "fetch-notarized-processed-round",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            assert!(
                mailbox.verified(round, block.clone()).await,
                "verified block should persist before finalization"
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            let retain_floor = resolver.retain_count() + 2;
            assert_eq!(
                application.acknowledged().await,
                Height::new(1),
                "application should receive the finalized block"
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "processed-round pruning",
                || resolver.retain_count() >= retain_floor,
            )
            .await;

            let fetches_before = resolver.fetches().len();
            StandardHarness::report_finalization(
                &mut mailbox.clone(),
                StandardHarness::make_finalization(
                    Proposal::new(
                        round,
                        View::zero(),
                        Sha256::hash(&[b"missing-at-processed-round"]),
                    ),
                    &schemes,
                    QUORUM,
                ),
            )
            .await;
            let _ = mailbox.get_processed_height().await;
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "processed round must suppress stale finalization acquisition"
            );
            let missing = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 101);
            let missing_digest = missing.digest();
            let mut subscription = mailbox.acquire(missing_digest);

            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await,
                "barrier verification should be processed"
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before + 1,
                "a live caller must acquire despite the processed round"
            );
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));

            buffer
                .commitment_subscriptions
                .lock()
                .pop()
                .expect("commitment subscription should be registered")
                .send_lossy(Arc::new(missing));
            assert_eq!(subscription.await.unwrap().digest(), missing_digest);
        });
    }

    #[test_traced("WARN")]
    fn test_standard_finalization_rejects_processed_round_block_fetch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "finalization-processed-round-fetch",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            let retain_floor = resolver.retain_count() + 2;
            assert_eq!(application.acknowledged().await, Height::new(1));
            wait_until(
                &context,
                Duration::from_secs(5),
                "processed-round pruning",
                || resolver.retain_count() >= retain_floor,
            )
            .await;

            let fetches_before = resolver.fetches().len();
            let stale_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    round,
                    View::zero(),
                    Sha256::hash(&[b"missing-finalized-at-processed-round"]),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, stale_finalization).await;

            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "stale finalization must not enqueue a round-bound block fetch"
            );
        });
    }

    #[test_traced("WARN")]
    #[should_panic(expected = "stored genesis block does not match configured anchor")]
    fn test_standard_restart_rejects_mismatched_genesis_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "restart-keeps-existing-genesis";

            let original_genesis =
                make_raw_block(Sha256::hash(&[b"original-genesis"]), Height::zero(), 0);
            let replacement_genesis =
                make_raw_block(Sha256::hash(&[b"replacement-genesis"]), Height::zero(), 1);
            assert_ne!(original_genesis.digest(), replacement_genesis.digest());

            let (mailbox, buffer, resolver, actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(original_genesis.clone().into()),
            )
            .await;
            assert_eq!(
                mailbox.get_block(Height::zero()).await.unwrap().digest(),
                original_genesis.digest()
            );

            actor_handle.abort();
            drop(mailbox);
            drop(buffer);
            drop(resolver);
            context.sleep(Duration::from_millis(1)).await;

            let (_mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator_restart"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(replacement_genesis.clone().into()),
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_processed_round_restored_after_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let partition_prefix = format!("processed-round-restart-{me}");

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            let retain_floor = resolver.retain_count() + 2;
            assert_eq!(application.acknowledged().await, Height::new(1));
            wait_until(
                &context,
                Duration::from_secs(5),
                "processed-round pruning",
                || resolver.retain_count() >= retain_floor,
            )
            .await;
            assert_eq!(
                mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(1), block.digest()))
            );

            actor_handle.abort();
            drop(mailbox);
            context.sleep(Duration::from_millis(1)).await;

            let (mailbox, buffer, resolver, _actor_handle) = start_standard_actor(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            let fetches_before = resolver.fetches().len();
            StandardHarness::report_finalization(
                &mut mailbox.clone(),
                StandardHarness::make_finalization(
                    Proposal::new(
                        round,
                        View::zero(),
                        Sha256::hash(&[b"missing-after-restart"]),
                    ),
                    &schemes,
                    QUORUM,
                ),
            )
            .await;
            let _ = mailbox.get_processed_height().await;
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "processed round must suppress stale finalization acquisition"
            );
            let missing = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 101);
            let missing_digest = missing.digest();
            let mut subscription = mailbox.acquire(missing_digest);

            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before + 1,
                "a live caller must acquire despite restored progress"
            );
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));

            // Local ingress satisfies the same commitment acquisition.
            buffer
                .commitment_subscriptions
                .lock()
                .pop()
                .expect("commitment subscription should be registered")
                .send_lossy(Arc::new(missing));
            assert_eq!(subscription.await.unwrap().digest(), missing_digest);
        });
    }

    #[test_traced("WARN")]
    fn test_standard_round_floor_does_not_restore_missing_next_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "round-floor-missing-next-block";

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);

            seed_processed_height(context.child("metadata"), partition_prefix, Height::zero())
                .await;
            seed_inconsistent_restart_state(
                context.child("storage"),
                partition_prefix,
                &[],
                &[(Height::new(1), finalization.clone())],
            )
            .await;

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            StandardHarness::report_finalization(&mut mailbox.clone(), finalization).await;
            let mut subscription = mailbox.acquire(StandardHarness::commitment(&block));
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(subscription.try_recv(), Err(TryRecvError::Empty)),
                "missing next block must not advance the restored round floor"
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "commitment fetch after missing-next restart",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            (&fetch.key, &fetch.subscriber),
                            (
                                handler::Key::Block(commitment),
                                handler::Annotation::Round(request_round),
                            ) if *commitment == block.digest() && *request_round == round
                        )
                    })
                },
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: handler::Key::Block(block.digest()),
                            subscribers: NonEmptyVec::new((
                                handler::Annotation::Subscription,
                                tracing::Span::none(),
                            )),
                        },
                        value: block.encode(),
                        response,
                    })
                    .accepted()
            );
            assert!(
                response_rx.await.expect("delivery response missing"),
                "block delivery should validate"
            );
            select! {
                result = subscription => {
                    let delivered = result.expect("block subscription should resolve");
                    assert_eq!(delivered.digest(), block.digest());
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("round-floor subscription did not resolve");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_round_floor_restores_unacknowledged_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "round-floor-before-anchor-ack";

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(&[b"floor-parent"]), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            let (application, started) = HoldingBlockReporter::new_after(Height::zero());
            let (mailbox, buffer, resolver, actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            assert!(mailbox.verified(floor_round, floor_block.clone()).await);
            mailbox.set_floor(floor_finalization);
            select! {
                height = started => {
                    assert_eq!(
                        height.expect("floor anchor delivery signal missing"),
                        Height::new(5),
                        "floor anchor should be delivered before the simulated crash"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("floor anchor was not delivered before restart");
                },
            }

            actor_handle.abort();
            drop(mailbox);
            drop(buffer);
            drop(resolver);
            context.sleep(Duration::from_millis(1)).await;

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            let fetches_before = resolver.fetches().len();
            StandardHarness::report_finalization(
                &mut mailbox.clone(),
                StandardHarness::make_finalization(
                    Proposal::new(
                        floor_round,
                        View::zero(),
                        Sha256::hash(&[b"stale-finality-before-anchor-ack"]),
                    ),
                    &schemes,
                    QUORUM,
                ),
            )
            .await;
            let _ = mailbox.get_processed_height().await;
            assert_eq!(resolver.fetches().len(), fetches_before);
            let mut subscription = mailbox.acquire(Sha256::hash(&[b"missing-before-anchor-ack"]));
            let barrier = make_raw_block(floor_block.digest(), Height::new(6), 600);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(6)), barrier)
                    .await,
                "barrier verification should be processed"
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before + 1,
                "live acquisition must survive the restored floor"
            );
            assert!(
                matches!(subscription.try_recv(), Err(TryRecvError::Empty)),
                "durable floor round must preserve local subscriptions after restart"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_prunes_round_bound_fetches() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-round-prune",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let missing = Sha256::hash(&[b"missing-before-set-floor"]);
            StandardHarness::report_finalization(&mut mailbox.clone(), StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), missing), &schemes, QUORUM,
            )).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound fetch",
                || {
                    resolver.active_fetches().iter().any(|fetch| {
                        matches!(fetch.key, handler::Key::Block(commitment) if commitment == missing)
                    })
                },
            )
            .await;

            mailbox.set_floor(finalization.clone());
            assert!(mailbox.verified(round, block.clone()).await);
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound prune",
                || {
                    resolver.active_fetches().iter().all(|fetch| {
                        !matches!(fetch.key, handler::Key::Block(commitment) if commitment == missing)
                    })
                },
            )
            .await;
            assert!(
                resolver.active_fetches().iter().all(|fetch| {
                    !matches!(fetch.key, handler::Key::Block(commitment) if commitment == missing)
                }),
                "processed finalization after set_floor must prune existing round-bound fetches"
            );

            let fetches_before = resolver.fetches().len();
            StandardHarness::report_finalization(&mut mailbox.clone(), StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), Sha256::hash(&[b"missing-after-set-floor"])), &schemes, QUORUM,
            )).await;
            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "set_floor must apply the round floor to future fetches"
            );
        });
    }

    /// A round-floor advance that supersedes the pending floor anchor must
    /// release the floor transition rather than strand it once its anchor
    /// fetch is pruned.
    #[test_traced("WARN")]
    fn test_standard_round_floor_advance_releases_superseded_pending_floor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "round-floor-releases-pending-floor";

            // Models a prunable deployment after section pruning: the application
            // processed through height 3, the section holding earlier heights was
            // pruned, and height 3 was repaired by walkback without a direct
            // finalization, so the recovered round floor lags every finalization
            // on the chain.
            let anchor_round = Round::new(Epoch::zero(), View::new(2));
            let anchor = make_raw_block(Sha256::hash(&[b"anchor-parent"]), Height::new(2), 200);
            let anchor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    anchor_round,
                    View::new(1),
                    StandardHarness::commitment(&anchor),
                ),
                &schemes,
                QUORUM,
            );
            let processed_round = Round::new(Epoch::zero(), View::new(3));
            let processed = make_raw_block(anchor.digest(), Height::new(3), 300);
            let processed_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    processed_round,
                    View::new(2),
                    StandardHarness::commitment(&processed),
                ),
                &schemes,
                QUORUM,
            );
            let next = make_raw_block(processed.digest(), Height::new(4), 400);
            seed_processed_height(context.child("metadata"), partition_prefix, Height::new(3))
                .await;
            seed_inconsistent_restart_state(
                context.child("storage"),
                partition_prefix,
                &[processed.clone(), next.clone()],
                &[],
            )
            .await;

            // A configured floor for the pruned height 2 block is above the
            // recovered round floor, so marshal fetches it as a pending anchor.
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Floor(anchor_finalization),
            )
            .await;
            let mut mailbox = mailbox;
            let is_anchor_fetch = |fetch: &FetchRecord| {
                matches!(
                    (&fetch.key, &fetch.subscriber),
                    (
                        handler::Key::Block(commitment),
                        handler::Annotation::Round(round),
                    ) if *commitment == StandardHarness::commitment(&anchor)
                        && *round == anchor_round
                )
            };
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor anchor fetch",
                || resolver.active_fetches().iter().any(is_anchor_fetch),
            )
            .await;
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                application.pending_ack_heights().is_empty(),
                "pending floor must hold dispatch until the anchor resolves"
            );

            // A finalization for the retained height 3 block (for example,
            // re-reported by consensus on restart) advances the round floor
            // past the pending anchor round.
            let retains_before = resolver.retain_count();
            StandardHarness::report_finalization(&mut mailbox, processed_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "round floor advance",
                || resolver.retain_count() > retains_before,
            )
            .await;

            // The anchor is now provably at or below the processed height. If
            // marshal still wants it, serve it. Either way the superseded
            // floor must release application dispatch.
            if let Some(fetch) = resolver
                .active_fetches()
                .into_iter()
                .find(is_anchor_fetch)
            {
                let (response, response_rx) = oneshot::channel();
                assert!(
                    resolver
                        .enqueue(handler::Message::Deliver {
                            delivery: Delivery {
                                key: fetch.key,
                                subscribers: NonEmptyVec::new((
                                    fetch.subscriber,
                                    tracing::Span::none()
                                )),
                            },
                            value: anchor.encode(),
                            response,
                        })
                        .accepted()
                );
                assert!(response_rx.await.expect("delivery response missing"));
            }
            select! {
                height = application.acknowledged() => {
                    assert_eq!(height, Height::new(4));
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!(
                        "superseded pending floor stranded dispatch: anchor fetch pruned without releasing the floor"
                    );
                },
            }
        });
    }

    /// Regression: application delivery of a finalized block must only happen
    /// after the finalized archives are durably synced. Otherwise a crash after
    /// the application observes the block, but before it acknowledges it, can
    /// expose derived state ahead of marshal's height-indexed finalization.
    #[test_traced("WARN")]
    fn test_standard_dispatches_finalized_blocks_after_sync() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let partition_prefix = format!("validator-{me}");
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            let (application, started) = HoldingBlockReporter::new_after(Height::zero());
            let (mut mailbox, _buffer, _resolver, actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization.clone()).await;

            select! {
                height = started => {
                    assert_eq!(
                        height.expect("delivery signal missing"),
                        Height::new(1),
                        "application should observe the first finalized block"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("application should observe block delivery promptly");
                },
            }

            actor_handle.abort();
            drop(mailbox);

            // Yield once so the aborted actor drops its storage handles before restart.
            context.sleep(Duration::from_millis(1)).await;

            let (mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            let recovered = mailbox
                .get_block(Height::new(1))
                .await
                .expect("finalized block must be durable before delivery");
            assert_eq!(
                recovered.digest(),
                block.digest(),
                "restart should recover the delivered finalized block by height"
            );
            assert_eq!(
                mailbox
                    .get_finalization(Height::new(1))
                    .await
                    .expect("finalization must be durable before delivery")
                    .round(),
                round,
                "restart should recover the delivered finalization by height"
            );
        });
    }

    /// A finalized-store wrapper that delays durability by `pace` of
    /// deterministic time to model a slow sync: `sync` blocks the caller for
    /// the pace, while `start_sync` returns immediately with a handle that
    /// completes after the pace (like an archive with a non-blocking sync
    /// path, e.g. [`prunable::Archive`]).
    struct PacedStore<T> {
        inner: T,
        context: deterministic::Context,
        pace: Duration,
    }

    impl<T: crate::marshal::store::Blocks> crate::marshal::store::Blocks for PacedStore<T> {
        type Block = T::Block;
        type Error = T::Error;

        async fn put(mut self, block: &Self::Block) -> Result<Self, Self::Error> {
            self.inner = self.inner.put(block).await?;
            Ok(self)
        }

        async fn sync(mut self) -> Result<Self, Self::Error> {
            self.context.sleep(self.pace).await;
            self.inner = self.inner.sync().await?;
            Ok(self)
        }

        async fn start_sync(
            mut self,
        ) -> Result<(Self, commonware_runtime::Handle<()>), Self::Error> {
            let handle;
            (self.inner, handle) = self.inner.start_sync().await?;
            let sleep = self.context.sleep(self.pace);
            Ok((
                self,
                commonware_runtime::Handle::from_future(async move {
                    sleep.await;
                    handle.await
                }),
            ))
        }

        async fn has(
            &self,
            digest: &<Self::Block as Digestible>::Digest,
        ) -> Result<bool, Self::Error> {
            self.inner.has(digest).await
        }

        async fn get(
            &self,
            id: commonware_storage::archive::Identifier<'_, <Self::Block as Digestible>::Digest>,
        ) -> Result<Option<Self::Block>, Self::Error> {
            self.inner.get(id).await
        }

        async fn prune(mut self, min: Height) -> Result<Self, Self::Error> {
            self.inner = self.inner.prune(min).await?;
            Ok(self)
        }

        fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
            self.inner.next_gap(value)
        }

        fn last_index(&self) -> Option<Height> {
            self.inner.last_index()
        }
    }

    impl<T: crate::marshal::store::Certificates> crate::marshal::store::Certificates for PacedStore<T> {
        type BlockDigest = T::BlockDigest;
        type Commitment = T::Commitment;
        type Scheme = T::Scheme;
        type Error = T::Error;

        async fn put(
            mut self,
            height: Height,
            digest: Self::BlockDigest,
            finalization: &Finalization<Self::Scheme, Self::Commitment>,
        ) -> Result<Self, Self::Error> {
            self.inner = self.inner.put(height, digest, finalization).await?;
            Ok(self)
        }

        async fn sync(mut self) -> Result<Self, Self::Error> {
            self.context.sleep(self.pace).await;
            self.inner = self.inner.sync().await?;
            Ok(self)
        }

        async fn start_sync(
            mut self,
        ) -> Result<(Self, commonware_runtime::Handle<()>), Self::Error> {
            let handle;
            (self.inner, handle) = self.inner.start_sync().await?;
            let sleep = self.context.sleep(self.pace);
            Ok((
                self,
                commonware_runtime::Handle::from_future(async move {
                    sleep.await;
                    handle.await
                }),
            ))
        }

        async fn get(
            &self,
            id: commonware_storage::archive::Identifier<'_, Self::BlockDigest>,
        ) -> Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error> {
            self.inner.get(id).await
        }

        async fn prune(mut self, min: Height) -> Result<Self, Self::Error> {
            self.inner = self.inner.prune(min).await?;
            Ok(self)
        }

        fn last_index(&self) -> Option<Height> {
            self.inner.last_index()
        }

        fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)> {
            self.inner.ranges_from(from)
        }
    }

    type Finalizations = prunable::Archive<EightCap, deterministic::Context, D, Finalization<S, D>>;
    type FinalizedBlocks<T = Arc<B>> = prunable::Archive<EightCap, deterministic::Context, D, T>;

    /// Initialize prunable finalized stores for direct actor tests.
    async fn prunable_finalized_stores<T: crate::Block<Digest = D> + Read<Cfg = ()>>(
        context: &deterministic::Context,
        partition_prefix: &str,
    ) -> (Finalizations, FinalizedBlocks<T>) {
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            prunable::Config {
                translator: EightCap,
                metadata_partition: format!("{partition_prefix}-fbh-metadata"),
                key_partition: format!("{partition_prefix}-fbh-key"),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{partition_prefix}-fbh-value"),
                compression: None,
                codec_config: S::certificate_codec_config_unbounded(),
                items_per_section: NZU64!(10),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            prunable::Config {
                translator: EightCap,
                metadata_partition: format!("{partition_prefix}-fb-metadata"),
                key_partition: format!("{partition_prefix}-fb-key"),
                key_page_cache: page_cache,
                value_partition: format!("{partition_prefix}-fb-value"),
                compression: None,
                codec_config: (),
                items_per_section: NZU64!(10),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        (finalizations_by_height, finalized_blocks)
    }

    /// Initialize paced prunable finalized stores for direct actor tests.
    async fn paced_finalized_stores(
        context: &deterministic::Context,
        partition_prefix: &str,
        pace: Duration,
    ) -> (PacedStore<Finalizations>, PacedStore<FinalizedBlocks>) {
        let (finalizations_by_height, finalized_blocks) =
            prunable_finalized_stores(context, partition_prefix).await;
        (
            PacedStore {
                inner: finalizations_by_height,
                context: context.child("finalizations_pacer"),
                pace,
            },
            PacedStore {
                inner: finalized_blocks,
                context: context.child("blocks_pacer"),
                pace,
            },
        )
    }

    /// Builds a marshal actor configuration for tests.
    fn test_config(
        context: &deterministic::Context,
        partition_prefix: &str,
        provider: harness::P,
        max_pending_acks: NonZeroUsize,
    ) -> Config<harness::P, FixedEpocher, Sequential, B, Arc<B>, D> {
        Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start: Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            mailbox_size: NZUsize!(100),
            view_retention: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks,
            block_codec_config: (),
            partition_prefix: partition_prefix.to_string(),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        }
    }

    /// Counts full block clones through a zero-byte mock context.
    #[derive(Debug, Default)]
    struct CloneCounter(Arc<AtomicUsize>);

    impl Clone for CloneCounter {
        fn clone(&self) -> Self {
            self.0.fetch_add(1, Ordering::Relaxed);
            Self(Arc::clone(&self.0))
        }
    }

    impl FixedSize for CloneCounter {
        const SIZE: usize = 0;
    }

    impl Write for CloneCounter {
        fn write(&self, _: &mut impl BufMut) {}
    }

    impl Read for CloneCounter {
        type Cfg = ();

        fn read_cfg(_: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
            Ok(Self::default())
        }
    }

    #[test_traced("WARN")]
    fn test_standard_cache_writes_do_not_clone_block_payloads() {
        type CountedBlock = crate::marshal::mocks::block::Block<D, CloneCounter>;
        const PREFIX: &str = "shared-cache";
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let genesis = CountedBlock::new::<Sha256>(
                CloneCounter::default(),
                Sha256::hash(&[b""]),
                Height::zero(),
                0,
            );
            let parent = genesis.digest();
            let (finalizations, blocks) = prunable_finalized_stores(&context, PREFIX).await;
            let (actor, mailbox, _) = Actor::<_, Standard<CountedBlock>, _, _, _, _, _>::init(
                context.child("actor"),
                finalizations,
                blocks,
                Config {
                    provider: ConstantProvider::new(schemes[0].clone()),
                    epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                    start: Start::Genesis(genesis.into()),
                    mailbox_size: NZUsize!(100),
                    view_retention: ViewDelta::new(10),
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    block_codec_config: (),
                    partition_prefix: PREFIX.to_string(),
                    prunable_items_per_section: NZU64!(10),
                    replay_buffer: NZUsize!(1024),
                    key_write_buffer: NZUsize!(1024),
                    value_write_buffer: NZUsize!(1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    strategy: Sequential,
                },
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let _actor_handle = actor.start_unbuffered(
                Application::<CountedBlock>::default(),
                (resolver_rx, resolver),
            );

            for (view, certified) in [(1, false), (2, true)] {
                let round = Round::new(Epoch::zero(), View::new(view));
                let block = Arc::new(CountedBlock::new::<Sha256>(
                    CloneCounter::default(),
                    parent,
                    Height::new(1),
                    view,
                ));

                // Keep an external owner through both insertion and duplicate delivery
                for _ in 0..2 {
                    let durable = if certified {
                        mailbox.certified(round, Arc::clone(&block)).await
                    } else {
                        mailbox.verified(round, Arc::clone(&block)).await
                    };
                    assert!(durable);
                    assert_eq!(
                        block.context.0.load(Ordering::Relaxed),
                        0,
                        "cache persistence must not clone the block payload (certified={certified})"
                    );
                    assert_eq!(
                        mailbox.get_block(&block.digest()).await.unwrap().digest(),
                        block.digest()
                    );
                }
            }
        });
    }

    /// A slow finalized-archive sync must not block the marshal mailbox.
    ///
    /// Processing a finalization requires making the finalized archives
    /// durable before the block is dispatched to the application, but the
    /// sync itself must not serialize unrelated mailbox traffic: a proposer's
    /// `get_verified` (a pure prunable-cache read) issued while the sync is in
    /// flight must be answered immediately.
    ///
    /// Paces both finalized stores so sync completion takes 100ms of
    /// deterministic time, processes a finalization, issues `get_verified` 1ms
    /// later, and asserts that (1) the read is served while the sync is still
    /// in flight and (2) the finalized block reaches the application only
    /// after the paced sync completes (the durability barrier).
    #[test_traced("WARN")]
    fn test_standard_finalization_sync_does_not_block_mailbox() {
        const PACE: Duration = Duration::from_millis(100);
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let config = test_config(
                &context,
                "paced-finalized-sync",
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
            );
            let (finalizations_by_height, finalized_blocks) =
                paced_finalized_stores(&context, "paced-finalized-sync", PACE).await;
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::default();
            let _actor_handle =
                actor.start_unbuffered(application.clone(), (resolver_rx, resolver));

            // Wait for the genesis block to flow through dispatch so the ack
            // pipeline is idle before the measurement starts.
            wait_until(
                &context,
                Duration::from_secs(1),
                "genesis dispatched",
                || application.blocks().contains_key(&Height::zero()),
            )
            .await;

            // Store a verified block for round 1 in the (unpaced) prunable cache.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            assert!(mailbox.verified(round, block.clone()).await);

            // Report the finalization: the actor buffers the block into the
            // finalized archives and starts the paced 100ms sync.
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            let finalized_at = context.current();
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            // Issue a get_verified 1ms later: it must not queue behind the sync.
            context.sleep(Duration::from_millis(1)).await;
            let requested_at = context.current();
            let verified = mailbox.get_verified(round).await;
            let elapsed = context
                .current()
                .duration_since(requested_at)
                .expect("time went backwards");
            assert_eq!(
                verified.expect("verified block missing").digest(),
                block.digest()
            );
            tracing::info!(?elapsed, "get_verified answered");
            assert!(
                elapsed < Duration::from_millis(5),
                "get_verified queued behind the finalized-archive sync: took {elapsed:?}"
            );

            // Durability barrier: the finalized block must not reach the
            // application until the paced sync completes.
            assert!(
                !application.blocks().contains_key(&Height::new(1)),
                "block dispatched before the finalized archives were durable"
            );
            context.sleep(Duration::from_millis(90)).await;
            assert!(
                !application.blocks().contains_key(&Height::new(1)),
                "block dispatched before the finalized archives were durable"
            );
            wait_until(
                &context,
                Duration::from_millis(50),
                "finalized block dispatched",
                || application.blocks().contains_key(&Height::new(1)),
            )
            .await;
            let dispatched = context
                .current()
                .duration_since(finalized_at)
                .expect("time went backwards");
            tracing::info!(?dispatched, "finalized block dispatched");
            assert!(
                dispatched >= PACE,
                "block dispatched before the paced sync completed: {dispatched:?}"
            );
        });
    }

    /// A buffered finalized-archive write must freeze dispatch even when a
    /// stale floor anchor triggers dispatch before the batch's sync starts.
    ///
    /// Within one resolver batch, a repair delivery can buffer a block at the
    /// dispatch frontier and a later delivery can resolve a pending floor
    /// anchor whose height is at or below the processed height. That anchor
    /// path calls `try_dispatch_blocks` mid-batch, before the batch-end
    /// `start_finalized_sync` runs, so dispatch must be gated by the write
    /// itself (via `DispatchGate::defer`) rather than by a started sync.
    /// Without the gate, the frontier block reaches the application while its
    /// archive write is still buffered, and a crash after the application ack
    /// could durably advance the processed floor past a lost write.
    ///
    /// The stale anchor models adversarial input: a verified finalization at
    /// a round above the round floor naming a block marshal never stored at a
    /// height it already processed. Marshal cannot cross-check certificates
    /// against each other, so it must stay crash-safe when one lands in
    /// `apply_pending_floor`'s stale-anchor branch.
    ///
    /// The two repair blocks are delivered in ascending height order, so the
    /// batch entry must keep the lowest written height. Tracking the latest
    /// write instead would leave the gate above the first block and let it
    /// dispatch non-durably.
    #[test_traced("WARN")]
    fn test_standard_stale_floor_anchor_holds_dispatch_until_durable() {
        const PACE: Duration = Duration::from_millis(100);
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let config = test_config(
                &context,
                "stale-floor-anchor",
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(4),
            );
            let (finalizations_by_height, finalized_blocks) =
                paced_finalized_stores(&context, "stale-floor-anchor", PACE).await;
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::default();
            let _actor_handle =
                actor.start_unbuffered(application.clone(), (resolver_rx, resolver.clone()));

            // Finalize block 1 and wait until the application has acknowledged
            // it, so the processed height reaches the anchor height below.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            assert!(mailbox.verified(round, block.clone()).await);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "block 1 processed",
                || parse_processed_height(&context.encode()) == Some(1),
            )
            .await;

            // Install a pending floor anchor for a forked block at height 1:
            // a valid certificate at a round above the round floor whose block
            // is unknown locally, so marshal fetches it. Its height (at or
            // below the processed height) routes the arriving anchor into the
            // stale-anchor branch.
            let fork = make_raw_block(genesis.digest(), Height::new(1), 999);
            let fork_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(5)),
                    View::new(4),
                    StandardHarness::commitment(&fork),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(fork_finalization);
            wait_until(&context, Duration::from_secs(5), "anchor fetch", || {
                resolver.fetches().iter().any(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&fork)
                    )
                })
            })
            .await;
            let anchor_fetch = resolver
                .fetches()
                .into_iter()
                .find(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&fork)
                    )
                })
                .expect("anchor fetch missing");

            let next = make_raw_block(block.digest(), Height::new(2), 200);
            let above = make_raw_block(next.digest(), Height::new(3), 300);
            for block in [&next, &above] {
                let round = Round::new(Epoch::zero(), View::new(block.height().get()));
                StandardHarness::report_finalization(&mut mailbox, StandardHarness::make_finalization(
                    Proposal::new(round, View::zero(), block.digest()), &schemes, QUORUM,
                )).await;
            }
            let _ = mailbox.get_processed_height().await;
            for block in [&next, &above] {
                assert!(resolver.fetches().iter().any(|fetch| matches!(
                    (&fetch.key, &fetch.subscriber),
                    (handler::Key::Block(commitment), handler::Annotation::Round(_)) if *commitment == block.digest()
                )));
            }

            // Enqueue all deliveries back-to-back (no intervening await) so
            // the actor drains them in a single resolver batch: two repair
            // blocks at and above the dispatch frontier (buffered
            // finalized-archive writes, ascending), then the stale floor
            // anchor.
            let (next_response, next_response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: handler::Key::Block(StandardHarness::commitment(&next)),
                            subscribers: NonEmptyVec::new((
                                handler::Annotation::Height(Height::new(2)),
                                tracing::Span::none(),
                            )),
                        },
                        value: next.encode(),
                        response: next_response,
                    })
                    .accepted()
            );
            let (above_response, above_response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: handler::Key::Block(StandardHarness::commitment(&above)),
                            subscribers: NonEmptyVec::new((
                                handler::Annotation::Height(Height::new(3)),
                                tracing::Span::none(),
                            )),
                        },
                        value: above.encode(),
                        response: above_response,
                    })
                    .accepted()
            );
            let (anchor_response, anchor_response_rx) = oneshot::channel();
            assert!(
                resolver
                    .enqueue(handler::Message::Deliver {
                        delivery: Delivery {
                            key: anchor_fetch.key,
                            subscribers: NonEmptyVec::new((
                                anchor_fetch.subscriber,
                                tracing::Span::none()
                            )),
                        },
                        value: fork.encode(),
                        response: anchor_response,
                    })
                    .accepted()
            );
            let delivered_at = context.current();
            assert!(
                next_response_rx.await.expect("repair response missing"),
                "repair block delivery should validate"
            );
            assert!(
                above_response_rx.await.expect("repair response missing"),
                "repair block delivery should validate"
            );
            assert!(
                anchor_response_rx.await.expect("anchor response missing"),
                "anchor delivery should validate"
            );

            // Durability barrier: the stale-anchor branch runs dispatch before
            // the batch's sync starts, so the repair block at height 2 must
            // stay held until the paced sync completes.
            context.sleep(Duration::from_millis(1)).await;
            assert!(
                !application.blocks().contains_key(&Height::new(2)),
                "block dispatched before the finalized archives were durable"
            );
            context.sleep(Duration::from_millis(90)).await;
            assert!(
                !application.blocks().contains_key(&Height::new(2)),
                "block dispatched before the finalized archives were durable"
            );
            wait_until(
                &context,
                Duration::from_millis(50),
                "repair blocks dispatched",
                || application.blocks().contains_key(&Height::new(3)),
            )
            .await;
            assert!(application.blocks().contains_key(&Height::new(2)));
            let dispatched = context
                .current()
                .duration_since(delivered_at)
                .expect("time went backwards");
            tracing::info!(?dispatched, "repair blocks dispatched");
            assert!(
                dispatched >= PACE,
                "block dispatched before the paced sync completed: {dispatched:?}"
            );
        });
    }

    /// Overlapping pooled syncs must release the dispatch gate per batch.
    ///
    /// Two finalizations arrive 50ms apart, each starting its own paced 100ms
    /// sync. The first sync covers only the first write, so block 1 must
    /// dispatch as soon as that sync completes while block 2 stays held until
    /// the second sync completes. This pins the batch accounting in
    /// `start_finalized_sync`: if the second write were folded into the first
    /// sync's batch, that sync's completion would release a write it never
    /// covered.
    #[test_traced("WARN")]
    fn test_standard_overlapping_finalized_syncs_release_per_batch() {
        const PACE: Duration = Duration::from_millis(100);
        const STAGGER: Duration = Duration::from_millis(50);
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let config = test_config(
                &context,
                "overlapping-finalized-syncs",
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(4),
            );
            let (finalizations_by_height, finalized_blocks) =
                paced_finalized_stores(&context, "overlapping-finalized-syncs", PACE).await;
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::default();
            let _actor_handle =
                actor.start_unbuffered(application.clone(), (resolver_rx, resolver));
            wait_until(
                &context,
                Duration::from_secs(5),
                "genesis processed",
                || application.blocks().contains_key(&Height::zero()),
            )
            .await;

            // Store both verified blocks, then finalize them one STAGGER
            // apart so their pooled syncs overlap.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let first_round = Round::new(Epoch::zero(), View::new(1));
            let first = make_raw_block(genesis.digest(), Height::new(1), 100);
            assert!(mailbox.verified(first_round, first.clone()).await);
            let second_round = Round::new(Epoch::zero(), View::new(2));
            let second = make_raw_block(first.digest(), Height::new(2), 200);
            assert!(mailbox.verified(second_round, second.clone()).await);

            let started_at = context.current();
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    first_round,
                    View::zero(),
                    StandardHarness::commitment(&first),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            context.sleep(STAGGER).await;
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    second_round,
                    View::new(1),
                    StandardHarness::commitment(&second),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            // Block 1 dispatches as soon as the first sync completes, without
            // waiting for the second sync.
            wait_until(
                &context,
                Duration::from_millis(150),
                "first block dispatched",
                || application.blocks().contains_key(&Height::new(1)),
            )
            .await;
            let first_dispatched = context
                .current()
                .duration_since(started_at)
                .expect("time went backwards");
            tracing::info!(?first_dispatched, "first block dispatched");
            assert!(
                first_dispatched >= PACE,
                "block dispatched before its sync completed: {first_dispatched:?}"
            );
            assert!(
                first_dispatched < STAGGER + PACE,
                "first block waited for the second sync: {first_dispatched:?}"
            );

            // Block 2 stays held until its own sync completes.
            assert!(
                !application.blocks().contains_key(&Height::new(2)),
                "block dispatched before its sync completed"
            );
            context.sleep(Duration::from_millis(20)).await;
            assert!(
                !application.blocks().contains_key(&Height::new(2)),
                "block dispatched before its sync completed"
            );
            wait_until(
                &context,
                Duration::from_millis(50),
                "second block dispatched",
                || application.blocks().contains_key(&Height::new(2)),
            )
            .await;
            let second_dispatched = context
                .current()
                .duration_since(started_at)
                .expect("time went backwards");
            tracing::info!(?second_dispatched, "second block dispatched");
            assert!(
                second_dispatched >= STAGGER + PACE,
                "block dispatched before its sync completed: {second_dispatched:?}"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_finalization_reuses_ready_prefetch_without_refetch() {
        const PARTITION: &str = "finalization-reuses-ready-prefetch";
        deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let (finalizations, blocks) = prunable_finalized_stores(&context, PARTITION).await;
            let mut config = test_config(
                &context,
                PARTITION,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
            );
            config.max_repair = NZUsize!(1);
            let (actor, mut mailbox, _) =
                Actor::init(context.child("actor"), finalizations, blocks, config).await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::manual_ack();
            let _actor = actor.start(
                application.clone(),
                RecordingBuffer::default(),
                (resolver_rx, resolver.clone()),
            );
            assert_eq!(application.acknowledged().await, Height::zero());

            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            let commitment = block.digest();
            resolver.respond_to_next_fetch(block.encode());
            let mut lease = mailbox.prefetch(Arc::from([commitment]), 0..1);
            wait_until(
                &context,
                Duration::from_secs(1),
                "prefetched body delivered",
                || !resolver.delivery_responses.lock().is_empty(),
            )
            .await;
            assert!(resolver.wait_for_delivery_response().await);
            assert_eq!(resolver.fetches().len(), 1);
            assert!(matches!(lease.try_recv(), Err(TryRecvError::Empty)));

            // The resolver's one response is exhausted. Finality must find the
            // completed body while its speculative lease still owns it.
            let finalized = mailbox.finalized(Height::new(1));
            let round = Round::new(Epoch::zero(), View::new(1));
            StandardHarness::report_finalization(
                &mut mailbox,
                StandardHarness::make_finalization(
                    Proposal::new(round, View::zero(), commitment),
                    &schemes,
                    QUORUM,
                ),
            )
            .await;
            let _ = mailbox.get_processed_height().await;
            assert_eq!(
                resolver.fetches().len(),
                1,
                "finalization must reuse the completed prefetch without another network request"
            );
            select! {
                result = finalized => {
                    assert_eq!(result.expect("finalized waiter canceled").digest(), commitment);
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("finalization could not find the completed prefetched body");
                },
            }
            assert!(matches!(lease.try_recv(), Err(TryRecvError::Empty)));

            let next = Sha256::hash(&[b"next speculative commitment"]);
            let mut next_lease = mailbox.prefetch(Arc::from([next]), 0..1);
            wait_until(
                &context,
                Duration::from_secs(1),
                "canonical storage releases prefetch capacity",
                || {
                    resolver
                        .fetches()
                        .iter()
                        .any(|fetch| fetch.key == handler::Key::Block(next))
                },
            )
            .await;
            assert!(matches!(lease.try_recv(), Err(TryRecvError::Empty)));
            assert!(matches!(next_lease.try_recv(), Err(TryRecvError::Empty)));
        });
    }

    fn independent_acquisition_with_parked_request(speculative: bool) {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition = format!("independent-acquisition-{speculative}");
            let (finalizations, blocks) = prunable_finalized_stores(&context, &partition).await;
            let mut config = test_config(&context, &partition,
                ConstantProvider::new(schemes[0].clone()), NZUsize!(1));
            config.max_repair = NZUsize!(1);
            let (actor, mailbox, _) = Actor::init(
                context.child("actor"), finalizations, blocks, config,
            ).await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::manual_ack();
            let _actor = actor.start(application.clone(), RecordingBuffer::default(),
                (resolver_rx, resolver.clone()));
            assert_eq!(application.acknowledged().await, Height::zero());

            let withheld = Sha256::hash(&[b"indefinitely withheld"]);
            let mut lease = speculative.then(|| mailbox.prefetch(Arc::from([withheld]), 0..1));
            let mut caller = (!speculative).then(|| mailbox.acquire(withheld));
            wait_until(&context, Duration::from_secs(1), "first request occupies capacity", || {
                resolver.fetches().iter().any(|fetch| fetch.key == handler::Key::Block(withheld))
            }).await;

            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let available = make_raw_block(genesis.digest(), Height::new(1), 100);
            resolver.respond_to_next_fetch(available.encode());
            let independent = mailbox.acquire(available.digest());
            select! {
                result = independent => {
                    assert_eq!(result.expect("independent acquisition canceled").digest(), available.digest());
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("parked request blocked independent acquisition (speculative={speculative})");
                },
            }
            assert!(resolver.wait_for_delivery_response().await);
            assert!(resolver.fetches().iter().any(|fetch| fetch.key == handler::Key::Block(available.digest())));
            if let Some(lease) = &mut lease {
                assert!(matches!(lease.try_recv(), Err(TryRecvError::Empty)));
            }
            if let Some(caller) = &mut caller {
                assert!(matches!(caller.try_recv(), Err(TryRecvError::Empty)));
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_parked_prefetch_does_not_block_direct_acquisition() {
        independent_acquisition_with_parked_request(true);
    }

    #[test_traced("WARN")]
    fn test_standard_parked_direct_caller_does_not_block_independent_acquisition() {
        independent_acquisition_with_parked_request(false);
    }

    #[test_traced("WARN")]
    fn test_standard_ranges_use_max_repair_with_parked_leases() {
        const LENGTH: u64 = 10;
        for max_repair in [NZUsize!(1), NZUsize!(3)] {
            deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
                let Fixture { schemes, .. } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let partition = format!("range-window-{max_repair}");
                let (finalizations, stored) = prunable_finalized_stores(&context, &partition).await;
                let mut config = test_config(
                    &context,
                    &partition,
                    ConstantProvider::new(schemes[0].clone()),
                    NZUsize!(1),
                );
                config.max_repair = max_repair;
                let (actor, mailbox, _) =
                    Actor::init(context.child("actor"), finalizations, stored, config).await;
                let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
                let (application, started) = HoldingBlockReporter::new();
                let _actor = actor.start(
                    application,
                    RecordingBuffer::default(),
                    (resolver_rx, resolver.clone()),
                );
                assert_eq!(started.await.unwrap(), Height::zero());
                let _ = mailbox.get_processed_height().await;

                // An unrelated lease occupies the shared speculative capacity.
                // The selected range must use its own window of max_repair bodies.
                let parked: Arc<[_]> = (0..max_repair.get())
                    .map(|index| Sha256::hash(&[b"parked dependency", &index.to_be_bytes()]))
                    .collect();
                let parked_keys: Vec<_> = parked.iter().copied().map(handler::Key::Block).collect();
                let mut lease = mailbox.prefetch(parked, 0..max_repair.get());
                wait_until(&context, Duration::from_secs(1), "parked prefetch", || {
                    resolver.active_fetches().len() == max_repair.get()
                })
                .await;

                let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
                let mut selected = vec![genesis.digest()];
                let blocks: Vec<_> = (1..=LENGTH)
                    .map(|height| {
                        let block =
                            make_raw_block(*selected.last().unwrap(), Height::new(height), height);
                        selected.push(block.digest());
                        block
                    })
                    .collect();
                let source = mailbox.blocks(Height::new(LENGTH), selected.into());
                let mut range = source.range(Height::new(1)..=Height::new(LENGTH));
                assert!(range.next().now_or_never().is_none());
                let _ = mailbox.get_processed_height().await;

                let fetched_keys = || {
                    resolver
                        .fetches()
                        .iter()
                        .map(|fetch| fetch.key)
                        .collect::<Vec<_>>()
                };
                let mut expected = parked_keys.clone();
                expected.extend(
                    blocks[..max_repair.get()]
                        .iter()
                        .map(|block| handler::Key::Block(block.digest())),
                );
                assert_eq!(fetched_keys(), expected);
                assert_eq!(
                    resolver
                        .active_fetches()
                        .iter()
                        .map(|fetch| fetch.key)
                        .collect::<Vec<_>>(),
                    expected
                );

                // Completed positions still occupy the window until the head
                // is consumed, even when their bodies arrive in reverse order.
                for block in blocks[1..max_repair.get()].iter().rev() {
                    let fetch = resolver
                        .active_fetches()
                        .into_iter()
                        .find(|fetch| fetch.key == handler::Key::Block(block.digest()))
                        .expect("selected request missing");
                    deliver_acquisition_test_block(&resolver, fetch, block).await;
                    assert!(range.next().now_or_never().is_none());
                    let _ = mailbox.get_processed_height().await;
                    assert_eq!(fetched_keys(), expected);
                }

                assert!(range.next().now_or_never().is_none());
                let _ = mailbox.get_processed_height().await;
                assert_eq!(fetched_keys(), expected);

                let head = &blocks[0];
                let fetch = resolver
                    .active_fetches()
                    .into_iter()
                    .find(|fetch| fetch.key == handler::Key::Block(head.digest()))
                    .expect("head request missing");
                deliver_acquisition_test_block(&resolver, fetch, head).await;
                assert_eq!(range.next().await.unwrap().unwrap().digest(), head.digest());
                let _ = mailbox.get_processed_height().await;
                assert_eq!(fetched_keys(), expected);

                for block in &blocks[1..max_repair.get()] {
                    assert_eq!(
                        range
                            .next()
                            .now_or_never()
                            .unwrap()
                            .unwrap()
                            .unwrap()
                            .digest(),
                        block.digest()
                    );
                }
                assert!(range.next().now_or_never().is_none());
                let next_key = handler::Key::Block(blocks[max_repair.get()].digest());
                wait_until(
                    &context,
                    Duration::from_secs(1),
                    "range window advances",
                    || {
                        resolver
                            .active_fetches()
                            .iter()
                            .any(|fetch| fetch.key == next_key)
                    },
                )
                .await;
                let _ = mailbox.get_processed_height().await;
                expected.extend(
                    blocks[max_repair.get()..2 * max_repair.get()]
                        .iter()
                        .map(|block| handler::Key::Block(block.digest())),
                );
                assert_eq!(fetched_keys(), expected);

                drop(range);
                wait_until(
                    &context,
                    Duration::from_secs(1),
                    "range cancellation preserves parked lease",
                    || {
                        resolver
                            .active_fetches()
                            .iter()
                            .map(|fetch| fetch.key)
                            .collect::<Vec<_>>()
                            == parked_keys
                    },
                )
                .await;
                assert!(matches!(lease.try_recv(), Err(TryRecvError::Empty)));
                let _ = mailbox.get_processed_height().await;
                drop(lease);
                wait_until(
                    &context,
                    Duration::from_secs(1),
                    "parked lease cancellation",
                    || resolver.active_fetches().is_empty(),
                )
                .await;
                let _ = mailbox.get_processed_height().await;
                assert_eq!(fetched_keys(), expected);
            });
        }
    }

    #[test_traced("WARN")]
    fn test_standard_parked_local_range_bounds_body_reads() {
        const PARTITION: &str = "parked-local-range-body-reads";
        const LENGTH: u64 = 64;
        const BODY_WINDOW: usize = 8;
        deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let (finalizations, mut stored) = prunable_finalized_stores(&context, PARTITION).await;
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let mut selected = vec![genesis.digest()];
            for height in 1..=LENGTH {
                let block = Arc::new(make_raw_block(
                    *selected.last().unwrap(),
                    Height::new(height),
                    height,
                ));
                selected.push(block.digest());
                stored = stored
                    .put_sync(height, block.digest(), &block)
                    .await
                    .unwrap();
            }
            let stored = Recording::new(stored, |block: &Arc<B>| Arc::as_ptr(block).addr());
            let operations = stored.ops();
            let mut config = test_config(
                &context,
                PARTITION,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
            );
            config.max_repair = NZUsize!(BODY_WINDOW);
            assert!(LENGTH as usize > config.max_repair.get());
            let (actor, mailbox, _) =
                Actor::init(context.child("actor"), finalizations, stored, config).await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::manual_ack();
            let _actor = actor.start(
                application.clone(),
                RecordingBuffer::default(),
                (resolver_rx, resolver.clone()),
            );
            wait_until(
                &context,
                Duration::from_secs(1),
                "held genesis acknowledgement",
                || application.pending_ack_heights() == vec![Height::zero()],
            )
            .await;
            let _ = mailbox.get_processed_height().await;
            operations.lock().clear();

            let expected = selected[1];
            let source = mailbox.blocks(Height::new(LENGTH), selected.into());
            let mut range = source.range(Height::new(1)..=Height::new(LENGTH));
            let first = range.next().await.unwrap().unwrap();
            assert_eq!(first.digest(), expected);

            // Keep the range alive without polling again. Speculative scheduling
            // must use metadata while the application holds its first body.
            context.sleep(Duration::from_millis(100)).await;
            let reads = operations
                .lock()
                .iter()
                .filter(|op| matches!(op, Op::Get(None)))
                .count();
            assert!(
                reads <= BODY_WINDOW,
                "parked range decoded {reads} stored bodies for a {BODY_WINDOW}-body window"
            );
            assert!(
                reads > 0,
                "the range must acquire bodies from recorded storage"
            );
            assert!(
                resolver.fetches().is_empty(),
                "locally stored bodies must not be fetched"
            );
            assert_eq!(application.pending_ack_heights(), vec![Height::zero()]);
            drop(range);
        });
    }

    /// Dispatch preserves the buffered block object without rereading it from the archive.
    #[test_traced("WARN")]
    fn test_standard_dispatch_delivers_staged_block_without_archive_read() {
        const PARTITION_PREFIX: &str = "staged-dispatch";
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let (finalizations_by_height, finalized_blocks) =
                prunable_finalized_stores(&context, PARTITION_PREFIX).await;
            let finalized_blocks =
                Recording::new(finalized_blocks, |block: &Arc<B>| Arc::as_ptr(block).addr());
            let ops = finalized_blocks.ops();
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                test_config(
                    &context,
                    PARTITION_PREFIX,
                    ConstantProvider::new(schemes[0].clone()),
                    NZUsize!(1),
                ),
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::default();
            let buffer = RecordingBuffer::default();
            let _actor_handle =
                actor.start(application.clone(), buffer.clone(), (resolver_rx, resolver));

            // Genesis is dispatched from the archive and acknowledged on
            // delivery, so the pipeline is idle before the finalization arrives.
            while !application.blocks().contains_key(&Height::zero()) {
                reschedule().await;
            }

            // Finalize a block the buffer serves.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            buffer.insert(block.clone());
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            while !application.blocks().contains_key(&Height::new(1)) {
                reschedule().await;
            }

            let delivered = application
                .blocks()
                .get(&Height::new(1))
                .cloned()
                .expect("finalized block dispatched");
            assert_eq!(delivered.digest(), block.digest());
            assert!(
                buffer
                    .last_handed()
                    .and_then(|handed| handed.upgrade())
                    .is_some_and(|handed| Arc::ptr_eq(&handed, &delivered)),
                "dispatch must deliver the block object the buffer handed to marshal"
            );
            let ops = ops.lock();
            let written = ops
                .iter()
                .position(|op| matches!(op, Op::Put(height, _) if *height == Height::new(1)))
                .expect("finalized block written");
            assert_eq!(
                ops[written],
                Op::Put(Height::new(1), Arc::as_ptr(&delivered).addr()),
                "storage must share the block payload dispatched to the application"
            );
            assert!(
                !ops[written..].contains(&Op::Get(Some(Height::new(1)))),
                "dispatch must not read the finalized block back from the archive: {ops:?}"
            );
        });
    }

    fn staged_dispatch_deduplicates_finalizations(preexisting: bool) {
        const PARTITION_PREFIX: &str = "staged-dedup";
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            let (finalizations_by_height, mut finalized_blocks) =
                prunable_finalized_stores(&context, PARTITION_PREFIX).await;
            if preexisting {
                finalized_blocks = finalized_blocks
                    .put_sync(
                        block.height().get(),
                        block.digest(),
                        &Arc::new(block.clone()),
                    )
                    .await
                    .unwrap();
            }
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                test_config(
                    &context,
                    PARTITION_PREFIX,
                    ConstantProvider::new(schemes[0].clone()),
                    NZUsize!(1),
                ),
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::manual_ack();
            let buffer = RecordingBuffer::default();
            let _actor_handle =
                actor.start(application.clone(), buffer.clone(), (resolver_rx, resolver));

            // Hold genesis so both finalizations precede dispatch at height one
            while application.pending_ack_heights() != vec![Height::zero()] {
                reschedule().await;
            }

            // Repeated finalizations retain the first staged object
            buffer.insert(block.clone());
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    block.digest(),
                ),
                &schemes,
                QUORUM,
            );
            let mut handed = Vec::new();
            for _ in 0..2 {
                StandardHarness::report_finalization(&mut mailbox, finalization.clone()).await;

                // A served read proves the preceding finalization arm has run
                let archived = mailbox.get_block(Height::new(1)).await.unwrap();
                assert_eq!(archived.digest(), block.digest());
                handed.push(
                    buffer
                        .last_handed()
                        .expect("buffer must have served the finalized block"),
                );
            }
            assert!(
                handed[0].upgrade().is_some(),
                "the first buffered object must remain staged even if already archived"
            );
            assert!(
                handed[1].upgrade().is_none(),
                "a duplicate finalization must not replace the staged object"
            );

            assert_eq!(application.acknowledged().await, Height::zero());
            while !application.blocks().contains_key(&Height::new(1)) {
                reschedule().await;
            }
            let delivered = application.blocks()[&Height::new(1)].clone();
            assert!(
                handed[0]
                    .upgrade()
                    .is_some_and(|block| Arc::ptr_eq(&block, &delivered)),
                "dispatch must reuse the first staged object"
            );
            let archived = mailbox.get_block(Height::new(1)).await.unwrap();
            assert_eq!(
                delivered.digest(),
                archived.digest(),
                "dispatch must deliver the block retained by the archive"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_staged_dispatch_deduplicates_finalizations() {
        staged_dispatch_deduplicates_finalizations(false);
    }

    #[test_traced("WARN")]
    fn test_standard_staged_dispatch_deduplicates_preexisting_block() {
        staged_dispatch_deduplicates_finalizations(true);
    }

    /// Staging retains at most twice the ack capacity until dispatch or a floor skips the blocks.
    fn staged_blocks_bounded(skip_to_floor: bool) {
        const PARTITION_PREFIX: &str = "staged-bounded";
        const ANCHOR_HEIGHT: u64 = 5;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let (finalizations_by_height, finalized_blocks) =
                prunable_finalized_stores(&context, PARTITION_PREFIX).await;
            let finalized_blocks =
                Recording::new(finalized_blocks, |block: &Arc<B>| Arc::as_ptr(block).addr());
            let ops = finalized_blocks.ops();
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                test_config(
                    &context,
                    PARTITION_PREFIX,
                    ConstantProvider::new(schemes[0].clone()),
                    NZUsize!(1),
                ),
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::manual_ack();
            let buffer = RecordingBuffer::default();
            let _actor_handle =
                actor.start(application.clone(), buffer.clone(), (resolver_rx, resolver));

            // Hold the genesis acknowledgement so nothing else can dispatch
            while application.pending_ack_heights() != vec![Height::zero()] {
                reschedule().await;
            }

            // Build a chain whose tip is the floor anchor
            let mut parent = StandardHarness::genesis_block(NUM_VALIDATORS as u16).digest();
            let mut chain = Vec::new();
            for i in 1..=ANCHOR_HEIGHT {
                let block = make_raw_block(parent, Height::new(i), i);
                parent = block.digest();
                chain.push(block);
            }

            // Two blocks fit in staging. A third must not displace either.
            let mut handed = Vec::new();
            for block in &chain[..3] {
                let height = block.height();
                let round = Round::new(Epoch::zero(), View::new(height.get()));
                buffer.insert(block.clone());
                let finalization = StandardHarness::make_finalization(
                    Proposal::new(round, View::new(height.get() - 1), block.digest()),
                    &schemes,
                    QUORUM,
                );
                StandardHarness::report_finalization(&mut mailbox, finalization).await;

                // A served read proves the preceding finalization arm has run
                assert!(mailbox.get_block(height).await.is_some());
                handed.push(
                    buffer
                        .last_handed()
                        .expect("buffer must have served the finalized block"),
                );
            }
            assert!(
                handed[..2].iter().all(|block| block.upgrade().is_some()),
                "staging must retain two blocks without evicting either on overflow"
            );
            assert!(
                handed[2].upgrade().is_none(),
                "staging must stop at twice the pending-ack capacity"
            );
            assert_eq!(application.pending_ack_heights(), vec![Height::zero()]);

            if skip_to_floor {
                // A floor anchor releases the blocks it skips
                let anchor = chain.last().unwrap();
                let anchor_round = Round::new(Epoch::zero(), View::new(ANCHOR_HEIGHT));
                buffer.insert(anchor.clone());
                let finalization = StandardHarness::make_finalization(
                    Proposal::new(anchor_round, View::new(ANCHOR_HEIGHT - 1), anchor.digest()),
                    &schemes,
                    QUORUM,
                );
                mailbox.set_floor(finalization);
                while !application
                    .blocks()
                    .contains_key(&Height::new(ANCHOR_HEIGHT))
                {
                    reschedule().await;
                }
                assert!(
                    handed.iter().all(|block| block.upgrade().is_none()),
                    "floor transition must release skipped staged blocks"
                );
                for block in &chain[..3] {
                    assert!(!application.blocks().contains_key(&block.height()));
                }
            } else {
                // Drain the backlog: only the overflow block needs an archive read
                ops.lock().clear();
                for height in 0..=3 {
                    assert_eq!(application.acknowledged().await, Height::new(height));
                }
                let ops = ops.lock();
                for height in 1..=3 {
                    let reads = ops
                        .iter()
                        .filter(|op| **op == Op::Get(Some(Height::new(height))))
                        .count();
                    assert_eq!(reads, usize::from(height == 3), "archive reads at {height}");
                }
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_staged_blocks_bounded_drain() {
        staged_blocks_bounded(false);
    }

    #[test_traced("WARN")]
    fn test_standard_staged_blocks_bounded_floor() {
        staged_blocks_bounded(true);
    }

    /// Repeated finalization of an in-flight block must not consume staging capacity.
    #[test_traced("WARN")]
    fn test_standard_does_not_restage_dispatched_block() {
        const PARTITION_PREFIX: &str = "restaged-ack";
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let (finalizations_by_height, finalized_blocks) =
                prunable_finalized_stores(&context, PARTITION_PREFIX).await;
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                test_config(
                    &context,
                    PARTITION_PREFIX,
                    ConstantProvider::new(schemes[0].clone()),
                    NZUsize!(1),
                ),
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::manual_ack();
            let buffer = RecordingBuffer::default();
            let _actor_handle =
                actor.start(application.clone(), buffer.clone(), (resolver_rx, resolver));
            assert_eq!(application.acknowledged().await, Height::zero());

            // Finalize block 1 and hold its acknowledgement once dispatched.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            buffer.insert(block.clone());
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, finalization.clone()).await;
            while application.pending_ack_heights() != vec![Height::new(1)] {
                reschedule().await;
            }

            // The block is already in flight, so another finalization needs no retained copy
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            // Mailbox messages are FIFO, so a served read proves the
            // finalization arm has run.
            assert!(
                mailbox.get_block(Height::new(1)).await.is_some(),
                "finalized block must be stored"
            );
            let repeated = buffer
                .last_handed()
                .expect("buffer must have served the finalized block again");
            assert_eq!(application.pending_ack_heights(), vec![Height::new(1)]);
            assert!(
                repeated.upgrade().is_none(),
                "an already-dispatched block must not consume staging capacity"
            );
        });
    }

    /// Parse the `processed_height` gauge value from a prometheus-encoded
    /// metrics dump produced by `Metrics::encode`. Looks for any line of the
    /// form `<prefix>processed_height <value>` or
    /// `<prefix>processed_height{labels} <value>`.
    fn parse_processed_height(metrics: &str) -> Option<u64> {
        for line in metrics.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }

            let Some(idx) = line.find("processed_height") else {
                continue;
            };
            let mut rest = &line[idx + "processed_height".len()..];
            if let Some(labeled) = rest.strip_prefix('{') {
                let Some(labels_end) = labeled.find('}') else {
                    continue;
                };
                rest = &labeled[labels_end + 1..];
            }
            if rest.chars().next().is_some_and(char::is_whitespace) {
                let value = rest.split_whitespace().next()?;
                return value.parse().ok();
            }
        }
        None
    }

    /// Regression test for the [`crate::marshal::Update::Block`] pruning
    /// contract.
    ///
    /// Asserts that for every block at height `H` the application has
    /// received, marshal's `processed_height` gauge is at least
    /// `H - max_pending_acks`. Because `processed_height` is monotonic, the
    /// invariant holds at *every* observation point, so the test simply
    /// drives the pipeline (fill, drain, refill) and re-checks the bound
    /// after each step.
    #[test_traced("WARN")]
    fn test_standard_update_block_processed_height_invariant() {
        const MAX_PENDING_ACKS: u64 = 4;
        const NUM_BLOCKS: u64 = 12;

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let validator = participants[0].clone();
            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                validator,
                ConstantProvider::new(schemes[0].clone()),
                NonZeroUsize::new(MAX_PENDING_ACKS as usize).unwrap(),
                application,
            )
            .await;
            let application = setup.application;
            let mut handle = ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            };
            let mut handles = vec![handle.clone()];
            assert_eq!(application.acknowledged().await, Height::zero());

            // Submit finalizations; marshal dispatches up to MAX_PENDING_ACKS
            // blocks at a time and stalls until the application acks.
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            let mut parent = Sha256::hash(&[b""]);
            let mut parent_commitment =
                StandardHarness::genesis_parent_commitment(NUM_VALIDATORS as u16);
            for i in 1..=NUM_BLOCKS {
                let block = StandardHarness::make_test_block(
                    parent,
                    parent_commitment,
                    Height::new(i),
                    i,
                    NUM_VALIDATORS as u16,
                );
                let commitment = StandardHarness::commitment(&block);
                parent = StandardHarness::digest(&block);
                parent_commitment = commitment;
                let round = Round::new(
                    epocher
                        .containing(StandardHarness::height(&block))
                        .unwrap()
                        .epoch(),
                    View::new(i),
                );
                StandardHarness::verify(&mut handle, round, &block, &mut handles).await;
                let proposal = Proposal {
                    round,
                    parent: View::new(i.saturating_sub(1)),
                    payload: commitment,
                };
                let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);
                StandardHarness::report_finalization(&mut handle.mailbox, finalization).await;
            }

            let check_invariant = |label: &str| {
                let Some(highest) = application.blocks().keys().max().copied() else {
                    return;
                };
                let processed = parse_processed_height(&context.encode())
                    .expect("processed_height gauge missing");
                let gap = highest.get().saturating_sub(processed);
                assert!(
                    gap <= MAX_PENDING_ACKS,
                    "{label}: highest={} processed={} gap={} > max_pending_acks={}",
                    highest.get(),
                    processed,
                    gap,
                    MAX_PENDING_ACKS,
                );
            };

            // Wait until marshal has dispatched up to the pipeline limit
            // (we submitted more than MAX_PENDING_ACKS finalizations above,
            // so the pipeline must stall at MAX_PENDING_ACKS unacked blocks).
            // This is the peak-gap observation point.
            while (application.blocks().len() as u64) < MAX_PENDING_ACKS {
                context.sleep(Duration::from_millis(10)).await;
            }
            check_invariant("pipeline full");

            // Drain: acknowledge blocks as they arrive; re-check the bound
            // after each dispatch cycle.
            loop {
                let acked = application.acknowledged().await;
                check_invariant(&format!("after ack {acked}"));
                if acked.get() == NUM_BLOCKS {
                    break;
                }
            }
        });
    }

    /// `Forward` for an unknown commitment must early-return without
    /// dispatching, even when peers are provided.
    #[test_traced("WARN")]
    fn test_standard_forward_unknown_block_is_noop() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let unknown = Sha256::hash(&[b"unknown-block"]);

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("forward-unknown-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            mailbox.forward(
                round,
                unknown,
                Recipients::Some(vec![participants[1].clone()]),
            );
            context.sleep(Duration::from_millis(50)).await;

            assert!(
                buffer.sends().is_empty(),
                "forward for an unknown block must not dispatch"
            );
        });
    }

    /// A block relayed via `Proposed` must be dispatched to the buffer and
    /// persisted, with the sync handle resolving durable. A subsequent
    /// `Forward` for the same `(round, commitment)` serves the persisted
    /// block from storage.
    #[test_traced("WARN")]
    fn test_standard_proposed_broadcasts_then_persists() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("proposed-cache-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            let targets = vec![participants[1].clone()];
            let (ack, persist) = oneshot::channel();
            mailbox.proposed(round, block.clone(), Recipients::Some(targets.clone()), ack);
            wait_until(&context, Duration::from_secs(5), "proposed send", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1, "proposal must dispatch exactly once");
            assert_eq!(sends[0].0, round);
            assert_eq!(sends[0].1.digest(), digest);

            // The message persists the block after broadcasting it, so the
            // sync handle must resolve durable.
            let sync = persist.await.expect("proposed sync handle missing");
            assert!(sync.durable(round, "proposed").await);

            // A forward for the same commitment must serve the persisted
            // block from storage.
            mailbox.forward(round, digest, Recipients::Some(targets));
            wait_until(&context, Duration::from_secs(5), "forward send", || {
                buffer.sends.lock().len() >= 2
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 2);
            assert_eq!(sends[1].1.digest(), digest);
        });
    }

    /// A propose relay that finds no staged proposal must fall back to
    /// forwarding the persisted block. Staging then flushing at certify (the
    /// recovered-leader race) persists the block and resolves the
    /// certification gate through the staged ack, so the subsequent relay
    /// broadcast re-sends the block from storage instead of dropping it.
    #[test_traced("WARN")]
    fn test_standard_propose_relay_miss_forwards_persisted_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("relay-miss-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            // Stage the proposal as propose would, then flush it as certify
            // does when certification wins the race against the relay.
            let gates = Gates::new();
            let (tx, rx) = oneshot::channel();
            context.child("stager").spawn({
                let gates = gates.clone();
                let block = block.clone();
                move |_| async move {
                    gates
                        .stage(round, digest, Arc::new(block), tx, "test")
                        .await;
                }
            });
            assert_eq!(rx.await.expect("id published"), digest);
            let gate = gates.take(round, digest).expect("gate registered");
            gates.flush_unrelayed(&mailbox, round, digest);
            assert_eq!(
                gate.await.expect("gate resolved"),
                GateOutcome::Ready(true),
                "certify flush must resolve the gate durably",
            );

            // The relay finds nothing staged and must forward the persisted
            // block instead of dropping the broadcast.
            let feedback = relay::broadcast(&gates, &mailbox, digest, Plan::Propose { round });
            assert!(matches!(feedback, Feedback::Ok));
            wait_until(&context, Duration::from_secs(5), "fallback send", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1, "fallback must dispatch exactly once");
            assert_eq!(sends[0].0, round);
            assert_eq!(sends[0].1.digest(), digest);
            assert!(matches!(sends[0].2, Recipients::All));
        });
    }

    /// A propose relay with a staged proposal must dispatch it through the
    /// `Proposed` message and complete the durability handshake. The block is
    /// never persisted beforehand, so the forward fallback has nothing to
    /// serve: only the staged-hit path can produce the send.
    #[test_traced("WARN")]
    fn test_standard_propose_relay_sends_staged_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("relay-hit-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            // Stage the proposal as propose would.
            let gates = Gates::new();
            let (tx, rx) = oneshot::channel();
            context.child("stager").spawn({
                let gates = gates.clone();
                let block = block.clone();
                move |_| async move {
                    gates
                        .stage(round, digest, Arc::new(block), tx, "test")
                        .await;
                }
            });
            assert_eq!(rx.await.expect("id published"), digest);
            let gate = gates.take(round, digest).expect("gate registered");

            // The relay must take the staged proposal and dispatch it.
            let feedback = relay::broadcast(&gates, &mailbox, digest, Plan::Propose { round });
            assert!(matches!(feedback, Feedback::Ok));
            wait_until(&context, Duration::from_secs(5), "staged send", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1, "staged proposal must dispatch exactly once");
            assert_eq!(sends[0].0, round);
            assert_eq!(sends[0].1.digest(), digest);
            assert!(matches!(sends[0].2, Recipients::All));
            assert!(
                gates.take_staged(round, digest).is_none(),
                "relay must consume the staged proposal"
            );

            // The relayed proposal is persisted through the staged ack, so
            // the certification gate resolves durably.
            assert_eq!(
                gate.await.expect("gate resolved"),
                GateOutcome::Ready(true),
                "relay handshake must resolve the gate durably",
            );
        });
    }

    /// A proposer that relays conflicting blocks for the same round must not
    /// be blocked by its own conflict: a leader that crashes after the send
    /// may legitimately propose a different block for the round after
    /// restart. The verified archive stores candidates with multi-put
    /// semantics, so both `Proposed` handshakes must broadcast and resolve
    /// durable.
    #[test_traced("WARN")]
    fn test_standard_proposed_conflicting_blocks_both_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block_a = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let block_b = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 200);
            assert_ne!(block_a.digest(), block_b.digest());

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("proposed-conflict-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            let (ack_a, persist_a) = oneshot::channel();
            mailbox.proposed(round, block_a.clone(), Recipients::All, ack_a);
            let (ack_b, persist_b) = oneshot::channel();
            mailbox.proposed(round, block_b.clone(), Recipients::All, ack_b);

            let sync_a = persist_a.await.expect("first proposed sync handle missing");
            assert!(sync_a.durable(round, "proposed").await);
            let sync_b = persist_b
                .await
                .expect("second proposed sync handle missing");
            assert!(sync_b.durable(round, "proposed").await);

            let sends = buffer.sends();
            assert_eq!(sends.len(), 2, "both conflicting proposals must dispatch");
            assert_eq!(sends[0].1.digest(), block_a.digest());
            assert_eq!(sends[1].1.digest(), block_b.digest());
        });
    }

    /// `Forward` for a block that marshal has cached must dispatch that block
    /// to exactly the provided peer set via the buffer.
    #[test_traced("WARN")]
    fn test_standard_forward_cached_block_sends_to_peers() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("forward-cached-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            assert!(mailbox.verified(round, block.clone()).await);

            let targets = vec![participants[1].clone(), participants[2].clone()];
            mailbox.forward(round, digest, Recipients::Some(targets.clone()));
            wait_until(&context, Duration::from_secs(5), "buffer.send", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1);
            let (sent_round, sent_block, sent_recipients) = &sends[0];
            assert_eq!(*sent_round, round);
            assert_eq!(sent_block.digest(), digest);
            match sent_recipients {
                Recipients::Some(peers) => assert_eq!(peers, &targets),
                other => panic!("expected Recipients::Some, got {other:?}"),
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_rejected_overflow_prune_preserves_canonical_waiters() {
        for prune_first in [true, false] {
            deterministic::Runner::timed(Duration::from_secs(30)).start(
                move |mut context| async move {
                    const PREFIX: &str = "rejected-overflow-prune";
                    let Fixture { schemes, .. } =
                        bls12381_threshold_vrf::fixture::<V, _>(
                            &mut context, NAMESPACE, NUM_VALIDATORS,
                        );
                    let (finalizations, blocks) =
                        prunable_finalized_stores(&context, PREFIX).await;
                    let mut config = test_config(
                        &context,
                        PREFIX,
                        ConstantProvider::new(schemes[0].clone()),
                        NZUsize!(1),
                    );
                    config.mailbox_size = NZUsize!(1);
                    let (actor, mut mailbox, floor) = Actor::<_, Standard<B>, _, _, _, _, _>::init(
                        context.child("actor"), finalizations, blocks, config,
                    ).await;
                    assert_eq!(floor.height(), None);

                    let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
                    let height = Height::new(1);
                    let round = Round::new(Epoch::zero(), View::new(1));
                    let block = make_raw_block(genesis.digest(), height, 100);
                    let finalization = StandardHarness::make_finalization(
                        Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                        &schemes,
                        QUORUM,
                    );

                    // The actor has not started, so this live request fills ready capacity.
                    let ready = mailbox.acquire(genesis.digest());
                    if prune_first {
                        mailbox.prune(Height::new(10));
                    }
                    let mut direct = mailbox.finalized(height);
                    let source = mailbox.blocks(height, Arc::from([]));
                    let mut range = source.range(height..=height);
                    let mut read = Box::pin(range.next());
                    let early = read.as_mut().now_or_never();
                    let mut canceled = mailbox.finalized(Height::new(10));
                    assert!(matches!(canceled.try_recv(), Err(TryRecvError::Empty)));
                    drop(canceled);
                    if !prune_first {
                        mailbox.prune(Height::new(10));
                    }

                    let (resolver_rx, resolver) =
                        RecordingResolver::holding(context.child("resolver"));
                    let _actor = actor.start_unbuffered(
                        Application::<B>::manual_ack(),
                        (resolver_rx, resolver),
                    );

                    // This read follows the overflowed prune in the actor mailbox.
                    assert!(mailbox.get_verified(round).await.is_none());
                    assert_eq!(ready.await.unwrap().digest(), genesis.digest());
                    assert_eq!(mailbox.get_processed_height().await, None);
                    assert_eq!(
                        mailbox.get_block(Height::zero()).await.unwrap().digest(),
                        genesis.digest(),
                    );
                    assert!(mailbox.get_block(height).await.is_none());
                    assert!(mailbox.get_finalization(height).await.is_none());
                    let direct_before = direct.try_recv();
                    let canonical_before = early.or_else(|| read.as_mut().now_or_never());

                    assert!(mailbox.verified(round, block.clone()).await);
                    assert!(mailbox.get_block(height).await.is_none());
                    StandardHarness::report_finalization(&mut mailbox, finalization).await;
                    assert_eq!(
                        mailbox.get_finalization(height).await.unwrap().proposal.payload,
                        block.digest(),
                    );
                    assert_eq!(
                        mailbox.get_block(height).await.unwrap().digest(),
                        block.digest(),
                    );
                    assert_eq!(mailbox.get_processed_height().await, None);

                    assert!(
                        canonical_before.is_none(),
                        "canonical request terminated before finalization (prune_first={prune_first}): {canonical_before:?}",
                    );
                    assert!(
                        matches!(direct_before, Err(TryRecvError::Empty)),
                        "live finalized waiter closed before finalization (prune_first={prune_first})",
                    );
                    assert_eq!(direct.await.unwrap().digest(), block.digest());
                    assert_eq!(read.await.unwrap().unwrap().digest(), block.digest());
                    assert!(range.next().await.is_none());
                },
            );
        }
    }

    /// `Prune` for a height above the floor must be rejected (warn + continue)
    /// and must not advance the floor or alter the finalized archive contents.
    #[test_traced("WARN")]
    fn test_standard_prune_above_floor_is_rejected() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(&[b""]), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            let (mut mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("prune-above-floor-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
            )
            .await;

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            while mailbox.get_finalization(Height::new(1)).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Prune above the floor must be a no-op, not an error.
            mailbox.prune(Height::new(100));
            context.sleep(Duration::from_millis(50)).await;

            // The finalized block and its finalization must still be retrievable.
            assert!(mailbox.get_block(Height::new(1)).await.is_some());
            assert!(mailbox.get_finalization(Height::new(1)).await.is_some());
        });
    }
}
