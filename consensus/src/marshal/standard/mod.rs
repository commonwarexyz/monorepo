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

    mod validation;
});

mod variant;
pub use variant::Standard;

#[cfg(test)]
mod tests {
    use super::{Deferred, Inline, Standard};
    use crate::{
        marshal::{
            ancestry::BlockProvider,
            config::{Config, Start},
            core::{cache, Actor, CommitmentFallback, Mailbox},
            mocks::{
                application::Application,
                harness::{
                    self, default_leader, make_raw_block, setup_network_links,
                    setup_network_with_participants, Ctx, DeferredHarness, EmptyProvider,
                    InlineHarness, StandardHarness, TestHarness, ValidatorHandle, B,
                    BLOCKS_PER_EPOCH, D, LINK, NAMESPACE, NUM_VALIDATORS, PAGE_CACHE_SIZE,
                    PAGE_SIZE, QUORUM, S, UNRELIABLE_LINK, V,
                },
                verifying::MockVerifyingApp,
            },
            resolver::handler,
            Identifier, Update,
        },
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
            types::{Finalization, Proposal},
        },
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
        Automaton, CertifiableAutomaton, Heightable, Reporter,
    };
    use bytes::Bytes;
    use commonware_actor::{mailbox, Feedback};
    use commonware_broadcast::buffered;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
        ed25519::PublicKey,
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::{
        simulated::{self, Network},
        Manager as _, Recipients,
    };
    use commonware_parallel::Sequential;
    use commonware_resolver::{Consumer, Delivery, Fetch, Resolver};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock, Metrics, Quota, Runner, Supervisor as _,
    };
    use commonware_storage::{
        archive::{immutable, prunable, Archive as _},
        metadata::{self, Metadata},
        translator::{EightCap, TwoCap},
    };
    use commonware_utils::{
        acknowledgement::Exact,
        channel::{fallible::OneshotExt, oneshot, oneshot::error::TryRecvError},
        ordered::Set,
        sync::Mutex,
        vec::NonEmptyVec,
        NZUsize, NZU16, NZU64,
    };
    use std::{
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };

    #[test]
    fn mailbox_provides_application_blocks() {
        fn assert_provider<P: BlockProvider<Block = B>>() {}
        assert_provider::<Mailbox<S, Standard<B>>>();
    }

    #[test_traced("WARN")]
    fn test_standard_block_provider_parent_fetches_by_commitment() {
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
                buffer,
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let parent = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let child = make_raw_block(parent.digest(), Height::new(2), 200);
            let subscription = mailbox.subscribe_parent(&child);

            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                buffer.commitment_subscription_count(),
                1,
                "parent walkback should use the standard parent commitment"
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
    fn test_standard_commitment_fetch_height_hint_mismatch_wakes_subscriber() {
        harness::commitment_fetch_height_hint_mismatch_wakes_subscriber::<InlineHarness>();
        harness::commitment_fetch_height_hint_mismatch_wakes_subscriber::<DeferredHarness>();
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
            finalized_blocks
                .put(block.height().get(), block.digest(), block.clone())
                .await
                .expect("failed to seed finalized block");
        }
        finalized_blocks
            .sync()
            .await
            .expect("failed to sync seeded finalized blocks");

        for (height, finalization) in finalizations {
            finalizations_by_height
                .put(
                    height.get(),
                    finalization.proposal.payload,
                    finalization.clone(),
                )
                .await
                .expect("failed to seed finalization");
        }
        finalizations_by_height
            .sync()
            .await
            .expect("failed to sync seeded finalizations");
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
        let mut notarized: prunable::Archive<TwoCap, deterministic::Context, D, B> =
            prunable::Archive::init(
                context.child("seed_notarized"),
                prunable::Config {
                    translator: TwoCap,
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
            .put_sync(view.get(), block.digest(), block.clone())
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
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
                Some(block_two.clone()),
                "block without a finalization row should still be queryable by height"
            );

            // Walk the application through sequential acks. Even though
            // block_two has no finalization, it is still dispatched because
            // its block data exists in the archive.
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
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
            let mut parent = Sha256::hash(b"");
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

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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

            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Write a block into the cache.
            {
                let mut mgr = cache::Manager::<_, Standard<B>, S>::init(
                    context.child("write"),
                    make_cfg(),
                    (),
                )
                .await;
                mgr.put_block(round, digest, block.clone()).await;
            }

            // Re-init the cache (simulating restart). find_block should fail
            // before loading persisted epochs.
            let mut mgr =
                cache::Manager::<_, Standard<B>, S>::init(context.child("read"), make_cfg(), ())
                    .await;
            assert_eq!(
                mgr.find_block(digest).await,
                None,
                "cache should not find block before loading persisted epochs"
            );

            mgr.load_persisted_epochs().await;
            assert_eq!(
                mgr.find_block(digest).await,
                Some(block),
                "cache should find block after loading persisted epochs"
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
    fn test_standard_hint_finalized_triggers_fetch() {
        harness::hint_finalized_triggers_fetch::<InlineHarness>();
        harness::hint_finalized_triggers_fetch::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_ancestry_stream() {
        harness::ancestry_stream::<InlineHarness>();
        harness::ancestry_stream::<DeferredHarness>();
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

        async fn propose(&mut self, context: Ctx) -> oneshot::Receiver<D> {
            match self {
                Self::Inline(inline) => inline.propose(context).await,
                Self::Deferred(deferred) => deferred.propose(context).await,
            }
        }

        async fn verify(&mut self, context: Ctx, digest: D) -> oneshot::Receiver<bool> {
            match self {
                Self::Inline(inline) => inline.verify(context, digest).await,
                Self::Deferred(deferred) => deferred.verify(context, digest).await,
            }
        }

        async fn certify(&mut self, round: Round, digest: D) -> oneshot::Receiver<bool> {
            match self {
                Self::Inline(inline) => inline.certify(round, digest).await,
                Self::Deferred(deferred) => deferred.certify(round, digest).await,
            }
        }
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
                    .verify(block_context, digest)
                    .await
                    .await
                    .expect("verify result missing");
                assert!(
                    verify_result,
                    "{kind:?}: height-1 block should verify with genesis as parent"
                );

                let certify_result = wrapper
                    .certify(round, digest)
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
    fn test_standard_verify_missing_candidate_waits_without_fetching() {
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let (marshal, buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("missing-candidate-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    RecordingBuffer::default(),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                )
                .await;
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let round = Round::new(Epoch::zero(), View::new(1));
                let consensus_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::zero(), genesis.digest()),
                };
                let missing = Sha256::hash(b"missing candidate");
                let mut verify = wrapper.verify(consensus_context, missing).await;

                context.sleep(Duration::from_millis(50)).await;
                assert!(
                    buffer.subscription_count() > 0,
                    "{kind:?}: unavailable candidate verification must register a local wait"
                );
                assert!(
                    resolver.fetches().is_empty(),
                    "{kind:?}: unavailable candidate verification must not fetch from peers"
                );
                assert!(
                    resolver.targeted_is_empty(),
                    "{kind:?}: unavailable candidate verification must not issue targeted fetches"
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
                    resolver.fetches().is_empty(),
                    "{kind:?}: canceling a missing candidate wait must not fetch from peers"
                );
            });
        }
    }

    #[test_traced("WARN")]
    fn test_standard_certify_missing_candidate_fetches_by_round() {
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let (marshal, buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("missing-certify-candidate-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    RecordingBuffer::default(),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                )
                .await;
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
                let proposal = Proposal::new(round, View::zero(), digest);
                let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);
                resolver.respond_to_next_fetch((notarization, block).encode());
                let certify = wrapper.certify(round, digest).await;

                let result = certify.await.expect("certify result missing");
                assert!(
                    result,
                    "{kind:?}: fetched notarized candidate should certify"
                );
                assert!(
                    resolver.wait_for_delivery_response().await,
                    "{kind:?}: notarized delivery should validate"
                );
                assert!(
                    resolver.fetches().iter().any(|fetch| matches!(
                        (&fetch.key, &fetch.subscriber),
                        (
                            handler::Key::Notarized { round: request_round },
                            handler::Annotation::Notarization { round: subscriber_round },
                        ) if *request_round == round && *subscriber_round == round
                    )),
                    "{kind:?}: certify should fetch notarized block by round"
                );

                assert!(
                    buffer.subscription_count() > 0,
                    "{kind:?}: unavailable candidate certification must register a local wait"
                );
                assert!(
                    resolver.targeted_is_empty(),
                    "{kind:?}: certification must not issue targeted fetches"
                );
            });
        }
    }

    /// Regression for `Deferred::certify`'s `hint_notarized` bump. When `verify`
    /// has an in-progress task with the block still missing locally, `certify`
    /// must take that task AND nudge a round-bound notarized fetch; otherwise
    /// the shared task would wait forever on a local subscription that nothing
    /// drives. Removing the `hint_notarized` call makes this test hang.
    #[test_traced("WARN")]
    fn test_standard_deferred_certify_bumps_notarized_fetch_for_pending_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let (marshal, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "deferred-certify-bumps-fetch",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
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

            // `verify` registers a pending verification task; the optimistic
            // task's `Wait` block subscription cannot pull from peers, so it
            // stays parked until something delivers the block locally.
            let verify_rx = wrapper.verify(block_context, digest).await;

            // Stage the notarized response so the bump's fetch can resolve.
            let proposal = Proposal::new(round, View::zero(), digest);
            let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);
            resolver.respond_to_next_fetch((notarization, block).encode());

            // `certify` takes the in-progress task and calls `hint_notarized`,
            // which issues a round-bound `Key::Notarized`. The recording
            // resolver delivers; the marshal stores the block and wakes
            // verify's digest subscription; deferred_verify produces the final
            // verdict shared by both receivers.
            let certify_rx = wrapper.certify(round, digest).await;

            select! {
                result = verify_rx => {
                    assert!(
                        result.expect("verify resolves"),
                        "optimistic verify should accept fetched block"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify must resolve after the notarized fetch delivers the block");
                },
            }
            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify resolves"),
                        "certify should succeed via the shared deferred_verify task"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should resolve via the bumped notarized fetch");
                },
            }

            assert!(
                resolver.fetches().iter().any(|fetch| matches!(
                    (&fetch.key, &fetch.subscriber),
                    (
                        handler::Key::Notarized { round: request_round },
                        handler::Annotation::Notarization { round: subscriber_round },
                    ) if *request_round == round && *subscriber_round == round
                )),
                "certify must bump a notarized round fetch when verify is in progress"
            );
        });
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

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let (marshal, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "deferred-certify-canceled-verify",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
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

            let verify_rx = wrapper.verify(block_context, digest).await;
            drop(verify_rx);
            context.sleep(Duration::from_millis(10)).await;

            let proposal = Proposal::new(round, View::zero(), digest);
            let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);
            resolver.respond_to_next_fetch((notarization, block).encode());
            let certify_rx = wrapper.certify(round, digest).await;

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
                "notarized delivery should validate"
            );
            assert!(
                resolver.fetches().iter().any(|fetch| matches!(
                    (&fetch.key, &fetch.subscriber),
                    (
                        handler::Key::Notarized { round: request_round },
                        handler::Annotation::Notarization { round: subscriber_round },
                    ) if *request_round == round && *subscriber_round == round
                )),
                "certify must recover by fetching the notarized round"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_verify_height_lie_parent_fetch_is_round_bound() {
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let (marshal, _buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("height-lie-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    RecordingBuffer::default(),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
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

                let verify = wrapper.verify(child_context, child_digest).await;
                wait_until(
                    &context,
                    Duration::from_secs(5),
                    "round-bound parent fetch",
                    || {
                        resolver.fetches().iter().any(|fetch| {
                            matches!(
                                fetch.key,
                                handler::Key::Notarized { round } if round == parent_round
                            ) && matches!(
                                fetch.subscriber,
                                handler::Annotation::Notarization { round }
                                    if round == parent_round
                            )
                        })
                    },
                )
                .await;

                let fetches = resolver.fetches();
                assert!(
                    fetches.iter().all(|fetch| {
                        !matches!(fetch.key, handler::Key::Block(_))
                            && !matches!(
                                fetch.subscriber,
                                handler::Annotation::Certified { height }
                                    if height == Height::new(2)
                            )
                    }),
                    "{kind:?}: malicious child height must not drive parent fetches"
                );

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
                    let certify = wrapper.certify(child_round, child_digest).await;
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
                            handler::Key::Notarized {
                                round: parent_round,
                            },
                            Bytes::from_static(b"not a valid notarization"),
                        ),
                        mailbox_size: NZUsize!(100),
                        me: Some(malicious.clone()),
                        initial: Duration::from_secs(1),
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
                let verify = wrapper.verify(child_context, child_digest).await;
                let verify_or_certify = if kind == WrapperKind::Deferred {
                    let optimistic = verify.await.expect("verify result missing");
                    assert!(optimistic, "deferred verify should optimistically succeed");
                    wrapper.certify(child_round, child_digest).await
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
                let proposal_rx = wrapper.propose(non_boundary_context).await;
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
                let boundary_round = Round::new(Epoch::zero(), View::new(boundary_height.get()));
                let boundary_block = B::new::<Sha256>(
                    Ctx {
                        round: boundary_round,
                        leader: default_leader(),
                        parent: (View::zero(), genesis.digest()),
                    },
                    genesis.digest(),
                    boundary_height,
                    1900,
                );
                let boundary_digest = boundary_block.digest();
                assert!(
                    marshal
                        .clone()
                        .verified(boundary_round, boundary_block.clone())
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                let reproposal_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(boundary_height.get() + 1)),
                    leader: me,
                    parent: (View::new(boundary_height.get()), boundary_digest),
                };
                let reproposal_rx = wrapper.propose(reproposal_context).await;
                assert_eq!(
                    reproposal_rx.await.expect("reproposal result missing"),
                    boundary_digest,
                    "{kind:?}: epoch-boundary proposal should re-propose parent digest"
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
                let boundary_round = Round::new(Epoch::zero(), View::new(boundary_height.get()));
                let boundary_block = B::new::<Sha256>(
                    Ctx {
                        round: boundary_round,
                        leader: default_leader(),
                        parent: (View::zero(), genesis.digest()),
                    },
                    genesis.digest(),
                    boundary_height,
                    1900,
                );
                let boundary_digest = boundary_block.digest();
                assert!(
                    marshal
                        .clone()
                        .verified(boundary_round, boundary_block)
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                // Valid re-proposal: boundary block in the same epoch.
                let valid_reproposal_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(boundary_height.get() + 1)),
                    leader: me.clone(),
                    parent: (View::new(boundary_height.get()), boundary_digest),
                };
                assert!(
                    wrapper
                        .verify(valid_reproposal_context, boundary_digest)
                        .await
                        .await
                        .expect("verify result missing"),
                    "{kind:?}: boundary re-proposal should be accepted"
                );

                // Invalid re-proposal: non-boundary block.
                let non_boundary_height = Height::new(10);
                let non_boundary_round =
                    Round::new(Epoch::zero(), View::new(non_boundary_height.get()));
                let non_boundary_block = B::new::<Sha256>(
                    Ctx {
                        round: non_boundary_round,
                        leader: default_leader(),
                        parent: (View::zero(), genesis.digest()),
                    },
                    genesis.digest(),
                    non_boundary_height,
                    1000,
                );
                let non_boundary_digest = non_boundary_block.digest();
                assert!(
                    marshal
                        .clone()
                        .verified(non_boundary_round, non_boundary_block)
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                // Attempt to re-propose a non-boundary block.
                let invalid_reproposal_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(15)),
                    leader: me.clone(),
                    parent: (View::new(non_boundary_height.get()), non_boundary_digest),
                };
                assert!(
                    !wrapper
                        .verify(invalid_reproposal_context, non_boundary_digest)
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
                        .verify(cross_epoch_context, boundary_digest)
                        .await
                        .await
                        .expect("verify result missing"),
                    "{kind:?}: cross-epoch re-proposal should be rejected"
                );

                if wrapper.kind() == WrapperKind::Deferred {
                    // Deferred-only crash-recovery path: certify without prior verify.
                    let certify_only_round = Round::new(Epoch::zero(), View::new(21));
                    let certify_result = wrapper
                        .certify(certify_only_round, boundary_digest)
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
                    .verify(malformed_context.clone(), malformed_digest)
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
                    let certify = wrapper.certify(malformed_round, malformed_digest).await;
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
                    .verify(mismatched_context, mismatched_digest)
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
                    let certify = wrapper.certify(mismatch_round, mismatched_digest).await;
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

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
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
                    .verify(verify_context, digest)
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
                    let certify = wrapper.certify(round, digest).await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should propagate deferred application verification failure"
                    );
                }
            });
        }
    }

    /// Recorded `send` call on the [`RecordingBuffer`].
    type BufferSend = (Round, B, Recipients<PublicKey>);

    /// A buffer that records each `send` invocation, keeps subscriptions open,
    /// and optionally serves locally inserted blocks.
    #[derive(Clone, Default)]
    struct RecordingBuffer {
        blocks: Arc<Mutex<Vec<B>>>,
        digest_subscriptions: Arc<Mutex<Vec<oneshot::Sender<B>>>>,
        commitment_subscriptions: Arc<Mutex<Vec<oneshot::Sender<B>>>>,
        sends: Arc<Mutex<Vec<BufferSend>>>,
    }

    impl RecordingBuffer {
        fn insert(&self, block: B) {
            self.blocks.lock().push(block);
        }

        fn sends(&self) -> Vec<BufferSend> {
            self.sends.lock().clone()
        }

        fn subscription_count(&self) -> usize {
            self.digest_subscriptions.lock().len() + self.commitment_subscriptions.lock().len()
        }

        fn commitment_subscription_count(&self) -> usize {
            self.commitment_subscriptions.lock().len()
        }
    }

    impl crate::marshal::core::Buffer<Standard<B>> for RecordingBuffer {
        type PublicKey = PublicKey;

        async fn find_by_digest(&self, digest: D) -> Option<B> {
            self.blocks
                .lock()
                .iter()
                .find(|block| block.digest() == digest)
                .cloned()
        }

        async fn find_by_commitment(&self, commitment: D) -> Option<B> {
            self.blocks
                .lock()
                .iter()
                .find(|block| block.digest() == commitment)
                .cloned()
        }

        fn subscribe_by_digest(&self, _digest: D) -> oneshot::Receiver<B> {
            let (sender, receiver) = oneshot::channel();
            self.digest_subscriptions.lock().push(sender);
            receiver
        }

        fn subscribe_by_commitment(&self, _commitment: D) -> oneshot::Receiver<B> {
            let (sender, receiver) = oneshot::channel();
            self.commitment_subscriptions.lock().push(sender);
            receiver
        }

        fn finalized(&self, _commitment: D) {}

        fn send(&self, round: Round, block: B, recipients: Recipients<PublicKey>) {
            self.sends.lock().push((round, block, recipients));
        }
    }

    /// Recorded `fetch_targeted` call on the [`RecordingResolver`].
    type TargetedFetch = (handler::Key<D>, NonEmptyVec<PublicKey>);

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
        targeted: Arc<Mutex<Vec<TargetedFetch>>>,
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
                    targeted: Arc::new(Mutex::new(Vec::new())),
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
                    subscribers: NonEmptyVec::new(fetch.subscriber),
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

        fn targeted(&self) -> Vec<TargetedFetch> {
            self.targeted.lock().clone()
        }

        fn targeted_is_empty(&self) -> bool {
            self.targeted.lock().is_empty()
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
        type PublicKey = PublicKey;

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

        fn fetch_targeted(
            &mut self,
            fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback {
            self.targeted.lock().push((fetch.into().key, targets));
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            let mut targeted = self.targeted.lock();
            for (fetch, targets) in fetches {
                targeted.push((fetch.into().key, targets));
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
    }

    impl HoldingBlockReporter {
        fn new() -> (Self, oneshot::Receiver<Height>) {
            let (started_tx, started_rx) = oneshot::channel();
            (
                Self {
                    started: Arc::new(Mutex::new(Some(started_tx))),
                    pending: Arc::new(Mutex::new(Vec::new())),
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

    async fn start_standard_actor<R, Buf>(
        context: deterministic::Context,
        partition_prefix: &str,
        provider: ConstantProvider<S, Epoch>,
        application: R,
        buffer: Buf,
        start: Start<S, D, B>,
    ) -> (
        Mailbox<S, Standard<B>>,
        Buf,
        RecordingResolver,
        commonware_runtime::Handle<()>,
    )
    where
        R: Reporter<Activity = Update<B>>,
        Buf: crate::marshal::core::Buffer<Standard<B>, PublicKey = PublicKey> + Clone,
    {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start,
            mailbox_size: NZUsize!(100),
            view_retention_timeout: ViewDelta::new(10),
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
        let actor_handle =
            actor.start(application, buffer.clone(), (resolver_rx, resolver.clone()));
        (mailbox, buffer, resolver, actor_handle)
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
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
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
                RecordingBuffer::default(),
                Start::Floor(floor_finalization),
            )
            .await;
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
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (application, mut started_rx) = HoldingBlockReporter::new();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "start-floor-async",
                ConstantProvider::new(schemes[0].clone()),
                application,
                RecordingBuffer::default(),
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

            let served = make_raw_block(Sha256::hash(b"served-parent"), Height::new(1), 100);
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
            assert_eq!(started_rx.await.unwrap(), Height::new(6));
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
                make_raw_block(Sha256::hash(b"local-floor-parent"), Height::new(5), 500);
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
                buffer,
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
            assert_eq!(started_rx.await.unwrap(), Height::new(6));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_holds_dispatch_until_anchor_arrives() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (application, mut started_rx) = HoldingBlockReporter::new();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-holds-dispatch",
                ConstantProvider::new(schemes[0].clone()),
                application,
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
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
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: floor_fetch.key,
                        subscribers: NonEmptyVec::new(floor_fetch.subscriber),
                    },
                    value: floor_block.encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx.await.expect("delivery response missing"),
                "floor block delivery should validate"
            );

            assert_eq!(started_rx.await.unwrap(), Height::new(6));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_newer_pending_floor_supersedes_older_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let (application, mut started_rx) = HoldingBlockReporter::new();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-supersedes-pending",
                ConstantProvider::new(schemes[0].clone()),
                application,
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

            let old_floor_round = Round::new(Epoch::zero(), View::new(5));
            let old_floor_block =
                make_raw_block(Sha256::hash(b"old-floor-parent"), Height::new(5), 500);
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
                make_raw_block(Sha256::hash(b"new-floor-parent"), Height::new(7), 700);
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
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: old_floor_fetch.key,
                        subscribers: NonEmptyVec::new(old_floor_fetch.subscriber),
                    },
                    value: old_floor_block.encode(),
                    response,
                })
                .accepted());
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
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: new_floor_fetch.key,
                        subscribers: NonEmptyVec::new(new_floor_fetch.subscriber),
                    },
                    value: new_floor_block.encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx
                    .await
                    .expect("new floor delivery response missing"),
                "new floor block delivery should validate"
            );
            assert_eq!(started_rx.await.unwrap(), Height::new(8));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_applies_buffered_anchor_on_notarization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_proposal = Proposal::new(
                floor_round,
                View::new(4),
                StandardHarness::commitment(&floor_block),
            );
            let floor_finalization =
                StandardHarness::make_finalization(floor_proposal.clone(), &schemes, QUORUM);
            let (application, mut started_rx) = HoldingBlockReporter::new();
            let buffer = RecordingBuffer::default();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-buffered-anchor-notarization",
                ConstantProvider::new(schemes[0].clone()),
                application,
                buffer.clone(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
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
            assert_eq!(started_rx.await.unwrap(), Height::new(6));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_stale_floor_anchor_resumes_dispatch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "stale-floor-anchor-resumes-dispatch",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(b"block1-parent"), Height::new(1), 100);
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
            let floor_block = make_raw_block(Sha256::hash(b"stale-floor"), Height::zero(), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
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

            let retain_before_ack = resolver.retain_count();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            wait_until(
                &context,
                Duration::from_secs(5),
                "first ack processed",
                || resolver.retain_count() > retain_before_ack,
            )
            .await;

            assert!(mailbox.verified(floor_round, floor_block).await);
            select! {
                height = application.acknowledged() => {
                    assert_eq!(height, Height::new(2));
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("stale floor anchor did not resume dispatch");
                },
            }
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
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(b"block1-parent"), Height::new(1), 100);
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
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
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
            let parent = B::new::<Sha256>(parent_context, Sha256::hash(b""), Height::new(1), 100);

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
    fn test_standard_notarized_delivery_wakes_fetch_by_round_subscriber() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "notarized-delivery-wakes-subscriber",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let subscription = mailbox.subscribe_by_commitment(
                notarization.proposal.payload,
                CommitmentFallback::FetchByRound { round },
            );

            wait_until(
                &context,
                Duration::from_secs(5),
                "fetch-by-round request",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            (&fetch.key, &fetch.subscriber),
                            (
                                handler::Key::Notarized { round: request_round },
                                handler::Annotation::Notarization { round: subscriber_round },
                            ) if *request_round == round && *subscriber_round == round
                        )
                    })
                },
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Notarized { round },
                        subscribers: NonEmptyVec::new(handler::Annotation::Notarization { round }),
                    },
                    value: (notarization, block.clone()).encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx.await.expect("delivery response missing"),
                "notarized delivery should validate"
            );

            select! {
                result = subscription => {
                    let delivered = result.expect("block subscription should resolve");
                    assert_eq!(delivered.digest(), block.digest());
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("notarized delivery did not wake block subscriber");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_round_fetches_reject_processed_round() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "fetch-notarized-processed-round",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

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
            mailbox.hint_notarized(round, Sha256::hash(b"missing-at-processed-round"));
            let subscription = mailbox.subscribe_by_commitment(
                Sha256::hash(b"missing-subscription-at-processed-round"),
                CommitmentFallback::FetchByRound { round },
            );

            let barrier = make_raw_block(block.digest(), Height::new(2), 200);
            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await,
                "barrier verification should be processed"
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "hint_notarized must not enqueue the already-pruned processed round"
            );
            select! {
                result = subscription => {
                    assert!(
                        result.is_err(),
                        "processed-round subscription should be canceled without a fetch"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("processed-round subscription remained open");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_finalization_rejects_processed_round_block_fetch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
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
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

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
                    Sha256::hash(b"missing-finalized-at-processed-round"),
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
    fn test_standard_restart_keeps_existing_genesis_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "restart-keeps-existing-genesis";

            let original_genesis =
                make_raw_block(Sha256::hash(b"original-genesis"), Height::zero(), 0);
            let replacement_genesis =
                make_raw_block(Sha256::hash(b"replacement-genesis"), Height::zero(), 1);
            assert_ne!(original_genesis.digest(), replacement_genesis.digest());

            let (mailbox, buffer, resolver, actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(original_genesis.clone()),
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

            let (mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator_restart"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(replacement_genesis.clone()),
            )
            .await;

            let stored = mailbox.get_block(Height::zero()).await.unwrap();
            assert_eq!(stored.digest(), original_genesis.digest());
            assert_ne!(stored.digest(), replacement_genesis.digest());
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
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
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
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

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

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let fetches_before = resolver.fetches().len();
            mailbox.hint_notarized(round, Sha256::hash(b"missing-after-restart"));
            let subscription = mailbox.subscribe_by_commitment(
                Sha256::hash(b"missing-subscription-after-restart"),
                CommitmentFallback::FetchByRound { round },
            );

            let barrier = make_raw_block(block.digest(), Height::new(2), 200);
            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "restart must restore the processed round floor"
            );
            select! {
                result = subscription => {
                    assert!(
                        result.is_err(),
                        "processed-round subscription should be canceled after restart"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("processed-round subscription remained open after restart");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_prunes_round_bound_fetches() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
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
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let missing = Sha256::hash(b"missing-before-set-floor");
            let _subscription = mailbox
                .subscribe_by_commitment(missing, CommitmentFallback::FetchByRound { round });
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound fetch",
                || {
                    resolver.active_fetches().iter().any(|fetch| {
                        matches!(fetch.key, handler::Key::Notarized { round: r } if r == round)
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
                        !matches!(fetch.key, handler::Key::Notarized { round: r } if r == round)
                    })
                },
            )
            .await;
            assert!(
                resolver.active_fetches().iter().all(|fetch| {
                    !matches!(fetch.key, handler::Key::Notarized { round: r } if r == round)
                }),
                "processed finalization after set_floor must prune existing round-bound fetches"
            );

            let fetches_before = resolver.fetches().len();
            mailbox.hint_notarized(round, Sha256::hash(b"missing-after-set-floor"));
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

    /// When the provider has no verifier for an epoch, in-flight deliveries
    /// for that epoch must be acknowledged (`true`) so the serving peer is
    /// not blamed, rather than rejected (`false`).
    #[test_traced("WARN")]
    fn test_standard_stale_finalized_delivery_does_not_block_peer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let me = default_leader();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                vec![me.clone()],
            )
            .await;
            network.start();
            let control = oracle.control(me.clone());
            let network_channel = control
                .register(0, Quota::per_second(NonZeroU32::MAX))
                .await
                .unwrap();

            let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10));
            let partition_prefix = "stale-finalized-test".to_string();
            let config = Config {
                provider: EmptyProvider,
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                mailbox_size: NZUsize!(100),
                view_retention_timeout: ViewDelta::new(10),
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                block_codec_config: (),
                partition_prefix: partition_prefix.clone(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NZUsize!(1024),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                page_cache: page_cache.clone(),
                strategy: Sequential,
            };
            let finalizations_by_height = prunable::Archive::init(
                context.child("finalizations_by_height"),
                prunable::Config {
                    translator: EightCap,
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

            let broadcast_config = buffered::Config {
                public_key: me.clone(),
                mailbox_size: NZUsize!(100),
                deque_size: 10,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
            };
            let (broadcast_engine, buffer) =
                buffered::Engine::new(context.child("broadcast"), broadcast_config);
            broadcast_engine.start(network_channel);

            let (resolver_tx, resolver_rx) = mailbox::new(context.child("mailbox"), NZUsize!(100));

            let (actor, _mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            actor.start(
                Application::<B>::default(),
                buffer,
                (
                    handler::Receiver::new(resolver_rx),
                    RecordingResolver::default(),
                ),
            );

            // Inject a Finalized delivery with garbage payload. The
            // provider has no verifier, so the marshal cannot decode it and
            // must ack (true) rather than blame the peer (false).
            let (response, response_rx) = oneshot::channel();
            assert!(resolver_tx
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Finalized {
                            height: Height::new(5),
                        },
                        subscribers: NonEmptyVec::new(handler::Annotation::Finalized(
                            handler::Finalized::ByHeight {
                                height: Height::new(5),
                            },
                        )),
                    },
                    value: Bytes::from_static(b"unverifiable"),
                    response,
                })
                .accepted());
            assert!(response_rx.await.unwrap());

            // Same for a Notarized delivery.
            let (response, response_rx) = oneshot::channel();
            assert!(resolver_tx
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Notarized {
                            round: Round::new(Epoch::zero(), View::new(1)),
                        },
                        subscribers: NonEmptyVec::new(handler::Annotation::Notarization {
                            round: Round::new(Epoch::zero(), View::new(1)),
                        }),
                    },
                    value: Bytes::from_static(b"unverifiable"),
                    response,
                })
                .accepted());
            assert!(response_rx.await.unwrap());
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
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            let (application, started) = HoldingBlockReporter::new();
            let (mut mailbox, _buffer, _resolver, actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            assert!(
                mailbox.verified(round, block.clone()).await,
                "verified block should persist to the cache"
            );
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
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
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

            // Submit finalizations; marshal dispatches up to MAX_PENDING_ACKS
            // blocks at a time and stalls until the application acks.
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            let mut parent = Sha256::hash(b"");
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
            let unknown = Sha256::hash(b"unknown-block");

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("forward-unknown-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

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

    /// A block admitted via `Proposed` must be broadcast straight from the
    /// in-memory cache when `Forward` arrives: the `RecordingBuffer` reports
    /// no `find_by_commitment` hits, so if the forward dispatches a block it
    /// must have come from the in-memory slot populated by `Proposed`.
    /// A subsequent `Forward` for the same `(round, commitment)` falls
    /// through to storage because the slot is consumed.
    #[test_traced("WARN")]
    fn test_standard_proposed_is_served_from_in_memory_cache() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("proposed-cache-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            assert!(mailbox.proposed(round, block.clone()).await);

            let targets = vec![participants[1].clone()];
            mailbox.forward(round, digest, Recipients::Some(targets.clone()));
            wait_until(&context, Duration::from_secs(5), "first forward", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1, "cached proposal must dispatch exactly once");
            assert_eq!(sends[0].0, round);
            assert_eq!(sends[0].1.digest(), digest);

            // The in-memory slot was consumed; a second forward for the same
            // commitment must still succeed by falling back to storage (the
            // block was persisted by `Proposed`, mirroring `Verified`).
            mailbox.forward(round, digest, Recipients::Some(targets));
            wait_until(&context, Duration::from_secs(5), "second forward", || {
                buffer.sends.lock().len() >= 2
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 2);
            assert_eq!(sends[1].1.digest(), digest);
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
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("forward-cached-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

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

    /// `HintFinalized` at or below the floor must be a no-op: marshal must
    /// not fire a targeted resolver fetch since the hint is stale.
    #[test_traced("WARN")]
    fn test_standard_hint_finalized_below_floor_is_noop() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("hint-below-floor-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            // Raise the floor above the hint we are about to send.
            let floor_anchor = StandardHarness::make_test_block(
                Sha256::hash(b"floor-parent"),
                StandardHarness::genesis_parent_commitment(NUM_VALIDATORS as u16),
                Height::new(10),
                10,
                NUM_VALIDATORS as u16,
            );
            let floor_round = Round::new(Epoch::zero(), View::new(10));
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(9),
                    StandardHarness::commitment(&floor_anchor),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(finalization);
            assert!(mailbox.verified(floor_round, floor_anchor).await);
            context.sleep(Duration::from_millis(50)).await;

            mailbox.hint_finalized(Height::new(5), NonEmptyVec::new(participants[1].clone()));
            context.sleep(Duration::from_millis(50)).await;

            assert!(
                resolver.targeted_is_empty(),
                "hint at or below floor must not fetch"
            );
        });
    }

    /// `HintFinalized` for a height whose finalization is already durable must
    /// be a no-op: marshal already has everything needed and must not
    /// initiate a redundant fetch.
    #[test_traced("WARN")]
    fn test_standard_hint_finalized_skips_when_already_finalized() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            let (mut mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("hint-already-final-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            // Wait until marshal has durably stored the finalization.
            while mailbox.get_finalization(Height::new(1)).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            mailbox.hint_finalized(Height::new(1), NonEmptyVec::new(participants[1].clone()));
            context.sleep(Duration::from_millis(50)).await;

            assert!(
                resolver.targeted_is_empty(),
                "hint for a locally-finalized height must not fetch"
            );
        });
    }

    /// `HintFinalized` above the floor for a not-yet-finalized height must
    /// trigger exactly one targeted fetch via the resolver.
    #[test_traced("WARN")]
    fn test_standard_hint_finalized_emits_targeted_fetch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("hint-targets-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let target = participants[1].clone();
            mailbox.hint_finalized(Height::new(7), NonEmptyVec::new(target.clone()));
            wait_until(&context, Duration::from_secs(5), "fetch_targeted", || {
                !resolver.targeted.lock().is_empty()
            })
            .await;

            let targeted = resolver.targeted();
            assert_eq!(targeted.len(), 1);
            let (request, targets) = &targeted[0];
            assert_eq!(
                request,
                &handler::Key::Finalized {
                    height: Height::new(7)
                }
            );
            assert_eq!(&targets[..], &[target]);
        });
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
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
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
                RecordingBuffer::default(),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
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
