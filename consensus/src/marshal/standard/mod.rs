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
            config::Config,
            core::{cache, Actor, Mailbox},
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
    use commonware_broadcast::buffered;
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
        ed25519::PublicKey,
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::{
        simulated::{self, Network},
        Recipients,
    };
    use commonware_parallel::Sequential;
    use commonware_resolver::Resolver;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock, Metrics, Quota, Runner,
    };
    use commonware_storage::{
        archive::{immutable, prunable, Archive as _},
        metadata::{self, Metadata},
        translator::{EightCap, TwoCap},
    };
    use commonware_utils::{
        channel::{fallible::OneshotExt, mpsc, oneshot},
        sync::Mutex,
        vec::NonEmptyVec,
        NZUsize, NZU16, NZU64,
    };
    use std::{
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };

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
        let r1 = harness::hailstorm::<H>(seed, 4, 4, LINK);
        let r2 = harness::hailstorm::<H>(seed, 4, 4, LINK);
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
        harness::proposed_success_implies_recoverable_after_restart::<InlineHarness>();
        harness::proposed_success_implies_recoverable_after_restart::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_verified_success_implies_recoverable_after_restart() {
        harness::verified_success_implies_recoverable_after_restart::<InlineHarness>();
        harness::verified_success_implies_recoverable_after_restart::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_delivery_visibility_implies_recoverable_after_restart() {
        harness::delivery_visibility_implies_recoverable_after_restart::<InlineHarness>();
        harness::delivery_visibility_implies_recoverable_after_restart::<DeferredHarness>();
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
            context.with_label("seed_finalizations_by_height"),
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
            context.with_label("seed_finalized_blocks"),
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
            context.with_label("seed_cache_metadata"),
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
                context.with_label("seed_notarized"),
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
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(3), participants.clone())
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
                    block_two.digest(),
                ),
                &schemes,
                3,
            );

            // Give the peer all blocks so it can serve them during repair.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.with_label("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;
            assert!(
                peer_mailbox
                    .proposed(Round::new(Epoch::zero(), View::new(1)), block_one.clone())
                    .await
            );
            assert!(
                peer_mailbox
                    .proposed(Round::new(Epoch::zero(), View::new(2)), block_two.clone())
                    .await
            );
            StandardHarness::report_finalization(&mut peer_mailbox, finalization_two.clone()).await;
            context.sleep(Duration::from_millis(200)).await;

            // Seed inconsistent state: has block_one but only a finalization
            // (no block data) for height 2.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.clone(),
                &partition_prefix,
                &[block_one],
                &[(Height::new(2), finalization_two)],
            )
            .await;

            // Start the recovering validator and verify initial state.
            let recovering = StandardHarness::setup_validator_with(
                context.with_label("recovering_validator"),
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
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(3), participants.clone())
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
                    block_two.digest(),
                ),
                &schemes,
                3,
            );
            let finalization_three = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(3)),
                    View::new(2),
                    block_three.digest(),
                ),
                &schemes,
                3,
            );

            // Give the peer all blocks so it can serve them during repair.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.with_label("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;
            assert!(
                peer_mailbox
                    .proposed(Round::new(Epoch::zero(), View::new(1)), block_one.clone())
                    .await
            );
            assert!(
                peer_mailbox
                    .proposed(Round::new(Epoch::zero(), View::new(2)), block_two.clone())
                    .await
            );
            assert!(
                peer_mailbox
                    .proposed(Round::new(Epoch::zero(), View::new(3)), block_three.clone())
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
                context.clone(),
                &partition_prefix,
                &[block_one, block_three.clone()],
                &[
                    (Height::new(2), finalization_two),
                    (Height::new(3), finalization_three),
                ],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.with_label("recovering_validator"),
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
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(3), participants.clone())
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
                    block_one.digest(),
                ),
                &schemes,
                3,
            );

            // Seed state: both blocks persisted, but only block_one has a
            // finalization. block_two is a block without a corresponding
            // finalization row.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.clone(),
                &partition_prefix,
                &[block_one.clone(), block_two.clone()],
                &[(Height::new(1), finalization_one)],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.with_label("recovering_validator"),
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
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(3), participants.clone())
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
                    Proposal::new(Round::new(Epoch::zero(), view), parent_view, block.digest()),
                    &schemes,
                    3,
                ));
            }

            // Give the peer all blocks and finalizations.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.with_label("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;
            for (i, block) in blocks.iter().enumerate() {
                assert!(
                    peer_mailbox
                        .proposed(
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
                context.clone(),
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
                context.with_label("recovering_validator"),
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
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(3), participants.clone())
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
                    block_one.digest(),
                ),
                &schemes,
                3,
            );
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    block_two.digest(),
                ),
                &schemes,
                3,
            );

            // Seed fully consistent state: both blocks and both finalizations.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.clone(),
                &partition_prefix,
                &[block_one.clone(), block_two.clone()],
                &[
                    (Height::new(1), finalization_one),
                    (Height::new(2), finalization_two),
                ],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.with_label("recovering_validator"),
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
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(3), participants.clone())
                    .await;

            let recovering_validator = participants[0].clone();

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    block_two.digest(),
                ),
                &schemes,
                3,
            );

            let partition_prefix = format!("validator-{recovering_validator}");

            // Seed block_two into the cache's notarized storage so the
            // recovering validator can find it locally during trailing repair,
            // without needing a peer to serve it.
            seed_cache_block(
                context.clone(),
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
                context.clone(),
                &partition_prefix,
                &[block_one],
                &[(Height::new(2), finalization_two)],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.with_label("recovering_validator"),
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
                    context.with_label("write"),
                    make_cfg(),
                    (),
                )
                .await;
                mgr.put_block(round, digest, block.clone()).await;
            }

            // Re-init the cache (simulating restart). find_block should fail
            // before loading persisted epochs.
            let mut mgr = cache::Manager::<_, Standard<B>, S>::init(
                context.with_label("read"),
                make_cfg(),
                (),
            )
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
                    context.clone(),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.with_label("validator_0"),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
                let mut wrapper = Wrapper::new(kind, context.clone(), mock_app, marshal.clone());

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
                        .proposed(boundary_round, boundary_block.clone())
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
                    context.clone(),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.with_label("validator_0"),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
                let mut wrapper = Wrapper::new(kind, context.clone(), mock_app, marshal.clone());

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
                        .proposed(boundary_round, boundary_block)
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
                        .proposed(non_boundary_round, non_boundary_block)
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
                    context.clone(),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.with_label("validator_0"),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
                let mut wrapper = Wrapper::new(kind, context.clone(), mock_app, marshal.clone());

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
                        .proposed(malformed_round, malformed_block)
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
                assert!(marshal.clone().proposed(parent_round, parent).await);

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
                        .proposed(mismatch_round, mismatched_block)
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
                let mut oracle = setup_network_with_participants(
                    context.clone(),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let me = participants[0].clone();

                let setup = StandardHarness::setup_validator(
                    context.with_label("validator_0"),
                    &mut oracle,
                    me.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let marshal = setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let mock_app: MockVerifyingApp<B, S> =
                    MockVerifyingApp::with_verify_result(genesis.clone(), false);
                let mut wrapper = Wrapper::new(kind, context.clone(), mock_app, marshal.clone());

                // 1) Set up a valid parent so structural checks can pass.
                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent = B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 100);
                let parent_digest = parent.digest();
                assert!(marshal.clone().proposed(parent_round, parent).await);

                // 2) Publish a valid child; only application-level verification should fail.
                let round = Round::new(Epoch::zero(), View::new(2));
                let verify_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::new(1), parent_digest),
                };
                let block = B::new::<Sha256>(verify_context.clone(), parent_digest, Height::new(2), 200);
                let digest = block.digest();
                assert!(marshal.clone().proposed(round, block).await);

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

    /// A no-op resolver used by tests that drive the marshal actor's
    /// resolver_rx channel directly. Outbound fetches/cancellations are dropped.
    #[derive(Clone, Default)]
    struct NoopResolver {
        _keepalive: Option<mpsc::Sender<handler::Message<D>>>,
    }

    impl NoopResolver {
        fn holding(sender: mpsc::Sender<handler::Message<D>>) -> Self {
            Self {
                _keepalive: Some(sender),
            }
        }
    }

    impl Resolver for NoopResolver {
        type Key = handler::Request<D>;
        type PublicKey = PublicKey;

        async fn fetch(&mut self, _key: Self::Key) {}
        async fn fetch_all(&mut self, _keys: Vec<Self::Key>) {}
        async fn fetch_targeted(
            &mut self,
            _key: Self::Key,
            _targets: NonEmptyVec<Self::PublicKey>,
        ) {
        }
        async fn fetch_all_targeted(
            &mut self,
            _requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
        ) {
        }
        async fn cancel(&mut self, _key: Self::Key) {}
        async fn clear(&mut self) {}
        async fn retain(&mut self, _predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {}
    }

    /// A no-op buffer used by tests that do not need marshal's dissemination path.
    #[derive(Clone, Default)]
    struct NoopBuffer;

    impl crate::marshal::core::Buffer<Standard<B>> for NoopBuffer {
        type PublicKey = PublicKey;
        type CachedBlock = B;

        async fn find_by_digest(&self, _digest: D) -> Option<Self::CachedBlock> {
            None
        }

        async fn find_by_commitment(&self, _commitment: D) -> Option<Self::CachedBlock> {
            None
        }

        async fn subscribe_by_digest(&self, _digest: D) -> oneshot::Receiver<Self::CachedBlock> {
            let (_sender, receiver) = oneshot::channel();
            receiver
        }

        async fn subscribe_by_commitment(
            &self,
            _commitment: D,
        ) -> oneshot::Receiver<Self::CachedBlock> {
            let (_sender, receiver) = oneshot::channel();
            receiver
        }

        async fn finalized(&self, _commitment: D) {}

        async fn send(&self, _round: Round, _block: B, _recipients: Recipients<PublicKey>) {}
    }

    /// A reporter that blocks inside `Update::Block` so tests can abort marshal
    /// exactly when application delivery starts.
    #[derive(Clone)]
    struct GatedBlockReporter {
        started: Arc<Mutex<Option<oneshot::Sender<Height>>>>,
        release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    }

    impl GatedBlockReporter {
        fn new() -> (Self, oneshot::Receiver<Height>, oneshot::Sender<()>) {
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            (
                Self {
                    started: Arc::new(Mutex::new(Some(started_tx))),
                    release: Arc::new(Mutex::new(Some(release_rx))),
                },
                started_rx,
                release_tx,
            )
        }
    }

    impl Reporter for GatedBlockReporter {
        type Activity = Update<B>;

        async fn report(&mut self, activity: Self::Activity) {
            match activity {
                Update::Block(block, _ack) => {
                    if let Some(started) = self.started.lock().take() {
                        started.send_lossy(block.height());
                    }
                    let release = self.release.lock().take();
                    if let Some(release) = release {
                        let _ = release.await;
                    }
                }
                Update::Tip(_, _, _) => {}
            }
        }
    }

    async fn start_standard_actor<R: Reporter<Activity = Update<B>>>(
        context: deterministic::Context,
        partition_prefix: &str,
        provider: ConstantProvider<S, Epoch>,
        application: R,
    ) -> (Mailbox<S, Standard<B>>, commonware_runtime::Handle<()>) {
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
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
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
            context.with_label("finalized_blocks"),
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
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let (resolver_tx, resolver_rx) = mpsc::channel(100);
        let actor_handle = actor.start(
            application,
            NoopBuffer,
            (resolver_rx, NoopResolver::holding(resolver_tx)),
        );
        (mailbox, actor_handle)
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
                context.with_label("network"),
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
                mailbox_size: 100,
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
                context.with_label("finalizations_by_height"),
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
                context.with_label("finalized_blocks"),
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
                mailbox_size: 100,
                deque_size: 10,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
            };
            let (broadcast_engine, buffer) =
                buffered::Engine::new(context.clone(), broadcast_config);
            broadcast_engine.start(network_channel);

            let (resolver_tx, resolver_rx) = mpsc::channel::<handler::Message<D>>(100);

            let (actor, _mailbox, _) = Actor::init(
                context.clone(),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            actor.start(
                Application::<B>::default(),
                buffer,
                (resolver_rx, NoopResolver::default()),
            );

            // Inject a Finalized delivery with garbage payload. The
            // provider has no verifier, so the marshal cannot decode it and
            // must ack (true) rather than blame the peer (false).
            let (response, response_rx) = oneshot::channel();
            resolver_tx
                .send(handler::Message::Deliver {
                    key: handler::Request::Finalized {
                        height: Height::new(5),
                    },
                    value: Bytes::from_static(b"unverifiable"),
                    response,
                })
                .await
                .unwrap();
            assert!(response_rx.await.unwrap());

            // Same for a Notarized delivery.
            let (response, response_rx) = oneshot::channel();
            resolver_tx
                .send(handler::Message::Deliver {
                    key: handler::Request::Notarized {
                        round: Round::new(Epoch::zero(), View::new(1)),
                    },
                    value: Bytes::from_static(b"unverifiable"),
                    response,
                })
                .await
                .unwrap();
            assert!(response_rx.await.unwrap());
        });
    }

    /// Regression: application delivery of a finalized block must only happen
    /// after the finalized archives are durably synced. Otherwise a crash in
    /// the delivery callback can expose a block to another subsystem that then
    /// persists derived state ahead of marshal's height-indexed finalization.
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
                Proposal::new(round, View::zero(), block.digest()),
                &schemes,
                QUORUM,
            );

            let (application, started, release) = GatedBlockReporter::new();
            let (mut mailbox, actor_handle) = start_standard_actor(
                context.with_label("validator_0"),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
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
            let _ = release.send_lossy(());
            drop(mailbox);

            // Yield once so the aborted actor drops its storage handles before restart.
            context.sleep(Duration::from_millis(1)).await;

            let (mailbox, _actor_handle) = start_standard_actor(
                context.with_label("validator_0_restart"),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
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
    /// form `<prefix>processed_height <value>`.
    fn parse_processed_height(metrics: &str) -> Option<u64> {
        for line in metrics.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let needle = "processed_height ";
            if let Some(idx) = line.find(needle) {
                let value = line[idx + needle.len()..].split_whitespace().next()?;
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
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(1), participants.clone())
                    .await;

            let validator = participants[0].clone();
            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.with_label("validator_0"),
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
}
