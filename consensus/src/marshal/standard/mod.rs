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
            core::{cache, Mailbox},
            mocks::{
                harness::{
                    self, default_leader, make_raw_block, setup_network_links,
                    setup_network_with_participants, Ctx, DeferredHarness, InlineHarness,
                    StandardHarness, TestHarness, B, BLOCKS_PER_EPOCH, D, LINK, NAMESPACE,
                    NUM_VALIDATORS, PAGE_CACHE_SIZE, PAGE_SIZE, S, UNRELIABLE_LINK, V,
                },
                verifying::MockVerifyingApp,
            },
            Identifier,
        },
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
            types::{Finalization, Proposal},
        },
        types::{Epoch, FixedEpocher, Height, Round, View},
        Automaton, CertifiableAutomaton, Heightable,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::{test_group, test_traced};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock, Metrics, Runner,
    };
    use commonware_storage::{
        archive::{immutable, prunable, Archive as _},
        metadata::{self, Metadata},
        translator::TwoCap,
    };
    use commonware_utils::{
        channel::oneshot,
        NZUsize,
    };
    use std::{
        num::{NonZeroU64, NonZeroUsize},
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
    // us manufacture inconsistent on-disk state (e.g. a finalization without
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
            let mut oracle = setup_network_with_participants(
                context.clone(),
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
            peer_mailbox
                .proposed(Round::new(Epoch::zero(), View::new(1)), block_one.clone())
                .await;
            peer_mailbox
                .proposed(Round::new(Epoch::zero(), View::new(2)), block_two.clone())
                .await;
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
            let recovering_mailbox = recovering.mailbox;

            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(
                recovering_mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(2), block_two.digest())),
                "seeded restart state should expose the trailing finalization as the latest tip"
            );
            assert_eq!(
                recovering_mailbox.get_block(Identifier::Latest).await,
                None,
                "seeded restart state should begin without the trailing finalized block"
            );

            // Poll until the trailing block is repaired from the peer.
            loop {
                if recovering_mailbox.get_block(Identifier::Latest).await == Some(block_two.clone())
                {
                    return;
                }
                context.sleep(Duration::from_millis(200)).await;
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
                context.clone(),
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
            peer_mailbox
                .proposed(Round::new(Epoch::zero(), View::new(1)), block_one.clone())
                .await;
            peer_mailbox
                .proposed(Round::new(Epoch::zero(), View::new(2)), block_two.clone())
                .await;
            peer_mailbox
                .proposed(Round::new(Epoch::zero(), View::new(3)), block_three.clone())
                .await;
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
            let recovering_mailbox = recovering.mailbox;

            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(
                recovering_mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(3), block_three.digest())),
                "seeded restart state should expose the highest stored finalization as the latest tip"
            );
            assert_eq!(
                recovering_mailbox.get_block(Height::new(2)).await,
                None,
                "seeded restart state should begin with the internal finalized gap still missing"
            );

            // Poll until the internal gap is repaired from the peer.
            loop {
                if recovering_mailbox.get_block(Height::new(2)).await == Some(block_two.clone()) {
                    return;
                }
                context.sleep(Duration::from_millis(200)).await;
            }
        });
    }

    // Verifies that a block persisted at a height beyond the last finalization
    // is still surfaced via get_block and dispatched to the application. This
    // can happen if a crash occurs after persisting the block but before
    // persisting its finalization.
    #[test_traced("WARN")]
    fn test_standard_restart_does_surface_block_without_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.clone(),
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
            let recovering_application = recovering.application;
            let recovering_mailbox = recovering.mailbox;

            // The tip tracks the highest finalization, not the highest block.
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(
                recovering_mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(1), block_one.digest())),
                "latest tip should be derived from the highest stored finalization"
            );
            assert_eq!(
                recovering_mailbox.get_block(Identifier::Latest).await,
                Some(block_one.clone()),
                "latest block should remain the highest finalized block"
            );
            assert_eq!(
                recovering_mailbox.get_block(Height::new(2)).await,
                Some(block_two.clone()),
                "get_block by height reads the finalized-blocks archive; inconsistent seeding can \
                 persist a block at a height without a finalization row, and the lookup still \
                 returns that block"
            );
            assert_eq!(
                recovering_application.pending_ack_heights(),
                vec![Height::new(1)],
                "height 1 should be pending before acknowledging the tip"
            );

            // Walk the application through sequential acks. Even though
            // block_two has no finalization, it is still dispatched because
            // its block data exists in the archive.
            assert_eq!(
                recovering_application.acknowledge_next(),
                Some(Height::new(1)),
                "expected the application to acknowledge height 1"
            );
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(
                recovering_application.pending_ack_heights(),
                vec![Height::new(2)],
                "height 2 can be dispatched after height 1 even when no finalization exists at height 2"
            );
            assert_eq!(
                recovering_application.acknowledge_next(),
                Some(Height::new(2)),
                "expected the application to acknowledge height 2"
            );
            context.sleep(Duration::from_millis(200)).await;
            assert!(
                recovering_application.pending_ack_heights().is_empty(),
                "pending acks should be empty after acknowledging through height 2"
            );
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
                context.clone(),
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
            let blocks = [&block_one, &block_two, &block_three, &block_four, &block_five];
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
                        block.digest(),
                    ),
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
                peer_mailbox
                    .proposed(
                        Round::new(Epoch::zero(), View::new(block.height().get())),
                        (*block).clone(),
                    )
                    .await;
                StandardHarness::report_finalization(
                    &mut peer_mailbox,
                    finalizations[i].clone(),
                )
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
            let recovering_mailbox = recovering.mailbox;

            // Poll until all missing blocks are repaired (check the last one).
            loop {
                if recovering_mailbox.get_block(Height::new(5)).await
                    == Some(block_five.clone())
                {
                    return;
                }
                context.sleep(Duration::from_millis(200)).await;
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
                context.clone(),
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
            let recovering_application = recovering.application;
            let recovering_mailbox = recovering.mailbox;

            // Everything is present on disk -- no repair needed.
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(
                recovering_mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(2), block_two.digest())),
                "latest tip should be the highest finalized block"
            );
            assert_eq!(
                recovering_mailbox.get_block(Identifier::Latest).await,
                Some(block_two.clone()),
                "latest block should be available"
            );
            assert_eq!(
                recovering_application.pending_ack_heights(),
                vec![Height::new(1)],
                "only height 1 should be pending (height 2 awaits ack of height 1)"
            );

            // Walk through sequential acks to confirm no repair was needed.
            assert_eq!(
                recovering_application.acknowledge_next(),
                Some(Height::new(1)),
            );
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(
                recovering_application.acknowledge_next(),
                Some(Height::new(2)),
            );
            context.sleep(Duration::from_millis(200)).await;
            assert!(
                recovering_application.pending_ack_heights().is_empty(),
                "all blocks should be dispatched without any trailing repair"
            );
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
            let mut oracle = setup_network_with_participants(
                context.clone(),
                NZUsize!(3),
                participants.clone(),
            )
            .await;
            setup_network_links(&mut oracle, &participants, LINK).await;

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
            let recovering_application = recovering.application;
            let recovering_mailbox = recovering.mailbox;

            // Repair should find block_two in the local cache immediately.
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(
                recovering_mailbox.get_block(Identifier::Latest).await,
                Some(block_two.clone()),
                "trailing block should be repaired from local cache without peer fetch"
            );
            assert_eq!(
                recovering_application.pending_ack_heights(),
                vec![Height::new(1)],
                "height 1 should be pending"
            );
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
                prunable_items_per_section: NonZeroU64::new(10).unwrap().into(),
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
                mgr.put_block(round, digest, block.clone().into()).await;
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
                mgr.find_block(digest).await.map(Into::into),
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
                marshal
                    .clone()
                    .proposed(boundary_round, boundary_block.clone())
                    .await;

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
                marshal
                    .clone()
                    .proposed(boundary_round, boundary_block)
                    .await;

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
                marshal
                    .clone()
                    .proposed(non_boundary_round, non_boundary_block)
                    .await;

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
                marshal
                    .clone()
                    .proposed(malformed_round, malformed_block)
                    .await;

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
                marshal.clone().proposed(parent_round, parent).await;

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
                marshal
                    .clone()
                    .proposed(mismatch_round, mismatched_block)
                    .await;

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
                marshal.clone().proposed(parent_round, parent).await;

                // 2) Publish a valid child; only application-level verification should fail.
                let round = Round::new(Epoch::zero(), View::new(2));
                let verify_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::new(1), parent_digest),
                };
                let block = B::new::<Sha256>(verify_context.clone(), parent_digest, Height::new(2), 200);
                let digest = block.digest();
                marshal.clone().proposed(round, block).await;

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
}
