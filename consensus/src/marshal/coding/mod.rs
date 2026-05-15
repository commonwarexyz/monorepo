//! Ordered delivery of erasure-coded blocks.
//!
//! # Overview
//!
//! The coding marshal couples the consensus pipeline with erasure-coded block broadcast.
//! Blocks are produced by an application, encoded into [`types::Shard`]s, fanned out to peers, and
//! later reconstructed when a notarization or finalization proves that the data is needed.
//! Compared to [`super::standard`], this variant makes more efficient usage of the network's bandwidth
//! by spreading the load of block dissemination across all participants.
//!
//! # Components
//!
//! - [`crate::marshal::core::Actor`]: The unified marshal actor that orders finalized blocks,
//!   handles acknowledgements from the application, and requests repairs when gaps are detected.
//!   Used with [`Coding`] as the variant type parameter.
//! - [`crate::marshal::core::Mailbox`]: Accepts requests from other local subsystems and forwards
//!   them to the actor. Used with [`Coding`] as the variant type parameter.
//! - [`shards::Engine`]: Broadcasts shards, verifies locally held fragments, and reconstructs
//!   entire [`types::CodedBlock`]s on demand.
//! - [`crate::marshal::resolver`]: Issues outbound fetches to remote peers when marshal is missing
//!   a block, notarization, or finalization referenced by consensus.
//! - [`types`]: Defines commitments, distribution shards, and helper builders used across the
//!   module.
//! - [`Marshaled`]: Wraps an [`crate::Application`] implementation so it automatically enforces
//!   epoch boundaries and performs erasure encoding before a proposal leaves the application.
//!
//! # Data Flow
//!
//! 1. The application produces a block through [`Marshaled`], which encodes the payload and
//!    obtains a [`crate::types::coding::Commitment`] describing the shard layout.
//! 2. The block is broadcast via [`shards::Engine`]; each participant receives exactly one shard
//!    and reshares it to everyone else once it verifies the fragment.
//! 3. The actor ingests notarizations/finalizations from `simplex`, pulls reconstructed blocks
//!    from the shard engine or backfills them through [`crate::marshal::resolver`], and durably
//!    persists the ordered data.
//! 4. The actor reports finalized blocks to the node's [`crate::Reporter`] at-least-once and
//!    drives repair loops whenever notarizations reference yet-to-be-delivered payloads.
//!
//! # Storage and Repair
//!
//! Notarized data and certificates live in prunable archives managed internally, while finalized
//! blocks are migrated into immutable archives. Any gaps are filled by asking peers for specific
//! commitments through the resolver pipeline. The shard engine keeps only ephemeral, in-memory
//! caches; once a block is finalized it is evicted from the reconstruction map, reducing memory
//! pressure.
//!
//! # When to Use
//!
//! Choose this module when the consensus deployment wants erasure-coded dissemination with the
//! same ordering guarantees provided by [`super::standard`]. The API is a breaking change from
//! the standard marshal: applications must adapt to the coding-specific variant type and buffer
//! implementation required by this module.

pub mod shards;
pub mod types;
pub(crate) mod validation;

mod variant;
pub use variant::Coding;

mod marshaled;
pub use marshaled::{Marshaled, MarshaledConfig};

#[cfg(test)]
mod tests {
    use crate::{
        marshal::{
            coding::{
                marshaled::genesis_coding_commitment,
                types::{coding_config_for_participants, CodedBlock},
                Marshaled, MarshaledConfig,
            },
            mocks::{
                harness::{
                    self, default_leader, genesis_commitment, make_coding_block,
                    setup_network_links, setup_network_with_participants, CodingB, CodingCtx,
                    CodingHarness, EmptyProvider, TestHarness, BLOCKS_PER_EPOCH, LINK, NAMESPACE,
                    NUM_VALIDATORS, QUORUM, S, UNRELIABLE_LINK, V,
                },
                verifying::{AncestryVerifyingApp, MockVerifyingApp},
            },
        },
        simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Proposal},
        types::{coding::Commitment, Epoch, Epocher, FixedEpocher, Height, Round, View},
        Automaton, CertifiableAutomaton, CertifiableBlock,
    };
    use commonware_codec::FixedSize;
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        sha256::Sha256,
        Committable, Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
    use commonware_utils::{NZUsize, NZU16};
    use std::time::Duration;

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_finalize_good_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, LINK, false);
            let r2 = harness::finalize::<CodingHarness>(seed, LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_finalize_bad_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, false);
            let r2 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, LINK, true);
            let r2 = harness::finalize::<CodingHarness>(seed, LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, true);
            let r2 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_hailstorm_restarts() {
        for seed in 0..2 {
            let r1 = harness::hailstorm::<CodingHarness>(seed, 4, 4, 1, LINK);
            let r2 = harness::hailstorm::<CodingHarness>(seed, 4, 4, 1, LINK);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_hailstorm_multi_restarts() {
        for seed in 0..2 {
            let r1 = harness::hailstorm::<CodingHarness>(seed, 4, 4, 2, LINK);
            let r2 = harness::hailstorm::<CodingHarness>(seed, 4, 4, 2, LINK);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_ack_pipeline_backlog() {
        harness::ack_pipeline_backlog::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_ack_pipeline_backlog_persists_on_restart() {
        harness::ack_pipeline_backlog_persists_on_restart::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_proposed_success_implies_recoverable_after_restart() {
        harness::proposed_success_implies_recoverable_after_restart::<CodingHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_coding_verified_success_implies_recoverable_after_restart() {
        harness::verified_success_implies_recoverable_after_restart::<CodingHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_coding_certified_success_implies_recoverable_after_restart() {
        harness::certified_success_implies_recoverable_after_restart::<CodingHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_coding_delivery_visibility_implies_recoverable_after_restart() {
        harness::delivery_visibility_implies_recoverable_after_restart::<CodingHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_coding_sync_height_floor() {
        harness::sync_height_floor::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_prune_finalized_archives() {
        harness::prune_finalized_archives::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_ignores_block_delivery_below_floor() {
        harness::ignore_stale_block_delivery_after_floor_update::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_basic_block_delivery() {
        harness::subscribe_basic_block_delivery::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_multiple_subscriptions() {
        harness::subscribe_multiple_subscriptions::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_canceled_subscriptions() {
        harness::subscribe_canceled_subscriptions::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_blocks_from_different_sources() {
        harness::subscribe_blocks_from_different_sources::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_info_basic_queries_present_and_missing() {
        harness::get_info_basic_queries_present_and_missing::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_info_latest_progression_multiple_finalizations() {
        harness::get_info_latest_progression_multiple_finalizations::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_block_by_height_and_latest() {
        harness::get_block_by_height_and_latest::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_block_by_commitment_from_sources_and_missing() {
        harness::get_block_by_commitment_from_sources_and_missing::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_finalization_by_height() {
        harness::get_finalization_by_height::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_hint_finalized_triggers_fetch() {
        harness::hint_finalized_triggers_fetch::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_ancestry_stream() {
        harness::ancestry_stream::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_same_height_different_views() {
        harness::finalize_same_height_different_views::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_certify_persists_equivocated_block() {
        harness::certify_persists_equivocated_block::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_certify_at_later_view_survives_earlier_view_pruning() {
        harness::certify_at_later_view_survives_earlier_view_pruning::<CodingHarness>();
    }

    /// Finalizing a descendant must not height-prune the shard-engine buffer before
    /// `try_repair_gaps` has consumed buffer-only ancestors.
    ///
    /// Places parent (height 1) and descendant (height 2) in the shard engine's
    /// reconstructed-block cache via `proposed()`, then reports a finalization
    /// for the descendant only.
    #[test_traced("WARN")]
    fn test_coding_store_finalization_does_not_prune_buffer_before_repair() {
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

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let mut handle = harness::ValidatorHandle::<CodingHarness> {
                mailbox: setup.mailbox,
                extra: setup.extra,
            };

            // Build a 2-block chain: parent at height 1, descendant at height 2.
            let parent_block = CodingHarness::make_test_block(
                Sha256::hash(b""),
                CodingHarness::genesis_parent_commitment(NUM_VALIDATORS as u16),
                Height::new(1),
                1,
                NUM_VALIDATORS as u16,
            );
            let parent_digest = CodingHarness::digest(&parent_block);
            let parent_commitment = CodingHarness::commitment(&parent_block);

            let descendant_block = CodingHarness::make_test_block(
                parent_digest,
                parent_commitment,
                Height::new(2),
                2,
                NUM_VALIDATORS as u16,
            );
            let descendant_commitment = CodingHarness::commitment(&descendant_block);

            // Seed the shard engine's reconstructed-block cache with both blocks.
            CodingHarness::propose(
                &mut handle,
                Round::new(Epoch::new(0), View::new(1)),
                &parent_block,
            )
            .await;
            CodingHarness::propose(
                &mut handle,
                Round::new(Epoch::new(0), View::new(2)),
                &descendant_block,
            )
            .await;

            // Report finalization for the descendant only. The parent has no
            // finalization certificate: it must be archived by walking the
            // parent link from the descendant and sourcing the block from the
            // shard-engine buffer.
            let descendant_proposal = Proposal {
                round: Round::new(Epoch::new(0), View::new(2)),
                parent: View::new(1),
                payload: descendant_commitment,
            };
            let descendant_finalization =
                CodingHarness::make_finalization(descendant_proposal, &schemes, QUORUM);
            CodingHarness::report_finalization(&mut handle.mailbox, descendant_finalization).await;

            // Wait until the descendant is archived: that proves finalization processing
            // has completed, at which point the parent must already have been repaired
            // from the shard buffer.
            while handle.mailbox.get_block(Height::new(2)).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let parent = handle.mailbox.get_block(Height::new(1)).await;
            assert!(
                parent.is_some(),
                "parent must be archived from shard buffer before height-prune evicts it"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_coding_marshaled_fetches_digest_ancestor_above_tip() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
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

            let victim_setup = CodingHarness::setup_validator(
                context.child("victim"),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let peer_setup = CodingHarness::setup_validator(
                context.child("peer"),
                &mut oracle,
                participants[1].clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;
            let mut peer_handle = harness::ValidatorHandle::<CodingHarness> {
                mailbox: peer_setup.mailbox,
                extra: peer_setup.extra,
            };

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let block1 = CodingHarness::make_test_block(
                genesis.digest(),
                genesis_commitment(),
                Height::new(1),
                100,
                NUM_VALIDATORS as u16,
            );
            let block2 = CodingHarness::make_test_block(
                CodingHarness::digest(&block1),
                CodingHarness::commitment(&block1),
                Height::new(2),
                200,
                NUM_VALIDATORS as u16,
            );
            let block3 = CodingHarness::make_test_block(
                CodingHarness::digest(&block2),
                CodingHarness::commitment(&block2),
                Height::new(3),
                300,
                NUM_VALIDATORS as u16,
            );
            let round1 = Round::new(Epoch::zero(), View::new(1));
            let round2 = Round::new(Epoch::zero(), View::new(2));
            let round3 = Round::new(Epoch::zero(), View::new(3));

            for (round, parent_view, block) in [
                (round1, View::zero(), block1.clone()),
                (round2, View::new(1), block2.clone()),
                (round3, View::new(2), block3.clone()),
            ] {
                CodingHarness::propose(&mut peer_handle, round, &block).await;
                let notarization = CodingHarness::make_notarization(
                    Proposal {
                        round,
                        parent: parent_view,
                        payload: CodingHarness::commitment(&block),
                    },
                    &schemes,
                    QUORUM,
                );
                CodingHarness::report_notarization(&mut peer_handle.mailbox, notarization).await;
            }
            context.sleep(Duration::from_millis(100)).await;
            setup_network_links(&mut oracle, &participants[..2], LINK).await;

            let victim_mailbox = victim_setup.mailbox.clone();
            assert!(victim_mailbox.verified(round3, block3.clone()).await);

            let app = AncestryVerifyingApp::<CodingB, S>::new(
                genesis,
                vec![Height::new(3), Height::new(2), Height::new(1)],
            );
            let cfg = MarshaledConfig {
                application: app,
                marshal: victim_setup.mailbox.clone(),
                shards: victim_setup.extra.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);
            let commitment = CodingHarness::commitment(&block3);
            let _verify = marshaled.verify(block3.context(), commitment).await;
            let certify = marshaled.certify(round3, commitment).await;
            assert!(
                certify.await.expect("certify result missing"),
                "coding certify should fetch certified ancestry by digest"
            );

            assert!(
                victim_mailbox.get_block(&block2.digest()).await.is_some(),
                "coding certify should fetch the certified parent by digest"
            );
            assert!(
                victim_mailbox.get_block(&block1.digest()).await.is_some(),
                "coding certify should fetch missing certified ancestry by digest"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_coding_init_processed_height() {
        harness::init_processed_height::<CodingHarness>();
    }

    #[test_traced("INFO")]
    fn test_coding_broadcast_caches_block() {
        harness::broadcast_caches_block::<CodingHarness>();
    }

    /// Test that certifying a lower-view block after a higher-view block succeeds.
    ///
    /// This is a critical test for crash recovery scenarios where a validator may need
    /// to certify blocks in non-sequential view order.
    #[test_traced("INFO")]
    fn test_certify_lower_view_after_higher_view() {
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

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis.clone());

            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Create parent block at height 1
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::new(0), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(Round::new(Epoch::new(0), View::new(1)), coded_parent);

            // Block A at view 5 (height 2) - create with context matching what verify will receive
            let round_a = Round::new(Epoch::new(0), View::new(5));
            let context_a = CodingCtx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a = make_coding_block(context_a.clone(), parent_digest, Height::new(2), 200);
            let coded_block_a = CodedBlock::new(block_a.clone(), coding_config, &Sequential);
            let commitment_a = coded_block_a.commitment();
            shards.proposed(round_a, coded_block_a);

            // Block B at view 10 (height 2, different block same height - could happen with
            // different proposers or re-proposals)
            let round_b = Round::new(Epoch::new(0), View::new(10));
            let context_b = CodingCtx {
                round: round_b,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_b = make_coding_block(context_b.clone(), parent_digest, Height::new(2), 300);
            let coded_block_b = CodedBlock::new(block_b.clone(), coding_config, &Sequential);
            let commitment_b = coded_block_b.commitment();
            shards.proposed(round_b, coded_block_b);

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
                    assert!(result.unwrap(), "Block A certification should succeed");
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
    /// A re-proposal occurs when the parent digest equals the block being verified,
    /// meaning the same block is being proposed again in a new view.
    #[test_traced("INFO")]
    fn test_marshaled_reproposal_validation() {
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

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis.clone());
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Build a chain up to the epoch boundary (height 19 is the last block in epoch 0
            // with BLOCKS_PER_EPOCH=20, since epoch 0 covers heights 0-19)
            let mut parent = genesis.digest();
            let mut last_view = View::zero();
            let mut last_commitment = genesis_commitment();
            for i in 1..BLOCKS_PER_EPOCH.get() {
                let round = Round::new(Epoch::new(0), View::new(i));
                let ctx = CodingCtx {
                    round,
                    leader: me.clone(),
                    parent: (last_view, last_commitment),
                };
                let block = make_coding_block(ctx.clone(), parent, Height::new(i), i * 100);
                let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
                last_commitment = coded_block.commitment();
                shards.proposed(round, coded_block);
                parent = block.digest();
                last_view = View::new(i);
            }

            // Create the epoch boundary block (height 19, last block in epoch 0)
            let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
            let boundary_round = Round::new(Epoch::new(0), View::new(boundary_height.get()));
            let boundary_context = CodingCtx {
                round: boundary_round,
                leader: me.clone(),
                parent: (last_view, last_commitment),
            };
            let boundary_block = make_coding_block(
                boundary_context.clone(),
                parent,
                boundary_height,
                boundary_height.get() * 100,
            );
            let coded_boundary =
                CodedBlock::new(boundary_block.clone(), coding_config, &Sequential);
            let boundary_commitment = coded_boundary.commitment();
            shards.proposed(boundary_round, coded_boundary);

            context.sleep(Duration::from_millis(10)).await;

            // Test 1: Valid re-proposal at epoch boundary should be accepted
            // Re-proposal context: parent digest equals the block being verified
            // Re-proposals happen within the same epoch when the parent is the last block
            //
            // In the coding marshal, verify() returns shard validity while deferred_verify
            // runs in the background. We call verify() to register the verification task,
            // then certify() returns the deferred_verify result.
            let reproposal_round = Round::new(Epoch::new(0), View::new(20));
            let reproposal_context = CodingCtx {
                round: reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_commitment), // Parent IS the boundary block
            };

            // Call verify to kick off deferred verification.
            // We must await the verify result to ensure the verification task is
            // registered before calling certify.
            let shard_validity = marshaled
                .verify(reproposal_context.clone(), boundary_commitment)
                .await
                .await;
            assert!(
                shard_validity.unwrap(),
                "Re-proposal verify should return true for shard validity"
            );

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(reproposal_round, boundary_commitment)
                .await
                .await;
            assert!(
                certify_result.unwrap(),
                "Valid re-proposal at epoch boundary should be accepted"
            );

            // Test 2: Invalid re-proposal (not at epoch boundary) should be rejected
            // Create a block at height 10 (not at epoch boundary)
            let non_boundary_height = Height::new(10);
            let non_boundary_round = Round::new(Epoch::new(0), View::new(10));
            // For simplicity, we'll create a fresh non-boundary block and test re-proposal
            let non_boundary_context = CodingCtx {
                round: non_boundary_round,
                leader: me.clone(),
                parent: (View::new(9), last_commitment), // Use a prior commitment
            };
            let non_boundary_block = make_coding_block(
                non_boundary_context.clone(),
                parent,
                non_boundary_height,
                1000,
            );
            let coded_non_boundary =
                CodedBlock::new(non_boundary_block.clone(), coding_config, &Sequential);
            let non_boundary_commitment = coded_non_boundary.commitment();

            // Make the non-boundary block available
            shards.proposed(non_boundary_round, coded_non_boundary);

            context.sleep(Duration::from_millis(10)).await;

            // Attempt to re-propose the non-boundary block
            let invalid_reproposal_round = Round::new(Epoch::new(0), View::new(15));
            let invalid_reproposal_context = CodingCtx {
                round: invalid_reproposal_round,
                leader: me.clone(),
                parent: (View::new(10), non_boundary_commitment),
            };

            // Call verify to kick off deferred verification.
            // We must await the verify result to ensure the verification task is
            // registered before calling certify.
            let shard_validity = marshaled
                .verify(invalid_reproposal_context, non_boundary_commitment)
                .await
                .await;
            assert!(
                !shard_validity.unwrap(),
                "Invalid re-proposal verify should return false"
            );

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(invalid_reproposal_round, non_boundary_commitment)
                .await
                .await;
            assert!(
                !certify_result.unwrap(),
                "Invalid re-proposal (not at epoch boundary) should be rejected"
            );

            // Test 3: Re-proposal with mismatched epoch should be rejected
            // This is a regression test - re-proposals must be in the same epoch as the block.
            let cross_epoch_reproposal_round = Round::new(Epoch::new(1), View::new(20));
            let cross_epoch_reproposal_context = CodingCtx {
                round: cross_epoch_reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_commitment),
            };

            // Call verify to kick off deferred verification.
            // We must await the verify result to ensure the verification task is
            // registered before calling certify.
            let shard_validity = marshaled
                .verify(cross_epoch_reproposal_context.clone(), boundary_commitment)
                .await
                .await;
            assert!(
                !shard_validity.unwrap(),
                "Cross-epoch re-proposal verify should return false"
            );

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(cross_epoch_reproposal_round, boundary_commitment)
                .await
                .await;
            assert!(
                !certify_result.unwrap(),
                "Re-proposal with mismatched epoch should be rejected"
            );

            // Note: Tests for certify-only paths (crash recovery scenarios) are not included here
            // because they require multiple validators to reconstruct blocks from shards. In a
            // single-validator test setup, block reconstruction fails due to insufficient shards.
            // These paths are tested in integration tests with multiple validators.
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_mismatched_context_digest() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis.clone());
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Create parent block at height 1 so the commitment is well-formed.
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(Round::new(Epoch::zero(), View::new(1)), coded_parent);

            // Build a block with context A (commitment hash uses this context).
            let round_a = Round::new(Epoch::zero(), View::new(2));
            let context_a = CodingCtx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a = make_coding_block(context_a, parent.digest(), Height::new(2), 200);
            let coded_block_a: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block_a, coding_config, &Sequential);
            let commitment_a = coded_block_a.commitment();

            // Verify using a different consensus context B (hash mismatch).
            let round_b = Round::new(Epoch::zero(), View::new(3));
            let context_b = CodingCtx {
                round: round_b,
                leader: participants[1].clone(),
                parent: (View::new(1), parent_commitment),
            };

            let verify_rx = marshaled.verify(context_b, commitment_a).await;
            select! {
                result = verify_rx => {
                    assert!(
                        !result.unwrap(),
                        "mismatched context digest should be rejected"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify should reject mismatched context digest promptly");
                },
            }
        })
    }

    #[test_traced("WARN")]
    fn test_reproposal_verify_receiver_drop_does_not_synthesize_false() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(context.child("network"), NZUsize!(1), participants.clone()).await;

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis.clone());
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Re-proposal payload with valid coding config, but no block available.
            let missing_payload = Commitment::from((
                Sha256::hash(b"missing_block"),
                Sha256::hash(b"missing_root"),
                Sha256::hash(b"missing_context"),
                coding_config,
            ));
            let round = Round::new(Epoch::zero(), View::new(1));
            let reproposal_context = CodingCtx {
                round,
                leader: me,
                parent: (View::zero(), missing_payload),
            };

            // Start verify, then drop the receiver immediately.
            let verify_rx = marshaled.verify(reproposal_context, missing_payload).await;
            drop(verify_rx);

            // Certify should resolve promptly from the in-progress task, but must
            // not synthesize `false` when verification was canceled before a verdict.
            let certify_rx = marshaled.certify(round, missing_payload).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.is_err(),
                        "certify should resolve without an explicit verdict when verify receiver is dropped"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify task should resolve promptly after verify receiver drop");
                },
            }
        })
    }

    #[test_traced("WARN")]
    fn test_reproposal_missing_block_does_not_synthesize_false() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(context.child("network"), NZUsize!(1), participants.clone()).await;

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis.clone());
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Re-proposal payload with valid coding config, but no block available.
            let missing_payload = Commitment::from((
                Sha256::hash(b"missing_block"),
                Sha256::hash(b"missing_root"),
                Sha256::hash(b"missing_context"),
                coding_config,
            ));
            let round = Round::new(Epoch::zero(), View::new(1));
            let reproposal_context = CodingCtx {
                round,
                leader: me,
                parent: (View::zero(), missing_payload),
            };

            // Verify must not synthesize `false` when the block cannot be fetched.
            let verify_rx = marshaled.verify(reproposal_context, missing_payload).await;

            // Ensure the verification task has registered its subscription, then
            // force cancellation by pruning the missing commitment.
            context.sleep(Duration::from_millis(100)).await;
            shards.prune(missing_payload);

            select! {
                result = verify_rx => {
                    assert!(
                        result.is_err(),
                        "verify should resolve without explicit false when re-proposal block is unavailable"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify should resolve promptly when re-proposal block is unavailable");
                },
            }

            // Certify should consume the same unresolved verification task.
            let certify_rx = marshaled.certify(round, missing_payload).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.is_err(),
                        "certify should resolve without explicit false when re-proposal block is unavailable"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should resolve promptly when re-proposal block is unavailable");
                },
            }
        })
    }

    #[test_traced("WARN")]
    fn test_core_subscription_closes_when_coding_buffer_prunes_missing_commitment() {
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

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);
            let missing_commitment = Commitment::from((
                Sha256::hash(b"missing_block"),
                Sha256::hash(b"missing_root"),
                Sha256::hash(b"missing_context"),
                coding_config,
            ));
            let round = Round::new(Epoch::zero(), View::new(1));

            // Subscribe through the core actor. This internally subscribes to the
            // coding shard buffer and registers local waiters.
            let block_rx = marshal
                .subscribe_by_commitment(
                    missing_commitment,
                    crate::marshal::core::CommitmentRequest::FetchByRound { round },
                );

            // Allow core actor to register the underlying buffer subscription.
            context.sleep(Duration::from_millis(100)).await;

            // Prune the missing commitment in the shard engine, which should cancel
            // the underlying buffer subscription.
            shards.prune(missing_commitment);

            // The core actor must surface cancellation by closing the subscription,
            // not by panicking or leaving the waiter parked indefinitely.
            select! {
                result = block_rx => {
                    assert!(
                        result.is_err(),
                        "core subscription should close when coding buffer drops subscription"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("core subscription should resolve promptly after coding prune");
                },
            }
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_unsupported_epoch() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis.clone());
            let limited_epocher = LimitedEpocher {
                inner: FixedEpocher::new(BLOCKS_PER_EPOCH),
                max_epoch: 0,
            };
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: limited_epocher,
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Create a parent block at height 19 (last block in epoch 0, which is supported)
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(19)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(19), 1000);
            let parent_digest = parent.digest();
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(Round::new(Epoch::zero(), View::new(19)), coded_parent);

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let block_ctx = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(20)),
                leader: default_leader(),
                parent: (View::new(19), parent_commitment),
            };
            let block = make_coding_block(block_ctx, parent_digest, Height::new(20), 2000);
            let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
            let block_commitment = coded_block.commitment();
            shards.proposed(Round::new(Epoch::new(1), View::new(20)), coded_block);

            context.sleep(Duration::from_millis(10)).await;

            // In the coding marshal, verify() returns shard validity while deferred_verify
            // runs in the background. We need to use certify() to get the deferred_verify result.
            let unsupported_round = Round::new(Epoch::new(1), View::new(20));
            let unsupported_context = CodingCtx {
                round: unsupported_round,
                leader: me.clone(),
                parent: (View::new(19), parent_commitment),
            };

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(unsupported_context, block_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(unsupported_round, block_commitment)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Block in unsupported epoch should be rejected"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_invalid_ancestry() {
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

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            // Create genesis block
            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Wrap with Marshaled verifier
            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis.clone());
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Test case 1: Non-contiguous height
            //
            // We need both blocks in the same epoch.
            // With BLOCKS_PER_EPOCH=20: epoch 0 is heights 0-19, epoch 1 is heights 20-39
            //
            // Store honest parent at height 21 (epoch 1)
            let honest_parent_ctx = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(21)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let honest_parent = make_coding_block(
                honest_parent_ctx,
                genesis.digest(),
                Height::new(BLOCKS_PER_EPOCH.get() + 1),
                1000,
            );
            let parent_digest = honest_parent.digest();
            let coded_parent = CodedBlock::new(honest_parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(Round::new(Epoch::new(1), View::new(21)), coded_parent);

            // Byzantine proposer broadcasts malicious block at height 35
            // The block has the correct context (matching what consensus will provide)
            // but contains invalid content (non-contiguous height: 21 -> 35 instead of 21 -> 22)
            let byzantine_round = Round::new(Epoch::new(1), View::new(35));
            let byzantine_context = CodingCtx {
                round: byzantine_round,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };
            let malicious_block = make_coding_block(
                byzantine_context.clone(),
                parent_digest,
                Height::new(BLOCKS_PER_EPOCH.get() + 15), // Byzantine: non-contiguous height
                2000,
            );
            let coded_malicious =
                CodedBlock::new(malicious_block.clone(), coding_config, &Sequential);
            let malicious_commitment = coded_malicious.commitment();
            shards.proposed(byzantine_round, coded_malicious);

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Marshaled.verify() kicks off deferred verification in the background.
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 35) from marshal based on digest
            // 3. Validate height is contiguous (fail)
            // 4. Return false
            let _shard_validity = marshaled
                .verify(byzantine_context, malicious_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(byzantine_round, malicious_commitment)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Byzantine block with non-contiguous heights should be rejected"
            );

            // Test case 2: Mismatched parent digest
            //
            // Create another malicious block with correct context and height
            // but referencing the wrong parent digest (genesis instead of honest_parent)
            let byzantine_round2 = Round::new(Epoch::new(1), View::new(22));
            let byzantine_context2 = CodingCtx {
                round: byzantine_round2,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };
            let malicious_block2 = make_coding_block(
                byzantine_context2.clone(),
                genesis.digest(), // Byzantine: wrong parent digest
                Height::new(BLOCKS_PER_EPOCH.get() + 2),
                3000,
            );
            let coded_malicious2 =
                CodedBlock::new(malicious_block2.clone(), coding_config, &Sequential);
            let malicious_commitment2 = coded_malicious2.commitment();
            shards.proposed(byzantine_round2, coded_malicious2);

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Marshaled.verify() kicks off deferred verification in the background.
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 22) from marshal based on digest
            // 3. Validate height is contiguous
            // 4. Validate parent commitment matches (fail)
            // 5. Return false
            let _shard_validity = marshaled
                .verify(byzantine_context2, malicious_commitment2)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(byzantine_round2, malicious_commitment2)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Byzantine block with mismatched parent commitment should be rejected"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_certify_without_prior_verify_crash_recovery() {
        // After a crash, consensus may call certify() without a prior verify().
        // The certify path (marshaled.rs:842-936) should:
        //   1. Find no in-progress verification task
        //   2. Subscribe to the block from the shard engine
        //   3. Use the block's embedded context for deferred_verify
        //   4. Return Ok(true) for a valid block
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis.clone());
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Create parent at height 1.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = CodingCtx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(parent_round, coded_parent);

            // Create child at height 2.
            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = CodingCtx {
                round: child_round,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let child = make_coding_block(child_ctx, parent.digest(), Height::new(2), 200);
            let coded_child = CodedBlock::new(child, coding_config, &Sequential);
            let child_commitment = coded_child.commitment();
            shards.proposed(child_round, coded_child);

            context.sleep(Duration::from_millis(10)).await;

            // Call certify directly without any prior verify (simulating crash recovery).
            let certify_rx = marshaled.certify(child_round, child_commitment).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.unwrap(),
                        "certify without prior verify should succeed for valid block"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should complete within timeout");
                },
            }
        })
    }

    /// Regression test: a Byzantine leader must not be able to crash honest nodes
    /// by proposing a `Commitment` with invalid `CodingConfig` bytes (e.g.
    /// zero-valued `NonZeroU16` fields). The fix validates the embedded config
    /// during deserialization so malformed commitments are rejected at the codec
    /// level before reaching `verify()`.
    #[test_traced("WARN")]
    fn test_malformed_commitment_config_rejected_at_deserialization() {
        use commonware_codec::{Encode, ReadExt};

        // Construct a Commitment with all-zero bytes (invalid CodingConfig:
        // minimum_shards=0, extra_shards=0). Serialize it and attempt to
        // deserialize -- this must fail.
        let malformed_bytes = [0u8; Commitment::SIZE];
        let result = Commitment::read(&mut &malformed_bytes[..]);
        assert!(
            result.is_err(),
            "deserialization of Commitment with zeroed CodingConfig must fail"
        );

        // A validly-constructed Commitment must still round-trip.
        let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);
        let valid = Commitment::from((
            Sha256::hash(b"block"),
            Sha256::hash(b"root"),
            Sha256::hash(b"context"),
            coding_config,
        ));
        let encoded = valid.encode();
        let decoded =
            Commitment::read(&mut &encoded[..]).expect("valid Commitment must deserialize");
        assert_eq!(valid, decoded);
    }

    #[test_traced("WARN")]
    fn test_certify_propagates_application_verify_failure() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // 1) Set up a single validator marshal stack.
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            // 2) Force application verification to fail in deferred verification.
            let mock_app: MockVerifyingApp<CodingB, S> =
                MockVerifyingApp::with_verify_result(genesis.clone(), false);

            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_context = CodingCtx {
                round: parent_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_context, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(parent_round, coded_parent);

            // 3) Publish a valid child so optimistic verify can succeed.
            let round = Round::new(Epoch::zero(), View::new(2));
            let verify_context = CodingCtx {
                round,
                leader: me,
                parent: (View::new(1), parent_commitment),
            };
            let block =
                make_coding_block(verify_context.clone(), parent.digest(), Height::new(2), 200);
            let coded_block = CodedBlock::new(block, coding_config, &Sequential);
            let commitment = coded_block.commitment();
            shards.proposed(round, coded_block);

            context.sleep(Duration::from_millis(10)).await;

            let optimistic = marshaled.verify(verify_context, commitment).await;
            assert!(
                optimistic.await.expect("verify result missing"),
                "optimistic verify should pass pre-checks and schedule deferred verification"
            );

            // 4) Certify must observe the deferred application failure and return false.
            let certify = marshaled.certify(round, commitment).await;
            assert!(
                !certify.await.expect("certify result missing"),
                "certify should propagate deferred application verify failure"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_backfill_block_mismatched_commitment() {
        // Regression: when backfilling by Request::Block(commitment), a peer may return
        // a coded block with matching inner digest but a different coding commitment.
        // If a finalization for this digest is already cached, marshal must reject
        // the block unless V::commitment(block) matches the finalization payload.
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
                participants[..2].iter().cloned(),
            )
            .await;

            let coding_config_a = coding_config_for_participants(NUM_VALIDATORS as u16);
            // Same total shards (4) but different min/extra split produces a different
            // coding root and config bytes, yielding a different commitment.
            let coding_config_b = commonware_coding::Config {
                minimum_shards: coding_config_a.minimum_shards.checked_add(1).unwrap(),
                extra_shards: NZU16!(coding_config_a.extra_shards.get() - 1),
            };

            let v0_setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let v1_setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 1),
                &mut oracle,
                participants[1].clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;

            setup_network_links(&mut oracle, &participants[..2], LINK).await;

            let mut v0_mailbox = v0_setup.mailbox;
            let v1_mailbox = v1_setup.mailbox;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let round1 = Round::new(Epoch::zero(), View::new(1));
            let block1_ctx = CodingCtx {
                round: round1,
                leader: participants[0].clone(),
                parent: (View::zero(), genesis_commitment()),
            };
            let block1 = make_coding_block(block1_ctx, genesis.digest(), Height::new(1), 100);

            let coded_block_a: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block1.clone(), coding_config_a, &Sequential);
            let commitment_a = coded_block_a.commitment();

            let coded_block_b: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block1.clone(), coding_config_b, &Sequential);
            let commitment_b = coded_block_b.commitment();

            assert_eq!(coded_block_a.digest(), coded_block_b.digest());
            assert_ne!(commitment_a, commitment_b);

            // Validator 1 proposes coded_block_b (same inner block, different coding).
            // This stores it in v1's shard engine and actor cache.
            assert!(v1_mailbox.verified(round1, coded_block_b.clone()).await);
            context.sleep(Duration::from_millis(100)).await;

            // Create finalization referencing commitment_a (the "correct" commitment).
            let proposal: Proposal<Commitment> = Proposal {
                round: round1,
                parent: View::zero(),
                payload: commitment_a,
            };
            let finalization = CodingHarness::make_finalization(proposal.clone(), &schemes, QUORUM);

            // Report finalization to v0. v0 doesn't have the block:
            //   - it fetches Request::Block(commitment_a)
            //   - v1 responds with coded_block_b (same digest, wrong commitment)
            //   - finalization lookup is digest-indexed, so deliver path must still
            //     reject because cached finalization expects commitment_a
            CodingHarness::report_finalization(&mut v0_mailbox, finalization).await;

            // Wait for the fetch cycle to complete.
            context.sleep(Duration::from_secs(5)).await;

            // The mismatched block must not be stored.
            let stored = v0_mailbox.get_block(Height::new(1)).await;
            assert!(
                stored.is_none(),
                "v0 should reject backfilled block with mismatched commitment"
            );

            // Without the block, finalization should not be persisted by height yet.
            let stored_finalization = v0_mailbox.get_finalization(Height::new(1)).await;
            assert!(
                stored_finalization.is_none(),
                "finalization should not be archived until matching block is available"
            );
        })
    }

    /// When the scheme provider has no entry for the current epoch,
    /// `Marshaled::propose` and `Marshaled::verify` must return a dropped
    /// receiver (the consensus engine treats `RecvError` as "abstain").
    #[test_traced("WARN")]
    fn test_marshaled_missing_scheme_skips_propose_and_verify() {
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

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis);

            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: setup.mailbox,
                shards: setup.extra,
                scheme_provider: EmptyProvider,
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: me.clone(),
                parent: (View::zero(), genesis_commitment()),
            };

            // propose with a missing scheme returns a dropped sender
            let rx = marshaled.propose(ctx.clone()).await;
            assert!(rx.await.is_err());

            // verify with a missing scheme returns a dropped sender
            let rx = marshaled.verify(ctx, genesis_commitment()).await;
            assert!(rx.await.is_err());
        });
    }

    /// Regression: a validator must not vote finalize on a block that is not
    /// durably persisted. `certify` resolves true ⟹ block is on disk for
    /// this validator. We assert this by aborting the marshal actor the
    /// instant `certify` returns true; without the persist-before-certify
    /// fix, the actor may have only had the `Verified` message enqueued (not
    /// processed), and the block is lost on restart even though the validator
    /// would have proceeded to broadcast a finalize vote.
    #[test_traced("WARN")]
    fn test_marshaled_certify_persists_block_before_resolving() {
        for seed in 0u64..16 {
            certify_persists_block_before_resolving_at(seed);
        }
    }

    fn certify_persists_block_before_resolving_at(seed: u64) {
        let runner = deterministic::Runner::new(
            deterministic::Config::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(60))),
        );
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;
            let marshal_actor_handle = setup.actor_handle;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Push parent (height 1) and child (height 2) into the shards
            // engine. These are reconstructable but NOT durably persisted.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = CodingCtx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(parent_round, coded_parent);

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = CodingCtx {
                round: child_round,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let child = make_coding_block(child_ctx.clone(), parent.digest(), Height::new(2), 200);
            let coded_child = CodedBlock::new(child.clone(), coding_config, &Sequential);
            let child_commitment = coded_child.commitment();
            let child_digest = coded_child.digest();
            shards.proposed(child_round, coded_child);

            context.sleep(Duration::from_millis(10)).await;

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis);
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Optimistic verify - returns shard validity (true).
            let shard_validity = marshaled
                .verify(child_ctx, child_commitment)
                .await
                .await
                .expect("verify result missing");
            assert!(shard_validity, "shard validity should pass");

            // Certify - this is the safety gate before finalize voting.
            let certify_result = marshaled
                .certify(child_round, child_commitment)
                .await
                .await
                .expect("certify result missing");
            assert!(certify_result, "certify should succeed");

            // Abort marshal immediately after certify returns to prove the
            // block is already persisted at that point.
            marshal_actor_handle.abort();
            drop(marshaled);
            drop(marshal);
            drop(shards);

            // Restart from the same partition. The block must be durably
            // persisted - otherwise the validator would have voted finalize
            // for a block it cannot serve from local storage.
            let setup2 = CodingHarness::setup_validator(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            let post_restart = marshal2.get_block(&child_digest).await;
            assert!(
                post_restart.is_some(),
                "certify resolved true ⟹ block must be durably persisted"
            );
        });
    }

    /// Regression: a proposer must be able to recover its own block after a
    /// crash that occurs immediately after `Marshaled::propose()` returns a
    /// commitment. `propose` is responsible for persisting the block via
    /// `marshal.verified`, so the block must survive restart even if
    /// `Relay::broadcast` never runs or marshal aborts in between.
    #[test_traced("WARN")]
    fn test_marshaled_proposed_block_persists_across_restart() {
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

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;
            let marshal_actor_handle = setup.actor_handle;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);

            // Build the block we want propose() to return. Its embedded context
            // uses the proper genesis commitment so fetch_parent matches the
            // cached genesis without going through the marshal subscription.
            let propose_round = Round::new(Epoch::zero(), View::new(1));
            let propose_context = CodingCtx {
                round: propose_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_parent_commitment),
            };
            let block_to_propose = make_coding_block(
                propose_context.clone(),
                genesis.digest(),
                Height::new(1),
                100,
            );
            let block_digest = block_to_propose.digest();
            let expected_commitment = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(
                block_to_propose.clone(),
                coding_config,
                &Sequential,
            )
            .commitment();

            let mock_app: MockVerifyingApp<CodingB, S> =
                MockVerifyingApp::new(genesis).with_propose_result(block_to_propose);
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Drive the leader-side propose path. `propose` must persist the
            // block before returning the commitment.
            let commitment = marshaled
                .propose(propose_context)
                .await
                .await
                .expect("propose should produce a commitment");
            assert_eq!(commitment, expected_commitment);

            // Abort marshal immediately after propose returns; the propose
            // path must already have persisted the block.
            marshal_actor_handle.abort();
            drop(marshaled);
            drop(marshal);
            drop(shards);

            let setup2 = CodingHarness::setup_validator(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            // The proposer must recover its own block after restart. Without
            // the broadcast-path persistence fix, the block lived only in the
            // shards engine's in-memory cache and is now gone.
            let post_restart = marshal2.get_block(&block_digest).await;
            assert!(
                post_restart.is_some(),
                "proposer should recover its own block after restart"
            );
        });
    }

    /// Regression: if marshal already holds a verified block for a round
    /// (say, persisted by a pre-crash propose whose notarize vote never
    /// reached the journal), a restarted leader's `propose` must return
    /// that block's commitment instead of rebuilding. Otherwise the
    /// new block lands on the same view index in the prunable archive,
    /// gets silently dropped (`skip_if_index_exists=true`), and the
    /// leader's notarize targets a commitment no peer can serve.
    #[test_traced("WARN")]
    fn test_propose_reuses_verified_block_on_restart() {
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

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);

            let round = Round::new(Epoch::zero(), View::new(1));
            let ctx = CodingCtx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis_parent_commitment),
            };

            // Seed block A in marshal's verified cache for `round`.
            let block_a = make_coding_block(ctx.clone(), genesis.digest(), Height::new(1), 100);
            let coded_a: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block_a.clone(), coding_config, &Sequential);
            let commitment_a = coded_a.commitment();
            assert!(marshal.verified(round, coded_a).await);

            // After restart, a fresh application would build a different
            // block for the same round.
            let block_b = make_coding_block(ctx.clone(), genesis.digest(), Height::new(1), 200);
            let coded_b: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block_b.clone(), coding_config, &Sequential);
            let commitment_b = coded_b.commitment();
            assert_ne!(
                commitment_a, commitment_b,
                "test requires distinct commitments"
            );

            let mock_app: MockVerifyingApp<CodingB, S> =
                MockVerifyingApp::new(genesis).with_propose_result(block_b);
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let commitment = marshaled
                .propose(ctx)
                .await
                .await
                .expect("propose must return a commitment");
            assert_eq!(
                commitment, commitment_a,
                "propose must reuse the block marshal already persisted for this round"
            );
        });
    }

    /// Regression: if a pre-crash leader persisted a verified block for a
    /// round but the simplex `Notarize` never reached the journal, replay
    /// can recover a `consensus_context` whose parent differs from the one
    /// the cached block was built against. The restarted leader must then
    /// drop the receiver so the voter nullifies the view via
    /// `MissingProposal`, rather than broadcasting the stale cached block
    /// under a header that peers will reject.
    #[test_traced("WARN")]
    fn test_propose_skips_when_verified_block_context_changed() {
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

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);

            // Stash a stale block built against genesis as its parent at round V=2.
            let round = Round::new(Epoch::zero(), View::new(2));
            let stale_ctx = CodingCtx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis_parent_commitment),
            };
            let stale_block = make_coding_block(stale_ctx, genesis.digest(), Height::new(1), 100);
            let stale_coded: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(stale_block, coding_config, &Sequential);
            assert!(marshal.verified(round, stale_coded).await);

            // Simulate a replay where parent selection now points to a
            // different parent commitment than the cached block was built for.
            let new_parent_commitment = Commitment::from((
                Sha256::hash(b"different-parent-block"),
                Sha256::hash(b"different-parent-inner"),
                Sha256::hash(b"different-parent-ctx"),
                coding_config,
            ));
            let new_ctx = CodingCtx {
                round,
                leader: me.clone(),
                parent: (View::new(1), new_parent_commitment),
            };

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new(genesis);
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let commitment_rx = marshaled.propose(new_ctx).await;
            assert!(
                commitment_rx.await.is_err(),
                "propose must drop the receiver when the cached block's context no longer matches"
            );
        });
    }
}
