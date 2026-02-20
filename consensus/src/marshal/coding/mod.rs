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
                types::{coding_config_for_participants, CodedBlock},
                Marshaled, MarshaledConfig,
            },
            mocks::{
                harness::{
                    self, default_leader, genesis_commitment, make_coding_block, setup_network,
                    setup_network_links, CodingB, CodingCtx, CodingHarness, TestHarness,
                    BLOCKS_PER_EPOCH, LINK, NAMESPACE, NUM_VALIDATORS, QUORUM, S, UNRELIABLE_LINK,
                    V,
                },
                verifying::MockVerifyingApp,
            },
        },
        simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Proposal},
        types::{coding::Commitment, Epoch, Epocher, FixedEpocher, Height, Round, View},
        Automaton, CertifiableAutomaton,
    };
    use commonware_codec::FixedSize;
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        sha256::Sha256,
        Committable, Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::Manager;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use commonware_utils::NZU16;
    use std::time::Duration;

    #[test_traced("WARN")]
    fn test_coding_finalize_good_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, LINK, false);
            let r2 = harness::finalize::<CodingHarness>(seed, LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_bad_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, false);
            let r2 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, LINK, true);
            let r2 = harness::finalize::<CodingHarness>(seed, LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, true);
            let r2 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, true);
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
    fn test_coding_sync_height_floor() {
        harness::sync_height_floor::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_prune_finalized_archives() {
        harness::prune_finalized_archives::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_rejects_block_delivery_below_floor() {
        harness::reject_stale_block_delivery_after_floor_update::<CodingHarness>();
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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

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
            shards
                .clone()
                .proposed(Round::new(Epoch::new(0), View::new(1)), coded_parent)
                .await;

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
            shards.clone().proposed(round_a, coded_block_a).await;

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
            shards.clone().proposed(round_b, coded_block_b).await;

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

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
                shards.clone().proposed(round, coded_block).await;
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
            shards
                .clone()
                .proposed(boundary_round, coded_boundary)
                .await;

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
            shards
                .clone()
                .proposed(non_boundary_round, coded_non_boundary)
                .await;

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

            // Create parent block at height 1 so the commitment is well-formed.
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards
                .clone()
                .proposed(Round::new(Epoch::zero(), View::new(1)), coded_parent)
                .await;

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

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
            shards.prune(missing_payload).await;

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
                .subscribe_by_commitment(Some(round), missing_commitment)
                .await;

            // Allow core actor to register the underlying buffer subscription.
            context.sleep(Duration::from_millis(100)).await;

            // Prune the missing commitment in the shard engine, which should cancel
            // the underlying buffer subscription.
            shards.prune(missing_commitment).await;

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

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
            shards
                .clone()
                .proposed(Round::new(Epoch::zero(), View::new(19)), coded_parent)
                .await;

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let block_ctx = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(20)),
                leader: default_leader(),
                parent: (View::new(19), parent_commitment),
            };
            let block = make_coding_block(block_ctx, parent_digest, Height::new(20), 2000);
            let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
            let block_commitment = coded_block.commitment();
            shards
                .clone()
                .proposed(Round::new(Epoch::new(1), View::new(20)), coded_block)
                .await;

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

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
            shards
                .clone()
                .proposed(Round::new(Epoch::new(1), View::new(21)), coded_parent)
                .await;

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
            shards
                .clone()
                .proposed(byzantine_round, coded_malicious)
                .await;

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
            shards
                .clone()
                .proposed(byzantine_round2, coded_malicious2)
                .await;

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

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
            shards.clone().proposed(parent_round, coded_parent).await;

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
            shards.clone().proposed(child_round, coded_child).await;

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
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut marshaled = Marshaled::new(context.clone(), cfg);

            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_context = CodingCtx {
                round: parent_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_context, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.clone().proposed(parent_round, coded_parent).await;

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
            shards.clone().proposed(round, coded_block).await;

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
        // Regression: when backfilling by Request::Block(digest), a peer may return
        // a coded block with matching inner digest but a different coding commitment.
        // If a finalization for this digest is already cached, marshal must reject
        // the block unless V::commitment(block) matches the finalization payload.
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), Some(1));
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let coding_config_a = coding_config_for_participants(NUM_VALIDATORS as u16);
            // Same total shards (4) but different min/extra split produces a different
            // coding root and config bytes, yielding a different commitment.
            let coding_config_b = commonware_coding::Config {
                minimum_shards: coding_config_a.minimum_shards.checked_add(1).unwrap(),
                extra_shards: NZU16!(coding_config_a.extra_shards.get() - 1),
            };

            let v0_setup = CodingHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let v1_setup = CodingHarness::setup_validator(
                context.with_label("validator_1"),
                &mut oracle,
                participants[1].clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;

            setup_network_links(&mut oracle, &participants[..2], LINK).await;
            oracle
                .manager()
                .track(0, participants[..2].to_vec().try_into().unwrap())
                .await;

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
            v1_mailbox.proposed(round1, coded_block_b.clone()).await;
            context.sleep(Duration::from_millis(100)).await;

            // Create finalization referencing commitment_a (the "correct" commitment).
            let proposal: Proposal<Commitment> = Proposal {
                round: round1,
                parent: View::zero(),
                payload: commitment_a,
            };
            let finalization = CodingHarness::make_finalization(proposal.clone(), &schemes, QUORUM);

            // Report finalization to v0. v0 doesn't have the block:
            //   - it fetches Request::Block(digest)
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
}
