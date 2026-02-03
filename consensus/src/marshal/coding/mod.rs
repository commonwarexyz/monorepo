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
//!    obtains a [`crate::types::CodingCommitment`] describing the shard layout.
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
//! same ordering guarantees provided by [`super::standard`]. The API mirrors the standard marshal,
//! so applications can switch between the two by swapping the variant type and buffer implementation
//! they provide to the core actor.

pub mod shards;
pub mod types;

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
                    default_leader, genesis_commitment, make_coding_block, setup_network, CodingB,
                    CodingCtx, CodingHarness, TestHarness, BLOCKS_PER_EPOCH, NAMESPACE,
                    NUM_VALIDATORS, S, V,
                },
                verifying::MockVerifyingApp,
            },
        },
        simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View},
        Automaton, CertifiableAutomaton,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        sha256::Sha256,
        Committable, Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_traced};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use std::time::Duration;

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
                partition_prefix: "test_certify_marshaled".to_string(),
            };
            let mut marshaled = Marshaled::init(context.clone(), cfg).await;

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
                .proposed(coded_parent, participants.clone())
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
            shards
                .clone()
                .proposed(coded_block_a, participants.clone())
                .await;

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
            shards
                .clone()
                .proposed(coded_block_b, participants.clone())
                .await;

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
                partition_prefix: "test_reproposal_marshaled".to_string(),
            };
            let mut marshaled = Marshaled::init(context.clone(), cfg).await;

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
                shards
                    .clone()
                    .proposed(coded_block, participants.clone())
                    .await;
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
                .proposed(coded_boundary, participants.clone())
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

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(reproposal_context.clone(), boundary_commitment)
                .await;

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
                .proposed(coded_non_boundary, participants.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Attempt to re-propose the non-boundary block
            let invalid_reproposal_round = Round::new(Epoch::new(0), View::new(15));
            let invalid_reproposal_context = CodingCtx {
                round: invalid_reproposal_round,
                leader: me.clone(),
                parent: (View::new(10), non_boundary_commitment),
            };

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(invalid_reproposal_context, non_boundary_commitment)
                .await;

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

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(cross_epoch_reproposal_context.clone(), boundary_commitment)
                .await;

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
                partition_prefix: "test_unsupported_epoch_marshaled".to_string(),
            };
            let mut marshaled = Marshaled::init(context.clone(), cfg).await;

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
                .proposed(coded_parent, participants.clone())
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
                .proposed(coded_block, participants.clone())
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
                partition_prefix: "test_invalid_ancestry_marshaled".to_string(),
            };
            let mut marshaled = Marshaled::init(context.clone(), cfg).await;

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
                .proposed(coded_parent, participants.clone())
                .await;

            // Byzantine proposer broadcasts malicious block at height 35
            // In reality this would come via buffered broadcast, but for test simplicity
            // we call broadcast() directly which makes it available for subscription
            let malicious_ctx1 = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(35)),
                leader: default_leader(),
                parent: (View::new(21), parent_commitment),
            };
            let malicious_block = make_coding_block(
                malicious_ctx1,
                parent_digest,
                Height::new(BLOCKS_PER_EPOCH.get() + 15),
                2000,
            );
            let coded_malicious =
                CodedBlock::new(malicious_block.clone(), coding_config, &Sequential);
            let malicious_commitment = coded_malicious.commitment();
            shards
                .clone()
                .proposed(coded_malicious, participants.clone())
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 35
            //
            // In the coding marshal, verify() returns shard validity while deferred_verify
            // runs in the background. We need to use certify() to get the deferred_verify result.
            let byzantine_round = Round::new(Epoch::new(1), View::new(35));
            let byzantine_context = CodingCtx {
                round: byzantine_round,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

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

            // Test case 2: Mismatched parent commitment
            //
            // Create another malicious block with correct height but invalid parent commitment
            let malicious_ctx2 = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(22)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()), // Claims genesis as parent
            };
            let malicious_block2 = make_coding_block(
                malicious_ctx2,
                genesis.digest(),
                Height::new(BLOCKS_PER_EPOCH.get() + 2),
                3000,
            );
            let coded_malicious2 =
                CodedBlock::new(malicious_block2.clone(), coding_config, &Sequential);
            let malicious_commitment2 = coded_malicious2.commitment();
            shards
                .clone()
                .proposed(coded_malicious2, participants.clone())
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 22
            let byzantine_round2 = Round::new(Epoch::new(1), View::new(22));
            let byzantine_context2 = CodingCtx {
                round: byzantine_round2,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

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
}
