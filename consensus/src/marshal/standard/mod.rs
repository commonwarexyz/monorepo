//! Standard variant for Marshal.
//!
//! # Overview
//!
//! The standard variant broadcasts complete blocks to all peers without erasure coding.
//! This is simpler but uses more bandwidth than the coding variant.
//!
//! # Components
//!
//! - [`Standard`]: The variant marker type that configures marshal for full-block broadcast.
//! - [`Marshaled`]: Wraps an [`crate::Application`] implementation to enforce epoch boundaries
//!   and coordinate with the marshal actor.
//!
//! # Usage
//!
//! The standard variant uses the core [`crate::marshal::core::Actor`] and
//! [`crate::marshal::core::Mailbox`] with [`Standard`] as the variant type parameter.
//! Blocks are broadcast through [`commonware_broadcast::buffered`].
//!
//! # When to Use
//!
//! Prefer this variant when validators can afford to ship entire blocks to every peer or when
//! erasure coding is unnecessary.

mod marshaled;
pub use marshaled::Marshaled;

mod variant;
pub use variant::Standard;

#[cfg(test)]
mod tests {
    use crate::{
        marshal::{
            ancestry::{AncestorStream, AncestryProvider},
            mocks::harness::{
                default_leader, make_raw_block, setup_network, Ctx, StandardHarness, TestHarness,
                B, BLOCKS_PER_EPOCH, D, K, NAMESPACE, NUM_VALIDATORS, S, V,
            },
            standard::Marshaled,
        },
        simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Context},
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View},
        Automaton, CertifiableAutomaton, VerifyingApplication,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use std::time::Duration;

    #[test_traced("WARN")]
    fn test_marshaled_rejects_invalid_ancestry() {
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: B,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = B;
            type Context = Context<D, K>;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            // Create genesis block
            let genesis_ctx = Ctx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), Sha256::hash(b"")),
            };
            let genesis = B::new::<Sha256>(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Wrap with Marshaled verifier
            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
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
            let honest_parent_ctx = Ctx {
                round: Round::new(Epoch::new(1), View::new(21)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let honest_parent = B::new::<Sha256>(
                honest_parent_ctx,
                genesis.digest(),
                Height::new(BLOCKS_PER_EPOCH.get() + 1),
                1000,
            );
            let parent_commitment = honest_parent.digest();
            let parent_round = Round::new(Epoch::new(1), View::new(21));
            marshal
                .clone()
                .verified(parent_round, honest_parent.clone())
                .await;

            // Byzantine proposer broadcasts malicious block at height 35
            // In reality this would come via buffered broadcast, but for test simplicity
            // we call broadcast() directly which makes it available for subscription
            let malicious_ctx1 = Ctx {
                round: Round::new(Epoch::new(1), View::new(35)),
                leader: default_leader(),
                parent: (View::new(21), parent_commitment),
            };
            let malicious_block = B::new::<Sha256>(
                malicious_ctx1,
                parent_commitment,
                Height::new(BLOCKS_PER_EPOCH.get() + 15),
                2000,
            );
            let malicious_commitment = malicious_block.digest();
            marshal
                .clone()
                .proposed(
                    Round::new(Epoch::new(1), View::new(35)),
                    malicious_block.clone(),
                    (),
                )
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 35
            let byzantine_context = Context {
                round: Round::new(Epoch::new(1), View::new(35)),
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

            // Marshaled.verify() should reject the malicious block
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 35) from marshal based on digest
            // 3. Validate height is contiguous (fail)
            // 4. Return false
            let verify = marshaled
                .verify(byzantine_context, malicious_commitment)
                .await;

            assert!(
                !verify.await.unwrap(),
                "Byzantine block with non-contiguous heights should be rejected"
            );

            // Test case 2: Mismatched parent commitment
            //
            // Create another malicious block with correct height but invalid parent commitment
            let malicious_ctx2 = Ctx {
                round: Round::new(Epoch::new(1), View::new(22)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()), // Claims genesis as parent
            };
            let malicious_block = B::new::<Sha256>(
                malicious_ctx2,
                genesis.digest(),
                Height::new(BLOCKS_PER_EPOCH.get() + 2),
                3000,
            );
            let malicious_digest = malicious_block.digest();
            marshal
                .clone()
                .proposed(
                    Round::new(Epoch::new(1), View::new(22)),
                    malicious_block.clone(),
                    (),
                )
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 22
            let byzantine_context = Context {
                round: Round::new(Epoch::new(1), View::new(22)),
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

            // Marshaled.verify() should reject the malicious block
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 22) from marshal based on digest
            // 3. Validate height is contiguous
            // 3. Validate parent commitment matches (fail)
            // 4. Return false
            let verify = marshaled.verify(byzantine_context, malicious_digest).await;

            assert!(
                !verify.await.unwrap(),
                "Byzantine block with mismatched parent commitment should be rejected"
            );
        })
    }

    #[test_traced("WARN")]
    #[test_traced("WARN")]
    fn test_marshaled_rejects_unsupported_epoch() {
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: B,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = B;
            type Context = Context<D, K>;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis_ctx = Ctx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), Sha256::hash(b"")),
            };
            let genesis = B::new::<Sha256>(genesis_ctx, Sha256::hash(b""), Height::new(0), 0);

            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
            };
            let limited_epocher = LimitedEpocher {
                inner: FixedEpocher::new(BLOCKS_PER_EPOCH),
                max_epoch: 0,
            };
            let mut marshaled =
                Marshaled::new(context.clone(), mock_app, marshal.clone(), limited_epocher);

            // Create a parent block at height 19 (last block in epoch 0, which is supported)
            let parent_ctx = Ctx {
                round: Round::new(Epoch::zero(), View::new(19)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(19), 1000);
            let parent_digest = parent.digest();
            let parent_round = Round::new(Epoch::new(0), View::new(19));
            marshal.clone().verified(parent_round, parent).await;

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let block_ctx = Ctx {
                round: Round::new(Epoch::new(1), View::new(20)),
                leader: default_leader(),
                parent: (View::new(19), parent_digest),
            };
            let block = B::new::<Sha256>(block_ctx, parent_digest, Height::new(20), 2000);
            let block_digest = block.digest();
            marshal
                .clone()
                .proposed(Round::new(Epoch::new(1), View::new(20)), block, ())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            let unsupported_context = Context {
                round: Round::new(Epoch::new(1), View::new(20)),
                leader: me.clone(),
                parent: (View::new(19), parent_digest),
            };

            let verify = marshaled.verify(unsupported_context, block_digest).await;

            assert!(
                !verify.await.unwrap(),
                "Block in unsupported epoch should be rejected"
            );
        })
    }

    #[test_traced("INFO")]
    #[test_traced("INFO")]
    fn test_certify_lower_view_after_higher_view() {
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: B,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = B;
            type Context = Context<D, K>;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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

            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
            };
            let mut marshaled = Marshaled::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Create parent block at height 1
            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            let parent_round = Round::new(Epoch::new(0), View::new(1));
            marshal.clone().verified(parent_round, parent).await;

            // Block A at view 5 (height 2) - create with context matching what verify will receive
            let round_a = Round::new(Epoch::new(0), View::new(5));
            let context_a = Context {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let block_a = B::new::<Sha256>(context_a.clone(), parent_digest, Height::new(2), 200);
            let digest_a = block_a.digest();
            marshal.clone().proposed(round_a, block_a, ()).await;

            // Block B at view 10 (height 2, different block same height - could happen with
            // different proposers or re-proposals)
            let round_b = Round::new(Epoch::new(0), View::new(10));
            let context_b = Context {
                round: round_b,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let block_b = B::new::<Sha256>(context_b.clone(), parent_digest, Height::new(2), 300);
            let digest_b = block_b.digest();
            marshal.clone().proposed(round_b, block_b, ()).await;

            context.sleep(Duration::from_millis(10)).await;

            // Step 1: Verify block A at view 5
            let _ = marshaled.verify(context_a, digest_a).await.await;

            // Step 2: Verify block B at view 10
            let _ = marshaled.verify(context_b, digest_b).await.await;

            // Step 3: Certify block B at view 10 FIRST
            let certify_b = marshaled.certify(round_b, digest_b).await;
            assert!(
                certify_b.await.unwrap(),
                "Block B certification should succeed"
            );

            // Step 4: Certify block A at view 5 - should succeed
            let certify_a = marshaled.certify(round_a, digest_a).await;

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
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: B,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = B;
            type Context = Context<D, K>;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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

            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
            };
            let mut marshaled = Marshaled::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Build a chain up to the epoch boundary (height 19 is the last block in epoch 0
            // with BLOCKS_PER_EPOCH=20, since epoch 0 covers heights 0-19)
            let mut parent = genesis.digest();
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
                parent = block.digest();
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
            let boundary_digest = boundary_block.digest();
            marshal
                .clone()
                .verified(boundary_round, boundary_block.clone())
                .await;

            // Make the boundary block available for subscription
            marshal
                .clone()
                .proposed(boundary_round, boundary_block.clone(), ())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Test 1: Valid re-proposal at epoch boundary should be accepted
            // Re-proposal context: parent digest equals the block being verified
            // Re-proposals happen within the same epoch when the parent is the last block
            let reproposal_round = Round::new(Epoch::new(0), View::new(20));
            let reproposal_context = Context {
                round: reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_digest), // Parent IS the boundary block
            };

            // Call verify (which calls optimistic_verify internally via Automaton trait)
            let verify_result = marshaled
                .verify(reproposal_context.clone(), boundary_digest)
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
            let non_boundary_digest = non_boundary_block.digest();

            // Make the non-boundary block available
            marshal
                .clone()
                .proposed(non_boundary_round, non_boundary_block.clone(), ())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Attempt to re-propose the non-boundary block
            let invalid_reproposal_round = Round::new(Epoch::new(0), View::new(15));
            let invalid_reproposal_context = Context {
                round: invalid_reproposal_round,
                leader: me.clone(),
                parent: (View::new(10), non_boundary_digest),
            };

            let verify_result = marshaled
                .verify(invalid_reproposal_context, non_boundary_digest)
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
                parent: (View::new(boundary_height.get()), boundary_digest),
            };

            let verify_result = marshaled
                .verify(cross_epoch_reproposal_context, boundary_digest)
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
                .certify(certify_only_round, boundary_digest)
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
            let genesis_digest = genesis.digest();

            let normal_context = Context {
                round: normal_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_digest),
            };
            let normal_block =
                B::new::<Sha256>(normal_context.clone(), genesis_digest, normal_height, 500);
            let normal_digest = normal_block.digest();
            marshal
                .clone()
                .proposed(normal_round, normal_block.clone(), ())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Certify without calling verify first
            let certify_result = marshaled.certify(normal_round, normal_digest).await.await;
            assert!(
                certify_result.unwrap(),
                "Certify-only path for normal block should succeed"
            );
        })
    }
}
