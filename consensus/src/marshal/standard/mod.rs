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
});

mod verification;

mod variant;
pub use variant::Standard;

#[cfg(test)]
mod wrapper_tests;

#[cfg(test)]
mod tests {
    use crate::{
        marshal::{
            mocks::{
                harness::{
                    self, default_leader, make_raw_block, setup_network, Ctx, StandardHarness,
                    TestHarness, B, BLOCKS_PER_EPOCH, LINK, NAMESPACE, NUM_VALIDATORS, S,
                    UNRELIABLE_LINK, V,
                },
                verifying::MockVerifyingApp,
            },
            standard::Deferred,
        },
        simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View},
        Automaton, CertifiableAutomaton,
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
    fn test_standard_finalize_good_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<StandardHarness>(seed, LINK, false);
            let r2 = harness::finalize::<StandardHarness>(seed, LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_bad_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<StandardHarness>(seed, UNRELIABLE_LINK, false);
            let r2 = harness::finalize::<StandardHarness>(seed, UNRELIABLE_LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<StandardHarness>(seed, LINK, true);
            let r2 = harness::finalize::<StandardHarness>(seed, LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<StandardHarness>(seed, UNRELIABLE_LINK, true);
            let r2 = harness::finalize::<StandardHarness>(seed, UNRELIABLE_LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_ack_pipeline_backlog() {
        harness::ack_pipeline_backlog::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_ack_pipeline_backlog_persists_on_restart() {
        harness::ack_pipeline_backlog_persists_on_restart::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_sync_height_floor() {
        harness::sync_height_floor::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_reject_stale_block_delivery_after_floor_update() {
        harness::reject_stale_block_delivery_after_floor_update::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_prune_finalized_archives() {
        harness::prune_finalized_archives::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_basic_block_delivery() {
        harness::subscribe_basic_block_delivery::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_multiple_subscriptions() {
        harness::subscribe_multiple_subscriptions::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_canceled_subscriptions() {
        harness::subscribe_canceled_subscriptions::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_blocks_from_different_sources() {
        harness::subscribe_blocks_from_different_sources::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_info_basic_queries_present_and_missing() {
        harness::get_info_basic_queries_present_and_missing::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_info_latest_progression_multiple_finalizations() {
        harness::get_info_latest_progression_multiple_finalizations::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_block_by_height_and_latest() {
        harness::get_block_by_height_and_latest::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_block_by_commitment_from_sources_and_missing() {
        harness::get_block_by_commitment_from_sources_and_missing::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_finalization_by_height() {
        harness::get_finalization_by_height::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_hint_finalized_triggers_fetch() {
        harness::hint_finalized_triggers_fetch::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_ancestry_stream() {
        harness::ancestry_stream::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_same_height_different_views() {
        harness::finalize_same_height_different_views::<StandardHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_init_processed_height() {
        harness::init_processed_height::<StandardHarness>();
    }

    #[test_traced("INFO")]
    fn test_standard_broadcast_caches_block() {
        harness::broadcast_caches_block::<StandardHarness>();
    }

    #[test_traced("INFO")]
    fn test_standard_rejects_block_delivery_below_floor() {
        harness::reject_stale_block_delivery_after_floor_update::<StandardHarness>();
    }

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

            let mut marshaled = Deferred::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Create parent block at height 1
            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            marshal
                .clone()
                .proposed(Round::new(Epoch::new(0), View::new(1)), parent.clone())
                .await;

            // Block A at view 5 (height 2)
            let round_a = Round::new(Epoch::new(0), View::new(5));
            let context_a = Ctx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let block_a = B::new::<Sha256>(context_a.clone(), parent_digest, Height::new(2), 200);
            let commitment_a = block_a.digest();
            marshal.clone().proposed(round_a, block_a.clone()).await;

            // Block B at view 10 (height 2, different block same height)
            let round_b = Round::new(Epoch::new(0), View::new(10));
            let context_b = Ctx {
                round: round_b,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let block_b = B::new::<Sha256>(context_b.clone(), parent_digest, Height::new(2), 300);
            let commitment_b = block_b.digest();
            marshal.clone().proposed(round_b, block_b.clone()).await;

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
            let limited_epocher = LimitedEpocher {
                inner: FixedEpocher::new(BLOCKS_PER_EPOCH),
                max_epoch: 0,
            };

            let mut marshaled =
                Deferred::new(context.clone(), mock_app, marshal.clone(), limited_epocher);

            // Create a parent block at height 19 (last block in epoch 0, which is supported)
            let parent_ctx = Ctx {
                round: Round::new(Epoch::zero(), View::new(19)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent =
                B::new::<Sha256>(parent_ctx.clone(), genesis.digest(), Height::new(19), 1000);
            let parent_digest = parent.digest();
            marshal
                .clone()
                .proposed(Round::new(Epoch::zero(), View::new(19)), parent.clone())
                .await;

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let unsupported_round = Round::new(Epoch::new(1), View::new(20));
            let unsupported_context = Ctx {
                round: unsupported_round,
                leader: me.clone(),
                parent: (View::new(19), parent_digest),
            };
            let block = B::new::<Sha256>(
                unsupported_context.clone(),
                parent_digest,
                Height::new(20),
                2000,
            );
            let block_commitment = block.digest();
            marshal
                .clone()
                .proposed(unsupported_round, block.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Call verify and wait for the result (verify returns optimistic result,
            // but also spawns deferred verification)
            let verify_result = marshaled
                .verify(unsupported_context, block_commitment)
                .await;
            // Wait for optimistic verify to complete so the verification task is registered
            let optimistic_result = verify_result.await;

            // The optimistic verify should return false because the block is in an unsupported epoch
            assert!(
                !optimistic_result.unwrap(),
                "Optimistic verify should reject block in unsupported epoch"
            );
        })
    }

    /// Test that marshaled rejects blocks when consensus context doesn't match block's embedded context.
    ///
    /// This tests that when verify() is called with a context that doesn't match what's embedded
    /// in the block, the verification should fail. A Byzantine proposer could broadcast a block
    /// with one embedded context but consensus could call verify() with a different context.
    #[test_traced("WARN")]
    fn test_marshaled_rejects_mismatched_context() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
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
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());

            let mut marshaled = Deferred::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Create parent block at height 1 so the commitment is well-formed.
            let parent_ctx = Ctx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_commitment = parent.digest();
            marshal
                .clone()
                .proposed(Round::new(Epoch::zero(), View::new(1)), parent.clone())
                .await;

            // Build a block with context A (embedded in the block).
            let round_a = Round::new(Epoch::zero(), View::new(2));
            let context_a = Ctx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a = B::new::<Sha256>(context_a, parent.digest(), Height::new(2), 200);
            let commitment_a = block_a.digest();
            marshal.clone().proposed(round_a, block_a).await;

            context.sleep(Duration::from_millis(10)).await;

            // Verify using a different consensus context B (hash mismatch).
            let round_b = Round::new(Epoch::zero(), View::new(3));
            let context_b = Ctx {
                round: round_b,
                leader: participants[1].clone(),
                parent: (View::new(1), parent_commitment),
            };

            let verify_rx = marshaled.verify(context_b, commitment_a).await;
            select! {
                result = verify_rx => {
                    assert!(
                        !result.unwrap(),
                        "mismatched context hash should be rejected"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify should reject mismatched context hash promptly");
                },
            }
        })
    }
}
