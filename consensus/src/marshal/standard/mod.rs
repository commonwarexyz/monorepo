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
mod tests {
    use crate::marshal::mocks::harness::{self, StandardHarness, LINK, UNRELIABLE_LINK};
    use commonware_macros::test_traced;
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
}

#[cfg(test)]
mod wrapper_tests {
    use super::{Deferred, Inline, Standard};
    use crate::{
        marshal::{
            core::Mailbox,
            mocks::{
                harness::{
                    default_leader, make_raw_block, setup_network, Ctx, StandardHarness,
                    TestHarness, B, BLOCKS_PER_EPOCH, D, NAMESPACE, NUM_VALIDATORS, S, V,
                },
                verifying::MockVerifyingApp,
            },
        },
        simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Epoch, FixedEpocher, Height, Round, View},
        Automaton, CertifiableAutomaton,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use commonware_utils::channel::oneshot;
    use std::time::Duration;

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
    fn test_wrapper_propose_paths() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let mut oracle = setup_network(context.clone(), None);
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
    fn test_wrapper_verify_reproposal_validation() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let mut oracle = setup_network(context.clone(), None);
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
    fn test_wrapper_verify_rejects_invalid_ancestry() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let mut oracle = setup_network(context.clone(), None);
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
                    assert!(
                        !malformed_verify,
                        "inline verify should reject non-contiguous ancestry"
                    );
                } else {
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
                    assert!(
                        !mismatch_verify,
                        "inline verify should reject mismatched parent digest"
                    );
                } else {
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
    fn test_wrapper_application_verify_failure() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let mut oracle = setup_network(context.clone(), None);
                let Fixture {
                    participants,
                    schemes,
                    ..
                } =
                    bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
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

                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent = B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 100);
                let parent_digest = parent.digest();
                marshal.clone().proposed(parent_round, parent).await;

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
