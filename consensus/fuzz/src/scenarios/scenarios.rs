//! Concrete marshal scenarios extracted from the standard-marshal tests.
//!
//! Each scenario scripts a deterministic prefix over the honest core {B, C, D}
//! (node A is reserved for the adversary) and stops at an interesting semantic
//! point, returning the certified floor the engines start from. Node D is the
//! deprived node; B and C are the holders that keep full state and serve
//! backfill. Fabricated certificates are signed by the honest quorum.
//!
//! Every scenario is annotated with the standard-marshal test it derives from.

use super::{
    environment::{Expectation, FuzzPoint, Node, PendingBlock, QUORUM_SIGNERS, ScenarioEnv},
    input::ScenarioKind,
};
use crate::{marshal::end_to_end::twins::B, simplex::Simplex};
use commonware_consensus::types::Height;
use commonware_cryptography::Digestible;

/// A scripted prefix that drives the cluster to an interesting marshal state.
///
/// Every scenario runs on the `Deferred` marshal (the certify-fetch path is only
/// meaningful there; `Inline`'s certify structurally returns true) with the
/// always-accept block builder, so the runner uses those concrete types directly.
pub(crate) trait Scenario {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P>;
}

/// Dispatch to the concrete scenario for `kind`.
pub(crate) async fn drive<P: Simplex>(kind: ScenarioKind, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
    match kind {
        ScenarioKind::MissingCandidate => MissingCandidate.drive(env).await,
        ScenarioKind::FinalizationWithoutBlock => FinalizationWithoutBlock.drive(env).await,
        ScenarioKind::SubscribeBeforeBlock => SubscribeBeforeBlock.drive(env).await,
        ScenarioKind::SameHeightDifferentViews => SameHeightDifferentViews.drive(env).await,
        ScenarioKind::PendingFloorAnchor => PendingFloorAnchor.drive(env).await,
    }
}

/// Verify `block` at `view` on each node in `nodes`, then report its finalization
/// (over the honest quorum) to each, so every listed node delivers it and can
/// serve it via backfill.
async fn seed_finalized<P: Simplex>(env: &ScenarioEnv<P>, nodes: &[Node], view: u64, block: &B<P>) {
    for &node in nodes {
        env.verify(node, view, block).await;
    }
    let finalization = env.finalization(block, &QUORUM_SIGNERS);
    for &node in nodes {
        env.report_finalization(node, finalization.clone());
    }
}

const HOLDERS: [Node; 2] = [Node::B, Node::C];
const HOLDERS_AND_DEPRIVED: [Node; 3] = [Node::B, Node::C, Node::D];

// State from test_standard_certify_missing_candidate_fetches_by_round
// (consensus/src/marshal/standard/mod.rs:2489); the retained verify gate makes
// certify take the existing-task path exercised by
// test_standard_certify_bumps_notarized_fetch_for_pending_verify (:2571).
pub(crate) struct MissingCandidate;

impl Scenario for MissingCandidate {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        // Canonical h1, h2 finalized on the holders and the deprived node.
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS_AND_DEPRIVED, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS_AND_DEPRIVED, 2, &h2).await;

        // A side block at view 3 built on h2, notarized by the quorum but held
        // only on the holders. The deprived node never receives it.
        let side = env.fork_block(&h2, Node::C, 3, Height::new(3));
        env.verify(Node::B, 3, &side).await;
        env.verify(Node::C, 3, &side).await;
        let side_notarization = env.notarization_at(3, 2, &side, &QUORUM_SIGNERS);
        env.report_notarization(Node::B, side_notarization.clone());
        env.report_notarization(Node::C, side_notarization);

        // Canonical h3 at view 4 (skipping the nullified view 3), finalized on
        // the holders only. This finalization is the floor.
        let h3 = env.block(Node::B, 4);
        seed_finalized(env, &HOLDERS, 4, &h3).await;
        let floor = env.finalization_at(4, 2, &h3, &QUORUM_SIGNERS);

        // Drive the deprived node into the missing-candidate state through the
        // real automaton, which is the operation under test: an optimistic verify
        // registers the certification gate (kept open by holding its receiver),
        // then certify itself must issue the notarized fetch that repairs the
        // candidate from a holder (the deprived node holds the notarization
        // reference but not the block). This runs while the network is meshed,
        // before any floor advance prunes the round-bound fetch. If certify no
        // longer issued that fetch, the block would stay missing and the
        // availability assertion below would fail.
        let verify_gate = env
            .automaton_verify_hold(Node::D, side.context.clone(), side.digest())
            .await;
        assert!(
            env.automaton_certify(Node::D, 3, side.digest()).await,
            "certify must resolve true for the missing candidate",
        );
        assert!(
            env.get_block(Node::D, side.digest()).await.is_some(),
            "certify must make the missing candidate locally available on the deprived node",
        );
        drop(verify_gate);
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            prefix_fetches: Vec::new(),
            subscriptions: Vec::new(),
            expectation: Expectation {
                floor_started: None,
                deprived: Node::D,
                deprived_min_height: 3,
                finalization_views: Vec::new(),
            },
        }
    }
}

// Extracted from test_standard_restart_repairs_trailing_missing_finalized_block
// (consensus/src/marshal/standard/mod.rs:567).
pub(crate) struct FinalizationWithoutBlock;

impl Scenario for FinalizationWithoutBlock {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let h3 = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &h3).await;
        let floor = env.finalization(&h3, &QUORUM_SIGNERS);

        // The deprived node receives only the tip finalization and no blocks, so
        // it must repair the whole chain by backfill.
        env.report_finalization(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            prefix_fetches: Vec::new(),
            subscriptions: Vec::new(),
            expectation: Expectation {
                floor_started: None,
                deprived: Node::D,
                deprived_min_height: 3,
                finalization_views: Vec::new(),
            },
        }
    }
}

// Extracted from test_standard_subscribe_basic_block_delivery /
// subscribe_blocks_from_different_sources
// (consensus/src/marshal/standard/mod.rs:346 / :364).
pub(crate) struct SubscribeBeforeBlock;

impl Scenario for SubscribeBeforeBlock {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let floor = env.finalization(&h2, &QUORUM_SIGNERS);

        // The deprived node subscribes to both blocks before holding either,
        // then is handed the tip finalization so backfill resolves the waits.
        let sub1 = env.subscribe(Node::D, h1.digest());
        let sub2 = env.subscribe(Node::D, h2.digest());
        env.report_finalization(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            prefix_fetches: Vec::new(),
            subscriptions: vec![
                PendingBlock {
                    node: Node::D,
                    expected: h1.digest(),
                    receiver: sub1,
                },
                PendingBlock {
                    node: Node::D,
                    expected: h2.digest(),
                    receiver: sub2,
                },
            ],
            expectation: Expectation {
                floor_started: None,
                deprived: Node::D,
                deprived_min_height: 2,
                finalization_views: Vec::new(),
            },
        }
    }
}

// Extracted from finalize_same_height_different_views
// (consensus/src/marshal/mocks/harness.rs:5100, test standard/mod.rs:1375).
pub(crate) struct SameHeightDifferentViews;

impl Scenario for SameHeightDifferentViews {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        // One block finalized at two different views: view 1 on the holders,
        // view 2 on the deprived node. Same payload, divergent certificates.
        let b1 = env.block(Node::B, 1);
        env.verify(Node::B, 1, &b1).await;
        env.verify(Node::C, 1, &b1).await;
        env.verify(Node::D, 1, &b1).await;
        let finalization_v1 = env.finalization_at(1, 0, &b1, &QUORUM_SIGNERS);
        let finalization_v2 = env.finalization_at(2, 0, &b1, &QUORUM_SIGNERS);
        env.report_finalization(Node::B, finalization_v1.clone());
        env.report_finalization(Node::C, finalization_v1.clone());
        env.report_finalization(Node::D, finalization_v2.clone());
        let _ = env.barrier(Node::B).await;
        let _ = env.barrier(Node::D).await;

        // Oracle: each node stored the finalization view it saw first.
        assert_eq!(
            env.finalization_view(Node::B, 1).await,
            Some(1),
            "holder stored the wrong finalization view",
        );
        assert_eq!(
            env.finalization_view(Node::D, 1).await,
            Some(2),
            "deprived node stored the wrong finalization view",
        );

        // Cross-report the other view: first-finalization-wins must hold.
        env.report_finalization(Node::B, finalization_v2);
        env.report_finalization(Node::D, finalization_v1);
        let _ = env.barrier(Node::B).await;
        let _ = env.barrier(Node::D).await;
        assert_eq!(
            env.finalization_view(Node::B, 1).await,
            Some(1),
            "holder finalization changed after cross-report (first-wins violated)",
        );
        assert_eq!(
            env.finalization_view(Node::D, 1).await,
            Some(2),
            "deprived finalization changed after cross-report (first-wins violated)",
        );

        // Canonical h2 at view 3 finalized on the holders is the floor.
        let h2 = env.block(Node::C, 3);
        seed_finalized(env, &HOLDERS, 3, &h2).await;
        let floor = env.finalization(&h2, &QUORUM_SIGNERS);
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            prefix_fetches: Vec::new(),
            subscriptions: Vec::new(),
            expectation: Expectation {
                floor_started: None,
                deprived: Node::D,
                deprived_min_height: 2,
                // b1 was finalized at view 1 on the holders and view 2 on D;
                // first-finalization-wins must still hold after the fuzzing
                // window, so each node must retain the view it saw first.
                finalization_views: vec![
                    (Node::B, 1, 1),
                    (Node::C, 1, 1),
                    (Node::D, 1, 2),
                ],
            },
        }
    }
}

// Extracted from test_standard_set_floor_holds_dispatch_until_anchor_arrives /
// buffered_block_installs_floor_anchor
// (consensus/src/marshal/standard/mod.rs:4651 / :1399).
pub(crate) struct PendingFloorAnchor;

impl Scenario for PendingFloorAnchor {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        // Holders build and finalize a five-block chain.
        let mut anchor = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &anchor).await;
        for view in 2..=5 {
            anchor = env.block(Node::C, view);
            seed_finalized(env, &HOLDERS, view, &anchor).await;
        }
        let floor = env.finalization(&anchor, &QUORUM_SIGNERS);

        // The deprived node, holding nothing, installs the floor at height 5 and
        // subscribes to the anchor: dispatch is held until the anchor backfills.
        let subscription = env.subscribe(Node::D, anchor.digest());
        env.set_floor(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            prefix_fetches: Vec::new(),
            subscriptions: vec![PendingBlock {
                node: Node::D,
                expected: anchor.digest(),
                receiver: subscription,
            }],
            expectation: Expectation {
                floor_started: Some(Node::D),
                deprived: Node::D,
                deprived_min_height: 5,
                finalization_views: Vec::new(),
            },
        }
    }
}
