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
    environment::{Expectation, FuzzPoint, Node, QUORUM_SIGNERS, ScenarioEnv},
    input::ScenarioKind,
};
use crate::{marshal::end_to_end::twins::B, simplex::Simplex};
use commonware_consensus::types::Height;
use commonware_cryptography::Digestible;

/// A scripted prefix that drives the cluster to an interesting marshal state.
///
/// A scenario only builds the prefix state; the per-scenario behaviours it is
/// derived from are covered by the `consensus/src` standard tests. The fuzzer
/// then checks the marshal-layer invariants and liveness from this state.
pub(crate) trait Scenario {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P>;
}

/// Dispatch to the concrete scenario for `kind`.
pub(crate) async fn drive<P: Simplex>(
    kind: ScenarioKind,
    env: &mut ScenarioEnv<P>,
) -> FuzzPoint<P> {
    match kind {
        ScenarioKind::MissingCandidate => MissingCandidate.drive(env).await,
        ScenarioKind::FinalizationWithoutBlock => FinalizationWithoutBlock.drive(env).await,
        ScenarioKind::SubscribeBeforeBlock => SubscribeBeforeBlock.drive(env).await,
        ScenarioKind::SameHeightDifferentViews => SameHeightDifferentViews.drive(env).await,
        ScenarioKind::PendingFloorAnchor => PendingFloorAnchor.drive(env).await,
        ScenarioKind::ByzantineParentEquivocation => ByzantineParentEquivocation.drive(env).await,
        ScenarioKind::ConflictingVerifyNoCertPoison => {
            ConflictingVerifyNoCertPoison.drive(env).await
        }
        ScenarioKind::EquivocatedBlockPersists => EquivocatedBlockPersists.drive(env).await,
        ScenarioKind::ConflictingProposalsBothAck => ConflictingProposalsBothAck.drive(env).await,
        ScenarioKind::HeightLieParentFetch => HeightLieParentFetch.drive(env).await,
        ScenarioKind::InternalMissingFinalizedBlock => {
            InternalMissingFinalizedBlock.drive(env).await
        }
        ScenarioKind::MultipleTrailingGaps => MultipleTrailingGaps.drive(env).await,
        ScenarioKind::LargePendingTip => LargePendingTip.drive(env).await,
        ScenarioKind::BlockWithoutFinalization => BlockWithoutFinalization.drive(env).await,
        ScenarioKind::FloorRepairsGapAfterAnchor => FloorRepairsGapAfterAnchor.drive(env).await,
        ScenarioKind::NewerFloorSupersedesOlder => NewerFloorSupersedesOlder.drive(env).await,
        ScenarioKind::BelowFloorAnchorWakesSubscriber => {
            BelowFloorAnchorWakesSubscriber.drive(env).await
        }
        ScenarioKind::StaleBlockRejectedAfterFloor => StaleBlockRejectedAfterFloor.drive(env).await,
        ScenarioKind::CertifySurvivesViewPruning => CertifySurvivesViewPruning.drive(env).await,
        ScenarioKind::DeferredCertifyFallback => DeferredCertifyFallback.drive(env).await,
        ScenarioKind::FirstBlockFetchesGenesisParent => {
            FirstBlockFetchesGenesisParent.drive(env).await
        }
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
// (consensus/src/marshal/standard/mod.rs:2489).
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

        // Leave the deprived node in the missing-candidate state: it holds the
        // notarized reference for the side block (a round-bound hint) but not the
        // block itself, so it must attempt a backfill during the fuzzing phase.
        env.hint_notarized(Node::D, 3, side.digest());
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
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
            expectation: Expectation {
                floor_started: None,
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

        // The deprived node holds neither block, then is handed the tip
        // finalization so it must backfill both during fuzzing.
        env.report_finalization(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
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
        // Cross-report the other view so every node has seen the conflict.
        env.report_finalization(Node::B, finalization_v2);
        env.report_finalization(Node::D, finalization_v1);

        // Canonical h2 at view 3 finalized on the holders is the floor.
        let h2 = env.block(Node::C, 3);
        seed_finalized(env, &HOLDERS, 3, &h2).await;
        let floor = env.finalization(&h2, &QUORUM_SIGNERS);
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
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

        // The deprived node, holding nothing, installs the floor at height 5;
        // dispatch is held until the anchor backfills during fuzzing.
        env.set_floor(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;

        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: Some(Node::D),
            },
        }
    }
}

// scripted_byzantine_parent_equivocation (consensus/src/marshal/standard/mod.rs:2092).
pub(crate) struct ByzantineParentEquivocation;

impl Scenario for ByzantineParentEquivocation {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS_AND_DEPRIVED, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS_AND_DEPRIVED, 2, &h2).await;
        // A view-3 fork that equivocates on the parent: it declares the older
        // view-1 block (h1) instead of the honest view-2 parent (h2). Notarized
        // on the holders only.
        let equivocation = env.fork_block(&h1, Node::C, 3, Height::new(3));
        env.verify(Node::B, 3, &equivocation).await;
        env.verify(Node::C, 3, &equivocation).await;
        let notarization = env.notarization_at(3, 1, &equivocation, &QUORUM_SIGNERS);
        env.report_notarization(Node::B, notarization.clone());
        env.report_notarization(Node::C, notarization);
        // The honest chain nullifies view 3 and finalizes the height-3 block at
        // view 4 on the legitimate view-2 parent; that tip is the floor.
        let h3 = env.block(Node::B, 4);
        seed_finalized(env, &HOLDERS, 4, &h3).await;
        let floor = env.finalization_at(4, 2, &h3, &QUORUM_SIGNERS);
        env.hint_notarized(Node::D, 3, equivocation.digest());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// pending_conflicting_verify_does_not_poison_certification (standard/mod.rs:1963).
// State analog: the automaton certify-gate mechanic is covered by the source test.
pub(crate) struct ConflictingVerifyNoCertPoison;

impl Scenario for ConflictingVerifyNoCertPoison {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS_AND_DEPRIVED, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS_AND_DEPRIVED, 2, &h2).await;
        // Honest view-3 candidate on the view-2 parent, finalized as the floor; a
        // conflicting candidate at the same view names the older view-1 parent.
        // Verifying both on the holders is the pending conflicting verify.
        let h3 = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &h3).await;
        let conflicting = env.fork_block(&h1, Node::C, 3, Height::new(3));
        env.verify(Node::B, 3, &conflicting).await;
        env.verify(Node::C, 3, &conflicting).await;
        let floor = env.finalization(&h3, &QUORUM_SIGNERS);
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// certify_persists_equivocated_block (harness.rs:1384; test standard/mod.rs:285).
pub(crate) struct EquivocatedBlockPersists;

impl Scenario for EquivocatedBlockPersists {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        // Block A occupies canonical round 1 (verified). An equivocation at the
        // same round on the same genesis parent (a different leader gives a
        // distinct digest) is certified on the holders and must persist.
        let genesis = env.genesis.clone();
        let block_a = env.block(Node::B, 1);
        env.verify(Node::B, 1, &block_a).await;
        env.verify(Node::C, 1, &block_a).await;
        let block_b = env.fork_block(&genesis, Node::C, 1, Height::new(1));
        env.certify(Node::B, 1, &block_b).await;
        env.certify(Node::C, 1, &block_b).await;
        // Canonical advances to view 2 so the floor sits above the equivocated round.
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let floor = env.finalization(&h2, &QUORUM_SIGNERS);
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// proposed_conflicting_blocks_both_ack (standard/mod.rs:8116).
pub(crate) struct ConflictingProposalsBothAck;

impl Scenario for ConflictingProposalsBothAck {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        // Two conflicting proposals at the same round on the genesis parent, both
        // verified/acked and persisted on the holders.
        let genesis = env.genesis.clone();
        let block_a = env.block(Node::B, 1);
        env.verify(Node::B, 1, &block_a).await;
        env.verify(Node::C, 1, &block_a).await;
        let block_b = env.fork_block(&genesis, Node::C, 1, Height::new(1));
        env.verify(Node::B, 1, &block_b).await;
        env.verify(Node::C, 1, &block_b).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let floor = env.finalization(&h2, &QUORUM_SIGNERS);
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// verify_height_lie_parent_fetch_is_round_bound (standard/mod.rs:2747).
pub(crate) struct HeightLieParentFetch;

impl Scenario for HeightLieParentFetch {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        // A child fork on h1 at the nullified view 2 whose declared height lies:
        // its true position is height 2, but it claims height 3 (a +1 lie).
        let child = env.fork_block(&h1, Node::C, 2, Height::new(3));
        env.verify(Node::B, 2, &child).await;
        env.verify(Node::C, 2, &child).await;
        let notarization = env.notarization_at(2, 1, &child, &QUORUM_SIGNERS);
        env.report_notarization(Node::B, notarization.clone());
        env.report_notarization(Node::C, notarization);
        // Canonical h2 at view 3 (view 2 nullified), true height 2, is the floor;
        // the child cert at view 2 stays at/below the floor view.
        let h2 = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &h2).await;
        let floor = env.finalization(&h2, &QUORUM_SIGNERS);
        env.hint_notarized(Node::D, 2, child.digest());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// restart_repairs_internal_missing_finalized_block (standard/mod.rs:660).
pub(crate) struct InternalMissingFinalizedBlock;

impl Scenario for InternalMissingFinalizedBlock {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let h3 = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &h3).await;
        let floor = env.finalization(&h3, &QUORUM_SIGNERS);
        // D holds blocks 1 and 3 plus finalizations for heights 2 and 3, but is
        // missing block 2's data: an internal gap it must repair by backfill.
        env.verify(Node::D, 1, &h1).await;
        env.verify(Node::D, 3, &h3).await;
        let h2_finalization = env.finalization(&h2, &QUORUM_SIGNERS);
        env.report_finalization(Node::D, h2_finalization);
        env.report_finalization(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// restart_repairs_multiple_trailing_missing_finalized_blocks (standard/mod.rs:861).
pub(crate) struct MultipleTrailingGaps;

impl Scenario for MultipleTrailingGaps {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let h3 = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &h3).await;
        let h4 = env.block(Node::C, 4);
        seed_finalized(env, &HOLDERS, 4, &h4).await;
        let h5 = env.block(Node::B, 5);
        seed_finalized(env, &HOLDERS, 5, &h5).await;
        let floor = env.finalization(&h5, &QUORUM_SIGNERS);
        // D holds only block 1's data but finalizations for all five heights, so
        // blocks 2-5 are a deep run of trailing gaps it must backfill.
        env.verify(Node::D, 1, &h1).await;
        for block in [&h1, &h2, &h3, &h4] {
            let finalization = env.finalization(block, &QUORUM_SIGNERS);
            env.report_finalization(Node::D, finalization);
        }
        env.report_finalization(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// restart_repairs_large_pending_tip_by_commitment (standard/mod.rs:977). Chain
// length reduced to 8 to stay within the single-epoch delivery ceiling.
pub(crate) struct LargePendingTip;

impl Scenario for LargePendingTip {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let mut tip = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &tip).await;
        for view in 3..=8 {
            let leader = if view % 2 == 0 { Node::C } else { Node::B };
            tip = env.block(leader, view);
            seed_finalized(env, &HOLDERS, view, &tip).await;
        }
        let floor = env.finalization(&tip, &QUORUM_SIGNERS);
        // D holds only block 1's data and only the tip finalization, so recovery
        // must walk the chain backwards from the tip by commitment.
        env.verify(Node::D, 1, &h1).await;
        env.report_finalization(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// restart_surfaces_block_without_finalization (standard/mod.rs:774). D holds every
// block but is missing an interior finalization row (a block without its cert).
pub(crate) struct BlockWithoutFinalization;

impl Scenario for BlockWithoutFinalization {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let h3 = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &h3).await;
        let floor = env.finalization(&h3, &QUORUM_SIGNERS);
        // D holds all three blocks (verified) and the finalizations for heights 1
        // and 3, but not for height 2: block h2 is present without its cert.
        env.verify(Node::D, 1, &h1).await;
        env.verify(Node::D, 2, &h2).await;
        env.verify(Node::D, 3, &h3).await;
        let h1_finalization = env.finalization(&h1, &QUORUM_SIGNERS);
        env.report_finalization(Node::D, h1_finalization);
        env.report_finalization(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// set_floor_repairs_gap_after_anchor_arrives (standard/mod.rs:4942). The source
// stores a finalization ABOVE a still-pending floor anchor with the block between
// missing; a finalization above the engine floor is unsound here (the engine
// would produce that view), and a floor-started node whose marshal floor sits
// below the canonical tip breaks the single-floor delivery check. So this is
// reproduced as a deprived-node gap: D is handed the anchor finalization (height
// 2) and a higher tip finalization (height 4) but NOT the one between, and holds
// no blocks, so it must backfill the anchor before repairing the gap (height 3).
pub(crate) struct FloorRepairsGapAfterAnchor;

impl Scenario for FloorRepairsGapAfterAnchor {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let anchor = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &anchor).await;
        let gap = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &gap).await;
        let tip = env.block(Node::C, 4);
        seed_finalized(env, &HOLDERS, 4, &tip).await;
        let floor = env.finalization(&tip, &QUORUM_SIGNERS);
        // D holds no blocks and gets the anchor (height 2) and tip (height 4)
        // finalizations but not the gap's (height 3): it backfills the anchor,
        // then repairs the gap, then follows the tip.
        let anchor_finalization = env.finalization(&anchor, &QUORUM_SIGNERS);
        env.report_finalization(Node::D, anchor_finalization);
        env.report_finalization(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// newer_pending_floor_supersedes_older_anchor (standard/mod.rs:5126).
pub(crate) struct NewerFloorSupersedesOlder;

impl Scenario for NewerFloorSupersedesOlder {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let mut block = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &block).await;
        for view in 2..=4 {
            block = env.block(Node::C, view);
            seed_finalized(env, &HOLDERS, view, &block).await;
        }
        // The older floor: the height-5 canonical finalization.
        let older_anchor = env.block(Node::B, 5);
        seed_finalized(env, &HOLDERS, 5, &older_anchor).await;
        let older_floor = env.finalization(&older_anchor, &QUORUM_SIGNERS);
        // The chain continues to the height-7 tip: the newer floor.
        let mid = env.block(Node::C, 6);
        seed_finalized(env, &HOLDERS, 6, &mid).await;
        let tip = env.block(Node::B, 7);
        seed_finalized(env, &HOLDERS, 7, &tip).await;
        let floor = env.finalization(&tip, &QUORUM_SIGNERS);
        // D is given the older floor first, then the newer floor supersedes it.
        env.set_floor(Node::D, older_floor);
        env.set_floor(Node::D, floor.clone());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: Some(Node::D),
            },
        }
    }
}

// below_floor_anchor_delivery_wakes_subscriber (standard/mod.rs:1721). Partial:
// the subscriber wakeup is the oracle; only the below-floor delivery state is built.
pub(crate) struct BelowFloorAnchorWakesSubscriber;

impl Scenario for BelowFloorAnchorWakesSubscriber {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let h3 = env.block(Node::B, 4);
        seed_finalized(env, &HOLDERS, 4, &h3).await;
        let floor = env.finalization(&h3, &QUORUM_SIGNERS);
        // A below-floor fork of h1 at the nullified view 3, notarized on the holders.
        let fork = env.fork_block(&h1, Node::C, 3, Height::new(2));
        env.verify(Node::B, 3, &fork).await;
        env.verify(Node::C, 3, &fork).await;
        let notarization = env.notarization_at(3, 1, &fork, &QUORUM_SIGNERS);
        env.report_notarization(Node::B, notarization.clone());
        env.report_notarization(Node::C, notarization.clone());
        // D installs the floor at the tip, then the below-floor fork is reported.
        env.set_floor(Node::D, floor.clone());
        env.report_notarization(Node::D, notarization);
        env.hint_notarized(Node::D, 3, fork.digest());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: Some(Node::D),
            },
        }
    }
}

// reject_stale_block_delivery_after_floor_update (harness.rs:3744; test mod.rs:328).
pub(crate) struct StaleBlockRejectedAfterFloor;

impl Scenario for StaleBlockRejectedAfterFloor {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        seed_finalized(env, &HOLDERS, 1, &h1).await;
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let h3 = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &h3).await;
        let h4 = env.block(Node::C, 4);
        seed_finalized(env, &HOLDERS, 4, &h4).await;
        let h5 = env.block(Node::B, 6);
        seed_finalized(env, &HOLDERS, 6, &h5).await;
        let floor = env.finalization(&h5, &QUORUM_SIGNERS);
        // A stale fork of h1 at height 2 carrying a finalization at the nullified
        // view 5 (below the height-5 floor); D must reject it.
        let stale = env.fork_block(&h1, Node::C, 5, Height::new(2));
        env.verify(Node::B, 5, &stale).await;
        env.verify(Node::C, 5, &stale).await;
        let stale_finalization = env.finalization_at(5, 1, &stale, &QUORUM_SIGNERS);
        env.set_floor(Node::D, floor.clone());
        env.report_finalization(Node::D, stale_finalization);
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: Some(Node::D),
            },
        }
    }
}

// certify_at_later_view_survives_earlier_view_pruning (harness.rs:1248). The
// source certifies above the chain tip (a region never pruned); composition
// forbids state above the floor, so the certify sits below the floor and the
// canonical chain must advance far enough that the view-indexed cache actually
// prunes the early verify entry. Pruning floors `previous_processed_round -
// view_retention(10)` to an archive section (items_per_section 10): to drop
// section 0 (views 0..9) it needs the PREVIOUS processed round at 20, i.e. the
// processed round must reach 21. The fuzzer exercises the pruning path; the
// certified-copy retrievability assertion is the source test's.
pub(crate) struct CertifySurvivesViewPruning;

impl Scenario for CertifySurvivesViewPruning {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        // An off-canonical block verified at view 1 (archive section 0) and
        // certified at view 11 (section 10, which survives the prune).
        let genesis = env.genesis.clone();
        let repeated = env.fork_block(&genesis, Node::B, 1, Height::new(1));
        env.verify(Node::B, 1, &repeated).await;
        env.verify(Node::C, 1, &repeated).await;
        env.certify(Node::B, 11, &repeated).await;
        env.certify(Node::C, 11, &repeated).await;
        // Large nullified-view jumps put the processed round at view 21 with only
        // height 4 (well under the epoch ceiling). Processing view 21 prunes with
        // previous round 20 - 10 = 10 -> section 10, dropping section 0 (the
        // view-1 verify entry) while the view-11 certified entry survives.
        let mut tip = env.block(Node::B, 3);
        seed_finalized(env, &HOLDERS, 3, &tip).await;
        for (view, leader) in [(12u64, Node::C), (20, Node::B), (21, Node::C)] {
            tip = env.block(leader, view);
            seed_finalized(env, &HOLDERS, view, &tip).await;
        }
        let floor = env.finalization(&tip, &QUORUM_SIGNERS);
        // Flush the holders so they process every finalization to view 21 and run
        // the section-0 prune before the fuzzing phase starts.
        let _ = env.barrier(Node::B).await;
        let _ = env.barrier(Node::C).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// deferred_certify_falls_back_after_canceled_verify (standard/mod.rs:2671). State
// analog only: the automaton verify-cancel-certify fallback is not scriptable via
// the mailbox verbs, so this builds the resulting state (a notarized+certified
// block D must backfill by round).
pub(crate) struct DeferredCertifyFallback;

impl Scenario for DeferredCertifyFallback {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        let h1 = env.block(Node::B, 1);
        env.verify(Node::B, 1, &h1).await;
        env.verify(Node::C, 1, &h1).await;
        env.certify(Node::B, 1, &h1).await;
        env.certify(Node::C, 1, &h1).await;
        let notarization = env.notarization(&h1, &QUORUM_SIGNERS);
        env.report_notarization(Node::B, notarization.clone());
        env.report_notarization(Node::C, notarization);
        let h2 = env.block(Node::C, 2);
        seed_finalized(env, &HOLDERS, 2, &h2).await;
        let floor = env.finalization(&h2, &QUORUM_SIGNERS);
        env.hint_notarized(Node::D, 1, h1.digest());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}

// certify_first_block_fetches_genesis_parent (standard/mod.rs:2341).
pub(crate) struct FirstBlockFetchesGenesisParent;

impl Scenario for FirstBlockFetchesGenesisParent {
    async fn drive<P: Simplex>(&self, env: &mut ScenarioEnv<P>) -> FuzzPoint<P> {
        // The first canonical block h1 has genesis (view 0) as its parent.
        let h1 = env.block(Node::B, 1);
        env.verify(Node::B, 1, &h1).await;
        env.verify(Node::C, 1, &h1).await;
        env.certify(Node::B, 1, &h1).await;
        env.certify(Node::C, 1, &h1).await;
        let notarization = env.notarization(&h1, &QUORUM_SIGNERS);
        env.report_notarization(Node::B, notarization.clone());
        env.report_notarization(Node::C, notarization);
        let floor = env.finalization(&h1, &QUORUM_SIGNERS);
        // D holds the floor and a round-bound hint for h1 but lacks the block, so
        // backfilling h1 makes its parent fetch resolve to genesis.
        env.report_finalization(Node::D, floor.clone());
        env.hint_notarized(Node::D, 1, h1.digest());
        let _ = env.barrier(Node::D).await;
        FuzzPoint {
            floor,
            canonical: env.canonical.clone(),
            expectation: Expectation {
                floor_started: None,
            },
        }
    }
}
