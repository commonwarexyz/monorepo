//! Three-phase driver: setup, scripted prefix, and fuzzing.
//!
//! Setup builds four validators on the deterministic runtime with a marshal
//! stack whose wrapper and application come from the chosen scenario. The prefix
//! drives the honest core into an interesting state and returns a certified
//! floor. The fuzzing phase starts the engines from that floor (honestly, or
//! with node 0 replaced by the full-channel adversary), heals the network at a
//! GST boundary, and checks recovery liveness, block safety, and the scenario's
//! own expectations.

use super::{
    adversary,
    elector::ByzantineLeaderAtView,
    environment::{Mb, Node, ScenarioEnv},
    input::{ConsensusMutation, MarshalScenarioPrefixInput, Mode},
    scenarios,
};
use crate::{
    NetworkChannels,
    marshal::end_to_end::{
        app::{
            AlwaysAcceptBlockBuilderApp, BlockContextRegistry, DeliveryReporter, ProgressHandle,
        },
        invariants,
        twins::{
            B, Ctx, PublicKeyOf, SchemeOf,
            stack::{
                DEFAULT_MAX_PENDING_ACKS, DeferredMarshal, InlineMarshal, MarshalChoice,
                TwinsMarshal, genesis_block, register_engine_networks, setup_network,
                setup_network_links, setup_validator, start_engine_with_floor,
            },
        },
    },
    simplex::{Simplex, round_robin},
    utils::apply_partition,
};
use commonware_consensus::{
    Heightable,
    marshal::mocks::{
        application::Application,
        harness::{BLOCKS_PER_EPOCH, LINK, NUM_VALIDATORS},
    },
    simplex::Floor,
    types::{Height, TermLength, View},
};
use commonware_cryptography::{
    Digestible, certificate::ConstantProvider, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{Clock, Runner, Supervisor as _, deterministic};
use commonware_utils::FuzzRng;
use futures::future::{join_all, select_all};
use std::{sync::Arc, time::Duration};

/// The always-accept block builder wired under every marshal variant.
type App<P> = AlwaysAcceptBlockBuilderApp<Ctx<P>, SchemeOf<P>>;

/// Per-node marshal handles produced by setup, for the `M` marshal variant.
struct MarshalNode<P: Simplex, M: TwinsMarshal<P, App<P>>> {
    mailbox: Mb<P>,
    buffer: commonware_broadcast::buffered::Mailbox<PublicKeyOf<P>, B<P>>,
    application: Application<B<P>>,
    progress: ProgressHandle,
    builder: M::Wrapper,
}

/// Pre-GST fault window: an upper bound for how long faults act before the heal.
/// Progressing runs leave early via the delivery-height subscription, so this
/// only caps a stalled (e.g. no-quorum-partition) run.
const FAULT_PHASE: Duration = Duration::from_secs(12);
/// Post-GST recovery budget.
const LIVENESS_WINDOW: Duration = Duration::from_secs(360);
/// Live views past the attack view the disrupter may fault, beyond the target
/// height, to cover views nullified by the fault.
const LIVE_FAULT_MARGIN: u64 = 5;
/// Single-epoch delivery ceiling (epoch-0 boundary).
const MAX_REQUIRED: u64 = BLOCKS_PER_EPOCH.get() - 1;

/// Degrade the last participant's links, mirroring the disrupter runner.
async fn apply_degraded_network<P: Simplex>(
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
) {
    let Some(victim) = participants.last() else {
        return;
    };
    let degraded = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::from_millis(50),
        success_rate: 0.6,
    };
    for peer in participants
        .iter()
        .take(participants.len().saturating_sub(1))
    {
        oracle.remove_link(victim.clone(), peer.clone()).await.ok();
        oracle.remove_link(peer.clone(), victim.clone()).await.ok();
        oracle
            .add_link(victim.clone(), peer.clone(), degraded.clone())
            .await
            .unwrap();
        oracle
            .add_link(peer.clone(), victim.clone(), degraded.clone())
            .await
            .unwrap();
    }
}

/// Floor-aware in-order check: like the standard oracle, but the first delivery
/// may be the floor height (a single jump out of genesis is permitted) since
/// `set_floor` prunes below the floor. Duplicate heights with different digests,
/// gaps, and out-of-order delivery are still rejected.
fn check_floor_started_order(
    idx: usize,
    delivered: &[(Height, Sha256Digest)],
    floor_height: u64,
    stack: &str,
) {
    if let Some((first, _)) = delivered.first() {
        assert!(
            first.get() == 0 || first.get() == floor_height,
            "floor-started node{idx} first delivery {} is neither genesis nor floor {floor_height}; \
             stack={stack}",
            first.get(),
        );
    }
    for window in delivered.windows(2) {
        let (height_0, digest_0) = &window[0];
        let (height_1, digest_1) = &window[1];
        if height_1 == height_0 && digest_1 == digest_0 {
            continue;
        }
        let contiguous = height_0.get().checked_add(1) == Some(height_1.get());
        let genesis_to_floor = height_0.get() == 0 && height_1.get() == floor_height;
        assert!(
            contiguous || genesis_to_floor,
            "floor-started node{idx} out-of-order, gap, or same-height fork: {} -> {}; \
             sequence={delivered:?}; stack={stack}",
            height_0.get(),
            height_1.get(),
        );
    }
}

/// Deferred-variant entry point.
pub fn fuzz_marshal_scenario_prefix_deferred<P: Simplex>(input: MarshalScenarioPrefixInput) {
    run::<P, DeferredMarshal>(input, MarshalChoice::Deferred);
}

/// Inline-variant entry point.
pub fn fuzz_marshal_scenario_prefix_inline<P: Simplex>(input: MarshalScenarioPrefixInput) {
    run::<P, InlineMarshal>(input, MarshalChoice::Inline);
}

/// Run one scenario prefix and its fuzzing phase under the `M` marshal variant.
/// `marshal` matches `M` (the concrete `DeferredMarshal`/`InlineMarshal` selectors
/// ignore it; it documents the variant).
fn run<P: Simplex, M>(input: MarshalScenarioPrefixInput, marshal: MarshalChoice)
where
    M: TwinsMarshal<P, App<P>>,
    M::Wrapper: Clone + Send + 'static,
{
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let config = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(config);

    executor.start(|mut context| async move {
        // === SETUP ===
        let (participants, schemes) = P::setup(&mut context, crate::NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;
        setup_network_links::<P>(&mut oracle, &participants).await;

        let genesis = genesis_block::<P>(participants[0].clone());
        let genesis_commitment = genesis.digest();
        let block_contexts = BlockContextRegistry::<Ctx<P>>::default();
        block_contexts.record(genesis_commitment, genesis.context.clone());
        let stack_label: Arc<str> = "scenario".into();

        let byzantine = matches!(input.mode, Mode::DisrupterN4F1C3);

        let mut nodes: Vec<Option<MarshalNode<P, M>>> = Vec::with_capacity(NUM_VALIDATORS as usize);
        let mut engine_channels: Vec<Option<NetworkChannels<PublicKeyOf<P>>>> =
            Vec::with_capacity(NUM_VALIDATORS as usize);
        for (idx, validator) in participants.iter().enumerate() {
            let validator_ctx = context.child("validator").with_attribute("index", idx);
            engine_channels
                .push(Some(register_engine_networks::<P>(&oracle, validator.clone()).await));
            if byzantine && idx == Node::A.idx() {
                // Node 0 has no marshal: the dissemination-layer disrupter owns
                // its ch1/ch2 and the Simplex disrupter owns ch3/4/5.
                nodes.push(None);
                continue;
            }
            let mut validator_state = setup_validator::<P>(
                validator_ctx.child("marshal"),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[idx].clone()),
                genesis.clone(),
                DEFAULT_MAX_PENDING_ACKS,
                None,
            )
            .await;
            let progress = ProgressHandle::new();
            let application = AlwaysAcceptBlockBuilderApp::<Ctx<P>, SchemeOf<P>>::default()
                .with_block_contexts(block_contexts.clone())
                .with_reporter(
                    DeliveryReporter::new(
                        idx,
                        validator_state.application.clone(),
                        None,
                        stack_label.clone(),
                    )
                    .with_progress(progress.clone()),
                );
            let builder = <M as TwinsMarshal<P, _>>::create(
                marshal,
                &validator_ctx,
                application,
                validator_state.mailbox.clone(),
            );
            validator_state.start(builder.clone());
            nodes.push(Some(MarshalNode {
                mailbox: validator_state.mailbox.clone(),
                buffer: validator_state.buffer.clone(),
                application: validator_state.application.clone(),
                progress,
                builder,
            }));
        }

        // A mailbox/buffer for every index: scenarios only address the honest
        // core {B, C, D}, so node 0's absent slot is filled with a placeholder.
        let reference = nodes.iter().flatten().next().expect("at least one marshal node");
        let placeholder_mailbox = reference.mailbox.clone();
        let placeholder_buffer = reference.buffer.clone();
        let mailboxes: Vec<Mb<P>> = nodes
            .iter()
            .map(|node| node.as_ref().map_or_else(|| placeholder_mailbox.clone(), |node| node.mailbox.clone()))
            .collect();
        let buffers = nodes
            .iter()
            .map(|node| node.as_ref().map_or_else(|| placeholder_buffer.clone(), |node| node.buffer.clone()))
            .collect();

        // === PREFIX ===
        let mut env = ScenarioEnv::<P> {
            context: context.child("prefix"),
            participants: participants.clone(),
            schemes: schemes.clone(),
            mailboxes,
            buffers,
            genesis,
            canonical: Vec::new(),
        };
        let point = scenarios::drive(input.scenario, &mut env).await;
        let tip = point.canonical.last().expect("scenario built a canonical chain");
        let floor_height = tip.height().get();
        let floor_view = tip.context.round.view().get();
        let floor_digest = tip.digest();
        let floor = Floor::Finalized(point.floor.clone());
        // The adversary leads the first view above the floor.
        let attack_view = View::new(floor_view + 1);
        let attack_height = Height::new(floor_height + 1);

        // === FUZZING PHASE ===
        apply_partition(&oracle, &participants, input.partition.set_partition(), &LINK).await;
        if input.degraded_network {
            apply_degraded_network::<P>(&oracle, &participants).await;
        }

        for (idx, validator) in participants.iter().enumerate() {
            let channels = engine_channels[idx].take().expect("engine channels");
            if byzantine && idx == Node::A.idx() {
                let (vote, certificate, resolver) = channels;
                // Dissemination-layer disrupter on ch1/ch2 (leader announce on a
                // clone of the vote sender at the attack view).
                let dissemination_ctx = context.child("adversary").child("dissemination");
                adversary::start_dissemination_disrupter::<P>(
                    &dissemination_ctx,
                    &oracle,
                    validator.clone(),
                    schemes[idx].clone(),
                    schemes.clone(),
                    participants.clone(),
                    floor_digest,
                    View::new(floor_view),
                    attack_view,
                    attack_height,
                    vote.0.clone(),
                    input.fault_plan,
                )
                .await;
                // Simplex-layer disrupter on ch3/4/5, faulting live views above
                // the attack view (disjoint from the announce → no shadowing).
                if matches!(input.fault_plan.consensus, ConsensusMutation::Corrupt) {
                    let span = input.required_containers.max(1);
                    adversary::start_simplex_disrupter::<P>(
                        context.child("adversary").child("disrupter"),
                        schemes[idx].clone(),
                        input.fault_rounds,
                        input.fault_rounds_bound,
                        attack_view.get() + 1,
                        attack_view.get() + span + LIVE_FAULT_MARGIN,
                        input.required_containers,
                        vote,
                        certificate,
                        resolver,
                    );
                }
                continue;
            }
            let node = nodes[idx].as_ref().expect("honest node has a marshal");
            let (vote, certificate, resolver) = channels;
            let validator_ctx = context.child("validator").with_attribute("index", idx);
            let partition = format!("scenario-{idx}");
            if byzantine {
                start_engine_with_floor::<P, _, _, _>(
                    validator_ctx,
                    &oracle,
                    validator.clone(),
                    schemes[idx].clone(),
                    ByzantineLeaderAtView { attack_view },
                    node.builder.clone(),
                    node.builder.clone(),
                    node.mailbox.clone(),
                    floor.clone(),
                    partition,
                    input.forwarding,
                    vote,
                    certificate,
                    resolver,
                );
            } else {
                start_engine_with_floor::<P, _, _, _>(
                    validator_ctx,
                    &oracle,
                    validator.clone(),
                    schemes[idx].clone(),
                    round_robin(TermLength::ONE),
                    node.builder.clone(),
                    node.builder.clone(),
                    node.mailbox.clone(),
                    floor.clone(),
                    partition,
                    input.forwarding,
                    vote,
                    certificate,
                    resolver,
                );
            }
        }

        // Honest apps (for the safety invariants) and per-node delivery-height
        // progress handles (for the subscription-based liveness watch); every
        // index that has a marshal.
        let honest_apps: Vec<(usize, Application<B<P>>)> = nodes
            .iter()
            .enumerate()
            .filter_map(|(idx, node)| node.as_ref().map(|node| (idx, node.application.clone())))
            .collect();
        let honest_progress: Vec<(usize, ProgressHandle)> = nodes
            .iter()
            .enumerate()
            .filter_map(|(idx, node)| node.as_ref().map(|node| (idx, node.progress.clone())))
            .collect();

        // Liveness. Phase 1: let the pre-GST faults act until the fastest honest
        // node advances the requested run depth past the prefix floor, or the fault
        // window elapses. Deriving the target from `required_containers` keeps a
        // shallow run close to the interesting scenario state instead of racing to
        // a fixed height; the cap keeps it below the single-epoch boundary so a
        // fresh baseline + 1 stays achievable. Each node's delivery-height watcher
        // races against one deadline (no polling), and the first to reach the
        // ceiling ends the phase.
        let phase1_ceiling =
            (floor_height + input.required_containers).min(MAX_REQUIRED.saturating_sub(1));
        let phase1_watchers: Vec<_> = honest_progress
            .iter()
            .map(|(_, progress)| {
                let (mut latest, mut updates) = progress.subscribe();
                Box::pin(async move {
                    while latest < phase1_ceiling {
                        match updates.recv().await {
                            Some(height) => latest = height,
                            None => break,
                        }
                    }
                })
            })
            .collect();
        select! {
            _ = select_all(phase1_watchers) => {},
            _ = context.sleep(FAULT_PHASE) => {},
        }

        // Heal unconditionally, then capture each honest node's baseline plus a
        // receiver for fresh updates. Subscribing *after* the heal completes is
        // load-bearing: the heal awaits many link remove/add requests while
        // consensus keeps running, so a delivery mid-heal must not count as
        // post-GST progress. `subscribe` reads the latest height and registers the
        // receiver under one lock, so no post-heal delivery is missed.
        apply_partition(&oracle, &participants, None, &LINK).await;
        let baselines: Vec<(usize, u64, _)> = honest_progress
            .iter()
            .map(|(idx, progress)| {
                let (baseline, updates) = progress.subscribe();
                (*idx, baseline, updates)
            })
            .collect();

        // Phase 2: every honest node that still has epoch headroom must make fresh
        // post-GST progress (baseline + 1). A node already at the epoch ceiling has
        // completed the epoch's maximal work and cannot advance further, so it is
        // excluded from the measurement rather than passed vacuously. If none
        // remains measurable (all completed the epoch before the heal), the run is
        // healthy but unmeasurable, so the check is skipped and only safety runs.
        // Otherwise all measurable watchers race against one recovery deadline.
        let measurable: Vec<(usize, u64, _)> = baselines
            .into_iter()
            .filter(|(_, baseline, _)| *baseline < MAX_REQUIRED)
            .collect();
        if !measurable.is_empty() {
            let targets: Vec<(usize, u64)> =
                measurable.iter().map(|(idx, baseline, _)| (*idx, baseline + 1)).collect();
            let watchers: Vec<_> = measurable
                .into_iter()
                .map(|(_, baseline, mut updates)| {
                    let target = baseline + 1;
                    Box::pin(async move {
                        let mut latest = baseline;
                        while latest < target {
                            match updates.recv().await {
                                Some(height) => latest = height,
                                None => return false,
                            }
                        }
                        true
                    })
                })
                .collect();
            let reached = select! {
                results = join_all(watchers) => results.iter().all(|reached| *reached),
                _ = context.sleep(LIVENESS_WINDOW) => false,
            };
            if !reached {
                let observed: Vec<(usize, u64)> = honest_progress
                    .iter()
                    .map(|(idx, progress)| (*idx, progress.latest()))
                    .collect();
                panic!(
                    "scenario {:?} made no fresh post-GST progress: targets={targets:?} observed={observed:?}",
                    input.scenario,
                );
            }
        }

        // === SAFETY (marshal-layer invariants; last observation point) ===
        let floor_started = point.expectation.floor_started.map(Node::idx);
        invariants::agreement(&honest_apps, &stack_label);
        for (idx, app) in &honest_apps {
            if Some(*idx) == floor_started {
                invariants::check_parent_linkage::<Sha256Digest, PublicKeyOf<P>>(
                    *idx,
                    &app.blocks(),
                    genesis_commitment,
                    &stack_label,
                );
                check_floor_started_order(*idx, &app.delivered(), floor_height, &stack_label);
            } else {
                invariants::check_local_blocks::<Sha256Digest, PublicKeyOf<P>>(
                    *idx,
                    app,
                    genesis_commitment,
                    &stack_label,
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SimplexCertificateMock,
        scenarios::input::{
            BackfillFault, BlockFault, ConsensusMutation, FaultPlan, Mode, ScenarioKind,
        },
        utils::Partition,
    };
    use commonware_consensus::simplex::ForwardingPolicy;

    fn run(scenario: ScenarioKind, mode: Mode) {
        let input = MarshalScenarioPrefixInput {
            raw_bytes: vec![0u8; 64],
            scenario,
            mode,
            fault_plan: FaultPlan {
                block_fault: BlockFault::Partition,
                backfill: BackfillFault::Poison,
                consensus: ConsensusMutation::Corrupt,
            },
            fault_rounds: 1,
            fault_rounds_bound: 1,
            required_containers: 1,
            degraded_network: false,
            partition: Partition::Connected,
            forwarding: ForwardingPolicy::Disabled,
        };
        // Exercise both Standard variants with the same input.
        fuzz_marshal_scenario_prefix_deferred::<SimplexCertificateMock>(input.clone());
        fuzz_marshal_scenario_prefix_inline::<SimplexCertificateMock>(input);
    }

    #[test]
    fn honest_missing_candidate() {
        run(ScenarioKind::MissingCandidate, Mode::HonestN4F0C4);
    }

    #[test]
    fn honest_finalization_without_block() {
        run(ScenarioKind::FinalizationWithoutBlock, Mode::HonestN4F0C4);
    }

    #[test]
    fn honest_subscribe_before_block() {
        run(ScenarioKind::SubscribeBeforeBlock, Mode::HonestN4F0C4);
    }

    #[test]
    fn honest_same_height_different_views() {
        run(ScenarioKind::SameHeightDifferentViews, Mode::HonestN4F0C4);
    }

    #[test]
    fn honest_pending_floor_anchor() {
        run(ScenarioKind::PendingFloorAnchor, Mode::HonestN4F0C4);
    }

    #[test]
    fn adversarial_missing_candidate() {
        run(ScenarioKind::MissingCandidate, Mode::DisrupterN4F1C3);
    }

    #[test]
    fn adversarial_finalization_without_block() {
        run(
            ScenarioKind::FinalizationWithoutBlock,
            Mode::DisrupterN4F1C3,
        );
    }

    #[test]
    fn adversarial_subscribe_before_block() {
        run(ScenarioKind::SubscribeBeforeBlock, Mode::DisrupterN4F1C3);
    }

    #[test]
    fn adversarial_same_height_different_views() {
        run(
            ScenarioKind::SameHeightDifferentViews,
            Mode::DisrupterN4F1C3,
        );
    }

    #[test]
    fn adversarial_pending_floor_anchor() {
        run(ScenarioKind::PendingFloorAnchor, Mode::DisrupterN4F1C3);
    }

    // Smoke: an honest run with a degraded deprived-node link exercises the
    // marshal-layer invariants and liveness under lossy backfill.
    #[test]
    fn honest_pending_floor_anchor_degraded() {
        let input = MarshalScenarioPrefixInput {
            raw_bytes: vec![0],
            scenario: ScenarioKind::PendingFloorAnchor,
            mode: Mode::HonestN4F0C4,
            fault_plan: FaultPlan {
                block_fault: BlockFault::Omit,
                backfill: BackfillFault::Withhold,
                consensus: ConsensusMutation::Corrupt,
            },
            fault_rounds: 1,
            fault_rounds_bound: 1,
            required_containers: 1,
            degraded_network: true,
            partition: Partition::Connected,
            forwarding: ForwardingPolicy::Disabled,
        };
        // Exercise both Standard variants with the same input.
        fuzz_marshal_scenario_prefix_deferred::<SimplexCertificateMock>(input.clone());
        fuzz_marshal_scenario_prefix_inline::<SimplexCertificateMock>(input);
    }

    macro_rules! scenario_smoke {
        ($honest:ident, $adversarial:ident, $kind:ident) => {
            #[test]
            fn $honest() {
                run(ScenarioKind::$kind, Mode::HonestN4F0C4);
            }
            #[test]
            fn $adversarial() {
                run(ScenarioKind::$kind, Mode::DisrupterN4F1C3);
            }
        };
    }

    scenario_smoke!(
        honest_byzantine_parent_equivocation,
        adversarial_byzantine_parent_equivocation,
        ByzantineParentEquivocation
    );
    scenario_smoke!(
        honest_conflicting_verify_no_cert_poison,
        adversarial_conflicting_verify_no_cert_poison,
        ConflictingVerifyNoCertPoison
    );
    scenario_smoke!(
        honest_equivocated_block_persists,
        adversarial_equivocated_block_persists,
        EquivocatedBlockPersists
    );
    scenario_smoke!(
        honest_conflicting_proposals_both_ack,
        adversarial_conflicting_proposals_both_ack,
        ConflictingProposalsBothAck
    );
    scenario_smoke!(
        honest_height_lie_parent_fetch,
        adversarial_height_lie_parent_fetch,
        HeightLieParentFetch
    );
    scenario_smoke!(
        honest_internal_missing_finalized_block,
        adversarial_internal_missing_finalized_block,
        InternalMissingFinalizedBlock
    );
    scenario_smoke!(
        honest_multiple_trailing_gaps,
        adversarial_multiple_trailing_gaps,
        MultipleTrailingGaps
    );
    scenario_smoke!(
        honest_large_pending_tip,
        adversarial_large_pending_tip,
        LargePendingTip
    );
    scenario_smoke!(
        honest_block_without_finalization,
        adversarial_block_without_finalization,
        BlockWithoutFinalization
    );
    scenario_smoke!(
        honest_floor_repairs_gap_after_anchor,
        adversarial_floor_repairs_gap_after_anchor,
        FloorRepairsGapAfterAnchor
    );
    scenario_smoke!(
        honest_newer_floor_supersedes_older,
        adversarial_newer_floor_supersedes_older,
        NewerFloorSupersedesOlder
    );
    scenario_smoke!(
        honest_below_floor_anchor_wakes_subscriber,
        adversarial_below_floor_anchor_wakes_subscriber,
        BelowFloorAnchorWakesSubscriber
    );
    scenario_smoke!(
        honest_stale_block_rejected_after_floor,
        adversarial_stale_block_rejected_after_floor,
        StaleBlockRejectedAfterFloor
    );
    scenario_smoke!(
        honest_certify_survives_view_pruning,
        adversarial_certify_survives_view_pruning,
        CertifySurvivesViewPruning
    );
    scenario_smoke!(
        honest_deferred_certify_fallback,
        adversarial_deferred_certify_fallback,
        DeferredCertifyFallback
    );
    scenario_smoke!(
        honest_first_block_fetches_genesis_parent,
        adversarial_first_block_fetches_genesis_parent,
        FirstBlockFetchesGenesisParent
    );
}
