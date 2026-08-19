//! Three-phase driver: setup, scripted prefix, and fuzzing.
//!
//! Setup builds four validators on the deterministic runtime, optionally seeding
//! a node's archives before its marshal actor starts, and wraps each node's
//! resolver in an observing adapter. The prefix drives the honest core into a
//! source-defined state through the [`FuzzScenarioStandardHarness`] and verifies
//! the [`ScenarioHandoff`](super::environment::ScenarioHandoff) before any engine
//! starts. The fuzzing phase starts the engines from the handoff floor (honestly,
//! or with node 0 replaced by the full-channel adversary), heals the network at a
//! GST boundary, and checks recovery liveness and the marshal-layer safety
//! invariants selected by the handoff.

use super::{
    adversary,
    elector::ByzantineLeaderAtView,
    environment::Node,
    harness::{App, BufferSend, FuzzScenarioStandardHarness, HarnessNode, RecordingBuffer},
    input::{ConsensusMutation, MarshalScenarioPrefixInput},
    recording_resolver::{RecordingResolver, init_injectable},
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
                setup_validator, start_engine_with_floor,
            },
        },
    },
    simplex::Simplex,
    utils::apply_partition,
};
use commonware_consensus::{
    marshal::{
        Start,
        mocks::{
            application::Application,
            harness::{BLOCKS_PER_EPOCH, LINK, NUM_VALIDATORS, PAGE_CACHE_SIZE, PAGE_SIZE},
        },
    },
    simplex::{elector::RoundRobin, types::Artifact},
    types::View,
};
use commonware_cryptography::{
    Digestible, Sha256, certificate::Verifier as _, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{Clock, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use commonware_utils::{FuzzRng, NZUsize};
use futures::future::{join_all, select_all};
use std::{
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

/// The scenario harness generic over the marshal wrapper `M`.
type Harness<P, M> = FuzzScenarioStandardHarness<P, M>;

/// Per-node marshal handles produced by setup, for the `M` marshal variant.
struct MarshalNode<P: Simplex, M: TwinsMarshal<P, App<P>>> {
    mailbox: super::environment::Mb<P>,
    application: Application<B<P>>,
    progress: ProgressHandle,
    builder: M::Wrapper,
    resolver: RecordingResolver<P>,
    sends: Arc<commonware_utils::sync::Mutex<Vec<BufferSend<P>>>>,
    subscriptions: Arc<AtomicUsize>,
    forwarding: Arc<std::sync::atomic::AtomicBool>,
}

/// Pre-GST fault window: an upper bound for how long faults act before the heal.
const FAULT_PHASE: Duration = Duration::from_secs(12);
/// Minimum pre-GST fault window: a lower bound so the heal never fires before the
/// adversary has had time to emit (the dissemination announce runs after a
/// sub-second delay, and the Simplex disrupter faults the first live views). This
/// keeps an adversarial run's fault phase non-empty even when honest progress
/// reaches the phase-1 ceiling immediately.
const MIN_FAULT_PHASE: Duration = Duration::from_secs(4);
/// Post-GST recovery budget.
const LIVENESS_WINDOW: Duration = Duration::from_secs(360);
/// Live views past the attack view the disrupter may fault.
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

/// Deferred-variant entry point.
pub fn fuzz_marshal_scenario_prefix_deferred<P: Simplex>(input: MarshalScenarioPrefixInput) {
    run::<P, DeferredMarshal>(input, MarshalChoice::Deferred);
}

/// Inline-variant entry point.
pub fn fuzz_marshal_scenario_prefix_inline<P: Simplex>(input: MarshalScenarioPrefixInput) {
    run::<P, InlineMarshal>(input, MarshalChoice::Inline);
}

/// Run one scenario prefix and its fuzzing phase under the `M` marshal variant.
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

        let genesis = genesis_block::<P>(participants[0].clone());
        let genesis_commitment = genesis.digest();
        let block_contexts = BlockContextRegistry::<Ctx<P>>::default();
        block_contexts.record(genesis_commitment, genesis.context.clone());
        let stack_label: Arc<str> = "scenario".into();

        let byzantine = input.config.faults > 0;

        let mut nodes: Vec<Option<MarshalNode<P, M>>> = Vec::with_capacity(NUM_VALIDATORS as usize);
        let mut engine_channels: Vec<Option<NetworkChannels<PublicKeyOf<P>>>> =
            Vec::with_capacity(NUM_VALIDATORS as usize);
        for (idx, validator) in participants.iter().enumerate() {
            let validator_ctx = context.child("validator").with_attribute("index", idx);
            engine_channels
                .push(Some(register_engine_networks::<P>(&oracle, validator.clone()).await));
            if byzantine && idx == Node::A.idx() {
                nodes.push(None);
                continue;
            }
            // The victim's P2P resolver is built around a handler pair the
            // runner holds, so the prefix can inject the source's armed
            // delivery while the real fetch, deliver, and serve paths stay
            // live for the fuzzing phase.
            let (resolver_override, injection_handler) = if idx == Node::B.idx() {
                let injectable_ctx = validator_ctx.child("injectable");
                let (pair, handler) = init_injectable::<P>(
                    &injectable_ctx,
                    &oracle,
                    validator.clone(),
                )
                .await;
                (Some(pair), Some(handler))
            } else {
                (None, None)
            };
            let mut validator_state = setup_validator::<P>(
                validator_ctx.child("marshal"),
                &mut oracle,
                validator.clone(),
                commonware_cryptography::certificate::ConstantProvider::new(schemes[idx].clone()),
                Start::Genesis(genesis.clone()),
                resolver_override,
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
            // Wrap the real resolver so the prefix can observe exact fetches
            // (and inject deliveries on the victim), and the real broadcast
            // buffer so it can observe dispatched blocks and local waits.
            let (resolver_rx, real_resolver) = validator_state.take_resolver();
            let resolver = match injection_handler {
                Some(handler) => RecordingResolver::<P>::injectable(handler, real_resolver),
                None => RecordingResolver::<P>::observing(real_resolver),
            };
            let sends = Arc::new(commonware_utils::sync::Mutex::new(Vec::new()));
            let subscriptions = Arc::new(AtomicUsize::new(0));
            // Recording-only during the prefix; the runner enables forwarding
            // before the engines start.
            let forwarding = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let buffer = RecordingBuffer::<P>::new(
                validator_state.buffer.clone(),
                sends.clone(),
                forwarding.clone(),
                subscriptions.clone(),
            );
            validator_state.start_with_buffer(
                builder.clone(),
                (resolver_rx, resolver.clone()),
                buffer,
            );
            nodes.push(Some(MarshalNode {
                mailbox: validator_state.mailbox.clone(),
                application: validator_state.application.clone(),
                progress,
                builder,
                resolver,
                sends,
                subscriptions,
                forwarding,
            }));
        }

        // === PREFIX ===
        let harness_nodes: Vec<Option<HarnessNode<P, M>>> = nodes
            .iter()
            .map(|node| {
                node.as_ref().map(|node| HarnessNode {
                    mailbox: node.mailbox.clone(),
                    wrapper: node.builder.clone(),
                    resolver: node.resolver.clone(),
                    application: node.application.clone(),
                    sends: node.sends.clone(),
                    subscriptions: node.subscriptions.clone(),
                })
            })
            .collect();
        let mut harness = Harness::<P, M>::new(
            context.child("prefix"),
            participants.clone(),
            schemes.clone(),
            genesis,
            harness_nodes,
        );
        let handoff = scenarios::drive::<P, M>(input.scenario, &mut harness).await;
        harness.finish(&handoff).await;

        // The prefix is validated; enable broadcast forwarding so the fuzzing
        // phase disseminates blocks normally (the prefix buffer was recording-only).
        for node in nodes.iter().flatten() {
            node.forwarding
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // Seed the recovered-journal artifacts into every honest engine's voter
        // journal (partition `scenario-{idx}`) before `Engine::new`: startup
        // replay installs the recovered proposal ahead of the live loop and
        // re-drives its certification, the Simplex recovery path this feature
        // composes with.
        if !handoff.engine_journal.is_empty() {
            for idx in 0..NUM_VALIDATORS as usize {
                if nodes[idx].is_none() {
                    continue;
                }
                let mut journal = Journal::<_, Artifact<SchemeOf<P>, Sha256Digest>>::init(
                    context.child("journal_seed").with_attribute("index", idx),
                    JConfig {
                        partition: format!("scenario-{idx}"),
                        compression: None,
                        codec_config: schemes[idx].certificate_codec_config(),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        write_buffer: NZUsize!(1024 * 1024),
                    },
                )
                .await
                .expect("failed to initialize seeded voter journal");
                for notarization in &handoff.engine_journal {
                    let view = notarization.round().view();
                    let artifact = Artifact::Notarization(notarization.clone());
                    (journal, _, _) = journal
                        .append(view.get(), &artifact)
                        .await
                        .expect("failed to append seeded voter artifact");
                    journal = journal
                        .sync(view.get())
                        .await
                        .expect("failed to sync seeded voter journal");
                }
                let _ = journal;
            }
        }

        let floor = handoff.engine_floor.clone();
        // The adversary extends the recovered state: its attack block's parent
        // is the anchor digest at the view and height directly below the attack
        // (the engine floor when nothing is recovered above it; the handoff
        // assertions pin this correspondence).
        let anchor_parent_digest = handoff.attack_anchor.digest;
        let anchor_parent_view = View::new(handoff.attack_anchor.view.get().saturating_sub(1));
        let anchor_parent_height = handoff.attack_anchor.height.get().saturating_sub(1);
        let attack_view = handoff.attack_anchor.view;
        let attack_height = handoff.attack_anchor.height;

        // === FUZZING PHASE ===
        // Install the complete pre-heal topology before releasing any engine or
        // disrupter, so none can emit into a partially-installed network. The
        // marshals (already running since setup) may backfill over the new links;
        // that is the intended post-handoff fuzzing behaviour, and the handoff
        // assertions above already validated the engine-free prefix state.
        apply_partition(&oracle, &participants, input.partition.set_partition(), &LINK).await;
        if input.degraded_network {
            apply_degraded_network::<P>(&oracle, &participants).await;
        }

        for (idx, validator) in participants.iter().enumerate() {
            let channels = engine_channels[idx].take().expect("engine channels");
            if byzantine && idx == Node::A.idx() {
                let (vote, certificate, resolver) = channels;
                let dissemination_ctx = context.child("adversary").child("dissemination");
                adversary::start_dissemination_disrupter::<P>(
                    &dissemination_ctx,
                    &oracle,
                    validator.clone(),
                    schemes[idx].clone(),
                    schemes.clone(),
                    participants.clone(),
                    anchor_parent_digest,
                    anchor_parent_view,
                    attack_view,
                    attack_height,
                    vote.0.clone(),
                    input.fault_plan,
                )
                .await;
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
                    RoundRobin::<Sha256>::default(),
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

        // Liveness phase 1: let pre-GST faults act until the fastest honest node
        // advances the requested run depth past the floor, or the window elapses.
        let phase1_ceiling =
            (anchor_parent_height + input.required_containers).min(MAX_REQUIRED.saturating_sub(1));
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
        // The heal must not fire before the adversary has had time to act. When
        // the honest nodes already sit at (or race to) the phase-1 ceiling before
        // the adversary emits (for example a restart scenario whose floor already
        // sits at the ceiling, or a disrupter whose faults land a few views ahead),
        // the ceiling watchers alone would heal a zero-length fault phase. Requiring
        // a minimum pre-heal window ensures the dissemination announce and the
        // Simplex disrupter's live-view faults are exercised before the heal.
        let min_fault_phase = if byzantine {
            MIN_FAULT_PHASE
        } else {
            Duration::ZERO
        };
        select! {
            _ = async {
                futures::future::join(
                    select_all(phase1_watchers),
                    context.sleep(min_fault_phase),
                )
                .await;
            } => {},
            _ = context.sleep(FAULT_PHASE) => {},
        }

        // Heal unconditionally, then capture each honest node's baseline.
        apply_partition(&oracle, &participants, None, &LINK).await;
        let baselines: Vec<(usize, u64, _)> = honest_progress
            .iter()
            .map(|(idx, progress)| {
                let (baseline, updates) = progress.subscribe();
                (*idx, baseline, updates)
            })
            .collect();

        // Liveness phase 2: every honest node with epoch headroom must make fresh
        // post-GST progress; nodes already at the epoch ceiling are excluded.
        let (measurable, at_ceiling): (Vec<_>, Vec<_>) = baselines
            .into_iter()
            .partition(|(_, baseline, _)| *baseline < MAX_REQUIRED);
        if measurable.is_empty() {
            // The check is skipped, never silently: report the reason on
            // stdout so an ordinary `#[test]` run surfaces it.
            let skipped: Vec<(usize, u64)> = at_ceiling
                .iter()
                .map(|(idx, baseline, _)| (*idx, *baseline))
                .collect();
            if cfg!(not(fuzzing)) {
                println!(
                    "scenario liveness skipped: scenario={:?} marshal={marshal} \
                     byzantine={byzantine} skipped={skipped:?} reason=\"every honest node \
                     already at the single-epoch delivery ceiling ({MAX_REQUIRED})\"",
                    input.scenario,
                );
            }
        } else {
            let targets: Vec<(usize, u64)> = measurable
                .iter()
                .map(|(idx, baseline, _)| (*idx, baseline + 1))
                .collect();
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
        // I6: after the unconditional heal restores every link losslessly, no
        // honest node may blocklist an honest peer. Pairs touching the byzantine
        // node (index 0, adversarial mode only) are exempt, since blocklisting a
        // poison-serving adversary is correct.
        let byzantine_key = byzantine.then(|| participants[Node::A.idx()].clone());
        let blocked = oracle.blocked().await.expect("blocklist query failed");
        for (blocker, blocked_peer) in &blocked {
            let touches_byzantine = byzantine_key
                .as_ref()
                .is_some_and(|adversary| blocker == adversary || blocked_peer == adversary);
            assert!(
                touches_byzantine,
                "I6 violated: honest node blocklisted an honest peer at the measurement point: \
                 {blocker} -> {blocked_peer}; scenario={:?}",
                input.scenario,
            );
        }

        let floor_height = handoff
            .expectation
            .all_floor_rooted
            .unwrap_or(commonware_consensus::types::Height::zero());
        invariants::check_all_blocks(
            &honest_apps,
            genesis_commitment,
            floor_height,
            Some(&stack_label),
        );

        // The checks are not vacuous: report how many nodes were checked and
        // how many blocks were delivered at the measurement point, and require
        // both counts to be nonzero. The report goes to stdout so an ordinary
        // `#[test]` run surfaces it, and names the marshal variant so it is
        // identifiable per configuration; fuzz runs stay silent.
        let nodes_checked = honest_apps.len();
        let blocks_delivered: usize = honest_apps
            .iter()
            .map(|(_, app)| app.delivered().len())
            .sum();
        if cfg!(not(fuzzing)) {
            println!(
                "scenario measurement point: scenario={:?} marshal={marshal} \
                 byzantine={byzantine} nodes_checked={nodes_checked} \
                 blocks_delivered={blocks_delivered}",
                input.scenario,
            );
        }
        assert!(
            nodes_checked > 0,
            "measurement vacuous: no honest node was checked; scenario={:?}",
            input.scenario,
        );
        assert!(
            blocks_delivered > 0,
            "measurement vacuous: no block was delivered at the measurement point; \
             scenario={:?} nodes_checked={nodes_checked}",
            input.scenario,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Configuration, N4F0C4, N4F1C3, SimplexCertificateMock,
        scenarios::input::{BackfillFault, BlockFault, ConsensusMutation, FaultPlan, ScenarioKind},
        utils::Partition,
    };
    use commonware_consensus::simplex::ForwardingPolicy;

    fn input(scenario: ScenarioKind, config: Configuration) -> MarshalScenarioPrefixInput {
        MarshalScenarioPrefixInput {
            raw_bytes: vec![0u8; 64],
            scenario,
            config,
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
        }
    }

    /// Run one scenario configuration under one Standard variant.
    fn run_one(scenario: ScenarioKind, config: Configuration, marshal: MarshalChoice) {
        let input = input(scenario, config);
        match marshal {
            MarshalChoice::Deferred => {
                fuzz_marshal_scenario_prefix_deferred::<SimplexCertificateMock>(input)
            }
            MarshalChoice::Inline => {
                fuzz_marshal_scenario_prefix_inline::<SimplexCertificateMock>(input)
            }
        }
    }

    // One `#[test]` per configuration (scenario x mode x variant), so a failure
    // in one variant cannot mask the other variant's result.
    macro_rules! scenario_smoke {
        ($module:ident, $kind:ident) => {
            mod $module {
                use super::*;

                #[test]
                fn honest_deferred() {
                    run_one(ScenarioKind::$kind, N4F0C4, MarshalChoice::Deferred);
                }
                #[test]
                fn honest_inline() {
                    run_one(ScenarioKind::$kind, N4F0C4, MarshalChoice::Inline);
                }
                #[test]
                fn adversarial_deferred() {
                    run_one(ScenarioKind::$kind, N4F1C3, MarshalChoice::Deferred);
                }
                #[test]
                fn adversarial_inline() {
                    run_one(ScenarioKind::$kind, N4F1C3, MarshalChoice::Inline);
                }
            }
        };
    }

    scenario_smoke!(missing_candidate, MissingCandidate);
}
