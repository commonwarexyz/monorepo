pub mod compare;
pub mod injected;
pub mod messages;

use crate::{
    invariants,
    tracing::{data::TraceData, sniffer::TraceEntry},
    types::ReplayedReplicaState,
};
use commonware_consensus::{
    simplex::{
        config,
        config::ForwardingPolicy,
        elector::RoundRobin,
        mocks::{application, relay, reporter},
        scheme::ed25519,
        Engine,
    },
    types::{Delta, Epoch as EpochType},
};
use commonware_cryptography::{
    certificate::mocks::Fixture, sha256::Sha256 as Sha256Hasher, Sha256,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Clock, Metrics, Runner};
use commonware_utils::{NZUsize, NZU16};
use injected::{channel, NullBlocker, NullSender, PendingReceiver};
use messages::build_proposal_parents;
use std::{
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"consensus_fuzz";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

/// Replays a trace by injecting messages into isolated engines and extracting
/// observable state from reporters.
///
/// `faults_override` overrides the trace's `faults` field, controlling how
/// many leading nodes are skipped as Byzantine. Pass `Some(0)` to replay on
/// all `n` nodes as correct (matching the TLC all-correct model).
pub fn replay_trace(
    trace: &TraceData,
    faults_override: Option<usize>,
) -> Vec<ReplayedReplicaState> {
    let executor = deterministic::Runner::timed(Duration::from_secs(120));

    executor.start(|mut context| async move {
        let n = trace.n;
        let faults = faults_override.unwrap_or(trace.faults);
        let epoch = trace.epoch;

        // Generate deterministic ed25519 keys (same as fuzzer)
        let Fixture {
            participants,
            schemes,
            verifier: _,
            ..
        } = ed25519::fixture(&mut context, NAMESPACE, n as u32);

        // Create injectors and receivers for each correct node
        let correct_start = faults;
        let mut vote_injectors = Vec::new();
        let mut cert_injectors = Vec::new();
        let mut reporters = Vec::new();

        let relay = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();

        for i in correct_start..n {
            let validator = participants[i].clone();
            let ctx = context.with_label(&format!("validator_n{i}"));

            // Vote channel: injected receiver, null sender
            let (vote_inj, vote_rx) = channel();
            vote_injectors.push(vote_inj);

            // Certificate channel: injected receiver, null sender
            let (cert_inj, cert_rx) = channel();
            cert_injectors.push(cert_inj);

            // Resolver channel: pending receiver, null sender
            let resolver_rx = PendingReceiver;

            // Reporter
            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let app_cfg = application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Sometimes,
            };
            let (actor, application) =
                application::Application::new(ctx.with_label("application"), app_cfg);
            actor.start();

            // Engine
            let engine_cfg = config::Config {
                blocker: NullBlocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("replayer_n{i}"),
                mailbox_size: 1024,
                epoch: EpochType::new(epoch),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_secs(30),
                fetch_timeout: Duration::from_secs(5),
                activity_timeout: Delta::new(100),
                skip_timeout: Delta::new(50),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
            engine.start(
                (NullSender, vote_rx),
                (NullSender, cert_rx),
                (NullSender, resolver_rx),
            );
        }

        // Reconstruct proposal parents with the same per-(view, block)
        // heuristic used by the tracing encoder.
        let proposal_parents = build_proposal_parents(&trace.entries);

        // Replay trace entries
        for entry in &trace.entries {
            // Skip self-votes: the engine generates its own votes internally
            // via constructed(), so injecting them again causes duplicates.
            if let TraceEntry::Vote {
                sender, receiver, ..
            } = entry
            {
                if sender == receiver {
                    continue;
                }
            }

            let receiver_id = match entry {
                TraceEntry::Vote { receiver, .. } => receiver,
                TraceEntry::Certificate { receiver, .. } => receiver,
            };

            // Parse receiver index
            let receiver_idx = receiver_id
                .strip_prefix('n')
                .and_then(|s| s.parse::<usize>().ok())
                .expect("invalid receiver id");

            // Skip entries for Byzantine nodes
            if receiver_idx < faults {
                continue;
            }

            // Map to correct node index (0-based in our injector arrays)
            let correct_idx = receiver_idx - faults;

            let msg = messages::construct_message(
                entry,
                &schemes,
                &participants,
                epoch,
                &proposal_parents,
            );

            if msg.is_certificate {
                cert_injectors[correct_idx].inject(msg.sender_pk, msg.payload);
            } else {
                vote_injectors[correct_idx].inject(msg.sender_pk, msg.payload);
            }

            // Yield to let the engine process the message
            context.sleep(Duration::from_millis(1)).await;
        }

        // Wait for processing to settle
        context.sleep(Duration::from_secs(2)).await;

        // Extract observable state
        invariants::extract_replayed(&reporters, n)
    })
}

/// Replays a trace and runs invariant checks on the extracted state.
pub fn replay_and_check(trace: &TraceData, faults_override: Option<usize>) {
    let states = replay_trace(trace, faults_override);
    // Convert to ReplicaState tuples for invariant checking
    let replica_states: Vec<_> = states
        .iter()
        .map(|s| {
            // We can't move out of s, so we need to reference the fields.
            // invariants::check needs owned data, so clone isn't ideal,
            // but this is test-only code.
            let notarizations = s
                .notarizations
                .iter()
                .map(|(&v, n)| {
                    (
                        v,
                        crate::types::Notarization {
                            payload: n.payload,
                            signature_count: n.signature_count,
                        },
                    )
                })
                .collect();
            let nullifications = s
                .nullifications
                .iter()
                .map(|(&v, n)| {
                    (
                        v,
                        crate::types::Nullification {
                            signature_count: n.signature_count,
                        },
                    )
                })
                .collect();
            let finalizations = s
                .finalizations
                .iter()
                .map(|(&v, f)| {
                    (
                        v,
                        crate::types::Finalization {
                            payload: f.payload,
                            signature_count: f.signature_count,
                        },
                    )
                })
                .collect();
            (notarizations, nullifications, finalizations)
        })
        .collect();
    invariants::check::<crate::SimplexEd25519>(trace.n as u32, &replica_states);
}
