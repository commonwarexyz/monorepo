pub mod automaton;
pub mod compare;
pub mod injected;
pub mod messages;

use crate::{
    invariants,
    tracing::{
        data::TraceData,
        encoder::{build_action_items, build_block_map, ActionItem, EncoderConfig},
    },
    types::ReplayedReplicaState,
};
use automaton::ReplayAutomaton;
use commonware_consensus::{
    simplex::{
        config,
        config::ForwardingPolicy,
        elector::RoundRobin,
        mocks::reporter,
        scheme::ed25519,
        types::{Finalize, Nullify, Vote},
        voter, Engine,
    },
    types::{Delta, Epoch as EpochType, Round, View},
};
use commonware_cryptography::{
    certificate::mocks::Fixture,
    sha256::{Digest as Sha256Digest, Sha256 as Sha256Hasher},
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Clock, Metrics, Runner};
use commonware_utils::{NZUsize, NZU16};
use injected::{channel, NullBlocker, NullSender, PendingReceiver};
use messages::{
    construct_cert_from_item, construct_finalize_vote, construct_notarize_vote,
    construct_nullify_vote, digest_from_block_hex, make_proposal,
};
use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroUsize},
    time::Duration,
};

const NAMESPACE: &[u8] = b"consensus_fuzz";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

/// Replays a trace by injecting messages into isolated engines and extracting
/// observable state from reporters.
///
/// Uses `build_action_items` to normalize the trace into causal `ActionItem`s,
/// then processes each action: proposals are injected via the voter's `Proposed`
/// hook, votes and certificates are injected via network channels.
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

        // Build block map and reverse map (val_bN -> hex hash)
        let block_map = build_block_map(trace);
        let block_map_rev: HashMap<String, String> = block_map
            .iter()
            .map(|(hex, name)| (name.clone(), hex.clone()))
            .collect();

        // Create injectors, voter mailboxes, and reporters for each correct node
        let correct_start = faults;
        let mut vote_injectors = Vec::new();
        let mut cert_injectors = Vec::new();
        let mut voter_mailboxes: Vec<voter::Mailbox<ed25519::Scheme, Sha256Digest>> = Vec::new();
        let mut reporters = Vec::new();
        let mut automatons = Vec::new();

        let elector = RoundRobin::<Sha256Hasher>::default();

        for i in correct_start..n {
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

            // ReplayAutomaton instead of full application
            let automaton = ReplayAutomaton::new();
            automatons.push(automaton.clone());

            // Engine
            let engine_cfg = config::Config {
                blocker: NullBlocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: automaton.clone(),
                relay: automaton,
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
            voter_mailboxes.push(engine.voter_mailbox());
            engine.start(
                (NullSender, vote_rx),
                (NullSender, cert_rx),
                (NullSender, resolver_rx),
            );
        }

        // Build normalized action items from the trace
        let cfg = EncoderConfig {
            n,
            faults,
            epoch,
            max_view: trace.max_view,
            required_containers: 0,
        };
        let actions = build_action_items(trace, &cfg);

        // Replay action items
        for action in &actions {
            match action {
                ActionItem::Propose {
                    leader,
                    view,
                    payload,
                    parent_view,
                } => {
                    let leader_idx = parse_node_id(leader);
                    let block_hex = block_map_rev
                        .get(payload)
                        .expect("unknown block name in propose");

                    // Register the digest in the automaton so verify() succeeds
                    let digest = digest_from_block_hex(block_hex);
                    // Register in ALL automatons (any node may need to verify)
                    for auto in &automatons {
                        auto.register(digest);
                    }

                    // If the leader is a correct node, inject via Proposed hook
                    if leader_idx >= faults {
                        let correct_idx = leader_idx - faults;
                        let proposal =
                            make_proposal(epoch, *view, *parent_view, block_hex);
                        voter_mailboxes[correct_idx].proposed(proposal).await;
                    }
                }
                ActionItem::OnNotarize {
                    receiver,
                    view,
                    parent_view,
                    payload,
                    sig,
                } => {
                    let block_hex = block_map_rev
                        .get(payload)
                        .expect("unknown block name in on_notarize");
                    let msg = construct_notarize_vote(
                        receiver,
                        sig,
                        *view,
                        *parent_view,
                        block_hex,
                        &schemes,
                        &participants,
                        epoch,
                    );
                    if msg.receiver_idx >= faults {
                        let correct_idx = msg.receiver_idx - faults;
                        vote_injectors[correct_idx]
                            .inject(msg.sender_pk, msg.payload);
                    }
                }
                ActionItem::OnNullify {
                    receiver,
                    view,
                    sig,
                } => {
                    // Skip self-deliveries; sender-local state is driven
                    // by SendNullifyVote instead (sets broadcast_nullify flag).
                    if receiver == sig {
                        continue;
                    }
                    let msg = construct_nullify_vote(
                        receiver,
                        sig,
                        *view,
                        &schemes,
                        &participants,
                        epoch,
                    );
                    if msg.receiver_idx >= faults {
                        let correct_idx = msg.receiver_idx - faults;
                        vote_injectors[correct_idx]
                            .inject(msg.sender_pk, msg.payload);
                    }
                }
                ActionItem::OnFinalize {
                    receiver,
                    view,
                    parent_view,
                    payload,
                    sig,
                } => {
                    // Skip self-deliveries; sender-local state is driven
                    // by SendFinalizeVote instead (sets broadcast_finalize flag).
                    if receiver == sig {
                        continue;
                    }
                    let block_hex = block_map_rev
                        .get(payload)
                        .expect("unknown block name in on_finalize");
                    let msg = construct_finalize_vote(
                        receiver,
                        sig,
                        *view,
                        *parent_view,
                        block_hex,
                        &schemes,
                        &participants,
                        epoch,
                    );
                    if msg.receiver_idx >= faults {
                        let correct_idx = msg.receiver_idx - faults;
                        vote_injectors[correct_idx]
                            .inject(msg.sender_pk, msg.payload);
                    }
                }
                ActionItem::OnCertificate { receiver, cert } => {
                    let msg = construct_cert_from_item(
                        receiver,
                        cert,
                        &block_map_rev,
                        &schemes,
                        &participants,
                        epoch,
                    );
                    if msg.receiver_idx >= faults {
                        let correct_idx = msg.receiver_idx - faults;
                        cert_injectors[correct_idx]
                            .inject(msg.sender_pk, msg.payload);
                    }
                }
                ActionItem::SendNullifyVote { view, sig } => {
                    let signer_idx = parse_node_id(sig);
                    if signer_idx >= faults {
                        let correct_idx = signer_idx - faults;
                        let round = Round::new(
                            EpochType::new(epoch),
                            View::new(*view),
                        );
                        let nullify = Nullify::<ed25519::Scheme>::sign::<Sha256Digest>(
                            &schemes[signer_idx],
                            round,
                        )
                        .expect("signing must succeed");
                        voter_mailboxes[correct_idx]
                            .replayed(Vote::Nullify(nullify))
                            .await;
                    }
                }
                ActionItem::SendFinalizeVote {
                    view,
                    parent_view,
                    payload,
                    sig,
                } => {
                    let signer_idx = parse_node_id(sig);
                    if signer_idx >= faults {
                        let correct_idx = signer_idx - faults;
                        let block_hex = block_map_rev
                            .get(payload)
                            .expect("unknown block name in send_finalize_vote");
                        let proposal =
                            make_proposal(epoch, *view, *parent_view, block_hex);
                        let finalize = Finalize::<ed25519::Scheme, Sha256Digest>::sign(
                            &schemes[signer_idx],
                            proposal,
                        )
                        .expect("signing must succeed");
                        voter_mailboxes[correct_idx]
                            .replayed(Vote::Finalize(finalize))
                            .await;
                    }
                }
                // Notarize sends and certificate sends are no-ops for the replayer.
                // Notarize local state is already set by the Proposed hook.
                ActionItem::SendNotarizeVote { .. }
                | ActionItem::SendCertificate { .. } => {}
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

fn parse_node_id(id: &str) -> usize {
    id.strip_prefix('n')
        .and_then(|s| s.parse().ok())
        .expect("invalid node id")
}

/// Replays a trace and runs invariant checks on the extracted state.
pub fn replay_and_check(
    trace: &TraceData,
    faults_override: Option<usize>,
) -> Vec<ReplayedReplicaState> {
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
    let faults = faults_override.unwrap_or(trace.faults);
    invariants::check_vote_invariants(&states, faults);
    states
}
