use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Copying, DecodeExt, Encode};
use commonware_consensus::{
    Reporter, Viewable,
    simplex::{
        scheme::ed25519,
        types::{
            Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Finalize, Notarize,
            Nullify, NullifyFinalize, Proposal, Vote,
        },
    },
    types::{Epoch, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    EPOCH, MAX_RAW_BYTES, MAX_TERM_LENGTH, reach, sample_optimistic_views, state_bounds,
};
use commonware_consensus_fuzz_simplex::evidence::{
    self, Classified, EvidenceType, Exported, FuzzInput, Logs, Obligation, Pair, PairKind, Plant,
    Raw, Reason, Recorded, Report, Rules, Scheme, Sequence, Taken,
};
use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
use commonware_invariants::minifuzz;
use commonware_p2p::{Message, Receiver};
use commonware_parallel::Sequential;
use commonware_runtime::IoBuf;
use commonware_utils::{NZU32, TestRng, sync::Mutex};
use futures::executor::block_on;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    sync::OnceLock,
    time::Instant,
};

type Ballot = Vote<Scheme, Sha256Digest>;

fn term_length(value: u32) -> TermLength {
    TermLength::new(NZU32!(value))
}

fn decode_input(bytes: &[u8]) -> FuzzInput {
    FuzzInput::arbitrary(&mut Unstructured::new(bytes)).expect("the input must decode")
}

fn reference_decode(bytes: &[u8]) -> FuzzInput {
    let mut input = Unstructured::new(bytes);
    let required_containers = input.int_in_range(20..=40).unwrap();
    let term_length = TermLength::new(NZU32!(input.int_in_range(1..=MAX_TERM_LENGTH).unwrap()));
    let optimistic_views =
        ViewDelta::new(sample_optimistic_views(&mut input, term_length).unwrap());
    let latency_ms = input.int_in_range(1..=50).unwrap();
    let jitter_ms = input.int_in_range(0..=50).unwrap();
    let track_historical_votes = input.int_in_range(0..=7).unwrap() != 7;
    FuzzInput {
        raw_bytes: bytes[..bytes.len().min(MAX_RAW_BYTES)].to_vec(),
        required_containers,
        term_length,
        optimistic_views,
        latency_ms,
        jitter_ms,
        track_historical_votes,
    }
}

fn empty_input() -> FuzzInput {
    decode_input(&[])
}

fn panic_text(f: impl FnOnce()) -> String {
    let payload = panic::catch_unwind(AssertUnwindSafe(f)).expect_err("the control must panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&'static str>()
                .map(|text| (*text).to_owned())
        })
        .unwrap_or_else(|| "<non-string panic>".to_owned())
}

fn fixture(namespace: &[u8]) -> Fixture<Scheme> {
    ed25519::fixture(&mut TestRng::new(7), namespace, 4)
}

fn round(view: u64) -> Round {
    Round::new(Epoch::new(EPOCH), View::new(view))
}

fn proposal(view: u64, payload: u8) -> Proposal<Sha256Digest> {
    Proposal::new(
        round(view),
        View::new(view.saturating_sub(1)),
        Sha256Digest::from([payload; 32]),
    )
}

fn ballot_activity(vote: &Ballot) -> Exported {
    match vote {
        Vote::Notarize(vote) => Activity::Notarize(vote.clone()),
        Vote::Nullify(vote) => Activity::Nullify(vote.clone()),
        Vote::Finalize(vote) => Activity::Finalize(vote.clone()),
    }
}

fn fault_activity(kind: PairKind, first: &Ballot, second: &Ballot) -> Exported {
    match (kind, first, second) {
        (PairKind::K1, Vote::Notarize(first), Vote::Notarize(second)) => {
            Activity::ConflictingNotarize(ConflictingNotarize::new(first.clone(), second.clone()))
        }
        (PairKind::K2, Vote::Finalize(first), Vote::Finalize(second)) => {
            Activity::ConflictingFinalize(ConflictingFinalize::new(first.clone(), second.clone()))
        }
        (PairKind::K3, Vote::Nullify(nullify), Vote::Finalize(finalize))
        | (PairKind::K4, Vote::Finalize(finalize), Vote::Nullify(nullify)) => {
            Activity::NullifyFinalize(NullifyFinalize::new(nullify.clone(), finalize.clone()))
        }
        _ => panic!("wrong vote shape for {kind:?}"),
    }
}

fn signed_pair(kind: PairKind, scheme: &Scheme, view: u64) -> (Ballot, Ballot) {
    match kind {
        PairKind::K1 => (
            Vote::Notarize(Notarize::sign(scheme, proposal(view, 1)).unwrap()),
            Vote::Notarize(Notarize::sign(scheme, proposal(view, 2)).unwrap()),
        ),
        PairKind::K2 => (
            Vote::Finalize(Finalize::sign(scheme, proposal(view, 1)).unwrap()),
            Vote::Finalize(Finalize::sign(scheme, proposal(view, 2)).unwrap()),
        ),
        PairKind::K3 => (
            Vote::Nullify(Nullify::sign::<Sha256Digest>(scheme, round(view)).unwrap()),
            Vote::Finalize(Finalize::sign(scheme, proposal(view, 2)).unwrap()),
        ),
        PairKind::K4 => (
            Vote::Finalize(Finalize::sign(scheme, proposal(view, 1)).unwrap()),
            Vote::Nullify(Nullify::sign::<Sha256Digest>(scheme, round(view)).unwrap()),
        ),
        PairKind::None => panic!("None has no pair"),
    }
}

#[derive(Clone)]
struct BuiltTrace {
    verifier: Scheme,
    rules: Rules,
    pair: Pair,
    logs: Logs,
}

fn built_trace_with(
    kind: PairKind,
    view: u64,
    gauge: u64,
    node: usize,
    signer: &Scheme,
    verifier: Scheme,
) -> BuiltTrace {
    let (first, second) = signed_pair(kind, signer, view);
    let evidence = fault_activity(kind, &first, &second);
    let first_bytes = first.encode().to_vec();
    let second_bytes = second.encode().to_vec();
    BuiltTrace {
        verifier,
        rules: Rules {
            equivocator: 0,
            track_historical_votes: true,
            term_length: term_length(5),
            optimistic_views: ViewDelta::new(5),
        },
        pair: Pair {
            kind,
            view: View::new(view),
            first: first_bytes.clone(),
            second: second_bytes.clone(),
        },
        logs: Logs {
            node,
            tap: vec![
                Taken {
                    seq: 0,
                    bytes: first_bytes,
                    gauge: view,
                },
                Taken {
                    seq: 3,
                    bytes: second_bytes,
                    gauge,
                },
                Taken {
                    seq: 6,
                    bytes: vec![0xff],
                    gauge,
                },
            ],
            raw: vec![
                Recorded {
                    seq: 1,
                    activity: ballot_activity(&first),
                },
                Recorded {
                    seq: 4,
                    activity: evidence.clone(),
                },
            ],
            forwarded: vec![evidence],
        },
    }
}

fn built_trace(kind: PairKind) -> BuiltTrace {
    let fixture = fixture(b"consensus-c4-acceptance");
    built_trace_with(kind, 8, 8, 1, &fixture.schemes[0], fixture.verifier)
}

fn classify(trace: &BuiltTrace) -> Classified {
    evidence::obligations(
        &trace.verifier,
        &trace.rules,
        std::slice::from_ref(&trace.pair),
        &trace.logs,
    )
}

fn only_reason(trace: &BuiltTrace) -> Reason {
    let classified = classify(trace);
    assert!(classified.obligations.is_empty());
    assert!(classified.untracked.is_empty());
    assert_eq!(classified.unmeasured.len(), 1);
    classified.unmeasured[0].reason
}

fn fixed_outcomes() -> &'static [evidence::Outcome] {
    static OUTCOMES: OnceLock<Vec<evidence::Outcome>> = OnceLock::new();
    OUTCOMES.get_or_init(|| evidence::fixed_corpus().iter().map(evidence::run).collect())
}

fn default_outcomes() -> &'static [evidence::Outcome] {
    static OUTCOMES: OnceLock<Vec<evidence::Outcome>> = OnceLock::new();
    OUTCOMES.get_or_init(|| {
        evidence::fixed_corpus()
            .into_iter()
            .map(|input| {
                evidence::run(&FuzzInput {
                    track_historical_votes: false,
                    ..input
                })
            })
            .collect()
    })
}

fn production_admits(current: u64, pending: u64, length: u32, lookahead: u64) -> bool {
    let term_length = term_length(length);
    let current = View::new(current);
    let pending = View::new(pending);
    if current.admits(pending, term_length) {
        return true;
    }
    let window = current
        .term_end(term_length)
        .min(current.saturating_add(ViewDelta::new(
            lookahead.saturating_mul(2).saturating_add(1),
        )));
    if current < pending && pending <= window {
        return true;
    }
    let next = current.next_term_start(term_length);
    let lane = lookahead.max(1).min(u64::from(length)).saturating_add(1);
    pending > next && pending <= next.saturating_add(ViewDelta::new(lane))
}

#[derive(Debug)]
struct QueueReceiver {
    messages: VecDeque<Message<evidence::PublicKey>>,
}

impl Receiver for QueueReceiver {
    type Error = io::Error;
    type PublicKey = evidence::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        self.messages
            .pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "queue empty"))
    }

    fn capacity(&self) -> NonZeroUsize {
        NonZeroUsize::new(8).unwrap()
    }
}

fn decode_ballot(bytes: &[u8]) -> Ballot {
    Ballot::decode(Copying(bytes)).expect("the trace contains an encoded vote")
}

fn assert_valid_ballot(verifier: &Scheme, vote: &Ballot, signer: usize, view: View) {
    assert_eq!(vote.view(), view);
    let actual = match vote {
        Vote::Notarize(vote) => vote.signer(),
        Vote::Nullify(vote) => vote.signer(),
        Vote::Finalize(vote) => vote.signer(),
    };
    assert_eq!(usize::from(actual), signer);
    let mut rng = TestRng::new(0);
    let valid = match vote {
        Vote::Notarize(vote) => vote.verify(&mut rng, verifier, &Sequential),
        Vote::Nullify(vote) => vote.verify::<_, Sha256Digest>(&mut rng, verifier, &Sequential),
        Vote::Finalize(vote) => vote.verify(&mut rng, verifier, &Sequential),
    };
    assert!(valid);
}

#[test]
fn evidence_at_002_admission_examples() {
    let cases: &[(u64, u64, u64, &[u64], u64)] = &[
        (20, 2, 10, &[11, 12, 13, 14, 15, 21, 22, 23, 24], 16),
        (20, 2, 19, &[20, 21, 22, 23, 24], 25),
        (1, 0, 5, &[6, 7, 8], 9),
        (5, 0, 5, &[6, 7, 8], 9),
        (5, 0, 6, &[7, 11, 12, 13], 8),
        (5, 0, 0, &[1, 2, 3], 4),
    ];
    for &(length, lookahead, current, admitted, rejected) in cases {
        for pending in current + 1..=rejected {
            assert_eq!(
                evidence::admits(current, pending, length, lookahead),
                admitted.contains(&pending),
                "L={length} k={lookahead} x={current} V={pending}"
            );
        }
        assert!(!evidence::admits(current, rejected, length, lookahead));
    }
}

#[test]
fn evidence_at_003_admission_matches_production_rule() {
    for length in 1u32..=7 {
        for lookahead in 0..=u64::from(length) + 2 {
            for current in 0..60 {
                for pending in 0..90 {
                    assert_eq!(
                        evidence::admits(current, pending, u64::from(length), lookahead),
                        production_admits(current, pending, length, lookahead),
                        "L={length} k={lookahead} x={current} V={pending}"
                    );
                }
            }
        }
    }
}

#[test]
fn evidence_at_004_005_current_view_selects_exactly_one_gauge() {
    let metrics = r#"
test_engine_voter_state_current_view{index="1",role="engine"} 0
test_engine_voter_state_tracked_views{index="1",role="engine"} 77
test_engine_voter_state_current_view{index="2",role="engine"} 1
test_engine_voter_state_current_view{index="3",role="engine"} 900
test_other_engine_voter_state_current_view_suffix{index="3"} 901
"#;
    assert_eq!(
        evidence::current_view(metrics, &state_bounds::Node::index(1)),
        0
    );
    assert_eq!(
        evidence::current_view(metrics, &state_bounds::Node::index(2)),
        1
    );
    assert_eq!(
        evidence::current_view(metrics, &state_bounds::Node::index(3)),
        900
    );

    for missing in ["", "test_engine_voter_state_current_view{index=\"2\"} 7"] {
        let text = panic_text(|| {
            evidence::current_view(missing, &state_bounds::Node::index(1));
        });
        assert!(text.contains("engine_voter_state_current_view"), "{text}");
    }
}

#[test]
fn evidence_at_006_tap_and_raw_share_order_without_changing_messages() {
    let fixture = fixture(b"consensus-c4-acceptance-tap");
    let b = fixture.participants[0].clone();
    let other = fixture.participants[2].clone();
    let trace = built_trace(PairKind::K1);
    let first = trace.pair.first.clone();
    let second = trace.pair.second.clone();
    let unrelated = vec![9, 8, 7];
    let receiver = QueueReceiver {
        messages: VecDeque::from([
            (b.clone(), IoBuf::from(first.clone())),
            (other, IoBuf::from(unrelated.clone())),
            (b.clone(), IoBuf::from(second.clone())),
        ]),
    };
    let gauges = Mutex::new(VecDeque::from([0, 19]));
    let sequence = Sequence::default();
    let tap_log = evidence::Log::default();
    let mut tap = evidence::Tap::new(receiver, b, sequence.clone(), tap_log.clone(), move || {
        gauges.lock().pop_front().unwrap()
    });
    let raw_log = evidence::Log::default();
    let forwarded = evidence::Log::default();
    let mut raw = Raw::new(sequence, raw_log.clone(), forwarded);

    let (_, got_first) = block_on(tap.recv()).unwrap();
    assert_eq!(got_first.as_ref(), first);
    raw.report(trace.logs.raw[0].activity.clone());
    let (_, got_unrelated) = block_on(tap.recv()).unwrap();
    assert_eq!(got_unrelated.as_ref(), unrelated);
    raw.report(trace.logs.raw[1].activity.clone());
    let (_, got_second) = block_on(tap.recv()).unwrap();
    assert_eq!(got_second.as_ref(), second);
    raw.report(trace.logs.raw[0].activity.clone());

    let taps = tap_log.entries();
    assert_eq!(taps.len(), 2);
    assert_eq!((taps[0].seq, taps[0].gauge), (0, 0));
    assert_eq!((taps[1].seq, taps[1].gauge), (3, 19));
    assert_eq!(taps[0].bytes, first);
    assert_eq!(taps[1].bytes, second);
    assert_eq!(
        raw_log
            .entries()
            .iter()
            .map(|entry| entry.seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 4]
    );
}

#[test]
fn evidence_at_008_009_positive_obligations_and_tracking_gate() {
    for kind in PairKind::PAIRS {
        let trace = built_trace(kind);
        let classified = classify(&trace);
        assert_eq!(classified.obligations.len(), 1, "{kind:?}");
        assert!(classified.unmeasured.is_empty());
        assert!(classified.untracked.is_empty());
        assert_eq!(classified.obligations[0].kind, kind);

        let rules = Rules {
            track_historical_votes: false,
            ..trace.rules
        };
        let untracked = evidence::obligations(
            &trace.verifier,
            &rules,
            std::slice::from_ref(&trace.pair),
            &trace.logs,
        );
        assert!(untracked.obligations.is_empty());
        assert!(untracked.unmeasured.is_empty());
        assert_eq!(untracked.untracked.len(), 1);
    }
}

#[test]
fn evidence_at_010_o2_rejects_each_invalid_pair_shape() {
    let valid = built_trace(PairKind::K1);
    assert_eq!(classify(&valid).obligations.len(), 1);

    let mut missing_first = valid.clone();
    missing_first.logs.tap.remove(0);
    assert_eq!(only_reason(&missing_first), Reason::FirstNotTaken);

    let mut missing_second = valid.clone();
    missing_second.logs.tap.remove(1);
    assert_eq!(only_reason(&missing_second), Reason::SecondNotTaken);

    let mut reversed = valid.clone();
    reversed.logs.tap[0].seq = 3;
    reversed.logs.tap[1].seq = 0;
    assert_eq!(only_reason(&reversed), Reason::OutOfOrder);

    let mut corrupt_first = valid.clone();
    corrupt_first.pair.first = vec![0xff];
    corrupt_first.logs.tap[0].bytes = vec![0xff];
    assert_eq!(only_reason(&corrupt_first), Reason::FirstUndecodable);

    let mut corrupt_second = valid.clone();
    corrupt_second.pair.second = vec![0xff];
    corrupt_second.logs.tap[1].bytes = vec![0xff];
    assert_eq!(only_reason(&corrupt_second), Reason::SecondUndecodable);

    let keys = fixture(b"consensus-c4-acceptance");
    let foreign = built_trace_with(PairKind::K1, 8, 8, 1, &keys.schemes[1], keys.verifier);
    assert_eq!(only_reason(&foreign), Reason::ForeignSigner);

    let correct = fixture(b"consensus-c4-acceptance-valid");
    let wrong = fixture(b"consensus-c4-acceptance-wrong");
    let invalid = built_trace_with(PairKind::K1, 8, 8, 1, &wrong.schemes[0], correct.verifier);
    assert_eq!(only_reason(&invalid), Reason::InvalidSignature);
}

#[test]
fn evidence_at_011_o3_requires_first_vote_in_its_window() {
    let valid = built_trace(PairKind::K1);
    assert_eq!(classify(&valid).obligations.len(), 1);

    let mut missing = valid.clone();
    missing.logs.raw.remove(0);
    assert_eq!(only_reason(&missing), Reason::FirstNotRecorded);

    let mut too_early = valid.clone();
    too_early.logs.raw[0].seq = 0;
    assert_eq!(only_reason(&too_early), Reason::FirstNotRecorded);

    let mut too_late = valid.clone();
    too_late.logs.raw[0].seq = 3;
    assert_eq!(only_reason(&too_late), Reason::FirstNotRecorded);

    let mut different = valid.clone();
    different.logs.raw[0].activity = built_trace(PairKind::K2).logs.raw[0].activity.clone();
    assert_eq!(only_reason(&different), Reason::FirstNotRecorded);
}

#[test]
fn evidence_at_012_o4_checks_retention_and_every_admission_view() {
    let fixture = fixture(b"consensus-c4-acceptance");
    let make = |view, gauge| {
        built_trace_with(
            PairKind::K1,
            view,
            gauge,
            1,
            &fixture.schemes[0],
            fixture.verifier.clone(),
        )
    };

    let equality = make(8, 19);
    assert_eq!(classify(&equality).obligations.len(), 1);
    assert_eq!(only_reason(&make(8, 20)), Reason::NotRetained);
    assert_eq!(only_reason(&make(0, 0)), Reason::NotRetained);

    let mut admitted = make(8, 5);
    admitted.rules.optimistic_views = ViewDelta::zero();
    assert_eq!(classify(&admitted).obligations.len(), 1);
    let mut gap = make(8, 6);
    gap.rules.optimistic_views = ViewDelta::zero();
    assert_eq!(only_reason(&gap), Reason::NotAdmitted);
}

#[test]
fn evidence_at_013_o5_applies_only_to_k2() {
    for kind in PairKind::PAIRS {
        let mut trace = built_trace(kind);
        let fixture = fixture(b"consensus-c4-acceptance");
        let cross = Nullify::<Scheme>::sign::<Sha256Digest>(&fixture.schemes[0], round(8)).unwrap();
        trace.logs.raw.insert(
            1,
            Recorded {
                seq: 2,
                activity: Activity::Nullify(cross),
            },
        );
        if kind == PairKind::K2 {
            assert_eq!(only_reason(&trace), Reason::EarlierCrossVote);
        } else {
            assert_eq!(classify(&trace).obligations.len(), 1, "{kind:?}");
        }
    }
}

#[test]
fn evidence_at_014_report_keeps_kind_node_late_and_reason_dimensions() {
    let mut classified = Vec::new();
    for (offset, kind) in PairKind::PAIRS.into_iter().enumerate() {
        let mut trace = built_trace(kind);
        trace.logs.node = offset % 3 + 1;
        let mut item = classify(&trace);
        item.obligations[0].late = offset % 2 == 0;
        classified.push(item);
    }
    classified.push(Classified {
        node: 3,
        obligations: Vec::new(),
        unmeasured: vec![evidence::Unmeasured {
            node: 3,
            kind: PairKind::K4,
            view: View::new(8),
            reason: Reason::NotAdmitted,
        }],
        untracked: Vec::new(),
    });
    let report = Report::new(&classified);
    for (offset, kind) in PairKind::PAIRS.into_iter().enumerate() {
        assert_eq!(report.at(kind, offset % 3 + 1), 1);
        assert_eq!(report.late(kind), u64::from(offset % 2 == 0));
    }
    assert_eq!(
        report.kinds[&PairKind::K4].unmeasured[&Reason::NotAdmitted],
        1
    );
}

#[test]
fn evidence_at_007_observation_wiring_and_measurement_point() {
    let outcome = &fixed_outcomes()[0];
    assert_eq!(outcome.nodes.len(), 3);
    assert_eq!(outcome.measured_at - outcome.finalized_at, evidence::SETTLE);
    for node in &outcome.nodes {
        assert_eq!(node.gauge_reads as usize, node.logs.tap.len());
        let mut sequences = BTreeSet::new();
        for entry in &node.logs.tap {
            assert!(sequences.insert(entry.seq));
        }
        for entry in &node.logs.raw {
            assert!(sequences.insert(entry.seq));
        }
        for forwarded in &node.logs.forwarded {
            assert!(node.logs.raw.iter().any(|raw| raw.activity == *forwarded));
        }
        let participant = &outcome.participants[node.logs.node];
        let gauge = evidence::current_view(
            &outcome.metrics,
            &state_bounds::Node::public_key(participant),
        );
        assert!(gauge > 0);
    }
    for classified in &outcome.classified {
        if !classified.obligations.is_empty() {
            assert!(outcome.blocked.contains(&(classified.node, 0)));
        }
    }
}

#[test]
fn evidence_at_015_topology_and_bounded_configuration_matrix() {
    let started = Instant::now();
    let mut runs = 0u64;
    for required_containers in [20, 40] {
        for length in [1, 5] {
            for lookahead in [0, length, length + 2] {
                for latency_ms in [1, 50] {
                    for jitter_ms in [0, 50] {
                        for track_historical_votes in [false, true] {
                            let input = FuzzInput {
                                raw_bytes: runs.to_be_bytes().to_vec(),
                                required_containers,
                                term_length: term_length(length as u32),
                                optimistic_views: ViewDelta::new(lookahead),
                                latency_ms,
                                jitter_ms,
                                track_historical_votes,
                            };
                            let outcome = evidence::run(&input);
                            assert_eq!(outcome.participants.len(), 4);
                            assert_eq!(outcome.nodes.len(), 3);
                            assert_eq!(outcome.rules.term_length, input.term_length);
                            assert_eq!(outcome.rules.optimistic_views, input.optimistic_views);
                            assert_eq!(
                                outcome.rules.track_historical_votes,
                                track_historical_votes
                            );
                            assert!(
                                outcome
                                    .nodes
                                    .iter()
                                    .all(|node| node.finalized >= required_containers)
                            );
                            runs += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(runs, 96);
    println!(
        "configuration matrix: {runs} runs, {:?} per input",
        started.elapsed() / runs as u32
    );
}

#[test]
fn evidence_at_016_adversary_sends_only_valid_own_epoch_votes() {
    for outcome in fixed_outcomes() {
        assert!(
            outcome
                .adversary
                .heard
                .iter()
                .all(|heard| (1..=3).contains(&heard.from))
        );
        for sent in &outcome.adversary.sent {
            let vote = decode_ballot(&sent.vote);
            assert_valid_ballot(&outcome.verifier, &vote, 0, sent.view);
            let epoch = match vote {
                Vote::Notarize(vote) => vote.proposal.round.epoch(),
                Vote::Nullify(vote) => vote.round.epoch(),
                Vote::Finalize(vote) => vote.proposal.round.epoch(),
            };
            assert_eq!(epoch, Epoch::new(EPOCH));
        }
    }
}

#[test]
fn evidence_at_017_plans_replay_from_the_runtime_tape() {
    for (input, outcome) in evidence::fixed_corpus().iter().zip(fixed_outcomes()) {
        let mut planned_views = BTreeSet::new();
        for planned in &outcome.adversary.plans {
            assert!(planned_views.insert(planned.view));
            assert!(PairKind::ALL.contains(&planned.plan.kind));
            assert!(planned.plan.delay <= evidence::MAX_DELAY);
            assert_eq!(
                evidence::sample_plan(&mut evidence::stream_at(&input.raw_bytes, planned.drawn_at)),
                planned.plan
            );
            let first_for_view = outcome
                .adversary
                .heard
                .iter()
                .position(|heard| decode_ballot(&heard.vote).view() == planned.view)
                .unwrap();
            assert_eq!(planned.trigger, first_for_view);
        }
    }
}

fn trigger_matches(kind: PairKind, vote: &Ballot) -> bool {
    matches!(
        (kind, vote),
        (PairKind::K1, Vote::Notarize(_))
            | (PairKind::K2 | PairKind::K4, Vote::Finalize(_))
            | (PairKind::K3, Vote::Nullify(_))
    )
}

#[test]
fn evidence_at_018_021_pair_construction_and_trigger_order() {
    let inputs = evidence::fixed_corpus();
    let mut kinds = BTreeMap::<PairKind, u64>::new();
    let mut early = BTreeMap::<PairKind, u64>::new();
    for (input, outcome) in inputs.iter().zip(fixed_outcomes()) {
        for planned in &outcome.adversary.plans {
            let sent: Vec<_> = outcome
                .adversary
                .sent
                .iter()
                .filter(|sent| sent.view == planned.view)
                .collect();
            if planned.plan.kind == PairKind::None {
                assert!(sent.is_empty());
                continue;
            }
            let Some(t1) = outcome
                .adversary
                .heard
                .iter()
                .enumerate()
                .find(|(_, heard)| {
                    let vote = decode_ballot(&heard.vote);
                    vote.view() == planned.view && trigger_matches(planned.plan.kind, &vote)
                })
                .map(|(position, _)| position)
            else {
                assert!(sent.is_empty());
                continue;
            };
            assert!(!sent.is_empty());
            assert!(!sent[0].second);
            assert_eq!(sent[0].trigger, t1);
            let first = decode_ballot(&sent[0].vote);
            let trigger = decode_ballot(&outcome.adversary.heard[t1].vote);
            match (&first, &trigger, planned.plan.kind) {
                (Vote::Notarize(first), Vote::Notarize(trigger), PairKind::K1) => {
                    assert_eq!(first.proposal, trigger.proposal);
                }
                (Vote::Finalize(first), Vote::Finalize(trigger), PairKind::K2 | PairKind::K4) => {
                    assert_eq!(first.proposal, trigger.proposal);
                }
                (Vote::Nullify(first), Vote::Nullify(trigger), PairKind::K3) => {
                    assert_eq!(first.round, trigger.round);
                }
                _ => panic!("wrong first-vote shape for {:?}", planned.plan.kind),
            }

            let threshold = planned.view.get().saturating_add(planned.plan.delay);
            let t2 = outcome
                .adversary
                .heard
                .iter()
                .position(|heard| decode_ballot(&heard.vote).view().get() >= threshold);
            let Some(t2) = t2 else {
                assert_eq!(sent.len(), 1);
                continue;
            };
            assert_eq!(sent.len(), 2);
            assert!(sent[1].second);
            assert_eq!(sent[1].trigger, t1.max(t2));
            if planned.plan.delay > 0 && t2 < t1 {
                *early.entry(planned.plan.kind).or_default() += 1;
                assert_eq!(sent[1].trigger, sent[0].trigger);
            }
            let second = decode_ballot(&sent[1].vote);
            assert_valid_ballot(&outcome.verifier, &first, 0, planned.view);
            assert_valid_ballot(&outcome.verifier, &second, 0, planned.view);
            match (&first, &second, planned.plan.kind) {
                (Vote::Notarize(first), Vote::Notarize(second), PairKind::K1) => {
                    assert_eq!(first.proposal.round, second.proposal.round);
                    assert_eq!(first.proposal.parent, second.proposal.parent);
                    assert_ne!(first.proposal.payload, second.proposal.payload);
                    assert_eq!(
                        second.proposal.payload,
                        evidence::sample_payload(
                            &mut evidence::stream_at(&input.raw_bytes, sent[1].drawn_at.unwrap()),
                            Some(&first.proposal.payload),
                        )
                    );
                }
                (Vote::Finalize(first), Vote::Finalize(second), PairKind::K2) => {
                    assert_eq!(first.proposal.round, second.proposal.round);
                    assert_eq!(first.proposal.parent, second.proposal.parent);
                    assert_ne!(first.proposal.payload, second.proposal.payload);
                    assert_eq!(
                        second.proposal.payload,
                        evidence::sample_payload(
                            &mut evidence::stream_at(&input.raw_bytes, sent[1].drawn_at.unwrap()),
                            Some(&first.proposal.payload),
                        )
                    );
                }
                (Vote::Nullify(first), Vote::Finalize(second), PairKind::K3) => {
                    assert_eq!(first.round, second.proposal.round);
                    assert_eq!(
                        second.proposal.payload,
                        evidence::sample_payload(
                            &mut evidence::stream_at(&input.raw_bytes, sent[1].drawn_at.unwrap()),
                            None,
                        )
                    );
                }
                (Vote::Finalize(first), Vote::Nullify(second), PairKind::K4) => {
                    assert_eq!(first.proposal.round, second.round);
                    assert_eq!(sent[1].drawn_at, None);
                }
                _ => panic!("wrong second-vote shape for {:?}", planned.plan.kind),
            }
            *kinds.entry(planned.plan.kind).or_default() += 1;
        }
    }
    for kind in PairKind::PAIRS {
        assert!(
            kinds.get(&kind).copied().unwrap_or_default() > 0,
            "{kind:?}"
        );
    }
    assert!(early.get(&PairKind::K2).copied().unwrap_or_default() > 0);
    assert!(early.get(&PairKind::K4).copied().unwrap_or_default() > 0);
}

#[test]
fn evidence_at_022_silence_before_triggers_and_honest_progress() {
    let outcome = &fixed_outcomes()[0];
    let planned: BTreeSet<_> = outcome
        .adversary
        .plans
        .iter()
        .map(|plan| plan.plan.kind)
        .collect();
    assert!(
        PairKind::ALL
            .into_iter()
            .all(|kind| planned.contains(&kind))
    );
    assert!(
        outcome
            .adversary
            .plans
            .iter()
            .filter(|plan| plan.plan.kind == PairKind::None)
            .all(|plan| outcome
                .adversary
                .sent
                .iter()
                .all(|sent| sent.view != plan.view))
    );
    assert!(outcome.report.obligations(PairKind::K3) > 0);
    assert!(outcome.nodes.iter().all(|node| node.finalized >= 30));
}

#[test]
fn evidence_at_023_completion_settle_oracles_and_report() {
    reach::reset();
    let input = empty_input();
    let outcome = evidence::run(&input);
    assert!(
        outcome
            .nodes
            .iter()
            .all(|node| node.finalized >= input.required_containers)
    );
    assert_eq!(outcome.measured_at - outcome.finalized_at, evidence::SETTLE);
    assert_eq!(outcome.report, Report::new(&outcome.classified));
    let obligations: u64 = outcome
        .classified
        .iter()
        .map(|node| node.obligations.len() as u64)
        .sum();
    assert_eq!(reach::count(evidence::EXPORT_CHECKED), obligations);
    assert_eq!(reach::count(evidence::FORWARD_CHECKED), obligations);
    assert_eq!(reach::count(evidence::BLOCK_CHECKED), 3);
    assert_eq!(reach::count(evidence::SIGNER_CHECKED), 3);
    assert_eq!(reach::count(evidence::SAFETY_CHECKED), 1);
}

#[test]
fn evidence_at_024_typed_target_and_registration_are_self_contained() {
    let target = include_str!("../fuzz_targets/exp_simplex_ed25519_equivocation_evidence.rs");
    let manifest = include_str!("../Cargo.toml");
    let library = include_str!("../src/lib.rs");
    assert!(target.contains("fuzz_target!(|input: FuzzInput|"));
    assert!(!target.contains("&[u8]"));
    assert!(target.contains("fuzz(input);"));
    assert!(manifest.contains("name = \"exp_simplex_ed25519_equivocation_evidence\""));
    assert!(
        manifest.contains("path = \"fuzz_targets/exp_simplex_ed25519_equivocation_evidence.rs\"")
    );
    assert!(manifest.contains("required-features = [\"base\"]"));
    assert!(library.contains("pub mod evidence;"));
}

#[test]
fn evidence_at_025_026_input_decode_order_bounds_and_defaults() {
    let module = include_str!("../src/evidence.rs");
    assert!(module.contains("impl Arbitrary<'_> for FuzzInput"));
    assert!(module.contains("peek_bytes(u.len().min(MAX_RAW_BYTES))"));
    assert!(module.contains("sample_optimistic_views(u, term_length)"));
    assert!(module.contains("Tape::new(&input.raw_bytes"));

    let empty = empty_input();
    assert_eq!(empty.raw_bytes, Vec::<u8>::new());
    assert_eq!(empty.required_containers, 20);
    assert_eq!(empty.term_length, TermLength::ONE);
    assert_eq!(empty.optimistic_views, ViewDelta::zero());
    assert_eq!(empty.latency_ms, 1);
    assert_eq!(empty.jitter_ms, 0);
    assert!(empty.track_historical_votes);

    for value in 0u8..=7 {
        let input = decode_input(&[0, 0, 0, 0, 0, value]);
        assert_eq!(input.track_historical_votes, value != 7, "{value}");
    }

    let mut prefixes = vec![vec![]];
    for len in 1..=16 {
        prefixes.push(vec![0; len]);
        prefixes.push(vec![0xff; len]);
        prefixes.push((0..len).map(|value| value as u8).collect());
    }
    prefixes.extend((0u8..=u8::MAX).map(|value| vec![value]));
    for bytes in &prefixes {
        assert_eq!(decode_input(bytes), reference_decode(bytes), "{bytes:02x?}");
    }

    let long: Vec<u8> = (0..40_000).map(|value| value as u8).collect();
    let decoded = decode_input(&long);
    assert_eq!(decoded, reference_decode(&long));
    assert_eq!(decoded.raw_bytes, long[..MAX_RAW_BYTES]);
    assert!((20..=40).contains(&decoded.required_containers));
    assert!((1..=u64::from(MAX_TERM_LENGTH)).contains(&decoded.term_length.get()));
    assert!(decoded.optimistic_views.get() <= decoded.term_length.get() + 2);
    assert!((1..=50).contains(&decoded.latency_ms));
    assert!(decoded.jitter_ms <= 50);
}

#[test]
fn evidence_at_027_every_one_and_two_byte_input_decodes() {
    for first in 0u8..=u8::MAX {
        let input = decode_input(&[first]);
        assert!((20..=40).contains(&input.required_containers));
        for second in 0u8..=u8::MAX {
            let input = decode_input(&[first, second]);
            assert!((20..=40).contains(&input.required_containers));
            assert!((1..=u64::from(MAX_TERM_LENGTH)).contains(&input.term_length.get()));
        }
    }
    for len in 3..=16 {
        for input in [
            vec![0; len],
            vec![0xff; len],
            (0..len).map(|value| value as u8).collect(),
        ] {
            assert_eq!(decode_input(&input), reference_decode(&input));
        }
    }
}

#[test]
fn evidence_at_028_empty_input_runs_the_complete_baseline() {
    let input = empty_input();
    let outcome = evidence::run(&input);
    assert_eq!(outcome.participants.len(), 4);
    assert_eq!(outcome.nodes.len(), 3);
    assert!(outcome.nodes.iter().all(|node| node.finalized >= 20));
    assert_eq!(outcome.measured_at - outcome.finalized_at, evidence::SETTLE);
    println!("empty baseline: {}", outcome.report);
    evidence::fuzz(input);
}

#[test]
fn evidence_at_029_short_prefixes_cannot_disable_progress() {
    let prefixes = [
        vec![0x00],
        vec![0xff],
        vec![0x00, 0x00],
        vec![0xff, 0xff],
        vec![0; 3],
        vec![0xff; 4],
        vec![0; 5],
        vec![0xff; 6],
        vec![0; 7],
    ];
    for bytes in prefixes {
        let input = decode_input(&bytes);
        let outcome = evidence::run(&input);
        assert_eq!(outcome.nodes.len(), 3);
        assert!(
            outcome
                .nodes
                .iter()
                .all(|node| node.finalized >= input.required_containers)
        );
    }
}

#[test]
fn evidence_at_030_minifuzz_100_inputs() {
    let started = Instant::now();
    let mut runs = 0u64;
    minifuzz::Builder::default()
        .with_seed(0)
        .with_search_limit(100)
        .test(|u| {
            let input = FuzzInput::arbitrary(u)?;
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| evidence::run(&input)))
                .unwrap_or_else(|payload| {
                    let message = payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| {
                            payload
                                .downcast_ref::<&'static str>()
                                .map(|text| (*text).to_owned())
                        })
                        .unwrap_or_else(|| "<non-string panic>".to_owned());
                    panic!("minifuzz input {input:?}: {message}")
                });
            assert!(
                outcome
                    .nodes
                    .iter()
                    .all(|node| node.finalized >= input.required_containers)
            );
            runs += 1;
            Ok(())
        });
    assert_eq!(runs, 100);
    println!(
        "minifuzz: {runs} runs, {:?} per input",
        started.elapsed() / runs as u32
    );
}

#[test]
fn evidence_at_031_fixed_grid_meets_all_positive_floors() {
    let reports: Vec<_> = fixed_outcomes()
        .iter()
        .map(|outcome| outcome.report.clone())
        .collect();
    evidence::check_floors(&reports).unwrap();
    let sum = Report::sum(&reports);
    for kind in PairKind::PAIRS {
        assert!(sum.obligations(kind) > 0, "{kind:?}");
        assert!(sum.late(kind) > 0, "{kind:?}");
    }
    println!("fixed grid: {sum}");
}

#[test]
fn evidence_at_032_six_picks_are_pinned_to_the_least_index() {
    let reports: Vec<_> = fixed_outcomes()
        .iter()
        .map(|outcome| outcome.report.clone())
        .collect();
    let picks = evidence::picks(&reports).unwrap();
    assert_eq!(picks.by_type.len(), 3);
    assert_eq!(picks.by_node.len(), 3);
    assert!(picks.by_type.values().all(|position| *position == 0));
    assert!(picks.by_node.values().all(|position| *position == 0));
    for evidence_type in EvidenceType::ALL {
        assert_eq!(
            picks.by_type[&evidence_type],
            evidence::pick_type(&reports, evidence_type, evidence::PICK_NODE).unwrap()
        );
    }
    for node in 1..=3 {
        assert_eq!(
            picks.by_node[&node],
            evidence::pick_node(&reports, node).unwrap()
        );
    }
    println!("{picks}");
}

fn assert_planted_failure(plant: Plant, prefix: &str, fragments: &[&str]) {
    let input = evidence::fixed_corpus().into_iter().next().unwrap();
    let text = panic_text(|| {
        evidence::run_planted(&input, Some(plant));
    });
    assert!(text.lines().all(|line| line.starts_with(prefix)), "{text}");
    for fragment in fragments {
        assert!(text.contains(fragment), "missing {fragment:?}: {text}");
    }
}

#[test]
fn evidence_at_033_drop_conflicting_notarize_fires_i1() {
    assert!(fixed_outcomes()[0].report.at(PairKind::K1, 1) > 0);
    assert_planted_failure(
        Plant::DropBeforeRaw {
            node: 1,
            evidence: EvidenceType::ConflictingNotarize,
        },
        "C4-I1",
        &["node 1", "ConflictingNotarize"],
    );
}

#[test]
fn evidence_at_034_drop_conflicting_finalize_fires_i1() {
    assert!(fixed_outcomes()[0].report.at(PairKind::K2, 1) > 0);
    assert_planted_failure(
        Plant::DropBeforeRaw {
            node: 1,
            evidence: EvidenceType::ConflictingFinalize,
        },
        "C4-I1",
        &["node 1", "ConflictingFinalize"],
    );
}

#[test]
fn evidence_at_035_drop_nullify_finalize_fires_i1() {
    assert!(
        fixed_outcomes()[0].report.at(PairKind::K3, 1)
            + fixed_outcomes()[0].report.at(PairKind::K4, 1)
            > 0
    );
    assert_planted_failure(
        Plant::DropBeforeRaw {
            node: 1,
            evidence: EvidenceType::NullifyFinalize,
        },
        "C4-I1",
        &["node 1", "NullifyFinalize"],
    );
}

#[test]
fn evidence_at_036_drop_forwarded_conflicting_notarize_fires_only_i2() {
    assert_planted_failure(
        Plant::DropAfterExport {
            node: 1,
            evidence: EvidenceType::ConflictingNotarize,
        },
        "C4-I2",
        &["node 1", "ConflictingNotarize"],
    );
}

#[test]
fn evidence_at_037_drop_forwarded_conflicting_finalize_fires_only_i2() {
    assert_planted_failure(
        Plant::DropAfterExport {
            node: 1,
            evidence: EvidenceType::ConflictingFinalize,
        },
        "C4-I2",
        &["node 1", "ConflictingFinalize"],
    );
}

#[test]
fn evidence_at_038_drop_forwarded_nullify_finalize_fires_only_i2() {
    assert_planted_failure(
        Plant::DropAfterExport {
            node: 1,
            evidence: EvidenceType::NullifyFinalize,
        },
        "C4-I2",
        &["node 1", "NullifyFinalize"],
    );
}

#[test]
fn evidence_at_039_swallowed_block_at_node_1_fires_i3() {
    assert_planted_failure(Plant::SwallowBlock { node: 1 }, "C4-I3", &["node 1"]);
}

#[test]
fn evidence_at_040_swallowed_block_at_node_2_fires_i3() {
    assert_planted_failure(Plant::SwallowBlock { node: 2 }, "C4-I3", &["node 2"]);
}

#[test]
fn evidence_at_041_swallowed_block_at_node_3_fires_i3() {
    assert_planted_failure(Plant::SwallowBlock { node: 3 }, "C4-I3", &["node 3"]);
}

#[test]
fn evidence_at_042_false_evidence_against_honest_signer_fires_i4() {
    let clean = evidence::run(&empty_input());
    assert!(
        clean
            .nodes
            .iter()
            .flat_map(|node| &node.logs.raw)
            .filter_map(|entry| EvidenceType::of(&entry.activity))
            .all(|(_, signer)| usize::from(signer) == 0)
    );
    assert_planted_failure(
        Plant::FalseEvidence { node: 1, signer: 2 },
        "C4-I4",
        &["signer 2"],
    );
}

#[test]
fn evidence_at_043_zeroed_k4_floor_fires_i5_only() {
    let mut reports: Vec<_> = fixed_outcomes()
        .iter()
        .map(|outcome| outcome.report.clone())
        .collect();
    for report in &mut reports {
        let k4 = report.kinds.get_mut(&PairKind::K4).unwrap();
        k4.obligations.values_mut().for_each(|count| *count = 0);
        k4.late = 0;
    }
    let error = evidence::check_floors(&reports).unwrap_err();
    assert!(error.starts_with("C4-I5 vacuous"), "{error}");
    assert!(error.contains("K4"), "{error}");
}

fn assert_equal_outcomes(left: &evidence::Outcome, right: &evidence::Outcome) {
    assert_eq!(left.report, right.report);
    assert_eq!(left.rules, right.rules);
    assert_eq!(left.participants, right.participants);
    assert_eq!(left.adversary, right.adversary);
    assert_eq!(left.pairs, right.pairs);
    assert_eq!(left.nodes, right.nodes);
    assert_eq!(left.blocked, right.blocked);
    assert_eq!(left.classified, right.classified);
    assert_eq!(left.finalized_at, right.finalized_at);
    assert_eq!(left.measured_at, right.measured_at);
    assert_eq!(left.metrics, right.metrics);
}

#[test]
fn evidence_at_046_replay_is_deterministic() {
    let corpus = evidence::fixed_corpus();
    let empty = empty_input();
    for input in [&empty, &corpus[0], &corpus[99]] {
        let first = evidence::run(input);
        let second = evidence::run(input);
        assert_equal_outcomes(&first, &second);
    }
}

#[test]
fn evidence_at_047_default_mode_is_unmeasured_and_printed() {
    let outcomes = default_outcomes();
    let reports: Vec<_> = outcomes
        .iter()
        .map(|outcome| outcome.report.clone())
        .collect();
    for outcome in outcomes {
        assert!(!outcome.rules.track_historical_votes);
        assert!(
            outcome
                .classified
                .iter()
                .all(|node| { node.obligations.is_empty() && node.unmeasured.is_empty() })
        );
        assert!(outcome.nodes.iter().all(|node| node.finalized >= 30));
    }
    let sum = Report::sum(&reports);
    for kind in PairKind::PAIRS {
        assert_eq!(sum.obligations(kind), 0);
    }
    println!("default grid: {sum}");
}

#[test]
fn evidence_at_048_split_pair_is_unmeasured_at_every_node() {
    let base = built_trace(PairKind::K1);
    let mut logs = Vec::new();
    for node in 1..=3 {
        let mut node_logs = base.logs.clone();
        node_logs.node = node;
        if node <= 2 {
            node_logs
                .tap
                .retain(|entry| entry.bytes != base.pair.second);
        } else {
            node_logs.tap.retain(|entry| entry.bytes != base.pair.first);
            node_logs.raw.retain(|entry| {
                entry.activity != ballot_activity(&decode_ballot(&base.pair.first))
            });
        }
        node_logs
            .raw
            .retain(|entry| entry.activity != base.logs.forwarded[0]);
        node_logs.forwarded.clear();
        logs.push(node_logs);
    }
    let evaluation = evidence::evaluate(
        &base.verifier,
        &base.rules,
        std::slice::from_ref(&base.pair),
        &logs,
        &[],
    );
    assert!(evaluation.violations.is_empty());
    assert!(
        evaluation
            .classified
            .iter()
            .all(|node| node.obligations.is_empty() && node.unmeasured.len() == 1)
    );
    assert_eq!(
        evaluation.classified[0].unmeasured[0].reason,
        Reason::SecondNotTaken
    );
    assert_eq!(
        evaluation.classified[1].unmeasured[0].reason,
        Reason::SecondNotTaken
    );
    assert_eq!(
        evaluation.classified[2].unmeasured[0].reason,
        Reason::FirstNotTaken
    );
}

#[test]
fn evidence_at_056_target_guide_hygiene() {
    let target = include_str!("../fuzz_targets/exp_simplex_ed25519_equivocation_evidence.rs");
    let module = include_str!("../src/evidence.rs");
    let components = include_str!("../../COMPONENTS.md");
    assert!(!target.contains("#[test]"));
    assert!(!target.contains("Unstructured"));
    assert!(target.contains("fuzz(input);"));
    assert!(module.contains("pub fn fuzz(input: FuzzInput)"));
    assert!(module.contains("assert!("));
    assert!(!module.contains("CR-"));
    assert!(components.contains("### C10. Equivocation evidence"));
}

#[test]
fn evidence_at_057_cost_and_gauge_read_evidence() {
    let input = empty_input();
    let started = Instant::now();
    let outcome = evidence::run(&input);
    let elapsed = started.elapsed();
    for node in &outcome.nodes {
        assert_eq!(node.gauge_reads as usize, node.logs.tap.len());
        assert!(node.gauge_reads > 0);
    }
    println!("empty input host time: {elapsed:?}");
}

fn obligation_and_raw(kind: PairKind) -> (Obligation, Vec<Recorded>) {
    let trace = built_trace(kind);
    let obligation = classify(&trace).obligations.remove(0);
    (obligation, trace.logs.raw)
}

#[test]
fn evidence_at_058_i1_requires_exact_evidence_inside_sequence_bounds() {
    let (obligation, raw) = obligation_and_raw(PairKind::K1);
    evidence::check_exported(&obligation, &raw).unwrap();

    let wrong_type = built_trace(PairKind::K2).logs.forwarded[0].clone();
    let fixture = fixture(b"consensus-c4-acceptance");
    let foreign = built_trace_with(
        PairKind::K1,
        8,
        8,
        1,
        &fixture.schemes[1],
        fixture.verifier.clone(),
    )
    .logs
    .forwarded[0]
        .clone();
    let wrong_view = built_trace_with(
        PairKind::K1,
        9,
        9,
        1,
        &fixture.schemes[0],
        fixture.verifier.clone(),
    )
    .logs
    .forwarded[0]
        .clone();
    for activity in [wrong_type, foreign, wrong_view] {
        let changed = vec![Recorded { seq: 4, activity }];
        let error = evidence::check_exported(&obligation, &changed).unwrap_err();
        assert!(error.starts_with("C4-I1"), "{error}");
    }

    for sequence in [obligation.second_seq, obligation.next_seq.unwrap()] {
        let changed = vec![Recorded {
            seq: sequence,
            activity: obligation.evidence.clone(),
        }];
        let error = evidence::check_exported(&obligation, &changed).unwrap_err();
        assert!(error.starts_with("C4-I1"), "{error}");
    }

    let original = built_trace(PairKind::K1);
    let first = decode_ballot(&original.pair.first);
    let second = decode_ballot(&original.pair.second);
    let alternative_first =
        Vote::Notarize(Notarize::sign(&fixture.schemes[0], proposal(8, 3)).unwrap());
    let alternative_second =
        Vote::Notarize(Notarize::sign(&fixture.schemes[0], proposal(8, 4)).unwrap());
    for activity in [
        fault_activity(PairKind::K1, &alternative_first, &second),
        fault_activity(PairKind::K1, &first, &alternative_second),
    ] {
        let changed = vec![Recorded { seq: 4, activity }];
        let error = evidence::check_exported(&obligation, &changed).unwrap_err();
        assert!(error.starts_with("C4-I1"), "{error}");
    }
}

#[test]
fn evidence_at_059_i2_requires_forwarded_activity_equality() {
    let trace = built_trace(PairKind::K2);
    let obligation = classify(&trace).obligations.remove(0);
    evidence::check_exported(&obligation, &trace.logs.raw).unwrap();
    evidence::check_forwarded(&obligation, &trace.logs.forwarded).unwrap();

    let fixture = fixture(b"consensus-c4-acceptance");
    let mut variants = vec![
        built_trace(PairKind::K1).logs.forwarded[0].clone(),
        built_trace_with(
            PairKind::K2,
            8,
            8,
            1,
            &fixture.schemes[1],
            fixture.verifier.clone(),
        )
        .logs
        .forwarded[0]
            .clone(),
        built_trace_with(PairKind::K2, 9, 9, 1, &fixture.schemes[0], fixture.verifier)
            .logs
            .forwarded[0]
            .clone(),
    ];
    let first = decode_ballot(&trace.pair.first);
    let second = decode_ballot(&trace.pair.second);
    let alternative_first =
        Vote::Finalize(Finalize::sign(&fixture.schemes[0], proposal(8, 3)).unwrap());
    let alternative_second =
        Vote::Finalize(Finalize::sign(&fixture.schemes[0], proposal(8, 4)).unwrap());
    variants.extend([
        fault_activity(PairKind::K2, &alternative_first, &second),
        fault_activity(PairKind::K2, &first, &alternative_second),
    ]);
    for forwarded in variants
        .into_iter()
        .map(|activity| vec![activity])
        .chain([vec![]])
    {
        let error = evidence::check_forwarded(&obligation, &forwarded).unwrap_err();
        assert!(error.starts_with("C4-I2"), "{error}");
        evidence::check_exported(&obligation, &trace.logs.raw).unwrap();
    }
}

fn is_late_phase(kind: PairKind, view: View, activity: &Exported) -> bool {
    activity.view() == view
        && matches!(
            (kind, activity),
            (PairKind::K1, Activity::Notarization(_))
                | (PairKind::K2 | PairKind::K4, Activity::Finalization(_))
                | (PairKind::K3, Activity::Nullification(_))
        )
}

#[test]
fn evidence_at_060_late_classification_uses_the_exact_prior_certificate() {
    let outcome = &fixed_outcomes()[0];
    for kind in PairKind::PAIRS {
        let (classified, obligation) = outcome
            .classified
            .iter()
            .find_map(|classified| {
                classified
                    .obligations
                    .iter()
                    .find(|obligation| obligation.kind == kind && obligation.late)
                    .map(|obligation| (classified, obligation))
            })
            .expect("input zero has a late obligation of every kind");
        let raw = &outcome
            .nodes
            .iter()
            .find(|node| node.logs.node == classified.node)
            .unwrap()
            .logs
            .raw;
        assert!(evidence::late(
            kind,
            obligation.view,
            obligation.second_seq,
            raw
        ));

        let without: Vec<_> = raw
            .iter()
            .filter(|entry| !is_late_phase(kind, obligation.view, &entry.activity))
            .cloned()
            .collect();
        assert!(!evidence::late(
            kind,
            obligation.view,
            obligation.second_seq,
            &without
        ));

        let exact = raw
            .iter()
            .find(|entry| is_late_phase(kind, obligation.view, &entry.activity))
            .unwrap();
        let mut at_boundary = without.clone();
        at_boundary.push(Recorded {
            seq: obligation.second_seq,
            activity: exact.activity.clone(),
        });
        assert!(!evidence::late(
            kind,
            obligation.view,
            obligation.second_seq,
            &at_boundary
        ));

        let mut wrong = without;
        wrong.push(Recorded {
            seq: obligation.second_seq.saturating_sub(1),
            activity: ballot_activity(&decode_ballot(
                outcome
                    .pairs
                    .iter()
                    .find(|pair| pair.kind == kind && pair.view == obligation.view)
                    .unwrap()
                    .first
                    .as_slice(),
            )),
        });
        assert!(!evidence::late(
            kind,
            obligation.view,
            obligation.second_seq,
            &wrong
        ));
        assert!(obligation.late);
    }
}

#[test]
fn evidence_at_061_i4_checks_raw_and_forwarded_logs() {
    let clean = built_trace(PairKind::K1);
    evidence::check_honest_signers(&clean.logs, 0).unwrap();

    let fixture = fixture(b"consensus-c4-acceptance");
    let honest = built_trace_with(PairKind::K1, 8, 8, 1, &fixture.schemes[2], fixture.verifier)
        .logs
        .forwarded[0]
        .clone();
    let mut raw_only = clean.logs.clone();
    raw_only.raw.push(Recorded {
        seq: 5,
        activity: honest.clone(),
    });
    let error = evidence::check_honest_signers(&raw_only, 0).unwrap_err();
    assert!(error.starts_with("C4-I4"), "{error}");
    assert!(error.contains("signer 2"), "{error}");

    let mut forwarded_only = clean.logs;
    forwarded_only.forwarded.push(honest);
    let error = evidence::check_honest_signers(&forwarded_only, 0).unwrap_err();
    assert!(error.starts_with("C4-I4"), "{error}");
    assert!(error.contains("signer 2"), "{error}");
}
