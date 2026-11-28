use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{
    simplex::{
        elector::{Config as ElectorConfig, Elector as _, RoundRobin},
        scheme::secp256r1,
        types::{Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal},
    },
    types::{Attributable as _, Epoch, Participant, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    CertifyChoice, EPOCH, NAMESPACE, ReporterWiring,
    simplex::{Simplex, SimplexSecp256r1},
};
use commonware_consensus_fuzz_simplex::proposal_switch::{
    CANONICAL_STEPS, CERTIFICATE_CHANNEL, Checked, Checks, FuzzInput, MAX_EXTRA_STEPS, MAX_GAP_MS,
    MAX_RAW_BYTES, MAX_VIEW, Message, MessageKind, Observation, Observed, Op, Options,
    PARTICIPANTS, PAYLOADS, PLANTED_PROPOSAL, PROPOSALS, Plant, RESOLVER_CHANNEL, Report, Roles,
    SCRIPTED, SETTLE_MS, Step, VOTE_CHANNEL, assert_floor, fuzz, prop, run, run_observed,
};
use commonware_cryptography::{
    certificate::{Scheme as _, mocks::Fixture},
    ed25519::PublicKey,
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, deterministic};
use commonware_utils::{
    FuzzRng, TestRng, TryCollect as _, non_empty,
    ordered::{Quorum as _, Set},
};
use rand_core::Rng as _;
use std::{
    collections::BTreeSet,
    panic::{self, AssertUnwindSafe},
    sync::OnceLock,
    time::Duration,
};

const FIXED_SEEDS: u64 = 10;
const RANDOM_VECTORS: usize = 1_000;
const EXPECTED_CORPUS: usize = 67_468;
const CORPUS_SHARDS: usize = 16;
const OLD_VOTE_ENV: &str = "PROPOSAL_SWITCH_EXPECT_OLD_VOTE";
const OUTBOUND_LABEL: &str = "outbound certificate invalid:";
const REPORTED_LABEL: &str = "reported invalid certificates:";
const VACUOUS_LABEL: &str = "proposal switch vacuous:";

type Scheme = secp256r1::Scheme<PublicKey>;

fn fixture() -> &'static Fixture<Scheme> {
    static FIXTURE: OnceLock<Fixture<Scheme>> = OnceLock::new();
    FIXTURE.get_or_init(|| secp256r1::fixture(&mut TestRng::new(7), NAMESPACE, 4))
}

fn roles() -> Roles {
    Roles::new(&fixture().participants)
}

fn decode(bytes: &[u8]) -> FuzzInput {
    FuzzInput::arbitrary(&mut Unstructured::new(bytes)).expect("every byte string must decode")
}

fn reference_decode(bytes: &[u8]) -> FuzzInput {
    let mut u = Unstructured::new(bytes);
    let extra = u
        .int_in_range(0..=MAX_EXTRA_STEPS)
        .expect("the extra count has an exhausted-input value");
    let mut steps = Vec::with_capacity(CANONICAL_STEPS + extra);
    for _ in 0..CANONICAL_STEPS + extra {
        let op = Op::ALL[u
            .int_in_range(0..=Op::ALL.len() - 1)
            .expect("the operation has an exhausted-input value")];
        let view = u
            .int_in_range(1..=MAX_VIEW)
            .expect("the view has an exhausted-input value");
        let s = u
            .int_in_range(0..=SCRIPTED - 1)
            .expect("the signer has an exhausted-input value");
        let p = u
            .int_in_range(0..=PROPOSALS - 1)
            .expect("the proposal has an exhausted-input value");
        let gap_ms = MAX_GAP_MS
            - u.int_in_range(0..=MAX_GAP_MS)
                .expect("the gap has an exhausted-input value");
        steps.push(Step {
            op,
            view,
            s,
            p,
            gap_ms,
        });
    }
    FuzzInput {
        raw_bytes: bytes[..bytes.len().min(MAX_RAW_BYTES)].to_vec(),
        steps,
    }
}

fn payload(p: usize) -> [u8; 32] {
    match p {
        0 => [1; 32],
        1 => [2; 32],
        2 => [3; 32],
        _ => panic!("unknown proposal"),
    }
}

fn round(view: u64) -> Round {
    Round::new(Epoch::new(EPOCH), View::new(view))
}

fn proposal(view: u64, p: usize) -> Proposal<Digest> {
    Proposal::new(round(view), View::new(view - 1), Digest::from(payload(p)))
}

fn independent_message(kind: MessageKind, vote_signer: usize, view: u64, p: usize) -> Message {
    let fixture = fixture();
    let mut rng = TestRng::new(0);
    match kind {
        MessageKind::Notarize => {
            let vote = Notarize::sign(&fixture.schemes[vote_signer], proposal(view, p))
                .expect("a fixture participant signs");
            assert_eq!(usize::from(vote.signer()), vote_signer);
            assert!(vote.verify(&mut rng, &fixture.schemes[vote_signer], &Sequential));
            Message {
                kind,
                epoch: EPOCH,
                view,
                parent: Some(view - 1),
                digest: Some(payload(p)),
                signers: vec![vote_signer],
            }
        }
        MessageKind::Finalize => {
            let vote = Finalize::sign(&fixture.schemes[vote_signer], proposal(view, p))
                .expect("a fixture participant signs");
            assert_eq!(usize::from(vote.signer()), vote_signer);
            assert!(vote.verify(&mut rng, &fixture.schemes[vote_signer], &Sequential));
            Message {
                kind,
                epoch: EPOCH,
                view,
                parent: Some(view - 1),
                digest: Some(payload(p)),
                signers: vec![vote_signer],
            }
        }
        MessageKind::Nullify => {
            let vote = Nullify::sign::<Digest>(&fixture.schemes[vote_signer], round(view))
                .expect("a fixture participant signs");
            assert_eq!(usize::from(vote.signer()), vote_signer);
            assert!(vote.verify::<_, Digest>(&mut rng, &fixture.schemes[vote_signer], &Sequential));
            Message {
                kind,
                epoch: EPOCH,
                view,
                parent: None,
                digest: None,
                signers: vec![vote_signer],
            }
        }
        MessageKind::Notarization | MessageKind::Finalization | MessageKind::Nullification => {
            let scripted = roles().scripted;
            let signers: BTreeSet<_> = scripted.into_iter().collect();
            assert_eq!(signers.len(), SCRIPTED);
            match kind {
                MessageKind::Notarization => {
                    let votes: Vec<_> = scripted
                        .into_iter()
                        .map(|signer| {
                            Notarize::sign(&fixture.schemes[signer], proposal(view, p))
                                .expect("a fixture participant signs")
                        })
                        .collect();
                    for (vote, signer) in votes.iter().zip(scripted) {
                        assert_eq!(usize::from(vote.signer()), signer);
                        assert!(vote.verify(&mut rng, &fixture.schemes[signer], &Sequential));
                    }
                    let certificate = Notarization::from_notarizes(
                        &fixture.schemes[scripted[0]],
                        non_empty![@votes.iter()],
                        &Sequential,
                    )
                    .expect("three votes assemble");
                    assert!(certificate.verify(
                        &mut rng,
                        &fixture.schemes[scripted[0]],
                        &Sequential
                    ));
                }
                MessageKind::Finalization => {
                    let votes: Vec<_> = scripted
                        .into_iter()
                        .map(|signer| {
                            Finalize::sign(&fixture.schemes[signer], proposal(view, p))
                                .expect("a fixture participant signs")
                        })
                        .collect();
                    for (vote, signer) in votes.iter().zip(scripted) {
                        assert_eq!(usize::from(vote.signer()), signer);
                        assert!(vote.verify(&mut rng, &fixture.schemes[signer], &Sequential));
                    }
                    let certificate = Finalization::from_finalizes(
                        &fixture.schemes[scripted[0]],
                        non_empty![@votes.iter()],
                        &Sequential,
                    )
                    .expect("three votes assemble");
                    assert!(certificate.verify(
                        &mut rng,
                        &fixture.schemes[scripted[0]],
                        &Sequential
                    ));
                }
                MessageKind::Nullification => {
                    let votes: Vec<_> = scripted
                        .into_iter()
                        .map(|signer| {
                            Nullify::sign::<Digest>(&fixture.schemes[signer], round(view))
                                .expect("a fixture participant signs")
                        })
                        .collect();
                    for (vote, signer) in votes.iter().zip(scripted) {
                        assert_eq!(usize::from(vote.signer()), signer);
                        assert!(vote.verify::<_, Digest>(
                            &mut rng,
                            &fixture.schemes[signer],
                            &Sequential
                        ));
                    }
                    let certificate = Nullification::from_nullifies(
                        &fixture.schemes[scripted[0]],
                        non_empty![@votes.iter()],
                        &Sequential,
                    )
                    .expect("three votes assemble");
                    assert!(certificate.verify::<_, Digest>(
                        &mut rng,
                        &fixture.schemes[scripted[0]],
                        &Sequential
                    ));
                }
                _ => unreachable!(),
            }
            Message {
                kind,
                epoch: EPOCH,
                view,
                parent: (kind != MessageKind::Nullification).then_some(view - 1),
                digest: (kind != MessageKind::Nullification).then_some(payload(p)),
                signers: scripted.to_vec(),
            }
        }
    }
}

fn expected_outbound(position: usize, step: &Step) -> Option<(usize, u64, Message)> {
    let roles = roles();
    let leader = roles.leaders[0];
    let x = roles.scripted[roles.x];
    let y = roles.scripted[roles.y];
    let by = roles.scripted[step.s];
    let (sender, channel, kind, signer, view, p) = match step.op {
        Op::Canonical => match position {
            0 => (leader, VOTE_CHANNEL, MessageKind::Notarize, leader, 1, 0),
            1 => (leader, VOTE_CHANNEL, MessageKind::Finalize, leader, 1, 0),
            2 => (x, CERTIFICATE_CHANNEL, MessageKind::Notarization, x, 1, 1),
            3 => (x, VOTE_CHANNEL, MessageKind::Finalize, x, 1, 1),
            4 => (y, VOTE_CHANNEL, MessageKind::Finalize, y, 1, 1),
            _ => return None,
        },
        Op::LeaderNotarize => {
            let signer = roles.leaders[(step.view - 1) as usize];
            (
                signer,
                VOTE_CHANNEL,
                MessageKind::Notarize,
                signer,
                step.view,
                step.p,
            )
        }
        Op::Notarize => (
            by,
            VOTE_CHANNEL,
            MessageKind::Notarize,
            by,
            step.view,
            step.p,
        ),
        Op::Finalize => (
            by,
            VOTE_CHANNEL,
            MessageKind::Finalize,
            by,
            step.view,
            step.p,
        ),
        Op::Nullify => (
            by,
            VOTE_CHANNEL,
            MessageKind::Nullify,
            by,
            step.view,
            step.p,
        ),
        Op::Notarization => (
            by,
            CERTIFICATE_CHANNEL,
            MessageKind::Notarization,
            by,
            step.view,
            step.p,
        ),
        Op::Finalization => (
            by,
            CERTIFICATE_CHANNEL,
            MessageKind::Finalization,
            by,
            step.view,
            step.p,
        ),
        Op::Nullification => (
            by,
            CERTIFICATE_CHANNEL,
            MessageKind::Nullification,
            by,
            step.view,
            step.p,
        ),
    };
    Some((sender, channel, independent_message(kind, signer, view, p)))
}

fn with_gap(step: Step, gap_ms: u64) -> Step {
    Step { gap_ms, ..step }
}

fn fixed_input(shape: usize, seed: u64) -> FuzzInput {
    let roles = roles();
    let l1 = roles.position(roles.leaders[0]);
    let steps = match shape {
        1 => vec![Step::canonical(); CANONICAL_STEPS],
        2 => vec![
            Step::canonical(),
            Step::canonical(),
            Step::new(Op::Finalization, 1, roles.x, 1),
            Step::new(Op::Notarize, 1, roles.x, 1),
            Step::new(Op::Notarize, 1, roles.y, 1),
        ],
        3 => vec![
            Step::new(Op::Notarize, 1, l1, 0),
            Step::new(Op::Notarization, 1, roles.x, 1),
            Step::new(Op::Finalize, 1, l1, 0),
            Step::new(Op::Finalize, 1, roles.x, 1),
            Step::new(Op::Finalize, 1, roles.y, 1),
        ],
        4 => vec![
            Step::new(Op::LeaderNotarize, 1, 0, 1),
            Step::new(Op::Notarize, 1, roles.x, 1),
            Step::new(Op::Notarize, 1, roles.y, 1),
            Step::new(Op::Finalize, 1, l1, 1),
            Step::new(Op::Finalize, 1, roles.x, 1),
            Step::new(Op::Finalize, 1, roles.y, 1),
        ],
        _ => panic!("unknown fixed shape"),
    };
    FuzzInput::from_steps(seed, steps)
}

fn payload_text(payload: Box<dyn std::any::Any + Send>) -> String {
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

fn panic_text(f: impl FnOnce()) -> String {
    let payload = panic::catch_unwind(AssertUnwindSafe(f)).expect_err("the control must panic");
    payload_text(payload)
}

fn old_vote_planted() -> bool {
    std::env::var_os(OLD_VOTE_ENV).is_some()
}

fn matching(events: &[Observed], predicate: impl Fn(&Observation) -> bool) -> Vec<&Observed> {
    events
        .iter()
        .filter(|event| predicate(&event.what))
        .collect()
}

fn one_engine_start(events: &[Observed]) -> (usize, Duration) {
    let started = matching(events, |event| {
        matches!(event, Observation::EngineStarted { .. })
    });
    assert_eq!(started.len(), 1);
    let Observation::EngineStarted { participant, .. } = started[0].what else {
        unreachable!();
    };
    (participant, started[0].at)
}

fn assert_trace(input: &FuzzInput, report: &Report, events: &[Observed]) {
    let (victim, started_at) = one_engine_start(events);
    assert_eq!(victim, report.victim);
    assert_eq!(report.sent.len(), input.steps.len());
    let sent = matching(events, |event| matches!(event, Observation::Sent { .. }));
    assert_eq!(sent.len(), input.steps.len());
    let mut due = 0;
    for (position, step) in input.steps.iter().enumerate() {
        due += step.gap_ms;
        assert_eq!(
            report.sent[position],
            (due, step.op, step.view, step.s, step.p)
        );
        assert_eq!(sent[position].at, started_at + Duration::from_millis(due));
        let Observation::Sent {
            step: observed_step,
            op,
            sender,
            recipient,
            channel,
            message,
        } = &sent[position].what
        else {
            unreachable!();
        };
        assert_eq!(*observed_step, position);
        assert_eq!(*op, step.op);
        if let Some((expected_sender, expected_channel, expected_message)) =
            expected_outbound(position, step)
        {
            assert_eq!(*sender, Some(expected_sender));
            assert_eq!(*recipient, Some(report.victim));
            assert_eq!(*channel, Some(expected_channel));
            assert_eq!(message.as_ref(), Some(&expected_message));
        } else {
            assert_eq!(*sender, None);
            assert_eq!(*recipient, None);
            assert_eq!(*channel, None);
            assert_eq!(message, &None);
        }
    }

    let received = matching(events, |event| {
        matches!(
            event,
            Observation::Received {
                channel: CERTIFICATE_CHANNEL,
                ..
            }
        )
    });
    assert_eq!(received.len(), report.checked.len());
    for (event, checked) in received.into_iter().zip(&report.checked) {
        let Observation::Received {
            receiver,
            from,
            channel,
        } = event.what
        else {
            unreachable!();
        };
        assert_eq!(channel, CERTIFICATE_CHANNEL);
        assert_eq!(from, report.victim);
        assert_eq!(receiver, checked.receiver);
        assert_eq!(event.at, started_at + Duration::from_millis(checked.at_ms));
    }
}

fn assert_end_check(report: &Report, events: &[Observed]) {
    let end = matching(events, |event| {
        matches!(event, Observation::EndCheck { .. })
    });
    assert_eq!(end.len(), 1);
    let Observation::EndCheck {
        invalid_certificates,
    } = end[0].what
    else {
        unreachable!();
    };
    assert_eq!(invalid_certificates, report.invalid_certificates);
    let sent = matching(events, |event| matches!(event, Observation::Sent { .. }));
    let last_sent = sent.last().expect("a scenario sends steps");
    assert_eq!(end[0].at, last_sent.at + Duration::from_millis(SETTLE_MS));
    let completed = matching(events, |event| matches!(event, Observation::Completed));
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].at, end[0].at);
}

fn assert_consistent(input: &FuzzInput, report: &Report, events: &[Observed]) {
    assert_trace(input, report, events);
    assert_end_check(report, events);
    assert!(report.checked.iter().all(|checked| checked.valid));
    assert_eq!(report.invalid_certificates, 0);
    let roles = roles();
    assert_eq!(report.victim, roles.victim);
    assert_eq!(report.leaders, roles.leaders);
}

fn full_prefix() -> Vec<u8> {
    let fields = 1 + (CANONICAL_STEPS + MAX_EXTRA_STEPS) * 5;
    (0..=u8::MAX)
        .map(|byte| vec![byte; fields])
        .find(|bytes| reference_decode(bytes).steps.len() == CANONICAL_STEPS + MAX_EXTRA_STEPS)
        .expect("one first-byte value selects the maximum step count")
}

fn decode_corpus() -> Vec<Vec<u8>> {
    let mut corpus = Vec::new();
    corpus.push(Vec::new());
    for first in 0..=u8::MAX {
        corpus.push(vec![first]);
        for second in 0..=u8::MAX {
            corpus.push(vec![first, second]);
        }
    }
    for len in 1..=256 {
        corpus.push(vec![0; len]);
        corpus.push(vec![u8::MAX; len]);
    }
    let prefix = full_prefix();
    corpus.extend((0..=prefix.len()).map(|end| prefix[..end].to_vec()));
    let mut rng = TestRng::new(0x5eed);
    for case in 0..RANDOM_VECTORS {
        let len = case % 257;
        let mut bytes = vec![0; len];
        rng.fill_bytes(&mut bytes);
        corpus.push(bytes);
    }
    corpus.push(vec![0xa5; MAX_RAW_BYTES + 1]);
    corpus
}

fn assert_decode_bounds(bytes: &[u8]) {
    let input = decode(bytes);
    assert_eq!(input, reference_decode(bytes));
    assert_eq!(input.raw_bytes, bytes[..bytes.len().min(MAX_RAW_BYTES)]);
    assert!((CANONICAL_STEPS..=CANONICAL_STEPS + MAX_EXTRA_STEPS).contains(&input.steps.len()));
    for step in input.steps {
        assert!(Op::ALL.contains(&step.op));
        assert!((1..=MAX_VIEW).contains(&step.view));
        assert!(step.s < SCRIPTED);
        assert!(step.p < PROPOSALS);
        assert!(step.gap_ms <= MAX_GAP_MS);
    }
}

fn assert_baseline(input: FuzzInput) {
    assert!(input.steps.len() >= CANONICAL_STEPS);
    let expected_steps = input.steps.len();
    let (report, events) = run_observed(&input, Options::default());
    assert_eq!(report.sent.len(), expected_steps);
    let sent = matching(&events, |event| matches!(event, Observation::Sent { .. }));
    assert_eq!(sent.len(), expected_steps);
    for (position, event) in sent.into_iter().enumerate() {
        let Observation::Sent { step, .. } = event.what else {
            unreachable!();
        };
        assert_eq!(step, position);
    }
    let (victim, _) = one_engine_start(&events);
    assert_eq!(victim, report.victim);
    assert!(report.checked.iter().all(|checked| checked.valid));
    assert_eq!(report.invalid_certificates, 0);
    assert_end_check(&report, &events);
    assert!(!events.iter().any(|event| matches!(
        event.what,
        Observation::Planted(_) | Observation::ResolverProbe { .. }
    )));
}

fn run_baseline_shard(shard: usize) {
    let mut runs = 0;
    for (index, bytes) in decode_corpus().into_iter().enumerate() {
        if index % CORPUS_SHARDS == shard {
            assert_baseline(decode(&bytes));
            runs += 1;
        }
    }
    assert!(runs > 0);
    println!("baseline shard {shard}: {runs} inputs");
}

macro_rules! baseline_shard {
    ($name:ident, $shard:expr) => {
        #[test]
        fn $name() {
            run_baseline_shard($shard);
        }
    };
}

baseline_shard!(proposal_switch_baseline_corpus_00, 0);
baseline_shard!(proposal_switch_baseline_corpus_01, 1);
baseline_shard!(proposal_switch_baseline_corpus_02, 2);
baseline_shard!(proposal_switch_baseline_corpus_03, 3);
baseline_shard!(proposal_switch_baseline_corpus_04, 4);
baseline_shard!(proposal_switch_baseline_corpus_05, 5);
baseline_shard!(proposal_switch_baseline_corpus_06, 6);
baseline_shard!(proposal_switch_baseline_corpus_07, 7);
baseline_shard!(proposal_switch_baseline_corpus_08, 8);
baseline_shard!(proposal_switch_baseline_corpus_09, 9);
baseline_shard!(proposal_switch_baseline_corpus_10, 10);
baseline_shard!(proposal_switch_baseline_corpus_11, 11);
baseline_shard!(proposal_switch_baseline_corpus_12, 12);
baseline_shard!(proposal_switch_baseline_corpus_13, 13);
baseline_shard!(proposal_switch_baseline_corpus_14, 14);
baseline_shard!(proposal_switch_baseline_corpus_15, 15);

#[test]
fn proposal_switch_public_entry_and_panic_propagation() {
    let input = fixed_input(1, 0);
    let first = run(&input);
    let second = run(&input);
    assert_eq!(first, second);
    fuzz(input);

    let text = panic_text(|| {
        run_observed(
            &fixed_input(4, 0),
            Options {
                plant: Plant::RewriteFirstFinalization,
                ..Options::default()
            },
        );
    });
    assert!(text.starts_with(OUTBOUND_LABEL), "{text}");
}

#[test]
fn proposal_switch_production_scheme_and_independent_election() {
    assert_eq!(
        std::any::TypeId::of::<<SimplexSecp256r1 as Simplex>::Scheme>(),
        std::any::TypeId::of::<Scheme>()
    );
    assert_eq!(
        std::any::TypeId::of::<<SimplexSecp256r1 as Simplex>::Elector>(),
        std::any::TypeId::of::<RoundRobin>()
    );
    assert!(!<Scheme as commonware_cryptography::certificate::Verifier>::is_batchable());
    assert_eq!(
        SimplexSecp256r1::effective_term_length(TermLength::ONE),
        TermLength::ONE
    );

    let elected =
        deterministic::Runner::new(deterministic::Config::new().with_rng(FuzzRng::new(vec![0])))
            .start(|mut context| async move {
                let (participants, schemes) =
                    SimplexSecp256r1::setup(&mut context, NAMESPACE, PARTICIPANTS as u32);
                assert_eq!(participants.len(), PARTICIPANTS);
                assert_eq!(schemes.len(), PARTICIPANTS);
                let set: Set<_> = participants
                    .iter()
                    .cloned()
                    .try_collect()
                    .expect("participant keys are unique");
                let elector: <<SimplexSecp256r1 as Simplex>::Elector as ElectorConfig<
                    Scheme,
                >>::Elector = <SimplexSecp256r1 as Simplex>::elector(
                    TermLength::ONE,
                    ViewDelta::zero(),
                )
                .build(&set);
                assert_eq!(elector.terms().length(), TermLength::ONE);
                assert_eq!(elector.terms().optimistic_views(), ViewDelta::zero());
                for (index, scheme) in schemes.iter().enumerate() {
                    assert_eq!(
                        scheme.me().map(|membership| membership.index()),
                        Some(Participant::from_usize(index))
                    );
                    assert_eq!(
                        scheme.participants().key(Participant::from_usize(index)),
                        Some(&participants[index])
                    );
                }
                [1, 2].map(|view| {
                    let leader = elector.elect(round(view), ());
                    participants
                        .iter()
                        .position(|key| {
                            key == set.key(leader).expect("the leader is a participant")
                        })
                        .expect("the leader has a fixture index")
                })
            });
    assert_eq!(elected, [2, 3]);

    let (report, events) = run_observed(&fixed_input(4, 0), Options::default());
    assert_eq!(report.leaders, elected);
    assert_floor(&report, 1, payload(1));
    assert_consistent(&fixed_input(4, 0), &report, &events);
}

#[test]
fn proposal_switch_committee_network_and_resolver_wiring() {
    for shape in [1, 4] {
        let (report, events) = run_observed(
            &fixed_input(shape, 0),
            Options {
                resolver_probe: true,
                ..Options::default()
            },
        );
        let committee = matching(&events, |event| {
            matches!(event, Observation::Committee { .. })
        });
        assert_eq!(committee.len(), 1);
        let Observation::Committee {
            participants,
            roles,
        } = committee[0].what
        else {
            unreachable!();
        };
        assert_eq!(participants, PARTICIPANTS);
        assert_eq!(roles.victim, report.victim);
        assert_eq!(roles.leaders, report.leaders);
        assert_eq!(roles.victim, 0);
        assert_eq!(roles.leaders, [2, 3]);
        assert_eq!(roles.scripted, [1, 2, 3]);
        assert_eq!(roles.scripted[roles.x], 1);
        assert_eq!(roles.scripted[roles.y], 3);
        let expected_scripted: Vec<_> = (0..PARTICIPANTS)
            .filter(|index| *index != roles.victim)
            .collect();
        assert_eq!(roles.scripted, expected_scripted.as_slice());

        let (engine, _) = one_engine_start(&events);
        assert_eq!(engine, roles.victim);
        let started = matching(&events, |event| {
            matches!(event, Observation::EngineStarted { .. })
        });
        let Observation::EngineStarted {
            reporter,
            wiring,
            certify,
            leader_timeout,
            certification_timeout,
            ..
        } = started[0].what
        else {
            unreachable!();
        };
        assert_eq!(reporter, "ChaosReporter");
        assert_eq!(wiring, ReporterWiring::Solo);
        assert_eq!(certify, CertifyChoice::Always);
        assert_eq!(leader_timeout, Duration::from_secs(1));
        assert_eq!(certification_timeout, Duration::from_secs(2));

        let network = matching(&events, |event| {
            matches!(event, Observation::Network { .. })
        });
        assert_eq!(network.len(), 1);
        let Observation::Network {
            configuration,
            connected,
            degraded,
        } = network[0].what
        else {
            unreachable!();
        };
        assert_eq!(configuration, (4, 0, 4));
        assert!(connected);
        assert!(!degraded);

        let registrations = matching(&events, |event| {
            matches!(event, Observation::Registered { .. })
        });
        assert_eq!(registrations.len(), PARTICIPANTS);
        for (index, registration) in registrations.into_iter().enumerate() {
            let Observation::Registered {
                participant,
                channels,
            } = &registration.what
            else {
                unreachable!();
            };
            assert_eq!(*participant, index);
            assert_eq!(
                channels,
                &[VOTE_CHANNEL, CERTIFICATE_CHANNEL, RESOLVER_CHANNEL]
            );
        }

        let probes = matching(&events, |event| {
            matches!(event, Observation::ResolverProbe { .. })
        });
        assert_eq!(probes.len(), SCRIPTED);
        let probe_targets: BTreeSet<_> = probes
            .into_iter()
            .map(|event| {
                let Observation::ResolverProbe { to } = event.what else {
                    unreachable!();
                };
                to
            })
            .collect();
        assert_eq!(probe_targets, roles.scripted.into_iter().collect());
        for participant in roles.scripted {
            assert!(events.iter().any(|event| matches!(
                event.what,
                Observation::Received {
                    receiver,
                    channel: RESOLVER_CHANNEL,
                    from,
                } if receiver == participant && from == roles.victim
            )));
        }
        assert!(!events.iter().any(|event| matches!(
            event.what,
            Observation::Sent {
                channel: Some(RESOLVER_CHANNEL),
                ..
            }
        )));
        assert_consistent(&fixed_input(shape, 0), &report, &events);
    }

    let core = include_str!("../../core/src/lib.rs");
    assert!(core.contains("latency: Duration::from_millis(10)"));
    assert!(core.contains("jitter: Duration::from_millis(1)"));
    assert!(core.contains("success_rate: probability!(1.0)"));
    let module = include_str!("../src/proposal_switch.rs");
    assert!(module.contains("setup_network::<P>"));
    assert!(!module.contains(".add_link("));
    assert!(!module.contains(".remove_link("));
    assert!(!module.contains("apply_partition"));
}

#[test]
fn proposal_switch_fixed_matrix_and_real_old_vote_detection() {
    for shape in 1..=4 {
        for seed in 0..FIXED_SEEDS {
            let input = fixed_input(shape, seed);
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                run_observed(&input, Options::default())
            }));
            if old_vote_planted() {
                match shape {
                    1 => {
                        let text = payload_text(result.expect_err("the old vote must be detected"));
                        assert!(
                            text.starts_with(OUTBOUND_LABEL) || text.starts_with(REPORTED_LABEL),
                            "seed {seed}: {text}"
                        );
                        if text.starts_with(OUTBOUND_LABEL) {
                            assert!(text.contains("Finalization"), "seed {seed}: {text}");
                            assert!(text.contains("view 1"), "seed {seed}: {text}");
                            let digest = "02".repeat(32);
                            assert!(text.contains(&digest), "seed {seed}: {text}");
                        } else {
                            assert!(
                                text.contains("counted 1 invalid certificates"),
                                "seed {seed}: {text}"
                            );
                        }
                        println!("old-vote seed {seed}: {text}");
                        continue;
                    }
                    2 | 4 => {
                        match result {
                            Ok((report, _)) => println!(
                                "old-vote shape {shape} seed {seed}: pass; invalid_certificates={}",
                                report.invalid_certificates
                            ),
                            Err(payload) => println!(
                                "old-vote shape {shape} seed {seed}: {}",
                                payload_text(payload)
                            ),
                        }
                        continue;
                    }
                    3 => {}
                    _ => unreachable!(),
                }
            }
            let (report, events) = result.unwrap_or_else(|payload| {
                panic!("shape {shape} seed {seed}: {}", payload_text(payload))
            });
            assert_consistent(&input, &report, &events);
            assert!(!report.reported_certificates.contains(&(1, 1, payload(0))));
            match shape {
                1 => {
                    let roles = roles();
                    assert!(
                        report
                            .reported_votes
                            .contains(&(1, 0, roles.leaders[0], payload(0)))
                    );
                    assert!(
                        report
                            .reported_votes
                            .contains(&(1, 1, roles.leaders[0], payload(0)))
                    );
                    assert!(report.reported_certificates.contains(&(0, 1, payload(1))));
                    assert!(!report.reported_certificates.contains(&(1, 1, payload(1))));
                }
                2 | 4 => {
                    assert!(report.has_valid_finalization(1, payload(1)));
                    assert!(report.reported_certificates.contains(&(1, 1, payload(1))));
                }
                3 => {
                    assert!(!report.has_valid_finalization(1, payload(0)));
                }
                _ => unreachable!(),
            }
            if shape == 4 {
                assert_floor(&report, 1, payload(1));
            }
        }
    }

    let missing_floor = Report {
        victim: 0,
        leaders: [2, 3],
        sent: Vec::new(),
        checked: Vec::new(),
        reported_votes: BTreeSet::new(),
        reported_certificates: BTreeSet::new(),
        invalid_certificates: 0,
        invalid_votes: 0,
    };
    let text = panic_text(|| assert_floor(&missing_floor, 1, payload(1)));
    assert!(text.starts_with(VACUOUS_LABEL), "{text}");
}

#[test]
fn proposal_switch_empty_input_trace_and_determinism() {
    let input = decode(&[]);
    assert_eq!(input.raw_bytes, Vec::<u8>::new());
    assert_eq!(input.steps, vec![Step::canonical(); CANONICAL_STEPS]);
    let first = run(&input);
    let second = run(&input);
    assert_eq!(first, second);
    let (observed, events) = run_observed(&input, Options::default());
    assert_eq!(observed, first);
    assert_consistent(&input, &observed, &events);
    let times: Vec<_> = observed.sent.iter().map(|step| step.0).collect();
    assert_eq!(times, [100, 200, 300, 400, 500]);
    fuzz(input);

    let input = fixed_input(2, 7);
    assert_eq!(run(&input), run(&input));
}

#[test]
fn proposal_switch_messages_verify_independently() {
    for shape in 1..=4 {
        let input = fixed_input(shape, 0);
        for (position, step) in input.steps.iter().enumerate() {
            expected_outbound(position, step);
        }
    }
    for shape in 1..=4 {
        let input = fixed_input(shape, 0);
        let (report, events) = run_observed(&input, Options::default());
        assert_trace(&input, &report, &events);
    }
}

#[test]
fn proposal_switch_operation_alphabet() {
    for op in Op::ALL {
        let mut steps = vec![Step::canonical(); CANONICAL_STEPS];
        steps.push(Step::new(op, 2, 1, 2));
        let input = FuzzInput::from_steps(0, steps);
        let (report, events) = run_observed(&input, Options::default());
        assert_consistent(&input, &report, &events);
        assert_eq!(report.sent.len(), CANONICAL_STEPS + 1);
        assert_eq!(report.sent[CANONICAL_STEPS].0, 600);
    }
}

#[test]
fn proposal_switch_duplicate_steps_timing_and_settle() {
    let roles = roles();
    let gaps = [100, 0, 37, 100, 0];
    let definitions = [
        Step::new(Op::Notarization, 1, roles.x, 1),
        Step::new(Op::Notarization, 1, roles.x, 1),
        Step::new(Op::Finalize, 1, roles.x, 1),
        Step::new(Op::Finalize, 1, roles.x, 1),
        Step::new(Op::Finalize, 1, roles.y, 1),
    ];
    let steps: Vec<_> = definitions
        .into_iter()
        .zip(gaps)
        .map(|(step, gap)| with_gap(step, gap))
        .collect();
    let input = FuzzInput::from_steps(0, steps);
    let (report, events) = run_observed(&input, Options::default());
    assert_consistent(&input, &report, &events);
    let times: Vec<_> = report.sent.iter().map(|step| step.0).collect();
    assert_eq!(times, [100, 100, 137, 237, 237]);
    assert_eq!(report.sent[0].1, Op::Notarization);
    assert_eq!(report.sent[1].1, Op::Notarization);
    assert_eq!(report.sent[2].1, Op::Finalize);
    assert_eq!(report.sent[3].1, Op::Finalize);
    assert!(report.checked.iter().any(|checked| {
        checked.kind
            == commonware_consensus_fuzz_simplex::proposal_switch::CertificateKind::Notarization
            && checked.view == 1
            && checked.digest == Some(payload(1))
    }));
}

#[test]
fn proposal_switch_outbound_negative_control() {
    let input = fixed_input(4, 0);
    let text = panic_text(|| {
        run_observed(
            &input,
            Options {
                plant: Plant::RewriteFirstFinalization,
                ..Options::default()
            },
        );
    });
    assert!(text.starts_with(OUTBOUND_LABEL), "{text}");
    assert!(text.contains("Finalization"), "{text}");
    assert!(text.contains(&"03".repeat(32)), "{text}");

    let (report, events) = run_observed(
        &input,
        Options {
            plant: Plant::RewriteFirstFinalization,
            checks: Checks {
                outbound: false,
                reported: true,
            },
            resolver_probe: false,
        },
    );
    assert_eq!(report.invalid_certificates, 0);
    assert!(
        report
            .checked
            .iter()
            .any(|checked| { checked.digest == Some(payload(PLANTED_PROPOSAL)) && !checked.valid })
    );
    assert!(events.iter().any(|event| matches!(
        event.what,
        Observation::Planted(Plant::RewriteFirstFinalization)
    )));
}

#[test]
fn proposal_switch_reporter_negative_control() {
    let input = fixed_input(4, 0);
    let text = panic_text(|| {
        run_observed(
            &input,
            Options {
                plant: Plant::ReportForgedFinalization,
                ..Options::default()
            },
        );
    });
    assert!(text.starts_with(REPORTED_LABEL), "{text}");
    assert!(text.contains("counted 1"), "{text}");

    let (report, events) = run_observed(
        &input,
        Options {
            plant: Plant::ReportForgedFinalization,
            checks: Checks {
                outbound: true,
                reported: false,
            },
            resolver_probe: false,
        },
    );
    assert_eq!(report.invalid_certificates, 1);
    assert!(report.checked.iter().all(|checked| checked.valid));
    assert!(report.has_valid_finalization(1, payload(1)));
    assert!(events.iter().any(|event| matches!(
        event.what,
        Observation::Planted(Plant::ReportForgedFinalization)
    )));
}

#[test]
fn proposal_switch_decoder_total_and_bounded() {
    assert_eq!(MAX_RAW_BYTES, 32_768);
    assert_eq!(CANONICAL_STEPS, 5);
    assert_eq!(MAX_EXTRA_STEPS, 27);
    assert_eq!(MAX_GAP_MS, 100);
    assert_eq!(MAX_VIEW, 2);
    assert_eq!(PROPOSALS, 3);
    assert_eq!(PAYLOADS, [payload(0), payload(1), payload(2)]);
    for view in 1..=MAX_VIEW {
        for p in 0..PROPOSALS {
            assert_eq!(prop(view, p), proposal(view, p));
        }
    }

    let corpus = decode_corpus();
    assert_eq!(corpus.len(), EXPECTED_CORPUS);
    for bytes in corpus {
        assert_decode_bounds(&bytes);
    }
    let overlong = decode(&vec![0xa5; MAX_RAW_BYTES + 1]);
    assert_eq!(overlong.raw_bytes.len(), MAX_RAW_BYTES);

    let module = include_str!("../src/proposal_switch.rs");
    assert!(module.contains("peek_bytes(u.len().min(MAX_RAW_BYTES))"));
    assert!(module.contains("MAX_GAP_MS - u.int_in_range(0..=MAX_GAP_MS)?"));
    assert!(!module.contains("unwrap_or_else(|_| Step"));
}

#[test]
fn proposal_switch_majority_equivocation_stays_in_scope() {
    let mut steps = vec![Step::canonical(); CANONICAL_STEPS];
    for signer in 0..SCRIPTED {
        steps.push(Step::new(Op::Notarize, 1, signer, signer));
        steps.push(Step::new(Op::Notarize, 1, signer, (signer + 1) % PROPOSALS));
        steps.push(Step::new(Op::Finalize, 1, signer, (signer + 2) % PROPOSALS));
    }
    let input = FuzzInput::from_steps(3, steps);
    let (report, events) = run_observed(&input, Options::default());
    assert_consistent(&input, &report, &events);
    for signer in roles().scripted {
        let digests: BTreeSet<_> = events
            .iter()
            .filter_map(|event| match &event.what {
                Observation::Sent {
                    message: Some(message),
                    ..
                } if message.signers == [signer] => message.digest,
                _ => None,
            })
            .collect();
        assert!(
            digests.len() >= 2,
            "participant {signer} did not equivocate"
        );
    }
    assert_eq!(roles().scripted.len(), 3);
}

#[test]
fn proposal_switch_typed_target_and_component_registration() {
    let target = include_str!("../fuzz_targets/exp_simplex_secp256r1_proposal_switch.rs");
    assert!(target.contains("#[cfg(feature = \"mocks\")]"));
    assert!(target.contains("fuzz_target!(|input: FuzzInput|"));
    assert!(target.contains("fuzz(input);"));
    assert!(!target.contains("&[u8]"));
    let manifest = include_str!("../Cargo.toml");
    let entry = "name = \"exp_simplex_secp256r1_proposal_switch\"\npath = \"fuzz_targets/exp_simplex_secp256r1_proposal_switch.rs\"\ntest = false\ndoc = false\nbench = false\nrequired-features = [\"base\"]";
    assert!(manifest.contains(entry));
    let blackout = "name = \"exp_simplex_cert_mock_blackout\"\npath = \"fuzz_targets/exp_simplex_cert_mock_blackout.rs\"\ntest = false\ndoc = false\nbench = false\nrequired-features = [\"base\"]";
    assert!(manifest.contains(blackout));
    let components = include_str!("../../COMPONENTS.md");
    assert!(components.contains("src/proposal_switch.rs"));
    assert!(components.contains("exp_simplex_secp256r1_proposal_switch"));
    assert!(components.contains("SimplexSecp256r1"));
}

#[test]
fn proposal_switch_checked_report_fields_are_structured() {
    let checked = Checked {
        at_ms: 525,
        receiver: 1,
        kind: commonware_consensus_fuzz_simplex::proposal_switch::CertificateKind::Finalization,
        view: 1,
        digest: Some(payload(1)),
        valid: true,
    };
    assert_eq!(checked.at_ms, 525);
    assert_eq!(checked.receiver, 1);
    assert_eq!(checked.view, 1);
    assert_eq!(checked.digest, Some(payload(1)));
    assert!(checked.valid);
}
