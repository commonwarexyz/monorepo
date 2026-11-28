use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Copying, DecodeExt};
use commonware_consensus::{
    Handoff, Viewable,
    simplex::{ForwardPolicy, types::Vote},
    types::{Attributable, Epoch, Participant, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    BlockFilterChoice, CertifyChoice, Configuration, DEFAULT_MAILBOX_SIZE, EPOCH,
    FuzzInput as DriverInput, MAX_RAW_BYTES, MAX_TERM_LENGTH, N4F0C4, N4F1C3, N4F3C1,
    ReporterWiring, SimplexCertificateMock, reach,
    simplex::Simplex,
    state_bounds::{self, ADMISSION_CHECKED, RETENTION_CHECKED, UNIQUENESS_CHECKED, VoteKind},
    strategy::StrategyChoice,
    utils::Partition,
};
use commonware_consensus_fuzz_simplex::{
    CodeCoverage, FaultyNet, Standard, TwinsMutator,
    flood::{
        self, FAR_DISTANCE, FIXED_BURSTS, FIXED_CONTAINERS, FLOOR, FloodClass, FuzzInput,
        MAX_BURST_VOTES, MAX_BURSTS, MAX_REQUIRED_CONTAINERS, MIN_BURST_VOTES,
        MIN_REQUIRED_CONTAINERS, Plant, REPEAT_AHEAD, REPEAT_BEHIND, SETTLE, SWEEP_RADIUS,
    },
    fuzz, fuzz_audit,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_invariants::minifuzz;
use commonware_utils::{NZU32, NZUsize};
use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{self, AssertUnwindSafe},
    time::Instant,
};

type FloodScheme = <SimplexCertificateMock as Simplex>::Scheme;

fn term_length(value: u32) -> TermLength {
    TermLength::new(NZU32!(value))
}

fn decode_input(bytes: &[u8]) -> FuzzInput {
    FuzzInput::arbitrary(&mut Unstructured::new(bytes)).expect("every short input decodes")
}

fn empty_input() -> FuzzInput {
    decode_input(&[])
}

fn driver_input(configuration: Configuration) -> DriverInput {
    DriverInput {
        raw_bytes: 1u64.to_be_bytes().to_vec(),
        required_containers: 4,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        heterogeneous_optimism: false,
        handoff: Handoff::Wait,
        degraded_network: false,
        configuration,
        partition: Partition::Connected,
        strategy: StrategyChoice::AnyScope,
        mailbox_size: DEFAULT_MAILBOX_SIZE,
        forwarding: ForwardPolicy::Disabled,
        certify: CertifyChoice::Always,
        block_filter: BlockFilterChoice::None,
        reporting: ReporterWiring::Solo,
    }
}

fn panic_text(f: impl FnOnce()) -> String {
    let payload = panic::catch_unwind(AssertUnwindSafe(f)).expect_err("the control must panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&'static str>()
                .map(|s| (*s).to_owned())
        })
        .unwrap_or_else(|| "<non-string panic>".to_owned())
}

fn assert_reach_counts(expected: [u64; 4]) {
    let actual = [
        reach::count(state_bounds::MEASURED),
        reach::count(ADMISSION_CHECKED),
        reach::count(UNIQUENESS_CHECKED),
        reach::count(RETENTION_CHECKED),
    ];
    assert_eq!(actual, expected, "reach labels: {:?}", reach::snapshot());
}

fn decode_vote(bytes: &[u8]) -> Vote<FloodScheme, Sha256Digest> {
    Vote::decode(Copying(bytes)).expect("the flood trace contains encoded votes")
}

fn vote_shape(bytes: &[u8]) -> (VoteKind, Participant, View, Option<Sha256Digest>, Epoch) {
    match decode_vote(bytes) {
        Vote::Notarize(vote) => (
            VoteKind::Notarize,
            vote.signer(),
            vote.view(),
            Some(vote.proposal.payload),
            vote.proposal.round.epoch(),
        ),
        Vote::Nullify(vote) => (
            VoteKind::Nullify,
            vote.signer(),
            vote.view(),
            None,
            vote.round.epoch(),
        ),
        Vote::Finalize(vote) => (
            VoteKind::Finalize,
            vote.signer(),
            vote.view(),
            Some(vote.proposal.payload),
            vote.proposal.round.epoch(),
        ),
    }
}

fn assert_common_vote_shape(bytes: &[u8]) -> (VoteKind, View, Option<Sha256Digest>) {
    let (kind, signer, view, payload, epoch) = vote_shape(bytes);
    assert_eq!(
        signer,
        Participant::new(0),
        "the flooder must sign every vote"
    );
    assert_eq!(epoch, Epoch::new(EPOCH), "the vote must use the run epoch");
    (kind, view, payload)
}

fn assert_burst_shape(burst: &flood::Burst) {
    match burst.class {
        FloodClass::Far => {
            assert!((MIN_BURST_VOTES..=MAX_BURST_VOTES).contains(&burst.votes.len()));
            for bytes in &burst.votes {
                let (_, view, _) = assert_common_vote_shape(bytes);
                assert!(
                    view.get() >= burst.seen.get().saturating_add(FAR_DISTANCE),
                    "FAR view {view} is too close to seen view {}",
                    burst.seen
                );
            }
        }
        FloodClass::Repeat => {
            assert!((MIN_BURST_VOTES..=MAX_BURST_VOTES).contains(&burst.votes.len()));
            let first = &burst.votes[0];
            let (first_kind, first_view, first_payload) = assert_common_vote_shape(first);
            assert_eq!(first_kind, VoteKind::Notarize);
            let lower = burst.seen.get().saturating_sub(REPEAT_BEHIND).max(1);
            assert!(
                (lower..=burst.seen.get().saturating_add(REPEAT_AHEAD)).contains(&first_view.get())
            );
            let first_payload = first_payload.expect("a notarize has a payload");
            let mut odd_payloads = Vec::new();
            for (position, bytes) in burst.votes.iter().enumerate() {
                let (kind, view, payload) = assert_common_vote_shape(bytes);
                assert_eq!(kind, VoteKind::Notarize);
                assert_eq!(view, first_view);
                if position % 2 == 0 {
                    assert_eq!(bytes, first, "even REPEAT vote {position} is not vote zero");
                } else {
                    let payload = payload.expect("a notarize has a payload");
                    assert_ne!(payload, first_payload);
                    assert!(
                        !odd_payloads.contains(&payload),
                        "odd REPEAT payload repeated"
                    );
                    odd_payloads.push(payload);
                }
            }
            assert_eq!(
                burst.votes.len().div_ceil(2),
                burst.votes.iter().step_by(2).count()
            );
            assert_eq!(burst.votes.len() / 2, odd_payloads.len());
            assert!(odd_payloads.len() >= 32);
        }
        FloodClass::Sweep => {
            let lower = burst.seen.get().saturating_sub(SWEEP_RADIUS).max(1);
            let upper = burst.seen.get().saturating_add(SWEEP_RADIUS);
            assert_eq!(burst.votes.len() as u64, 3 * (upper - lower + 1));
            let mut by_view: BTreeMap<View, BTreeSet<VoteKind>> = BTreeMap::new();
            for bytes in &burst.votes {
                let (kind, view, _) = assert_common_vote_shape(bytes);
                assert!((lower..=upper).contains(&view.get()));
                assert!(by_view.entry(view).or_default().insert(kind));
            }
            assert_eq!(by_view.len() as u64, upper - lower + 1);
            for view in lower..=upper {
                assert_eq!(
                    by_view.get(&View::new(view)),
                    Some(&BTreeSet::from([
                        VoteKind::Notarize,
                        VoteKind::Nullify,
                        VoteKind::Finalize,
                    ]))
                );
            }
        }
    }
}

fn classify_received(report: &flood::Report, bytes: &[u8]) -> FloodClass {
    let classes: BTreeSet<_> = report
        .bursts
        .iter()
        .filter(|burst| burst.votes.iter().any(|vote| vote == bytes))
        .map(|burst| burst.class)
        .collect();
    assert_eq!(
        classes.len(),
        1,
        "a received vote must have one flood class"
    );
    *classes.first().unwrap()
}

fn assert_completed_report(report: &flood::Report, required: u64, bursts: u8) {
    assert_eq!(report.bursts.len(), usize::from(bursts));
    assert_eq!(report.nodes.len(), 3);
    assert_eq!(report.measured_at - report.finalized_at, SETTLE);
    assert!(report.sent().far + report.sent().repeat + report.sent().sweep <= 3072);
    for node in &report.nodes {
        assert!((1..=3).contains(&node.index));
        assert!(node.finalized >= required);
        assert!(node.measured.retained.is_some());
        assert!(node.measured.tracked <= node.measured.retained.unwrap());
    }
}

fn assert_runtime_tape(input: &FuzzInput, report: &flood::Report) {
    for (index, burst) in report.bursts.iter().enumerate() {
        let choices: Vec<_> = burst
            .votes
            .iter()
            .map(|vote| flood::Choice::of(vote))
            .collect();
        let mut stream = flood::stream_at(&input.raw_bytes, burst.sampled_at);
        assert_eq!(
            flood::sample_burst(&mut stream, burst.class, burst.seen),
            choices,
            "burst {index} did not come from its recorded runtime-tape offset"
        );

        if index == 0 {
            assert_eq!(burst.scheduled_at, None);
            assert_eq!((burst.start, burst.class), (View::new(1), FloodClass::Far));
            continue;
        }

        let previous = &report.bursts[index - 1];
        let scheduled_at = burst
            .scheduled_at
            .expect("every later burst records its scheduling offset");
        assert!(previous.sampled_at < scheduled_at);
        assert!(scheduled_at < burst.sampled_at);
        let mut stream = flood::stream_at(&input.raw_bytes, scheduled_at);
        let after = report.bursts.len() as u64 - index as u64 - 1;
        assert_eq!(
            flood::sample_next(
                &mut stream,
                previous.start,
                View::new(input.required_containers),
                after,
            ),
            (burst.start, burst.class),
            "burst {index} was not scheduled from its recorded runtime-tape offset"
        );
    }
}

#[test]
fn flood_acceptance_part_a_drivers_and_fault_gate() {
    reach::reset();
    fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(driver_input(N4F1C3));
    assert_reach_counts([3, 3, 3, 3]);

    reach::reset();
    fuzz::<SimplexCertificateMock, FaultyNet, CodeCoverage>(driver_input(N4F1C3));
    assert_reach_counts([3, 3, 3, 3]);

    reach::reset();
    fuzz_audit::<SimplexCertificateMock>(driver_input(N4F1C3));
    assert_reach_counts([3, 3, 3, 3]);

    reach::reset();
    fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(driver_input(N4F1C3));
    assert_reach_counts([3, 3, 3, 3]);

    reach::reset();
    fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(driver_input(N4F0C4));
    assert_reach_counts([4, 4, 4, 4]);

    reach::reset();
    fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(driver_input(N4F3C1));
    assert_reach_counts([1, 1, 1, 0]);
}

#[test]
fn flood_acceptance_decode_order_ranges_and_short_space() {
    fn reference(bytes: &[u8]) -> (Vec<u8>, u64, u64, u64, usize, u8) {
        let mut u = Unstructured::new(bytes);
        let raw = bytes[..bytes.len().min(MAX_RAW_BYTES)].to_vec();
        let containers = u
            .int_in_range(MIN_REQUIRED_CONTAINERS..=MAX_REQUIRED_CONTAINERS)
            .unwrap();
        let term = u.int_in_range(1..=MAX_TERM_LENGTH).unwrap();
        let max_lookahead = u64::from(term) + 2;
        let draw = u.int_in_range(0..=2 * max_lookahead - 1).unwrap();
        let lookahead = if draw < max_lookahead {
            0
        } else {
            draw - max_lookahead + 1
        };
        let mailbox = match u.int_in_range(0..=99).unwrap() {
            0..=49 => 1024,
            50..=74 => 1,
            75..=89 => 2,
            90..=96 => 4,
            _ => 8,
        };
        let bursts = u.int_in_range(1..=MAX_BURSTS).unwrap();
        (raw, containers, u64::from(term), lookahead, mailbox, bursts)
    }

    let baseline = empty_input();
    assert_eq!(baseline.raw_bytes, Vec::<u8>::new());
    assert_eq!(baseline.required_containers, 30);
    assert_eq!(baseline.term_length, TermLength::ONE);
    assert_eq!(baseline.optimistic_views, ViewDelta::zero());
    assert_eq!(baseline.mailbox_size, NZUsize!(1024));
    assert_eq!(baseline.bursts, 1);

    let mut samples = Vec::new();
    samples.push(Vec::new());
    samples.extend((0u8..=u8::MAX).map(|byte| vec![byte]));
    samples.extend([
        vec![0, 0],
        vec![0xff, 0xff],
        vec![0, 1, 2, 3, 4, 5],
        vec![0xff, 0, 0xff, 0, 0xff, 0],
    ]);
    for bytes in &samples {
        let input = decode_input(bytes);
        let expected = reference(bytes);
        assert_eq!(input.raw_bytes, expected.0, "bytes={bytes:02x?}");
        assert_eq!(input.required_containers, expected.1, "bytes={bytes:02x?}");
        assert_eq!(input.term_length.get(), expected.2, "bytes={bytes:02x?}");
        assert_eq!(
            input.optimistic_views.get(),
            expected.3,
            "bytes={bytes:02x?}"
        );
        assert_eq!(input.mailbox_size.get(), expected.4, "bytes={bytes:02x?}");
        assert_eq!(input.bursts, expected.5, "bytes={bytes:02x?}");
    }

    for value in 0u16..=u16::MAX {
        let bytes = value.to_be_bytes();
        let input = decode_input(&bytes);
        assert!((30..=60).contains(&input.required_containers));
        assert!((1..=5).contains(&input.term_length.get()));
        assert!(input.optimistic_views.get() <= input.term_length.get() + 2);
        assert!([1, 2, 4, 8, 1024].contains(&input.mailbox_size.get()));
        assert!((1..=6).contains(&input.bursts));
    }
    for pattern in [vec![0; 16], vec![0xff; 16], (0u8..16).collect::<Vec<_>>()] {
        for length in 3..=pattern.len() {
            decode_input(&pattern[..length]);
        }
    }

    let patterned: Vec<u8> = (0..MAX_RAW_BYTES).map(|i| i as u8).collect();
    let capped = decode_input(&patterned);
    let mut with_suffix = patterned.clone();
    with_suffix.push(0xa5);
    let suffixed = decode_input(&with_suffix);
    assert_eq!(capped.raw_bytes, patterned);
    assert_eq!(suffixed.raw_bytes, patterned);
}

#[test]
fn flood_acceptance_empty_short_and_deterministic_runs() {
    let empty = empty_input();
    let first = flood::run(&empty);
    println!("empty flood report: {first}");
    assert_completed_report(&first, 30, 1);
    assert_eq!(first.bursts[0].class, FloodClass::Far);
    assert_eq!(first.bursts[0].start, View::new(1));
    assert!((MIN_BURST_VOTES..=MAX_BURST_VOTES).contains(&first.bursts[0].votes.len()));
    assert_burst_shape(&first.bursts[0]);
    for node in &first.nodes {
        assert!(node.taken.far >= FLOOR);
    }
    assert_eq!(first, flood::run(&empty));

    let fixed = flood::fixed_corpus().into_iter().next().unwrap();
    assert_eq!(flood::run(&fixed), flood::run(&fixed));

    let short = [
        vec![0],
        vec![0xff],
        vec![0, 0],
        vec![0xff, 0xff],
        vec![0, 1, 2],
        vec![0, 1, 2, 3],
        vec![0, 1, 2, 3, 4],
        vec![0, 1, 2, 3, 4, 5],
    ];
    for bytes in short {
        let input = decode_input(&bytes);
        let report = flood::run(&input);
        assert_completed_report(&report, input.required_containers, input.bursts);
    }
}

#[test]
fn flood_acceptance_topology_matrix() {
    for mailbox in [1024, 1, 2, 4, 8] {
        for term in 1..=5 {
            for lookahead in [0, u64::from(term), u64::from(term) + 2] {
                let input = FuzzInput {
                    raw_bytes: 0u64.to_be_bytes().to_vec(),
                    required_containers: 30,
                    term_length: term_length(term),
                    optimistic_views: ViewDelta::new(lookahead),
                    mailbox_size: std::num::NonZeroUsize::new(mailbox).unwrap(),
                    bursts: 1,
                };
                let report = flood::run(&input);
                assert_completed_report(&report, 30, 1);
                assert_eq!(
                    report
                        .nodes
                        .iter()
                        .map(|node| node.index)
                        .collect::<Vec<_>>(),
                    vec![1, 2, 3]
                );
            }
        }
    }
}

#[test]
fn flood_acceptance_fixed_corpus_traces_and_floors() {
    let corpus = flood::fixed_corpus();
    assert_eq!(corpus.len(), 100);
    let started = Instant::now();
    let mut reports = Vec::with_capacity(corpus.len());
    for input in &corpus {
        assert_eq!(input.required_containers, FIXED_CONTAINERS);
        assert_eq!(input.bursts, FIXED_BURSTS);
        let report = flood::run(input);
        assert_completed_report(&report, FIXED_CONTAINERS, FIXED_BURSTS);
        assert_runtime_tape(input, &report);
        for burst in &report.bursts {
            assert!(report.heard[burst.trigger] >= burst.start);
            assert!(
                report.heard[..burst.trigger]
                    .iter()
                    .all(|view| *view < burst.start),
                "burst at {} did not use the first qualifying honest vote",
                burst.start
            );
            assert_burst_shape(burst);
        }
        assert_eq!(report.bursts[0].class, FloodClass::Far);
        assert_eq!(report.bursts[0].start, View::new(1));
        for node in &report.nodes {
            let mut independent = flood::ClassCounts::default();
            for bytes in &node.received {
                match classify_received(&report, bytes) {
                    FloodClass::Far => independent.far += 1,
                    FloodClass::Repeat => independent.repeat += 1,
                    FloodClass::Sweep => independent.sweep += 1,
                }
            }
            assert_eq!(node.taken, independent);
        }
        reports.push(report);
    }
    flood::check_floors(&reports).expect("the fixed corpus must exercise every class");
    let sent: u64 = reports
        .iter()
        .map(|report| {
            let sent = report.sent();
            sent.far + sent.repeat + sent.sweep
        })
        .sum();
    println!(
        "fixed corpus: {} reports, {sent} votes, {:?} per input",
        reports.len(),
        started.elapsed() / reports.len() as u32
    );
}

#[test]
fn flood_acceptance_minifuzz_100_inputs() {
    let started = Instant::now();
    let mut runs = 0u64;
    let mut largest = 0u64;
    minifuzz::Builder::default()
        .with_seed(0)
        .with_search_limit(100)
        .test(|u| {
            let input = FuzzInput::arbitrary(u)?;
            let report = panic::catch_unwind(AssertUnwindSafe(|| flood::run(&input)))
                .unwrap_or_else(|payload| {
                    let message = payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| {
                            payload
                                .downcast_ref::<&'static str>()
                                .map(|s| (*s).to_owned())
                        })
                        .unwrap_or_else(|| "<non-string panic>".to_owned());
                    panic!("minifuzz input {input:?}: {message}")
                });
            assert_completed_report(&report, input.required_containers, input.bursts);
            let sent = report.sent();
            largest = largest.max(sent.far + sent.repeat + sent.sweep);
            runs += 1;
            Ok(())
        });
    assert_eq!(runs, 100);
    assert!(largest <= u64::from(MAX_BURSTS) * MAX_BURST_VOTES as u64);
    println!(
        "minifuzz: {runs} reports, largest={largest} votes, {:?} per input",
        started.elapsed() / runs as u32
    );
}

#[test]
fn flood_acceptance_run_level_negative_controls() {
    let input = flood::fixed_corpus().into_iter().next().unwrap();
    let i1 = panic_text(|| {
        flood::run_planted(&input, Some(Plant::FarVote { node: 1 }));
    });
    assert!(i1.starts_with("C6-I1"), "{i1}");

    let i2 = panic_text(|| {
        flood::run_planted(&input, Some(Plant::DuplicateVotes { node: 1 }));
    });
    assert!(i2.starts_with("C6-I2"), "{i2}");

    let i4 = panic_text(|| {
        flood::run_planted(&empty_input(), Some(Plant::Isolate { node: 1 }));
    });
    assert!(i4.contains("runtime timeout"), "{i4}");
}

#[test]
fn flood_acceptance_uncounted_sweep_negative_control() {
    let mut reports = Vec::new();
    let mut comparison_done = false;
    for input in flood::fixed_corpus() {
        let planted = flood::run_planted(&input, Some(Plant::UncountedSweep));
        if !comparison_done && planted.sent().sweep > 0 {
            let ordinary = flood::run(&input);
            assert_eq!(ordinary.heard, planted.heard);
            assert_eq!(ordinary.bursts, planted.bursts);
            assert_eq!(ordinary.finalized_at, planted.finalized_at);
            assert_eq!(ordinary.measured_at, planted.measured_at);
            for (ordinary, planted) in ordinary.nodes.iter().zip(&planted.nodes) {
                assert_eq!(ordinary.received, planted.received);
                assert_eq!(ordinary.recorded, planted.recorded);
                assert_eq!(ordinary.finalized, planted.finalized);
                assert_eq!(ordinary.measured, planted.measured);
                assert_eq!(ordinary.taken.far, planted.taken.far);
                assert_eq!(ordinary.taken.repeat, planted.taken.repeat);
                assert!(ordinary.taken.sweep > 0);
                assert_eq!(planted.taken.sweep, 0);
            }
            comparison_done = true;
        }
        reports.push(planted);
    }
    assert!(comparison_done, "the fixed corpus sent no SWEEP burst");
    let error = flood::check_floors(&reports).unwrap_err();
    assert!(error.starts_with("C6-I5 vacuous"), "{error}");
}
