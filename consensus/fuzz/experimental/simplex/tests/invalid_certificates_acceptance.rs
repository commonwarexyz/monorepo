use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{
    Handoff, Monitor as _, Reporter as _,
    simplex::{
        ForwardPolicy,
        elector::RoundRobin,
        mocks::reporter::Config as ReporterConfig,
        types::{
            Activity, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            Proposal,
        },
    },
    types::{Epoch, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    BlockFilterChoice, CertifyChoice, DEFAULT_MAILBOX_SIZE, FuzzInput, MIN_REQUIRED_CONTAINERS,
    N4F0C4, N4F1C3, ReporterWiring, SimplexCertificateMock, simplex_audit::RecordingReporter,
    simplex_certificate_mock as certificate_mock, strategy::StrategyChoice, utils::Partition,
};
use commonware_consensus_fuzz_simplex::{
    Chaos, ChaosTwins, CodeCoverage, FaultyNet, MalloryContainer, Standard, TwinsCampaign,
    TwinsMutator, blackout, blame, evidence, flood, fuzz, fuzz_audit, fuzz_audit_notarize_omission,
    fuzz_twins_audit,
    invariants::{
        Judged, check_no_invalid_certificates, check_no_invalid_reports_if_no_faults,
        install_certificate_probe, take_certificate_probe,
    },
};
use commonware_cryptography::{
    ed25519::PublicKey as Ed25519PublicKey, sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, non_empty, ordered::Set, test_rng};
use futures::executor::block_on;
use std::{
    collections::BTreeSet,
    panic::{self, AssertUnwindSafe},
};

type MockScheme = certificate_mock::Scheme<Ed25519PublicKey, false>;
type DirectReporter = RecordingReporter<TestRng, MockScheme, RoundRobin, Sha256Digest>;

const FIXTURE_NAMESPACE: &[u8] =
    b"_COMMONWARE_CONSENSUS_FUZZ_SIMPLEX_INVALID_CERTIFICATES_ACCEPTANCE";

fn base_input() -> FuzzInput {
    FuzzInput {
        raw_bytes: 0u64.to_be_bytes().to_vec(),
        required_containers: MIN_REQUIRED_CONTAINERS,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        heterogeneous_optimism: false,
        handoff: Handoff::Wait,
        degraded_network: false,
        configuration: N4F0C4,
        partition: Partition::Connected,
        strategy: StrategyChoice::AnyScope,
        mailbox_size: DEFAULT_MAILBOX_SIZE,
        forwarding: ForwardPolicy::Disabled,
        certify: CertifyChoice::Always,
        block_filter: BlockFilterChoice::None,
        reporting: ReporterWiring::Solo,
    }
}

fn faulty_input() -> FuzzInput {
    FuzzInput {
        configuration: N4F1C3,
        ..base_input()
    }
}

fn rejected_view_input() -> FuzzInput {
    FuzzInput {
        required_containers: 4,
        certify: CertifyChoice::RejectView { view: View::new(3) },
        ..faulty_input()
    }
}

fn mallory_input(byte: u8) -> FuzzInput {
    FuzzInput {
        raw_bytes: vec![byte],
        ..base_input()
    }
}

fn empty_input<T: for<'a> Arbitrary<'a>>() -> T {
    T::arbitrary_take_rest(Unstructured::new(&[])).expect("the empty input must decode")
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
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

fn catch_message(run: impl FnOnce()) -> String {
    let payload = panic::catch_unwind(AssertUnwindSafe(run)).expect_err("the call must panic");
    panic_message(payload)
}

fn planted_run(run: impl FnOnce()) {
    install_certificate_probe(true);
    let message = catch_message(run);
    let log = take_certificate_probe().expect("the planted probe must remain installed");

    assert!(
        message.contains("Invariant violation: honest reporter"),
        "wrong panic: {message}"
    );
    assert!(
        message.contains("counted 1 invalid certificates"),
        "wrong panic: {message}"
    );
    assert_eq!(log.len(), 1, "the planted run must stop in its first check");
    let call = &log[0];
    let planted = call.last().expect("the check must judge a reporter");
    assert!(
        message.contains(&format!("honest reporter {} counted", planted.participant)),
        "the panic must name the planted reporter: {message}"
    );
    assert_eq!(planted.invalid_certificates, 1);
    assert!(
        call[..call.len() - 1]
            .iter()
            .all(|judged| judged.invalid_certificates == 0),
        "only the last reporter may receive the planted certificate: {call:?}"
    );
}

fn judged_run(run: impl FnOnce()) -> Vec<Vec<Judged>> {
    install_certificate_probe(false);
    run();
    let log = take_certificate_probe().expect("the probe must remain installed");
    assert!(!log.is_empty(), "the run must reach a certificate check");
    for call in &log {
        assert!(
            call.iter().all(|judged| judged.invalid_certificates == 0),
            "an unplanted run counted an invalid certificate: {call:?}"
        );
    }
    log
}

fn participants(call: &[Judged]) -> BTreeSet<u32> {
    let participants: BTreeSet<_> = call.iter().map(|judged| judged.participant).collect();
    assert_eq!(
        participants.len(),
        call.len(),
        "a participant was judged twice: {call:?}"
    );
    participants
}

fn assert_participants(log: &[Vec<Judged>], expected: &[u32]) {
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    for call in log {
        assert_eq!(participants(call), expected);
    }
}

fn assert_three_participants(log: &[Vec<Judged>]) {
    for call in log {
        assert_eq!(participants(call).len(), 3);
    }
}

#[test]
fn at_001_standard_plant() {
    planted_run(|| fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(faulty_input()));
}

#[test]
fn at_002_faulty_net_plant() {
    planted_run(|| fuzz::<SimplexCertificateMock, FaultyNet, CodeCoverage>(faulty_input()));
}

#[test]
fn at_003_audit_plant() {
    planted_run(|| fuzz_audit::<SimplexCertificateMock>(faulty_input()));
}

#[test]
fn at_004_notarize_omission_plant() {
    planted_run(|| fuzz_audit_notarize_omission::<SimplexCertificateMock>(base_input()));
}

#[test]
fn at_005_twins_mutator_plant() {
    planted_run(|| fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(base_input()));
}

#[test]
fn at_006_twins_campaign_plant() {
    planted_run(|| fuzz::<SimplexCertificateMock, TwinsCampaign, CodeCoverage>(base_input()));
}

#[test]
fn at_007_twins_audit_plant() {
    planted_run(|| fuzz_twins_audit::<SimplexCertificateMock, TwinsCampaign>(base_input()));
}

#[test]
fn at_008_mallory_plant() {
    planted_run(|| {
        fuzz::<SimplexCertificateMock, MalloryContainer, CodeCoverage>(mallory_input(1));
    });
}

#[test]
fn at_009_chaos_plant() {
    planted_run(|| fuzz::<SimplexCertificateMock, Chaos, CodeCoverage>(base_input()));
}

#[test]
fn at_010_chaos_twins_plant() {
    planted_run(|| fuzz::<SimplexCertificateMock, ChaosTwins, CodeCoverage>(base_input()));
}

#[test]
fn at_011_blackout_plant() {
    planted_run(|| {
        blackout::run(empty_input());
    });
}

#[test]
fn at_012_flood_plant() {
    planted_run(|| {
        flood::run(&empty_input());
    });
}

#[test]
fn at_013_evidence_plant() {
    planted_run(|| {
        evidence::run(&empty_input());
    });
}

#[test]
fn at_014_blame_plant() {
    planted_run(|| {
        blame::run(&blame::fixed_scenarios()[0]);
    });
}

#[test]
fn at_015_standard_judged_set() {
    let log = judged_run(|| {
        fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(faulty_input());
    });
    assert_participants(&log, &[1, 2, 3]);
}

#[test]
fn at_016_faulty_net_judged_set() {
    let log = judged_run(|| {
        fuzz::<SimplexCertificateMock, FaultyNet, CodeCoverage>(faulty_input());
    });
    assert_participants(&log, &[1, 2, 3]);
}

#[test]
fn at_017_audit_judged_set() {
    let log = judged_run(|| fuzz_audit::<SimplexCertificateMock>(faulty_input()));
    assert_participants(&log, &[1, 2, 3]);
}

#[test]
fn at_018_rejected_view_excludes_observer() {
    let log = judged_run(|| fuzz_audit::<SimplexCertificateMock>(rejected_view_input()));
    assert_participants(&log, &[1, 2, 3]);
}

#[test]
fn at_019_notarize_omission_judged_set() {
    let log = judged_run(|| {
        fuzz_audit_notarize_omission::<SimplexCertificateMock>(base_input());
    });
    assert_participants(&log, &[0, 1, 2, 3]);
}

#[test]
fn at_020_twins_mutator_judged_set() {
    let log = judged_run(|| {
        fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(base_input());
    });
    assert_three_participants(&log);
}

#[test]
fn at_021_twins_campaign_judged_set() {
    let log = judged_run(|| {
        fuzz::<SimplexCertificateMock, TwinsCampaign, CodeCoverage>(base_input());
    });
    assert_three_participants(&log);
}

#[test]
fn at_022_twins_audit_judged_set() {
    let log = judged_run(|| {
        fuzz_twins_audit::<SimplexCertificateMock, TwinsCampaign>(base_input());
    });
    assert_three_participants(&log);
}

#[test]
fn at_023_mallory_honest_judged_set() {
    let log = judged_run(|| {
        fuzz::<SimplexCertificateMock, MalloryContainer, CodeCoverage>(mallory_input(0));
    });
    assert_participants(&log, &[0, 1, 2, 3]);
}

#[test]
fn at_024_mallory_disrupter_judged_set() {
    let log = judged_run(|| {
        fuzz::<SimplexCertificateMock, MalloryContainer, CodeCoverage>(mallory_input(1));
    });
    assert_participants(&log, &[1, 2, 3]);
}

#[test]
fn at_025_chaos_judged_set() {
    let log = judged_run(|| {
        fuzz::<SimplexCertificateMock, Chaos, CodeCoverage>(base_input());
    });
    assert_participants(&log, &[0, 1, 2, 3]);
}

#[test]
fn at_026_chaos_twins_judged_set() {
    let log = judged_run(|| {
        fuzz::<SimplexCertificateMock, ChaosTwins, CodeCoverage>(base_input());
    });
    assert_three_participants(&log);
}

#[test]
fn at_027_blackout_judged_set() {
    let input: blackout::FuzzInput = empty_input();
    let expected: Vec<_> = blackout::live_validators(input.absent)
        .into_iter()
        .map(|participant| participant as u32)
        .collect();
    let log = judged_run(|| {
        blackout::run(input);
    });
    assert_participants(&log, &expected);
}

#[test]
fn at_028_scripted_runner_judged_sets() {
    let flood_log = judged_run(|| {
        flood::run(&empty_input());
    });
    assert_participants(&flood_log, &[1, 2, 3]);

    let evidence_log = judged_run(|| {
        evidence::run(&empty_input());
    });
    assert_participants(&evidence_log, &[1, 2, 3]);

    let blame_log = judged_run(|| {
        blame::run(&blame::fixed_scenarios()[0]);
    });
    assert_participants(&blame_log, &[1, 2, 3]);
}

#[test]
fn at_029_invalid_votes_are_not_certificate_failures() {
    let scenario = &blame::fixed_scenarios()[36];
    assert_eq!(scenario.attack, blame::Attack::BadSignature);
    let log = judged_run(|| {
        blame::run(scenario);
    });
    assert!(
        log.iter().flatten().any(|judged| judged.invalid_votes >= 1),
        "the bad-signature scenario must count an invalid vote: {log:?}"
    );
}

#[test]
fn at_030_probe_log_is_deterministic() {
    let first = judged_run(|| {
        fuzz::<SimplexCertificateMock, Chaos, CodeCoverage>(base_input());
    });
    let second = judged_run(|| {
        fuzz::<SimplexCertificateMock, Chaos, CodeCoverage>(base_input());
    });
    assert_eq!(first, second);
}

fn direct_fixture() -> (Vec<DirectReporter>, Vec<MockScheme>) {
    let fixture = certificate_mock::fixture_with::<false, true, true, _>(
        &mut test_rng(),
        FIXTURE_NAMESPACE,
        4,
    );
    let reporters = [1, 2]
        .map(|observer| {
            RecordingReporter::new(
                test_rng(),
                fixture.participants[observer].clone(),
                0,
                ReporterConfig {
                    participants: Set::try_from(fixture.participants.clone())
                        .expect("fixture keys must be unique"),
                    scheme: fixture.schemes[observer].clone(),
                    elector: RoundRobin::default(),
                },
            )
        })
        .into();
    (reporters, fixture.schemes)
}

fn round(view: u64) -> Round {
    Round::new(Epoch::new(0), View::new(view))
}

fn proposal(view: u64, payload: u8) -> Proposal<Sha256Digest> {
    Proposal::new(
        round(view),
        View::new(view.saturating_sub(1)),
        Sha256Digest::from([payload; 32]),
    )
}

fn notarization(schemes: &[MockScheme], view: u64) -> Notarization<MockScheme, Sha256Digest> {
    let votes: Vec<_> = schemes[..3]
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal(view, 0x11)).unwrap())
        .collect();
    Notarization::from_notarizes(&schemes[0], non_empty![@&votes], &Sequential).unwrap()
}

fn finalization(schemes: &[MockScheme], view: u64) -> Finalization<MockScheme, Sha256Digest> {
    let votes: Vec<_> = schemes[..3]
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal(view, 0x22)).unwrap())
        .collect();
    Finalization::from_finalizes(&schemes[0], non_empty![@&votes], &Sequential).unwrap()
}

fn nullification(schemes: &[MockScheme], view: u64) -> Nullification<MockScheme> {
    let votes: Vec<_> = schemes[..3]
        .iter()
        .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round(view)).unwrap())
        .collect();
    Nullification::from_nullifies(&schemes[0], non_empty![@&votes], &Sequential).unwrap()
}

#[derive(Clone, Copy)]
enum CertificateKind {
    Notarization,
    Finalization,
    Nullification,
    All,
}

fn record_certificates(
    reporter: &mut DirectReporter,
    schemes: &[MockScheme],
    kind: CertificateKind,
) {
    if matches!(kind, CertificateKind::Notarization | CertificateKind::All) {
        reporter.report(Activity::Notarization(notarization(schemes, 5)));
    }
    if matches!(kind, CertificateKind::Finalization | CertificateKind::All) {
        reporter.report(Activity::Finalization(finalization(schemes, 6)));
    }
    if matches!(kind, CertificateKind::Nullification | CertificateKind::All) {
        reporter.report(Activity::Nullification(nullification(schemes, 7)));
    }
}

fn judged_values(reporters: &[DirectReporter]) -> Vec<Judged> {
    reporters
        .iter()
        .map(|reporter| Judged {
            participant: reporter.me().expect("the reporter must sign").get(),
            invalid_votes: *reporter.inner().invalid_votes.lock(),
            invalid_certificates: *reporter.inner().invalid_certificates.lock(),
        })
        .collect()
}

#[test]
fn at_031_direct_check_contract() {
    let (reporters, _) = direct_fixture();
    *reporters[0].inner().invalid_votes.lock() = 7;
    let before: Vec<_> = reporters
        .iter()
        .map(|reporter| {
            let inner = reporter.inner();
            (
                inner.notarizations.lock().clone(),
                inner.certifications.lock().clone(),
                inner.nullifications.lock().clone(),
                inner.finalizations.lock().clone(),
                *inner.invalid_votes.lock(),
                *inner.invalid_certificates.lock(),
                reporter.audit().events().len(),
            )
        })
        .collect();
    check_no_invalid_certificates(&reporters);
    for (reporter, state) in reporters.iter().zip(&before) {
        let inner = reporter.inner();
        let (
            notarizations,
            certifications,
            nullifications,
            finalizations,
            invalid_votes,
            invalid_certificates,
            audit_len,
        ) = state;
        assert_eq!(&*inner.notarizations.lock(), notarizations);
        assert_eq!(&*inner.certifications.lock(), certifications);
        assert_eq!(&*inner.nullifications.lock(), nullifications);
        assert_eq!(&*inner.finalizations.lock(), finalizations);
        assert_eq!(*inner.invalid_votes.lock(), *invalid_votes);
        assert_eq!(*inner.invalid_certificates.lock(), *invalid_certificates);
        assert_eq!(reporter.audit().events().len(), *audit_len);
    }

    *reporters[0].inner().invalid_certificates.lock() = 2;
    *reporters[1].inner().invalid_certificates.lock() = 3;
    let before = judged_values(&reporters);
    let first = reporters[0].me().expect("the reporter must sign").get();
    let message = catch_message(|| check_no_invalid_certificates(&reporters));
    assert!(
        message.contains(&format!(
            "honest reporter {first} counted 2 invalid certificates"
        )),
        "the first invalid reporter must fail with its exact count: {message}"
    );
    assert_eq!(judged_values(&reporters), before);
}

#[test]
fn at_032_judged_public_contract() {
    let judged = Judged {
        participant: 7u32,
        invalid_votes: 2usize,
        invalid_certificates: 3usize,
    };
    let cloned = judged.clone();
    assert_eq!(cloned, judged);
    assert_ne!(
        judged,
        Judged {
            participant: 8,
            ..cloned
        }
    );
    assert!(format!("{judged:?}").contains("invalid_certificates"));
}

#[test]
fn at_033_probe_lifecycle_is_thread_local() {
    install_certificate_probe(false);
    install_certificate_probe(true);
    assert_eq!(take_certificate_probe(), Some(Vec::new()));
    assert_eq!(take_certificate_probe(), None);

    std::thread::spawn(|| {
        assert_eq!(take_certificate_probe(), None);
        install_certificate_probe(false);
        install_certificate_probe(true);
        assert_eq!(take_certificate_probe(), Some(Vec::new()));
        assert_eq!(take_certificate_probe(), None);
    })
    .join()
    .expect("the probe thread must finish");

    fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(faulty_input());
    assert_eq!(
        take_certificate_probe(),
        None,
        "the driver installed a probe"
    );
}

fn assert_single_plant(kind: CertificateKind) {
    let (mut reporters, schemes) = direct_fixture();
    record_certificates(
        reporters.last_mut().expect("the fixture has reporters"),
        &schemes,
        kind,
    );

    let mut monitored = reporters
        .last()
        .expect("the fixture has reporters")
        .inner()
        .clone();
    let (latest_before, mut subscription) = block_on(monitored.subscribe());
    let before: Vec<_> = reporters
        .iter()
        .map(|reporter| {
            let inner = reporter.inner();
            (
                inner.leaders.lock().clone(),
                inner.certified.lock().clone(),
                inner.notarizes.lock().clone(),
                inner.notarizations.lock().clone(),
                inner.certifications.lock().clone(),
                inner.nullifies.lock().clone(),
                inner.nullifications.lock().clone(),
                inner.finalizes.lock().clone(),
                inner.finalizations.lock().clone(),
                inner.faults.lock().clone(),
                *inner.invalid_votes.lock(),
                *inner.invalid_certificates.lock(),
                reporter.audit().events().len(),
            )
        })
        .collect();

    install_certificate_probe(true);
    let message = catch_message(|| check_no_invalid_certificates(&reporters));
    let log = take_certificate_probe().expect("the planted probe must remain installed");
    let last = reporters.last().expect("the fixture has reporters");
    let participant = last.me().expect("the reporter must sign").get();
    assert!(
        message.contains(&format!(
            "honest reporter {participant} counted 1 invalid certificates"
        )),
        "wrong plant panic: {message}"
    );

    let last_index = reporters.len() - 1;
    for (index, (reporter, state)) in reporters.iter().zip(&before).enumerate() {
        let inner = reporter.inner();
        let (
            leaders,
            certified,
            notarizes,
            notarizations,
            certifications,
            nullifies,
            nullifications,
            finalizes,
            finalizations,
            faults,
            invalid_votes,
            invalid_certificates,
            audit_len,
        ) = state;
        assert_eq!(&*inner.leaders.lock(), leaders);
        assert_eq!(&*inner.certified.lock(), certified);
        assert_eq!(&*inner.notarizes.lock(), notarizes);
        assert_eq!(&*inner.notarizations.lock(), notarizations);
        assert_eq!(&*inner.certifications.lock(), certifications);
        assert_eq!(&*inner.nullifies.lock(), nullifies);
        assert_eq!(&*inner.nullifications.lock(), nullifications);
        assert_eq!(&*inner.finalizes.lock(), finalizes);
        assert_eq!(&*inner.finalizations.lock(), finalizations);
        assert_eq!(&*inner.faults.lock(), faults);
        assert_eq!(*inner.invalid_votes.lock(), *invalid_votes);
        assert_eq!(
            *inner.invalid_certificates.lock(),
            *invalid_certificates + usize::from(index == last_index)
        );
        assert_eq!(reporter.audit().events().len(), *audit_len);
    }

    assert!(subscription.try_recv().is_err(), "the plant sent a view");
    let (latest_after, _) = block_on(monitored.subscribe());
    assert_eq!(latest_after, latest_before);
    assert_eq!(log, vec![judged_values(&reporters)]);
}

#[test]
fn at_034_plant_changes_only_one_counter() {
    for kind in [
        CertificateKind::Notarization,
        CertificateKind::Finalization,
        CertificateKind::Nullification,
        CertificateKind::All,
    ] {
        assert_single_plant(kind);
    }

    let (mut reporters, schemes) = direct_fixture();
    record_certificates(
        reporters.last_mut().expect("the fixture has reporters"),
        &schemes,
        CertificateKind::Notarization,
    );
    install_certificate_probe(true);
    let first = catch_message(|| check_no_invalid_certificates(&reporters));
    let second = catch_message(|| check_no_invalid_certificates(&reporters));
    assert!(first.contains("counted 1 invalid certificates"));
    assert!(second.contains("counted 1 invalid certificates"));
    assert_eq!(
        *reporters
            .last()
            .expect("the fixture has reporters")
            .inner()
            .invalid_certificates
            .lock(),
        1,
        "the second check planted again"
    );
    let log = take_certificate_probe().expect("the probe must remain installed");
    assert_eq!(log.len(), 2);
}

#[test]
fn at_035_vacuous_plant_fails_first() {
    let (reporters, _) = direct_fixture();
    let participant = reporters
        .last()
        .expect("the fixture has reporters")
        .me()
        .expect("the reporter must sign")
        .get();
    install_certificate_probe(true);
    let message = catch_message(|| check_no_invalid_certificates(&reporters));
    assert_eq!(
        message,
        format!("certificate plant vacuous: participant {participant} recorded no certificate")
    );
    assert_eq!(take_certificate_probe(), Some(Vec::new()));
}

#[test]
fn at_036_old_invalid_report_check_is_preserved() {
    let (reporters, _) = direct_fixture();
    *reporters[0].inner().invalid_votes.lock() = 1;
    check_no_invalid_certificates(&reporters);
    let summaries: Vec<_> = reporters
        .iter()
        .map(|reporter| reporter.inner().clone())
        .collect();
    check_no_invalid_reports_if_no_faults(1, &summaries);
    let vote_message = catch_message(|| check_no_invalid_reports_if_no_faults(0, &summaries));
    assert!(vote_message.contains("invalid votes detected"));

    let (certificate_reporters, _) = direct_fixture();
    *certificate_reporters[0].inner().invalid_certificates.lock() = 1;
    let certificate_message =
        catch_message(|| check_no_invalid_certificates(&certificate_reporters));
    assert!(certificate_message.contains("Invariant violation: honest reporter"));
    assert!(certificate_message.contains("counted 1 invalid certificates"));
}
