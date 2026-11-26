use super::{
    super::{
        runner::{
            LedgerReporter, LedgerSender, force_poison, run_standard_disrupter,
            seams::{self, Event},
        },
        twins::{
            PublicKeyOf as MarshalPublicKeyOf,
            stack::{FETCH_RETRY_DELAY, FETCH_TIMEOUT},
        },
    },
    FuzzInput, RetryCheck, check_retry, standard,
};
use crate::marshal::MarshalDisrupterInput;
use arbitrary::{Arbitrary, Unstructured};
use commonware_actor::{Feedback, Unreliable};
use commonware_codec::Encode;
use commonware_consensus::{
    Reporter,
    simplex::types::{
        Activity, ConflictingFinalize, ConflictingNotarize, Finalization, Finalize, Notarization,
        Notarize, Nullification, Nullify, NullifyFinalize, Proposal,
    },
    types::{Epoch, Round, View},
};
use commonware_consensus_fuzz_core::{
    PublicKeyOf, SimplexCertificateMock,
    network::{ActivityKind, CertificatePoison, LedgerRecord},
    simplex::Simplex,
};
use commonware_cryptography::{PublicKey, sha256::Digest as Sha256Digest};
use commonware_p2p::{CheckedSender, LimitedSender, Recipients};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::{IoBufs, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{iter::NonEmpty, sequence::U64, sync::Mutex};
use std::{
    any::Any,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, SystemTime},
};

const BASE_BYTES: [u8; 16] = [
    0x3c, 0x07, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x21, 0xfd, 0x07, 0xab, 0xe4, 0xe0, 0xb6,
];

fn decode<T: for<'a> Arbitrary<'a>>(bytes: &[u8]) -> T {
    T::arbitrary(&mut Unstructured::new(bytes)).expect("the acceptance input must decode")
}

fn fixed_input(tape: &[u8]) -> FuzzInput {
    FuzzInput {
        raw_bytes: tape.to_vec(),
        base: decode(&BASE_BYTES),
    }
}

fn fixed_inputs() -> [FuzzInput; 8] {
    [
        fixed_input(&[0x15]),
        fixed_input(&[0xb9]),
        fixed_input(&[0xf2]),
        fixed_input(&[0x78, 0x60, 0x97, 0x2e]),
        fixed_input(&[
            0x89, 0xcc, 0x5d, 0x6a, 0x31, 0x0e, 0x7d, 0xda, 0x39, 0x5e, 0xf2, 0xbf, 0xfa, 0x48,
            0x41, 0x65, 0x2a, 0x89, 0x32, 0xa6, 0xeb, 0x16, 0x54, 0xec, 0xd2, 0x91, 0xfe, 0x8e,
            0x58, 0xf5, 0xd7, 0x34, 0x1a, 0xe5, 0x0b, 0xf6, 0xac, 0xff, 0x4f, 0x55, 0x3b, 0xcd,
            0x81, 0xfd, 0xcb, 0x9b, 0x71, 0x2a, 0x8d, 0x36, 0xc2, 0xd0, 0x17, 0xe4, 0x82, 0x1e,
            0x09, 0x7a, 0x34, 0x89, 0x1f, 0x3a, 0x2d, 0xc8,
        ]),
        fixed_input(&[
            0xa7, 0x62, 0x68, 0x27, 0x4f, 0xcf, 0xd6, 0xed, 0xad, 0xbb, 0x23, 0x88, 0x01, 0x0d,
            0x7c, 0x38, 0x66, 0xfb, 0x6d, 0x54, 0xf5, 0x72, 0x46, 0xbc, 0x78, 0xa5, 0x6a, 0x0b,
            0x51, 0x19, 0xf8, 0xc7, 0xd5, 0xab, 0xae, 0x80, 0x8e, 0x22, 0x49, 0xe6, 0xa3, 0xa0,
            0xc7, 0xa8, 0x6b, 0x95, 0x67, 0x08, 0xe6, 0x31, 0x83, 0xb3, 0xc4, 0x02, 0x91, 0x33,
            0x21, 0x2b, 0x7b, 0x71, 0xae, 0x29, 0x19, 0x44,
        ]),
        fixed_input(&[0xbd]),
        fixed_input(&[
            0xc8, 0x31, 0x7b, 0x2f, 0x42, 0xfe, 0x0a, 0xa9, 0x97, 0x1a, 0x81, 0x45, 0x96, 0x43,
            0x36, 0x6e, 0xfb, 0xc4, 0xb8, 0xf5, 0x0a, 0xca, 0x3f, 0xa8, 0x37, 0x51, 0x05, 0x26,
            0x8b, 0xfc, 0xc0, 0xd3, 0x67, 0x9a, 0x65, 0x9c, 0x63, 0x66, 0xf0, 0x55, 0x54, 0xb3,
            0x8a, 0x0b, 0xac, 0x8a, 0x6e, 0x53, 0xe2, 0x21, 0x65, 0x38, 0xb6, 0x46, 0x2a, 0x79,
            0x4e, 0x1b, 0xbe, 0xbb, 0xef, 0x6f, 0xcf, 0x3a,
        ]),
    ]
}

fn panic_text(payload: Box<dyn Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else {
        "non-string panic".to_string()
    }
}

#[test]
fn deferred_poison_tape_suppressed_evidence_fails_the_retry_check() {
    for input in fixed_inputs() {
        let normal = standard::run(input.clone());
        let (view, at) = normal
            .poisoned
            .expect("backfill retry vacuous: the normal run must fire the poison");
        assert_eq!(normal.retry_check, RetryCheck::Held);
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
            standard::run_suppressed(input);
        }))
        .expect_err("suppressed evidence must fail the retry check");
        let text = panic_text(panic);
        assert!(text.starts_with("backfill retry:"), "{text}");
        assert!(text.contains(&format!("view {view}")), "{text}");
        assert!(text.contains(&format!("at {at:?}")), "{text}");
        assert!(text.contains("first later request: none"), "{text}");
        assert!(text.contains("first settling activity: none"), "{text}");
    }
}

#[test]
fn deferred_poison_tape_retry_check_respects_order_bound_and_settlement() {
    let view = View::new(4);
    let at = Duration::from_secs(5);
    let poisoned = LedgerRecord::Poisoned { view, at };
    assert_eq!(check_retry(&[], Duration::MAX), RetryCheck::NotFired);
    assert_eq!(
        check_retry(
            &[poisoned],
            at + super::RETRY_BOUND - Duration::from_nanos(1)
        ),
        RetryCheck::NotMeasured
    );

    for request_at in [at, at + super::RETRY_BOUND] {
        assert_eq!(
            check_retry(
                &[
                    poisoned,
                    LedgerRecord::Request {
                        view,
                        at: request_at,
                    },
                ],
                at + super::RETRY_BOUND,
            ),
            RetryCheck::Held
        );
    }

    let before_poison = [LedgerRecord::Request { view, at }, poisoned];
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        check_retry(&before_poison, at + super::RETRY_BOUND);
    }))
    .expect_err("a request before the poison must not count");
    let text = panic_text(panic);
    assert!(text.starts_with("backfill retry:"), "{text}");
    assert!(text.contains("first later request: none"), "{text}");

    let too_late = [
        poisoned,
        LedgerRecord::Request {
            view,
            at: at + super::RETRY_BOUND + Duration::from_nanos(1),
        },
    ];
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        check_retry(&too_late, at + super::RETRY_BOUND + Duration::from_nanos(1));
    }))
    .expect_err("a request after the bound must not count");

    for (kind, activity_view) in [
        (ActivityKind::Nullification, View::new(3)),
        (ActivityKind::Certification, view),
    ] {
        let ledger = [
            poisoned,
            LedgerRecord::Activity {
                kind,
                view: activity_view,
                at,
            },
        ];
        std::panic::catch_unwind(AssertUnwindSafe(|| {
            check_retry(&ledger, at + super::RETRY_BOUND);
        }))
        .expect_err("a non-settling activity must not count");
    }
    for (kind, activity_view, activity_at) in [
        (
            ActivityKind::Nullification,
            view,
            at - Duration::from_secs(1),
        ),
        (ActivityKind::Finalization, view, at),
        (ActivityKind::Certification, View::new(5), at),
    ] {
        assert_eq!(
            check_retry(
                &[
                    LedgerRecord::Activity {
                        kind,
                        view: activity_view,
                        at: activity_at,
                    },
                    poisoned,
                ],
                at + super::RETRY_BOUND,
            ),
            RetryCheck::Held
        );
    }
}

#[test]
fn deferred_poison_tape_ledger_is_inert_for_the_old_call() {
    for input in fixed_inputs() {
        let mut old = MarshalDisrupterInput {
            raw_bytes: input.raw_bytes.clone(),
            ..input.base.clone()
        };
        force_poison(&mut old);
        let poison = CertificatePoison::new();
        let (state, end, _) =
            run_standard_disrupter::<SimplexCertificateMock>(old, Some(poison.clone()), None, None);
        let report = standard::run(input);
        assert_eq!(state, report.state);
        assert_eq!(end, report.end);
        assert_eq!(poison.view(), report.poisoned.map(|(view, _)| view));
        assert_eq!(poison.retries_answered(), report.retries_answered);
    }
}

#[test]
fn deferred_poison_tape_retry_check_precedes_end_checks() {
    seams::reset();
    let report = standard::run(fixed_input(&[0x15]));
    assert_eq!(
        seams::take_trace(),
        vec![
            Event::RetryCheck(report.end, RetryCheck::Held),
            Event::CheckAllBlocks,
        ]
    );
}

#[test]
fn deferred_poison_tape_retry_check_precedes_both_stall_paths() {
    for missed in [vec![1], vec![3]] {
        seams::force_phase2_miss(missed.clone());
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
            standard::run(fixed_input(&[0x15]));
        }))
        .expect_err("the forced phase-2 miss must reach the stall panic");
        let trace = seams::take_trace();
        seams::reset();
        assert!(panic_text(panic).starts_with("marshal: no post-GST progress"));
        assert!(matches!(
            trace.first(),
            Some(Event::RetryCheck(_, RetryCheck::Held))
        ));
        assert_eq!(trace.get(1), Some(&Event::OnStall(missed.clone())));
        if missed.contains(&3) {
            assert_eq!(trace.get(2), Some(&Event::BackfillCheck));
            assert_eq!(trace.get(3), Some(&Event::StallPanic));
        } else {
            assert_eq!(trace.get(2), Some(&Event::StallPanic));
        }
        assert!(!trace.contains(&Event::CheckAllBlocks));
    }
}

#[test]
fn deferred_poison_tape_non_ledger_run_keeps_the_old_end_order() {
    let input = fixed_input(&[0x15]);
    let mut old = MarshalDisrupterInput {
        raw_bytes: input.raw_bytes,
        ..input.base
    };
    force_poison(&mut old);
    seams::reset();
    let _ = run_standard_disrupter::<SimplexCertificateMock>(
        old,
        Some(CertificatePoison::new()),
        None,
        None,
    );
    assert_eq!(seams::take_trace(), vec![Event::CheckAllBlocks]);
}

#[test]
fn deferred_poison_tape_non_ledger_run_keeps_the_old_stall_order() {
    for missed in [vec![1], vec![3]] {
        let input = fixed_input(&[0x15]);
        let mut old = MarshalDisrupterInput {
            raw_bytes: input.raw_bytes,
            ..input.base
        };
        force_poison(&mut old);
        seams::force_phase2_miss(missed.clone());
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
            run_standard_disrupter::<SimplexCertificateMock>(
                old,
                Some(CertificatePoison::new()),
                None,
                None,
            );
        }))
        .expect_err("the forced phase-2 miss must reach the stall panic");
        let trace = seams::take_trace();
        seams::reset();
        assert!(panic_text(panic).starts_with("marshal: no post-GST progress"));
        let mut expected = vec![Event::OnStall(missed.clone())];
        if missed.contains(&3) {
            expected.push(Event::BackfillCheck);
        }
        expected.push(Event::StallPanic);
        assert_eq!(trace, expected);
    }
}

#[test]
fn deferred_poison_tape_standard_fetch_timing_is_fixed() {
    assert_eq!(FETCH_RETRY_DELAY, Duration::from_millis(100));
    assert_eq!(FETCH_TIMEOUT, Duration::from_secs(1));
    eprintln!("fetch retry delay: {FETCH_RETRY_DELAY:?}; fetch timeout: {FETCH_TIMEOUT:?}");
}

type Sent<K> = Arc<Mutex<Vec<(Vec<K>, Vec<u8>, bool)>>>;

#[derive(Clone)]
struct RecordingSender<K: PublicKey> {
    recipients: Vec<K>,
    sent: Sent<K>,
    result: Unreliable<Feedback>,
}

struct RecordingChecked<K: PublicKey> {
    recipients: Vec<K>,
    sent: Sent<K>,
    result: Unreliable<Feedback>,
}

impl<K: PublicKey> LimitedSender for RecordingSender<K> {
    type PublicKey = K;
    type Checked<'a>
        = RecordingChecked<K>
    where
        Self: 'a;

    fn check(&mut self, recipients: Recipients<K>) -> Result<Self::Checked<'_>, SystemTime> {
        let recipients = match recipients {
            Recipients::All => self.recipients.clone(),
            Recipients::Some(recipients) => recipients,
            Recipients::One(recipient) => vec![recipient],
        };
        Ok(RecordingChecked {
            recipients,
            sent: self.sent.clone(),
            result: self.result,
        })
    }
}

impl<K: PublicKey> CheckedSender for RecordingChecked<K> {
    type PublicKey = K;

    fn recipients(&self) -> Vec<K> {
        self.recipients.clone()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        self.sent.lock().push((
            self.recipients,
            message.into().coalesce().as_ref().to_vec(),
            priority,
        ));
        self.result
    }
}

#[test]
fn deferred_poison_tape_sender_records_requests_and_forwards_bytes_and_result() {
    type Key = PublicKeyOf<SimplexCertificateMock>;
    let runner = deterministic::Runner::new(deterministic::Config::new());
    runner.start(|mut context| async move {
        let (participants, _) =
            SimplexCertificateMock::setup(&mut context, b"acceptance_sender", 4);
        let poison = CertificatePoison::<Key>::with_ledger();
        poison.start_ledger(context.child("acceptance_sender_ledger"));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingSender {
            recipients: participants.clone(),
            sent: sent.clone(),
            result: Unreliable::new(Feedback::Backoff),
        };
        let mut sender = LedgerSender::new(inner, Some(poison.clone()));
        let request = |id, view| {
            ResolverMessage::<U64> {
                id,
                payload: ResolverPayload::Request(U64::from(view)),
            }
            .encode()
            .to_vec()
        };
        let request_nine = request(7, 9u64);
        let request_ten = request(8, 10u64);
        let response = ResolverMessage::<U64> {
            id: 7,
            payload: ResolverPayload::Response(vec![1, 2, 3].into()),
        }
        .encode()
        .to_vec();
        let malformed = vec![0xff, 0x00, 0x7f];
        let without_recipients = request(11, 11u64);
        for (recipients, message, priority) in [
            (
                Recipients::One(participants[1].clone()),
                request_nine.clone(),
                true,
            ),
            (
                Recipients::One(participants[1].clone()),
                response.clone(),
                false,
            ),
            (
                Recipients::One(participants[0].clone()),
                request_ten.clone(),
                false,
            ),
            (
                Recipients::One(participants[1].clone()),
                malformed.clone(),
                false,
            ),
            (
                Recipients::Some(Vec::new()),
                without_recipients.clone(),
                true,
            ),
        ] {
            let result = sender.check(recipients).unwrap().send(message, priority);
            assert_eq!(result, Unreliable::new(Feedback::Backoff));
        }
        assert_eq!(
            *sent.lock(),
            vec![
                (vec![participants[1].clone()], request_nine, true),
                (vec![participants[1].clone()], response, false),
                (vec![participants[0].clone()], request_ten, false),
                (vec![participants[1].clone()], malformed, false),
                (Vec::new(), without_recipients, true),
            ]
        );
        assert_eq!(
            poison.ledger(),
            vec![
                LedgerRecord::Request {
                    view: View::new(9),
                    at: Duration::ZERO,
                },
                LedgerRecord::Request {
                    view: View::new(10),
                    at: Duration::ZERO,
                },
            ]
        );
        poison.stop_ledger();

        let sent_without_ledger = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingSender {
            recipients: participants.clone(),
            sent: sent_without_ledger.clone(),
            result: Unreliable::new(Feedback::Backoff),
        };
        let mut sender = LedgerSender::new(inner, None);
        let request = request(12, 12u64);
        let result = sender
            .check(Recipients::One(participants[1].clone()))
            .unwrap()
            .send(request.clone(), true);
        assert_eq!(result, Unreliable::new(Feedback::Backoff));
        assert_eq!(
            *sent_without_ledger.lock(),
            vec![(vec![participants[1].clone()], request, true)]
        );
    });
}

#[derive(Clone)]
struct RecordingReporter<A> {
    seen: Arc<Mutex<Vec<A>>>,
    feedback: Feedback,
}

impl<A: Clone + Send + 'static> Reporter for RecordingReporter<A> {
    type Activity = A;

    fn report(&mut self, activity: A) -> Feedback {
        self.seen.lock().push(activity);
        self.feedback
    }
}

type MockScheme = <SimplexCertificateMock as Simplex>::Scheme;
type MockActivity = Activity<MockScheme, Sha256Digest>;

fn proposal_with_payload(view: u64, parent: u64, payload: u8) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::zero(), View::new(view)),
        View::new(parent),
        Sha256Digest([payload; 32]),
    )
}

fn proposal(view: u64, parent: u64) -> Proposal<Sha256Digest> {
    proposal_with_payload(view, parent, view as u8)
}

fn nullification(schemes: &[MockScheme], view: u64) -> Nullification<MockScheme> {
    let votes = schemes[..3]
        .iter()
        .map(|scheme| {
            Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::zero(), View::new(view)))
                .unwrap()
        })
        .collect::<Vec<_>>();
    Nullification::from_nullifies(
        &schemes[0],
        NonEmpty::try_new(votes.iter()).unwrap(),
        &Sequential,
    )
    .unwrap()
}

fn notarization(schemes: &[MockScheme], view: u64) -> Notarization<MockScheme, Sha256Digest> {
    let votes = schemes[..3]
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal(view, view - 1)).unwrap())
        .collect::<Vec<_>>();
    Notarization::from_notarizes(
        &schemes[0],
        NonEmpty::try_new(votes.iter()).unwrap(),
        &Sequential,
    )
    .unwrap()
}

fn finalization(schemes: &[MockScheme], view: u64) -> Finalization<MockScheme, Sha256Digest> {
    let votes = schemes[..3]
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal(view, view - 1)).unwrap())
        .collect::<Vec<_>>();
    Finalization::from_finalizes(
        &schemes[0],
        NonEmpty::try_new(votes.iter()).unwrap(),
        &Sequential,
    )
    .unwrap()
}

#[test]
fn deferred_poison_tape_reporter_records_selected_activity_and_forwards_everything() {
    type Key = MarshalPublicKeyOf<SimplexCertificateMock>;
    let runner = deterministic::Runner::new(deterministic::Config::new());
    runner.start(|mut context| async move {
        let (_, schemes) = SimplexCertificateMock::setup(&mut context, b"acceptance_reporter", 4);
        let poison = CertificatePoison::<Key>::with_ledger();
        poison.start_ledger(context.child("acceptance_reporter_ledger"));
        let seen = Arc::new(Mutex::new(Vec::<MockActivity>::new()));
        let inner = RecordingReporter {
            seen: seen.clone(),
            feedback: Feedback::Backoff,
        };
        let mut reporter = LedgerReporter::<_, Key>::new(inner, Some(poison.clone()));
        let notarize = Notarize::sign(&schemes[0], proposal(2, 1)).unwrap();
        let other_notarize = Notarize::sign(&schemes[0], proposal_with_payload(2, 1, 22)).unwrap();
        let nullify =
            Nullify::sign::<Sha256Digest>(&schemes[0], Round::new(Epoch::zero(), View::new(6)))
                .unwrap();
        let finalize = Finalize::sign(&schemes[0], proposal(7, 6)).unwrap();
        let other_finalize = Finalize::sign(&schemes[0], proposal_with_payload(7, 6, 77)).unwrap();
        let conflicting_nullify =
            Nullify::sign::<Sha256Digest>(&schemes[0], Round::new(Epoch::zero(), View::new(8)))
                .unwrap();
        let conflicting_finalize = Finalize::sign(&schemes[0], proposal(8, 7)).unwrap();
        let activities = vec![
            Activity::Notarize(notarize.clone()),
            Activity::Notarization(notarization(&schemes, 2)),
            Activity::Nullify(nullify),
            Activity::Finalize(finalize.clone()),
            Activity::ConflictingNotarize(ConflictingNotarize::new(notarize, other_notarize)),
            Activity::ConflictingFinalize(ConflictingFinalize::new(finalize, other_finalize)),
            Activity::NullifyFinalize(NullifyFinalize::new(
                conflicting_nullify,
                conflicting_finalize,
            )),
            Activity::Nullification(nullification(&schemes, 3)),
            Activity::Finalization(finalization(&schemes, 4)),
            Activity::Certification(notarization(&schemes, 5)),
        ];
        for activity in activities.iter().cloned() {
            assert_eq!(reporter.report(activity), Feedback::Backoff);
        }
        assert_eq!(*seen.lock(), activities);
        assert_eq!(
            poison.ledger(),
            vec![
                LedgerRecord::Activity {
                    kind: ActivityKind::Nullification,
                    view: View::new(3),
                    at: Duration::ZERO,
                },
                LedgerRecord::Activity {
                    kind: ActivityKind::Finalization,
                    view: View::new(4),
                    at: Duration::ZERO,
                },
                LedgerRecord::Activity {
                    kind: ActivityKind::Certification,
                    view: View::new(5),
                    at: Duration::ZERO,
                },
            ]
        );
        poison.stop_ledger();

        let seen_without_ledger = Arc::new(Mutex::new(Vec::<MockActivity>::new()));
        let inner = RecordingReporter {
            seen: seen_without_ledger.clone(),
            feedback: Feedback::Backoff,
        };
        let mut reporter = LedgerReporter::<_, Key>::new(inner, None);
        for activity in activities.iter().cloned() {
            assert_eq!(reporter.report(activity), Feedback::Backoff);
        }
        assert_eq!(*seen_without_ledger.lock(), activities);
    });
}
