use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{simplex::ForwardPolicy, types::View};
use commonware_consensus_fuzz_core::{
    PublicKeyOf, SimplexCertificateMock,
    network::{ActivityKind, CertificatePoison, LedgerRecord},
};
use commonware_consensus_fuzz_marshal::marshal::{
    MarshalDisrupterInput,
    poison_tape::{FuzzInput, RETRY_BOUND, RetryCheck, standard},
};
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
use std::{any::Any, panic::AssertUnwindSafe, time::Duration};

const BASE_BYTES: [u8; 16] = [
    0x3c, 0x07, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x21, 0xfd, 0x07, 0xab, 0xe4, 0xe0, 0xb6,
];
const MAX_RAW_BYTES: usize = 32_768;

fn decode<T: for<'a> Arbitrary<'a>>(bytes: &[u8]) -> T {
    T::arbitrary(&mut Unstructured::new(bytes)).expect("the acceptance input must decode")
}

fn fixed_input(tape: &[u8]) -> FuzzInput {
    let base = decode::<MarshalDisrupterInput>(&BASE_BYTES);
    assert_eq!(base.required_containers, 7);
    assert!(matches!(base.forwarding, ForwardPolicy::Disabled));
    FuzzInput {
        raw_bytes: tape.to_vec(),
        base,
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

fn assert_same_base(actual: &MarshalDisrupterInput, expected: &MarshalDisrupterInput) {
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

fn assert_decode(bytes: &[u8]) {
    let actual = decode::<FuzzInput>(bytes);
    let expected = decode::<MarshalDisrupterInput>(bytes);
    assert_eq!(actual.raw_bytes, bytes[..bytes.len().min(MAX_RAW_BYTES)]);
    assert_same_base(&actual.base, &expected);
}

fn settling_for(view: View, record: LedgerRecord) -> Option<(ActivityKind, View, Duration)> {
    let LedgerRecord::Activity {
        kind,
        view: at_view,
        at,
    } = record
    else {
        return None;
    };
    match kind {
        ActivityKind::Nullification if at_view == view => Some((kind, at_view, at)),
        ActivityKind::Finalization if at_view >= view => Some((kind, at_view, at)),
        ActivityKind::Certification if at_view > view => Some((kind, at_view, at)),
        _ => None,
    }
}

fn assert_held_report(input: FuzzInput) -> Option<Duration> {
    let report = standard::run(input);
    let (poison_index, view, t0) = report
        .ledger
        .iter()
        .enumerate()
        .find_map(|(index, record)| match *record {
            LedgerRecord::Poisoned { view, at } => Some((index, view, at)),
            _ => None,
        })
        .expect("backfill retry vacuous: the poison did not fire");
    assert_eq!(report.poisoned, Some((view, t0)));

    let request = report.ledger[poison_index + 1..]
        .iter()
        .find_map(|record| match *record {
            LedgerRecord::Request {
                view: requested,
                at,
            } if requested == view => Some(at),
            _ => None,
        });
    let settling = report
        .ledger
        .iter()
        .find_map(|record| settling_for(view, *record));
    assert_eq!(report.first_request, request);
    assert_eq!(report.first_settling, settling);
    assert!(
        report.retry_check == RetryCheck::Held,
        "backfill retry vacuous: expected a measured run, got {:?}",
        report.retry_check
    );
    assert!(
        report.end >= t0 + RETRY_BOUND,
        "backfill retry vacuous: the run ended before the retry bound"
    );
    assert!(
        request.is_some_and(|at| at <= t0 + RETRY_BOUND)
            || settling.is_some_and(|(_, _, at)| at <= t0 + RETRY_BOUND),
        "backfill retry: report does not contain timely retry or settlement evidence: {report:?}"
    );
    request.map(|at| at - t0)
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
fn deferred_poison_tape_public_entries_accept_a_constructed_value() {
    let input = fixed_input(&[0x15]);
    let report = standard::run(input.clone());
    assert_eq!(report.retry_check, RetryCheck::Held);
    standard::fuzz(input);
}

#[test]
fn deferred_poison_tape_decoding_preserves_the_full_input_and_base() {
    assert_decode(&[]);
    assert_decode(&[0; 64]);
    assert_decode(&[0xff; 64]);

    for byte in 0..=u8::MAX {
        assert_decode(&[byte]);
    }
    for length in [15, 16, 17, 32_768, 32_769] {
        let bytes = (0..length)
            .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
            .collect::<Vec<_>>();
        assert_decode(&bytes);
    }
    for case in 0..1_000usize {
        let length = case.wrapping_mul(73) % 257;
        let bytes = (0..length)
            .map(|index| {
                (case as u8)
                    .wrapping_mul(29)
                    .wrapping_add((index as u8).wrapping_mul(101))
            })
            .collect::<Vec<_>>();
        assert_decode(&bytes);
    }
}

macro_rules! fixed_case {
    ($name:ident, $index:expr) => {
        #[test]
        fn $name() {
            let input = fixed_inputs().into_iter().nth($index).unwrap();
            let _ = assert_held_report(input);
        }
    };
}

fixed_case!(deferred_poison_tape_f14_1, 0);
fixed_case!(deferred_poison_tape_f14_2, 1);
fixed_case!(deferred_poison_tape_f14_3, 2);
fixed_case!(deferred_poison_tape_f14_4, 3);
fixed_case!(deferred_poison_tape_f14_5, 4);
fixed_case!(deferred_poison_tape_f14_6, 5);
fixed_case!(deferred_poison_tape_f14_7_false_positive_guard, 6);
fixed_case!(deferred_poison_tape_f14_8_false_positive_guard, 7);

#[test]
fn deferred_poison_tape_reports_are_recomputable_and_have_timing_margin() {
    let largest = fixed_inputs()
        .into_iter()
        .filter_map(assert_held_report)
        .max()
        .expect("at least one fixed case must send a retry");
    eprintln!("largest qualifying retry delta: {largest:?}");
    assert!(
        largest <= Duration::from_millis(500),
        "the retry timing margin exceeded 500 ms: {largest:?}"
    );
}

#[test]
fn deferred_poison_tape_empty_input_runs_a_complete_scenario() {
    let input = decode::<FuzzInput>(&[]);
    let old = decode::<MarshalDisrupterInput>(&[]);
    assert!(input.raw_bytes.is_empty());
    assert_same_base(&input.base, &old);
    assert_eq!(input.base.required_containers, 1);
    assert!(matches!(input.base.forwarding, ForwardPolicy::Disabled));
    standard::fuzz(input.clone());
    let report = standard::run(input);
    let expected = match report.poisoned {
        None => RetryCheck::NotFired,
        Some((_, at)) if report.end < at + RETRY_BOUND => RetryCheck::NotMeasured,
        Some(_) => RetryCheck::Held,
    };
    assert_eq!(report.retry_check, expected);
}

#[test]
fn deferred_poison_tape_replays_deterministically() {
    let input = fixed_input(&[0x15]);
    assert_eq!(standard::run(input.clone()), standard::run(input));
}

#[test]
fn deferred_poison_tape_ledger_requires_the_run_clock_and_keeps_one_order() {
    type Key = PublicKeyOf<SimplexCertificateMock>;

    let poison = CertificatePoison::<Key>::with_ledger();
    assert!(poison.armed());
    assert!(poison.has_ledger());
    assert!(poison.ledger().is_empty());
    assert_eq!(poison.view(), None);
    assert_eq!(poison.retries_answered(), 0);
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        poison.record_request(View::new(4));
    }))
    .expect_err("a ledger request without a clock must panic");
    assert!(panic_text(panic).starts_with("poison ledger: no clock"));
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        poison.record_activity(ActivityKind::Certification, View::new(5));
    }))
    .expect_err("a ledger activity without a clock must panic");
    assert!(panic_text(panic).starts_with("poison ledger: no clock"));

    let unrecorded = CertificatePoison::<Key>::new();
    assert!(!unrecorded.has_ledger());
    unrecorded.record_request(View::new(1));
    unrecorded.record_activity(ActivityKind::Finalization, View::new(1));
    assert!(unrecorded.ledger().is_empty());
    let disarmed = CertificatePoison::<Key>::disarmed();
    assert!(!disarmed.armed());
    assert!(!disarmed.has_ledger());
    disarmed.record_request(View::new(1));
    assert!(disarmed.ledger().is_empty());
    disarmed.arm();
    assert!(disarmed.armed());

    let expected = vec![
        LedgerRecord::Request {
            view: View::new(4),
            at: Duration::ZERO,
        },
        LedgerRecord::Activity {
            kind: ActivityKind::Certification,
            view: View::new(5),
            at: Duration::from_millis(7),
        },
    ];
    let expected_in_run = expected.clone();
    let runner = deterministic::Runner::new(deterministic::Config::new());
    let recorded = poison.clone();
    runner.start(|context| async move {
        recorded.start_ledger(context.child("acceptance_ledger"));
        recorded.record_request(View::new(4));
        context.sleep(Duration::from_millis(7)).await;
        recorded.record_activity(ActivityKind::Certification, View::new(5));
        assert_eq!(recorded.ledger(), expected_in_run);
        recorded.stop_ledger();
    });
    assert_eq!(poison.ledger(), expected);
}
