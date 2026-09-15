use super::{fixtures, native_fixtures};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    challenge::{AccountLookup, ChangeAbsence, ChangeOpening},
    commitment::{self, VectorKind},
    logs::{Floors, LogHead, Logs, Opening, PayoutOperation},
    state::{AccountChange, AccountRow, SettlementOutput},
    transition::{ActivityRange, WithdrawalClaim, WithdrawalOutput},
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, RangeCfg};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::StrictVerifyingKey as VerifyingKey;
use commonware_parallel::Rayon;
use commonware_runtime::{Runner as _, deterministic};
use commonware_storage::{merkle::Location, mmr, qmdb};
use criterion::{Criterion, criterion_group};
use std::{hint::black_box, num::NonZeroU64};

type NativeLogs = Logs<deterministic::Context, Sha256, VerifyingKey, Rayon>;
const FLOORS: Floors = Floors {
    activity: 0,
    payouts: 0,
};

struct ActivityCase {
    label: String,
    range: ActivityRange<Digest>,
    account: VerifyingKey,
    lookup: AccountLookup<VerifyingKey, Digest>,
    present: bool,
}

impl ActivityCase {
    fn verify(&self) {
        let (debit, change) = self
            .lookup
            .resolve::<Sha256>(&self.range, &self.account)
            .unwrap();
        assert_eq!(debit, 0);
        assert_eq!(change.is_some(), self.present);
    }
}

#[commonware_macros::boxed]
async fn activity_cases(
    runtime: deterministic::Context,
    history: usize,
    rows: usize,
) -> Vec<ActivityCase> {
    let keys = fixtures::accounts((rows.max(history) * 2 + 1).max(3));
    let empty = commitment::empty_root::<Sha256>(VectorKind::OutEntry);
    let changes = keys
        .iter()
        .skip(1)
        .step_by(2)
        .map(|(account, _)| {
            AccountChange::from_row(
                &AccountRow {
                    account: account.clone(),
                    predecessor: 10,
                    successor: 10,
                    outgoing: None,
                    output: SettlementOutput::None,
                },
                empty,
            )
        })
        .collect::<Vec<_>>();
    let cfg = fixtures::logs_config(&runtime, "activity-measurement");
    let mut logs = NativeLogs::open(runtime, cfg).await.unwrap();
    if history > 0 {
        let batch = logs
            .prepare(
                logs.head(),
                commonware_clearing::bajillion::logs::ActivityInput::new(
                    changes[..history].to_vec(),
                    vec![],
                ),
                vec![],
                FLOORS,
            )
            .await
            .unwrap();
        logs = logs.apply(batch).await.unwrap();
    }
    let start = logs.head().activity.operations;
    let batch = logs
        .prepare(
            logs.head(),
            commonware_clearing::bajillion::logs::ActivityInput::new(
                changes[..rows].to_vec(),
                vec![],
            ),
            vec![],
            FLOORS,
        )
        .await
        .unwrap();
    logs = logs.apply(batch).await.unwrap();
    let range = ActivityRange {
        start,
        end: start + rows as u64,
        head: logs.head().activity,
    };
    assert_eq!(range.head.operations, range.end + 1);
    let key = format!(
        "H={history} R={rows} operations={} floor={}",
        range.head.operations, range.head.floor
    );
    let mut cases = Vec::new();
    if rows > 0 {
        let position = rows / 2;
        let (proof, _) = logs
            .activity_opening(&range.head, start + position as u64, NonZeroU64::MIN)
            .await
            .unwrap();
        cases.push(ActivityCase {
            label: format!("presence/{key}"),
            range,
            account: changes[position].account().clone(),
            lookup: AccountLookup::Present(Box::new(ChangeOpening {
                value: changes[position].value(),
                proof,
            })),
            present: true,
        });
    }
    let gaps = if rows == 0 {
        vec![("empty", 0)]
    } else if rows == 1 {
        vec![("left", 0), ("right", rows)]
    } else {
        vec![("left", 0), ("adjacent", rows / 2), ("right", rows)]
    };
    for (kind, gap) in gaps {
        let left = gap.saturating_sub(1);
        let right = (gap + 1).min(rows);
        let opening = if rows == 0 {
            None
        } else {
            Some(
                logs.activity_opening(
                    &range.head,
                    start + left as u64,
                    NonZeroU64::new((right - left) as u64).unwrap(),
                )
                .await
                .unwrap()
                .0,
            )
        };
        cases.push(ActivityCase {
            label: format!("absence_{kind}/{key}"),
            range,
            account: keys[if rows == 0 && history > 0 { 1 } else { gap * 2 }]
                .0
                .clone(),
            lookup: AccountLookup::Absent(ChangeAbsence {
                predecessor: gap.checked_sub(1).map(|i| changes[i].clone()),
                successor: changes.get(gap).filter(|_| gap < rows).cloned(),
                opening,
            }),
            present: false,
        });
    }
    for case in &cases {
        case.verify();
        let encoded = case.lookup.encode();
        let decoded = AccountLookup::<VerifyingKey, Digest>::decode(encoded.clone()).unwrap();
        assert_eq!(decoded, case.lookup);
        assert_eq!(decoded.encode(), encoded);
    }
    cases
}

enum PayoutProof {
    Claim(WithdrawalClaim<Digest>),
    Commit(Opening<Digest>, Vec<PayoutOperation>),
}

struct PayoutCase {
    label: String,
    head: LogHead<Digest>,
    proof: PayoutProof,
}

impl PayoutCase {
    fn verify(&self) {
        match &self.proof {
            PayoutProof::Claim(claim) => {
                assert_eq!(claim.verify::<Sha256>(&self.head).unwrap(), *claim.output())
            }
            PayoutProof::Commit(opening, operations) => {
                assert_eq!(opening.start + 1, self.head.operations);
                assert_eq!(operations.len(), 1);
                assert!(matches!(operations[0], PayoutOperation::Commit(..)));
                assert!(qmdb::verify_proof::<Sha256, mmr::Family, _>(
                    &opening.proof,
                    Location::new(opening.start),
                    operations,
                    &self.head.root
                ));
            }
        }
    }

    fn bytes(&self) -> (usize, usize) {
        match &self.proof {
            PayoutProof::Claim(claim) => {
                let bytes = claim.encode().len();
                let decoded =
                    WithdrawalClaim::<Digest>::decode_cfg(claim.encode(), &RangeCfg::new(0..=1024))
                        .unwrap();
                assert_eq!(&decoded, claim);
                (bytes - claim.output().encode().len(), bytes)
            }
            PayoutProof::Commit(opening, ops) => (
                opening.encode().len(),
                opening.encode().len() + ops[0].encode().len(),
            ),
        }
    }
}

fn output(index: usize) -> WithdrawalOutput {
    WithdrawalOutput::decode_cfg(
        (Bytes::from(format!("exit-{index:016}")), 1_u64).encode(),
        &RangeCfg::new(0..=1024),
    )
    .unwrap()
}

async fn payout_case(
    logs: &NativeLogs,
    head: LogHead<Digest>,
    position: u64,
    label: String,
) -> PayoutCase {
    let (opening, operations) = logs
        .payout_opening(&head, position, NonZeroU64::MIN)
        .await
        .unwrap();
    let proof = match &operations[0] {
        PayoutOperation::Append(value) => {
            PayoutProof::Claim(WithdrawalClaim::new(value.clone(), opening))
        }
        PayoutOperation::Commit(..) => PayoutProof::Commit(opening, operations),
    };
    let case = PayoutCase { label, head, proof };
    case.verify();
    case
}

#[commonware_macros::boxed]
async fn payout_cases(
    runtime: deterministic::Context,
    history: usize,
    count: usize,
    accounts: usize,
) -> Vec<PayoutCase> {
    let cfg = fixtures::logs_config(&runtime, "payout-measurement");
    let mut logs = NativeLogs::open(runtime, cfg).await.unwrap();
    if history > 0 {
        let batch = logs
            .prepare(
                logs.head(),
                commonware_clearing::bajillion::logs::ActivityInput::new(vec![], vec![]),
                (0..history).map(output).collect(),
                FLOORS,
            )
            .await
            .unwrap();
        logs = logs.apply(batch).await.unwrap();
    }
    let historical = logs.head().payouts;
    let start = historical.operations;
    let batch = logs
        .prepare(
            logs.head(),
            commonware_clearing::bajillion::logs::ActivityInput::new(vec![], vec![]),
            (0..count).map(output).collect(),
            FLOORS,
        )
        .await
        .unwrap();
    logs = logs.apply(batch).await.unwrap();
    let issued = logs.head().payouts;
    assert_eq!(issued.operations, start + count as u64 + 1);
    let key = format!("H={history} W={count} N={accounts}");
    let mut cases = Vec::new();
    if history > 0 {
        cases.push(payout_case(&logs, historical, 1, format!("historical/{key}")).await);
        cases.push(payout_case(&logs, issued, 1, format!("historical_refreshed/{key}")).await);
    }
    if count == 0 {
        cases.push(payout_case(&logs, issued, start, format!("empty_commit/{key}")).await);
    } else {
        for (kind, offset) in [("first", 0), ("middle", count / 2), ("last", count - 1)] {
            cases.push(
                payout_case(
                    &logs,
                    issued,
                    start + offset as u64,
                    format!("current_{kind}/{key}"),
                )
                .await,
            );
        }

        // Retained native rows support refreshed proofs after the signed floor advances.
        let old = logs
            .payout_opening(&issued, start, NonZeroU64::MIN)
            .await
            .unwrap()
            .0;
        for (kind, floor) in [
            ("old_after_append", 0),
            ("old_after_floor", issued.operations - 1),
        ] {
            let floors = Floors {
                activity: 0,
                payouts: floor,
            };
            let batch = logs
                .prepare(
                    logs.head(),
                    commonware_clearing::bajillion::logs::ActivityInput::new(vec![], vec![]),
                    vec![output(count)],
                    floors,
                )
                .await
                .unwrap();
            logs = logs.apply(batch).await.unwrap();
            let head = logs.head().payouts;
            assert!(old.verify_payout::<Sha256>(&head, &output(0)).is_err());
            cases.push(payout_case(&logs, head, start, format!("{kind}/{key}")).await);
        }
    }
    cases
}

fn visit_activity(mut visit: impl FnMut(ActivityCase)) {
    for history in native_fixtures::histories() {
        for rows in native_fixtures::rows() {
            for case in fixtures::runner().start(|runtime| activity_cases(runtime, history, rows)) {
                visit(case);
            }
        }
    }
}

fn visit_payout(mut visit: impl FnMut(PayoutCase)) {
    let accounts = native_fixtures::accounts();
    for history in native_fixtures::histories() {
        for count in native_fixtures::payouts(accounts) {
            for case in
                fixtures::runner().start(|runtime| payout_cases(runtime, history, count, accounts))
            {
                visit(case);
            }
        }
    }
}

pub(crate) fn activity_sizes() {
    visit_activity(|case| {
        println!(
            "native_activity {} lookup_bytes={} head_bytes={}",
            case.label,
            case.lookup.encode().len(),
            case.range.head.encode().len()
        )
    });
}

pub(crate) fn payout_sizes() {
    visit_payout(|case| {
        let (opening, complete) = case.bytes();
        println!(
            "native_payout {} operations={} floor={} opening_bytes={opening} artifact_bytes={complete} head_bytes={}",
            case.label,
            case.head.operations,
            case.head.floor,
            case.head.encode().len()
        );
    });
}

pub(crate) fn sizes() {
    activity_sizes();
    payout_sizes();
}

fn bench_activity(c: &mut Criterion) {
    let mut activity = Vec::new();
    visit_activity(|case| activity.push(case));
    for case in activity {
        c.bench_function(
            &format!("{}::activity_verify/{}", module_path!(), case.label),
            |b| {
                b.iter(|| {
                    black_box(
                        black_box(&case.lookup)
                            .resolve::<Sha256>(black_box(&case.range), black_box(&case.account)),
                    )
                })
            },
        );
    }
}

fn bench_payout(c: &mut Criterion) {
    let mut payout = Vec::new();
    visit_payout(|case| payout.push(case));
    for case in payout {
        c.bench_function(
            &format!(
                "{}::payout_verify/{} operations={} floor={}",
                module_path!(),
                case.label,
                case.head.operations,
                case.head.floor
            ),
            |b| match &case.proof {
                PayoutProof::Claim(claim) => {
                    b.iter(|| black_box(black_box(claim).verify::<Sha256>(black_box(&case.head))))
                }
                PayoutProof::Commit(opening, operations) => b.iter(|| {
                    black_box(qmdb::verify_proof::<Sha256, mmr::Family, _>(
                        black_box(&opening.proof),
                        Location::new(opening.start),
                        black_box(operations),
                        black_box(&case.head.root),
                    ))
                }),
            },
        );
    }
}

criterion_group! { name = activity_benches; config = Criterion::default().sample_size(20); targets = bench_activity, }
criterion_group! { name = payout_benches; config = Criterion::default().sample_size(20); targets = bench_payout, }
criterion_group! { name = benches; config = Criterion::default().sample_size(20); targets = bench_activity, bench_payout, }
