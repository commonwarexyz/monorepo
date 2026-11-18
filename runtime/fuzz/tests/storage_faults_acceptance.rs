//! Acceptance tests derived from `runtime/fuzz/SPEC.md` and
//! `storage-faults-acceptance.md`.

use arbitrary::{Arbitrary, Unstructured};
use bytes::Buf as _;
use commonware_runtime::{
    Blob, BlobVersion, Error, Handle, IoBufs, IoBufsMut, ReadOptions, Storage, WriteOptions,
    deterministic::{self, FaultConfig, PartialWriteMode},
};
use commonware_runtime_fuzz::{
    SEED_BYTES,
    storage_faults::{
        BlobName, Call, CallResult, Entry, Fault, FuzzInput, Invariant, MAX_OFFSET, MAX_OPS,
        MAX_SIZE, MAX_WRITE, Op, Origin, PartitionName, Record, ResizeFault, Rule, Verify,
        WriteFault, fuzz, reachable, run, sample_armed, sample_write_fails,
    },
    storage_model::{Offset, value},
};
use commonware_utils::sync::{Mutex, RwLock};
use futures::{StreamExt as _, stream};
use std::{
    collections::BTreeSet,
    ops::RangeInclusive,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Instant,
};

fn decoded(bytes: &[u8]) -> FuzzInput {
    FuzzInput::arbitrary(&mut Unstructured::new(bytes)).expect("every input length must decode")
}

#[test]
fn acceptance_at_019_decoding_pin_matches_extracted_input() {
    use commonware_cryptography::{Hasher, Sha256};
    use std::fmt::Write as _;

    let mut inputs = vec![("empty".to_string(), Vec::new())];
    inputs.extend((0u64..=255).map(|seed| (format!("seed{seed:03}"), seed.to_le_bytes().to_vec())));
    let mut actual = String::new();
    for (name, bytes) in inputs {
        let input = commonware_runtime_fuzz::storage_model::FuzzInput::arbitrary_take_rest(
            Unstructured::new(&bytes),
        )
        .expect("fixed input must decode");
        writeln!(actual, "{name}\t{input:?}").expect("writing to a string cannot fail");
    }
    assert_eq!(
        Sha256::hash(&[actual.as_bytes()]).as_ref(),
        &[
            166, 33, 17, 40, 203, 184, 10, 157, 40, 51, 179, 195, 240, 63, 0, 27, 95, 54, 248, 24,
            139, 236, 29, 37, 28, 122, 251, 194, 181, 32, 213, 224,
        ],
        "post-extraction decoding differs from the pre-move pin"
    );
}

mod extracted_model_pin {
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_runtime_fuzz::storage_model::*;

    include!("storage_faults_acceptance_model_pin.inc");

    #[test]
    fn acceptance_at_021_model_pin_matches_extracted_model() {
        assert_eq!(
            Sha256::hash(&[model_sequences().as_bytes()]).as_ref(),
            &[
                67, 193, 155, 173, 153, 215, 18, 13, 92, 47, 117, 70, 97, 216, 119, 53, 55, 208,
                71, 229, 238, 249, 170, 24, 119, 59, 18, 140, 77, 132, 20, 112,
            ],
            "post-extraction model behavior differs from the pre-move pin"
        );
    }
}

fn hand(ops: Vec<Op>) -> FuzzInput {
    let mut input = decoded(&[]);
    input.ops = ops;
    input
}

fn resize_op(len: u64, failure_percent: u8, partial_percent: u8) -> Op {
    Op::Resize {
        slot: 0,
        len: Offset::At(len),
        fault: Some(ResizeFault {
            failure_percent,
            partial_percent,
        }),
    }
}

fn write(
    offset: u64,
    len: usize,
    sync: bool,
    write_fault: Option<WriteFault>,
    sync_fault: bool,
) -> Op {
    Op::Write {
        slot: 0,
        offset: Offset::At(offset),
        chunks: vec![len],
        sync,
        dont_cache: false,
        write_fault,
        sync_fault,
    }
}

fn failing_write(retention_percent: u8) -> WriteFault {
    WriteFault {
        fails: true,
        retention_percent,
        mode: PartialWriteMode::Prefix,
    }
}

fn torn_write() -> WriteFault {
    WriteFault {
        fails: false,
        retention_percent: 50,
        mode: PartialWriteMode::Subset,
    }
}

fn collapse_twice(records: &[Record], input: usize) -> Vec<Record> {
    let mut records = records.to_vec();
    for record in &mut records {
        if record.origin == Origin::Verification {
            record.logged = None;
        }
    }
    let mut collapsed = Vec::new();
    let mut index = 0;
    while index < records.len() {
        let record = &records[index];
        if record.origin != Origin::Verification {
            collapsed.push(record.clone());
            index += 1;
            continue;
        }
        let mut end = index + 1;
        while end < records.len() && records[end] == *record {
            end += 1;
        }
        let copies = end - index;
        assert_eq!(
            copies % 2,
            0,
            "fixed input {input}, verification replay differed near {:#?}",
            &records[index..records.len().min(end + 2)]
        );
        collapsed.extend(std::iter::repeat_n(record.clone(), copies / 2));
        index = end;
    }
    collapsed
}

fn without_verification_logs(records: &[Record]) -> Vec<Record> {
    records
        .iter()
        .cloned()
        .map(|mut record| {
            if record.origin == Origin::Verification {
                record.logged = None;
            }
            record
        })
        .collect()
}

#[test]
fn acceptance_at_011_and_012_fixed_replay_and_verification_schedule() {
    let mut inputs = vec![Vec::new()];
    inputs.extend((0u64..=255).map(|seed| seed.to_le_bytes().to_vec()));
    for (index, bytes) in inputs.iter().enumerate() {
        let first_input = decoded(bytes);
        let second_input = decoded(bytes);
        let first = run(&first_input, |context| context, Verify::Once);
        let second = run(&second_input, |context| context, Verify::Once);
        assert_eq!(first, second, "fixed input {index}");

        let twice_input = decoded(bytes);
        let twice = run(&twice_input, |context| context, Verify::Twice);
        assert_eq!(first.violation, twice.violation, "fixed input {index}");
        assert_eq!(first.measured, twice.measured, "fixed input {index}");
        assert_eq!(
            without_verification_logs(&first.trace.records),
            collapse_twice(&twice.trace.records, index),
            "fixed input {index}"
        );
    }
}

#[test]
fn acceptance_at_001_and_076_empty_short_and_fixed_inputs_are_clean() {
    let empty = decoded(&[]);
    assert!(empty.ops.is_empty());
    let outcome = run(&empty, |context| context, Verify::Once);
    assert!(outcome.violation.is_none(), "{outcome:#?}");
    let records = &outcome.trace.records;
    assert_eq!(records.len(), 11, "{records:#?}");
    assert!(
        records
            .iter()
            .all(|record| record.fault == Fault::default())
    );
    assert_eq!(
        records
            .iter()
            .map(|record| record.session)
            .collect::<Vec<_>>(),
        [0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
    );
    assert_eq!(
        records
            .iter()
            .map(|record| record.origin)
            .collect::<Vec<_>>(),
        [
            Origin::Baseline,
            Origin::Verification,
            Origin::Baseline,
            Origin::Baseline,
            Origin::Baseline,
            Origin::Verification,
            Origin::Verification,
            Origin::Verification,
            Origin::Verification,
            Origin::Verification,
            Origin::Verification,
        ]
    );
    let baseline_bytes = (0..64)
        .map(|position| value(1, position))
        .collect::<Vec<_>>();
    let expected_calls = vec![
        Call::Open {
            partition: "p0".into(),
            name: b"a".to_vec(),
            versions: (0, 0),
            default: false,
        },
        Call::ReadAt {
            slot: None,
            offset: 0,
            len: 1,
            dont_cache: false,
        },
        Call::Write {
            slot: 0,
            offset: 0,
            bytes: baseline_bytes.clone(),
            chunks: vec![64],
            sync: false,
            dont_cache: false,
        },
        Call::ReadAt {
            slot: Some(0),
            offset: 0,
            len: 64,
            dont_cache: false,
        },
        Call::Sync { slot: 0 },
        Call::Scan {
            partition: "p0".into(),
        },
        Call::Scan {
            partition: "p1".into(),
        },
        Call::Open {
            partition: "p0".into(),
            name: b"a".to_vec(),
            versions: (0, 2),
            default: false,
        },
        Call::ReadAt {
            slot: None,
            offset: 64,
            len: 1,
            dont_cache: false,
        },
        Call::ReadAt {
            slot: None,
            offset: 63,
            len: 1,
            dont_cache: false,
        },
        Call::ReadAt {
            slot: None,
            offset: 0,
            len: 64,
            dont_cache: false,
        },
    ];
    assert_eq!(
        records
            .iter()
            .map(|record| &record.call)
            .collect::<Vec<_>>(),
        expected_calls.iter().collect::<Vec<_>>()
    );
    assert_eq!(
        records[0].result,
        CallResult::Opened {
            size: 0,
            version: Some(0),
        }
    );
    assert!(matches!(records[1].result, CallResult::Err(_)));
    assert_eq!(records[2].result, CallResult::Unit);
    assert_eq!(
        records[3].result,
        CallResult::Bytes(vec![baseline_bytes.clone()])
    );
    assert_eq!(records[4].result, CallResult::Unit);
    assert_eq!(records[5].result, CallResult::Names(vec![b"a".to_vec()]));
    assert_eq!(
        records[7].result,
        CallResult::Opened {
            size: 64,
            version: Some(0),
        }
    );
    assert!(matches!(records[8].result, CallResult::Err(_)));
    assert_eq!(
        records[9].result,
        CallResult::Bytes(vec![vec![baseline_bytes[63]]])
    );
    assert_eq!(records[10].result, CallResult::Bytes(vec![baseline_bytes]));

    for len in 1..SEED_BYTES {
        let input = decoded(&vec![0; len]);
        assert!(!input.ops.is_empty(), "input length {len}");
        let outcome = run(&input, |context| context, Verify::Once);
        assert!(
            outcome.violation.is_none(),
            "input length {len}: {outcome:#?}"
        );
    }

    for seed in 0u64..=255 {
        let bytes = seed.to_le_bytes();
        let input = decoded(&bytes);
        assert!(!input.ops.is_empty(), "fixed seed {seed}");
        let outcome = run(&input, |context| context, Verify::Once);
        assert!(
            outcome.violation.is_none(),
            "fixed seed {seed}: {outcome:#?}"
        );
    }
}

#[test]
fn acceptance_at_002_crashes_bound_sessions_and_recover_first() {
    for (extra_crashes, expected_sessions) in [(0, 2), (1, 3), (3, 5), (4, 5)] {
        let input = hand(vec![Op::Crash; extra_crashes]);
        let seam_calls = Arc::new(AtomicUsize::new(0));
        let calls = seam_calls.clone();
        let outcome = run(
            &input,
            move |context| {
                calls.fetch_add(1, Ordering::Relaxed);
                context
            },
            Verify::Once,
        );
        assert!(outcome.violation.is_none(), "{outcome:#?}");
        assert_eq!(seam_calls.load(Ordering::Relaxed), expected_sessions);
        assert_eq!(
            outcome
                .trace
                .records
                .iter()
                .map(|record| record.session)
                .max()
                .unwrap()
                + 1,
            expected_sessions
        );
        for session in 1..expected_sessions {
            let first = outcome
                .trace
                .records
                .iter()
                .find(|record| record.session == session)
                .unwrap();
            assert_eq!(first.origin, Origin::Verification, "{first:#?}");
            assert_eq!(
                first.call,
                Call::Scan {
                    partition: "p0".into()
                },
                "{first:#?}"
            );
        }
    }
}

#[test]
fn acceptance_at_005_armed_success_and_half_resize_replay() {
    let torn = hand(vec![write(
        0,
        16,
        false,
        Some(WriteFault {
            fails: false,
            retention_percent: 50,
            mode: PartialWriteMode::Subset,
        }),
        false,
    )]);
    let outcome = run(&torn, |context| context, Verify::Once);
    assert!(outcome.violation.is_none(), "{outcome:#?}");
    let record = outcome
        .trace
        .records
        .iter()
        .find(|record| record.origin == Origin::Input)
        .unwrap();
    assert_eq!(record.result, CallResult::Unit);
    assert!(
        outcome
            .trace
            .records
            .iter()
            .any(|record| matches!(record.logged, Some(Entry::Torn { .. })))
    );

    for partial_percent in [0, 50, 100] {
        let input = hand(vec![resize_op(128, 50, partial_percent)]);
        let first = run(&input, |context| context, Verify::Once);
        let second = run(&input, |context| context, Verify::Once);
        assert_eq!(first, second);
        assert!(first.violation.is_none(), "{first:#?}");
        let record = first
            .trace
            .records
            .iter()
            .find(|record| record.origin == Origin::Input)
            .unwrap();
        assert!(matches!(
            record.result,
            CallResult::Unit | CallResult::Err(_)
        ));
    }
}

#[test]
fn plant() {
    let input = hand(vec![
        write(
            0,
            8,
            false,
            Some(WriteFault {
                fails: false,
                retention_percent: 100,
                mode: PartialWriteMode::Prefix,
            }),
            false,
        ),
        Op::Open {
            slot: 0,
            partition: PartitionName::P0,
            name: BlobName::A,
            versions: (0, 0),
            fault: false,
        },
    ]);
    fuzz(input);
}

#[test]
fn acceptance_at_030_positive_scenarios_measure_every_invariant() {
    let scenarios = vec![
        hand(Vec::new()),
        hand(vec![
            Op::ReadAtBuf {
                slot: 0,
                offset: Offset::At(0),
                len: 16,
                chunks: vec![32],
                dont_cache: false,
                fault: false,
            },
            Op::ReadMany {
                slot: 0,
                ranges: vec![(Offset::At(0), 8), (Offset::At(8), 8)],
                dont_cache: false,
                fault: false,
            },
            Op::StartReadMany {
                slot: 0,
                ranges: vec![(Offset::At(0), 8), (Offset::At(8), 8)],
                dont_cache: false,
                wait: true,
                fault: false,
            },
        ]),
        hand(vec![Op::Open {
            slot: 1,
            partition: PartitionName::P0,
            name: BlobName::A,
            versions: (0, 0),
            fault: false,
        }]),
        hand(vec![Op::Open {
            slot: 0,
            partition: PartitionName::P0,
            name: BlobName::A,
            versions: (1, 2),
            fault: false,
        }]),
        hand(vec![Op::Open {
            slot: 1,
            partition: PartitionName::Slash,
            name: BlobName::A,
            versions: (0, 0),
            fault: false,
        }]),
        hand(vec![Op::Remove {
            partition: PartitionName::Slash,
            name: None,
            fault: false,
        }]),
        hand(vec![Op::Scan {
            partition: PartitionName::Slash,
            fault: false,
        }]),
        hand(vec![Op::Open {
            slot: 1,
            partition: PartitionName::P0,
            name: BlobName::B,
            versions: (1, 2),
            fault: false,
        }]),
        hand(vec![Op::Open {
            slot: 0,
            partition: PartitionName::P0,
            name: BlobName::A,
            versions: (0, 2),
            fault: false,
        }]),
        hand(vec![
            Op::Remove {
                partition: PartitionName::P0,
                name: Some(BlobName::A),
                fault: false,
            },
            Op::Open {
                slot: 1,
                partition: PartitionName::P0,
                name: BlobName::A,
                versions: (0, 0),
                fault: false,
            },
        ]),
        hand(vec![write(8, 8, false, Some(failing_write(100)), false)]),
        hand(vec![write(0, 8, true, None, true)]),
        hand(vec![Op::Resize {
            slot: 0,
            len: Offset::At(128),
            fault: Some(ResizeFault {
                failure_percent: 100,
                partial_percent: 100,
            }),
        }]),
        hand(vec![Op::Open {
            slot: 1,
            partition: PartitionName::P0,
            name: BlobName::B,
            versions: (0, 0),
            fault: true,
        }]),
        hand(vec![Op::ReadAt {
            slot: 0,
            offset: Offset::At(0),
            len: 16,
            dont_cache: false,
            fault: true,
        }]),
        hand(vec![Op::Sync {
            slot: 0,
            fault: true,
        }]),
        hand(vec![Op::Remove {
            partition: PartitionName::P0,
            name: Some(BlobName::A),
            fault: true,
        }]),
        hand(vec![Op::Scan {
            partition: PartitionName::P0,
            fault: true,
        }]),
        hand(vec![
            write(0, 8, false, None, false),
            Op::Sync {
                slot: 0,
                fault: false,
            },
        ]),
        hand(vec![write(0, 8, true, None, false)]),
        hand(vec![
            write(0, 8, false, Some(torn_write()), false),
            Op::Open {
                slot: 0,
                partition: PartitionName::P0,
                name: BlobName::A,
                versions: (0, 0),
                fault: false,
            },
        ]),
        hand(vec![write(0, 8, false, Some(torn_write()), false)]),
        hand(vec![Op::Scan {
            partition: PartitionName::P0,
            fault: false,
        }]),
        hand(vec![
            Op::Remove {
                partition: PartitionName::P0,
                name: Some(BlobName::A),
                fault: false,
            },
            Op::ReadAt {
                slot: 0,
                offset: Offset::At(0),
                len: 16,
                dont_cache: false,
                fault: false,
            },
        ]),
        hand(vec![Op::Resize {
            slot: 0,
            len: Offset::At(32),
            fault: None,
        }]),
        hand(vec![Op::StartSync {
            slot: 0,
            wait: true,
            fault: false,
        }]),
        hand(vec![Op::Remove {
            partition: PartitionName::P0,
            name: Some(BlobName::A),
            fault: false,
        }]),
    ];

    let empty = run(&scenarios[0], |context| context, Verify::Once);
    for invariant in [
        Invariant::I8,
        Invariant::I9,
        Invariant::I10,
        Invariant::I11,
        Invariant::I12,
        Invariant::I13,
    ] {
        assert!(!empty.measured.contains(&invariant), "{}", invariant.id());
    }

    let mut measured = BTreeSet::new();
    for (index, input) in scenarios.iter().enumerate() {
        let outcome = run(input, |context| context, Verify::Once);
        let replay = run(input, |context| context, Verify::Once);
        assert_eq!(outcome, replay, "scenario {index} replay");
        let twice = run(input, |context| context, Verify::Twice);
        assert_eq!(outcome.violation, twice.violation, "scenario {index}");
        assert_eq!(outcome.measured, twice.measured, "scenario {index}");
        assert_eq!(
            without_verification_logs(&outcome.trace.records),
            collapse_twice(&twice.trace.records, index),
            "scenario {index} verification schedule"
        );
        assert!(
            outcome.violation.is_none(),
            "scenario {index}: {outcome:#?}"
        );
        for record in &outcome.trace.records {
            if record.origin == Origin::Verification
                && let Call::ReadAt { offset, len, .. } = record.call
            {
                assert!(offset <= MAX_SIZE && len as u64 <= MAX_SIZE, "{record:#?}");
            }
        }
        measured.extend(outcome.measured);
    }
    let expected = Invariant::ALL
        .iter()
        .copied()
        .filter(|invariant| *invariant != Invariant::I17)
        .collect::<BTreeSet<_>>();
    assert_eq!(measured, expected);
}

#[test]
fn acceptance_at_004_fault_windows_are_exact() {
    let inputs = [
        hand(vec![Op::Open {
            slot: 1,
            partition: PartitionName::P0,
            name: BlobName::B,
            versions: (0, 0),
            fault: true,
        }]),
        hand(vec![Op::ReadAt {
            slot: 0,
            offset: Offset::At(0),
            len: 8,
            dont_cache: false,
            fault: true,
        }]),
        hand(vec![write(0, 8, false, Some(failing_write(50)), false)]),
        hand(vec![Op::Resize {
            slot: 0,
            len: Offset::At(128),
            fault: Some(ResizeFault {
                failure_percent: 100,
                partial_percent: 50,
            }),
        }]),
        hand(vec![Op::Sync {
            slot: 0,
            fault: true,
        }]),
        hand(vec![Op::Remove {
            partition: PartitionName::P0,
            name: Some(BlobName::A),
            fault: true,
        }]),
        hand(vec![Op::Scan {
            partition: PartitionName::P0,
            fault: true,
        }]),
    ];
    for input in &inputs {
        let state = Arc::new(PlantState::new(Plant::Pass));
        let seam_state = state.clone();
        let outcome = run(
            input,
            move |context: deterministic::Context| {
                let faults = context.storage_fault_config();
                seam_state
                    .session_starts
                    .lock()
                    .push(format!("{:?}", *faults.read()));
                let session = seam_state.next_session.fetch_add(1, Ordering::Relaxed);
                PlantStorage {
                    inner: context,
                    state: seam_state.clone(),
                    session,
                    faults,
                }
            },
            Verify::Once,
        );
        assert!(outcome.violation.is_none(), "{outcome:#?}");
        let observed = state.observed_faults.lock();
        assert_eq!(observed.len(), outcome.trace.records.len());
        for (record, actual) in outcome.trace.records.iter().zip(observed.iter()) {
            let expected = if record.origin == Origin::Input {
                input.ops[record.index - 4].fault()
            } else {
                Fault::default()
            };
            assert_eq!(record.fault, expected, "{record:#?}");
            assert_eq!(*actual, format!("{:?}", expected.config()), "{record:#?}");
        }
        let default = format!("{:?}", FaultConfig::default());
        assert!(
            state
                .session_starts
                .lock()
                .iter()
                .all(|actual| actual == &default)
        );
    }
}

#[test]
fn acceptance_at_014_verification_reads_are_bounded() {
    for seed in 0u64..=255 {
        let input = decoded(&seed.to_le_bytes());
        let outcome = run(&input, |context| context, Verify::Once);
        assert!(outcome.violation.is_none(), "seed {seed}: {outcome:#?}");
        for record in &outcome.trace.records {
            if record.origin != Origin::Verification {
                continue;
            }
            if let Call::ReadAt { offset, len, .. } = record.call {
                assert!(offset <= 2304, "{record:#?}");
                assert!(len <= 2304, "{record:#?}");
            }
        }
    }

    let outcome = planted(&hand(Vec::new()), Plant::I18a);
    assert_eq!(
        outcome.violation.as_ref().unwrap().invariant,
        Invariant::I18a
    );
    let oversized = outcome
        .trace
        .records
        .iter()
        .position(|record| {
            record.result
                == CallResult::Opened {
                    size: u64::MAX,
                    version: Some(0),
                }
        })
        .unwrap();
    assert!(outcome.trace.records[oversized + 1..].is_empty());
}

#[test]
fn acceptance_at_015_failing_write_reveals_one_kept_mask() {
    let (index, position) = (4usize..=52)
        .find_map(|index| {
            (0u64..64).find_map(|position| {
                (value(index, position) == value(1, position)).then_some((index, position))
            })
        })
        .expect("bounded search must find an equal generated byte");
    let mut ops = vec![Op::Drop { slot: 3 }; index - 4];
    ops.push(write(position, 1, false, Some(failing_write(100)), false));
    let outcome = run(&hand(ops), |context| context, Verify::Once);
    assert!(outcome.violation.is_none(), "{outcome:#?}");
    let record = outcome
        .trace
        .records
        .iter()
        .find(|record| record.origin == Origin::Input && matches!(record.call, Call::Write { .. }))
        .unwrap();
    let Call::Write { bytes, .. } = &record.call else {
        unreachable!()
    };
    assert_ne!(bytes[0], value(1, position));
    assert_ne!(bytes[0], 0);
    let logged = record
        .logged
        .as_ref()
        .expect("the failed write record must expose its model entry");
    assert!(
        matches!(
            logged,
            Entry::Kept {
                bytes: logged,
                mask,
                ..
            } if logged == bytes && mask == &[true]
        ),
        "{logged:#?}"
    );
    assert!(
        outcome
            .trace
            .records
            .iter()
            .filter(|record| record.origin == Origin::Verification)
            .all(|record| record.logged.is_none())
    );
}

#[test]
fn acceptance_at_079_failed_open_empties_occupied_slot() {
    for fault in [false, true] {
        let input = hand(vec![
            Op::Open {
                slot: 0,
                partition: PartitionName::P0,
                name: BlobName::A,
                versions: if fault { (0, 0) } else { (1, 2) },
                fault,
            },
            Op::ReadAt {
                slot: 0,
                offset: Offset::At(0),
                len: 8,
                dont_cache: false,
                fault: false,
            },
        ]);
        let outcome = run(&input, |context| context, Verify::Once);
        assert!(outcome.violation.is_none(), "{outcome:#?}");
        assert!(!outcome.trace.records.iter().any(|record| {
            record.origin == Origin::Input
                && record.index == 5
                && matches!(record.call, Call::ReadAt { .. })
        }));
    }
}

#[test]
fn acceptance_at_006_fault_samplers() {
    for (selector, expected) in [(0, false), (1, false), (2, false), (3, true)] {
        let bytes = [selector, 0xa5];
        let mut input = Unstructured::new(&bytes);
        assert_eq!(sample_armed(&mut input).unwrap(), expected);
        assert_eq!(
            input.len(),
            1,
            "sample_armed consumed more than its selector"
        );
    }
    assert!(!sample_armed(&mut Unstructured::new(&[])).unwrap());

    for (selector, expected) in [(0, false), (1, true)] {
        let bytes = [selector, 0xa5];
        let mut input = Unstructured::new(&bytes);
        assert_eq!(sample_write_fails(&mut input).unwrap(), expected);
        assert_eq!(
            input.len(),
            1,
            "sample_write_fails consumed more than its selector"
        );
    }
    assert!(!sample_write_fails(&mut Unstructured::new(&[])).unwrap());
}

#[derive(Clone, Debug)]
enum SpecEntry {
    Torn {
        offset: u64,
        len: usize,
    },
    Kept {
        offset: u64,
        len: usize,
        mask: Vec<bool>,
    },
    MaybeResize(u64),
    ForcedResize(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpecRule {
    Crash,
    Reopen,
}

impl SpecRule {
    const fn harness(self) -> Rule {
        match self {
            Self::Crash => Rule::Crash,
            Self::Reopen => Rule::Reopen,
        }
    }
}

impl SpecEntry {
    fn harness_entry(&self, place: usize) -> Entry {
        let byte = u8::try_from(place + 1).unwrap();
        match self {
            Self::Torn { offset, len } => Entry::Torn {
                offset: *offset,
                bytes: vec![byte; *len],
            },
            Self::Kept { offset, len, mask } => Entry::Kept {
                offset: *offset,
                bytes: vec![byte; *len],
                mask: mask.clone(),
            },
            Self::MaybeResize(len) => Entry::MaybeResize(*len),
            Self::ForcedResize(len) => Entry::ForcedResize(*len),
        }
    }
}

fn images(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut level = vec![Vec::new()];
    for _ in 0..max_len {
        level = level
            .iter()
            .flat_map(|prefix| {
                alphabet.iter().map(move |byte| {
                    let mut image = prefix.clone();
                    image.push(*byte);
                    image
                })
            })
            .collect();
        all.extend(level.iter().cloned());
    }
    all
}

fn write_selected(mut image: Vec<u8>, offset: u64, bytes: &[u8], selected: &[bool]) -> Vec<u8> {
    for (index, (byte, selected)) in bytes.iter().zip(selected).enumerate() {
        if !selected {
            continue;
        }
        let position = usize::try_from(offset).unwrap() + index;
        if image.len() <= position {
            image.resize(position + 1, 0);
        }
        image[position] = *byte;
    }
    image
}

fn resize(mut image: Vec<u8>, len: u64) -> Vec<u8> {
    image.resize(usize::try_from(len).unwrap(), 0);
    image
}

fn enumerate(base: &[u8], log: &[SpecEntry], rule: SpecRule) -> BTreeSet<Vec<u8>> {
    let mut current = BTreeSet::from([base.to_vec()]);
    for (place, entry) in log.iter().enumerate() {
        let byte = u8::try_from(place + 1).unwrap();
        let mut next = BTreeSet::new();
        for image in current {
            match entry {
                SpecEntry::Torn { offset, len } => {
                    for subset in 0..(1usize << len) {
                        let selected = (0..*len)
                            .map(|index| subset & (1 << index) != 0)
                            .collect::<Vec<_>>();
                        next.insert(write_selected(
                            image.clone(),
                            *offset,
                            &vec![byte; *len],
                            &selected,
                        ));
                    }
                }
                SpecEntry::Kept { offset, len, mask } => {
                    next.insert(write_selected(image, *offset, &vec![byte; *len], mask));
                }
                SpecEntry::MaybeResize(len) => {
                    next.insert(image.clone());
                    next.insert(resize(image, *len));
                }
                SpecEntry::ForcedResize(len) => {
                    if rule == SpecRule::Reopen {
                        next.insert(image.clone());
                    }
                    next.insert(resize(image, *len));
                }
            }
        }
        current = next;
    }
    current
}

fn domain_a_entries() -> Vec<SpecEntry> {
    let mut entries = Vec::new();
    for offset in 0..=2 {
        for len in 1..=2 {
            entries.push(SpecEntry::Torn { offset, len });
            for bits in 1..(1usize << len) {
                entries.push(SpecEntry::Kept {
                    offset,
                    len,
                    mask: (0..len).map(|index| bits & (1 << index) != 0).collect(),
                });
            }
        }
    }
    for len in 0..=4 {
        entries.push(SpecEntry::MaybeResize(len));
        entries.push(SpecEntry::ForcedResize(len));
    }
    assert_eq!(entries.len(), 28);
    entries
}

fn domain_b_entries() -> Vec<SpecEntry> {
    let mut entries = Vec::new();
    for offset in [0, 2] {
        let len = 2;
        entries.push(SpecEntry::Torn { offset, len });
        for bits in 1..(1usize << len) {
            entries.push(SpecEntry::Kept {
                offset,
                len,
                mask: (0..len).map(|index| bits & (1 << index) != 0).collect(),
            });
        }
    }
    for len in [0, 1, 3] {
        entries.push(SpecEntry::MaybeResize(len));
        entries.push(SpecEntry::ForcedResize(len));
    }
    assert_eq!(entries.len(), 14);
    entries
}

fn check_case(base: &[u8], log: &[SpecEntry], rule: SpecRule, judged: &[Vec<u8>]) {
    let expected = enumerate(base, log, rule);
    let harness_log = log
        .iter()
        .enumerate()
        .map(|(place, entry)| entry.harness_entry(place))
        .collect::<Vec<_>>();
    for image in judged {
        assert_eq!(
            reachable(base, &harness_log, rule.harness(), image),
            expected.contains(image),
            "base={base:?} log={log:?} rule={rule:?} image={image:?}"
        );
    }
}

#[test]
fn acceptance_at_009_reachable_domain_a() {
    let bases = images(&[0, 9], 2);
    let judged = images(&[0, 1, 2, 3, 9], 4);
    assert_eq!(bases.len(), 7);
    assert_eq!(judged.len(), 781);

    let entries = domain_a_entries();
    let mut logs = vec![Vec::new()];
    logs.extend(entries.iter().cloned().map(|entry| vec![entry]));
    logs.extend(entries.iter().flat_map(|first| {
        entries
            .iter()
            .map(move |second| vec![first.clone(), second.clone()])
    }));
    assert_eq!(logs.len(), 813);

    let mut cases = 0;
    for base in &bases {
        for log in &logs {
            for rule in [SpecRule::Crash, SpecRule::Reopen] {
                check_case(base, log, rule, &judged);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 11_382);
}

#[test]
fn acceptance_at_009_reachable_domain_b() {
    let bases = images(&[0, 9], 2);
    let judged = images(&[0, 1, 2, 3, 9], 4);
    let entries = domain_b_entries();
    let mut cases = 0;

    for base in &bases {
        for first in &entries {
            for second in &entries {
                for third in &entries {
                    let log = [first.clone(), second.clone(), third.clone()];
                    for rule in [SpecRule::Crash, SpecRule::Reopen] {
                        check_case(base, &log, rule, &judged);
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 38_416);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Plant {
    Pass,
    I1a,
    I1b,
    I2a,
    I2b,
    I2bThenError,
    I2c,
    I3a,
    I3b,
    I3c,
    I3d,
    I3e,
    I3f,
    I3g,
    I3h,
    I4a,
    I4b,
    I4c,
    I4d,
    I5a,
    I5b,
    I5c,
    I6a,
    I6b,
    I6c,
    I6d,
    I6e,
    I7,
    I8,
    I9,
    I10,
    I11,
    I12,
    I13,
    I14a,
    I14b,
    I15,
    I16a,
    I16b,
    I16c,
    I16d,
    I16e,
    I16f,
    I16g,
    I17,
    I18a,
    I18b,
    I18bShortProbe,
    DroppedStartSync,
}

struct PlantState {
    plant: Plant,
    next_session: AtomicUsize,
    active_calls: AtomicUsize,
    max_active_calls: AtomicUsize,
    live_blobs: AtomicUsize,
    removed_p0a: AtomicBool,
    opens_p0a: AtomicUsize,
    last_write: Mutex<Option<(u64, Vec<u8>)>>,
    observed_faults: Mutex<Vec<String>>,
    session_starts: Mutex<Vec<String>>,
}

impl PlantState {
    fn new(plant: Plant) -> Self {
        Self {
            plant,
            next_session: AtomicUsize::new(0),
            active_calls: AtomicUsize::new(0),
            max_active_calls: AtomicUsize::new(0),
            live_blobs: AtomicUsize::new(0),
            removed_p0a: AtomicBool::new(false),
            opens_p0a: AtomicUsize::new(0),
            last_write: Mutex::new(None),
            observed_faults: Mutex::new(Vec::new()),
            session_starts: Mutex::new(Vec::new()),
        }
    }

    fn enter(self: &Arc<Self>) -> ActiveCall {
        let active = self.active_calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active_calls.fetch_max(active, Ordering::SeqCst);
        assert_eq!(active, 1, "storage calls must not overlap");
        ActiveCall {
            state: self.clone(),
        }
    }
}

struct ActiveCall {
    state: Arc<PlantState>,
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        assert_eq!(self.state.active_calls.fetch_sub(1, Ordering::SeqCst), 1);
    }
}

struct PlantStorage<S> {
    inner: S,
    state: Arc<PlantState>,
    session: usize,
    faults: Arc<RwLock<FaultConfig>>,
}

struct PlantBlob<B> {
    inner: B,
    state: Arc<PlantState>,
    session: usize,
    faults: Arc<RwLock<FaultConfig>>,
    partition: String,
    name: Vec<u8>,
}

fn injected() -> Error {
    Error::Io(std::io::Error::other("acceptance plant").into())
}

fn is_io(error: &Error) -> bool {
    matches!(error, Error::Io(_))
}

impl<S: Storage> Storage for PlantStorage<S> {
    type Blob = PlantBlob<S::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        let _active = self.state.enter();
        self.observe();
        let plant = self.state.plant;
        if plant == Plant::I16a {
            return Err(Error::Closed);
        }
        if plant == Plant::I3c && partition == "a/b" {
            let (inner, size, version) = self.inner.open_versioned("p1", b"a", versions).await?;
            return Ok((self.wrap(inner, "p1", b"a"), size, version));
        }

        let result = self.inner.open_versioned(partition, name, versions).await;
        let (inner, mut size, mut version) = match result {
            Err(Error::BlobAlreadyOpen(_, _)) if plant == Plant::I3a => return Err(Error::Closed),
            Err(Error::BlobVersionMismatch { .. }) if plant == Plant::I3b => {
                return Err(Error::Closed);
            }
            Err(error) if plant == Plant::I6a && is_io(&error) => {
                let saved = self.faults.read().clone();
                *self.faults.write() = FaultConfig::default();
                let extra = self
                    .inner
                    .open_versioned(partition, name, BlobVersion::new(0)..=BlobVersion::new(0))
                    .await;
                *self.faults.write() = saved;
                drop(extra);
                return Err(error);
            }
            Err(error) => return Err(error),
            Ok(opened) => opened,
        };

        let p0a = partition == "p0" && name == b"a";
        let prior_opens = if p0a {
            self.state.opens_p0a.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        };
        if plant == Plant::I3f && partition == "p0" && name == b"b" {
            version = BlobVersion::new(0);
        }
        if plant == Plant::I3g && self.session == 0 && p0a && prior_opens > 0 {
            version = BlobVersion::new(1);
        }
        if plant == Plant::I18a && self.session > 0 && p0a {
            size = u64::MAX;
        }
        if plant == Plant::I18b && self.session == 0 && p0a && prior_opens > 0 {
            size = 63;
        }
        if plant == Plant::I3h && p0a && self.state.removed_p0a.load(Ordering::Relaxed) {
            inner
                .write_at(0, vec![1, 2, 3, 4], WriteOptions::default())
                .await?;
            size = 4;
        }
        if plant == Plant::I11 && self.session == 0 && p0a && prior_opens > 0 {
            let last_write = self.state.last_write.lock().clone();
            if let Some((offset, bytes)) = last_write {
                let saved = self.faults.read().clone();
                *self.faults.write() = FaultConfig::default();
                inner
                    .write_at(offset, bytes, WriteOptions::default())
                    .await?;
                *self.faults.write() = saved;
            }
        }
        if plant == Plant::I12 && self.session == 0 && p0a && prior_opens > 0 {
            let saved = self.faults.read().clone();
            *self.faults.write() = FaultConfig::default();
            inner
                .write_at(20, vec![0xff], WriteOptions::default())
                .await?;
            *self.faults.write() = saved;
        }
        Ok((self.wrap(inner, partition, name), size, version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        let _active = self.state.enter();
        self.observe();
        let plant = self.state.plant;
        if plant == Plant::I3d && partition == "a/b" {
            return Ok(());
        }
        if plant == Plant::I16f && self.session == 0 {
            return Err(Error::Closed);
        }
        if plant == Plant::I14b && partition == "p0" && name == Some(b"a".as_slice()) {
            return Ok(());
        }
        let result = self.inner.remove(partition, name).await;
        if plant == Plant::I6d && result.as_ref().is_err_and(is_io) {
            let saved = self.faults.read().clone();
            *self.faults.write() = FaultConfig::default();
            let _ = self.inner.remove(partition, name).await;
            *self.faults.write() = saved;
        }
        if result.is_ok() && partition == "p0" && name == Some(b"a".as_slice()) {
            self.state.removed_p0a.store(true, Ordering::Relaxed);
        }
        result
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        let _active = self.state.enter();
        self.observe();
        let plant = self.state.plant;
        if plant == Plant::I3e && partition == "a/b" {
            return Ok(Vec::new());
        }
        if plant == Plant::I16g && self.session == 0 && partition == "p0" {
            return Err(Error::Closed);
        }
        if plant == Plant::I17 && self.session == 0 && partition == "p0" {
            panic!("acceptance SF-I17 plant");
        }
        let mut result = self.inner.scan(partition).await;
        if plant == Plant::I6e && result.as_ref().is_err_and(is_io) {
            let saved = self.faults.read().clone();
            *self.faults.write() = FaultConfig::default();
            let _ = self.inner.remove("p0", Some(b"a")).await;
            *self.faults.write() = saved;
        }
        if plant == Plant::I14a
            && self.session == 0
            && partition == "p0"
            && let Ok(names) = &mut result
        {
            names.push(b"zz".to_vec());
        }
        result
    }
}

impl<S: Storage> PlantStorage<S> {
    fn observe(&self) {
        self.state
            .observed_faults
            .lock()
            .push(format!("{:?}", *self.faults.read()));
    }

    fn wrap(&self, inner: S::Blob, partition: &str, name: &[u8]) -> PlantBlob<S::Blob> {
        self.state.live_blobs.fetch_add(1, Ordering::SeqCst);
        PlantBlob {
            inner,
            state: self.state.clone(),
            session: self.session,
            faults: self.faults.clone(),
            partition: partition.to_string(),
            name: name.to_vec(),
        }
    }
}

impl<B> Drop for PlantBlob<B> {
    fn drop(&mut self) {
        assert!(self.state.live_blobs.fetch_sub(1, Ordering::SeqCst) > 0);
    }
}

impl<B: Blob> PlantBlob<B> {
    fn observe(&self) {
        self.state
            .observed_faults
            .lock()
            .push(format!("{:?}", *self.faults.read()));
    }

    async fn extra_write(&self, offset: u64, bytes: Vec<u8>) -> Result<(), Error> {
        let saved = self.faults.read().clone();
        *self.faults.write() = FaultConfig::default();
        let result = self
            .inner
            .write_at(offset, bytes, WriteOptions::default())
            .await;
        *self.faults.write() = saved;
        result
    }

    async fn extra_resize(&self, len: u64) -> Result<(), Error> {
        let saved = self.faults.read().clone();
        *self.faults.write() = FaultConfig::default();
        let result = self.inner.resize(len).await;
        *self.faults.write() = saved;
        result
    }

    fn removed_p0a(&self) -> bool {
        self.partition == "p0"
            && self.name == b"a"
            && self.state.removed_p0a.load(Ordering::Relaxed)
    }
}

impl<B: Blob> Blob for PlantBlob<B> {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        let _active = self.state.enter();
        self.observe();
        let result = self.inner.read_at_buf(offset, len, bufs, options).await;
        if self.state.plant == Plant::I6b && result.as_ref().is_err_and(is_io) {
            self.extra_write(0, vec![0xff]).await?;
        }
        if self.state.plant == Plant::I2a {
            return result.map(|mut bufs| {
                let len = bufs.remaining();
                bufs.copy_to_bytes(len).to_vec().into()
            });
        }
        result
    }

    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        let _active = self.state.enter();
        self.observe();
        if self.state.plant == Plant::I1b && offset == 0 && len == 64 {
            return Err(Error::Closed);
        }
        if self.state.plant == Plant::I18bShortProbe && offset == 0 && len == 1 {
            return Ok(Vec::<u8>::new().into());
        }
        if self.state.plant == Plant::I15 && self.removed_p0a() {
            return Err(Error::Closed);
        }
        let result = self.inner.read_at(offset, len, options).await;
        if self.state.plant == Plant::I6b && result.as_ref().is_err_and(is_io) {
            self.extra_write(0, vec![0xff]).await?;
        }
        result.map(|mut bufs| {
            let size = bufs.remaining();
            let mut bytes = bufs.copy_to_bytes(size).to_vec();
            if self.state.plant == Plant::I1a && !bytes.is_empty() {
                bytes[0] ^= 1;
            }
            if self.state.plant == Plant::I13 && self.session > 0 && offset == 0 && bytes.len() > 40
            {
                bytes[40] ^= 1;
            }
            bytes.into()
        })
    }

    fn read_many(
        &self,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> impl futures::Stream<Item = Result<(usize, IoBufsMut), Error>> + Send {
        let _active = self.state.enter();
        self.observe();
        let duplicate = self.state.plant == Plant::I2b;
        let duplicate_then_error = self.state.plant == Plant::I2bThenError;
        let corrupt = self.state.plant == Plant::I6b;
        self.inner
            .read_many(ranges, options)
            .then(move |item| async move {
                if corrupt && item.as_ref().is_err_and(is_io) {
                    self.extra_write(0, vec![0xff]).await?;
                }
                item
            })
            .flat_map(move |item| {
                let items = match item {
                    Ok((0, mut bufs)) if duplicate => {
                        let len = bufs.remaining();
                        let bytes = bufs.copy_to_bytes(len).to_vec();
                        vec![Ok((0, bytes.clone().into())), Ok((0, bytes.into()))]
                    }
                    Ok((index, mut bufs)) if duplicate_then_error => {
                        let len = bufs.remaining();
                        let bytes = bufs.copy_to_bytes(len).to_vec();
                        vec![
                            Ok((index, bytes.clone().into())),
                            Ok((index, bytes.into())),
                            Err(Error::Closed),
                        ]
                    }
                    item => vec![item],
                };
                stream::iter(items)
            })
    }

    async fn start_read_many(
        &self,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> Handle<Vec<IoBufsMut>> {
        let _active = self.state.enter();
        self.observe();
        if self.state.plant == Plant::I6b {
            self.extra_write(0, vec![0xff])
                .await
                .expect("acceptance plant write");
        }
        let handle = self.inner.start_read_many(ranges, options).await;
        if self.state.plant != Plant::I2c {
            return handle;
        }
        Handle::from_future(async move {
            let mut result = handle.await?;
            result.truncate(1);
            Ok(result)
        })
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let _active = self.state.enter();
        self.observe();
        let bufs = bufs.into();
        let bytes = bufs.clone().coalesce().as_ref().to_vec();
        let input_write = bytes.len() == 8;
        let plant = self.state.plant;
        if plant == Plant::I16b {
            return Err(Error::Closed);
        }
        if plant == Plant::I4d && input_write && options.contains(WriteOptions::SYNC) {
            return Err(injected());
        }
        if plant == Plant::I9 && input_write {
            self.extra_write(offset, bytes).await?;
            return Err(injected());
        }
        let forwarded = if plant == Plant::I8 && input_write {
            options.without(WriteOptions::SYNC)
        } else {
            options
        };
        let result = self.inner.write_at(offset, bufs, forwarded).await;
        if result.is_ok() && input_write {
            *self.state.last_write.lock() = Some((offset, bytes.clone()));
        }
        if result.as_ref().is_err_and(is_io) && input_write {
            match plant {
                Plant::I4a => self.extra_write(32, vec![0xff]).await?,
                Plant::I4b => {
                    let old = value(1, 8);
                    let submitted = bytes[0];
                    let bad = (1..=u8::MAX)
                        .find(|byte| *byte != old && *byte != submitted)
                        .unwrap();
                    self.extra_write(8, vec![bad]).await?;
                }
                Plant::I4c => self.extra_resize(80).await?,
                _ => {}
            }
        }
        result
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let _active = self.state.enter();
        self.observe();
        let plant = self.state.plant;
        if plant == Plant::I16c {
            return Err(Error::Closed);
        }
        if plant == Plant::I10 && len == 128 {
            self.extra_resize(96).await?;
            return Err(injected());
        }
        let result = self.inner.resize(len).await;
        if result.as_ref().is_err_and(is_io) && len == 128 {
            match plant {
                Plant::I5a => self.extra_resize(200).await?,
                Plant::I5b => self.extra_write(0, vec![0xff]).await?,
                Plant::I5c => self.extra_write(64, vec![0xff]).await?,
                _ => {}
            }
        }
        result
    }

    async fn sync(&self) -> Result<(), Error> {
        let _active = self.state.enter();
        self.observe();
        let plant = self.state.plant;
        if plant == Plant::I16d {
            return Err(Error::Closed);
        }
        if plant == Plant::I7 {
            return Ok(());
        }
        let result = self.inner.sync().await;
        if plant == Plant::I6c && result.as_ref().is_err_and(is_io) {
            self.extra_resize(10).await?;
        }
        result
    }

    async fn start_sync(&self) -> Handle<()> {
        let _active = self.state.enter();
        self.observe();
        if self.state.plant == Plant::I16e {
            return Handle::ready(Err(Error::Closed));
        }
        if self.state.plant == Plant::DroppedStartSync {
            return Handle::ready(Ok(()));
        }
        if self.state.plant == Plant::I6c {
            self.extra_resize(10)
                .await
                .expect("acceptance plant resize");
        }
        self.inner.start_sync().await
    }
}

fn planted(input: &FuzzInput, plant: Plant) -> commonware_runtime_fuzz::storage_faults::Outcome {
    let state = Arc::new(PlantState::new(plant));
    run(
        input,
        move |context: deterministic::Context| {
            let session = state.next_session.fetch_add(1, Ordering::Relaxed);
            PlantStorage {
                faults: context.storage_fault_config(),
                inner: context,
                state: state.clone(),
                session,
            }
        },
        Verify::Once,
    )
}

fn case(invariant: Invariant, plant: Plant, ops: Vec<Op>) -> (Invariant, Plant, FuzzInput) {
    (invariant, plant, hand(ops))
}

#[test]
fn acceptance_at_031_through_075_negative_controls_fire_exactly() {
    let fail_resize = |partial_percent| Op::Resize {
        slot: 0,
        len: Offset::At(128),
        fault: Some(ResizeFault {
            failure_percent: 100,
            partial_percent,
        }),
    };
    let cases = vec![
        case(Invariant::I1a, Plant::I1a, Vec::new()),
        case(Invariant::I1b, Plant::I1b, Vec::new()),
        case(
            Invariant::I2a,
            Plant::I2a,
            vec![Op::ReadAtBuf {
                slot: 0,
                offset: Offset::At(0),
                len: 16,
                chunks: vec![32],
                dont_cache: false,
                fault: false,
            }],
        ),
        case(
            Invariant::I2b,
            Plant::I2b,
            vec![Op::ReadMany {
                slot: 0,
                ranges: vec![(Offset::At(0), 8), (Offset::At(8), 8)],
                dont_cache: false,
                fault: false,
            }],
        ),
        case(
            Invariant::I2c,
            Plant::I2c,
            vec![Op::StartReadMany {
                slot: 0,
                ranges: vec![(Offset::At(0), 8), (Offset::At(8), 8)],
                dont_cache: false,
                wait: true,
                fault: false,
            }],
        ),
        case(
            Invariant::I3a,
            Plant::I3a,
            vec![Op::Open {
                slot: 1,
                partition: PartitionName::P0,
                name: BlobName::A,
                versions: (0, 0),
                fault: false,
            }],
        ),
        case(
            Invariant::I3b,
            Plant::I3b,
            vec![Op::Open {
                slot: 0,
                partition: PartitionName::P0,
                name: BlobName::A,
                versions: (1, 2),
                fault: false,
            }],
        ),
        case(
            Invariant::I3c,
            Plant::I3c,
            vec![Op::Open {
                slot: 1,
                partition: PartitionName::Slash,
                name: BlobName::A,
                versions: (0, 0),
                fault: false,
            }],
        ),
        case(
            Invariant::I3d,
            Plant::I3d,
            vec![Op::Remove {
                partition: PartitionName::Slash,
                name: None,
                fault: false,
            }],
        ),
        case(
            Invariant::I3e,
            Plant::I3e,
            vec![Op::Scan {
                partition: PartitionName::Slash,
                fault: false,
            }],
        ),
        case(
            Invariant::I3f,
            Plant::I3f,
            vec![Op::Open {
                slot: 1,
                partition: PartitionName::P0,
                name: BlobName::B,
                versions: (1, 2),
                fault: false,
            }],
        ),
        case(
            Invariant::I3g,
            Plant::I3g,
            vec![Op::Open {
                slot: 0,
                partition: PartitionName::P0,
                name: BlobName::A,
                versions: (0, 2),
                fault: false,
            }],
        ),
        case(
            Invariant::I3h,
            Plant::I3h,
            vec![
                Op::Remove {
                    partition: PartitionName::P0,
                    name: Some(BlobName::A),
                    fault: false,
                },
                Op::Open {
                    slot: 1,
                    partition: PartitionName::P0,
                    name: BlobName::A,
                    versions: (0, 0),
                    fault: false,
                },
            ],
        ),
        case(
            Invariant::I4a,
            Plant::I4a,
            vec![write(8, 8, false, Some(failing_write(100)), false)],
        ),
        case(
            Invariant::I4b,
            Plant::I4b,
            vec![write(8, 8, false, Some(failing_write(0)), false)],
        ),
        case(
            Invariant::I4c,
            Plant::I4c,
            vec![write(100, 8, false, Some(failing_write(0)), false)],
        ),
        case(
            Invariant::I4d,
            Plant::I4d,
            vec![write(0, 8, true, None, true)],
        ),
        case(Invariant::I5a, Plant::I5a, vec![fail_resize(0)]),
        case(Invariant::I5b, Plant::I5b, vec![fail_resize(0)]),
        case(Invariant::I5c, Plant::I5c, vec![fail_resize(100)]),
        case(
            Invariant::I6a,
            Plant::I6a,
            vec![Op::Open {
                slot: 1,
                partition: PartitionName::P0,
                name: BlobName::B,
                versions: (0, 0),
                fault: true,
            }],
        ),
        case(
            Invariant::I6b,
            Plant::I6b,
            vec![Op::ReadAt {
                slot: 0,
                offset: Offset::At(0),
                len: 16,
                dont_cache: false,
                fault: true,
            }],
        ),
        case(
            Invariant::I6c,
            Plant::I6c,
            vec![Op::Sync {
                slot: 0,
                fault: true,
            }],
        ),
        case(
            Invariant::I6d,
            Plant::I6d,
            vec![Op::Remove {
                partition: PartitionName::P0,
                name: Some(BlobName::A),
                fault: true,
            }],
        ),
        case(
            Invariant::I6e,
            Plant::I6e,
            vec![Op::Scan {
                partition: PartitionName::P0,
                fault: true,
            }],
        ),
        case(
            Invariant::I7,
            Plant::I7,
            vec![
                write(
                    0,
                    8,
                    false,
                    Some(WriteFault {
                        fails: false,
                        retention_percent: 0,
                        mode: PartialWriteMode::Prefix,
                    }),
                    false,
                ),
                Op::Sync {
                    slot: 0,
                    fault: false,
                },
            ],
        ),
        case(
            Invariant::I8,
            Plant::I8,
            vec![write(
                0,
                8,
                true,
                Some(WriteFault {
                    fails: false,
                    retention_percent: 0,
                    mode: PartialWriteMode::Prefix,
                }),
                false,
            )],
        ),
        case(
            Invariant::I9,
            Plant::I9,
            vec![write(0, 8, false, Some(failing_write(100)), false)],
        ),
        case(Invariant::I10, Plant::I10, vec![fail_resize(100)]),
        case(
            Invariant::I11,
            Plant::I11,
            vec![
                write(0, 8, false, Some(torn_write()), false),
                Op::Open {
                    slot: 0,
                    partition: PartitionName::P0,
                    name: BlobName::A,
                    versions: (0, 0),
                    fault: false,
                },
            ],
        ),
        case(
            Invariant::I12,
            Plant::I12,
            vec![
                write(0, 8, false, None, false),
                Op::Open {
                    slot: 0,
                    partition: PartitionName::P0,
                    name: BlobName::A,
                    versions: (0, 0),
                    fault: false,
                },
            ],
        ),
        case(
            Invariant::I13,
            Plant::I13,
            vec![write(0, 8, false, Some(torn_write()), false)],
        ),
        case(
            Invariant::I14a,
            Plant::I14a,
            vec![Op::Scan {
                partition: PartitionName::P0,
                fault: false,
            }],
        ),
        case(
            Invariant::I14b,
            Plant::I14b,
            vec![Op::Remove {
                partition: PartitionName::P0,
                name: Some(BlobName::A),
                fault: false,
            }],
        ),
        case(
            Invariant::I15,
            Plant::I15,
            vec![
                Op::Remove {
                    partition: PartitionName::P0,
                    name: Some(BlobName::A),
                    fault: false,
                },
                Op::ReadAt {
                    slot: 0,
                    offset: Offset::At(0),
                    len: 16,
                    dont_cache: false,
                    fault: false,
                },
            ],
        ),
        case(Invariant::I16a, Plant::I16a, Vec::new()),
        case(Invariant::I16b, Plant::I16b, Vec::new()),
        case(
            Invariant::I16c,
            Plant::I16c,
            vec![Op::Resize {
                slot: 0,
                len: Offset::At(32),
                fault: None,
            }],
        ),
        case(Invariant::I16d, Plant::I16d, Vec::new()),
        case(
            Invariant::I16e,
            Plant::I16e,
            vec![Op::StartSync {
                slot: 0,
                wait: true,
                fault: false,
            }],
        ),
        case(
            Invariant::I16f,
            Plant::I16f,
            vec![Op::Remove {
                partition: PartitionName::P0,
                name: Some(BlobName::A),
                fault: false,
            }],
        ),
        case(
            Invariant::I16g,
            Plant::I16g,
            vec![Op::Scan {
                partition: PartitionName::P0,
                fault: false,
            }],
        ),
        case(Invariant::I18a, Plant::I18a, Vec::new()),
        case(
            Invariant::I18b,
            Plant::I18b,
            vec![Op::Open {
                slot: 0,
                partition: PartitionName::P0,
                name: BlobName::A,
                versions: (0, 0),
                fault: false,
            }],
        ),
    ];

    assert_eq!(cases.len(), Invariant::ALL.len() - 1);
    for (expected, plant, input) in cases {
        let outcome = planted(&input, plant);
        let replay = planted(&input, plant);
        assert_eq!(outcome, replay, "plant {plant:?} replay");
        let violation = outcome
            .violation
            .as_ref()
            .unwrap_or_else(|| panic!("{} ({plant:?}) stayed silent: {outcome:#?}", expected.id()));
        assert_eq!(
            violation.invariant, expected,
            "plant {plant:?}: {violation:#?}"
        );
        assert_eq!(violation.class, expected.class().unwrap());
    }
}

#[test]
fn acceptance_at_034_error_exempts_yield_shape_but_is_measured() {
    let input = hand(vec![Op::ReadMany {
        slot: 0,
        ranges: vec![(Offset::At(0), 8), (Offset::At(8), 8)],
        dont_cache: false,
        fault: false,
    }]);
    let outcome = planted(&input, Plant::I2bThenError);
    assert_eq!(
        outcome.violation.as_ref().unwrap().invariant,
        Invariant::I1b,
        "an error exempts SF-I2b, but is unexpected for two valid ranges"
    );
    assert!(outcome.measured.contains(&Invariant::I2b));
}

#[test]
fn acceptance_at_075_successful_short_probe_is_sf_i18b() {
    let outcome = planted(&hand(Vec::new()), Plant::I18bShortProbe);
    assert_eq!(
        outcome.violation.as_ref().unwrap().invariant,
        Invariant::I18b
    );
}

#[test]
fn acceptance_at_073_sf_i17_panic_passes_through() {
    let input = hand(vec![Op::Scan {
        partition: PartitionName::P0,
        fault: false,
    }]);
    let result = std::panic::catch_unwind(|| planted(&input, Plant::I17));
    assert!(result.is_err());
}

#[test]
fn acceptance_at_077_started_handles_follow_await_and_drop_rules() {
    let read_ranges = vec![(Offset::At(0), 8), (Offset::At(8), 8)];
    let scenarios = [
        hand(vec![Op::StartReadMany {
            slot: 0,
            ranges: read_ranges.clone(),
            dont_cache: false,
            wait: true,
            fault: false,
        }]),
        hand(vec![Op::StartReadMany {
            slot: 0,
            ranges: read_ranges,
            dont_cache: false,
            wait: false,
            fault: false,
        }]),
        hand(vec![
            write(
                0,
                8,
                false,
                Some(WriteFault {
                    fails: false,
                    retention_percent: 0,
                    mode: PartialWriteMode::Prefix,
                }),
                false,
            ),
            Op::StartSync {
                slot: 0,
                wait: true,
                fault: false,
            },
        ]),
        hand(vec![
            write(
                0,
                8,
                false,
                Some(WriteFault {
                    fails: false,
                    retention_percent: 0,
                    mode: PartialWriteMode::Prefix,
                }),
                false,
            ),
            Op::StartSync {
                slot: 0,
                wait: false,
                fault: false,
            },
        ]),
        hand(vec![Op::StartSync {
            slot: 0,
            wait: true,
            fault: true,
        }]),
        hand(vec![Op::StartSync {
            slot: 0,
            wait: false,
            fault: true,
        }]),
    ];
    for input in &scenarios {
        let outcome = run(input, |context| context, Verify::Once);
        assert!(outcome.violation.is_none(), "{outcome:#?}");
    }
    assert!(
        scenarios[1]
            .ops
            .iter()
            .any(|op| matches!(op, Op::StartReadMany { wait: false, .. }))
    );
    let dropped = run(&scenarios[3], |context| context, Verify::Once);
    assert!(
        dropped.trace.records.iter().any(|record| {
            record.origin == Origin::Input && record.result == CallResult::Dropped
        })
    );

    let negative = planted(&scenarios[3], Plant::DroppedStartSync);
    assert_eq!(
        negative.violation.as_ref().unwrap().invariant,
        Invariant::I7
    );
}

#[test]
fn acceptance_at_078_all_injected_failure_carriers() {
    let ranges = vec![(Offset::At(0), 8), (Offset::At(8), 8)];
    let cases = vec![
        (
            Op::Open {
                slot: 1,
                partition: PartitionName::P0,
                name: BlobName::B,
                versions: (0, 0),
                fault: true,
            },
            Plant::I6a,
            Invariant::I6a,
        ),
        (
            Op::OpenDefault {
                slot: 1,
                partition: PartitionName::P0,
                name: BlobName::B,
                fault: true,
            },
            Plant::I6a,
            Invariant::I6a,
        ),
        (
            Op::ReadAt {
                slot: 0,
                offset: Offset::At(0),
                len: 8,
                dont_cache: false,
                fault: true,
            },
            Plant::I6b,
            Invariant::I6b,
        ),
        (
            Op::ReadAtBuf {
                slot: 0,
                offset: Offset::At(0),
                len: 8,
                chunks: vec![3, 7],
                dont_cache: false,
                fault: true,
            },
            Plant::I6b,
            Invariant::I6b,
        ),
        (
            Op::ReadMany {
                slot: 0,
                ranges: ranges.clone(),
                dont_cache: false,
                fault: true,
            },
            Plant::I6b,
            Invariant::I6b,
        ),
        (
            Op::StartReadMany {
                slot: 0,
                ranges,
                dont_cache: false,
                wait: true,
                fault: true,
            },
            Plant::I6b,
            Invariant::I6b,
        ),
        (
            Op::Sync {
                slot: 0,
                fault: true,
            },
            Plant::I6c,
            Invariant::I6c,
        ),
        (
            Op::StartSync {
                slot: 0,
                wait: true,
                fault: true,
            },
            Plant::I6c,
            Invariant::I6c,
        ),
        (
            Op::Remove {
                partition: PartitionName::P0,
                name: Some(BlobName::A),
                fault: true,
            },
            Plant::I6d,
            Invariant::I6d,
        ),
        (
            Op::Remove {
                partition: PartitionName::P0,
                name: None,
                fault: true,
            },
            Plant::I6d,
            Invariant::I6d,
        ),
        (
            Op::Scan {
                partition: PartitionName::P0,
                fault: true,
            },
            Plant::I6e,
            Invariant::I6e,
        ),
        (
            write(8, 8, false, Some(failing_write(100)), false),
            Plant::I4a,
            Invariant::I4a,
        ),
        (write(0, 8, true, None, true), Plant::I4d, Invariant::I4d),
        (resize_op(128, 100, 0), Plant::I5a, Invariant::I5a),
    ];

    for (op, plant, expected) in cases {
        let input = hand(vec![op.clone()]);
        let outcome = run(&input, |context| context, Verify::Once);
        assert!(outcome.violation.is_none(), "{op:#?}: {outcome:#?}");
        let input_record = outcome
            .trace
            .records
            .iter()
            .find(|record| record.origin == Origin::Input)
            .unwrap_or_else(|| panic!("no record for {op:#?}: {outcome:#?}"));
        assert_eq!(input_record.fault, op.fault(), "{input_record:#?}");
        assert!(
            matches!(input_record.result, CallResult::Err(_)),
            "{input_record:#?}"
        );
        assert!(
            outcome.trace.records.iter().all(|record| {
                record.origin == Origin::Input || record.fault == Fault::default()
            })
        );

        let negative = planted(&input, plant);
        let violation = negative
            .violation
            .as_ref()
            .unwrap_or_else(|| panic!("negative stayed silent for {op:#?}: {negative:#?}"));
        assert_eq!(violation.invariant, expected, "{op:#?}: {violation:#?}");
        assert_eq!(violation.class, expected.class().unwrap());
    }
}

#[test]
fn acceptance_at_028_one_run_covers_the_bounded_api_manifest() {
    let ops = vec![
        Op::ReadAt {
            slot: 0,
            offset: Offset::At(0),
            len: 8,
            dont_cache: true,
            fault: true,
        },
        Op::ReadAtBuf {
            slot: 0,
            offset: Offset::At(0),
            len: 8,
            chunks: vec![3, 7],
            dont_cache: true,
            fault: false,
        },
        Op::ReadMany {
            slot: 0,
            ranges: vec![(Offset::At(0), 8), (Offset::At(8), 8)],
            dont_cache: true,
            fault: false,
        },
        Op::StartReadMany {
            slot: 0,
            ranges: vec![(Offset::At(0), 8), (Offset::At(8), 8)],
            dont_cache: true,
            wait: true,
            fault: false,
        },
        Op::StartReadMany {
            slot: 0,
            ranges: vec![(Offset::At(0), 8)],
            dont_cache: false,
            wait: false,
            fault: false,
        },
        write(64, 0, false, None, false),
        Op::Write {
            slot: 0,
            offset: Offset::At(8),
            chunks: vec![2, 3, 3],
            sync: false,
            dont_cache: true,
            write_fault: None,
            sync_fault: false,
        },
        write(
            16,
            8,
            false,
            Some(WriteFault {
                fails: false,
                retention_percent: 50,
                mode: PartialWriteMode::Subset,
            }),
            false,
        ),
        write(
            24,
            8,
            false,
            Some(WriteFault {
                fails: false,
                retention_percent: 50,
                mode: PartialWriteMode::Prefix,
            }),
            false,
        ),
        write(32, 8, true, None, false),
        Op::Sync {
            slot: 0,
            fault: true,
        },
        write(40, 8, false, None, false),
        Op::StartSync {
            slot: 0,
            wait: true,
            fault: false,
        },
        write(48, 8, false, None, false),
        Op::StartSync {
            slot: 0,
            wait: false,
            fault: false,
        },
        resize_op(96, 50, 50),
        Op::Open {
            slot: 1,
            partition: PartitionName::P0,
            name: BlobName::B,
            versions: (0, 0),
            fault: true,
        },
        Op::OpenDefault {
            slot: 1,
            partition: PartitionName::P0,
            name: BlobName::B,
            fault: false,
        },
        Op::Scan {
            partition: PartitionName::P0,
            fault: true,
        },
        Op::Remove {
            partition: PartitionName::P0,
            name: Some(BlobName::B),
            fault: true,
        },
        Op::Remove {
            partition: PartitionName::P0,
            name: Some(BlobName::B),
            fault: false,
        },
        Op::Remove {
            partition: PartitionName::P1,
            name: None,
            fault: false,
        },
        Op::Crash,
        Op::Open {
            slot: 0,
            partition: PartitionName::P0,
            name: BlobName::A,
            versions: (0, 2),
            fault: false,
        },
        Op::Crash,
        Op::OpenDefault {
            slot: 0,
            partition: PartitionName::P0,
            name: BlobName::A,
            fault: false,
        },
        Op::Crash,
    ];
    assert!(ops.len() <= 48);
    assert_eq!(ops.iter().filter(|op| matches!(op, Op::Crash)).count(), 3);
    let input = hand(ops);
    let outcome = run(&input, |context| context, Verify::Once);
    assert!(outcome.violation.is_none(), "{outcome:#?}");

    let input_records = outcome
        .trace
        .records
        .iter()
        .filter(|record| record.origin == Origin::Input)
        .collect::<Vec<_>>();
    for covered in [
        "open",
        "open_default",
        "read_at",
        "read_at_buf",
        "read_many",
        "start_read_many_wait",
        "start_read_many_drop",
        "write_empty",
        "write_multichunk",
        "write_sync",
        "resize",
        "sync",
        "start_sync_wait",
        "start_sync_drop",
        "remove_named",
        "remove_partition",
        "scan",
    ] {
        let present = input_records
            .iter()
            .any(|record| match (covered, &record.call) {
                ("open", Call::Open { default: false, .. }) => true,
                ("open_default", Call::Open { default: true, .. }) => true,
                ("read_at", Call::ReadAt { .. }) => true,
                ("read_at_buf", Call::ReadAtBuf { .. }) => true,
                ("read_many", Call::ReadMany { .. }) => true,
                ("start_read_many_wait", Call::StartReadMany { wait: true, .. }) => true,
                ("start_read_many_drop", Call::StartReadMany { wait: false, .. }) => true,
                ("write_empty", Call::Write { bytes, .. }) if bytes.is_empty() => true,
                ("write_multichunk", Call::Write { chunks, .. }) if chunks.len() > 1 => true,
                ("write_sync", Call::Write { sync: true, .. }) => true,
                ("resize", Call::Resize { .. }) => true,
                ("sync", Call::Sync { .. }) => true,
                ("start_sync_wait", Call::StartSync { wait: true, .. }) => true,
                ("start_sync_drop", Call::StartSync { wait: false, .. }) => true,
                ("remove_named", Call::Remove { name: Some(_), .. }) => true,
                ("remove_partition", Call::Remove { name: None, .. }) => true,
                ("scan", Call::Scan { .. }) => true,
                _ => false,
            });
        assert!(present, "missing {covered}: {input_records:#?}");
    }
    let armed = input_records
        .iter()
        .fold(Fault::default(), |mut seen, record| {
            seen.open |= record.fault.open;
            seen.read |= record.fault.read;
            seen.sync |= record.fault.sync;
            seen.remove |= record.fault.remove;
            seen.scan |= record.fault.scan;
            seen.write = seen.write.or(record.fault.write);
            seen.resize = seen.resize.or(record.fault.resize);
            seen
        });
    assert!(
        armed.open
            && armed.read
            && armed.sync
            && armed.remove
            && armed.scan
            && armed.write.is_some()
            && armed.resize.is_some(),
        "{armed:#?}"
    );
}

fn heavy_write(slot: usize, offset: u64, fails: bool) -> Op {
    Op::Write {
        slot,
        offset: Offset::At(offset),
        chunks: vec![MAX_WRITE],
        sync: false,
        dont_cache: false,
        write_fault: Some(WriteFault {
            fails,
            retention_percent: 50,
            mode: PartialWriteMode::Subset,
        }),
        sync_fault: false,
    }
}

fn heavy_inputs() -> Vec<(&'static str, FuzzInput)> {
    let h1 = hand(
        (0..MAX_OPS)
            .map(|index| heavy_write(0, if index % 2 == 0 { 0 } else { MAX_OFFSET }, false))
            .collect(),
    );
    let h2 = hand(
        (0..MAX_OPS)
            .map(|_| heavy_write(0, MAX_OFFSET, true))
            .collect(),
    );
    let h3 = hand(
        (0..MAX_OPS)
            .map(|index| resize_op(if index % 2 == 0 { 0 } else { MAX_SIZE }, 100, 100))
            .collect(),
    );
    let mut h4_ops = (0..MAX_OPS - 1)
        .map(|index| heavy_write(0, if index % 2 == 0 { 0 } else { MAX_OFFSET }, false))
        .collect::<Vec<_>>();
    h4_ops.push(Op::Open {
        slot: 0,
        partition: PartitionName::P0,
        name: BlobName::A,
        versions: (0, 0),
        fault: false,
    });

    let opens = [
        (0, PartitionName::P0, BlobName::A),
        (1, PartitionName::P0, BlobName::B),
        (2, PartitionName::P0, BlobName::C),
        (3, PartitionName::P1, BlobName::A),
    ];
    let mut h5_ops = Vec::with_capacity(MAX_OPS);
    for session in 0..4 {
        let start = h5_ops.len();
        for &(slot, partition, name) in &opens[usize::from(session == 0)..] {
            h5_ops.push(Op::Open {
                slot,
                partition,
                name,
                versions: (0, 0),
                fault: false,
            });
        }
        let before_crash = if session < 3 { start + 11 } else { start + 12 };
        while h5_ops.len() < before_crash {
            let index = h5_ops.len();
            h5_ops.push(heavy_write(
                index % 4,
                if index % 2 == 0 { 0 } else { MAX_OFFSET },
                false,
            ));
        }
        if session < 3 {
            h5_ops.push(Op::Crash);
        }
    }
    assert_eq!(h5_ops.len(), MAX_OPS);
    assert_eq!(
        h5_ops.iter().filter(|op| matches!(op, Op::Crash)).count(),
        3
    );

    vec![
        ("H1", h1),
        ("H2", h2),
        ("H3", h3),
        ("H4", hand(h4_ops)),
        ("H5", hand(h5_ops)),
    ]
}

#[test]
#[ignore = "acceptance performance measurement"]
fn run_time() {
    for (name, input) in heavy_inputs() {
        let mut samples = Vec::with_capacity(11);
        for _ in 0..11 {
            let start = Instant::now();
            let outcome = run(&input, |context| context, Verify::Once);
            let elapsed = start.elapsed();
            assert!(outcome.violation.is_none(), "{name}: {outcome:#?}");
            samples.push(elapsed);
        }
        samples.sort_unstable();
        let milliseconds = samples
            .iter()
            .map(|duration| duration.as_secs_f64() * 1000.0)
            .collect::<Vec<_>>();
        println!("{name}: {milliseconds:?}; median={:.3} ms", milliseconds[5]);
        assert!(
            milliseconds[5] <= 50.0,
            "{name} median is {:.3} ms",
            milliseconds[5]
        );
    }
}
