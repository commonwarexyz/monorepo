//! Acceptance tests derived from the `shared_reads` section of `runtime/fuzz/SPEC.md`.

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{
    Blob, Error, Handle, IoBufMut, IoBufs, IoBufsMut, ReadOptions, Runner as _, Storage as _,
    WriteOptions, deterministic,
};
use commonware_runtime_fuzz::{
    ENTROPY_BYTES, SEED_BYTES, STREAM_BYTES,
    shared_reads::{
        BLOB, Class, Counter, DEADLINE, Event, Form, FuzzInput, Invariant, Location,
        MAX_OPENING_RANGES, MAX_OPS, MAX_PAGES, MAX_RANGES, MAX_READERS, MAX_SPAN, MIN_OPS,
        MIN_PAGES, MIN_READERS, Op, Opener, Opening, Outcome, PAGE_SIZE, PARTITION,
        PHYSICAL_PAGE_SIZE, ReadId, ReadResult, ReaderState, Record, Trace, Violation, fuzz, run,
        run_observed, sample_drop, sample_opening_drop, value,
    },
};
use futures::{StreamExt as _, future::pending};
use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

fn decoded(bytes: &[u8]) -> FuzzInput {
    FuzzInput::arbitrary(&mut Unstructured::new(bytes)).expect("every input length must decode")
}

fn fixed_inputs() -> Vec<Vec<u8>> {
    let mut inputs = vec![Vec::new()];
    inputs.extend((0u64..=255).map(|seed| seed.to_le_bytes().to_vec()));
    inputs
}

fn entropy(seed: u64) -> commonware_utils::Entropy {
    decoded(&seed.to_le_bytes()).entropy
}

fn op(form: Form, ranges: &[(u64, usize)], drop: bool) -> Op {
    Op {
        form,
        ranges: ranges.to_vec(),
        drop,
    }
}

fn plain_input() -> FuzzInput {
    FuzzInput {
        pages: 8,
        cache_pages: 4,
        opening: Opening {
            page: 1,
            first: op(Form::ReadAt, &[(64, 64)], false),
            second: op(Form::ReadAt, &[(64, 64)], false),
        },
        readers: vec![
            vec![op(Form::ReadAt, &[(64, 64)], false)],
            vec![op(Form::ReadAt, &[(64, 64)], false)],
        ],
        entropy: entropy(0),
    }
}

fn free_phase_input() -> FuzzInput {
    FuzzInput {
        pages: 8,
        cache_pages: 4,
        opening: Opening {
            page: 0,
            first: op(Form::ReadAt, &[(0, 64)], false),
            second: op(Form::ReadInto, &[(0, 64)], false),
        },
        readers: vec![
            vec![op(Form::ReadAt, &[(128, 64)], false)],
            vec![op(Form::ReadInto, &[(192, 64)], false)],
        ],
        entropy: entropy(0),
    }
}

fn plant_f1_input() -> FuzzInput {
    FuzzInput {
        pages: 8,
        cache_pages: 4,
        opening: Opening {
            page: 0,
            first: op(Form::ReadAt, &[(0, 64)], false),
            second: op(Form::ReadAt, &[(0, 64)], false),
        },
        readers: vec![
            vec![op(Form::ReadRangesInto, &[(128, 192)], false)],
            vec![op(Form::ReadRangesInto, &[(128, 192)], false)],
        ],
        entropy: entropy(0),
    }
}

fn plant_f2_candidate(seed: u64) -> FuzzInput {
    FuzzInput {
        pages: 8,
        cache_pages: 4,
        opening: Opening {
            page: 0,
            first: op(Form::ReadAt, &[(0, 64)], false),
            second: op(Form::ReadAt, &[(0, 64)], false),
        },
        readers: vec![
            vec![op(Form::ReadRangesInto, &[(128, 256)], false)],
            vec![op(Form::ReadRangesInto, &[(128, 256)], true)],
        ],
        entropy: entropy(seed),
    }
}

fn is_clean_f2_trace(outcome: &Outcome) -> bool {
    let expected = BTreeMap::from([(2, 1), (3, 1), (4, 1), (5, 1)]);
    outcome.violation.is_none() && outcome.cancellations == 1 && outcome.run_reads == expected
}

fn plant_f2_input() -> FuzzInput {
    plant_f2_candidate(2)
}

fn expected(ranges: &[(u64, usize)]) -> Vec<u8> {
    ranges
        .iter()
        .flat_map(|&(offset, len)| (offset..offset + len as u64).map(value))
        .collect()
}

fn location_ranges(location: &Location) -> Option<&[(u64, usize)]> {
    match location {
        Location::Opening { ranges, .. } | Location::Reader { ranges, .. } => Some(ranges),
        Location::OpeningCounts { .. } | Location::Deadline { .. } => None,
    }
}

fn touching_reads(input: &FuzzInput) -> BTreeMap<u64, usize> {
    let mut touches = BTreeMap::new();
    for operation in input.readers.iter().flatten() {
        let pages: BTreeSet<_> = operation
            .ranges
            .iter()
            .flat_map(|&(offset, len)| {
                let first = offset / PAGE_SIZE;
                let last = (offset + len as u64 - 1) / PAGE_SIZE;
                first..=last
            })
            .collect();
        for page in pages {
            *touches.entry(page).or_default() += 1;
        }
    }
    touches
}

fn assert_clean(outcome: &Outcome) {
    assert!(outcome.violation.is_none(), "{outcome:#?}");
    assert_eq!(
        outcome.measured,
        BTreeSet::from([Invariant::I1, Invariant::I2a, Invariant::I2b, Invariant::I3,]),
        "{outcome:#?}"
    );
    for record in &outcome.trace.records {
        match &record.result {
            ReadResult::Completed(bytes) => assert_eq!(
                bytes,
                &expected(location_ranges(&record.location).expect("a read location")),
                "{record:#?}"
            ),
            ReadResult::Cancelled => {}
            ReadResult::Failed(error) => panic!("clean read failed: {error}: {record:#?}"),
        }
    }
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    WrongPage { target: u64, replacement: u64 },
    Pending { target: u64 },
    ReadError { target: u64 },
    DoubleRead { target: u64 },
    StallSync,
}

struct FaultBlob {
    inner: Counter,
    fault: Fault,
}

impl FaultBlob {
    fn new(inner: Counter, fault: Fault) -> Self {
        Self { inner, fault }
    }

    fn applies(&self, offset: u64, len: usize, target: u64) -> bool {
        len > 0
            && offset / PHYSICAL_PAGE_SIZE <= target
            && target <= (offset + len as u64 - 1) / PHYSICAL_PAGE_SIZE
    }

    fn replacement_offset(&self, offset: u64, target: u64, replacement: u64) -> u64 {
        offset - target * PHYSICAL_PAGE_SIZE + replacement * PHYSICAL_PAGE_SIZE
    }
}

impl Blob for FaultBlob {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        match self.fault {
            Fault::WrongPage {
                target,
                replacement,
            } if self.applies(offset, len, target) => {
                self.inner
                    .read_at_buf(
                        self.replacement_offset(offset, target, replacement),
                        len,
                        bufs,
                        options,
                    )
                    .await
            }
            Fault::Pending { target } if self.applies(offset, len, target) => pending().await,
            Fault::ReadError { target } if self.applies(offset, len, target) => {
                Err(Error::ReadFailed)
            }
            Fault::DoubleRead { target } if self.applies(offset, len, target) => {
                self.inner.read_at(offset, len, options).await?;
                self.inner.read_at_buf(offset, len, bufs, options).await
            }
            Fault::None
            | Fault::WrongPage { .. }
            | Fault::Pending { .. }
            | Fault::ReadError { .. }
            | Fault::DoubleRead { .. }
            | Fault::StallSync => self.inner.read_at_buf(offset, len, bufs, options).await,
        }
    }

    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        match self.fault {
            Fault::WrongPage {
                target,
                replacement,
            } if self.applies(offset, len, target) => {
                self.inner
                    .read_at(
                        self.replacement_offset(offset, target, replacement),
                        len,
                        options,
                    )
                    .await
            }
            Fault::Pending { target } if self.applies(offset, len, target) => pending().await,
            Fault::ReadError { target } if self.applies(offset, len, target) => {
                Err(Error::ReadFailed)
            }
            Fault::DoubleRead { target } if self.applies(offset, len, target) => {
                self.inner.read_at(offset, len, options).await?;
                self.inner.read_at(offset, len, options).await
            }
            Fault::None
            | Fault::WrongPage { .. }
            | Fault::Pending { .. }
            | Fault::ReadError { .. }
            | Fault::DoubleRead { .. }
            | Fault::StallSync => self.inner.read_at(offset, len, options).await,
        }
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        self.inner.write_at(offset, bufs, options).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await
    }

    async fn start_sync(&self) -> Handle<()> {
        if matches!(self.fault, Fault::StallSync) {
            Handle::from_future(pending())
        } else {
            self.inner.start_sync().await
        }
    }
}

fn violated(input: &FuzzInput, fault: Fault) -> Violation {
    violated_outcome(input, fault)
        .violation
        .expect("a fault violation")
}

fn violated_outcome(input: &FuzzInput, fault: Fault) -> Outcome {
    let outcome = run(input, |counter| FaultBlob::new(counter, fault));
    assert!(
        outcome.violation.is_some(),
        "fault stayed silent: {outcome:#?}"
    );
    outcome
}

fn assert_violation(input: &FuzzInput, fault: Fault, invariant: Invariant, class: Class) {
    let violation = violated(input, fault);
    assert_eq!(violation.invariant, invariant, "{violation:#?}");
    assert_eq!(violation.class, class, "{violation:#?}");
}

fn panic_text(panic: Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_string()))
        .unwrap_or_else(|| "non-string panic".to_string())
}

#[test]
fn acceptance_at_004_to_008_fixed_decoding_bounds_and_baseline() {
    assert_eq!(<FuzzInput as Arbitrary>::size_hint(0), (0, None));
    let lengths = [
        0,
        1,
        SEED_BYTES + STREAM_BYTES - 1,
        SEED_BYTES + STREAM_BYTES,
        SEED_BYTES + STREAM_BYTES + 1,
        SEED_BYTES + STREAM_BYTES + ENTROPY_BYTES,
    ];
    for len in lengths {
        let input = decoded(&vec![0x5a; len]);
        assert!((MIN_PAGES..=MAX_PAGES).contains(&input.pages));
        assert!((1..input.pages as usize).contains(&input.cache_pages));
    }
    for byte in 0u8..=255 {
        let _ = decoded(&[byte]);
    }

    for (index, bytes) in fixed_inputs().iter().enumerate() {
        let input = decoded(bytes);
        assert!((MIN_READERS..=MAX_READERS).contains(&input.readers.len()));
        assert!(input.pages > input.cache_pages as u64);
        let hot = input.readers[0].first().unwrap().ranges[0].0 / PAGE_SIZE;
        assert_ne!(hot, input.opening.page, "fixed input {index}");
        for ops in &input.readers {
            assert!((MIN_OPS..=MAX_OPS).contains(&ops.len()));
            assert_eq!(ops[0].ranges[0].0 / PAGE_SIZE, hot, "fixed input {index}");
            for operation in ops {
                assert!(!operation.ranges.is_empty());
                assert!(operation.ranges.len() <= MAX_RANGES);
                let mut next = 0;
                for &(offset, len) in &operation.ranges {
                    assert!(len > 0);
                    assert!(offset >= next);
                    assert!(offset + len as u64 <= input.pages * PAGE_SIZE);
                    next = offset + len as u64;
                }
                let first = operation.ranges[0].0 / PAGE_SIZE;
                let last = (next - 1) / PAGE_SIZE;
                assert!(last - first < MAX_SPAN);
            }
        }
    }

    let empty = decoded(&[]);
    assert!(empty.readers.len() >= 2);
    assert!(empty.readers.iter().all(|ops| !ops.is_empty()));
    assert_clean(&run(&empty, |counter| counter));
}

#[test]
fn acceptance_at_004_invalid_manual_input_is_rejected() {
    let mut invalid = plain_input();
    invalid.readers[0][0].ranges = vec![(0, 0)];
    let panic = catch_unwind(AssertUnwindSafe(|| run(&invalid, |counter| counter)))
        .expect_err("an empty range must be rejected");
    assert!(panic_text(panic).contains("invalid input:"));

    let mut invalid = plain_input();
    invalid.opening.second.ranges = vec![(96, 32), (80, 16)];
    let panic = catch_unwind(AssertUnwindSafe(|| run(&invalid, |counter| counter)))
        .expect_err("overlapping ranges must be rejected");
    assert!(panic_text(panic).contains("invalid input:"));
}

#[test]
fn acceptance_at_007_samplers_use_one_selector() {
    for byte in 0u8..=3 {
        let bytes = [byte, 0xaa];
        let mut u = Unstructured::new(&bytes);
        assert_eq!(sample_drop(&mut u).unwrap(), byte == 3);
        assert_eq!(u.len(), 1);
    }
    let mut empty = Unstructured::new(&[]);
    assert!(!sample_drop(&mut empty).unwrap());
    assert_eq!(empty.len(), 0);

    for byte in 0u8..=1 {
        let bytes = [byte, 0xaa];
        let mut u = Unstructured::new(&bytes);
        assert_eq!(sample_opening_drop(&mut u).unwrap(), byte == 1);
        assert_eq!(u.len(), 1);
    }
    let mut empty = Unstructured::new(&[]);
    assert!(!sample_opening_drop(&mut empty).unwrap());
    assert_eq!(empty.len(), 0);
}

#[test]
fn acceptance_at_001_002_003_and_016_runner_construction_and_interface() {
    let input = FuzzInput {
        pages: 8,
        cache_pages: 4,
        opening: Opening {
            page: 1,
            first: op(Form::ReadInto, &[(64, 64)], false),
            second: op(Form::ReadRangesInto, &[(64, 16), (96, 32)], false),
        },
        readers: vec![
            vec![op(Form::ReadAt, &[(128, 64)], false)],
            vec![op(Form::ReadInto, &[(128, 64)], false)],
        ],
        entropy: entropy(0),
    };
    let (observed, events) = run_observed(&input, |counter| FaultBlob::new(counter, Fault::None));
    assert_clean(&observed);
    let direct = run(&input, |counter| FaultBlob::new(counter, Fault::None));
    assert_eq!(observed, direct);

    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Runner { .. }))
            .count(),
        1
    );
    assert!(matches!(
        events.first(),
        Some(Event::Runner {
            cycle,
            timeout: None,
            catch_panics: false,
        }) if *cycle == Duration::from_millis(1)
    ));
    assert!(matches!(
        events.get(1),
        Some(Event::Opened { partition, size: 0 }) if partition == PARTITION
    ));
    assert!(events.contains(&Event::Appended { len: 8 * 64 }));
    assert!(events.contains(&Event::Sealed { size: 8 * 64 }));
    assert!(events.contains(&Event::Synced));
    assert!(events.contains(&Event::Cleared));
    assert!(events.contains(&Event::CountsReset {
        residue: BTreeMap::new(),
    }));
    assert_eq!(BLOB, b"blob");
    assert_eq!(DEADLINE, Duration::from_secs(10));
    for offset in 0..8 * PAGE_SIZE {
        assert_ne!(value(offset), 0);
    }

    let _all = Invariant::ALL;
    assert_eq!(Invariant::I1.id(), "SR-I1");
    assert_eq!(Invariant::I2a.class(), Class::ReadIncomplete);
    assert_eq!(Class::ReadBytes.tag(), "read_bytes");
    let _record = Record {
        location: Location::Opening {
            read: Opener::A,
            form: Form::ReadAt,
            ranges: vec![(0, 1)],
            drop: Some(false),
        },
        result: ReadResult::Completed(vec![value(0)]),
    };
    let _trace = Trace::default();
    fuzz(plant_f1_input());
}

fn event_index(events: &[Event], predicate: impl Fn(&Event) -> bool) -> usize {
    events.iter().position(predicate).expect("event is present")
}

#[test]
fn acceptance_at_009_opening_order_and_forms() {
    for a_form in [Form::ReadAt, Form::ReadInto] {
        for b_form in [Form::ReadAt, Form::ReadInto, Form::ReadRangesInto] {
            for drop_a in [false, true] {
                let b_ranges = if b_form == Form::ReadRangesInto {
                    vec![(64, 16), (96, 16)]
                } else {
                    vec![(64, 64)]
                };
                assert!(b_ranges.len() <= MAX_OPENING_RANGES);
                let mut input = plain_input();
                input.opening.first = op(a_form, &[(64, 64)], drop_a);
                input.opening.second = op(b_form, &b_ranges, false);
                let (outcome, events) = run_observed(&input, |counter| counter);
                assert_clean(&outcome);
                let a = ReadId::Opening(Opener::A);
                let b = ReadId::Opening(Opener::B);
                let created_a = event_index(&events, |event| *event == Event::Created(a));
                let polled_a = event_index(
                    &events,
                    |event| matches!(event, Event::Polled { read, .. } if *read == a),
                );
                let created_b = event_index(&events, |event| *event == Event::Created(b));
                let polled_b = event_index(
                    &events,
                    |event| matches!(event, Event::Polled { read, .. } if *read == b),
                );
                assert!(created_a < polled_a && polled_a < created_b && created_b < polled_b);
                assert!(
                    !events[created_a..polled_b]
                        .iter()
                        .any(|event| matches!(event, Event::Awaited(_)))
                );
                assert!(!events.contains(&Event::Dropped(b)));
                if drop_a {
                    assert!(events.contains(&Event::Dropped(a)));
                }
            }
        }
    }
}

#[test]
fn acceptance_at_010_reader_spawn_poll_drop_and_continue_order() {
    let mut found = None;
    for seed in 0u64..=255 {
        let input = FuzzInput {
            pages: 8,
            cache_pages: 4,
            opening: Opening {
                page: 0,
                first: op(Form::ReadAt, &[(0, 64)], false),
                second: op(Form::ReadAt, &[(0, 64)], false),
            },
            readers: vec![
                vec![
                    op(Form::ReadRangesInto, &[(128, 256)], true),
                    op(Form::ReadAt, &[(64, 64)], false),
                ],
                vec![
                    op(Form::ReadRangesInto, &[(128, 256)], false),
                    op(Form::ReadAt, &[(64, 64)], true),
                ],
            ],
            entropy: entropy(seed),
        };
        let (outcome, events) = run_observed(&input, |counter| counter);
        if outcome.cancellations > 0
            && events
                .iter()
                .any(|event| matches!(event, Event::Dropped(ReadId::Reader { reader: 0, op: 0 })))
            && events
                .iter()
                .any(|event| matches!(event, Event::Created(ReadId::Reader { reader: 0, op: 1 })))
            && events.iter().any(|event| {
                matches!(
                    event,
                    Event::Polled {
                        read: ReadId::Reader { reader: 1, op: 1 },
                        ready: true,
                    }
                )
            })
        {
            found = Some((outcome, events));
            break;
        }
    }
    let (outcome, events) = found.expect("a fixed entropy cancels then continues");
    assert_clean(&outcome);
    let last_spawn = events
        .iter()
        .rposition(|event| matches!(event, Event::Spawned { .. }))
        .unwrap();
    let first_reader_action = events
        .iter()
        .position(|event| matches!(event, Event::Created(ReadId::Reader { .. })))
        .unwrap();
    assert!(last_spawn < first_reader_action);
    let dropped = event_index(&events, |event| {
        matches!(event, Event::Dropped(ReadId::Reader { reader: 0, op: 0 }))
    });
    let continued = event_index(&events, |event| {
        matches!(event, Event::Created(ReadId::Reader { reader: 0, op: 1 }))
    });
    assert!(dropped < continued);
    assert!(events.iter().any(|event| {
        matches!(
            event,
            Event::Polled {
                read: ReadId::Reader { reader: 1, op: 1 },
                ready: true,
            }
        )
    }));
    assert_eq!(
        outcome.cancellations,
        outcome
            .trace
            .records
            .iter()
            .filter(|record| record.result == ReadResult::Cancelled)
            .count()
    );
}

#[test]
fn acceptance_at_011_to_015_negative_controls_and_locations() {
    let opening = plain_input();
    let free = free_phase_input();
    for (input, target, expected_location) in [(&opening, 1, "opening"), (&free, 2, "reader")] {
        let wrong_outcome = violated_outcome(
            input,
            Fault::WrongPage {
                target,
                replacement: target + 1,
            },
        );
        let wrong = wrong_outcome.violation.as_ref().unwrap();
        assert_eq!(wrong.invariant, Invariant::I1);
        assert_eq!(wrong.class, Class::ReadBytes);
        assert!(wrong.mismatch.is_some());
        assert_eq!(
            matches!(wrong.location, Location::Opening { .. }),
            expected_location == "opening"
        );
        assert_eq!(
            wrong_outcome
                .trace
                .records
                .last()
                .map(|record| &record.location),
            Some(&wrong.location),
            "the violating completion must be the last read record"
        );

        let error_outcome = violated_outcome(input, Fault::ReadError { target });
        let error = error_outcome.violation.as_ref().unwrap();
        assert_eq!(error.invariant, Invariant::I2b);
        assert_eq!(error.class, Class::ReadError);
        assert_eq!(
            matches!(error.location, Location::Opening { .. }),
            expected_location == "opening"
        );
        assert_eq!(
            error_outcome
                .trace
                .records
                .last()
                .map(|record| &record.location),
            Some(&error.location),
            "the violating error must be the last read record"
        );
    }

    let timeout = violated(&opening, Fault::Pending { target: 1 });
    assert_eq!(timeout.invariant, Invariant::I2a);
    assert_eq!(timeout.class, Class::ReadIncomplete);
    assert!(matches!(
        timeout.location,
        Location::Deadline {
            opening_ended: false,
            readers: ref states,
            ..
        } if states == &[ReaderState::NotStarted, ReaderState::NotStarted]
    ));

    let timeout = violated(&free, Fault::Pending { target: 2 });
    assert_eq!(timeout.invariant, Invariant::I2a);
    assert!(matches!(
        timeout.location,
        Location::Deadline {
            opening_ended: true,
            ..
        }
    ));

    let count = violated(&opening, Fault::DoubleRead { target: 1 });
    assert_eq!(count.invariant, Invariant::I3);
    assert_eq!(count.class, Class::SingleFetchCount);
    assert!(matches!(
        count.location,
        Location::OpeningCounts {
            page: 1,
            ref opening_reads,
        } if opening_reads.get(&1) == Some(&2)
    ));

    let mut after_cancellation = None;
    for seed in 0u64..=255 {
        let input = FuzzInput {
            pages: 8,
            cache_pages: 4,
            opening: Opening {
                page: 0,
                first: op(Form::ReadAt, &[(0, 64)], false),
                second: op(Form::ReadAt, &[(0, 64)], false),
            },
            readers: vec![
                vec![
                    op(Form::ReadRangesInto, &[(128, 256)], true),
                    op(Form::ReadAt, &[(64, 64)], false),
                ],
                vec![
                    op(Form::ReadRangesInto, &[(128, 256)], false),
                    op(Form::ReadAt, &[(64, 64)], false),
                ],
            ],
            entropy: entropy(seed),
        };
        let outcome = run(&input, |counter| {
            FaultBlob::new(counter, Fault::ReadError { target: 1 })
        });
        if outcome
            .violation
            .as_ref()
            .is_some_and(|violation| violation.after_cancellation)
        {
            after_cancellation = outcome.violation;
            break;
        }
    }
    let after_cancellation =
        after_cancellation.expect("a fixed entropy must violate after a cancellation");
    assert_eq!(after_cancellation.invariant, Invariant::I2b);
    assert_eq!(after_cancellation.class, Class::ReadError);
    assert!(after_cancellation.after_cancellation);

    let panic = catch_unwind(AssertUnwindSafe(|| {
        run(&opening, |counter| {
            FaultBlob::new(counter, Fault::StallSync)
        })
    }))
    .expect_err("a pending start_sync handle must stall the runtime");
    assert!(panic_text(panic).contains("runtime stalled"));
}

#[test]
fn acceptance_at_013_counter_counts_physical_pages_and_forwards() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (blob, size) = context.open("counter", b"blob").await.unwrap();
        assert_eq!(size, 0);
        blob.resize(3 * PHYSICAL_PAGE_SIZE).await.unwrap();
        blob.write_at(
            0,
            vec![7; (3 * PHYSICAL_PAGE_SIZE) as usize],
            WriteOptions::default(),
        )
        .await
        .unwrap();
        let counter = Counter::new(blob);
        counter.read_at(1, 1, ReadOptions::default()).await.unwrap();
        counter
            .read_at_buf(
                PHYSICAL_PAGE_SIZE - 1,
                2,
                IoBufMut::with_capacity(2),
                ReadOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(counter.counts(), BTreeMap::from([(0, 2), (1, 1)]));

        let mut many = Box::pin(counter.read_many(
            &[(0, 1), (2 * PHYSICAL_PAGE_SIZE, 1)],
            ReadOptions::default(),
        ));
        assert!(many.next().await.unwrap().is_ok());
        assert!(many.next().await.unwrap().is_ok());
        assert!(many.next().await.is_none());
        let reads = counter
            .start_read_many(&[(0, 1)], ReadOptions::default())
            .await
            .await
            .unwrap();
        assert_eq!(reads.len(), 1);
        counter
            .write_at(0, vec![9], WriteOptions::default())
            .await
            .unwrap();
        counter.resize(2 * PHYSICAL_PAGE_SIZE).await.unwrap();
        counter.sync().await.unwrap();
        counter.start_sync().await.await.unwrap();
    });
}

#[test]
fn acceptance_at_017_020_021_023_to_032_fixed_clean_and_replay() {
    for (index, bytes) in fixed_inputs().iter().enumerate() {
        let first_input = decoded(bytes);
        let second_input = decoded(bytes);
        let first = run(&first_input, |counter| counter);
        let second = run(&second_input, |counter| counter);
        assert_clean(&first);
        assert_eq!(first, second, "fixed input {index}");
        assert_eq!(first.opening_reads.get(&first_input.opening.page), Some(&1));
    }
}

#[test]
fn acceptance_at_018_025_027_029_031_control_classes_are_distinct() {
    let input = plain_input();
    let cases = [
        (
            Fault::WrongPage {
                target: 1,
                replacement: 2,
            },
            Invariant::I1,
            Class::ReadBytes,
        ),
        (
            Fault::Pending { target: 1 },
            Invariant::I2a,
            Class::ReadIncomplete,
        ),
        (
            Fault::ReadError { target: 1 },
            Invariant::I2b,
            Class::ReadError,
        ),
        (
            Fault::DoubleRead { target: 1 },
            Invariant::I3,
            Class::SingleFetchCount,
        ),
    ];
    for (fault, invariant, class) in cases {
        assert_violation(&input, fault, invariant, class);
    }
}

fn fail_on_violation(input: &FuzzInput, outcome: &Outcome) {
    if let Some(violation) = &outcome.violation {
        violation.class.fail(&format!(
            "{} plant input violated at {:?}; input: {input:?}",
            violation.invariant.id(),
            violation.location
        ));
    }
}

#[test]
fn plant_f1_input_runs_clean() {
    let input = plant_f1_input();
    let outcome = run(&input, |counter| counter);
    fail_on_violation(&input, &outcome);
    assert_clean(&outcome);
}

#[test]
fn plant_f2_input_runs_clean() {
    let input = plant_f2_input();
    let outcome = run(&input, |counter| counter);
    fail_on_violation(&input, &outcome);
    assert_clean(&outcome);
}

#[test]
fn acceptance_at_039_f2_uses_first_qualifying_clean_entropy() {
    for seed in 0..2 {
        let input = plant_f2_candidate(seed);
        assert!(!is_clean_f2_trace(&run(&input, |counter| counter)));
    }
    let input = plant_f2_input();
    assert!(is_clean_f2_trace(&run(&input, |counter| counter)));
}

#[test]
#[ignore = "prints the evidence requested by SR-V10"]
fn batch_read_counts() {
    let mut above_bound = Vec::new();
    for (index, bytes) in fixed_inputs().iter().enumerate() {
        let input = decoded(bytes);
        let outcome = run(&input, |counter| counter);
        assert_clean(&outcome);
        let touches = touching_reads(&input);
        let reasons = if outcome.cancellations == 0 {
            "eviction"
        } else {
            "eviction, cancelled sole standalone waiter, or cancelled batch starter"
        };
        println!(
            "fixed input {index}: run_reads={:?} touching_reads={touches:?} cancellations={} admitted_reasons={reasons}",
            outcome.run_reads, outcome.cancellations
        );
        for (&page, &reads) in &outcome.run_reads {
            if reads > 1 {
                let bound = touches.get(&page).copied().unwrap_or(0);
                println!(
                    "fixed input {index}: page {page} read {reads} times; touching reads {bound}"
                );
                if reads > bound {
                    above_bound.push((index, page, reads, bound));
                }
            }
        }
    }
    assert!(
        above_bound.is_empty(),
        "backend reads above the touching-read bound: {above_bound:?}"
    );
}
