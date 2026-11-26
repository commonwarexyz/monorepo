use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::types::View;
use commonware_consensus_fuzz_simplex::blackout::{
    ABSENT_DRAW_MAX, ABSENT_PARTICIPANT, Blackout, CERTIFICATION_TIMEOUT, CutValue, FuzzInput,
    LEADER_TIMEOUT, LIVENESS_WINDOW, MAX_BLACKOUTS, MAX_CRASH_MASK, MAX_DOWN_MS, MAX_ISOLATE_MS,
    MAX_JITTER_MS, MAX_LATENCY_MS, MAX_RAW_BYTES, MAX_STAGGER_MS, MAX_START_MS, MIN_BLACKOUTS,
    MIN_LATENCY_MS, Observation, Observed, PARTICIPANTS, Plant, Report, all_nullified, fuzz,
    live_validators, own_nullify_at, run, run_observed,
};
use std::{
    collections::{HashMap, HashSet},
    panic::{self, AssertUnwindSafe},
    time::Duration,
};

const FIXED_LATENCY_MS: u64 = 10;
const FIXED_JITTER_MS: u64 = 10;
const FIXED_SEEDS: u64 = 10;

fn one_blackout(
    start_ms: u64,
    isolate_ms: u64,
    crash_mask: u8,
    down_ms: u64,
    stagger_ms: u64,
    relink_first: bool,
) -> Blackout {
    Blackout {
        start_ms,
        isolate_ms,
        crash_mask,
        down_ms,
        stagger_ms,
        relink_first,
    }
}

fn fixed_input(shape: usize, seed: u64) -> FuzzInput {
    let f1 = one_blackout(0, 5_000, 0, 0, 0, true);
    match shape {
        1 => FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            absent: true,
            latency_ms: FIXED_LATENCY_MS,
            jitter_ms: FIXED_JITTER_MS,
            blackouts: vec![f1],
        },
        2 => FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            absent: true,
            latency_ms: FIXED_LATENCY_MS,
            jitter_ms: FIXED_JITTER_MS,
            blackouts: vec![one_blackout(2_000, 500, 0, 1_000, 1_000, false)],
        },
        3 => FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            absent: true,
            latency_ms: FIXED_LATENCY_MS,
            jitter_ms: FIXED_JITTER_MS,
            blackouts: vec![one_blackout(0, 5_000, 0b011, 0, 2_000, true)],
        },
        4 => FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            absent: false,
            latency_ms: FIXED_LATENCY_MS,
            jitter_ms: FIXED_JITTER_MS,
            blackouts: vec![f1],
        },
        5 => FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            absent: true,
            latency_ms: FIXED_LATENCY_MS,
            jitter_ms: FIXED_JITTER_MS,
            blackouts: vec![f1.clone(), f1],
        },
        _ => panic!("unknown fixed shape"),
    }
}

fn decode(bytes: &[u8]) -> FuzzInput {
    FuzzInput::arbitrary(&mut Unstructured::new(bytes)).expect("every byte string must decode")
}

fn panic_text(f: impl FnOnce()) -> String {
    let payload = panic::catch_unwind(AssertUnwindSafe(f)).expect_err("plant must panic");
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

fn index_of(events: &[Observed], predicate: impl Fn(&Observation) -> bool) -> usize {
    events
        .iter()
        .position(|event| predicate(&event.what))
        .expect("expected observation")
}

fn matching(events: &[Observed], predicate: impl Fn(&Observation) -> bool) -> Vec<&Observed> {
    events
        .iter()
        .filter(|event| predicate(&event.what))
        .collect()
}

fn assert_report_consistent(report: &Report, expected_blackouts: usize) {
    assert_eq!(report.blackouts.len(), expected_blackouts);
    assert!(report.recovery <= LIVENESS_WINDOW);
    for blackout in &report.blackouts {
        assert_eq!(blackout.crash_set.len(), blackout.cut.len());
        assert_eq!(
            blackout.all_nullified,
            blackout
                .cut
                .iter()
                .all(|value| value.current_view > 0 && value.own_nullify)
        );
        assert!(
            blackout
                .crash_set
                .iter()
                .copied()
                .eq(blackout.cut.iter().map(|value| value.validator))
        );
    }
}

#[test]
fn blackout_public_entry_and_determinism() {
    let f1 = fixed_input(1, 0);
    let first = run(f1.clone());
    let second = run(f1.clone());
    assert_eq!(first, second);
    fuzz(f1);

    let f2 = fixed_input(2, 7);
    assert_eq!(run(f2.clone()), run(f2));
}

#[test]
fn blackout_committee_and_link_boundaries() {
    assert_eq!(PARTICIPANTS, 4);
    assert_eq!(ABSENT_PARTICIPANT, 0);
    assert_eq!(LEADER_TIMEOUT, Duration::from_secs(1));
    assert_eq!(CERTIFICATION_TIMEOUT, Duration::from_secs(2));

    for absent in [true, false] {
        for (latency_ms, jitter_ms) in [(MIN_LATENCY_MS, 0), (MAX_LATENCY_MS, MAX_JITTER_MS)] {
            let mut input = fixed_input(if absent { 1 } else { 4 }, 0);
            input.latency_ms = latency_ms;
            input.jitter_ms = jitter_ms;
            let (_, events) = run_observed(input, Plant::None);
            let live = live_validators(absent);

            let started: Vec<_> = events
                .iter()
                .filter_map(|event| match event.what {
                    Observation::Started { validator, .. } => Some(validator),
                    _ => None,
                })
                .collect();
            assert_eq!(started, live);

            let first_blackout = index_of(&events, |event| {
                matches!(event, Observation::BlackoutStarted { index: 0 })
            });
            let initial_links = matching(&events[..first_blackout], |event| {
                matches!(event, Observation::Linked { .. })
            });
            assert_eq!(initial_links.len(), live.len() * (live.len() - 1));
            for event in initial_links {
                let Observation::Linked {
                    from,
                    to,
                    latency_ms: observed_latency,
                    jitter_ms: observed_jitter,
                    lossless,
                } = event.what
                else {
                    unreachable!();
                };
                assert!(live.contains(&from) && live.contains(&to));
                assert_ne!(from, to);
                assert_eq!(observed_latency, latency_ms);
                assert_eq!(observed_jitter, jitter_ms);
                assert!(lossless);
            }

            let healed = index_of(&events, |event| matches!(event, Observation::Healed { .. }));
            let last_relink = events[..healed]
                .iter()
                .rposition(|event| matches!(event.what, Observation::Relinked))
                .expect("the final heal must relink the live validators");
            assert!(
                !events[last_relink + 1..healed]
                    .iter()
                    .any(|event| matches!(event.what, Observation::Unlinked { .. }))
            );
        }
    }
}

#[test]
fn blackout_script_order_and_state_reuse() {
    for shape in [1, 2] {
        let input = fixed_input(shape, 0);
        let crash_set = input.blackouts[0].crash_set(input.absent);
        let (_, events) = run_observed(input.clone(), Plant::None);

        let started = index_of(&events, |event| {
            matches!(event, Observation::BlackoutStarted { index: 0 })
        });
        let isolated = index_of(&events, |event| matches!(event, Observation::Isolated));
        let cut = index_of(&events, |event| matches!(event, Observation::Cut));
        let relinked = events
            .iter()
            .rposition(|event| matches!(event.what, Observation::Relinked))
            .expect("blackout must heal");
        let first_restart = index_of(&events, |event| {
            matches!(event, Observation::Restarting { .. })
        });
        let last_restart = events
            .iter()
            .rposition(|event| matches!(event.what, Observation::Restarted { .. }))
            .expect("crashed validators must restart");
        assert!(started < isolated && isolated < cut);

        let aborted = matching(&events, |event| {
            matches!(event, Observation::Aborted { .. })
        });
        let stopped = matching(&events, |event| {
            matches!(event, Observation::Stopped { .. })
        });
        assert_eq!(aborted.len(), crash_set.len());
        assert_eq!(stopped.len(), crash_set.len());
        assert!(aborted.iter().all(|event| event.at == aborted[0].at));
        assert!(
            events
                .iter()
                .rposition(|event| matches!(event.what, Observation::Stopped { .. }))
                .unwrap()
                < first_restart
        );
        if input.blackouts[0].relink_first {
            assert!(relinked < first_restart);
        } else {
            assert!(last_restart < relinked);
        }

        let initial: HashMap<_, _> = events
            .iter()
            .filter_map(|event| match &event.what {
                Observation::Started {
                    validator,
                    generation,
                    partition,
                } => Some((*validator, (*generation, partition.clone()))),
                _ => None,
            })
            .collect();
        for event in &events {
            if let Observation::Restarted {
                validator,
                generation,
                partition,
                same_reporter,
            } = &event.what
            {
                assert!(*same_reporter);
                assert_eq!(partition, &initial[validator].1);
                assert!(*generation > initial[validator].0);
            }
        }
    }

    let input = fixed_input(5, 0);
    let (report, events) = run_observed(input, Plant::None);
    assert_report_consistent(&report, 2);
    let starts: Vec<_> = events
        .iter()
        .enumerate()
        .filter_map(|(position, event)| match event.what {
            Observation::BlackoutStarted { index } => Some((index, position)),
            _ => None,
        })
        .collect();
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[0].0, 0);
    assert_eq!(starts[1].0, 1);
    let before_second = &events[..starts[1].1];
    assert_eq!(
        matching(before_second, |event| matches!(
            event,
            Observation::Restarted { .. }
        ))
        .len(),
        3
    );
    assert_eq!(
        matching(&events, |event| matches!(
            event,
            Observation::Started { .. }
        ))
        .len(),
        3
    );
    let generations: HashMap<usize, Vec<u32>> =
        events
            .iter()
            .fold(HashMap::new(), |mut generations, event| {
                if let Observation::Restarted {
                    validator,
                    generation,
                    same_reporter,
                    ..
                } = event.what
                {
                    assert!(same_reporter);
                    generations.entry(validator).or_default().push(generation);
                }
                generations
            });
    assert_eq!(generations.len(), 3);
    assert!(
        generations
            .values()
            .all(|values| values.len() == 2 && values[1] == values[0] + 1)
    );
}

#[test]
fn blackout_restart_starts_use_exact_stagger() {
    let input = fixed_input(2, 0);
    let stagger = Duration::from_millis(input.blackouts[0].stagger_ms);
    let (_, events) = run_observed(input, Plant::None);
    let starts = matching(&events, |event| {
        matches!(event, Observation::Restarting { .. })
    });
    assert_eq!(starts.len(), 3);
    for pair in starts.windows(2) {
        assert_eq!(pair[1].at - pair[0].at, stagger);
    }
}

#[test]
fn blackout_cut_rules_and_report_values() {
    let me = 7u8;
    let mut nullifies = HashMap::<View, HashSet<u8>>::new();
    assert!(!own_nullify_at(&nullifies, &me, 0));
    nullifies.entry(View::new(3)).or_default().insert(me);
    assert!(!own_nullify_at(&nullifies, &me, 0));
    assert!(!own_nullify_at(&nullifies, &me, 4));
    assert!(own_nullify_at(&nullifies, &me, 3));

    assert!(!all_nullified(&[CutValue {
        validator: 1,
        current_view: 0,
        own_nullify: true,
    }]));
    assert!(!all_nullified(&[CutValue {
        validator: 1,
        current_view: 4,
        own_nullify: false,
    }]));
    assert!(all_nullified(&[
        CutValue {
            validator: 1,
            current_view: 4,
            own_nullify: true,
        },
        CutValue {
            validator: 2,
            current_view: 5,
            own_nullify: true,
        },
    ]));

    let report = run(fixed_input(1, 0));
    assert_report_consistent(&report, 1);
    assert!(report.blackouts[0].all_nullified);
}

#[test]
fn blackout_fixed_matrix_fresh_progress_and_safety() {
    let mut f1_floor = false;
    let mut largest_recovery = Duration::ZERO;
    for shape in 1..=5 {
        for seed in 0..FIXED_SEEDS {
            let input = fixed_input(shape, seed);
            let expected_blackouts = input.blackouts.len();
            let (report, events) = run_observed(input, Plant::None);
            assert_report_consistent(&report, expected_blackouts);
            largest_recovery = largest_recovery.max(report.recovery);
            if shape == 1 {
                f1_floor |= report
                    .blackouts
                    .iter()
                    .any(|blackout| blackout.all_nullified);
            }

            let healed = matching(&events, |event| matches!(event, Observation::Healed { .. }));
            assert_eq!(healed.len(), 1);
            let (baseline, target) = match healed[0].what {
                Observation::Healed {
                    max_baseline,
                    target,
                } => (max_baseline, target),
                _ => unreachable!(),
            };
            assert_eq!(report.max_baseline, baseline);
            assert!(target > baseline);
            let crossed = matching(&events, |event| {
                matches!(event, Observation::Crossed { .. })
            });
            assert_eq!(crossed.len(), if shape == 4 { 4 } else { 3 });
            assert!(crossed.iter().all(|event| match event.what {
                Observation::Crossed { view, .. } => view >= target,
                _ => false,
            }));
            let last_crossing = crossed.iter().map(|event| event.at).max().unwrap();
            assert_eq!(last_crossing - healed[0].at, report.recovery);

            let settled = index_of(&events, |event| matches!(event, Observation::Settled));
            let checked = index_of(&events, |event| {
                matches!(event, Observation::SafetyChecked { .. })
            });
            assert!(settled < checked);
            let Observation::SafetyChecked { validators } = &events[checked].what else {
                unreachable!();
            };
            assert_eq!(validators, &live_validators(shape != 4));
        }
    }
    assert!(f1_floor, "B7 vacuous: no F1 run reached all_nullified");
    println!("largest blackout recovery: {largest_recovery:?}");
}

#[test]
fn blackout_input_decode_and_baseline_activity() {
    assert_eq!(MAX_RAW_BYTES, 32_768);
    assert_eq!(ABSENT_DRAW_MAX, 7);
    assert_eq!(MIN_LATENCY_MS, 1);
    assert_eq!(MAX_LATENCY_MS, 50);
    assert_eq!(MAX_JITTER_MS, 50);
    assert_eq!(MIN_BLACKOUTS, 1);
    assert_eq!(MAX_BLACKOUTS, 3);
    assert_eq!(MAX_START_MS, 3_000);
    assert_eq!(MAX_ISOLATE_MS, 5_000);
    assert_eq!(MAX_CRASH_MASK, 0b111);
    assert_eq!(MAX_DOWN_MS, 3_000);
    assert_eq!(MAX_STAGGER_MS, 2_000);

    let empty = decode(&[]);
    assert_eq!(
        empty,
        FuzzInput {
            raw_bytes: Vec::new(),
            absent: true,
            latency_ms: 1,
            jitter_ms: 0,
            blackouts: vec![one_blackout(0, 5_000, 0, 0, 0, true)],
        }
    );
    let empty_report = run(empty.clone());
    assert_report_consistent(&empty_report, 1);
    fuzz(empty);

    let overlong = vec![0xa5; MAX_RAW_BYTES + 1];
    assert_eq!(decode(&overlong).raw_bytes.len(), MAX_RAW_BYTES);

    let reference: Vec<u8> = (0..64).map(|value| value as u8).collect();
    let mut boundaries = vec![Vec::new()];
    boundaries.extend((1..=reference.len()).map(|length| reference[..length].to_vec()));
    boundaries.extend((1..=64).map(|length| vec![0; length]));
    boundaries.extend((1..=64).map(|length| vec![0xff; length]));
    for bytes in boundaries {
        let input = decode(&bytes);
        assert!((MIN_LATENCY_MS..=MAX_LATENCY_MS).contains(&input.latency_ms));
        assert!(input.jitter_ms <= MAX_JITTER_MS);
        assert!((MIN_BLACKOUTS..=MAX_BLACKOUTS).contains(&input.blackouts.len()));
        assert!(!live_validators(input.absent).is_empty());
    }

    let mut state = 0x7a57_0b1a_c0de_0001u64;
    for case in 0..1_000usize {
        let length = case % 65;
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            bytes.push((state >> 56) as u8);
        }
        let input = decode(&bytes);
        let expected_blackouts = input.blackouts.len();
        let live = live_validators(input.absent);
        let (report, events) = run_observed(input, Plant::None);
        assert_report_consistent(&report, expected_blackouts);
        assert!(!live.is_empty());
        assert_eq!(
            matching(&events, |event| matches!(event, Observation::Healed { .. })).len(),
            1
        );
        assert_eq!(
            matching(&events, |event| matches!(
                event,
                Observation::SafetyChecked { .. }
            ))
            .len(),
            1
        );
        assert_eq!(
            matching(&events, |event| matches!(
                event,
                Observation::BlackoutStarted { .. }
            ))
            .len(),
            expected_blackouts
        );
    }
}

#[test]
fn blackout_crash_masks_follow_the_adversary_model() {
    for absent in [true, false] {
        let live = live_validators(absent);
        for mask in 0..=MAX_CRASH_MASK {
            let blackout = one_blackout(0, 0, mask, 0, 0, true);
            let selected: Vec<_> = (0..3)
                .filter(|bit| mask & (1 << bit) != 0)
                .map(|bit| bit + 1)
                .filter(|validator| live.contains(validator))
                .collect();
            let expected = if selected.is_empty() {
                live.clone()
            } else {
                selected
            };
            assert_eq!(blackout.crash_set(absent), expected);
        }
    }
    let all_live = run(fixed_input(4, 0));
    assert!(!all_live.full_restart_after_nullify);
}

#[test]
fn blackout_liveness_negative_control() {
    let text = panic_text(|| {
        run_observed(
            fixed_input(1, 0),
            Plant::SilenceFinalizations { validator: 2 },
        );
    });
    assert!(text.starts_with("blackout-liveness"), "{text}");
    assert!(text.contains("validator2={"), "{text}");
    assert!(!text.contains("validator1={"), "{text}");
    assert!(!text.contains("validator3={"), "{text}");
    for frontier in ["finalization=", "notarization=", "nullification="] {
        assert!(text.contains(frontier), "{text}");
    }
}

#[test]
fn blackout_safety_negative_control() {
    let text = panic_text(|| {
        run_observed(
            fixed_input(1, 0),
            Plant::ConflictingFinalization { validator: 1 },
        );
    });
    assert!(!text.starts_with("blackout-liveness"), "{text}");
    assert!(text.contains("two payloads finalized"), "{text}");
}
