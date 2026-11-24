use super::*;
use arbitrary::Unstructured;
use commonware_consensus::{
    marshal::core::DigestFallback,
    types::{Epoch, Round, View, ViewDelta},
};
use commonware_resolver::Outcome;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpTag {
    SeedBlock,
    ReportFinalization,
    GetBlock,
    GetInfo,
    GetFinalization,
    Prune,
    SetFloor,
    HintFinalized,
    MessageBurst,
    Forward,
    Subscribe,
    DeliverBlock,
    Restart,
    ObserveApplication,
    DirectPutBlock,
    DirectSyncBlocks,
    DirectGetBlock,
    DirectPruneBlocks,
    DirectMissingBlocks,
    DirectLastBlock,
    DirectPutCertificate,
    DirectSyncCertificates,
    DirectGetCertificate,
    DirectPruneCertificates,
    DirectCertificateRanges,
    DirectLastCertificate,
    Ancestry,
    GetVerified,
}

fn tag(op: &StoreOp) -> OpTag {
    match op {
        StoreOp::SeedBlock { .. } => OpTag::SeedBlock,
        StoreOp::ReportFinalization { .. } => OpTag::ReportFinalization,
        StoreOp::GetBlock { .. } => OpTag::GetBlock,
        StoreOp::GetInfo { .. } => OpTag::GetInfo,
        StoreOp::GetFinalization { .. } => OpTag::GetFinalization,
        StoreOp::Prune { .. } => OpTag::Prune,
        StoreOp::SetFloor { .. } => OpTag::SetFloor,
        StoreOp::HintFinalized { .. } => OpTag::HintFinalized,
        StoreOp::MessageBurst { .. } => OpTag::MessageBurst,
        StoreOp::Forward { .. } => OpTag::Forward,
        StoreOp::Subscribe { .. } => OpTag::Subscribe,
        StoreOp::DeliverBlock { .. } => OpTag::DeliverBlock,
        StoreOp::Restart => OpTag::Restart,
        StoreOp::ObserveApplication => OpTag::ObserveApplication,
        StoreOp::DirectPutBlock { .. } => OpTag::DirectPutBlock,
        StoreOp::DirectSyncBlocks => OpTag::DirectSyncBlocks,
        StoreOp::DirectGetBlock { .. } => OpTag::DirectGetBlock,
        StoreOp::DirectPruneBlocks { .. } => OpTag::DirectPruneBlocks,
        StoreOp::DirectMissingBlocks { .. } => OpTag::DirectMissingBlocks,
        StoreOp::DirectLastBlock => OpTag::DirectLastBlock,
        StoreOp::DirectPutCertificate { .. } => OpTag::DirectPutCertificate,
        StoreOp::DirectSyncCertificates => OpTag::DirectSyncCertificates,
        StoreOp::DirectGetCertificate { .. } => OpTag::DirectGetCertificate,
        StoreOp::DirectPruneCertificates { .. } => OpTag::DirectPruneCertificates,
        StoreOp::DirectCertificateRanges { .. } => OpTag::DirectCertificateRanges,
        StoreOp::DirectLastCertificate => OpTag::DirectLastCertificate,
        StoreOp::Ancestry { .. } => OpTag::Ancestry,
        StoreOp::GetVerified { .. } => OpTag::GetVerified,
    }
}

fn expected_selector(selector: u8) -> (OpTag, usize) {
    match selector {
        0..=24 => (OpTag::SeedBlock, 1),
        25..=49 => (OpTag::ReportFinalization, 1),
        50..=61 => (OpTag::GetBlock, 2),
        62..=73 => (OpTag::GetInfo, 2),
        74..=83 => (OpTag::GetFinalization, 1),
        84..=91 => (OpTag::Prune, 2),
        92..=96 => (OpTag::Restart, 0),
        97..=101 => (OpTag::ObserveApplication, 0),
        102..=109 => (OpTag::DirectPutBlock, 1),
        110..=115 => (OpTag::DirectSyncBlocks, 0),
        116..=123 => (OpTag::DirectGetBlock, 2),
        124..=129 => (OpTag::DirectPruneBlocks, 1),
        130..=137 => (OpTag::DirectMissingBlocks, 2),
        138..=141 => (OpTag::DirectLastBlock, 0),
        142..=147 => (OpTag::DirectPutCertificate, 1),
        148..=151 => (OpTag::DirectSyncCertificates, 0),
        152..=155 => (OpTag::DirectGetCertificate, 2),
        156 => (OpTag::DirectPruneCertificates, 1),
        157..=158 => (OpTag::DirectCertificateRanges, 1),
        159 => (OpTag::DirectLastCertificate, 0),
        160..=167 => (OpTag::SetFloor, 2),
        168..=175 => (OpTag::HintFinalized, 2),
        176..=179 => (OpTag::MessageBurst, 2),
        180..=184 => (OpTag::Forward, 1),
        185..=189 => (OpTag::Subscribe, 2),
        190..=199 => (OpTag::DeliverBlock, 4),
        200..=229 => (OpTag::Ancestry, 3),
        230..=255 => (OpTag::GetVerified, 1),
    }
}

fn run_ops(ops: Vec<StoreOp>, unbuffered: bool) -> Vec<StoreEvent> {
    run_store(
        MarshalActorStoreInput {
            raw_bytes: vec![0],
            ops,
            unbuffered,
        },
        &StoreHooks::default(),
    )
    .0
}

fn seeds(indices: impl IntoIterator<Item = u8>) -> Vec<StoreOp> {
    indices
        .into_iter()
        .map(|block_idx| StoreOp::SeedBlock { block_idx })
        .collect()
}

fn finalizations(indices: impl IntoIterator<Item = u8>) -> Vec<StoreOp> {
    indices
        .into_iter()
        .map(|block_idx| StoreOp::ReportFinalization { block_idx })
        .collect()
}

fn yields(events: &[StoreEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|event| match event {
            StoreEvent::AncestryYield { height } => Some(height.get()),
            _ => None,
        })
        .collect()
}

fn ancestry_ends(events: &[StoreEvent]) -> Vec<(AncestryEnd, usize)> {
    events
        .iter()
        .filter_map(|event| match event {
            StoreEvent::AncestryDone { end, polls } => Some((*end, *polls)),
            _ => None,
        })
        .collect()
}

fn deliveries(events: &[StoreEvent]) -> Vec<(u64, Option<Outcome>)> {
    events
        .iter()
        .filter_map(|event| match event {
            StoreEvent::Delivery { height, verdict } => Some((height.get(), *verdict)),
            _ => None,
        })
        .collect()
}

#[test]
fn at_001_variants_have_the_required_fields() {
    let ancestry = StoreOp::Ancestry {
        block_idx: 7,
        bounded: true,
        serve: false,
    };
    assert!(matches!(
        ancestry,
        StoreOp::Ancestry {
            block_idx: 7,
            bounded: true,
            serve: false
        }
    ));
    assert!(matches!(
        StoreOp::GetVerified { block_idx: 9 },
        StoreOp::GetVerified { block_idx: 9 }
    ));
}

#[test]
fn at_002_selector_ranges_and_argument_consumption() {
    for selector in u8::MIN..=u8::MAX {
        let bytes = [selector, 0, 0, 0, 0];
        let mut input = Unstructured::new(&bytes);
        let op = StoreOp::arbitrary(&mut input).unwrap();
        let (expected, arguments) = expected_selector(selector);
        assert_eq!(tag(&op), expected, "selector {selector}");
        assert_eq!(
            input.len(),
            bytes.len() - 1 - arguments,
            "selector {selector}"
        );
    }
}

fn assert_forced_suffix(input: &MarshalActorStoreInput) {
    let expected_prefix = [
        "SeedBlock { block_idx: 0 }",
        "ReportFinalization { block_idx: 0 }",
        "GetBlock { block_idx: 0, by_digest: false }",
        "GetInfo { block_idx: 0, latest: false }",
        "GetFinalization { block_idx: 0 }",
        "ObserveApplication",
        "Prune { block_idx: 0, clamp: true }",
        "DirectPutBlock { block_idx: 0 }",
        "DirectPutBlock { block_idx: 2 }",
        "DirectSyncBlocks",
        "DirectGetBlock { block_idx: 0, by_digest: false }",
        "DirectGetBlock { block_idx: 2, by_digest: true }",
        "DirectMissingBlocks { block_idx: 0, max: 4 }",
        "DirectLastBlock",
        "DirectPruneBlocks { block_idx: 15 }",
        "DirectPutBlock { block_idx: 0 }",
        "DirectPutCertificate { block_idx: 0 }",
        "DirectPutCertificate { block_idx: 2 }",
        "DirectSyncCertificates",
        "DirectGetCertificate { block_idx: 0, by_digest: false }",
        "DirectGetCertificate { block_idx: 2, by_digest: true }",
        "DirectCertificateRanges { block_idx: 0 }",
        "DirectLastCertificate",
        "DirectPruneCertificates { block_idx: 15 }",
        "DirectPutCertificate { block_idx: 0 }",
        "Restart",
        "ObserveApplication",
    ];
    assert_eq!(input.ops.len().min(FORCED_OPS), FORCED_OPS);
    assert_eq!(
        input.ops[..FORCED_OPS - 2]
            .iter()
            .map(|op| format!("{op:?}"))
            .collect::<Vec<_>>(),
        expected_prefix,
    );
    assert!(matches!(
        input.ops[FORCED_OPS - 2],
        StoreOp::GetVerified { block_idx: 0 }
    ));
    assert!(matches!(
        input.ops[FORCED_OPS - 1],
        StoreOp::Ancestry {
            block_idx: 0,
            bounded: false,
            serve: true
        }
    ));
}

#[test]
fn at_003_forced_operations_and_extra_count() {
    assert_eq!((FORCED_OPS, MAX_OPS), (29, 98));
    for selector in u8::MIN..=u8::MAX {
        let mut bytes = vec![0; 256];
        bytes[0] = selector;
        let input = MarshalActorStoreInput::arbitrary(&mut Unstructured::new(&bytes)).unwrap();
        assert_eq!(
            input.ops.len(),
            FORCED_OPS + usize::from(selector % 70),
            "extra-operation selector {selector}",
        );
        assert_forced_suffix(&input);
    }

    for (bytes, expected_len) in [(&[][..], 29), (b"\n".as_slice(), 39)] {
        let input = MarshalActorStoreInput::arbitrary(&mut Unstructured::new(bytes)).unwrap();
        assert_eq!(input.ops.len(), expected_len, "short input {bytes:?}");
        assert_forced_suffix(&input);
        assert!(
            input.ops[FORCED_OPS..]
                .iter()
                .all(|op| matches!(op, StoreOp::SeedBlock { block_idx: 0 }))
        );
    }
}

#[test]
fn at_004_constants_match_the_note() {
    assert_eq!(VIEW_RETENTION, ViewDelta::new(10));
    assert_eq!(ANCESTRY_STEP, EVENT_SETTLE);
    assert_eq!(MAX_ANCESTRY_STEPS, NUM_BLOCKS as usize + 2);
}

#[test]
fn at_005_model_tracks_seed_finalization_and_restart() {
    let hooks = StoreHooks::default();
    let mut seed_model = StoreModel::default();
    seed_model.seeded(4, false, &hooks);
    assert_eq!(seed_model, StoreModel::default());
    seed_model.seeded(4, true, &hooks);
    let mut expected_verified = [false; NUM_BLOCKS as usize];
    expected_verified[4] = true;
    assert_eq!(seed_model.verified_ever, expected_verified);
    assert_eq!(seed_model.verified_since_restart, expected_verified);

    let mut ops = seeds([4]);
    ops.extend([
        StoreOp::ReportFinalization { block_idx: 2 },
        StoreOp::SetFloor {
            block_idx: 1,
            late_round: false,
        },
        StoreOp::SetFloor {
            block_idx: 3,
            late_round: true,
        },
        StoreOp::MessageBurst {
            block_idx: 0,
            count: 0,
        },
        StoreOp::Restart,
    ]);
    let models: Vec<_> = run_ops(ops, false)
        .into_iter()
        .filter_map(|event| match event {
            StoreEvent::Model { model, .. } => Some(model),
            _ => None,
        })
        .collect();
    assert_eq!(models.len(), 6);
    assert_eq!(models[0].verified_ever, expected_verified);
    assert_eq!(models[0].verified_since_restart, expected_verified);

    let mut after_report = [false; NUM_BLOCKS as usize];
    after_report[2] = true;
    assert_eq!(models[1].finalization_given, after_report);
    assert_eq!(models[1].max_final_view, Some(View::new(5)));

    let mut after_floor = after_report;
    after_floor[1] = true;
    assert_eq!(models[2].finalization_given, after_floor);
    assert_eq!(models[2].max_final_view, Some(View::new(5)));

    let mut after_late_floor = after_floor;
    after_late_floor[3] = true;
    assert_eq!(models[3].finalization_given, after_late_floor);
    assert_eq!(models[3].max_final_view, Some(View::new(8)));

    let mut after_burst = after_late_floor;
    for idx in [6, 7, 14, 15] {
        after_burst[idx] = true;
    }
    assert_eq!(models[4].finalization_given, after_burst);
    assert_eq!(models[4].max_final_view, Some(View::new(31)));

    let after_restart = models.last().unwrap();
    assert_eq!(after_restart.verified_ever, expected_verified);
    assert_eq!(
        after_restart.verified_since_restart,
        [false; NUM_BLOCKS as usize]
    );
    assert_eq!(after_restart.finalization_given, after_burst);
    assert_eq!(after_restart.max_final_view, Some(View::new(31)));
}

#[test]
fn at_006_registers_one_timed_before_many_operations() {
    let ops = (0..4)
        .map(|block_idx| StoreOp::Ancestry {
            block_idx,
            bounded: true,
            serve: false,
        })
        .collect();
    let events = run_ops(ops, false);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, StoreEvent::TimedRegistered { label: "ancestry" }))
            .count(),
        1,
    );
    assert!(matches!(
        events.first(),
        Some(StoreEvent::TimedRegistered { label: "ancestry" })
    ));
    let clock_ids: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            StoreEvent::AncestryClock { id } => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(clock_ids, vec![0, 0, 0, 0]);
}

#[test]
fn at_007_get_verified_uses_the_canonical_round() {
    let canonical = make_chain();
    let mut ops = seeds(0..=5);
    ops.extend([
        StoreOp::GetVerified { block_idx: 4 },
        StoreOp::GetVerified { block_idx: 10 },
    ]);
    for unbuffered in [false, true] {
        let queries: Vec<_> = run_ops(ops.clone(), unbuffered)
            .into_iter()
            .filter_map(|event| match event {
                StoreEvent::VerifiedQuery { round, returned } => Some((round, returned)),
                _ => None,
            })
            .collect();
        assert_eq!(queries[0].0, canonical[4].inner().context.round);
        assert_eq!(queries[0].1, Some(canonical[4].digest()));
        assert_eq!(queries[1].0, canonical[10].inner().context.round);
        assert_eq!(queries[1].1, None);
    }
}

#[test]
fn at_008_fallback_depends_on_bound_and_finalization() {
    let canonical = make_chain();
    let start_round = canonical[2].inner().context.round;
    let events = run_ops(
        vec![
            StoreOp::Ancestry {
                block_idx: 2,
                bounded: true,
                serve: false,
            },
            StoreOp::Ancestry {
                block_idx: 2,
                bounded: false,
                serve: false,
            },
            StoreOp::ReportFinalization { block_idx: 2 },
            StoreOp::Ancestry {
                block_idx: 2,
                bounded: false,
                serve: false,
            },
        ],
        false,
    );
    let fallbacks: Vec<_> = events
        .into_iter()
        .filter_map(|event| match event {
            StoreEvent::AncestryFallback { fallback, .. } => Some(fallback),
            _ => None,
        })
        .collect();
    assert_eq!(
        fallbacks,
        vec![
            DigestFallback::FetchByRound { round: start_round },
            DigestFallback::FetchByRound { round: start_round },
            DigestFallback::Wait,
        ]
    );
}

#[test]
fn at_009_absent_unserved_start_ends_only_its_operation() {
    let events = run_ops(
        vec![
            StoreOp::Ancestry {
                block_idx: 5,
                bounded: true,
                serve: false,
            },
            StoreOp::ReportFinalization { block_idx: 6 },
            StoreOp::Ancestry {
                block_idx: 6,
                bounded: false,
                serve: false,
            },
            StoreOp::GetVerified { block_idx: 10 },
        ],
        false,
    );
    assert_eq!(ancestry_ends(&events).len(), 2);
    assert!(matches!(
        events.last(),
        Some(StoreEvent::Model { op: 3, .. })
    ));
}

#[test]
fn at_010_014_016_022_local_walk_reaches_genesis() {
    let mut ops = seeds(0..=5);
    ops.extend(finalizations(0..=2));
    ops.push(StoreOp::Ancestry {
        block_idx: 5,
        bounded: true,
        serve: true,
    });
    for unbuffered in [false, true] {
        let events = run_ops(ops.clone(), unbuffered);
        assert_eq!(yields(&events), vec![6, 5, 4, 3, 2, 1, 0]);
        assert_eq!(ancestry_ends(&events), vec![(AncestryEnd::Genesis, 8)]);
        assert!(deliveries(&events).is_empty());
    }
}

#[test]
fn at_011_012_unserved_parent_is_bounded_and_dropped() {
    let mut ops = seeds([0, 1, 2, 3, 5]);
    ops.extend(finalizations([0, 1, 2, 3, 5]));
    ops.extend([
        StoreOp::Ancestry {
            block_idx: 5,
            bounded: false,
            serve: false,
        },
        StoreOp::GetVerified { block_idx: 3 },
    ]);
    for unbuffered in [false, true] {
        let events = run_ops(ops.clone(), unbuffered);
        assert_eq!(yields(&events), vec![6]);
        assert_eq!(ancestry_ends(&events), vec![(AncestryEnd::Pending, 2)]);
        assert!(deliveries(&events).is_empty());
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, StoreEvent::VerifiedQuery { .. }))
                .count(),
            1,
        );
    }
}

#[test]
fn at_018_020_resolved_delivery_is_yielded() {
    let mut ops = seeds([0, 1, 2, 3, 5]);
    ops.extend(finalizations([0, 1, 2, 3, 5]));
    ops.push(StoreOp::Ancestry {
        block_idx: 5,
        bounded: false,
        serve: true,
    });
    for unbuffered in [false, true] {
        let events = run_ops(ops.clone(), unbuffered);
        assert_eq!(yields(&events), vec![6, 5, 4, 3, 2, 1, 0]);
        let delivered = deliveries(&events);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, 5);
        assert!(matches!(delivered[0].1, Some(Outcome::Resolved(_))));
        assert_eq!(ancestry_ends(&events), vec![(AncestryEnd::Genesis, 9)]);
    }
}

#[test]
fn at_024_026_028_verified_controls() {
    let mut ops = seeds(0..=5);
    ops.extend([
        StoreOp::GetVerified { block_idx: 4 },
        StoreOp::GetVerified { block_idx: 10 },
        StoreOp::Prune {
            block_idx: 1,
            clamp: true,
        },
        StoreOp::SetFloor {
            block_idx: 4,
            late_round: false,
        },
        StoreOp::GetVerified { block_idx: 4 },
        StoreOp::GetVerified { block_idx: 10 },
    ]);
    for unbuffered in [false, true] {
        let queries: Vec<_> = run_ops(ops.clone(), unbuffered)
            .into_iter()
            .filter_map(|event| match event {
                StoreEvent::VerifiedQuery { returned, .. } => Some(returned),
                _ => None,
            })
            .collect();
        assert!(queries[0].is_some());
        assert!(queries[1].is_none());
        assert!(queries[2].is_some());
        assert!(queries[3].is_none());
    }
}

#[test]
#[should_panic(expected = "RA-16")]
fn at_027_suppressed_model_update_fires_ra_16() {
    let mut ops = seeds(0..=5);
    ops.push(StoreOp::GetVerified { block_idx: 4 });
    let _ = run_store(
        MarshalActorStoreInput {
            raw_bytes: vec![0],
            ops,
            unbuffered: false,
        },
        &StoreHooks {
            suppress_verified_ever: Some(4),
        },
    );
}

#[test]
fn at_055_empty_and_short_inputs_run_the_forced_baseline() {
    for (bytes, expected_len) in [(&[][..], 29), (b"\n".as_slice(), 39)] {
        for unbuffered in [false, true] {
            let mut input =
                MarshalActorStoreInput::arbitrary(&mut Unstructured::new(bytes)).unwrap();
            input.unbuffered = unbuffered;
            assert_eq!(input.ops.len(), expected_len, "short input {bytes:?}");
            assert!(
                input.ops[FORCED_OPS..]
                    .iter()
                    .all(|op| matches!(op, StoreOp::SeedBlock { block_idx: 0 }))
            );
            let events = run_store(input, &StoreHooks::default()).0;
            assert_eq!(yields(&events), vec![1, 0]);
            assert!(events.iter().any(|event| matches!(
                event,
                StoreEvent::VerifiedQuery {
                    round,
                    returned: _
                } if *round == Round::new(Epoch::zero(), View::new(1))
            )));
            assert_eq!(ancestry_ends(&events), vec![(AncestryEnd::Genesis, 3)]);
        }
    }
}

#[test]
fn at_057_store_run_is_deterministic() {
    let mut ops = seeds([0, 1, 2, 5]);
    ops.extend(finalizations([0, 1, 2, 5]));
    ops.extend([
        StoreOp::GetVerified { block_idx: 2 },
        StoreOp::Ancestry {
            block_idx: 5,
            bounded: false,
            serve: true,
        },
        StoreOp::Restart,
        StoreOp::GetVerified { block_idx: 2 },
    ]);
    assert_eq!(run_ops(ops.clone(), false), run_ops(ops, false));
}

#[test]
fn at_059_store_allows_legal_pending_and_early_end() {
    let events = run_ops(
        vec![
            StoreOp::Ancestry {
                block_idx: 7,
                bounded: true,
                serve: false,
            },
            StoreOp::ReportFinalization { block_idx: 7 },
            StoreOp::Ancestry {
                block_idx: 7,
                bounded: false,
                serve: false,
            },
        ],
        false,
    );
    assert_eq!(ancestry_ends(&events).len(), 2);
}

#[test]
fn at_069_restart_observation_is_recorded_without_an_assertion() {
    let events = run_ops(
        vec![
            StoreOp::SeedBlock { block_idx: 4 },
            StoreOp::Restart,
            StoreOp::GetVerified { block_idx: 4 },
        ],
        false,
    );
    let observation = events.into_iter().find_map(|event| match event {
        StoreEvent::VerifiedQuery { returned, .. } => Some(returned.is_some()),
        _ => None,
    });
    eprintln!("verified block survives restart: {observation:?}");
    assert!(observation.is_some());
}
