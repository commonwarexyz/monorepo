//! Independent acceptance controls from dkg-r30-acceptance.md and SPEC.md.

use super::{
    BootstrapInfo, EPOCH_LENGTH,
    environment::{Event, Program},
    fixtures::{committee, described},
    invariants::{
        self, Bootstrap, Bootstrapper, Carried, Ceremony, Chain, Ending, Material, Observed,
        ProbeCapture, ProbeSend, ProbeShape, ProbeStep, Reshare, Resharer, Startup, StateSync,
        Step,
    },
    schedule::Schedule,
};
use crate::stateful::ProbeEvent::*;
use commonware_consensus::types::{Epoch, FixedEpocher, Height, Round, View};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{Dealer, Info as DkgRound, Logs, Player, Reveal, observe},
        primitives::sharing::Mode,
    },
    sha256,
};
use commonware_glue::dkg::types::EpochOutcome;
use commonware_parallel::Sequential;
use commonware_runtime::{Spawner as _, Supervisor as _};
use commonware_utils::{N3f1, TestRng, ordered::Set, sequence::Unit};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn fails(id: &str, action: impl FnOnce()) {
    let error = catch_unwind(AssertUnwindSafe(action)).expect_err("planted fault must fail");
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .expect("text panic");
    assert!(
        message.starts_with(&format!("{id} violated:")),
        "wrong invariant: {message}"
    );
}

fn identities() -> Vec<super::PublicKey> {
    let mut members = committee();
    let outsider = super::fixtures::identities()
        .into_iter()
        .find(|key| !members.contains(key))
        .expect("fifth identity");
    members.push(outsider);
    members
}

fn bootstrap(count: usize) -> Bootstrap {
    let (info, shares) = described(908, Epoch::zero());
    let info = BootstrapInfo {
        outcome: EpochOutcome::Success,
        epoch: Epoch::zero(),
        directory: Unit,
        output: info.output,
        players: info.players,
        next_players: Set::default(),
    };
    Bootstrap {
        mode: Mode::NonZeroCounter,
        nodes: committee()
            .into_iter()
            .zip(shares)
            .take(count)
            .enumerate()
            .map(|(engine, (identity, share))| Bootstrapper {
                engine,
                identity,
                completions: vec![(Ending::Success(Box::new(info.clone())), Some(share.clone()))],
                held: vec![share.clone()],
                share: Some(share),
            })
            .collect(),
    }
}

fn chain(engine: usize) -> Chain {
    Chain {
        engine,
        finalized: vec![],
        committed: vec![],
        endorsed: vec![],
        delivered: vec![],
        steps: vec![],
    }
}

fn material(view: u64) -> Material {
    Material {
        round: Round::new(Epoch::zero(), View::new(view)),
        digest: sha256::Digest::from([19; 32]),
        info: Box::new(described(908, Epoch::zero()).0),
        boundary: false,
    }
}

#[test]
fn at_024_bootstrap_output_agreement_control() {
    let records = bootstrap(2);
    let counts = invariants::check_bootstrap(&records, &committee(), &[]);
    assert_eq!(counts.agreements + counts.successes, 2);
    let mut broken = records;
    broken.nodes[1].completions[0].0 = Ending::Failure;
    fails("I1", || {
        invariants::check_bootstrap(&broken, &committee(), &[]);
    });
}

#[test]
fn at_025_share_index_and_value_controls() {
    let records = bootstrap(1);
    assert_eq!(
        invariants::check_bootstrap(&records, &committee(), &[]).shares,
        1
    );
    let mut wrong_index = records.clone();
    wrong_index.nodes[0].held[0] = described(908, Epoch::zero()).1[1].clone();
    fails("I2", || {
        invariants::check_bootstrap(&wrong_index, &committee(), &[]);
    });
    let mut wrong_key = records;
    wrong_key.nodes[0].held[0] = described(909, Epoch::zero()).1[0].clone();
    fails("I2", || {
        invariants::check_bootstrap(&wrong_key, &committee(), &[]);
    });
}

#[test]
fn at_026_reconstruction_control() {
    let records = bootstrap(3);
    let Ending::Success(info) = &records.nodes[0].completions[0].0 else {
        unreachable!()
    };
    let mut ceremony = Ceremony {
        epoch: Epoch::zero(),
        nodes: records
            .nodes
            .iter()
            .map(|node| Observed {
                engine: node.engine,
                identity: node.identity.clone(),
                ending: None,
                share: node.share.clone(),
            })
            .collect(),
    };
    assert_eq!(invariants::check_reconstruction(&ceremony, info), 1);
    let mut short = ceremony.clone();
    short.nodes.pop();
    assert_eq!(invariants::check_reconstruction(&short, info), 0);
    ceremony.nodes[0].share = Some(described(909, Epoch::zero()).1[0].clone());
    fails("I3", || {
        invariants::check_reconstruction(&ceremony, info);
    });
}

#[test]
fn at_029_failed_bootstrap_control() {
    let mut records = bootstrap(2);
    for node in &mut records.nodes {
        node.completions = vec![(Ending::Failure, None)];
        node.share = None;
        node.held.clear();
    }
    assert_eq!(
        invariants::check_bootstrap(&records, &committee(), &[])
            .judged(Target::Bootstrap, 0)
            .count(Invariant::I6),
        Some(1)
    );
    records.nodes[0]
        .held
        .push(described(908, Epoch::zero()).1[0].clone());
    fails("I6", || {
        invariants::check_bootstrap(&records, &committee(), &[]);
    });
}

#[test]
fn at_032_correct_node_blocking_control() {
    let identities = committee();
    invariants::check_no_correct_blocks(&[], &identities);
    fails("I9", || {
        invariants::check_no_correct_blocks(
            &[(identities[0].clone(), identities[1].clone())],
            &identities,
        );
    });
}

#[test]
fn at_038_durable_single_sync_controls() {
    let a = material(2);
    let b = material(4);
    let height = Height::new(4);
    let mut node = chain(1);
    node.steps = vec![
        Step::Started(Startup {
            resumed: None,
            synced: None,
            syncs: true,
        }),
        Step::Entered(a.clone()),
        Step::Started(Startup {
            resumed: Some(a.round),
            synced: None,
            syncs: true,
        }),
        Step::Entered(b),
        Step::Synced(height),
        Step::Started(Startup {
            resumed: None,
            synced: Some(height),
            syncs: false,
        }),
    ];
    invariants::check_single_sync(&node);
    let mut backwards = node.clone();
    backwards.steps[3] = Step::Entered(material(1));
    fails("I15", || {
        invariants::check_single_sync(&backwards);
    });
    let mut repeat = node;
    repeat.steps[5] = Step::Started(Startup {
        resumed: None,
        synced: Some(height),
        syncs: true,
    });
    fails("I15", || {
        invariants::check_single_sync(&repeat);
    });
}

fn sync_records() -> StateSync {
    let floor = material(2);
    let height = Height::new(2);
    let mut source = chain(0);
    source.finalized.push((floor.round, height, floor.digest));
    source.committed.push((height, floor.digest));
    source
        .delivered
        .push((Epoch::zero(), (*floor.info).clone()));
    let mut joiner = chain(1);
    joiner.committed = source.committed.clone();
    joiner.delivered = source.delivered.clone();
    joiner.steps = vec![
        Step::Started(Startup {
            resumed: None,
            synced: None,
            syncs: true,
        }),
        Step::Entered(floor.clone()),
        Step::Synced(height),
    ];
    StateSync {
        genesis: *floor.info,
        joiner: 1,
        nodes: vec![source, joiner],
    }
}

#[test]
fn at_039_floor_provenance_control() {
    let records = sync_records();
    assert_eq!(invariants::check_floor_provenance(&records).0, 1);
    let mut unknown = records;
    unknown.nodes[0].finalized.clear();
    fails("I16", || {
        invariants::check_floor_provenance(&unknown);
    });
}

#[test]
fn at_040_agreement_after_sync_controls() {
    let records = sync_records();
    let (blocks, descriptions) = invariants::check_agreement_after_sync(&records);
    assert_eq!(blocks + descriptions, 2);
    let mut divergent = records.clone();
    divergent.nodes[1].committed[0].1 = sha256::Digest::from([20; 32]);
    fails("I17", || {
        invariants::check_agreement_after_sync(&divergent);
    });
    let mut unknown = records;
    unknown.nodes[1].delivered[0].1.outcome = EpochOutcome::Failure;
    fails("I17", || {
        invariants::check_agreement_after_sync(&unknown);
    });
}

#[test]
fn at_041_payload_placement_controls() {
    let genesis = described(908, Epoch::zero()).0;
    let schedule = Schedule::new(&identities(), 4, &super::fixtures::STAY);
    let node = Resharer {
        engine: 0,
        identity: committee()[0].clone(),
        placed: vec![
            (Height::new(1), Carried::Nothing),
            (Height::new(17), Carried::DealerLog),
            (Height::new(31), Carried::EpochInfo),
        ],
        delivered: vec![],
        registered: vec![],
        shares: vec![],
        unplayed: vec![],
    };
    let mut records = Reshare {
        genesis,
        schedule,
        nodes: vec![node],
    };
    let epocher = FixedEpocher::new(EPOCH_LENGTH);
    assert_eq!(invariants::check_placement(&epocher, &records).blocks, 3);
    let mut second = records.nodes[0].clone();
    second.engine = 1;
    second.identity = committee()[1].clone();
    second.placed = vec![(Height::new(31), Carried::EpochInfo)];
    records.nodes.push(second);
    assert_eq!(invariants::check_placement(&epocher, &records).blocks, 4);
    let mut early = records.clone();
    early.nodes[0].placed[0].1 = Carried::DealerLog;
    fails("I18", || {
        invariants::check_placement(&epocher, &early);
    });
    records.nodes[0].placed[1].1 = Carried::EpochInfo;
    fails("I18", || {
        invariants::check_placement(&epocher, &records);
    });
}

fn resharer(engine: usize) -> Resharer {
    Resharer {
        engine,
        identity: committee()[engine].clone(),
        placed: vec![],
        delivered: vec![],
        registered: vec![],
        shares: vec![],
        unplayed: vec![],
    }
}

fn reshare() -> Reshare {
    Reshare {
        genesis: described(908, Epoch::zero()).0,
        schedule: Schedule::new(&identities(), 4, &super::fixtures::STAY),
        nodes: vec![resharer(0), resharer(1)],
    }
}

#[test]
fn at_024_reshare_agreement_control() {
    let mut records = reshare();
    let mut next = records.genesis.clone();
    next.epoch = Epoch::new(1);
    next.outcome = EpochOutcome::Failure;
    for node in &mut records.nodes {
        node.delivered.push((next.epoch, next.clone()));
    }
    assert_eq!(invariants::check_epoch_agreement(&records).1, 1);
    records.nodes[1].delivered[0].1.outcome = EpochOutcome::Success;
    fails("I1", || {
        invariants::check_epoch_agreement(&records);
    });
}

#[test]
fn at_025_share_and_registration_units() {
    let mut records = reshare();
    records.nodes.truncate(1);
    let share = described(908, Epoch::zero()).1[0].clone();
    let registration = commonware_glue::dkg::types::SchemeInfo::Signer {
        participants: records.genesis.output.players().clone(),
        sharing: records.genesis.output.public().clone(),
        share: share.clone(),
    };
    records.nodes[0].shares.push((Epoch::zero(), share));
    records.nodes[0]
        .registered
        .push((Epoch::zero(), registration));
    let counts = invariants::check_reshare(&records, &[]);
    assert_eq!(counts.shares + counts.registrations, 2);
    records.nodes[0].registered[0].1 = commonware_glue::dkg::types::SchemeInfo::Verifier {
        participants: records.genesis.output.players().clone(),
        sharing: records.genesis.output.public().clone(),
    };
    fails("I2", || {
        invariants::check_reshare(&records, &[]);
    });
}

#[test]
fn at_029_failed_reshare_control() {
    let mut records = reshare();
    let mut next = records.genesis.clone();
    next.epoch = Epoch::new(1);
    next.outcome = EpochOutcome::Failure;
    records.nodes[0].delivered.push((next.epoch, next));
    assert_eq!(
        invariants::check_reshare(&records, &[])
            .judged(Target::Reshare)
            .count(Invariant::I6),
        Some(1)
    );
    records.nodes[0].delivered[0].1.output = super::fixtures::resummarized(&records.genesis.output);
    fails("I6", || {
        invariants::check_reshare(&records, &[]);
    });
}

#[test]
fn at_031_panic_ownership_controls() {
    let twin = crate::stateful::runner::Panic {
        engine: Some(4),
        message: "same message".into(),
    };
    invariants::check_panics(&[twin], &[4]);
    for engine in [Some(0), None] {
        let fault = crate::stateful::runner::Panic {
            engine,
            message: "same message".into(),
        };
        fails("I8", || {
            invariants::check_panics(&[fault], &[4]);
        });
    }
}

fn probe_records(deliveries: usize, artifacts: usize) -> invariants::ProbeRun {
    let (genesis, shares) = described(908, Epoch::zero());
    let signers: Vec<super::scheme::Scheme> = shares
        .into_iter()
        .map(|share| {
            super::scheme::Scheme::signer(
                super::RESHARE_NAMESPACE,
                genesis.output.players().clone(),
                genesis.output.public().clone(),
                share,
            )
            .unwrap()
        })
        .collect();
    let certify = |epoch, view, byte| {
        crate::stateful::observe::certify(
            &signers,
            commonware_consensus::simplex::types::Proposal::new(
                Round::new(Epoch::new(epoch), View::new(view)),
                View::new(view - 1),
                sha256::Digest::from([byte; 32]),
            ),
        )
    };
    let boundary = certify(0, 31, 31);
    let latest: Vec<_> = (1..=3)
        .map(|index| certify(1, index * 2, index as u8))
        .collect();
    let mut info = genesis.clone();
    info.epoch = Epoch::new(1);
    info.outcome = EpochOutcome::Failure;
    let identities = identities();
    let sources = (0..3)
        .map(|index| invariants::ProbeSource {
            engine: index + 1,
            identity: identities[index + 1].clone(),
            foreign: false,
            finalizations: vec![boundary.clone(), latest[index].clone()],
        })
        .collect();
    let captures = latest
        .iter()
        .enumerate()
        .map(|(source, finalization)| {
            let mut bytes = vec![5];
            commonware_codec::Write::write(finalization, &mut bytes);
            invariants::ProbeCapture {
                source,
                request: vec![4],
                bytes,
            }
        })
        .collect::<Vec<_>>();
    let mut steps = vec![
        invariants::ProbeStep::Subscribed,
        invariants::ProbeStep::Requested {
            recipients: commonware_p2p::Recipients::All,
            bytes: vec![4],
        },
    ];
    for (index, capture) in captures.iter().enumerate().take(deliveries) {
        steps.push(invariants::ProbeStep::Sent(invariants::ProbeSend {
            origin: identities[index + 1].clone(),
            shape: invariants::ProbeShape::Response(index),
            bytes: capture.bytes.clone(),
        }));
        steps.push(invariants::ProbeStep::Delivered {
            peer: identities[index + 1].clone(),
            bytes: capture.bytes.clone(),
        });
    }
    for _ in 0..artifacts {
        steps.push(invariants::ProbeStep::Resolved(Box::new(
            invariants::ProbeArtifact {
                floor: latest[1].clone(),
                finalization: Some(boundary.clone()),
                info: info.clone(),
            },
        )));
    }
    invariants::ProbeRun {
        discoverer: identities[0].clone(),
        outsider: identities[4].clone(),
        sources,
        chain: invariants::ProbeChain {
            genesis,
            finalizations: latest,
            boundaries: [(Epoch::new(1), (boundary, info))].into_iter().collect(),
        },
        foreign: invariants::ProbeChain {
            genesis: described(909, Epoch::zero()).0,
            finalizations: vec![],
            boundaries: Default::default(),
        },
        bootstrap: Epoch::zero(),
        persisted: None,
        steps,
        captures,
        blocked: vec![],
    }
}

#[test]
fn at_001_probe_units_are_independent() {
    let records = probe_records(2, 2);
    assert_eq!(invariants::check_probe_floor(&records), 1);
    assert_eq!(invariants::check_probe_artifact(&records), 2);
    let (required, forbidden, _, _) = invariants::check_probe_blocks(&records);
    assert_eq!(required + forbidden, 2);
}

#[test]
fn at_035_first_two_dealers_select_the_floor() {
    let mut records = probe_records(3, 1);
    assert_eq!(invariants::check_probe_floor(&records), 1);
    let third = records.sources[2].finalizations.last().unwrap().clone();
    let invariants::ProbeStep::Resolved(artifact) = records.steps.last_mut().unwrap() else {
        unreachable!()
    };
    artifact.floor = third;
    fails("I12", || {
        invariants::check_probe_floor(&records);
    });
}

#[test]
fn at_036_artifact_consistency_controls() {
    let records = probe_records(2, 1);
    assert_eq!(invariants::check_probe_artifact(&records), 1);
    let mut foreign = records.clone();
    let invariants::ProbeStep::Resolved(artifact) = foreign.steps.last_mut().unwrap() else {
        unreachable!()
    };
    artifact.info = foreign.foreign.genesis.clone();
    fails("I13", || {
        invariants::check_probe_artifact(&foreign);
    });
    let mut duplicate = records;
    let mut other = duplicate.steps.last().unwrap().clone();
    let invariants::ProbeStep::Resolved(artifact) = &mut other else {
        unreachable!()
    };
    artifact.finalization = None;
    duplicate.steps.push(other);
    fails("I13", || {
        invariants::check_probe_artifact(&duplicate);
    });
}

#[test]
fn at_037_response_isolation_both_directions() {
    let mut records = probe_records(1, 0);
    let sender = records.outsider.clone();
    records.steps.extend([
        invariants::ProbeStep::Sent(invariants::ProbeSend {
            origin: sender.clone(),
            shape: invariants::ProbeShape::Junk,
            bytes: vec![255],
        }),
        invariants::ProbeStep::Delivered {
            peer: sender.clone(),
            bytes: vec![255],
        },
        invariants::ProbeStep::Blocked {
            peer: sender.clone(),
        },
    ]);
    records.blocked.push((records.discoverer.clone(), sender));
    let (required, forbidden, _, _) = invariants::check_probe_blocks(&records);
    assert_eq!((required, forbidden), (1, 1));
    let mut missing = records.clone();
    missing.steps.pop();
    missing.blocked.clear();
    fails("I14", || {
        invariants::check_probe_blocks(&missing);
    });
    let mut extra = records;
    let valid = extra.sources[0].identity.clone();
    extra.steps.insert(
        4,
        invariants::ProbeStep::Blocked {
            peer: valid.clone(),
        },
    );
    extra.blocked.push((extra.discoverer.clone(), valid));
    fails("I14", || {
        invariants::check_probe_blocks(&extra);
    });
}

use super::report::{AGGREGATE_INTERVAL, Emitter, Invariant, Judged, Target, fold};

fn expected_ids(target: Target) -> &'static [u8] {
    match target {
        Target::Bootstrap | Target::BootstrapRestarts => &[1, 2, 3, 6, 8, 9],
        Target::Reshare | Target::ReshareRestarts => &[1, 2, 3, 4, 5, 6, 8, 9, 18],
        Target::Probe => &[8, 12, 13, 14],
        Target::StateSync => &[1, 2, 3, 4, 5, 6, 8, 9, 15, 16, 17, 18],
    }
}

fn expected_reason(id: u8) -> &'static str {
    match id {
        1 => "no result was compared",
        2 => "no share or registration was recorded",
        3 => "too few shares of one output",
        4 => "no ceremony completed",
        5 => "no mixed set of shares",
        6 => "no failed ceremony was reported",
        8 | 9 => "nothing ran",
        12 | 13 => "no artifact was emitted",
        14 => "no delivery was judged",
        15 => "no start followed a floor",
        16 => "no floor was entered",
        17 => "no sync completed",
        18 => "no block was delivered",
        _ => panic!("unexpected id"),
    }
}

fn assert_report(report: Judged, executed: bool) {
    let entries = report.entries();
    assert_eq!(
        entries
            .iter()
            .map(|e| e.invariant.number())
            .collect::<Vec<_>>(),
        expected_ids(report.target())
    );
    for entry in entries {
        assert_eq!(entry.measured(), entry.count > 0);
        assert_eq!(
            entry.reason,
            (entry.count == 0).then(|| expected_reason(entry.invariant.number()))
        );
        if executed && matches!(entry.invariant, Invariant::I8 | Invariant::I9) {
            assert_eq!(entry.count, 1);
        }
    }
}

#[test]
fn at_002_every_zero_reason_and_matrix() {
    for target in Target::ALL {
        assert_report(Judged::new(target), false);
    }
}

#[test]
fn at_001_at_006_at_009_probe_report_units() {
    for (deliveries, artifacts) in [(0, 0), (1, 0), (2, 1), (2, 2)] {
        let records = probe_records(deliveries, artifacts);
        let report = invariants::check_probe(&records).judged();
        assert_report(report, true);
        assert_eq!(
            report.count(Invariant::I12),
            Some(usize::from(artifacts > 0))
        );
        assert_eq!(report.count(Invariant::I13), Some(artifacts));
        assert_eq!(report.count(Invariant::I14), Some(deliveries));
    }
}

#[test]
fn at_003_at_005_independent_bootstrap_counts() {
    let mut records = bootstrap(1);
    let report =
        invariants::check_bootstrap(&records, &committee(), &[]).judged(Target::Bootstrap, 0);
    assert_eq!(report.count(Invariant::I2), Some(1));
    assert_eq!(report.count(Invariant::I6), Some(0));
    assert_eq!(
        report.reason(Invariant::I6),
        Some("no failed ceremony was reported")
    );
    records.nodes[0].held[0] = described(909, Epoch::zero()).1[0].clone();
    fails("I2", || {
        invariants::check_bootstrap(&records, &committee(), &[]);
    });
}

#[test]
fn at_012_at_038_state_sync_count_units() {
    let records = sync_records();
    let counts = invariants::check_state_sync(&records);
    let report = counts.judged(&Default::default());
    assert_eq!(report.count(Invariant::I15), Some(0));
    assert_eq!(report.count(Invariant::I16), Some(1));
    assert_eq!(report.count(Invariant::I17), Some(2));
    let mut more_sources = records;
    let mut extra = more_sources.nodes[0].clone();
    extra.engine = 2;
    more_sources.nodes.push(extra);
    assert_eq!(
        invariants::check_state_sync(&more_sources)
            .judged(&Default::default())
            .count(Invariant::I17),
        Some(2)
    );
    let mut node = chain(1);
    node.steps = vec![
        Step::Started(Startup {
            resumed: None,
            synced: None,
            syncs: true,
        }),
        Step::Entered(material(2)),
        Step::Started(Startup {
            resumed: Some(material(2).round),
            synced: None,
            syncs: true,
        }),
        Step::Entered(material(4)),
        Step::Synced(Height::new(4)),
        Step::Started(Startup {
            resumed: None,
            synced: Some(Height::new(4)),
            syncs: false,
        }),
    ];
    assert_eq!(invariants::check_single_sync(&node).judged_steps, 3);
}

#[test]
fn at_022_at_023_aggregate_values_and_exact_lines() {
    for target in Target::ALL {
        let id = target.invariants()[0];
        let reports = [
            Judged::new(target).with(id, 1),
            Judged::new(target),
            Judged::new(target).with(id, 2),
        ];
        let aggregate = fold(target, &reports);
        assert_eq!(aggregate.runs(), 3);
        let expected = expected_ids(target)
            .iter()
            .enumerate()
            .map(|(index, id)| format!(" I{id}={}", if index == 0 { "2/1" } else { "0/3" }))
            .collect::<String>();
        assert_eq!(
            aggregate.to_string(),
            format!("[{}] aggregate runs=3{expected}", target.name())
        );
        for tally in aggregate.tallies() {
            assert_eq!(tally.measured + tally.unmeasured, 3);
        }
    }
}

#[test]
fn at_051_aggregate_lifecycle() {
    for target in Target::ALL {
        let mut emitter = Emitter::new(target, Vec::<String>::new());
        let report = Judged::new(target).with(Invariant::I8, 1);
        let saved = report;
        for completed in 1..=2 * AGGREGATE_INTERVAL + 1 {
            emitter.completed(&report);
            assert_eq!(emitter.sink().len(), completed / AGGREGATE_INTERVAL);
        }
        emitter.finish();
        assert_eq!(report, saved);
        assert_eq!(emitter.sink().len(), 3);
        for (line, total) in emitter.sink().iter().zip([
            AGGREGATE_INTERVAL,
            2 * AGGREGATE_INTERVAL,
            2 * AGGREGATE_INTERVAL + 1,
        ]) {
            assert!(line.starts_with(&format!("[{target}] aggregate runs={total} ")));
            assert!(line.contains(&format!(" I8={total}/0")));
        }
    }
}

#[test]
fn at_033_replay_compares_entries_and_reasons() {
    let report = Judged::new(Target::Probe).with(Invariant::I8, 1);
    assert_eq!(invariants::check_replay(report, report), 1);
    fails("I10", || {
        invariants::check_replay(report, report.with(Invariant::I12, 1));
    });
}

#[test]
fn at_013_at_014_all_targets_short_inputs_and_replay() {
    macro_rules! check {
        ($run:path) => {
            for length in 0..=7 {
                let bytes = vec![0; length];
                let first = $run(super::fixtures::decode(&bytes));
                assert_report(first.judged, true);
                if length == 0 {
                    let second = $run(super::fixtures::decode(&bytes));
                    assert_eq!(invariants::check_replay(first, second), 1);
                }
            }
        };
    }
    check!(super::run_dkg_bootstrap);
    check!(super::run_dkg_bootstrap_restarts);
    check!(super::run_dkg_reshare);
    check!(super::run_dkg_reshare_restarts);
    check!(super::run_dkg_probe);
    check!(super::run_dkg_state_sync);
}

#[test]
fn at_004_timeout_is_healthy_and_keeps_zero_reasons() {
    let input = super::DkgBootstrapRestartsFuzzInput {
        sharing_mode: Mode::NonZeroCounter,
        environment: super::EnvironmentControls {
            restarts: 0,
            links: super::LinkControls {
                latency_ms: 10,
                jitter_ms: 0,
                delivery_percent: 0,
            },
            cuts: vec![],
        },
        raw_bytes: super::fixtures::tape(908),
    };
    let report = super::run_dkg_bootstrap_restarts(input);
    assert_eq!(report.outcome, super::Outcome::Timeout);
    assert_eq!(report.judged.count(Invariant::I1), Some(0));
    assert_report(report.judged, true);
}

#[test]
fn at_006_at_010_real_probe_without_deliveries() {
    let input = super::DkgProbeFuzzInput {
        sources: [0; 3],
        foreign: [false; 3],
        bootstrap_epoch: 0,
        floor: None,
        sharing_mode: Mode::NonZeroCounter,
        events: vec![],
        raw_bytes: super::fixtures::tape(908),
    };
    let report = super::run_dkg_probe(input);
    assert_eq!(report.judged.count(Invariant::I8), Some(1));
    for id in [Invariant::I12, Invariant::I13, Invariant::I14] {
        assert_eq!(report.judged.count(id), Some(0));
    }
    assert_report(report.judged, true);
}

fn assert_covered(target: Target, reports: &[Judged]) {
    for id in target.invariants() {
        if target == Target::Bootstrap && *id == Invariant::I6 {
            assert!(
                reports
                    .iter()
                    .any(|r| r.reason(*id) == Some("no failed ceremony was reported"))
            );
        } else {
            assert!(
                reports.iter().any(|r| r.count(*id).is_some_and(|n| n > 0)),
                "{target}: {id} is never measured"
            );
        }
    }
}

#[test]
fn at_016_bootstrap_coverage() {
    let report = super::run_dkg_bootstrap(super::fixtures::decode(&[]));
    assert_covered(Target::Bootstrap, &[report.judged]);
    let mut missing = report.judged;
    missing = missing.with(Invariant::I3, 0);
    assert!(catch_unwind(|| assert_covered(Target::Bootstrap, &[missing])).is_err());
}

#[test]
fn at_018_bootstrap_restart_coverage() {
    let normal = super::run_dkg_bootstrap_restarts(super::fixtures::decode(&[]));
    let (links, cuts, seed) = super::fixtures::failing();
    let failed = super::run_dkg_bootstrap_restarts(super::DkgBootstrapRestartsFuzzInput {
        sharing_mode: Mode::NonZeroCounter,
        environment: super::EnvironmentControls {
            restarts: 1,
            links,
            cuts,
        },
        raw_bytes: super::fixtures::tape(seed),
    });
    assert_eq!(failed.judged.count(Invariant::I6), Some(1));
    assert_covered(Target::BootstrapRestarts, &[normal.judged, failed.judged]);
}

#[test]
fn at_017_reshare_coverage() {
    let normal = super::run_dkg_reshare(super::fixtures::decode(&[]));
    let input = super::DkgReshareFuzzInput {
        case_selector: 0,
        sustained: true,
        prefix: None,
        epochs: 1,
        masks: [super::DkgMask([super::Side::Both; 4]); 3],
        sharing_mode: Mode::NonZeroCounter,
        outsider: 0,
        rotations: super::fixtures::STAY,
        mailbox: 100,
        raw_bytes: super::fixtures::tape(0),
    };
    let failed = super::run_dkg_reshare(input);
    assert_eq!(failed.judged.count(Invariant::I6), Some(1));
    assert_covered(Target::Reshare, &[normal.judged, failed.judged]);
}

#[test]
fn at_019_reshare_restart_coverage() {
    let normal = super::run_dkg_reshare_restarts(super::fixtures::decode(&[]));
    let (links, cuts, seed) = super::fixtures::failing();
    let input = super::DkgReshareRestartsFuzzInput {
        session: super::SessionControls {
            epochs: 2,
            sharing_mode: Mode::NonZeroCounter,
            outsider: 4,
            rotations: super::fixtures::STAY,
            mailbox: 100,
        },
        environment: super::EnvironmentControls {
            restarts: 1,
            links,
            cuts,
        },
        raw_bytes: super::fixtures::tape(seed),
    };
    let failed = super::run_dkg_reshare_restarts(input);
    assert!(failed.judged.count(Invariant::I6).unwrap() > 0);
    assert_covered(Target::ReshareRestarts, &[normal.judged, failed.judged]);
}

#[test]
fn at_007_at_020_probe_coverage() {
    let reports: Vec<_> = (0..8)
        .map(|byte| super::run_dkg_probe(super::fixtures::decode(&[byte])).judged)
        .collect();
    assert_covered(Target::Probe, &reports);
}

#[test]
fn at_027_continuity_control() {
    let mut records = reshare();
    let mut next = records.genesis.clone();
    next.epoch = Epoch::new(1);
    records.nodes[0].delivered.push((next.epoch, next.clone()));
    assert_eq!(
        invariants::check_reshare(&records, &[])
            .judged(Target::Reshare)
            .count(Invariant::I4),
        Some(1)
    );
    next.next_players = Set::default();
    fails("I4", || {
        invariants::check_continuity(&records.schedule, next.epoch, &records.genesis, &next);
    });
    next = records.nodes[0].delivered[0].1.clone();
    next.output = described(909, Epoch::zero()).0.output;
    fails("I4", || {
        invariants::check_continuity(&records.schedule, next.epoch, &records.genesis, &next);
    });
}

#[test]
fn at_021_state_sync_coverage() {
    let reports: Vec<_> = [vec![], vec![0x36, 0xf5], vec![0], vec![1], vec![2], vec![3]]
        .iter()
        .map(|bytes| super::run_dkg_state_sync(super::fixtures::decode(bytes)).judged)
        .collect();
    assert_eq!(reports[1].count(Invariant::I6), Some(1));
    assert_covered(Target::StateSync, &reports);
}

#[test]
fn at_008_real_probe_judges_one_delivery_without_artifact() {
    let report = super::run_dkg_probe(super::DkgProbeFuzzInput {
        sources: [0; 3],
        foreign: [false; 3],
        bootstrap_epoch: 0,
        floor: None,
        sharing_mode: Mode::NonZeroCounter,
        events: vec![crate::stateful::ProbeEvent::Junk {
            origin: 3,
            payload: vec![255],
        }],
        raw_bytes: super::fixtures::tape(908),
    });
    assert_eq!(report.counts.deliveries, 1);
    assert_eq!(report.judged.count(Invariant::I14), Some(1));
    for id in [Invariant::I12, Invariant::I13] {
        assert_eq!(report.judged.count(id), Some(0));
        assert_eq!(report.judged.reason(id), Some("no artifact was emitted"));
    }
    assert_report(report.judged, true);
}

#[test]
fn at_009_unsettled_delivery_adds_no_unit() {
    let mut records = probe_records(0, 0);
    let peer = records.sources[0].identity.clone();
    records.steps.push(ProbeStep::Requested {
        recipients: commonware_p2p::Recipients::One(peer.clone()),
        bytes: vec![2, 1],
    });
    let captured = records.captures.len();
    let bytes = vec![3, 1, 0];
    records.captures.push(ProbeCapture {
        source: 0,
        request: vec![2, 1],
        bytes: bytes.clone(),
    });
    // The requested responder delivered its whole block, but no artifact followed.
    // A later cut block can be ignored or refused (Choices made, item 11).
    for (shape, body) in [
        (ProbeShape::Response(captured), bytes.clone()),
        (ProbeShape::Prefix(captured), bytes[..2].to_vec()),
        (ProbeShape::Junk, vec![255]),
    ] {
        records.steps.extend([
            ProbeStep::Sent(ProbeSend {
                origin: peer.clone(),
                shape,
                bytes: body.clone(),
            }),
            ProbeStep::Delivered {
                peer: peer.clone(),
                bytes: body,
            },
        ]);
    }
    records
        .steps
        .push(ProbeStep::Blocked { peer: peer.clone() });
    records.blocked.push((records.discoverer.clone(), peer));
    let counts = invariants::check_probe(&records);
    assert_eq!(
        (
            counts.deliveries,
            counts.refusals,
            counts.admissions,
            counts.unsettled
        ),
        (3, 1, 1, 1)
    );
    assert_eq!(counts.judged().count(Invariant::I14), Some(2));
}

// The sampler is kept with the acceptance suite so its search can be repeated.
#[test]
#[ignore = "bounded search for a fixed AT-011 input"]
fn at_011_find_incomplete_sync_input() {
    let limit = std::env::var("DKG_ACCEPTANCE_SEARCH_LIMIT")
        .map(|value| value.parse::<u16>().expect("a bounded sample count"))
        .unwrap_or(4096)
        .clamp(1, 4096);
    for seed in 0..limit {
        let bytes = seed.to_le_bytes();
        let report = super::run_dkg_state_sync(super::fixtures::decode(&bytes));
        if report.outcome == super::Outcome::Timeout
            && report.sync.starts == 1
            && report.sync.entries == 0
            && report.sync.blocks == 0
            && report.sync.descriptions == 0
        {
            eprintln!("AT-011 seed={seed} bytes={bytes:?} report={report:?}");
            return;
        }
        if (seed + 1) % 64 == 0 {
            eprintln!("AT-011 completed {} inputs without a match", seed + 1);
        }
    }
    eprintln!(
        "AT-011 no incomplete-sync fixture in {limit} inputs; real-input acceptance remains open"
    );
}

#[test]
fn at_015_stalled_ceremony_is_healthy() {
    let report = super::run_dkg_bootstrap_restarts(super::DkgBootstrapRestartsFuzzInput {
        sharing_mode: Mode::NonZeroCounter,
        environment: super::EnvironmentControls {
            restarts: 0,
            links: super::LinkControls {
                latency_ms: 10,
                jitter_ms: 0,
                delivery_percent: 0,
            },
            cuts: vec![],
        },
        raw_bytes: super::fixtures::tape(909),
    });
    assert_eq!(report.outcome, super::Outcome::Timeout);
    assert_eq!(report.counts.completed, 0);
    assert_eq!(report.counts.shares, 0);
    for id in [Invariant::I1, Invariant::I2, Invariant::I3, Invariant::I6] {
        assert_eq!(report.judged.count(id), Some(0));
    }
    assert_report(report.judged, true);
}

// Build valid observations through the ceremony API; no oracle code supplies results.
fn acceptance_ceremony(
    previous: Option<(
        &super::Info,
        &[commonware_cryptography::bls12381::primitives::group::Share],
    )>,
    reveal: Option<usize>,
) -> (
    super::Info,
    Vec<commonware_cryptography::bls12381::primitives::group::Share>,
) {
    let keys = super::identities();
    let players = Set::from_iter_dedup(keys.iter().map(|key| key.public_key()));
    let epoch = u64::from(previous.is_some());
    let round = DkgRound::<super::MockGroup, super::PublicKey>::new::<N3f1>(
        b"_COMMONWARE_GLUE_FUZZ_ACCEPTANCE_CEREMONY",
        epoch,
        previous.map(|(info, _)| info.output.clone()),
        Mode::NonZeroCounter,
        Reveal::V1,
        players.clone(),
        players.clone(),
    )
    .unwrap();
    let mut rng = TestRng::new(919);
    let mut states: Vec<_> = players
        .iter()
        .map(|identity| {
            let key = keys
                .iter()
                .find(|key| key.public_key() == *identity)
                .unwrap();
            Player::new(round.clone(), key.clone()).unwrap()
        })
        .collect();
    let mut logs = Logs::<_, _, N3f1>::new(round.clone());
    for key in &keys {
        let index = players.position(&key.public_key()).unwrap();
        let (mut dealer, public, dealings) = Dealer::start::<N3f1>(
            &mut rng,
            round.clone(),
            key.clone(),
            previous.map(|(_, shares)| shares[index].clone()),
        )
        .unwrap();
        for (identity, private) in dealings {
            let index = players.position(&identity).unwrap();
            if reveal == Some(index) {
                continue;
            }
            let ack = states[index]
                .dealer_message::<N3f1>(key.public_key(), public.clone(), private)
                .unwrap()
                .unwrap();
            dealer.receive_player_ack(identity, ack).unwrap();
        }
        let (identity, log) = dealer.finalize::<N3f1>().check(&round).unwrap();
        logs.record(identity, log);
    }
    let output = observe::<_, _, N3f1>(&mut rng, logs.clone(), &Sequential).unwrap();
    let shares = states
        .into_iter()
        .map(|player| {
            player
                .finalize::<N3f1>(&mut rng, logs.clone(), &Sequential)
                .unwrap()
                .1
        })
        .collect();
    (
        super::Info {
            outcome: EpochOutcome::Success,
            epoch: Epoch::new(epoch),
            directory: super::schedule::directory(&players),
            output,
            players: players.clone(),
            next_players: players,
        },
        shares,
    )
}

#[test]
fn at_028_one_mixed_set_counts_once_and_detects_either_sharing() {
    let (old_info, old_shares) = described(908, Epoch::zero());
    let (new_info, new_shares) = acceptance_ceremony(Some((&old_info, &old_shares)), None);
    assert_eq!(
        old_info.output.public().public(),
        new_info.output.public().public()
    );
    let observation = |index: usize, share| Observed {
        engine: index,
        identity: committee()[index].clone(),
        ending: None,
        share: Some(share),
    };
    let old = Ceremony {
        epoch: Epoch::zero(),
        nodes: vec![observation(0, old_shares[0].clone())],
    };
    let new = Ceremony {
        epoch: Epoch::new(1),
        nodes: vec![
            observation(1, new_shares[1].clone()),
            observation(2, new_shares[2].clone()),
        ],
    };
    let count = invariants::check_isolation(Epoch::new(1), &old_info, &new_info, &old, &new);
    assert_eq!(count, 1);
    assert_eq!(
        invariants::ReshareCounts {
            isolations: count,
            ..Default::default()
        }
        .judged(Target::Reshare)
        .count(Invariant::I5),
        Some(1)
    );
    let mut verifies_old = new.clone();
    for (node, share) in verifies_old.nodes.iter_mut().zip(&old_shares[1..3]) {
        node.share = Some(share.clone());
    }
    fails("I5", || {
        invariants::check_isolation(Epoch::new(1), &old_info, &new_info, &old, &verifies_old);
    });
    let mut verifies_new = old.clone();
    verifies_new.nodes[0].share = Some(new_shares[0].clone());
    fails("I5", || {
        invariants::check_isolation(Epoch::new(1), &old_info, &new_info, &verifies_new, &new);
    });
}

#[test]
fn at_030_revealed_correct_identity_does_not_restore_i7() {
    let (info, shares) = acceptance_ceremony(None, Some(0));
    let members = committee();
    assert!(info.output.revealed().position(&members[0]).is_some());
    let info = BootstrapInfo {
        outcome: info.outcome,
        epoch: info.epoch,
        directory: Unit,
        output: info.output,
        players: info.players,
        next_players: Set::default(),
    };
    let records = Bootstrap {
        mode: Mode::NonZeroCounter,
        nodes: members
            .iter()
            .cloned()
            .zip(shares)
            .enumerate()
            .map(|(engine, (identity, share))| Bootstrapper {
                engine,
                identity,
                completions: vec![(Ending::Success(Box::new(info.clone())), Some(share.clone()))],
                held: vec![share.clone()],
                share: Some(share),
            })
            .collect(),
    };
    let report = invariants::check_bootstrap(&records, &members, &[]).judged(Target::Bootstrap, 0);
    assert_report(report, true);
    assert_eq!(report.count(Invariant::I2), Some(4));
    assert_eq!(report.count(Invariant::I3), Some(4));
    assert_eq!(invariants::check_replay(report, report), 1);
    assert!(
        fold(Target::Bootstrap, &[report])
            .tallies()
            .iter()
            .all(|entry| entry.invariant.number() != 7)
    );
}

#[test]
fn at_044_probe_event_boundary() {
    let events = vec![
        Attach { node: 1 },
        Attach { node: 2 },
        Attach { node: 3 },
        Subscribe,
        Release { source: 0 },
        Duplicate { source: 0 },
        Replay { source: 0 },
        Truncate { source: 0, keep: 0 },
        Fragment {
            origin: 1,
            source: 0,
            keep: 0,
        },
        Junk {
            origin: 3,
            payload: vec![255],
        },
        Advance { steps: 1 },
        Unsubscribe,
    ];
    assert!(super::probe_input::drawable(&events));
    let report = super::run_dkg_probe(super::DkgProbeFuzzInput {
        sources: [4; 3],
        foreign: [false; 3],
        bootstrap_epoch: 0,
        floor: None,
        sharing_mode: Mode::NonZeroCounter,
        events: events.clone(),
        raw_bytes: super::fixtures::tape(921),
    });
    assert!(
        report.events.iter().all(|count| *count > 0),
        "{:?}",
        report.events
    );
    assert_report(report.judged, true);
    let setup = include_str!("probe.rs")
        .split("impl Harness {")
        .nth(1)
        .unwrap()
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let probe_only = |source: &str| {
        require_construction(source, &["MarshalActor::init(", "probe::Actor::<"])
            && !["bootstrap::Engine", "reshare::Actor", "orchestrator::Actor"]
                .iter()
                .any(|actor| source.contains(actor))
    };
    assert!(probe_only(setup));
    for actor in ["bootstrap::Engine", "reshare::Actor", "orchestrator::Actor"] {
        assert!(!probe_only(&format!("{setup}\n {actor}::start();")));
    }
    // A same-identity fragment and a fabricated protocol message are not drawn.
    for mutation in [
        Fragment {
            origin: 0,
            source: 0,
            keep: 0,
        },
        Junk {
            origin: 0,
            payload: vec![0],
        },
    ] {
        let mut outside = events.clone();
        outside.push(mutation);
        assert!(!super::probe_input::drawable(&outside));
    }
}

fn source_compact(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect()
}

fn require_construction(source: &str, clauses: &[&str]) -> bool {
    let source = source_compact(source);
    clauses
        .iter()
        .all(|clause| source.contains(&source_compact(clause)))
}

fn construction_mutation(source: &str, clauses: &[&str], before: &str, after: &str) {
    assert!(require_construction(source, clauses));
    assert!(
        source.contains(before),
        "mutation must change source: {before}"
    );
    let changed = source.replace(before, after);
    assert!(
        !require_construction(&changed, clauses),
        "outside-model construction accepted"
    );
}

#[test]
fn at_042_twins_confinement_by_construction() {
    let bootstrap_source = include_str!("twins.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let reshare_source = include_str!("reshare_twins.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    for prefix in [Some(1), Some(16), None] {
        let mut bootstrap: super::DkgBootstrapFuzzInput = super::fixtures::decode(&[]);
        bootstrap.prefix = prefix;
        let report = super::run_dkg_bootstrap(bootstrap);
        assert_eq!(report.counts.correct_nodes, 3);
        assert_report(report.judged, true);
        let mut reshare: super::DkgReshareFuzzInput = super::fixtures::decode(&[]);
        reshare.prefix = prefix;
        let report = super::run_dkg_reshare(reshare);
        assert_eq!(report.counts.correct_nodes, 4);
        assert_report(report.judged, true);
    }
    let topology = [
        "network_sized(&context, &participants, LINK,",
        "(0..participants.len()).filter(|index| *index != compromised)",
        "EngineContext::new(node_context.child(\"secondary\"), SECONDARY_ENGINE)",
    ];
    for source in [bootstrap_source, reshare_source] {
        construction_mutation(
            source,
            &topology,
            "*index != compromised",
            "*index == compromised",
        );
        construction_mutation(source, &topology, "        LINK,", "        lossy_link,");
        let restart_free =
            |text: &str| !text.contains("Program::") && !text.contains("Event::Crash");
        assert!(restart_free(source));
        let restarted = format!("{source}\n Program::new(); Event::Crash(0);");
        assert!(!restart_free(&restarted));
    }
    construction_mutation(
        reshare_source,
        &["application: App,", "application: faulty,"],
        "application: App,",
        "application: faulty,",
    );
    assert!(require_construction(
        bootstrap_source,
        &[
            "(0..=SECONDARY_ENGINE).map(|_| Secrets::default()).collect()",
            "secrets: secrets[engine].clone()",
        ]
    ));
    assert!(require_construction(
        reshare_source,
        &[
            "if engine == SECONDARY_ENGINE { compromised } else { engine }",
            "Secrets::dealt(session.share(identity_of(engine)))",
            "signer: session.signers[identity_of(engine)].clone()",
        ]
    ));
    assert!(require_construction(
        include_str!("../stateful/runner.rs"),
        &["success_rate: probability!(1.0)"]
    ));
}

fn schedule_is_confined(
    events: &[(std::time::Duration, super::environment::Event)],
    identities: usize,
) -> bool {
    let mut down = None;
    for (_, event) in events {
        match event {
            Event::Crash(index) if *index < identities && down.is_none() => down = Some(*index),
            Event::Restart(index) if down == Some(*index) => down = None,
            Event::Cut(links) | Event::Heal(links)
                if links
                    .iter()
                    .all(|(a, b)| *a < identities && *b < identities && a != b) => {}
            _ => return false,
        }
    }
    down.is_none() && events.windows(2).all(|pair| pair[0].0 <= pair[1].0)
}

#[test]
fn at_043_restart_construction_and_schedule_boundaries() {
    let mut held = 0;
    for restarts in [0, super::input::MAX_RESTARTS] {
        let environment = super::EnvironmentControls {
            restarts,
            links: super::fixtures::CLEAN,
            cuts: vec![super::Cut {
                delay: 1,
                duration: 2,
                identity: 0,
                scope: super::CutScope::To(1),
            }],
        };
        let tape = super::fixtures::tape(0);
        let program = Program::new(&environment, tape.clone(), 4);
        assert!(schedule_is_confined(program.events(), 4));
        assert_eq!(
            program
                .events()
                .iter()
                .filter(|(_, event)| matches!(event, Event::Crash(_)))
                .count(),
            usize::from(restarts)
        );
        let mut outside = program.events().to_vec();
        outside.splice(
            0..0,
            [
                (std::time::Duration::ZERO, Event::Crash(0)),
                (std::time::Duration::ZERO, Event::Crash(1)),
            ],
        );
        assert!(!schedule_is_confined(&outside, 4));
        let report = super::run_dkg_bootstrap_restarts(super::DkgBootstrapRestartsFuzzInput {
            sharing_mode: Mode::NonZeroCounter,
            environment: environment.clone(),
            raw_bytes: tape.clone(),
        });
        assert_eq!(report.counts.correct_nodes, 4);
        assert_eq!(report.restarts.restarts, usize::from(restarts));
        held += report.restarts.paced.crashes;
        assert_report(report.judged, true);
        let report = super::run_dkg_reshare_restarts(super::DkgReshareRestartsFuzzInput {
            session: super::SessionControls {
                epochs: 1,
                sharing_mode: Mode::NonZeroCounter,
                outsider: 4,
                rotations: super::fixtures::STAY,
                mailbox: 100,
            },
            environment,
            raw_bytes: tape,
        });
        assert_eq!(report.counts.correct_nodes, 5);
        assert_eq!(report.restarts.restarts, usize::from(restarts));
        held += report.paced.crashes;
        assert_report(report.judged, true);
    }
    assert!(held > 0, "fixed maximum schedule must exercise held writes");
    let bootstrap = include_str!("restarts.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let reshare = include_str!("reshare_cluster.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    construction_mutation(
        bootstrap,
        &[
            "secrets: self.secrets[index].clone()",
            "partition: format!(\"engine-{index}\")",
        ],
        "secrets: self.secrets[index].clone()",
        "secrets: Secrets::default()",
    );
    construction_mutation(
        reshare,
        &[
            "secrets: node.secrets.clone()",
            "partition: format!(\"engine-{index}\")",
            "application: App,",
        ],
        "secrets: node.secrets.clone()",
        "secrets: Secrets::default()",
    );
    // Link faults operate on membership, never on message contents.
    let environment = include_str!("environment.rs");
    let drive = environment
        .split("async fn drive<S: Stack>(")
        .nth(1)
        .unwrap()
        .split("/// Run the engines")
        .next()
        .unwrap();
    let link_contract = |text: &str| {
        !text.contains(".send(")
            && !text.contains(".recv(")
            && require_construction(text, &[".remove_link(", ".add_link(", "link.clone(),"])
    };
    assert!(link_contract(drive));
    assert!(!link_contract(&format!(
        "{drive}\nchannel.send(corrupt(bytes));"
    )));
}

#[test]
fn at_045_state_sync_construction_and_restart_bounds() {
    for restarts in [0, super::state_sync_input::MAX_RESTARTS] {
        let mut input: super::DkgStateSyncFuzzInput = super::fixtures::decode(&[]);
        input.restarts = restarts;
        input.joiner_restart = (restarts > 0).then_some(super::JoinerRestart {
            steps: 1,
            doublings: 0,
            downtime: 1,
        });
        let report = super::run_dkg_state_sync(input);
        assert_eq!(report.counts.correct_nodes, 5);
        assert_eq!(report.overlaps, 0);
        assert!(report.sync.starts > 0 && report.sync.entries > 0);
        assert_eq!(
            report.restarts.restarts,
            usize::from(restarts) + usize::from(restarts > 0)
        );
        assert_report(report.judged, true);
    }
    let source = include_str!("state_sync.rs")
        .split("async fn run<S: Stack>(")
        .nth(1)
        .unwrap()
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    construction_mutation(
        include_str!("state_sync.rs"),
        &["entry: Entry::StateSync,"],
        "entry: Entry::StateSync,",
        "entry: Entry::Genesis,",
    );
    construction_mutation(
        source,
        &["network_sized(&context, &participants, LINK,"],
        "        LINK,",
        "        corrupted_link,",
    );
    let cluster = include_str!("reshare_cluster.rs");
    construction_mutation(
        cluster,
        &["application: App,"],
        "application: App,",
        "application: faulty,",
    );
    construction_mutation(
        cluster,
        &["secrets: node.secrets.clone()"],
        "secrets: node.secrets.clone()",
        "secrets: Secrets::default()",
    );
}

#[test]
#[ignore = "bounded search for an AT-043 held-write input"]
fn at_043_find_held_write_input() {
    for seed in 0..64u16 {
        let report = super::run_dkg_bootstrap_restarts(super::DkgBootstrapRestartsFuzzInput {
            sharing_mode: Mode::NonZeroCounter,
            environment: super::EnvironmentControls {
                restarts: 4,
                links: super::fixtures::CLEAN,
                cuts: vec![super::Cut {
                    delay: 1,
                    duration: 2,
                    identity: 0,
                    scope: super::CutScope::To(1),
                }],
            },
            raw_bytes: super::fixtures::tape(seed),
        });
        if report.restarts.paced.crashes > 0 {
            eprintln!("AT-043 seed={seed} report={report:?}");
            return;
        }
    }
    panic!("no held-write fixture in bounded sample");
}

struct IncompleteSyncStack {
    context: commonware_runtime::deterministic::Context,
    starts: Vec<usize>,
}

impl super::environment::Stack for IncompleteSyncStack {
    async fn start(&mut self, index: usize) -> commonware_runtime::Handle<()> {
        self.starts.push(index);
        self.context
            .child("acceptance_engine")
            .with_attribute("index", index)
            .spawn(|_| std::future::pending())
    }

    fn crashing(&mut self, _: usize) {
        panic!("the no-restart fixture must not crash an engine");
    }

    async fn settled(&mut self, _: &[bool]) {
        std::future::pending().await
    }

    async fn joined(&mut self) {}
}

#[test]
fn at_011_incomplete_sync_records_and_timeout_boundary() {
    let ((played, starts), panics) =
        super::runner::execute(super::fixtures::tape(923), |context| async move {
            let participants = identities();
            let link = super::fixtures::CLEAN.link();
            let oracle = crate::stateful::runner::network_with(
                &context,
                &participants,
                link.clone(),
                commonware_utils::NZUsize!(1),
            )
            .await;
            let program = Program::joining(
                0,
                super::fixtures::tape(923),
                participants.len(),
                super::environment::Join {
                    identity: 1,
                    restart: None,
                    lead: std::time::Duration::ZERO,
                    early: false,
                },
            );
            let mut stack = IncompleteSyncStack {
                context: context.child("acceptance_stack"),
                starts: vec![],
            };
            let played = super::environment::play(
                &context,
                &oracle,
                &participants,
                link,
                program,
                &mut stack,
                std::time::Duration::from_millis(1),
            )
            .await;
            (played, stack.starts)
        });
    assert_eq!(played.outcome, super::Outcome::Timeout);
    assert_eq!(starts, vec![0, 2, 3, 4, 1]);
    assert_eq!(invariants::check_instances_running(&played.instances), 0);
    invariants::check_panics(&panics, &[]);
    let mut records = sync_records();
    let joiner = &mut records.nodes[1];
    joiner.steps.truncate(1);
    joiner.committed.clear();
    joiner.delivered.clear();
    let sync = invariants::check_state_sync(&records);
    assert_eq!((sync.starts, sync.entries, sync.judged_commits), (1, 0, 0));
    let mut genesis = reshare();
    genesis.nodes[0]
        .shares
        .push((Epoch::zero(), described(908, Epoch::zero()).1[0].clone()));
    genesis.nodes[0]
        .placed
        .push((Height::new(1), Carried::Nothing));
    let counts = invariants::check_reshare(&genesis, &[]);
    let judged = sync.judged(&counts);
    assert_report(judged, true);
    for id in [Invariant::I15, Invariant::I16, Invariant::I17] {
        assert_eq!(judged.count(id), Some(0));
        assert_eq!(judged.reason(id), Some(expected_reason(id.number())));
    }
    assert_eq!(judged.count(Invariant::I2), Some(1));
    assert_eq!(judged.count(Invariant::I18), Some(1));
    let genesis_judged = counts.judged(Target::StateSync);
    for id in [
        Invariant::I1,
        Invariant::I2,
        Invariant::I3,
        Invariant::I4,
        Invariant::I5,
        Invariant::I6,
        Invariant::I18,
    ] {
        assert_eq!(judged.count(id), genesis_judged.count(id));
    }
}
