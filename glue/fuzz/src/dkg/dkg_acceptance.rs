//! Independent acceptance controls from dkg-r30-acceptance.md and SPEC.md.

use super::{
    BootstrapInfo, EPOCH_LENGTH,
    environment::{Event, Program},
    fixtures::{committee, described},
    invariants::{
        self, Bootstrap, Bootstrapper, Carried, Ceremony, Chain, Ending, Material, Observed,
        ProbeArtifact, ProbeCapture, ProbeSend, ProbeShape, ProbeStep, ProbeVerdict, Reshare,
        Resharer, Startup, StateSync, Step,
    },
    schedule::Schedule,
};
use crate::stateful::ProbeEvent::*;
use commonware_codec::Write as _;
use commonware_consensus::{
    Block as _, CertifiableBlock as _, Epochable as _, Heightable as _,
    types::{Epoch, FixedEpocher, Height, Round, View},
};
use commonware_cryptography::{
    Digestible as _, Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{Dealer, Info as DkgRound, Logs, Player, Reveal, observe},
        primitives::sharing::Mode,
    },
    sha256,
};
use commonware_glue::dkg::{ReshareBlock as _, types::EpochOutcome};
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

fn rejects(action: impl FnOnce()) {
    assert!(
        catch_unwind(AssertUnwindSafe(action)).is_err(),
        "planted mismatch must fail"
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

const PROBE_RETRY: crate::stateful::ProbeEvent = crate::stateful::ProbeEvent::Advance { steps: 10 };

fn probe_input(
    sources: [u8; 3],
    events: Vec<crate::stateful::ProbeEvent>,
    seed: u16,
) -> super::DkgProbeFuzzInput {
    super::DkgProbeFuzzInput {
        sources,
        foreign: [false; 3],
        bootstrap_epoch: 0,
        floor: None,
        sharing_mode: Mode::NonZeroCounter,
        events,
        checkpoints: [super::probe_input::FINALIZED; 3],
        raw_bytes: super::fixtures::tape(seed),
    }
}

fn probe_program(
    order: &[u8],
    rest: &[crate::stateful::ProbeEvent],
) -> Vec<crate::stateful::ProbeEvent> {
    let mut events = vec![
        Attach { node: 1 },
        Attach { node: 2 },
        Attach { node: 3 },
        Subscribe,
    ];
    events.extend(order.iter().map(|source| Release { source: *source }));
    events.extend(rest.iter().cloned());
    events
}

fn probe_artifact(observed: &super::probe::Observations) -> &ProbeArtifact {
    observed
        .run
        .steps
        .iter()
        .find_map(|step| match step {
            ProbeStep::Resolved(artifact) => Some(artifact.as_ref()),
            _ => None,
        })
        .expect("the fixed probe program emits an artifact")
}

fn assert_checkpoint_artifact(record: &invariants::ProbeCheckpoint, artifact: &ProbeArtifact) {
    assert_eq!(record.epoch, Epoch::new(2));
    assert_eq!(record.block.height(), Height::new(3));
    let Some(commonware_glue::dkg::types::Payload::EpochInfo(info)) = record.block.payload() else {
        panic!("the introducing block carries epoch information");
    };
    assert_eq!(info, artifact.info);
    assert_eq!(record.commitment, record.block.digest());
    let finalization = record
        .finalization
        .as_ref()
        .expect("an epoch past zero has a boundary finalization");
    assert_eq!(finalization.epoch(), Epoch::new(1));
    assert_eq!(finalization.proposal.payload, record.commitment);
    assert_eq!(artifact.floor.epoch(), Epoch::new(2));
    assert_eq!(artifact.finalization.as_ref(), Some(finalization));
}

fn flip_network_block(run: &mut invariants::ProbeRun, peer: &super::PublicKey, blocked: bool) {
    let pair = (run.discoverer.clone(), peer.clone());
    if blocked {
        assert!(!run.blocked.contains(&pair));
        run.blocked.push(pair);
    } else {
        let position = run
            .blocked
            .iter()
            .position(|recorded| *recorded == pair)
            .expect("the correct run recorded the required block");
        run.blocked.remove(position);
    }
}

fn probe_request(tag: u8, epoch: u64) -> Vec<u8> {
    let mut bytes = vec![tag];
    Epoch::new(epoch).write(&mut bytes);
    bytes
}

fn block_response(epoch: Epoch, block: &super::app::Block) -> Vec<u8> {
    let mut bytes = vec![3];
    epoch.write(&mut bytes);
    block.write(&mut bytes);
    bytes
}

fn probe_verdicts(observed: &super::probe::Observations) -> Vec<ProbeVerdict> {
    invariants::probe_judgments(&observed.run)
        .0
        .into_iter()
        .map(|judgment| judgment.verdict)
        .collect()
}

fn clone_probe(observed: &super::probe::Observations) -> super::probe::Observations {
    super::probe::Observations {
        outcome: observed.outcome,
        events: observed.events,
        run: observed.run.clone(),
        stopped: observed.stopped.clone(),
    }
}

fn crafted_probe(bytes: Vec<u8>, serving: bool) -> super::probe::Observations {
    let events = serving.then_some(Attach { node: 0 }).into_iter().collect();
    super::probe::observe_planted(
        probe_input([5; 3], events, 940),
        async move |harness, stage| {
            if stage == super::probe::Stage::Closing {
                harness.craft(3, bytes.clone());
                harness.execute(&Advance { steps: 1 }).await;
            }
        },
    )
}

fn crafted_fetch_probe(bytes: Vec<u8>) -> super::probe::Observations {
    super::probe::observe_planted(
        probe_input([5; 3], probe_program(&[0, 1], &[]), 941),
        async move |harness, stage| {
            if stage == super::probe::Stage::Closing {
                harness.craft(3, bytes.clone());
                harness.execute(&Advance { steps: 1 }).await;
            }
        },
    )
}

fn assert_one_probe_verdict(
    observed: &super::probe::Observations,
    verdict: ProbeVerdict,
) -> super::PublicKey {
    let (judgments, _) = invariants::probe_judgments(&observed.run);
    let [judgment] = judgments.as_slice() else {
        panic!("expected one crafted delivery, got {judgments:?}");
    };
    assert_eq!(judgment.verdict, verdict);
    assert_eq!(judgment.blocked, verdict == ProbeVerdict::Block);
    judgment.send.origin.clone()
}

fn recovered_state_sync_input(steps: u8, doublings: u8) -> super::DkgStateSyncFuzzInput {
    super::DkgStateSyncFuzzInput {
        session: super::SessionControls {
            epochs: 1,
            sharing_mode: Mode::NonZeroCounter,
            outsider: super::fixtures::OUTSIDER,
            rotations: super::fixtures::STAY,
            mailbox: 100,
        },
        joiner: 0,
        join_height: 5,
        joiner_restart: Some(super::JoinerRestart {
            steps,
            doublings,
            downtime: 1,
        }),
        restarts: 0,
        first_outage: super::FirstOutage {
            steps: 10,
            doublings: 3,
        },
        raw_bytes: super::fixtures::tape(0),
    }
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
            checkpoints: vec![],
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
    let observed = super::probe::observe_planted(
        probe_input([3, 4, 5], probe_program(&[0, 1, 5, 1, 1], &[]), 935),
        async |_, _| {},
    );
    let report = super::probe::measure(&observed);
    let (selections, artifact) = invariants::probe_selections(&observed.run);
    assert_eq!(selections.len(), 1, "{report}");
    assert_eq!(artifact.unwrap().floor, selections[0].floor);
    assert_eq!(report.judged.count(Invariant::I12), Some(1));
    let third = observed.run.sources[2]
        .finalizations
        .last()
        .expect("the third dealer answered")
        .clone();
    assert!(third.round() > selections[0].floor.round());

    let mut planted = observed;
    for step in &mut planted.run.steps {
        if let ProbeStep::Resolved(artifact) = step {
            artifact.floor = third.clone();
        }
    }
    fails("I12", || {
        super::probe::measure(&planted);
    });
}

#[test]
fn at_036_artifact_consistency_controls() {
    let observed = super::probe::observe_planted(
        probe_input([4, 5, 3], probe_program(&[0, 1, 0, 0], &[]), 936),
        async |_, _| {},
    );
    let report = super::probe::measure(&observed);
    assert_eq!(report.judged.count(Invariant::I13), Some(1));

    let mut foreign = clone_probe(&observed);
    for step in &mut foreign.run.steps {
        if let ProbeStep::Resolved(artifact) = step {
            artifact.info = foreign.run.foreign.genesis.clone();
        }
    }
    fails("I13", || {
        super::probe::measure(&foreign);
    });

    let mut wrong_boundary = clone_probe(&observed);
    for step in &mut wrong_boundary.run.steps {
        if let ProbeStep::Resolved(artifact) = step {
            artifact.finalization = wrong_boundary.run.chain.finalizations.first().cloned();
        }
    }
    fails("I13", || {
        super::probe::measure(&wrong_boundary);
    });

    let mut duplicate = observed;
    let mut other = duplicate
        .run
        .steps
        .iter()
        .find(|step| matches!(step, ProbeStep::Resolved(_)))
        .expect("the real run emitted an artifact")
        .clone();
    let ProbeStep::Resolved(artifact) = &mut other else {
        unreachable!();
    };
    artifact.info = duplicate.run.foreign.genesis.clone();
    duplicate.run.steps.push(other);
    fails("I13", || {
        super::probe::measure(&duplicate);
    });
}

#[test]
fn at_037_response_isolation_both_directions() {
    let blocked = crafted_probe(Vec::new(), false);
    let passing = super::probe::observe_planted(
        probe_input([3; 3], probe_program(&[0], &[]), 937),
        async |_, _| {},
    );
    assert_report(super::probe::measure(&blocked).judged, true);
    assert_report(super::probe::measure(&passing).judged, true);

    let mut missing = clone_probe(&blocked);
    missing
        .run
        .steps
        .retain(|step| !matches!(step, ProbeStep::Blocked { .. }));
    fails("I14", || {
        super::probe::measure(&missing);
    });

    let mut extra = clone_probe(&passing);
    let peer = extra.run.sources[0].identity.clone();
    let delivered = extra
        .run
        .steps
        .iter()
        .position(|step| matches!(step, ProbeStep::Delivered { .. }))
        .unwrap();
    extra
        .run
        .steps
        .insert(delivered + 1, ProbeStep::Blocked { peer: peer.clone() });
    extra
        .run
        .blocked
        .push((extra.run.discoverer.clone(), peer.clone()));
    fails("I14", || {
        super::probe::measure(&extra);
    });

    let mut sender_block = clone_probe(&passing);
    sender_block
        .run
        .blocked
        .push((peer.clone(), sender_block.run.discoverer.clone()));
    fails("I14", || {
        super::probe::measure(&sender_block);
    });

    let mut bystander = passing;
    let other = bystander.run.sources[1].identity.clone();
    let delivered = bystander
        .run
        .steps
        .iter()
        .position(|step| matches!(step, ProbeStep::Delivered { .. }))
        .unwrap();
    bystander
        .run
        .steps
        .insert(delivered + 1, ProbeStep::Blocked { peer: other });
    fails("I14", || {
        super::probe::measure(&bystander);
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

    for length in 0..=7 {
        let bytes = vec![0; length];
        let input: super::DkgProbeFuzzInput = super::fixtures::decode(&bytes);
        for (source, height) in input.checkpoints.iter().zip(input.sources) {
            for (epoch, checkpoint) in source.iter().enumerate() {
                if super::probe_input::introducing(epoch) > u64::from(height) {
                    assert_eq!(
                        *checkpoint,
                        super::SourceCheckpoint::Missing,
                        "length {length}, height {height}, epoch {epoch}"
                    );
                }
            }
            assert_ne!(source[0], super::SourceCheckpoint::Finalized);
        }
    }

    let mut input = probe_input([5, 3, 1], probe_program(&[0, 1], &[]), 913);
    input.checkpoints = [[super::SourceCheckpoint::Missing; 4]; 3];
    input.checkpoints[0][2] = super::SourceCheckpoint::Finalized;
    input.checkpoints[1][1] = super::SourceCheckpoint::Unfinalized;
    let first = super::probe::observe_planted(input.clone(), async |_, _| {});
    let second = super::probe::observe_planted(input, async |_, _| {});
    assert_eq!(
        super::probe::measure(&first),
        super::probe::measure(&second)
    );
    let checkpoint_trace = |observed: &super::probe::Observations| {
        observed
            .run
            .sources
            .iter()
            .map(|source| {
                source
                    .checkpoints
                    .iter()
                    .map(|checkpoint| {
                        (
                            checkpoint.epoch,
                            checkpoint.block.height(),
                            checkpoint.commitment,
                            checkpoint
                                .finalization
                                .as_ref()
                                .map(|finalization| finalization.round()),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };
    let response_trace = |observed: &super::probe::Observations| {
        observed
            .run
            .captures
            .iter()
            .map(|capture| {
                (
                    capture.source,
                    capture.request.clone(),
                    capture.bytes.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(checkpoint_trace(&first), checkpoint_trace(&second));
    assert_eq!(response_trace(&first), response_trace(&second));

    let named = &super::reshare_restarts::tests::BEFORE_THE_NEW_SHARE;
    let first = super::reshare_restarts::tests::forced(named);
    let second = super::reshare_restarts::tests::forced(named);
    assert_eq!(first.report, second.report);
    assert_eq!(first.trace, second.trace);
    assert_eq!(first.retained, second.retained);
    assert_eq!(first.recoveries, second.recoveries);

    let input = recovered_state_sync_input(15, 2);
    let first = super::state_sync::run_dkg_state_sync_recovered(input.clone());
    let second = super::state_sync::run_dkg_state_sync_recovered(input);
    assert_eq!(first, second);
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
        checkpoints: [super::probe_input::FINALIZED; 3],
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
    let artifact_input = probe_input([4, 5, 3], probe_program(&[0, 1, 0, 0], &[]), 920);
    let artifact = super::run_dkg_probe(artifact_input.clone());
    assert_eq!(artifact.judged.count(Invariant::I12), Some(1));
    assert_eq!(artifact.judged.count(Invariant::I13), Some(1));
    assert_eq!(super::run_dkg_probe(artifact_input), artifact);

    let refused = super::run_dkg_probe(probe_input(
        [3; 3],
        vec![Junk {
            origin: 3,
            payload: vec![255],
        }],
        921,
    ));
    assert_eq!(refused.judged.count(Invariant::I14), Some(1));
    assert_covered(Target::Probe, &[artifact.judged, refused.judged]);
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
    fn search() -> ([u8; 2], super::StateSyncReport, Vec<Judged>) {
        let mut earlier = Vec::new();
        for value in 0..512u16 {
            let bytes = value.to_be_bytes();
            let report = super::run_dkg_state_sync(super::fixtures::decode(&bytes));
            if report
                .judged
                .count(Invariant::I6)
                .is_some_and(|count| count > 0)
            {
                return (bytes, report, earlier);
            }
            assert_eq!(
                report.judged.reason(Invariant::I6),
                Some("no failed ceremony was reported"),
                "earlier input {bytes:?} did not give the required zero reason"
            );
            earlier.push(report.judged);
        }
        panic!("none of the first 512 two-byte inputs measured I6")
    }

    let (first_bytes, first, earlier) = search();
    let (second_bytes, second, second_earlier) = search();
    assert_eq!(first_bytes, second_bytes);
    assert_eq!(first, second);
    assert_eq!(earlier, second_earlier);
    assert_eq!(first.judged.count(Invariant::I6), Some(1));

    let mut reports = earlier;
    reports.push(first.judged);
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
        checkpoints: [super::probe_input::FINALIZED; 3],
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
    // An impossible request step makes the oracle stop inferring probe state
    // after the first valid reply. The second valid reply is therefore open,
    // while junk remains unconditionally blockable.
    let mut records = probe_records(2, 0);
    records.steps.insert(
        4,
        ProbeStep::Requested {
            recipients: commonware_p2p::Recipients::All,
            bytes: vec![255],
        },
    );
    let peer = records.outsider.clone();
    records.steps.extend([
        ProbeStep::Sent(ProbeSend {
            origin: peer.clone(),
            shape: ProbeShape::Junk,
            bytes: vec![255],
        }),
        ProbeStep::Delivered {
            peer: peer.clone(),
            bytes: vec![255],
        },
        ProbeStep::Blocked { peer: peer.clone() },
    ]);
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
    assert_eq!(
        invariants::probe_judgments(&records)
            .0
            .into_iter()
            .map(|judgment| judgment.verdict)
            .collect::<Vec<_>>(),
        [ProbeVerdict::Pass, ProbeVerdict::Open, ProbeVerdict::Block]
    );
}

#[test]
fn at_052_checkpoint_record_matches_the_epoch_two_artifact() {
    let observed = super::probe::observe_planted(
        probe_input([4, 5, 3], probe_program(&[0, 1, 0, 0], &[]), 952),
        async |_, _| {},
    );
    let report = super::probe::measure(&observed);
    assert_eq!(report.judged.count(Invariant::I12), Some(1));
    assert_eq!(report.judged.count(Invariant::I13), Some(1));

    let record = observed.run.sources[0]
        .checkpoints
        .iter()
        .find(|record| record.epoch == Epoch::new(2))
        .expect("source zero holds the selected epoch's checkpoint");
    let artifact = probe_artifact(&observed);
    assert_checkpoint_artifact(record, artifact);

    let mut wrong = record.clone();
    wrong.epoch = Epoch::new(1);
    rejects(|| assert_checkpoint_artifact(&wrong, artifact));

    let mut wrong = record.clone();
    wrong.block = super::app::Block::new(
        record.block.context(),
        record.block.parent(),
        record.block.height().next(),
        record.block.payload(),
    );
    rejects(|| assert_checkpoint_artifact(&wrong, artifact));

    let mut wrong = record.clone();
    wrong.block = super::app::Block::new(
        record.block.context(),
        record.block.parent(),
        record.block.height(),
        None,
    );
    rejects(|| assert_checkpoint_artifact(&wrong, artifact));

    let mut wrong = record.clone();
    wrong.commitment = sha256::Digest::from([52; 32]);
    rejects(|| assert_checkpoint_artifact(&wrong, artifact));

    let mut wrong = record.clone();
    wrong.finalization = None;
    rejects(|| assert_checkpoint_artifact(&wrong, artifact));

    let mut wrong = record.clone();
    let finalization = wrong
        .finalization
        .as_mut()
        .expect("the checkpoint has a finalization to mutate");
    finalization.proposal.round = Round::new(Epoch::zero(), View::new(52));
    let mut matching_artifact = artifact.clone();
    matching_artifact.finalization = wrong.finalization.clone();
    rejects(|| assert_checkpoint_artifact(&wrong, &matching_artifact));

    let mut wrong = record.clone();
    let finalization = wrong
        .finalization
        .as_mut()
        .expect("the checkpoint has a finalization to mutate");
    finalization.proposal.payload = sha256::Digest::from([52; 32]);
    let mut matching_artifact = artifact.clone();
    matching_artifact.finalization = wrong.finalization.clone();
    rejects(|| assert_checkpoint_artifact(&wrong, &matching_artifact));

    let mut wrong = artifact.clone();
    wrong.floor = observed.run.sources[0].finalizations[0].clone();
    rejects(|| assert_checkpoint_artifact(record, &wrong));

    let mut wrong = artifact.clone();
    wrong.info = observed.run.chain.genesis.clone();
    rejects(|| assert_checkpoint_artifact(record, &wrong));

    let mut wrong = artifact.clone();
    wrong.finalization = None;
    rejects(|| assert_checkpoint_artifact(record, &wrong));
}

#[test]
fn at_053_only_checkpoint_source_supplies_the_boundary() {
    let seed = |source: usize, chain: &super::probe::Chain, _: &super::probe::Chain| {
        (source == 0)
            .then(|| chain.checkpoint(2, true))
            .into_iter()
            .collect()
    };
    let observed = super::probe::observe_with_seed(
        probe_input([1, 5, 5], probe_program(&[1, 2, 0, 0], &[]), 953),
        &seed,
        async |_, _| {},
    );
    let artifact = probe_artifact(&observed);
    assert_eq!(artifact.floor.epoch(), Epoch::new(2));
    assert_eq!(observed.run.sources[0].finalizations.len(), 1);
    assert!(observed.run.sources[1].checkpoints.is_empty());
    assert!(observed.run.sources[2].checkpoints.is_empty());

    let provenance: Vec<_> = observed
        .run
        .steps
        .iter()
        .filter_map(|step| match step {
            ProbeStep::Sent(ProbeSend {
                shape: ProbeShape::Response(position),
                ..
            }) => Some(&observed.run.captures[*position]),
            _ => None,
        })
        .filter(|capture| matches!(capture.request.first(), Some(0 | 2)))
        .collect();
    assert_eq!(provenance.len(), 2);
    assert!(provenance.iter().all(|capture| capture.source == 0));
    assert_eq!(
        artifact.finalization.as_ref(),
        observed.run.sources[0].checkpoints[0].finalization.as_ref()
    );
    assert_report(super::probe::measure(&observed).judged, true);
}

#[test]
fn at_054_missing_or_unfinalized_checkpoint_serves_nothing() {
    for finalized in [None, Some(false)] {
        let seed = move |source: usize, chain: &super::probe::Chain, _: &super::probe::Chain| {
            if source == 0 {
                finalized
                    .map(|finalized| chain.checkpoint(2, finalized))
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            }
        };
        let boundary = probe_request(0, 2);
        let block = probe_request(2, 2);
        let observed = super::probe::observe_with_seed(
            probe_input([5; 3], probe_program(&[0, 1], &[]), 954),
            &seed,
            async |harness, stage| {
                if stage == super::probe::Stage::Closing {
                    harness.ask(0, boundary.clone());
                    harness.execute(&Advance { steps: 1 }).await;
                    harness.ask(0, block.clone());
                    harness.execute(&Advance { steps: 1 }).await;
                }
            },
        );
        assert!(observed.run.steps.iter().any(|step| {
            matches!(
                step,
                ProbeStep::Requested {
                    recipients: commonware_p2p::Recipients::All,
                    bytes,
                } if bytes == &boundary
            )
        }));
        assert!(
            observed
                .run
                .captures
                .iter()
                .all(|capture| capture.request != boundary && capture.request != block),
            "source answered with checkpoint finalized={finalized:?}"
        );
        let source = &observed.run.sources[0].identity;
        assert!(!observed.run.blocked.iter().any(|(blocker, blocked)| {
            blocker == source
                && (blocked == &observed.run.outsider || blocked == &observed.run.discoverer)
        }));
        assert_report(super::probe::measure(&observed).judged, true);
    }
}

#[test]
fn at_055_checkpoint_controls_are_independent_and_bounded() {
    let sessions: Vec<super::DkgProbeFuzzInput> = (0..4096u16)
        .map(|seed| super::fixtures::decode(&seed.to_le_bytes()))
        .collect();
    for session in &sessions {
        assert!(
            session
                .sources
                .iter()
                .all(|height| *height <= crate::stateful::MAX_SOURCE_HEIGHT)
        );
        assert!(super::probe_input::drawable(&session.events));
        for (held, height) in session.checkpoints.iter().zip(session.sources) {
            assert_ne!(held[0], super::SourceCheckpoint::Finalized);
            for (epoch, checkpoint) in held.iter().enumerate() {
                if super::probe_input::introducing(epoch) > u64::from(height) {
                    assert_eq!(*checkpoint, super::SourceCheckpoint::Missing);
                }
            }
        }
    }
    for source in 0..3 {
        for epoch in 1..super::probe_input::CHECKPOINT_EPOCHS {
            for choice in [
                super::SourceCheckpoint::Missing,
                super::SourceCheckpoint::Unfinalized,
                super::SourceCheckpoint::Finalized,
            ] {
                assert!(sessions.iter().any(|session| {
                    super::probe_input::introducing(epoch) <= u64::from(session.sources[source])
                        && session.checkpoints[source][epoch] == choice
                }));
            }
        }
    }
}

#[test]
fn at_056_seeding_is_partitioned_by_source_and_leaves_discoverer_empty() {
    let mut input = probe_input([5, 3, 1], vec![], 956);
    input.checkpoints = [[super::SourceCheckpoint::Missing; 4]; 3];
    input.checkpoints[0][0] = super::SourceCheckpoint::Unfinalized;
    input.checkpoints[0][2] = super::SourceCheckpoint::Finalized;
    input.checkpoints[1][1] = super::SourceCheckpoint::Unfinalized;
    let (observed, seeded) = super::probe::observe_seeding(input, None, async |harness, stage| {
        if stage == super::probe::Stage::Closing {
            // Attach the already initialized discovering plan, then ask it
            // for a seeded source epoch. An empty plan serves no response.
            harness.execute(&Attach { node: 0 }).await;
            harness.craft(3, probe_request(0, 2));
            harness.execute(&Advance { steps: 1 }).await;
        }
    });
    assert_report(super::probe::measure(&observed).judged, true);
    assert!(
        observed
            .run
            .steps
            .iter()
            .all(|step| !matches!(step, ProbeStep::Requested { .. })),
        "the initialized discovering plan serves no source checkpoint"
    );
    assert_eq!(seeded.len(), 4);

    // The trace deliberately proves only the two named DKG partitions read
    // by Plan: state_sync and checkpoint. It is not a whole-storage audit.
    for (member, seen) in seeded.iter().enumerate() {
        assert_eq!(seen.member, member);
        assert_eq!(seen.before, super::fixtures::Plan::default());
        assert_eq!(seen.opened.material, None);
        if member == 0 || member == 3 {
            assert!(seen.touched.is_empty());
            assert_eq!(seen.opened, super::fixtures::Plan::default());
            continue;
        }

        let checkpoint = format!("member-{member}_dkg_checkpoint");
        assert_eq!(seen.touched, [checkpoint.clone(), checkpoint]);
        assert!(
            seen.touched
                .iter()
                .all(|partition| !partition.ends_with("_dkg_state_sync"))
        );
    }
    assert_eq!(
        seeded[1].opened.checkpoints,
        [(Epoch::zero(), false), (Epoch::new(2), true)]
    );
    assert_eq!(seeded[2].opened.checkpoints, [(Epoch::new(1), false)]);
    assert!(seeded[3].opened.checkpoints.is_empty());
}

fn two_round_probe() -> super::probe::Observations {
    let rest = [
        PROBE_RETRY,
        Release { source: 0 },
        Release { source: 2 },
        Release { source: 3 },
        Release { source: 0 },
    ];
    super::probe::observe_planted(
        probe_input([4, 4, 5], probe_program(&[0, 1], &rest), 957),
        async |_, _| {},
    )
}

#[test]
fn at_057_at_058_later_same_epoch_selection_updates_the_floor() {
    let observed = two_round_probe();
    let report = super::probe::measure(&observed);
    let (selections, artifact) = invariants::probe_selections(&observed.run);
    assert_eq!(selections.len(), 2);
    assert_eq!(selections[0].floor.epoch(), Epoch::new(2));
    assert!(selections[1].floor.round() > selections[0].floor.round());
    assert_eq!(artifact.unwrap().floor, selections[1].floor);
    assert_eq!(report.judged.count(Invariant::I12), Some(1));
    assert_eq!(report.judged.count(Invariant::I13), Some(1));

    let mut planted = observed;
    let lower = selections[0].floor.clone();
    for step in &mut planted.run.steps {
        if let ProbeStep::Resolved(artifact) = step {
            artifact.floor = lower.clone();
        }
    }
    assert_eq!(invariants::check_probe_artifact(&planted.run), 1);
    fails("I12", || {
        super::probe::measure(&planted);
    });
}

#[test]
fn at_059_primary_rotation_keeps_a_completing_fallback() {
    let rest = [
        PROBE_RETRY,
        Release { source: 1 },
        Release { source: 2 },
        Release { source: 6 },
        Release { source: 0 },
    ];
    let observed = super::probe::observe_planted(
        probe_input([3, 3, 5], probe_program(&[0, 1], &rest), 959),
        async |_, _| {},
    );
    let report = super::probe::measure(&observed);
    let (selections, artifact) = invariants::probe_selections(&observed.run);
    assert_eq!(selections.len(), 2, "{report}");
    assert_eq!(selections[0].floor.epoch(), Epoch::new(1));
    assert_eq!(selections[1].floor.epoch(), Epoch::new(2));
    assert_eq!(artifact.unwrap().floor, selections[0].floor);
    assert_eq!(report.judged.count(Invariant::I12), Some(1));
    assert_eq!(report.judged.count(Invariant::I13), Some(1));

    let lower = super::probe::observe_planted(
        probe_input(
            [4, 4, 5],
            probe_program(
                &[2, 0],
                &[
                    PROBE_RETRY,
                    Release { source: 0 },
                    Release { source: 1 },
                    Release { source: 3 },
                    Release { source: 0 },
                ],
            ),
            9591,
        ),
        async |_, _| {},
    );
    let lower_report = super::probe::measure(&lower);
    let (lower_selections, lower_artifact) = invariants::probe_selections(&lower.run);
    assert_eq!(lower_selections.len(), 2, "{lower_report}");
    assert_eq!(lower_selections[0].floor.epoch(), Epoch::new(2));
    assert_eq!(lower_selections[1].floor.epoch(), Epoch::new(2));
    assert!(lower_selections[0].floor.round() > lower_selections[1].floor.round());
    assert_eq!(lower_artifact.unwrap().floor, lower_selections[0].floor);
    assert_eq!(lower_report.judged.count(Invariant::I12), Some(1));

    // The ordinary source model has one fixed latest response per source. A
    // real lower first selection therefore enters through the public probe
    // boundary, using a valid older certificate from the same fixed chain.
    let donor = super::probe::observe_planted(
        probe_input([3, 3, 5], probe_program(&[], &[]), 9592),
        async |_, _| {},
    );
    let lower = donor
        .run
        .chain
        .finalizations
        .iter()
        .filter(|finalization| finalization.epoch() == Epoch::new(1))
        .min_by_key(|finalization| finalization.round())
        .expect("the fixed chain has an older epoch-one finalization")
        .clone();
    let latest_tag = donor.run.captures[0].bytes[0];
    let mut lower_bytes = vec![latest_tag];
    lower.write(&mut lower_bytes);
    let mut fallback_selection = super::probe::observe_planted(
        probe_input(
            [3, 3, 5],
            vec![
                PROBE_RETRY,
                Release { source: 1 },
                Release { source: 2 },
                PROBE_RETRY,
                Release { source: 0 },
                Release { source: 1 },
                // Keep the primary's boundary responses held. Source zero's
                // fourth-newest distinct response is the fallback boundary;
                // its next response is that block.
                Release { source: 9 },
                Release { source: 0 },
            ],
            9592,
        ),
        async move |harness, stage| {
            if stage == super::probe::Stage::Started {
                for event in [
                    Attach { node: 1 },
                    Attach { node: 2 },
                    Attach { node: 3 },
                    Subscribe,
                ] {
                    harness.execute(&event).await;
                }
                for origin in [0, 1] {
                    harness.craft(origin, lower_bytes.clone());
                    harness.execute(&Advance { steps: 1 }).await;
                }
            }
        },
    );
    // `craft` is the public-boundary injection surface. Once the run has
    // delivered these two complete, valid latest replies, describe them to
    // the ordinary oracle as the dealer responses they represent so I12 and
    // I14 judge the same target events.
    let latest_request = fallback_selection
        .run
        .steps
        .iter()
        .find_map(|step| match step {
            ProbeStep::Requested { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .expect("subscribing requested latest finalizations");
    let dealers: Vec<_> = fallback_selection
        .run
        .sources
        .iter()
        .take(2)
        .map(|source| source.identity.clone())
        .collect();
    let mut modeled = 0;
    for step in &mut fallback_selection.run.steps {
        let ProbeStep::Sent(send) = step else {
            continue;
        };
        if send.shape != ProbeShape::Crafted {
            continue;
        }
        let source = dealers
            .iter()
            .position(|dealer| *dealer == send.origin)
            .expect("the fixed replies were delivered as the first two dealers");
        let capture = fallback_selection.run.captures.len();
        fallback_selection.run.captures.push(ProbeCapture {
            source,
            request: latest_request.clone(),
            bytes: send.bytes.clone(),
        });
        send.shape = ProbeShape::Response(capture);
        modeled += 1;
    }
    assert_eq!(modeled, 2);

    let capture_positions = |request: Vec<u8>| {
        fallback_selection
            .run
            .captures
            .iter()
            .enumerate()
            .filter_map(|(position, capture)| (capture.request == request).then_some(position))
            .collect::<Vec<_>>()
    };
    let primary_boundaries = capture_positions(probe_request(0, 2));
    let fallback_boundaries = capture_positions(probe_request(0, 1));
    let fallback_blocks = capture_positions(probe_request(2, 1));
    assert!(!primary_boundaries.is_empty());
    assert!(!fallback_boundaries.is_empty());
    assert!(!fallback_blocks.is_empty());

    let sent = fallback_selection
        .run
        .steps
        .iter()
        .enumerate()
        .filter_map(|(at, step)| match step {
            ProbeStep::Sent(ProbeSend {
                shape: ProbeShape::Response(position),
                ..
            }) => Some((at, *position)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        primary_boundaries
            .iter()
            .all(|position| sent.iter().all(|(_, sent)| sent != position)),
        "every primary boundary response remains held"
    );
    assert!(
        fallback_boundaries
            .iter()
            .any(|position| sent.iter().any(|(_, sent)| sent == position)),
        "a fallback boundary response is sent"
    );
    let fallback_block_sent = sent
        .iter()
        .filter_map(|(at, position)| fallback_blocks.contains(position).then_some(*at))
        .next()
        .expect("a fallback block response is sent");
    let resolved = fallback_selection
        .run
        .steps
        .iter()
        .position(|step| matches!(step, ProbeStep::Resolved(_)))
        .expect("the fallback resolves an artifact");
    assert!(
        fallback_block_sent < resolved,
        "the fallback block is sent before the artifact resolves"
    );
    let fallback_report = super::probe::measure(&fallback_selection);
    let (fallback_selections, fallback_artifact) =
        invariants::probe_selections(&fallback_selection.run);
    assert_eq!(
        fallback_selections
            .iter()
            .map(|selection| selection.floor.epoch())
            .collect::<Vec<_>>(),
        [Epoch::new(1), Epoch::new(2), Epoch::new(1)],
        "the lower fallback selection is followed by primary and fallback updates"
    );
    assert!(
        fallback_selections[2].floor.round() > lower.round(),
        "the later fallback selection must exceed the crafted first one"
    );
    assert_eq!(
        fallback_artifact.as_ref().unwrap().floor,
        fallback_selections[2].floor,
        "the completing fallback retains its later selection"
    );
    assert_eq!(fallback_report.judged.count(Invariant::I12), Some(1));
    assert_report(fallback_report.judged, true);

    for step in &mut fallback_selection.run.steps {
        if let ProbeStep::Resolved(artifact) = step {
            artifact.floor = lower.clone();
        }
    }
    fails("I12", || {
        super::probe::measure(&fallback_selection);
    });
}

#[test]
fn at_060_discovery_decodes_unconditional_faults_before_state() {
    for (bytes, expected) in [
        (vec![], ProbeVerdict::Block),
        (vec![6], ProbeVerdict::Block),
        (vec![5], ProbeVerdict::Block),
        (vec![1], ProbeVerdict::Block),
        (vec![3], ProbeVerdict::Block),
        (vec![4, 9], ProbeVerdict::Pass),
    ] {
        let mut observed = crafted_probe(bytes.clone(), false);
        let peer = assert_one_probe_verdict(&observed, expected);
        let report = super::probe::measure(&observed);
        assert_eq!(report.judged.count(Invariant::I14), Some(1));
        flip_network_block(&mut observed.run, &peer, expected == ProbeVerdict::Pass);
        fails("I14", || {
            super::probe::measure(&observed);
        });

        let mut fetching = crafted_fetch_probe(bytes);
        assert_eq!(probe_verdicts(&fetching).last(), Some(&expected));
        assert_report(super::probe::measure(&fetching).judged, true);
        let peer = fetching.run.outsider.clone();
        flip_network_block(&mut fetching.run, &peer, expected == ProbeVerdict::Pass);
        fails("I14", || {
            super::probe::measure(&fetching);
        });
    }
}

#[test]
fn at_061_latest_reply_state_table_and_no_subscriber_control() {
    let run = |mut input: super::DkgProbeFuzzInput| {
        let observed = super::probe::observe_planted(input.clone(), async |_, _| {});
        assert_report(super::probe::measure(&observed).judged, true);
        input.events.clear();
        observed
    };
    let verdicts = |observed: &super::probe::Observations| {
        invariants::probe_judgments(&observed.run)
            .0
            .into_iter()
            .map(|judgment| judgment.verdict)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        verdicts(&run(probe_input([3; 3], probe_program(&[0], &[]), 961))),
        [ProbeVerdict::Pass]
    );
    assert_eq!(
        verdicts(&run(probe_input(
            [3; 3],
            probe_program(&[], &[Replay { source: 0 }]),
            962,
        ))),
        [ProbeVerdict::Block]
    );
    let mut stale = probe_input([1, 3, 3], probe_program(&[0], &[]), 963);
    stale.bootstrap_epoch = 1;
    assert_eq!(verdicts(&run(stale.clone())), [ProbeVerdict::Pass]);
    stale.foreign[0] = true;
    assert_eq!(verdicts(&run(stale)), [ProbeVerdict::Pass]);
    let mut foreign = probe_input([3; 3], probe_program(&[0], &[]), 964);
    foreign.foreign[0] = true;
    assert_eq!(verdicts(&run(foreign)), [ProbeVerdict::Block]);
    assert_eq!(
        verdicts(&run(probe_input(
            [3; 3],
            probe_program(&[0], &[Duplicate { source: 0 }]),
            965,
        ))),
        [ProbeVerdict::Pass, ProbeVerdict::Pass]
    );

    let dropped = [
        Release { source: 0 },
        Unsubscribe,
        Duplicate { source: 0 },
        Release { source: 1 },
        Replay { source: 0 },
    ];
    let mut observed = run(probe_input([3; 3], probe_program(&[], &dropped), 966));
    assert!(
        verdicts(&observed)
            .into_iter()
            .all(|verdict| verdict == ProbeVerdict::Pass)
    );
    let peer = observed.run.outsider.clone();
    flip_network_block(&mut observed.run, &peer, true);
    fails("I14", || {
        super::probe::measure(&observed);
    });
}

#[test]
fn at_062_boundary_responses_follow_the_active_fetches() {
    let dealer = super::probe::observe_planted(
        probe_input([3; 3], probe_program(&[0, 1, 0], &[]), 9620),
        async |_, _| {},
    );
    assert_eq!(probe_verdicts(&dealer).last(), Some(&ProbeVerdict::Pass));
    assert_report(super::probe::measure(&dealer).judged, true);

    let nondealer = super::probe::observe_planted(
        probe_input(
            [3; 3],
            probe_program(&[0, 1], &[Replay { source: 0 }]),
            9621,
        ),
        async |_, _| {},
    );
    assert_eq!(probe_verdicts(&nondealer).last(), Some(&ProbeVerdict::Pass));
    assert_report(super::probe::measure(&nondealer).judged, true);

    let mut invalid_input = probe_input([3; 3], probe_program(&[0, 1, 2], &[]), 9622);
    invalid_input.foreign[2] = true;
    let invalid = super::probe::observe_planted(invalid_input, async |_, _| {});
    assert_eq!(probe_verdicts(&invalid).last(), Some(&ProbeVerdict::Block));
    assert_report(super::probe::measure(&invalid).judged, true);

    let mut invalid_nondealer_input = probe_input(
        [3; 3],
        probe_program(&[0, 1], &[Replay { source: 2 }]),
        9626,
    );
    invalid_nondealer_input.foreign[2] = true;
    let invalid_nondealer = super::probe::observe_planted(invalid_nondealer_input, async |_, _| {});
    assert_eq!(
        probe_verdicts(&invalid_nondealer).last(),
        Some(&ProbeVerdict::Block)
    );
    assert!(invalid_nondealer.run.blocked.contains(&(
        invalid_nondealer.run.discoverer.clone(),
        invalid_nondealer.run.outsider.clone()
    )));
    assert_report(super::probe::measure(&invalid_nondealer).judged, true);

    let mut repeated_input = probe_input(
        [3; 3],
        probe_program(
            &[0, 1],
            &[
                Replay { source: 0 },
                Release { source: 1 },
                Replay { source: 2 },
            ],
        ),
        9623,
    );
    repeated_input.foreign[2] = true;
    let repeated = super::probe::observe_planted(repeated_input, async |_, _| {});
    assert_eq!(
        probe_verdicts(&repeated).last(),
        Some(&ProbeVerdict::Pass),
        "an accepted responder is ignored before verification"
    );
    assert_report(super::probe::measure(&repeated).judged, true);

    let older_request = probe_request(0, 1);
    let older = super::probe::observe_planted(
        probe_input([4, 4, 5], probe_program(&[0, 1], &[]), 9624),
        async move |harness, stage| {
            if stage == super::probe::Stage::Closing {
                harness.ask(0, older_request.clone());
                harness.execute(&Advance { steps: 1 }).await;
                harness.execute(&Release { source: 0 }).await;
            }
        },
    );
    assert_eq!(probe_verdicts(&older).last(), Some(&ProbeVerdict::Pass));
    assert_report(super::probe::measure(&older).judged, true);

    let later_request = probe_request(0, 2);
    let later = super::probe::observe_planted(
        probe_input([3, 3, 5], probe_program(&[0, 1], &[]), 9625),
        async move |harness, stage| {
            if stage == super::probe::Stage::Closing {
                harness.ask(0, later_request.clone());
                harness.execute(&Advance { steps: 1 }).await;
                harness.execute(&Release { source: 0 }).await;
            }
        },
    );
    assert_eq!(probe_verdicts(&later).last(), Some(&ProbeVerdict::Block));
    assert_report(super::probe::measure(&later).judged, true);

    let fallback = super::probe::observe_planted(
        probe_input(
            [3, 3, 5],
            probe_program(
                &[0, 1],
                &[
                    PROBE_RETRY,
                    Release { source: 1 },
                    Release { source: 2 },
                    Release { source: 6 },
                    Release { source: 0 },
                ],
            ),
            9627,
        ),
        async |_, _| {},
    );
    let fallback_boundary = probe_request(0, 1);
    let fallback_judgments = invariants::probe_judgments(&fallback.run).0;
    assert!(fallback_judgments.iter().any(|judgment| {
        judgment.verdict == ProbeVerdict::Pass
            && matches!(
                judgment.send.shape,
                ProbeShape::Response(position)
                    if fallback.run.captures[position].request == fallback_boundary
            )
    }));
    let selections = invariants::probe_selections(&fallback.run).0;
    assert_eq!(selections.len(), 2);
    assert_eq!(selections[0].floor.epoch(), Epoch::new(1));
    assert_eq!(selections[1].floor.epoch(), Epoch::new(2));
    assert_report(super::probe::measure(&fallback).judged, true);

    let valid_fallback_nondealer = super::probe::observe_planted(
        probe_input(
            [3, 3, 5],
            probe_program(
                &[0, 1],
                &[
                    PROBE_RETRY,
                    Release { source: 1 },
                    Release { source: 2 },
                    Replay { source: 6 },
                ],
            ),
            9628,
        ),
        async |_, _| {},
    );
    let valid_judgment = invariants::probe_judgments(&valid_fallback_nondealer.run)
        .0
        .pop()
        .expect("the non-dealer delivered a fallback boundary");
    assert_eq!(
        valid_judgment.send.origin,
        valid_fallback_nondealer.run.outsider
    );
    assert_eq!(valid_judgment.verdict, ProbeVerdict::Pass);
    let ProbeShape::Response(position) = valid_judgment.send.shape else {
        panic!("the fallback boundary is a captured response")
    };
    assert_eq!(
        valid_fallback_nondealer.run.captures[position].request,
        fallback_boundary
    );
    assert_report(
        super::probe::measure(&valid_fallback_nondealer).judged,
        true,
    );

    let invalid_seed =
        |source: usize, chain: &super::probe::Chain, foreign: &super::probe::Chain| match source {
            0 => vec![foreign.checkpoint(1, true)],
            1 => vec![chain.checkpoint(1, true)],
            2 => vec![chain.checkpoint(2, true)],
            _ => unreachable!(),
        };
    let invalid_fallback_nondealer = super::probe::observe_with_seed(
        probe_input(
            [3, 3, 5],
            probe_program(
                &[0, 1],
                &[
                    PROBE_RETRY,
                    Release { source: 1 },
                    Release { source: 2 },
                    Replay { source: 6 },
                ],
            ),
            9629,
        ),
        &invalid_seed,
        async |_, _| {},
    );
    let invalid_judgment = invariants::probe_judgments(&invalid_fallback_nondealer.run)
        .0
        .pop()
        .expect("the non-dealer delivered an invalid fallback boundary");
    assert_eq!(
        invalid_judgment.send.origin,
        invalid_fallback_nondealer.run.outsider
    );
    assert_eq!(invalid_judgment.verdict, ProbeVerdict::Block);
    let ProbeShape::Response(position) = invalid_judgment.send.shape else {
        panic!("the fallback boundary is a captured response")
    };
    assert_eq!(
        invalid_fallback_nondealer.run.captures[position].request,
        fallback_boundary
    );
    assert_report(
        super::probe::measure(&invalid_fallback_nondealer).judged,
        true,
    );
}

#[test]
fn at_063_block_responses_are_decoded_only_for_eligible_peers() {
    let input = probe_input([3; 3], probe_program(&[0, 1, 0], &[]), 9630);
    let fixture = super::probe::observe_planted(input.clone(), async |_, _| {});
    let checkpoint = fixture.run.sources[0]
        .checkpoints
        .iter()
        .find(|checkpoint| checkpoint.epoch == Epoch::new(1))
        .expect("the requested boundary checkpoint is present");
    let valid_block = checkpoint.block.clone();
    let valid = block_response(Epoch::new(1), &valid_block);
    let wrong_commitment = block_response(
        Epoch::new(1),
        &super::app::Block::new(
            valid_block.context(),
            sha256::Digest::from([63; 32]),
            valid_block.height(),
            valid_block.payload(),
        ),
    );
    let wrong_height = block_response(
        Epoch::new(1),
        &super::app::Block::new(
            valid_block.context(),
            valid_block.parent(),
            valid_block.height().next(),
            valid_block.payload(),
        ),
    );
    let wrong_info = block_response(
        Epoch::new(1),
        &super::app::Block::new(
            valid_block.context(),
            valid_block.parent(),
            valid_block.height(),
            None,
        ),
    );
    let cut = valid[..9].to_vec();

    for (bytes, expected) in [
        (valid.clone(), ProbeVerdict::Pass),
        (cut, ProbeVerdict::Block),
        (wrong_commitment, ProbeVerdict::Block),
        (wrong_height, ProbeVerdict::Block),
        (wrong_info, ProbeVerdict::Block),
    ] {
        let observed = super::probe::observe_planted(input.clone(), async move |harness, stage| {
            if stage == super::probe::Stage::Closing {
                harness.craft(0, bytes.clone());
                harness.execute(&Advance { steps: 1 }).await;
            }
        });
        assert_eq!(probe_verdicts(&observed).last(), Some(&expected));
        assert_report(super::probe::measure(&observed).judged, true);
    }

    let earlier_input = probe_input(
        [3; 3],
        probe_program(&[0, 1, 0], std::slice::from_ref(&PROBE_RETRY)),
        9630,
    );
    let earlier_bytes = valid.clone();
    let earlier = super::probe::observe_planted(earlier_input, async move |harness, stage| {
        if stage == super::probe::Stage::Closing {
            harness.craft(0, earlier_bytes.clone());
            harness.execute(&Advance { steps: 1 }).await;
        }
    });
    assert_eq!(probe_verdicts(&earlier).last(), Some(&ProbeVerdict::Pass));
    assert_report(super::probe::measure(&earlier).judged, true);

    let blocked_valid = valid.clone();
    let blocked_cut = valid[..9].to_vec();
    let blocked = super::probe::observe_planted(input.clone(), async move |harness, stage| {
        if stage == super::probe::Stage::Closing {
            harness.craft(0, blocked_cut.clone());
            harness.execute(&Advance { steps: 1 }).await;
            harness.craft(0, blocked_valid.clone());
            harness.execute(&Advance { steps: 1 }).await;
        }
    });
    assert!(probe_verdicts(&blocked).ends_with(&[ProbeVerdict::Block, ProbeVerdict::Pass]));
    assert_report(super::probe::measure(&blocked).judged, true);

    for (origin, bytes) in [(2, valid[..9].to_vec()), (0, probe_request(3, 2))] {
        let observed = super::probe::observe_planted(input.clone(), async move |harness, stage| {
            if stage == super::probe::Stage::Closing {
                harness.craft(origin, bytes.clone());
                harness.execute(&Advance { steps: 1 }).await;
            }
        });
        assert_eq!(probe_verdicts(&observed).last(), Some(&ProbeVerdict::Pass));
        assert_report(super::probe::measure(&observed).judged, true);
    }

    let outsider_input = probe_input(
        [3; 3],
        probe_program(&[0, 1], &[Replay { source: 0 }]),
        9630,
    );
    let outsider_bytes = valid;
    let outsider = super::probe::observe_planted(outsider_input, async move |harness, stage| {
        if stage == super::probe::Stage::Closing {
            harness.craft(3, outsider_bytes.clone());
            harness.execute(&Advance { steps: 1 }).await;
        }
    });
    assert_eq!(probe_verdicts(&outsider).last(), Some(&ProbeVerdict::Pass));
    assert_report(super::probe::measure(&outsider).judged, true);
}

#[test]
fn at_064_serving_state_uses_the_request_table() {
    for (bytes, expected) in [
        (vec![], ProbeVerdict::Block),
        (vec![6], ProbeVerdict::Block),
        (vec![0], ProbeVerdict::Block),
        (vec![2], ProbeVerdict::Block),
        (probe_request(0, 1), ProbeVerdict::Pass),
        (probe_request(2, 1), ProbeVerdict::Pass),
        (vec![4, 9], ProbeVerdict::Pass),
        (vec![1, 9], ProbeVerdict::Pass),
        (vec![3, 9], ProbeVerdict::Pass),
        (vec![5, 9], ProbeVerdict::Pass),
    ] {
        let mut observed = crafted_probe(bytes, true);
        let peer = assert_one_probe_verdict(&observed, expected);
        assert!(observed.run.captures.is_empty());
        assert_report(super::probe::measure(&observed).judged, true);
        flip_network_block(&mut observed.run, &peer, expected == ProbeVerdict::Pass);
        fails("I14", || {
            super::probe::measure(&observed);
        });
    }
}

#[test]
fn at_065_checkpoint_partitions_are_dkg_paced_state() {
    use super::pacing::{Change, Operation, Partition};

    assert_eq!(
        Partition::named("engine-0_dkg_checkpoint"),
        Partition::Checkpoint
    );
    assert_ne!(
        Partition::named("engine-0_dkg_checkpoint_changed"),
        Partition::Checkpoint
    );
    for change in [
        Change::Write { synced: false },
        Change::Write { synced: true },
        Change::Resize,
        Change::Sync,
    ] {
        assert!(Operation::Blob(Partition::Checkpoint, change).dkg());
    }

    let reshare = super::reshare_restarts::tests::forced(
        &super::reshare_restarts::tests::BEFORE_THE_NEW_SHARE,
    );
    let opened = reshare
        .trace
        .opened(super::reshare_restarts::tests::BEFORE_THE_NEW_SHARE.victim);
    assert!(opened.contains(&Partition::Checkpoint));
    assert!(!opened.contains(&Partition::Unknown));

    let (report, trace, recoveries) =
        super::state_sync::run_dkg_state_sync_recovered(recovered_state_sync_input(15, 2));
    assert_report(report.judged, true);
    assert!(!recoveries.is_empty());
    for engine in 0..super::RESHARE_IDENTITIES as usize {
        assert!(!trace.opened(engine).contains(&Partition::Unknown));
    }
    assert!(
        (0..super::RESHARE_IDENTITIES as usize)
            .any(|engine| trace.opened(engine).contains(&Partition::Checkpoint))
    );

    for source in [include_str!("twins.rs"), include_str!("probe.rs")] {
        assert!(!source.contains("Pacing::new"));
        assert!(!source.contains("PacedStorage::new"));
    }
}

#[test]
fn at_066_recovery_sources_are_observed_in_precedence_order() {
    use super::{
        fixtures::{Plan, Recovery, Source},
        reshare_restarts::tests::{
            BEFORE_THE_NEW_SHARE, JOURNALED_DEALING_WITHOUT_PRIVATE_HALF, forced,
        },
    };

    let marshal = forced(&JOURNALED_DEALING_WITHOUT_PRIVATE_HALF);
    assert_report(marshal.report.judged, true);
    let marshal = marshal
        .recoveries
        .iter()
        .find(|recovery| recovery.source() == Some(Source::Marshal))
        .expect("the fixed dealing restart recovers from marshal");
    let marshal_epoch = marshal.entered.expect("marshal recovery enters an epoch");
    assert!(marshal.recorded);
    assert_ne!(marshal.plan.material, Some(marshal_epoch));
    assert!(
        marshal
            .plan
            .checkpoints
            .iter()
            .all(|(epoch, _)| *epoch != marshal_epoch)
    );

    let checkpoint = forced(&BEFORE_THE_NEW_SHARE);
    assert_report(checkpoint.report.judged, true);
    let checkpoint = checkpoint
        .recoveries
        .iter()
        .find(|recovery| recovery.source() == Some(Source::Checkpoint))
        .expect("the fixed share restart recovers from a checkpoint alone");
    let checkpoint_epoch = checkpoint
        .entered
        .expect("checkpoint recovery enters an epoch");
    assert!(!checkpoint.recorded);
    assert_ne!(checkpoint.plan.material, Some(checkpoint_epoch));
    assert!(
        checkpoint
            .plan
            .checkpoints
            .iter()
            .any(|(epoch, _)| *epoch == checkpoint_epoch)
    );

    let mut material = None;
    for (steps, doublings) in [(15, 2), (10, 3), (15, 3), (10, 4), (15, 4)] {
        let (report, _, recoveries) = super::state_sync::run_dkg_state_sync_recovered(
            recovered_state_sync_input(steps, doublings),
        );
        assert_report(report.judged, true);
        if recoveries
            .iter()
            .any(|recovery| recovery.source() == Some(Source::Material))
        {
            material = Some(recoveries);
            break;
        }
    }
    let material = material.expect("a fixed post-sync restart exposes plan material");
    let material = material
        .iter()
        .find(|recovery| recovery.source() == Some(Source::Material))
        .expect("the selected recovery uses material alone");
    let material_epoch = material.entered.expect("material recovery enters an epoch");
    assert!(!material.recorded);
    assert_eq!(material.plan.material, Some(material_epoch));
    assert!(
        material
            .plan
            .checkpoints
            .iter()
            .all(|(epoch, _)| *epoch != material_epoch)
    );

    let ambiguous = Recovery {
        engine: 0,
        plan: Plan {
            material: Some(Epoch::new(2)),
            checkpoints: vec![(Epoch::new(2), true)],
        },
        entered: Some(Epoch::new(2)),
        recorded: false,
    };
    assert_eq!(ambiguous.source(), Some(Source::MaterialOrCheckpoint));
}

#[test]
fn at_067_checkpoint_sync_is_atomic_at_both_crash_stages() {
    use super::{
        pacing::Stage,
        reshare_restarts::tests::{
            AFTER_THE_STARTUP_CHECKPOINT, BEFORE_THE_STARTUP_CHECKPOINT, CHECKPOINT,
            PRESEEDED_EPOCH, assert_dropped, forced_preseeded,
        },
    };

    let before = forced_preseeded(&BEFORE_THE_STARTUP_CHECKPOINT, Some(PRESEEDED_EPOCH));
    let after = forced_preseeded(&AFTER_THE_STARTUP_CHECKPOINT, Some(PRESEEDED_EPOCH));
    assert_report(before.report.judged, true);
    assert_report(after.report.judged, true);
    assert_dropped(&before, &[(CHECKPOINT, Stage::Before)]);
    assert_dropped(&after, &[(CHECKPOINT, Stage::After)]);
    let [before_recovery] = &before.recoveries[..] else {
        panic!(
            "one checkpoint crash has one recovery: {:?}",
            before.recoveries
        );
    };
    let [after_recovery] = &after.recoveries[..] else {
        panic!(
            "one checkpoint crash has one recovery: {:?}",
            after.recoveries
        );
    };
    assert!(before_recovery.entered.is_some());
    assert!(after_recovery.entered.is_some());
    assert_eq!(
        before_recovery.source(),
        Some(super::fixtures::Source::Marshal)
    );
    assert_eq!(
        after_recovery.source(),
        Some(super::fixtures::Source::Checkpoint)
    );
    assert_eq!(before_recovery.entered, Some(Epoch::zero()));
    assert_eq!(after_recovery.entered, Some(Epoch::zero()));
    assert!(before_recovery.recorded);
    assert!(!after_recovery.recorded);
    assert_eq!(
        before_recovery.plan.checkpoints,
        [(PRESEEDED_EPOCH, false)],
        "the earlier durable checkpoint survives the before-stage crash"
    );
    assert_eq!(
        after_recovery.plan.checkpoints,
        [(Epoch::zero(), false), (PRESEEDED_EPOCH, false)],
        "the applied startup checkpoint is complete and the earlier record is retained"
    );
}

#[test]
fn at_068_six_named_crashes_preserve_their_state_assertions() {
    use super::{
        environment::Landing,
        pacing::Stage,
        reshare_restarts::tests::{
            CHECKPOINT, JOURNAL_ENTRY, NAMED_CRASHES, PRIVATE_HALF, PRUNE, SHARE, assert_dropped,
            assert_entered, assert_registered_again, forced,
        },
    };

    for (case, state) in NAMED_CRASHES.iter().enumerate() {
        let run = forced(state);
        assert_report(run.report.judged, true);
        let found = super::reshare_restarts::tests::found(&run);
        let dropped = state
            .writes
            .iter()
            .map(|write| (write.operation, write.stage))
            .collect::<Vec<_>>();
        assert_dropped(&run, &dropped);
        assert!(
            state
                .writes
                .iter()
                .all(|write| write.engine == state.victim)
        );
        assert!(state.writes.iter().all(|write| {
            matches!(
                write.operation,
                PRIVATE_HALF | JOURNAL_ENTRY | SHARE | PRUNE
            ) && (write.after.0 == PRIVATE_HALF || write.after.0 == CHECKPOINT)
        }));

        match case {
            0 => {
                assert_eq!((found.landing, found.dealings), (Landing::Dealing, 0));
                assert!(found.journal > 0);
            }
            1 => {
                assert_eq!(
                    (found.landing, found.dealings, found.journal),
                    (Landing::Dealing, 1, 0)
                );
                assert_eq!(
                    run.trace.dropped(found.engine),
                    [(PRIVATE_HALF, Stage::After), (JOURNAL_ENTRY, Stage::Before)]
                );
            }
            2 => assert_eq!(
                (found.landing, found.share, found.next_share),
                (Landing::Inclusion, true, false)
            ),
            3 => assert_eq!(
                (found.landing, found.share, found.next_share),
                (Landing::Inclusion, true, true)
            ),
            4 => assert_eq!(
                (found.epoch, found.landing, found.oldest),
                (Epoch::new(1), Landing::Boundary, Some(Epoch::zero()))
            ),
            5 => {
                assert_eq!(
                    (found.epoch, found.landing, found.oldest),
                    (Epoch::new(1), Landing::Boundary, Some(Epoch::new(1)))
                );
                assert!(found.share && found.next_share);
            }
            _ => unreachable!(),
        }
        assert_registered_again(&run, found);
        assert_entered(&run, found, found.epoch.next());
    }
}

#[test]
fn at_069_direct_driver_is_an_exact_test_only_handoff() {
    let state = super::reshare_restarts::tests::NAMED_CRASHES[0];
    let input = super::reshare_restarts::tests::named_input(&state);
    let normal = super::run_dkg_reshare_restarts(input.clone());
    let program = Program::new(
        &input.environment,
        input.raw_bytes.clone(),
        super::RESHARE_IDENTITIES as usize,
    );
    let (direct, _, _) =
        super::reshare_restarts::run_dkg_reshare_restarts_under(input.clone(), program);
    assert_eq!(normal, direct);

    let watched = super::reshare_restarts::tests::watched(input.clone());
    let program = Program::new(
        &input.environment,
        input.raw_bytes.clone(),
        super::RESHARE_IDENTITIES as usize,
    );
    let watched_direct = super::reshare_restarts::tests::watched_under(input, program);
    assert_eq!(watched.report, watched_direct.report);
    assert_eq!(watched.trace, watched_direct.trace);
    assert_eq!(watched.retained, watched_direct.retained);
    assert_eq!(watched.recoveries, watched_direct.recoveries);

    let source = include_str!("reshare_restarts.rs");
    let handoff = source
        .split("pub(super) fn run_dkg_reshare_restarts_under")
        .nth(1)
        .expect("the test-only direct handoff exists");
    assert!(
        source[..source
            .find("pub(super) fn run_dkg_reshare_restarts_under")
            .unwrap()]
            .ends_with("#[cfg(test)]\n")
    );
    assert!(handoff.contains("execute_under(input, program, |cluster| cluster)"));
    assert!(
        source.contains("runner::fuzz(input.raw_bytes.clone(), input, run_dkg_reshare_restarts)")
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
    let mut minimum =
        [[super::SourceCheckpoint::Missing; super::probe_input::CHECKPOINT_EPOCHS]; 3];
    minimum[0][0] = super::SourceCheckpoint::Unfinalized;
    let maximum = [
        [
            super::SourceCheckpoint::Unfinalized,
            super::SourceCheckpoint::Missing,
            super::SourceCheckpoint::Finalized,
            super::SourceCheckpoint::Missing,
        ],
        [
            super::SourceCheckpoint::Missing,
            super::SourceCheckpoint::Finalized,
            super::SourceCheckpoint::Unfinalized,
            super::SourceCheckpoint::Finalized,
        ],
        [
            super::SourceCheckpoint::Unfinalized,
            super::SourceCheckpoint::Missing,
            super::SourceCheckpoint::Finalized,
            super::SourceCheckpoint::Unfinalized,
        ],
    ];
    for (sources, checkpoints, seed) in [
        ([0; 3], minimum, 921),
        ([crate::stateful::MAX_SOURCE_HEIGHT; 3], maximum, 922),
    ] {
        let input = super::DkgProbeFuzzInput {
            sources,
            foreign: [false; 3],
            bootstrap_epoch: 0,
            floor: None,
            sharing_mode: Mode::NonZeroCounter,
            events: events.clone(),
            checkpoints,
            raw_bytes: super::fixtures::tape(seed),
        };
        assert_eq!(input.sources, sources);
        assert_eq!(input.checkpoints, checkpoints);
        let report = super::run_dkg_probe(input);
        assert!(
            report.events.iter().all(|count| *count > 0),
            "{:?}",
            report.events
        );
        assert_report(report.judged, true);
    }
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
