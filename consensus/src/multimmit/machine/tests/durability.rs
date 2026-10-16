//! Durable transitions: every change applies identically live and in replay, and a change that
//! breaks its transition check is refused before it mutates anything.

use crate::{
    Viewable as _,
    multimmit::{
        config::{LeaderSchedule, Profile, Role, Tuning},
        machine::{
            capability::{Capabilities, Capability},
            durability::{
                Acceptance, Change, DurableEffect, DurableState, EffectId, OutboxEntry,
                ReplayError, RetentionRoot, SignRequest, Snapshot, SnapshotReason,
                TransitionReason, UpdateRequest, VoteWatermark,
            },
            input::{BlockValidity, Input, StepError},
            job::Generation,
            reducer::machine::Machine,
            testing::{
                CapabilitiesExt as _, Drive as _, Driver, Execution, Executor, MachineExt as _,
                SymbolicPersistence, SymbolicSigner, SymbolicVerifier, Until, cohort,
                executors::SymbolicApplication,
                fixtures::{
                    PARTICIPANTS, TestDriver, certifiers, committee, digest, path, produce,
                    profile, reference, started, tuned, validator, vqc_above,
                },
            },
            view::{declare::Declarations, proposal::HeldVqc},
        },
        mocks::Committee,
        types::{
            Artifact, BlockRef, CertificateId, ChainId, ChainSet, Floor, HistoryRecord,
            LeaderBlock, Resolution, ViewProof, VoteContent,
        },
    },
    types::{Height, Participant, View, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};

type TestMachine = Machine<Sha256, MinPk>;

/// Restores `snapshot` under `profile` and replays `driver`'s journal after it.
fn replayed(
    profile: Profile<Digest>,
    snapshot: Snapshot<MinPk, Digest>,
    driver: &TestDriver,
) -> TestMachine {
    let mut machine = Machine::restore(profile, snapshot).expect("the checkpoint is valid");
    for event in driver.journal() {
        machine.replay(event.clone()).expect("the journal replays");
    }
    machine
}

/// Stages `change` and makes every barrier it leads to durable.
fn stage(driver: &mut TestDriver, change: Change<MinPk, Digest>) {
    let step = driver.machine_mut().stage_test_change(change).unwrap();
    driver.record(step.capabilities());
    driver.drain_persisting(step);
}

/// Returns the transition check a refused change failed.
fn refused(driver: &mut TestDriver, change: Change<MinPk, Digest>) -> TransitionReason {
    let kind = change.kind();
    match driver.machine_mut().stage_test_change(change) {
        Err(StepError::DurableTransition {
            change,
            source: ReplayError::Transition(reason),
        }) if change == kind => reason,
        other => panic!("expected a refused {kind}, got {other:?}"),
    }
}

/// Drives `committee`'s validator 0 through one change of every kind, all durable.
fn exercised(committee: &Committee<MinPk>) -> TestDriver {
    let mut driver = started(committee, validator(0));
    let genesis = committee.genesis().tips();

    // An own header: produced, signed, published, and accepted.
    let reserved = produce(&mut driver);
    let mut executor = (
        SymbolicSigner::new(committee.signers[0].clone()),
        SymbolicPersistence,
    );
    let unhandled = driver.drain(&mut executor, reserved.into_capabilities());
    assert!(unhandled.released().is_empty());
    assert_eq!(executor.0.published.len(), 1);

    // Three updates of one view tag: reserving the third ends the first one's publication.
    let content = committee.content(View::new(1), None, false, committee.genesis_endorsement());
    for seq in 1..=3 {
        let request = UpdateRequest::new(content.clone(), seq, Vec::new());
        let reserved = driver
            .machine_mut()
            .reserve_test_effect(DurableEffect::sign(SignRequest::Update(request)))
            .unwrap();
        driver.record(reserved.capabilities());
        let unhandled = driver.drain(&mut executor, reserved.into_capabilities());
        let retired = unhandled
            .iter()
            .filter_map(|capability| match capability {
                Capability::Retire(retired) => Some(retired.len()),
                _ => None,
            })
            .sum::<usize>();
        assert_eq!(retired, usize::from(seq == 3));
    }
    assert_eq!(
        driver.machine().durable.state.watermark[&View::new(1)].seq,
        3
    );
    assert_eq!(
        driver.inspect().outbox().len(),
        3,
        "the header and two updates stay published"
    );

    // A peer header accepted on chain one, an emission, a certificate forwarded and used to exit
    // its view, and a retention floor.
    let peer = committee.sign_header(committee.header(&genesis[1], digest(b"peer")));
    stage(
        &mut driver,
        Change::Accepted {
            blocks: vec![Acceptance::Full(Arc::new(peer))],
        },
    );
    let record = HistoryRecord::new(committee.genesis().history(), genesis.to_vec()).unwrap();
    stage(
        &mut driver,
        Change::EmissionResolved {
            view: View::new(2),
            record: record.clone(),
            by: Resolution::Determined,
        },
    );
    let certificate = committee.vqc(View::new(1));
    let root = RetentionRoot {
        vqc: certificate.id::<Sha256>(),
        record,
    };
    let vqc = Arc::new(Artifact::Vqc(certificate));
    stage(
        &mut driver,
        Change::CertificateCreated {
            artifact: Arc::clone(&vqc),
        },
    );
    let forwarding = driver.machine().forwarding(Arc::clone(&vqc)).unwrap();
    stage(&mut driver, forwarding);
    let entry = driver.machine().view_entry(vqc.id::<Sha256>(), Vec::new());
    stage(&mut driver, entry);
    let retention = driver.machine().retention_advance(View::new(1), root);
    assert!(
        matches!(
            &retention,
            Change::RetentionAdvanced { retired_publications, .. } if retired_publications.len() == 3
        ),
        "the floor ends the view's update and certificate publications"
    );
    stage(&mut driver, retention);
    assert_eq!(driver.machine().view(), View::new(2));
    assert_eq!(
        driver.inspect().outbox().len(),
        1,
        "the own header stays published"
    );
    driver
}

#[test]
fn replaying_the_journal_reproduces_the_live_state() {
    let committee = committee(20);
    let driver = exercised(&committee);
    let profile = profile(&committee, validator(0));
    let live = driver.machine().live_snapshot_for_test();
    let replayed = replayed(profile.clone(), driver.checkpoint().clone(), &driver);
    assert_eq!(replayed.live_snapshot_for_test(), live);

    // A checkpoint cut at the acknowledged cursor restores to the same state.
    let cut = driver
        .machine()
        .checkpoint_cut()
        .expect("nothing is staged");
    assert_eq!(cut.cursor(), live.cursor());
    let restored = Machine::<Sha256, MinPk>::restore(profile, cut).unwrap();
    assert_eq!(restored.live_snapshot_for_test(), live);
}

#[test]
fn a_checkpoint_is_cut_only_at_an_acknowledged_cursor() {
    let committee = committee(21);
    let mut driver = started(&committee, Role::Observer);
    let step = driver
        .machine_mut()
        .reserve_test_effect(DurableEffect::broadcast(Arc::new(Artifact::Vqc(
            committee.vqc(View::new(1)),
        ))))
        .unwrap();
    driver.record(step.capabilities());
    assert!(
        driver.machine().checkpoint_cut().is_none(),
        "a staged batch is not durable"
    );
    driver.persist(&step.persist_job(), Until::Step);
    assert!(driver.checkpoint_now());
    assert_eq!(
        driver.checkpoint().cursor(),
        driver.machine().live_snapshot_for_test().cursor()
    );
    assert!(driver.journal().is_empty());

    // Recovery from the cut alone re-releases the durable publication.
    let recovered = driver.crash_and_restore().unwrap();
    let acknowledged = driver.persist(&recovered.persist_job(), Until::Step);
    assert_eq!(acknowledged.released_publications().len(), 1);
}

#[test]
fn transitions_refuse_changes_that_break_their_checks() {
    let committee = committee(22);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips();

    // An accepted header must extend its chain's accepted tip and be signed by its producer.
    let parent = committee.header(&genesis[1], digest(b"parent"));
    let orphan = committee.header(&parent.block_ref::<Sha256>(), digest(b"orphan"));
    assert_eq!(
        refused(
            &mut driver,
            Change::Accepted {
                blocks: vec![Acceptance::Full(Arc::new(committee.sign_header(orphan)))],
            },
        ),
        TransitionReason::Acceptance
    );

    // An emission is written once per view, in view order without gaps, each record extending
    // the previous one's commitment.
    let record = HistoryRecord::new(committee.genesis().history(), genesis.to_vec()).unwrap();
    let next = HistoryRecord::new(record.commitment::<Sha256>(), genesis.to_vec()).unwrap();
    stage(
        &mut driver,
        Change::EmissionResolved {
            view: View::new(2),
            record: record.clone(),
            by: Resolution::Determined,
        },
    );
    for (view, record) in [
        (View::new(2), next.clone()),
        (View::new(4), next.clone()),
        (View::new(3), record),
    ] {
        assert_eq!(
            refused(
                &mut driver,
                Change::EmissionResolved {
                    view,
                    record,
                    by: Resolution::Determined,
                },
            ),
            TransitionReason::Emission
        );
    }
    stage(
        &mut driver,
        Change::EmissionResolved {
            view: View::new(3),
            record: next,
            by: Resolution::Determined,
        },
    );

    // A view is exited only with a durable certificate of that view.
    let later = Arc::new(Artifact::Vqc(committee.vqc(View::new(2))));
    stage(
        &mut driver,
        Change::CertificateCreated {
            artifact: Arc::clone(&later),
        },
    );
    assert_eq!(
        refused(
            &mut driver,
            Change::ViewEntered {
                proof: later.id::<Sha256>(),
                ancestors: Vec::new(),
                retired_publications: Vec::new(),
            },
        ),
        TransitionReason::Exit
    );
    assert_eq!(
        refused(&mut driver, Change::CertificateCreated { artifact: later },),
        TransitionReason::DuplicateArtifact
    );

    // The retention floor stays below the current view.
    assert_eq!(
        refused(
            &mut driver,
            Change::RetentionAdvanced {
                floor: View::new(1),
                root: RetentionRoot {
                    vqc: committee.vqc(View::new(1)).id::<Sha256>(),
                    record: HistoryRecord::new(
                        committee.genesis().history(),
                        committee.genesis().tips().to_vec(),
                    )
                    .unwrap(),
                },
                retired_signing: Vec::new(),
                retired_publications: Vec::new(),
            },
        ),
        TransitionReason::RetentionFloor
    );
}

/// Returns a V-QC of `view` above `parent` whose leaderless final votes by `signers` endorse
/// every genesis object.
fn entry_vqc(
    committee: &Committee<MinPk>,
    view: View,
    parent: CertificateId<Digest>,
    signers: impl IntoIterator<Item = u32>,
) -> Arc<Artifact<MinPk, Digest>> {
    let content = committee.content(view, None, true, committee.genesis_endorsement());
    let contents = signers
        .into_iter()
        .map(|signer| (Participant::new(signer), content.clone()))
        .collect();
    Arc::new(Artifact::Vqc(committee.vqc_from(
        parent,
        contents,
        Vec::new(),
    )))
}

/// Returns the certificate identifier of the V-QC `artifact`.
fn certificate(artifact: &Artifact<MinPk, Digest>) -> CertificateId<Digest> {
    let Artifact::Vqc(vqc) = artifact else {
        unreachable!("the artifact is a V-QC")
    };
    vqc.id::<Sha256>()
}

#[test]
fn a_view_entry_retains_exactly_the_unretained_parent_chain_until_retention_passes_it() {
    let committee = committee(24);
    let profile = profile(&committee, Role::Observer);
    let mut driver = started(&committee, Role::Observer);
    let genesis = committee.genesis().vqc();
    let entry = |proof: &Arc<Artifact<MinPk, Digest>>, ancestors| Change::ViewEntered {
        proof: proof.id::<Sha256>(),
        ancestors,
        retired_publications: Vec::new(),
    };

    // View two is entered on `exit`; view three on `proof`, whose parent `other` is another V-QC
    // of view one that nothing retains.
    let exit = entry_vqc(&committee, View::new(1), genesis, 0..5);
    let other = entry_vqc(&committee, View::new(1), genesis, 1..6);
    let proof = entry_vqc(&committee, View::new(2), certificate(&other), 0..5);
    for artifact in [&exit, &proof] {
        stage(
            &mut driver,
            Change::CertificateCreated {
                artifact: Arc::clone(artifact),
            },
        );
    }
    stage(&mut driver, entry(&exit, Vec::new()));

    // The ancestors must be exactly the proof's chain down to a retained V-QC, none retained.
    for ancestors in [
        Vec::new(),
        vec![Arc::clone(&exit)],
        vec![Arc::clone(&other), Arc::clone(&other)],
        vec![Arc::clone(&proof)],
    ] {
        assert_eq!(
            refused(&mut driver, entry(&proof, ancestors)),
            TransitionReason::Ancestors
        );
    }
    let occupancy = driver
        .machine()
        .durable
        .state
        .artifact_occupancy::<Sha256>();
    stage(&mut driver, entry(&proof, vec![Arc::clone(&other)]));
    let state = &driver.machine().durable.state;
    assert_eq!(state.view, View::new(3));
    assert!(state.ancestors.keys().eq([&certificate(&other)]));
    assert_eq!(state.artifact_occupancy::<Sha256>(), occupancy + 1);
    assert!(state.resolver_proofs().iter().any(|proof| proof.view() == View::new(1)
        && matches!(proof, ViewProof::Vqc(vqc) if vqc.id::<Sha256>() == certificate(&other))));

    // The entry replays and restores identically.
    let live = driver.machine().live_snapshot_for_test();
    let replayed = replayed(profile.clone(), driver.checkpoint().clone(), &driver);
    assert_eq!(replayed.live_snapshot_for_test(), live);
    let restored = Machine::<Sha256, MinPk>::restore(profile, live).unwrap();
    assert_eq!(
        restored.durable.state.ancestors,
        driver.machine().durable.state.ancestors
    );

    // Retiring view one on `other` drops it as an ancestor: the root keeps its facts.
    let record = HistoryRecord::new(
        committee.genesis().history(),
        committee.genesis().tips().to_vec(),
    )
    .unwrap();
    stage(
        &mut driver,
        Change::EmissionResolved {
            view: View::new(2),
            record: record.clone(),
            by: Resolution::Determined,
        },
    );
    let root = RetentionRoot {
        vqc: certificate(&other),
        record,
    };

    // The root must be a V-QC of the floor that a retention holder keeps.
    let unretained = RetentionRoot {
        vqc: certificate(&entry_vqc(
            &committee,
            View::new(1),
            genesis,
            [0, 2, 3, 4, 5],
        )),
        ..root.clone()
    };
    let change = driver.machine().retention_advance(View::new(1), unretained);
    assert_eq!(
        refused(&mut driver, change),
        TransitionReason::RetentionFloor
    );
    let retention = driver.machine().retention_advance(View::new(1), root);
    stage(&mut driver, retention);
    let state = &driver.machine().durable.state;
    assert!(state.ancestors.is_empty());
    assert_eq!(state.artifact_occupancy::<Sha256>(), occupancy - 1);
}

/// Returns validator zero's `snapshot` with `mutate` applied to its state.
fn mutated(
    snapshot: &Snapshot<MinPk, Digest>,
    mutate: impl FnOnce(&mut DurableState<MinPk, Digest>),
) -> Snapshot<MinPk, Digest> {
    let mut state = snapshot.clone().into_state();
    mutate(&mut state);
    Snapshot::new(snapshot.epoch(), validator(0), state)
}

#[test]
fn restore_rejects_a_snapshot_whose_fields_disagree() {
    let committee = committee(23);
    let profile = profile(&committee, validator(0));
    let valid = exercised(&committee).machine().live_snapshot_for_test();
    let state = valid.clone().into_state();
    assert!(state.root.is_some(), "the run retired a view");
    assert!(
        !state.outbox.is_empty(),
        "the run left a publication queued"
    );
    assert!(Machine::<Sha256, MinPk>::restore(profile.clone(), valid.clone()).is_ok());

    let genesis = committee.genesis().tips().to_vec();
    let stray = committee.header(&genesis[1], digest(b"stray"));
    let orphan = committee.header(&stray.block_ref::<Sha256>(), digest(b"orphan"));
    let content = committee.content(View::new(2), None, false, committee.genesis_endorsement());
    let peer_update = Arc::new(Artifact::Update(committee.update(
        Participant::new(1),
        &content,
        &genesis,
        1,
    )));
    let current_vqc = Arc::new(Artifact::Vqc(committee.vqc(View::new(2))));
    type Mutation = Box<dyn FnOnce(&mut DurableState<MinPk, Digest>)>;
    let cases: Vec<(&str, SnapshotReason, Mutation)> = vec![
        (
            "a chain without its accepted headers",
            SnapshotReason::Bounds,
            Box::new(|state| {
                state.accepted.pop();
            }),
        ),
        (
            "a peer's update held as a local artifact",
            SnapshotReason::LocalArtifact,
            Box::new(move |state| {
                state.local.insert(peer_update.id::<Sha256>(), peer_update);
            }),
        ),
        (
            "an accepted header off its chain's path",
            SnapshotReason::Accepted,
            Box::new(move |state| {
                state.accepted[1].insert(orphan.height(), Acceptance::Adopted(orphan));
            }),
        ),
        (
            "a leader block slot of a retired view",
            SnapshotReason::SigningSlot,
            Box::new(|state| {
                let parent = state.root.as_ref().expect("a view is retired").vqc;
                state
                    .leader_blocks
                    .insert(state.retired_view, (parent, digest(b"history")));
            }),
        ),
        (
            "a retired view without its root",
            SnapshotReason::Emission,
            Box::new(|state| state.root = None),
        ),
        (
            "a chain's origin on another chain",
            SnapshotReason::Accepted,
            Box::new(|state| state.origin.swap(0, 1)),
        ),
        (
            "last final tips out of chain order",
            SnapshotReason::Bounds,
            Box::new(|state| state.last_final.1.swap(0, 1)),
        ),
        (
            "a root without the emission of the view after it",
            SnapshotReason::Emission,
            Box::new(|state| {
                let after = state.retired_view.next();
                state.emission.remove(&after);
            }),
        ),
        (
            "a publication minted after the cursor",
            SnapshotReason::Effect,
            Box::new(|state| {
                let (_, entry) = state.outbox.pop_first().expect("a publication is queued");
                let unminted = EffectId::new(state.cursor.get() + 1);
                state.outbox.insert(unminted, entry);
            }),
        ),
        (
            "a publication without discharges",
            SnapshotReason::Obligation,
            Box::new(|state| {
                let (id, entry) = state.outbox.pop_first().expect("a publication is queued");
                let undischarged = OutboxEntry::new(entry.publication().clone(), Vec::new());
                state.outbox.insert(id, undischarged);
            }),
        ),
        (
            "an empty set of forwarded certificates",
            SnapshotReason::Forwarded,
            Box::new(|state| {
                state.forwarded_vqcs.insert(state.view, BTreeSet::new());
            }),
        ),
        (
            "an exit of the current view",
            SnapshotReason::Exits,
            Box::new({
                let current_vqc = Arc::clone(&current_vqc);
                move |state| {
                    state.exits.insert(state.view, current_vqc);
                }
            }),
        ),
        (
            "an ancestor of the current view",
            SnapshotReason::Ancestors,
            Box::new(move |state| {
                let Artifact::Vqc(vqc) = current_vqc.as_ref() else {
                    unreachable!("the certificate is a V-QC")
                };
                state.ancestors.insert(vqc.id::<Sha256>(), current_vqc);
            }),
        ),
    ];
    for (case, reason, mutate) in cases {
        let error = Machine::<Sha256, MinPk>::restore(profile.clone(), mutated(&valid, mutate))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(error, ReplayError::Snapshot(reason), "{case}");
    }
}

/// Signs released requests with participant zero's keys, recording every request it signs, and
/// delivers released publications only when `deliver` is set.
struct RecordingSigner {
    signer: SymbolicSigner<MinPk>,
    deliver: bool,
    /// Every request signed, in release order.
    signed: Vec<SignRequest<MinPk, Digest>>,
}

impl RecordingSigner {
    fn new(committee: &Committee<MinPk>, deliver: bool) -> Self {
        Self {
            signer: SymbolicSigner::new(committee.signers[0].clone()),
            deliver,
            signed: Vec::new(),
        }
    }
}

impl Executor<MinPk, Digest> for RecordingSigner {
    fn execute(
        &mut self,
        capability: &Capability<MinPk, Digest>,
        generation: Generation,
    ) -> Option<Execution<MinPk, Digest>> {
        let Capability::Released(job) = capability else {
            return None;
        };
        match job.request() {
            DurableEffect::Sign(effect) => self.signed.extend(effect.requests().iter().cloned()),
            DurableEffect::Publish(_) if !self.deliver => return None,
            DurableEffect::Publish(_) => {}
        }
        self.signer.execute(capability, generation)
    }
}

/// Returns the vote updates among the publications `capabilities` release.
fn released_updates(capabilities: &[Capability<MinPk, Digest>]) -> Vec<Artifact<MinPk, Digest>> {
    capabilities
        .released_publications()
        .into_iter()
        .filter_map(|job| match job.request() {
            DurableEffect::Publish(publication) => Some(publication.artifacts()),
            DurableEffect::Sign(_) => None,
        })
        .flatten()
        .filter(|artifact| matches!(artifact.as_ref(), Artifact::Update(_)))
        .map(|artifact| artifact.as_ref().clone())
        .collect()
}

/// The views the crash-cut run spans.
const CUT_VIEWS: u64 = 4;

/// The view the crash-cut node leads.
const LED_VIEW: View = View::new(3);

/// The view the crash-cut node anchors at after its last view: beyond the anchor lag of its
/// retention window of one view.
const ANCHOR_VIEW: View = View::new(CUT_VIEWS + 4);

/// The peer chain that grows by one header per view in the crash-cut run.
const PEER_CHAIN: ChainId = ChainId::new(1);

/// The most capabilities and polls one crash-cut input may lead to.
const MAX_TURNS: usize = 4_096;

/// One input of a scripted run.
#[derive(Clone)]
enum Action {
    /// Peers deliver artifacts.
    Deliver(Vec<Artifact<MinPk, Digest>>),
    /// The clock advances by this many milliseconds.
    Elapse(u64),
}

/// Returns a committee whose leader schedule makes participant zero lead [`LED_VIEW`] alone among
/// the crash-cut views.
fn cut_committee() -> Committee<MinPk> {
    let order = [1, 2, 3, 0, 4, 5].map(Participant::new).to_vec();
    let schedule = LeaderSchedule::from_order(order, PARTICIPANTS as usize).unwrap();
    let committee = Committee::builder(24, PARTICIPANTS)
        .leaders(schedule)
        .build();
    for view in 1..=CUT_VIEWS {
        let view = View::new(view);
        assert_eq!(
            committee.config.leader(view) == Participant::new(0),
            view == LED_VIEW
        );
    }
    committee
}

/// A validator driven through a script that crashes once, at its `cut`-th journal boundary:
/// before a barrier is appended or between its append and its acknowledgement.
///
/// Every capability is executed as soon as it is issued and every publication is delivered.
struct CrashRun {
    driver: TestDriver,
    signer: RecordingSigner,
    others: (SymbolicApplication, SymbolicVerifier<Digest>),
    boundaries: usize,
    cut: Option<usize>,
    /// The number of requests signed before the crash and the vote watermarks recovery restored.
    crash: Option<(usize, BTreeMap<View, VoteWatermark<Digest>>)>,
}

impl CrashRun {
    /// Starts validator zero of `committee`, to crash at boundary `cut`.
    fn start(committee: &Committee<MinPk>, cut: Option<usize>) -> Self {
        let tuning = Tuning {
            view_retention: ViewDelta::new(1),
            ..Tuning::default()
        };
        let mut run = Self {
            driver: Driver::new(tuned(committee, validator(0), tuning)),
            signer: RecordingSigner::new(committee, true),
            others: (
                SymbolicApplication::new(BlockValidity::Valid),
                SymbolicVerifier::new(true),
            ),
            boundaries: 0,
            cut,
            crash: None,
        };
        let start = run.driver.submit(Input::Start).unwrap();
        run.process(start.into_capabilities());
        run
    }

    /// Counts one journal boundary and crashes there if it is the cut, returning whether it did.
    fn crash_here(&mut self) -> bool {
        let boundary = self.boundaries;
        self.boundaries += 1;
        if self.cut != Some(boundary) {
            return false;
        }
        let signed = self.signer.signed.len();
        let recovered = self.driver.crash_and_restore().expect("recovery replays");
        let watermarks = self.driver.machine().durable.state.watermark.clone();
        self.crash = Some((signed, watermarks));
        assert!(!self.process(recovered.into_capabilities()));
        true
    }

    /// Executes `capabilities` and everything they lead to, returning whether the process crashed
    /// on the way.
    fn process(&mut self, capabilities: Capabilities<MinPk, Digest>) -> bool {
        let mut pending = VecDeque::from(capabilities);
        for _ in 0..MAX_TURNS {
            while let Some(capability) = pending.pop_front() {
                if let Capability::Journal(directive) = capability {
                    if self.crash_here() {
                        return true;
                    }
                    self.driver.append(&directive.job).unwrap();
                    pending.extend(
                        directive
                            .release_after_enqueue
                            .into_iter()
                            .map(Capability::Released),
                    );
                    if self.crash_here() {
                        return true;
                    }
                    let acknowledged = self.driver.acknowledge(&directive.job).unwrap();
                    pending.extend(acknowledged.into_capabilities());
                    continue;
                }
                let mut executed = self.driver.execute(&mut self.signer, &capability).unwrap();
                if executed.is_none() {
                    executed = self.driver.execute(&mut self.others, &capability).unwrap();
                }
                if let Some(Some(step)) = executed {
                    pending.extend(step.into_capabilities());
                }
            }
            if !self.driver.work_remaining() {
                return false;
            }
            let polled = self.driver.poll_with(NonZeroUsize::MIN).unwrap();
            pending.extend(polled.into_parts().0);
        }
        panic!("the run did not settle within {MAX_TURNS} turns");
    }

    /// Performs `action`, returning whether the process crashed on the way.
    fn perform(&mut self, action: &Action) -> bool {
        match action {
            Action::Deliver(artifacts) => {
                let step = self
                    .driver
                    .submit(cohort::<Sha256, _>(artifacts.clone()))
                    .unwrap();
                self.process(step.into_capabilities())
            }
            Action::Elapse(millis) => {
                let ticks = self.driver.advance(*millis).unwrap();
                ticks
                    .into_iter()
                    .any(|tick| self.process(tick.into_capabilities()))
            }
        }
    }

    /// Performs `script`. After the crash, peers deliver again everything delivered so far and
    /// the interrupted action is performed again.
    fn play(&mut self, script: &[Action]) {
        for (index, action) in script.iter().enumerate() {
            if !self.perform(action) {
                continue;
            }
            for (earlier, again) in script[..=index].iter().enumerate() {
                if earlier == index || matches!(again, Action::Deliver(_)) {
                    assert!(!self.perform(again));
                }
            }
        }
    }
}

/// Runs the crash-cut script without a crash, building each view's certificates on the V-QC the
/// node entered the view on, and returns the run with its script.
///
/// Each view, peers deliver the peer chain up to the view's header, time passes for a vote update
/// and an own header, and the view ends on a V-QC designating the view's leader block, whose
/// L-QC finalizes it. Then peers deliver a floor of [`ANCHOR_VIEW`] on the last V-QC's tips, and
/// time passes for the node to vote in the anchored tag.
fn uninterrupted(committee: &Committee<MinPk>) -> (CrashRun, Vec<Action>) {
    let mut run = CrashRun::start(committee, None);
    let interval = run
        .driver
        .machine()
        .profile()
        .tuning()
        .vote_interval
        .as_millis() as u64;
    let blocks = path(committee, PEER_CHAIN, CUT_VIEWS as usize);
    let mut parent = HeldVqc::genesis(committee.genesis());
    let mut script = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let view = parent.view.next();
        let mut tips = parent.tips.to_vec();
        tips[PEER_CHAIN.index()] = reference(block);
        let vqc = vqc_above(committee, &parent, true, tips, std::slice::from_ref(block));
        let id = vqc.id::<Sha256>();
        let leader = LeaderBlock::new(committee.round(view), parent.id, parent.history).unwrap();
        let vote = committee.content(
            view,
            Some(leader.digest::<Sha256>()),
            false,
            committee.endorsement(
                ChainSet::empty(committee.codec().chains()),
                parent.tips.to_vec(),
            ),
        );
        let lqc = committee.lqc_from(
            leader,
            certifiers(committee)
                .into_iter()
                .map(|signer| (signer, vote.clone()))
                .collect(),
        );
        for action in [
            Action::Deliver(
                blocks[..=index]
                    .iter()
                    .cloned()
                    .map(Artifact::TransactionBlock)
                    .collect(),
            ),
            Action::Elapse(interval),
            Action::Deliver(vec![Artifact::Vqc(vqc)]),
            Action::Deliver(vec![Artifact::Lqc(lqc)]),
        ] {
            assert!(!run.perform(&action));
            script.push(action);
        }
        parent = run
            .driver
            .machine()
            .held_vqc(&id)
            .expect("the node enters the next view on the V-QC");
    }
    let lag = run.driver.machine().profile().tuning().anchor_lag.get();
    assert!(ANCHOR_VIEW.get() > CUT_VIEWS + 1 + lag);
    let opening =
        HistoryRecord::new(digest(b"anchor parent history"), parent.tips.to_vec()).unwrap();
    let lqc = committee.lqc_with(
        ANCHOR_VIEW,
        CertificateId::new(digest(b"anchor parent")),
        opening.commitment::<Sha256>(),
    );
    let floor = Floor::new(Arc::new(lqc), Arc::new(opening));
    for action in [
        Action::Deliver(vec![Artifact::Floor(floor)]),
        Action::Elapse(interval),
    ] {
        assert!(!run.perform(&action));
        script.push(action);
    }
    (run, script)
}

/// Returns the leader block each vote update of `signed` names, by view tag.
fn voted_leaders(signed: &[SignRequest<MinPk, Digest>]) -> BTreeMap<View, Digest> {
    signed
        .iter()
        .filter_map(|request| match request {
            SignRequest::Update(update) => update
                .content()
                .leader()
                .map(|leader| (update.content().view(), leader)),
            _ => None,
        })
        .collect()
}

/// Checks that `run` signed and published only statements the uninterrupted `reference` could
/// have: one leader block per view, the reference's, in every update and proposal; vote updates
/// re-signed only identically, monotone in their tips and declarations, and nothing after a tag's
/// final vote; and no own header height signed twice.
///
/// After the crash, every update respects the vote watermark recovery restored: it repeats a
/// recorded final vote, does not lower a recorded tip, and keeps every recorded declaration at its
/// recorded height.
fn assert_replay_equivalent(run: &CrashRun, reference: &CrashRun) {
    let leaders = voted_leaders(&reference.signer.signed);
    let mut updates = BTreeMap::<View, BTreeMap<u32, &VoteContent<Digest>>>::new();
    let mut headers = BTreeMap::<Height, BlockRef<Digest>>::new();
    let mut proposals = BTreeMap::<View, Digest>::new();
    for request in &run.signer.signed {
        match request {
            SignRequest::Update(update) => {
                let content = update.content();
                let previous = updates
                    .entry(content.view())
                    .or_default()
                    .insert(update.seq(), content);
                assert!(
                    previous.is_none_or(|previous| previous == content),
                    "update {} of view {} is signed only once",
                    update.seq(),
                    content.view()
                );
            }
            SignRequest::TransactionBlock(header) => {
                let signed = header.block_ref::<Sha256>();
                let previous = headers.insert(header.height(), signed);
                assert!(
                    previous.is_none_or(|previous| previous == signed),
                    "own height {} is signed only once",
                    header.height()
                );
            }
            SignRequest::LeaderBlock(proposal) => {
                let block = proposal.block();
                assert_eq!(block.view(), LED_VIEW);
                let signed = block.digest::<Sha256>();
                let previous = proposals.insert(block.view(), signed);
                assert!(previous.is_none_or(|previous| previous == signed));
                assert_eq!(leaders.get(&block.view()), Some(&signed));
            }
        }
    }

    for (tag, sequence) in &updates {
        let mut previous: Option<&VoteContent<Digest>> = None;
        for content in sequence.values() {
            assert!(
                content
                    .leader()
                    .is_none_or(|leader| leaders.get(tag) == Some(&leader)),
                "view {tag} votes only for the reference's leader block"
            );
            if let Some(previous) = previous {
                assert!(
                    !previous.is_final(),
                    "nothing follows the final vote of view {tag}"
                );
                assert!(
                    previous
                        .leader()
                        .is_none_or(|leader| content.leader() == Some(leader))
                );
                assert!(
                    previous
                        .tips()
                        .iter()
                        .zip(content.tips())
                        .all(|(before, after)| before.height() <= after.height()),
                    "the tips of view {tag} never fall"
                );
                assert!(previous.declared().is_subset(content.declared()));
                for chain in previous.declared().iter() {
                    assert_eq!(
                        previous.tips()[chain.index()],
                        content.tips()[chain.index()],
                        "a declared chain keeps its tip in view {tag}"
                    );
                }
            }
            previous = Some(content);
        }
    }

    let finals = updates
        .iter()
        .filter_map(|(tag, sequence)| {
            let last = sequence.values().next_back()?;
            last.is_final().then_some((*tag, *last))
        })
        .collect::<BTreeMap<_, _>>();
    if let Some((before, recovered)) = &run.crash {
        for (tag, watermark) in recovered {
            if let Some(recorded) = &watermark.final_content {
                assert_eq!(
                    finals.get(tag),
                    Some(&recorded),
                    "view {tag}'s final vote is the recorded one"
                );
            }
        }
        for request in &run.signer.signed[*before..] {
            let SignRequest::Update(update) = request else {
                continue;
            };
            let content = update.content();
            let Some(watermark) = recovered.get(&content.view()) else {
                continue;
            };
            assert!(update.seq() >= watermark.seq);
            assert!(
                watermark
                    .final_content
                    .as_ref()
                    .is_none_or(|recorded| recorded == content),
                "a recorded final vote is only sent again"
            );
            assert!(
                watermark
                    .tips
                    .iter()
                    .zip(content.tips())
                    .all(|(recorded, tip)| recorded.height() <= tip.height()),
                "no tip falls below the recorded one"
            );
            assert!(watermark.declared.is_subset(content.declared()));
            for chain in watermark.declared.iter() {
                let declared = watermark.declaration(chain).unwrap();
                assert!(content.tips()[chain.index()].height() <= declared);
            }
        }
        for (tag, watermark) in &run.driver.machine().durable.state.watermark {
            if let Some(recovered) = recovered.get(tag) {
                for chain in recovered.declared.iter() {
                    assert_eq!(watermark.declaration(chain), recovered.declaration(chain));
                }
            }
        }
    }
    for (tag, watermark) in &run.driver.machine().durable.state.watermark {
        if let Some(recorded) = &watermark.final_content {
            assert_eq!(finals.get(tag), Some(&recorded));
        }
    }

    for artifact in &run.signer.signer.published {
        let Artifact::Update(update) = artifact else {
            continue;
        };
        let content = updates[&update.view()][&update.seq()];
        assert_eq!(update.is_final(), content.is_final());
        assert_eq!(update.leader(), content.leader());
        assert_eq!(update.declared(), content.declared());
    }
}

#[test]
fn a_crash_at_any_journal_boundary_releases_only_statements_of_the_uninterrupted_run() {
    let committee = cut_committee();
    let (reference, script) = uninterrupted(&committee);
    let machine = reference.driver.machine();
    assert_eq!(machine.view(), ANCHOR_VIEW);
    assert_eq!(
        machine.durable.state.retired_view.next(),
        ANCHOR_VIEW,
        "the node anchored"
    );
    assert!(
        machine.durable.state.leader_blocks.contains_key(&LED_VIEW)
            || machine.durable.state.retired_view >= LED_VIEW
    );
    let signed = &reference.signer.signed;
    assert!(
        signed
            .iter()
            .any(|request| matches!(request, SignRequest::TransactionBlock(_)))
    );
    assert!(
        signed
            .iter()
            .any(|request| matches!(request, SignRequest::LeaderBlock(_)))
    );
    assert!(signed.iter().any(
        |request| matches!(request, SignRequest::Update(update) if update.content().is_final())
    ));
    assert!(signed.iter().any(
        |request| matches!(request, SignRequest::Update(update) if !update.content().is_final())
    ));
    assert!(
        signed.iter().any(
            |request| matches!(request, SignRequest::Update(update) if update.content().view() == ANCHOR_VIEW)
        ),
        "the node votes in the anchored tag"
    );
    assert!(
        reference
            .signer
            .signer
            .published
            .iter()
            .any(|artifact| matches!(artifact, Artifact::Vqc(_)))
    );
    assert_replay_equivalent(&reference, &reference);

    for cut in 0..reference.boundaries {
        let mut run = CrashRun::start(&committee, Some(cut));
        run.play(&script);
        assert!(run.crash.is_some(), "boundary {cut} is reached");
        assert_replay_equivalent(&run, &reference);
        assert_eq!(
            run.driver.machine().view(),
            machine.view(),
            "boundary {cut}"
        );
    }
}

#[test]
fn a_durable_final_vote_whose_publication_is_uncertain_is_resent_identically() {
    let committee = committee(25);
    let mut driver = started(&committee, validator(0));
    let mut executor = (RecordingSigner::new(&committee, false), SymbolicPersistence);
    let view = View::new(1);
    let declarations = Declarations::new(view, committee.codec().chains());
    let last = driver
        .machine()
        .endorsed_content(view, None, true, &declarations)
        .unwrap();
    let now = driver.now();
    let (_, mut capabilities) = driver.machine_mut().send_update(last.clone(), now).unwrap();
    capabilities.extend(driver.machine_mut().emit_staged());
    driver.record(&capabilities);
    let withheld = released_updates(&driver.drain(&mut executor, capabilities));
    assert_eq!(withheld.len(), 1);
    let state = &driver.machine().durable.state;
    assert_eq!(state.watermark[&view].final_content.as_ref(), Some(&last));
    assert!(
        driver.machine().checkpoint_cut().is_some(),
        "the final vote is durable"
    );

    // The process crashes before the publication is known to have left: recovery sends the same
    // update again and signs nothing.
    let signed = executor.0.signed.len();
    let recovered = driver.crash_and_restore().unwrap();
    let resent = released_updates(&driver.drain(&mut executor, recovered.into_capabilities()));
    assert_eq!(resent, withheld);
    assert_eq!(executor.0.signed.len(), signed);

    // No other final vote of the tag is ever signed.
    let other = committee.content(
        view,
        Some(digest(b"other")),
        true,
        committee.genesis_endorsement(),
    );
    let now = driver.now();
    assert!(matches!(
        driver.machine_mut().send_update(other, now),
        Err(StepError::DurableTransition {
            source: ReplayError::Transition(TransitionReason::SigningSlot),
            ..
        })
    ));
}
