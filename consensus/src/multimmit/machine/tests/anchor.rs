//! Finality anchoring: a floor beyond the anchor lag re-roots the node at the floor's view, one
//! within it is refused, and an anchor never lies at or below a vote tag this node may have signed.

use crate::{
    Viewable as _,
    multimmit::{
        config::{Profile, Tuning},
        machine::{
            capability::{Capability, ResolverCommand},
            durability::{ReplayError, RetentionRoot, SignRequest, TransitionReason},
            input::{BlockValidity, Input, ObservationStatus, Step, StepError, StepStatus},
            reducer::machine::Machine,
            resolution::RetrievalKey,
            testing::{
                CapabilitiesExt as _, Drive as _, MachineExt as _, SymbolicPersistence,
                SymbolicSigner, SymbolicVerifier, Until, cohort,
                fixtures::{
                    Block, PARTICIPANTS, TestDriver, block, committee, deliver, digest, elapse,
                    enter_next_view, path, persist_all, produce, quiesce, receive, reference,
                    started_with, tuned, validate, validator, vqc_above,
                },
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{
            Activity, Artifact, BlockRef, CertificateId, ChainId, Floor, HistoryRecord, Resolution,
        },
    },
    types::{Height, Participant, View, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::sync::Arc;

/// The anchor lag the tests run with.
const LAG: u64 = 4;

/// The chain validator 0 produces.
const OWN: ChainId = ChainId::new(0);

/// A peer chain whose accepted path holds the floor's base.
const HOLDING: ChainId = ChainId::new(1);

/// A peer chain whose accepted path lies on another branch than the floor's base.
const STRANDED: ChainId = ChainId::new(2);

/// Returns validator 0's profile anchoring beyond [`LAG`] views.
fn anchoring_profile(committee: &Committee<MinPk>) -> Profile<Digest> {
    let tuning = Tuning {
        view_retention: ViewDelta::new(2 * LAG),
        ..Tuning::default()
    };
    let profile = tuned(committee, validator(0), tuning);
    assert_eq!(profile.tuning().anchor_lag, ViewDelta::new(LAG));
    profile
}

/// Accepts `blocks`, one chain's path lowest first, on endorsements of every peer.
fn accept(driver: &mut TestDriver, blocks: &[Block]) {
    for block in blocks {
        receive(driver, std::slice::from_ref(block));
        let now = driver.now();
        for signer in 1..PARTICIPANTS {
            driver.machine_mut().note_endorsement(
                Participant::new(signer),
                View::new(1),
                reference(block),
                now,
                now,
            );
        }
        quiesce(driver);
        validate(driver, block, BlockValidity::Valid);
    }
    let last = reference(blocks.last().expect("a path"));
    assert_eq!(driver.machine().accepted_tip(last.chain()), last);
}

/// Produces, signs, and accepts validator 0's first own header, returning it.
fn produce_own(driver: &mut TestDriver, committee: &Committee<MinPk>) -> BlockRef<Digest> {
    let reserved = produce(driver);
    let mut executor = (
        SymbolicSigner::new(committee.signers[0].clone()),
        SymbolicPersistence,
    );
    driver.drain(&mut executor, reserved.into_capabilities());
    quiesce(driver);
    let own = driver.machine().accepted_tip(OWN);
    assert_eq!(own.height(), Height::new(1));
    own
}

/// A validator in view four that produced one own header, accepted three headers of
/// [`HOLDING`] and two of [`STRANDED`], and signed votes in every view it entered.
struct Lagging {
    driver: TestDriver,
    own: BlockRef<Digest>,
    holding: Vec<Block>,
    stranded: Vec<Block>,
}

fn lagging(committee: &Committee<MinPk>) -> Lagging {
    let mut driver = started_with(anchoring_profile(committee));
    let own = produce_own(&mut driver, committee);
    let holding = path(committee, HOLDING, 3);
    let stranded = path(committee, STRANDED, 2);
    accept(&mut driver, &holding);
    accept(&mut driver, &stranded);
    let mut parent = HeldVqc::genesis(committee.genesis());
    for _ in 1..4 {
        let tips = parent.tips.to_vec();
        parent = enter_next_view(&mut driver, vqc_above(committee, &parent, false, tips, &[]));
    }
    assert_eq!(driver.machine().view(), View::new(4));
    assert!(
        !driver.machine().durable.state.watermark.is_empty(),
        "the node signed votes"
    );
    Lagging {
        driver,
        own,
        holding,
        stranded,
    }
}

/// Returns a floor of `view` whose base is `base`, with the V-QC its leader block names.
fn floor(
    committee: &Committee<MinPk>,
    view: View,
    base: Vec<BlockRef<Digest>>,
) -> (Floor<MinPk, Digest>, CertificateId<Digest>) {
    let opening = HistoryRecord::new(digest(b"anchor parent history"), base).unwrap();
    let parent = CertificateId::new(digest(b"anchor parent"));
    let lqc = committee.lqc_with(view, parent, opening.commitment::<Sha256>());
    (Floor::new(Arc::new(lqc), Arc::new(opening)), parent)
}

/// Returns the base the tests anchor on: the own header, the middle of [`HOLDING`]'s path, a
/// header of [`STRANDED`] on another branch than the accepted one, and every other chain's genesis
/// object.
fn base(committee: &Committee<MinPk>, node: &Lagging) -> Vec<BlockRef<Digest>> {
    let mut base = committee.genesis().tips().to_vec();
    base[OWN.index()] = node.own;
    base[HOLDING.index()] = reference(&node.holding[1]);
    base[STRANDED.index()] = reference(&block(
        committee,
        &reference(&node.stranded[0]),
        b"other branch",
    ));
    base
}

/// Checks that `driver`'s journal replays from its checkpoint to its live state.
fn assert_replays(driver: &TestDriver) {
    let mut machine = Machine::<Sha256, MinPk>::restore(
        driver.machine().profile().clone(),
        driver.checkpoint().clone(),
    )
    .expect("the checkpoint is valid");
    for event in driver.journal() {
        machine.replay(event.clone()).expect("the journal replays");
    }
    assert_eq!(
        machine.live_snapshot_for_test(),
        driver.machine().live_snapshot_for_test()
    );
}

#[test]
fn a_floor_beyond_the_lag_anchors_the_node() {
    let committee = committee(700);
    let mut node = lagging(&committee);
    let view = View::new(4 + LAG + 1);
    let base = base(&committee, &node);
    let (floor, parent) = floor(&committee, view, base.clone());
    let produced = node.driver.machine().durable.state.produced;
    let generation = node.driver.machine().generation();
    let mut activities = deliver(&mut node.driver, vec![Artifact::Floor(floor.clone())]);
    activities.extend(quiesce(&mut node.driver));

    let retired = View::new(view.get() - 1);
    let state = &node.driver.machine().durable.state;
    assert_eq!(state.view, view);
    assert_eq!(state.retired_view, retired);
    assert_eq!(
        state.root,
        Some(RetentionRoot {
            vqc: parent,
            record: floor.opening().clone(),
        })
    );
    assert_eq!(state.emission.len(), 1);
    assert_eq!(state.emission[&view].record, *floor.opening());
    assert_eq!(
        state.emission[&view].by,
        Resolution::Pinned {
            view,
            lqc: floor.lqc().id::<Sha256>(),
        }
    );
    assert!(state.exits.is_empty() && state.ancestors.is_empty());
    assert!(state.forwarded_vqcs.is_empty());
    for views in [
        state.leader_blocks.keys().collect::<Vec<_>>(),
        state.notarised.keys().collect(),
        state.watermark.keys().collect(),
    ] {
        assert!(views.into_iter().all(|tagged| *tagged >= view));
    }
    assert!(
        state
            .local
            .values()
            .all(|artifact| artifact.view().is_none_or(|local| local >= view))
    );
    assert!(
        state
            .local
            .values()
            .any(|artifact| **artifact == Artifact::Lqc(floor.lqc().clone())),
        "the anchoring L-QC is retained"
    );
    assert_eq!(state.last_final, (retired, base.clone()));
    assert_eq!(state.anchored_tag, Some(view));
    assert_eq!(state.origin, base);
    assert_eq!(
        state.generation,
        generation.next().unwrap(),
        "a new generation fences the work issued before the anchor"
    );

    // The holding chain keeps its path from the base up; the stranded chain starts afresh at the
    // base; the own chain keeps its headers and its produced height.
    let heights = |chain: ChainId| {
        state.accepted[chain.index()]
            .keys()
            .map(|height| height.get())
            .collect::<Vec<_>>()
    };
    assert_eq!(heights(HOLDING), vec![2, 3]);
    assert!(heights(STRANDED).is_empty());
    assert_eq!(heights(OWN), vec![1]);
    assert_eq!(state.produced, produced);
    let machine = node.driver.machine();
    assert_eq!(machine.accepted_tip(HOLDING), reference(&node.holding[2]));
    assert_eq!(machine.accepted_tip(STRANDED), base[STRANDED.index()]);
    assert_eq!(machine.chain_layer().tip(STRANDED), base[STRANDED.index()]);
    assert_eq!(
        machine.chain_layer().finalized(HOLDING),
        base[HOLDING.index()].height()
    );

    // The floor's parent is held as the retention root, and the floor is reported finalized.
    assert_eq!(
        machine.held_vqc(&parent).map(|held| held.view),
        Some(retired)
    );
    let finalized = activities
        .iter()
        .filter_map(|activity| match activity {
            Activity::LeaderFinalized { lqc, opening } => Some((lqc.view(), opening.as_ref())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(finalized, vec![(view, floor.opening())]);

    // The first update of the anchored tag names every chain.
    elapse(&mut node.driver, 1_000);
    let state = &node.driver.machine().durable.state;
    let first = state
        .sign_requests()
        .find_map(|request| match request {
            SignRequest::Update(update) if update.content().view() == view && update.seq() == 1 => {
                Some(update.clone())
            }
            _ => None,
        })
        .expect("the node votes in the anchored tag");
    assert_eq!(first.changes().len(), committee.codec().chains());
    let tips = first.content().tips();
    assert_eq!(tips[HOLDING.index()], reference(&node.holding[2]));
    assert_eq!(tips[STRANDED.index()], base[STRANDED.index()]);
    assert_eq!(tips[OWN.index()], node.own);
    assert_replays(&node.driver);
}

#[test]
fn work_issued_before_an_anchor_completes_as_stale() {
    let committee = committee(704);
    let mut node = lagging(&committee);
    let content = committee.content(View::new(4), None, false, committee.genesis_endorsement());
    let update = committee.update(Participant::new(1), &content, committee.genesis().tips(), 1);
    let observed = node
        .driver
        .submit(cohort::<Sha256, _>(vec![Artifact::Update(update)]))
        .unwrap();
    let job = observed.verify_job();
    let (floor, _) = floor(&committee, View::new(4 + LAG + 1), base(&committee, &node));
    deliver(&mut node.driver, vec![Artifact::Floor(floor)]);
    let anchored = node.driver.machine().live_snapshot_for_test();

    // The verdict on the update observed before the anchor belongs to the previous generation.
    let step = node.driver.verify(&job, true, Until::Quiesce);
    assert_eq!(step.status(), &StepStatus::StaleCompletion);
    assert_eq!(node.driver.machine().live_snapshot_for_test(), anchored);
    assert_eq!(node.driver.inspect().cached_artifacts(), 0);
}

#[test]
fn a_floor_within_the_lag_does_not_anchor() {
    let committee = committee(701);
    let mut node = lagging(&committee);
    let before = node.driver.machine().live_snapshot_for_test();
    let (floor, _) = floor(&committee, View::new(4 + LAG), base(&committee, &node));
    let step = node
        .driver
        .submit(cohort::<Sha256, _>(vec![Artifact::Floor(floor)]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("the floor is observed");
    };
    assert_eq!(
        results[0].status(),
        ObservationStatus::Rejected(crate::multimmit::machine::input::Rejection::TagWindow)
    );
    assert_eq!(node.driver.machine().live_snapshot_for_test(), before);
}

#[test]
fn an_anchor_never_signs_a_tag_at_or_below_a_watermark_or_rewrites_an_emission() {
    let committee = committee(702);
    let mut node = lagging(&committee);
    let base = base(&committee, &node);
    let refused = |driver: &mut TestDriver, view: View| {
        let artifact = Arc::new(Artifact::Floor(floor(&committee, view, base.clone()).0));
        let change = driver.machine().anchoring(artifact);
        match driver.machine_mut().stage_test_change(change) {
            Err(StepError::DurableTransition {
                source: ReplayError::Transition(reason),
                ..
            }) => reason,
            other => panic!("the anchor at {view} is refused, got {other:?}"),
        }
    };

    // An anchor at most two views ahead could share a tag with a vote already signed.
    assert_eq!(
        refused(&mut node.driver, View::new(6)),
        TransitionReason::Anchor
    );

    // An anchor at or below a tag holding a watermark, or at or below the tag after the last final
    // vote, is refused however far ahead of the view it lies.
    let state = &mut node.driver.machine_mut().durable.state;
    let watermark = state.watermark.values().next_back().unwrap().clone();
    state.watermark.insert(View::new(12), watermark);
    assert_eq!(
        refused(&mut node.driver, View::new(12)),
        TransitionReason::Anchor
    );
    let state = &mut node.driver.machine_mut().durable.state;
    state.watermark.remove(&View::new(12));
    state.last_final.0 = View::new(11);
    assert_eq!(
        refused(&mut node.driver, View::new(12)),
        TransitionReason::Anchor
    );

    // An anchor at or below a view whose emission is written would rewrite it.
    let state = &mut node.driver.machine_mut().durable.state;
    state.last_final.0 = View::zero();
    let emission = state.emission.values().next_back().unwrap().clone();
    state.emission.insert(View::new(12), emission);
    assert_eq!(
        refused(&mut node.driver, View::new(12)),
        TransitionReason::Anchor
    );
    let state = &mut node.driver.machine_mut().durable.state;
    state.emission.remove(&View::new(12));
    state.last_final.0 = View::new(11);

    // The drive drops such a floor without staging it.
    let (floor, _) = floor(&committee, View::new(12), base);
    deliver(&mut node.driver, vec![Artifact::Floor(floor)]);
    assert_eq!(node.driver.machine().view(), View::new(4));
}

#[test]
fn only_a_verified_certificate_far_ahead_makes_the_node_request_a_floor() {
    let committee = committee(703);
    let mut driver = started_with(anchoring_profile(&committee));
    let horizon = driver
        .machine()
        .profile()
        .resources()
        .max_future_view_distance();
    let ahead = View::new(horizon + 2);
    let requests = |step: &Step<MinPk, Digest>| {
        step.capabilities()
            .iter()
            .filter(|capability| {
                matches!(
                    capability,
                    Capability::Resolver(ResolverCommand::Resolve(job))
                        if job.key() == RetrievalKey::LatestFloor
                )
            })
            .count()
    };
    let verifies = |step: &Step<MinPk, Digest>| {
        step.capabilities()
            .iter()
            .any(|capability| matches!(capability, Capability::Verify(_)))
    };

    // A signed artifact beyond the window is refused before its signature is checked, so no
    // number of signers it claims makes the node request anything.
    let content = committee.content(ahead, None, false, committee.genesis_endorsement());
    for signer in 1..PARTICIPANTS {
        let update = committee.update(
            Participant::new(signer),
            &content,
            committee.genesis().tips(),
            1,
        );
        let step = driver
            .submit(cohort::<Sha256, _>(vec![Artifact::Update(update)]))
            .unwrap();
        assert_eq!(requests(&step), 0);
        assert!(!verifies(&step));
    }

    // A certificate beyond the window is verified first: a forged one requests nothing.
    let vqc = Artifact::Vqc(committee.vqc(ahead));
    let check = |valid: bool, driver: &mut TestDriver| {
        let step = driver
            .submit(cohort::<Sha256, _>(vec![vqc.clone()]))
            .unwrap();
        assert_eq!(requests(&step), 0);
        let job = step.verify_job();
        driver
            .submit(Input::Verified(SymbolicVerifier::new(valid).complete(&job)))
            .unwrap()
    };
    let rejected = check(false, &mut driver);
    assert_eq!(requests(&rejected), 0);

    // Its `n - f` signers include a correct validator that far ahead, so a valid one requests a
    // peer's newest floor, once.
    let verified = check(true, &mut driver);
    assert_eq!(requests(&verified), 1);
    persist_all(&mut driver, verified);
    let step = driver
        .submit(cohort::<Sha256, _>(vec![vqc.clone()]))
        .unwrap();
    assert!(!verifies(&step), "one request is outstanding");
}

#[test]
fn an_anchor_links_the_headers_above_each_chains_origin() {
    let committee = committee(707);
    let mut node = lagging(&committee);
    let view = View::new(4 + LAG + 1);
    let base = base(&committee, &node);
    let (floor, _) = floor(&committee, view, base.clone());
    deliver(&mut node.driver, vec![Artifact::Floor(floor)]);
    quiesce(&mut node.driver);

    // The stranded chain restarts at the base, which this node never held: a header above it links
    // through the origin, while one above the abandoned branch at the origin's height does not.
    let origin = base[STRANDED.index()];
    assert_eq!(node.driver.machine().chain_layer().tip(STRANDED), origin);
    let above = block(&committee, &origin, b"above the origin");
    let abandoned = block(
        &committee,
        &reference(&node.stranded[1]),
        b"above the abandoned branch",
    );
    let machine = node.driver.machine_mut();
    assert!(machine.hold_header(above.header().clone()));
    assert!(!machine.hold_header(abandoned.header().clone()));
    let headers = &node.driver.machine().chain_layer().headers;
    assert!(
        headers
            .get(&reference(&above))
            .is_some_and(|entry| entry.linked)
    );
    assert!(headers.get(&reference(&abandoned)).is_none());
}
