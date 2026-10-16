//! Committee fixtures and profiles for machine tests.

use crate::{
    Viewable as _,
    multimmit::{
        config::{Profile, Role, Tuning},
        machine::{
            IdentifiedArtifact,
            capability::{AppJob, Capabilities, Capability},
            durability::Change,
            input::{BlockValidity, Input, Step, StepStatus, TimerFamily, ValidationCompletion},
            testing::{
                CapabilitiesExt as _, Drive as _, Driver, StepExt as _, SymbolicPersistence, Until,
                cohort, executors::SymbolicApplication,
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{
            Activity, Artifact, BlockRef, ChainId, ChainSet, LeaderBlock, ResolutionPath,
            SignedTransactionBlock, VoteContent, Vqc,
        },
    },
    types::{Participant, View},
};
use commonware_cryptography::{
    Hasher, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

/// The committee size the machine tests run with.
pub(crate) const PARTICIPANTS: u32 = 6;

/// The machine type the tests drive.
pub(crate) type TestDriver = Driver<Sha256, MinPk>;

/// Returns a committee of [`PARTICIPANTS`] with keys derived from `seed`.
pub(crate) fn committee(seed: u64) -> Committee<MinPk> {
    Committee::builder(seed, PARTICIPANTS).build()
}

/// Returns `role`'s profile in `committee` under the default tuning.
pub(crate) fn profile(committee: &Committee<MinPk>, role: Role) -> Profile<Digest> {
    tuned(committee, role, Tuning::default())
}

/// Returns `role`'s profile in `committee` under `tuning`.
pub(crate) fn tuned(committee: &Committee<MinPk>, role: Role, tuning: Tuning) -> Profile<Digest> {
    Profile::new::<MinPk>(committee.config.clone(), role, tuning)
        .expect("the tuning sustains the committee")
}

/// Returns the digest of `label`.
pub(crate) fn digest(label: &[u8]) -> Digest {
    Sha256::hash(&[label])
}

/// Returns the validator role of `participant`.
pub(crate) const fn validator(participant: u32) -> Role {
    Role::Validator(Participant::new(participant))
}

/// Returns a driver for `role` in `committee` whose machine started and made its first
/// generation durable.
pub(crate) fn started(committee: &Committee<MinPk>, role: Role) -> TestDriver {
    started_with(profile(committee, role))
}

/// Returns a driver for `profile` whose machine started and made its first generation durable.
pub(crate) fn started_with(profile: Profile<Digest>) -> TestDriver {
    let mut driver = Driver::new(profile);
    let start = driver.submit(Input::Start).expect("a fresh machine starts");
    let unhandled = driver.drain(&mut SymbolicPersistence, start.into_capabilities());
    // The driver's clock holds the deadlines a start arms.
    assert!(
        unhandled
            .iter()
            .all(|capability| matches!(capability, Capability::Timer(_))),
        "a fresh start releases nothing: {unhandled:?}"
    );
    assert!(driver.inspect().is_live());
    driver
}

/// Completes the local producer's outstanding build, or fires its armed deadline when no build is
/// outstanding, and the custody that build starts, with [`SymbolicApplication`]. Returns the step
/// that reserved the built header's signature, folded until it carries its barrier.
///
/// The build the producer starts on the completed one is left outstanding for the next call.
///
/// # Panics
///
/// Panics unless a build is outstanding or a production deadline is armed, and it leads to a
/// header reservation.
pub(crate) fn produce(driver: &mut TestDriver) -> Step<MinPk, Digest> {
    let outstanding = driver
        .machine()
        .components
        .producer
        .as_ref()
        .and_then(|producer| producer.build_job());
    let started = outstanding.map_or_else(
        || {
            let deadline = driver
                .clock()
                .deadline(TimerFamily::Production)
                .expect("the producer armed its deadline");
            driver
                .advance(deadline.millis().saturating_sub(driver.now().millis()))
                .expect("the deadline fires")
                .into_iter()
                .flat_map(Step::into_capabilities)
                .collect()
        },
        |job| vec![Capability::Application(AppJob::Build(job))],
    );
    let mut application = SymbolicApplication::new(BlockValidity::Valid);
    let mut pending = VecDeque::from(started);
    while let Some(capability) = pending.pop_front() {
        if matches!(capability, Capability::Application(AppJob::Build(_)))
            && driver
                .machine()
                .components
                .producer
                .as_ref()
                .is_some_and(|producer| producer.custody_pending())
        {
            // The build pipelined behind the one this call completes.
            continue;
        }
        let Some(Some(step)) = driver
            .execute(&mut application, &capability)
            .expect("the application completes")
        else {
            continue;
        };
        if matches!(capability, Capability::Application(AppJob::Custody(_))) {
            return driver.settle(step, Until::Persist);
        }
        pending.extend(step.into_capabilities());
    }
    panic!("the producer reserved no header");
}

/// Returns the body digest [`SymbolicApplication`] builds above `parent`.
pub(crate) fn built_body(parent: Digest) -> Digest {
    Sha256::hash(&[parent.as_ref()])
}

/// A producer-signed header.
pub(crate) type Block = SignedTransactionBlock<MinPk, Digest>;

/// Returns the producer-signed header above `parent` committing to the body `label`.
pub(crate) fn block(
    committee: &Committee<MinPk>,
    parent: &BlockRef<Digest>,
    label: &[u8],
) -> Block {
    committee.sign_header(committee.header(parent, digest(label)))
}

/// Returns `count` producer-signed headers extending `chain`'s genesis object, lowest first.
pub(crate) fn path(committee: &Committee<MinPk>, chain: ChainId, count: usize) -> Vec<Block> {
    let mut parent = committee.genesis().tips()[chain.index()];
    (0..count)
        .map(|index| {
            let block = block(committee, &parent, &index.to_be_bytes());
            parent = reference(&block);
            block
        })
        .collect()
}

/// Returns the reference of `block`.
pub(crate) fn reference(block: &Block) -> BlockRef<Digest> {
    block.header().block_ref::<Sha256>()
}

/// Makes every barrier `step` leads to durable, folding all follow-up work, and returns every
/// activity reported on the way.
pub(crate) fn persist_all(
    driver: &mut TestDriver,
    step: Step<MinPk, Digest>,
) -> Vec<Activity<MinPk, Digest>> {
    let mut activities = step.activities.clone();
    let mut jobs = step
        .journals()
        .into_iter()
        .map(|journal| journal.job.clone())
        .collect::<VecDeque<_>>();
    while let Some(job) = jobs.pop_front() {
        let acknowledged = driver.persist(&job, Until::Quiesce);
        activities.extend(acknowledged.activities.iter().cloned());
        jobs.extend(
            acknowledged
                .journals()
                .into_iter()
                .map(|journal| journal.job.clone()),
        );
    }
    activities
}

/// Runs the machine's pending work to quiescence and makes it durable.
pub(crate) fn quiesce(driver: &mut TestDriver) -> Vec<Activity<MinPk, Digest>> {
    let step = driver.settle(Step::from(StepStatus::Accepted), Until::Quiesce);
    persist_all(driver, step)
}

/// Observes `artifacts` and verifies them, returning the step their admission led to.
pub(crate) fn observe(
    driver: &mut TestDriver,
    artifacts: Vec<Artifact<MinPk, Digest>>,
) -> Step<MinPk, Digest> {
    let observed = driver.submit(cohort::<Sha256, _>(artifacts)).unwrap();
    driver.verify(&observed.verify_job(), true, Until::Quiesce)
}

/// Observes `artifacts` as ingress hands them over, already identified, and verifies them,
/// returning the step their admission led to.
pub(crate) fn observe_identified(
    driver: &mut TestDriver,
    artifacts: Vec<IdentifiedArtifact<MinPk, Digest>>,
) -> Step<MinPk, Digest> {
    let observed = driver.submit(Input::Observe(artifacts)).unwrap();
    driver.verify(&observed.verify_job(), true, Until::Quiesce)
}

/// Observes `artifacts`, verifies them, and runs everything their admission leads to durably,
/// returning every activity reported on the way.
pub(crate) fn deliver(
    driver: &mut TestDriver,
    artifacts: Vec<Artifact<MinPk, Digest>>,
) -> Vec<Activity<MinPk, Digest>> {
    let step = observe(driver, artifacts);
    let mut activities = persist_all(driver, step);
    activities.extend(quiesce(driver));
    activities
}

/// Observes `blocks` and verifies them, returning the step their admission led to.
pub(crate) fn receive(driver: &mut TestDriver, blocks: &[Block]) -> Step<MinPk, Digest> {
    observe(
        driver,
        blocks
            .iter()
            .cloned()
            .map(Artifact::TransactionBlock)
            .collect(),
    )
}

/// Advances the clock by `millis`, fires every deadline it reaches, and runs the work they wake
/// to quiescence, durably.
pub(crate) fn elapse(driver: &mut TestDriver, millis: u64) {
    for tick in driver.advance(millis).unwrap() {
        let step = driver.settle(tick, Until::Quiesce);
        persist_all(driver, step);
    }
    quiesce(driver);
}

/// Makes the capabilities a direct machine call returned durable, with whatever it staged.
pub(crate) fn persist_capabilities(
    driver: &mut TestDriver,
    mut capabilities: Capabilities<MinPk, Digest>,
) {
    capabilities.extend(driver.machine_mut().emit_staged());
    driver.record(&capabilities);
    persist_all(
        driver,
        Step::for_tests(StepStatus::Accepted, capabilities, Vec::new()),
    );
}

/// Returns the participants whose final votes the V-QC fixtures record: the last `n - f`, so a
/// test node at participant zero reads every one of them from the certificate.
pub(crate) fn certifiers(committee: &Committee<MinPk>) -> Vec<Participant> {
    let participants = committee.codec().participants();
    (participants - committee.codec().view_quorum()..participants)
        .map(Participant::from_usize)
        .collect()
}

/// Returns the resolution paths of every tip in `contents` above `base` that lies on no other
/// such tip's path, rebuilt from `blocks`.
///
/// # Panics
///
/// Panics unless `blocks` hold every header between such a tip and the base height.
pub(crate) fn resolution_paths(
    committee: &Committee<MinPk>,
    base: &[BlockRef<Digest>],
    contents: &[(Participant, VoteContent<Digest>)],
    blocks: &[Block],
) -> Vec<ResolutionPath<Digest>> {
    let headers = blocks
        .iter()
        .map(|block| (reference(block), block.header().clone()))
        .collect::<BTreeMap<_, _>>();
    let mut paths = BTreeMap::new();
    for (_, content) in contents {
        for (tip, base) in content.tips().iter().zip(base) {
            let mut lineage = Vec::new();
            let mut current = *tip;
            while current.height() > base.height() {
                let header = &headers[&current];
                lineage.push((current, header.body_digest()));
                current = header.parent_ref();
            }
            if !lineage.is_empty() {
                lineage.reverse();
                paths.insert(*tip, (current, lineage));
            }
        }
    }
    let interior = paths
        .values()
        .flat_map(|(_, lineage)| lineage[..lineage.len() - 1].iter().map(|(block, _)| *block))
        .collect::<BTreeSet<_>>();
    paths
        .into_iter()
        .filter(|(tip, _)| !interior.contains(tip))
        .map(|(_, (from, lineage))| {
            let payloads = lineage.into_iter().map(|(_, payload)| payload).collect();
            ResolutionPath::new(from, payloads, committee.codec()).unwrap()
        })
        .collect()
}

/// Returns the V-QC above `parent` recording `contents`, final votes of the view after
/// `parent`'s, with the resolution paths `blocks` rebuild.
pub(crate) fn vqc_of(
    committee: &Committee<MinPk>,
    parent: &HeldVqc<Digest>,
    contents: Vec<(Participant, VoteContent<Digest>)>,
    blocks: &[Block],
) -> Vqc<MinPk, Digest> {
    let paths = resolution_paths(committee, &parent.tips, &contents, blocks);
    committee.vqc_from(parent.id, contents, paths)
}

/// Returns the final vote of the view after `parent`'s endorsing `tips`, for the leader block
/// above `parent` when `leader`, else leaderless.
pub(crate) fn final_above(
    committee: &Committee<MinPk>,
    parent: &HeldVqc<Digest>,
    leader: bool,
    tips: Vec<BlockRef<Digest>>,
) -> VoteContent<Digest> {
    let view = parent.view.next();
    let leader = leader.then(|| {
        LeaderBlock::new(committee.round(view), parent.id, parent.history)
            .unwrap()
            .digest::<Sha256>()
    });
    let declared = ChainSet::empty(committee.codec().chains());
    committee.content(view, leader, true, committee.endorsement(declared, tips))
}

/// Returns a V-QC above `parent` in which the [`certifiers`] vote finally for `tips`, for the
/// leader block above `parent` when `leader`, with the resolution paths `blocks` rebuild.
pub(crate) fn vqc_above(
    committee: &Committee<MinPk>,
    parent: &HeldVqc<Digest>,
    leader: bool,
    tips: Vec<BlockRef<Digest>>,
    blocks: &[Block],
) -> Vqc<MinPk, Digest> {
    let content = final_above(committee, parent, leader, tips);
    let contents = certifiers(committee)
        .into_iter()
        .map(|signer| (signer, content.clone()))
        .collect();
    vqc_of(committee, parent, contents, blocks)
}

/// Returns a V-QC above `parent` whose tips are `parent`'s but whose final votes fix no base for
/// the next view: two of the [`certifiers`] endorse a block of chain one above `parent`'s tip and
/// the others `parent`'s tips, so no `n - f` final votes of the view agree on chain one and only a
/// later L-QC can resolve the view.
pub(crate) fn undetermined_vqc(
    committee: &Committee<MinPk>,
    parent: &HeldVqc<Digest>,
) -> Vqc<MinPk, Digest> {
    let chain = ChainId::new(1);
    let split = block(committee, &parent.tips[chain.index()], b"split");
    let mut tips = parent.tips.to_vec();
    let agreed = final_above(committee, parent, false, tips.clone());
    tips[chain.index()] = reference(&split);
    let diverged = final_above(committee, parent, false, tips);
    let contents = certifiers(committee)
        .into_iter()
        .enumerate()
        .map(|(index, signer)| {
            let content = if index < 2 { &diverged } else { &agreed };
            (signer, content.clone())
        })
        .collect();
    vqc_of(committee, parent, contents, &[split])
}

/// Delivers `vqc`, a V-QC of the current view whose parent chain is held, and runs the view change
/// it causes durably: this node's final vote, the V-QC's forwarding, and the entry into the next
/// view. Returns the V-QC as the store holds it.
///
/// # Panics
///
/// Panics unless the node enters the next view on `vqc`.
pub(crate) fn enter_next_view(driver: &mut TestDriver, vqc: Vqc<MinPk, Digest>) -> HeldVqc<Digest> {
    enter_next_view_identified(
        driver,
        Artifact::Vqc(vqc).identify::<Sha256>(&mut Vec::new()),
    )
}

/// Delivers the identified V-QC `vqc`, asserts it ends the current view, and returns the V-QC
/// the node now holds.
pub(crate) fn enter_next_view_identified(
    driver: &mut TestDriver,
    vqc: IdentifiedArtifact<MinPk, Digest>,
) -> HeldVqc<Digest> {
    let Artifact::Vqc(certificate) = &vqc.artifact else {
        panic!("the artifact is a V-QC");
    };
    let (view, id) = (certificate.view(), certificate.id::<Sha256>());
    let step = observe_identified(driver, vec![vqc]);
    persist_all(driver, step);
    quiesce(driver);
    assert_eq!(
        driver.inspect().view(),
        view.next(),
        "the V-QC ends its view"
    );
    driver.machine().held_vqc(&id).expect("the V-QC is held")
}

/// Stages the entries into every view below `view` on a chain of V-QCs above the genesis V-QC,
/// each made durable first and none held, and asserts the machine is in `view`.
///
/// Each V-QC records leaderless final votes of the first `n - f` participants endorsing every
/// genesis object.
pub(crate) fn stage_view_entries(
    driver: &mut TestDriver,
    committee: &Committee<MinPk>,
    view: View,
) {
    let mut parent = committee.genesis().vqc();
    for exited in 1..view.get() {
        let content = committee.content(
            View::new(exited),
            None,
            true,
            committee.genesis_endorsement(),
        );
        let vqc = committee.vqc_from(parent, committee.quorum(&content), Vec::new());
        let id = vqc.id::<Sha256>();
        let artifact = Arc::new(Artifact::Vqc(vqc));
        let entry = driver
            .machine()
            .view_entry(artifact.id::<Sha256>(), Vec::new());
        let created = Change::CertificateCreated { artifact };
        for change in [created, entry] {
            let staged = driver.machine_mut().reserve_change(change).unwrap();
            persist_capabilities(driver, staged);
        }
        parent = id;
    }
    assert_eq!(driver.machine().view(), view);
}

/// Delivers a chain plane's verdict on `block` and returns the activities its durable work
/// reported.
pub(crate) fn validate(
    driver: &mut TestDriver,
    block: &Block,
    validity: BlockValidity,
) -> Vec<Activity<MinPk, Digest>> {
    let completion =
        ValidationCompletion::new(driver.machine().generation(), reference(block), validity);
    let step = driver.submit(Input::Validated(completion)).unwrap();
    let step = driver.settle(step, Until::Quiesce);
    persist_all(driver, step)
}
