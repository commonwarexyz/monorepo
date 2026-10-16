//! Retrieval: a V-QC waits for its missing parent chain, which is requested by identifier; a
//! restart requests the leader block this node voted for to restore its base, and holds the parent
//! chain of the V-QC it entered the current view on from durable state alone; a dependency
//! refused a request slot is requested once one frees, and a retrieval whose result is not
//! admitted is requested again while an artifact waits on it; vote updates filling the request
//! table never hold back the parent V-QC a node behind its peers catches up through.

use crate::{
    multimmit::{
        config::{Profile, ResourceLimits, Role, Tuning},
        machine::{
            capability::{Capability, ResolverCommand},
            input::{Input, ObservationStatus, Rejection, StepStatus},
            resolution::{ResolutionCompletion, ResolutionJob, RetrievalKey},
            testing::{
                CapabilitiesExt as _, Drive as _, Driver, SymbolicPersistence, cohort,
                fixtures::{
                    TestDriver, committee, deliver, enter_next_view, observe, profile, started,
                    started_with, validator, vqc_above,
                },
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{Artifact, LeaderBlock},
    },
    types::{Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::num::NonZeroUsize;

const ONE: View = View::new(1);
const TWO: View = View::new(2);

/// Returns the jobs `capabilities` issue to the resolver.
fn jobs(capabilities: &[Capability<MinPk, Digest>]) -> Vec<ResolutionJob<Digest>> {
    capabilities
        .iter()
        .filter_map(|capability| match capability {
            Capability::Resolver(ResolverCommand::Resolve(job)) => Some(*job),
            _ => None,
        })
        .collect()
}

/// Returns the keys `capabilities` request from the resolver.
fn requested(capabilities: &[Capability<MinPk, Digest>]) -> Vec<RetrievalKey<Digest>> {
    jobs(capabilities)
        .into_iter()
        .map(ResolutionJob::key)
        .collect()
}

/// Returns validator zero's profile in `committee` with at most `requests` retrievals and
/// `verifications` verification jobs outstanding.
fn bounded(committee: &Committee<MinPk>, requests: usize, verifications: usize) -> Profile<Digest> {
    let profile = profile(committee, validator(0));
    let resources = profile.resources();
    let nonzero = |value| NonZeroUsize::new(value).unwrap();
    let resources = ResourceLimits::new(
        nonzero(resources.max_artifact_bytes()),
        nonzero(resources.max_cached_artifacts()),
        nonzero(resources.max_verification_batch()),
        nonzero(verifications),
        resources.max_future_view_distance(),
        nonzero(resources.max_future_artifacts()),
        nonzero(requests),
        nonzero(resources.max_outbox_effects()),
        nonzero(resources.max_forwarded_certificates()),
    );
    Profile::with_limits(
        profile.protocol().clone(),
        profile.role(),
        Tuning::default(),
        resources,
    )
    .unwrap()
}

/// Returns `signer`'s pre-vote update `seq` of view one, naming no chain, and the key that names
/// it.
fn pre_vote(
    committee: &Committee<MinPk>,
    signer: u32,
    seq: u32,
) -> (Artifact<MinPk, Digest>, RetrievalKey<Digest>) {
    let signer = Participant::new(signer);
    let content = committee.content(ONE, None, false, committee.genesis_endorsement());
    let update = committee.update(signer, &content, committee.genesis().tips(), seq);
    let key = RetrievalKey::Update { signer, view: ONE };
    (Artifact::Update(update), key)
}

#[test]
fn a_dependency_refused_a_request_slot_is_requested_once_one_frees() {
    let committee = committee(223);
    let mut driver = started_with(bounded(&committee, 2, 8));
    let (two, first) = pre_vote(&committee, 1, 2);
    let parked = [1, 2, 3].map(|signer| pre_vote(&committee, signer, 3).0);
    let [_, second, third] = [1, 2, 3].map(|signer| pre_vote(&committee, signer, 3).1);

    // Three senders' updates park on their votes; two requests fill the table.
    let step = driver.submit(cohort::<Sha256, _>(parked.to_vec())).unwrap();
    assert_eq!(requested(step.effects()), vec![first, second]);

    // The first sender's update two arrives and frees its request: the vote of the sender parked
    // without one is requested.
    let step = observe(&mut driver, vec![two]);
    assert_eq!(requested(step.effects()), vec![third]);
}

#[test]
fn vote_updates_filling_the_request_table_do_not_hold_back_a_parent_vqc() {
    let committee = committee(225);
    let genesis = HeldVqc::genesis(committee.genesis());
    let tips = committee.genesis().tips().to_vec();
    let first = vqc_above(&committee, &genesis, false, tips.clone(), &[]);
    let held = enter_next_view(&mut started(&committee, validator(0)), first.clone());
    let second = vqc_above(&committee, &held, false, tips, &[]);
    let mut driver = started_with(bounded(&committee, 2, 8));

    // Updates encoded against earlier ones this node never saw fill the request table.
    let parked = [1, 2, 3].map(|signer| pre_vote(&committee, signer, 3).0);
    let step = driver.submit(cohort::<Sha256, _>(parked.to_vec())).unwrap();
    assert_eq!(requested(step.effects()).len(), 2);

    // The V-QC of a view this node missed still has its parent requested, and the node catches
    // up through it.
    let step = observe(&mut driver, vec![Artifact::Vqc(second)]);
    assert_eq!(
        requested(step.effects()),
        vec![RetrievalKey::Vqc(first.id::<Sha256>())]
    );
    deliver(&mut driver, vec![Artifact::Vqc(first)]);
    assert_eq!(driver.inspect().view(), View::new(3));
}

#[test]
fn a_retrieval_whose_result_is_not_admitted_is_requested_again() {
    let committee = committee(224);
    let mut driver = started_with(bounded(&committee, 8, 1));
    let (two, key) = pre_vote(&committee, 1, 2);
    let step = driver
        .submit(cohort::<Sha256, _>(vec![pre_vote(&committee, 1, 3).0]))
        .unwrap();
    let [job] = jobs(step.effects())[..] else {
        panic!("the parked update requests its sender's vote");
    };
    assert_eq!(job.key(), key);
    // An update of another sender occupies the only verification job.
    let content = committee.content(ONE, None, false, committee.genesis_endorsement());
    let other = committee.update(Participant::new(2), &content, committee.genesis().tips(), 1);
    driver
        .submit(cohort::<Sha256, _>(vec![Artifact::Update(other)]))
        .unwrap();

    // A result that is not the requested artifact is rejected, and the key requested again.
    let complete = |driver: &mut TestDriver, job, artifact: Artifact<MinPk, Digest>| {
        let identified = artifact.identify::<Sha256>(&mut Vec::new());
        driver
            .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
                job, identified,
            )))
            .unwrap()
    };
    let step = complete(&mut driver, job, pre_vote(&committee, 3, 4).0);
    assert!(step.effects().iter().any(|capability| matches!(
        capability,
        Capability::Resolver(ResolverCommand::Reject(rejected)) if *rejected == job
    )));
    let [retry] = jobs(step.effects())[..] else {
        panic!("the key is requested again");
    };
    assert_eq!(retry.key(), key);

    // The requested artifact, refused while verification is full, is requested again.
    let step = complete(&mut driver, retry, two);
    assert_eq!(
        *step.status(),
        StepStatus::ResolutionCompleted {
            admission: ObservationStatus::Rejected(Rejection::VerificationJobsFull)
        }
    );
    assert!(step.effects().iter().any(|capability| matches!(
        capability,
        Capability::Resolver(ResolverCommand::Cancel(cancelled)) if *cancelled == retry
    )));
    assert_eq!(requested(step.effects()), vec![key]);
}

/// Returns a driver for a validator that does not lead view two, started in view one.
fn follower(committee: &Committee<MinPk>) -> TestDriver {
    let leader = committee.config.leader(TWO);
    let own = Participant::new((leader.get() + 1) % committee.codec().participants() as u32);
    let mut driver = Driver::new(profile(committee, Role::Validator(own)));
    let start = driver.submit(Input::Start).unwrap();
    driver.drain(&mut SymbolicPersistence, start.into_capabilities());
    driver
}

#[test]
fn a_vqc_waits_for_its_missing_parent_chain() {
    let committee = committee(220);
    let genesis = HeldVqc::genesis(committee.genesis());
    let tips = committee.genesis().tips().to_vec();
    let first = vqc_above(&committee, &genesis, false, tips.clone(), &[]);
    let held = enter_next_view(&mut started(&committee, validator(0)), first.clone());
    let second = vqc_above(&committee, &held, false, tips, &[]);

    // The V-QC of view two waits for its parent, which is requested by identifier.
    let mut driver = started(&committee, validator(0));
    let step = observe(&mut driver, vec![Artifact::Vqc(second.clone())]);
    assert_eq!(
        requested(step.effects()),
        vec![RetrievalKey::Vqc(first.id::<Sha256>())]
    );
    assert_eq!(driver.inspect().waiting_artifacts(), 1);
    assert!(driver.machine().held_vqc(&second.id::<Sha256>()).is_none());

    // The parent arrives: both are held and the node enters view three.
    deliver(&mut driver, vec![Artifact::Vqc(first)]);
    assert!(driver.machine().held_vqc(&second.id::<Sha256>()).is_some());
    assert_eq!(driver.inspect().view(), View::new(3));
}

#[test]
fn a_restart_requests_the_leader_block_it_voted_for() {
    let committee = committee(221);
    let genesis = HeldVqc::genesis(committee.genesis());
    let mut driver = follower(&committee);
    let one = enter_next_view(
        &mut driver,
        vqc_above(
            &committee,
            &genesis,
            false,
            committee.genesis().tips().to_vec(),
            &[],
        ),
    );
    let block = LeaderBlock::new(committee.round(TWO), one.id, one.history).unwrap();
    let signed = committee.signers[usize::from(committee.config.leader(TWO))]
        .sign_leader_block(block)
        .unwrap();
    deliver(&mut driver, vec![Artifact::LeaderBlock(signed.clone())]);
    assert!(driver.machine().notarised(TWO).is_some());
    assert_eq!(
        driver.machine().notarised_base(TWO),
        Some(one.tips.as_ref())
    );

    // The base of the block it voted for is volatile: a restart requests the block again, and
    // recording it restores the base.
    let recovered = driver.crash_and_restore().unwrap();
    assert_eq!(
        requested(recovered.effects()),
        vec![RetrievalKey::LeaderBlock(TWO)]
    );
    driver.drain_persisting(recovered);
    assert_eq!(driver.machine().notarised_base(TWO), None);
    deliver(&mut driver, vec![Artifact::LeaderBlock(signed)]);
    assert_eq!(
        driver.machine().notarised_base(TWO),
        Some(one.tips.as_ref())
    );
}

#[test]
fn a_restart_holds_the_parent_chain_of_the_vqc_it_entered_on_without_retrieval() {
    let committee = committee(222);
    let genesis = HeldVqc::genesis(committee.genesis());
    let tips = committee.genesis().tips().to_vec();
    let three = View::new(3);
    let leader = committee.config.leader(three);
    let own = Participant::new((leader.get() + 1) % committee.codec().participants() as u32);
    let mut driver = Driver::new(profile(&committee, Role::Validator(own)));
    let start = driver.submit(Input::Start).unwrap();
    driver.drain(&mut SymbolicPersistence, start.into_capabilities());

    // View two is entered on one V-QC of view one and view three on a V-QC of view two above
    // another, whose publication ends once view three is entered and which that entry retains.
    enter_next_view(
        &mut driver,
        vqc_above(&committee, &genesis, false, tips.clone(), &[]),
    );
    let content = committee.content(View::new(1), None, true, committee.genesis_endorsement());
    let contents = (0..5)
        .map(|signer| (Participant::new(signer), content.clone()))
        .collect();
    let parent = committee.vqc_from(genesis.id, contents, Vec::new());
    deliver(&mut driver, vec![Artifact::Vqc(parent.clone())]);
    let held = driver.machine().held_vqc(&parent.id::<Sha256>()).unwrap();
    let entered = enter_next_view(&mut driver, vqc_above(&committee, &held, true, tips, &[]));

    // After a restart the entry V-QC is held again on that parent without any retrieval, and
    // proposals naming it are valid.
    let recovered = driver.crash_and_restore().unwrap();
    assert!(requested(recovered.effects()).is_empty());
    driver.drain_persisting(recovered);
    assert_eq!(
        driver.machine().held_vqc(&parent.id::<Sha256>()),
        Some(held)
    );
    assert_eq!(
        driver.machine().held_vqc(&entered.id),
        Some(entered.clone())
    );
    let block = LeaderBlock::new(committee.round(three), entered.id, entered.history).unwrap();
    let signed = committee.signers[usize::from(leader)]
        .sign_leader_block(block)
        .unwrap();
    deliver(&mut driver, vec![Artifact::LeaderBlock(signed)]);
    assert!(driver.machine().valid_proposal(three).is_some());
}
