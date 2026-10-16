//! The local producer: one build every `theta` while the flow bound admits it, the pipeline of
//! builds, custody, and signing, one header per height across crashes, and empty payloads.

use crate::{
    multimmit::{
        machine::{
            ProductionHolds,
            capability::{AppJob, BuildJob, Capabilities, Capability, CustodyJob},
            durability::{Change, DurableEffect, DurableJob, Publication, SignRequest},
            input::{BuildCompletion, CustodyCompletion, Input, Step, StepStatus, TimerFamily},
            testing::{
                CapabilitiesExt as _, Drive as _, SymbolicPersistence, SymbolicSigner, Until,
                fixtures::{
                    TestDriver, built_body, committee, digest, started, validator,
                },
            },
            view::timing::millis,
        },
        mocks::Committee,
        types::{Artifact, BlockRef, ChainId, TransactionBlockHeader},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};

/// The chain validator 0 produces.
const OWN: ChainId = ChainId::new(0);

/// Returns the builds among `capabilities`.
fn builds(capabilities: &[Capability<MinPk, Digest>]) -> Vec<BuildJob<Digest>> {
    capabilities
        .iter()
        .filter_map(|capability| match capability {
            Capability::Application(AppJob::Build(job)) => Some(*job),
            _ => None,
        })
        .collect()
}

/// Returns the custody requests among `capabilities`.
fn custodies(capabilities: &[Capability<MinPk, Digest>]) -> Vec<CustodyJob<Digest>> {
    capabilities
        .iter()
        .filter_map(|capability| match capability {
            Capability::Application(AppJob::Custody(job)) => Some(job.clone()),
            _ => None,
        })
        .collect()
}

/// Returns the released header signing jobs among `capabilities`, with the headers they sign.
fn header_signings(
    capabilities: &[Capability<MinPk, Digest>],
) -> Vec<(DurableJob<MinPk, Digest>, TransactionBlockHeader<Digest>)> {
    capabilities
        .released_signing()
        .into_iter()
        .filter_map(|job| match job.request() {
            DurableEffect::Sign(effect) => match effect.requests() {
                [SignRequest::TransactionBlock(header)] => Some((job.clone(), header.clone())),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Fires the production deadline a start arms and returns the build it starts.
fn first_build(driver: &mut TestDriver) -> BuildJob<Digest> {
    assert_eq!(
        driver.clock().deadline(TimerFamily::Production),
        Some(driver.now()),
        "a started producer builds at once"
    );
    let ticks = driver.advance(0).unwrap();
    let [job] = builds(
        &ticks
            .into_iter()
            .flat_map(Step::into_capabilities)
            .collect::<Vec<_>>(),
    )[..] else {
        panic!("the deadline starts one build");
    };
    job
}

/// Completes `job` with the body the symbolic application builds, returning the step.
fn complete_build(driver: &mut TestDriver, job: BuildJob<Digest>) -> Step<MinPk, Digest> {
    let body = built_body(job.parent().digest());
    driver
        .submit(Input::BlockBuilt(BuildCompletion::new(
            job.issued(),
            job.parent(),
            Some(body),
        )))
        .unwrap()
}

/// Returns the build among `capabilities`, or else the build the armed production deadline starts
/// once the clock reaches it, or `None` when neither starts one.
fn next_build(
    driver: &mut TestDriver,
    capabilities: &[Capability<MinPk, Digest>],
) -> Option<BuildJob<Digest>> {
    match builds(capabilities)[..] {
        [job] => return Some(job),
        [] => {}
        _ => panic!("one build at a time"),
    }
    let deadline = driver.clock().deadline(TimerFamily::Production)?;
    let ticks = driver
        .advance(deadline.millis().saturating_sub(driver.now().millis()))
        .unwrap();
    match builds(
        &ticks
            .into_iter()
            .flat_map(Step::into_capabilities)
            .collect::<Vec<_>>(),
    )[..]
    {
        [job] => Some(job),
        [] => None,
        _ => panic!("one build at a time"),
    }
}

/// Completes builds from `job` on for as long as the producer starts another, each at its slot,
/// returning the custody requests they issued in height order.
fn build_until_stopped(driver: &mut TestDriver, job: BuildJob<Digest>) -> Vec<CustodyJob<Digest>> {
    let mut job = Some(job);
    let mut requested = Vec::new();
    while let Some(current) = job.take() {
        let built = complete_build(driver, current);
        let [custody] = &custodies(built.capabilities())[..] else {
            panic!("a built body enters custody");
        };
        requested.push(custody.clone());
        if let Some(next) = next_build(driver, built.capabilities()) {
            assert_eq!(
                next.parent(),
                custody.header().block_ref::<Sha256>(),
                "the next build extends the block just built, before its custody"
            );
            job = Some(next);
        }
    }
    requested
}

/// Completes the custody `job` and returns the step, folded until it carries its barrier.
fn complete_custody(driver: &mut TestDriver, job: &CustodyJob<Digest>) -> Step<MinPk, Digest> {
    let custodied = driver
        .submit(Input::BlockCustodied(CustodyCompletion::new(
            job.issued(),
            job.header().clone(),
        )))
        .unwrap();
    driver.settle(custodied, Until::Persist)
}

/// Signs, publishes, and persists everything `capabilities` lead to as validator 0, and returns
/// the capabilities left unhandled.
fn sign_all(
    driver: &mut TestDriver,
    committee: &Committee<MinPk>,
    capabilities: impl IntoIterator<Item = Capability<MinPk, Digest>>,
) -> Capabilities<MinPk, Digest> {
    let mut executor = (
        SymbolicSigner::new(committee.signers[0].clone()),
        SymbolicPersistence,
    );
    driver.drain(&mut executor, capabilities)
}

/// Returns the own chain's accepted height.
fn accepted(driver: &TestDriver) -> Height {
    driver.inspect().chain_progress()[OWN.index()].accepted()
}

/// Returns the heights of the own headers the outbox still publishes.
fn published_heights(driver: &TestDriver) -> Vec<Height> {
    driver
        .machine()
        .durable
        .state
        .outbox
        .values()
        .flat_map(|entry| match entry.publication() {
            Publication::Broadcast(artifacts) => artifacts
                .iter()
                .filter_map(|artifact| match artifact.as_ref() {
                    Artifact::TransactionBlock(block) => Some(block.header().height()),
                    _ => None,
                })
                .collect(),
            Publication::Propose(_) => Vec::new(),
        })
        .collect()
}

/// Returns `committee`'s tips with the own chain's replaced by `tip`.
fn with_own_tip(committee: &Committee<MinPk>, tip: BlockRef<Digest>) -> Vec<BlockRef<Digest>> {
    let mut tips = committee.genesis().tips().to_vec();
    tips[OWN.index()] = tip;
    tips
}

#[test]
fn builds_are_requested_every_theta_up_to_the_flow_bound() {
    let committee = committee(60);
    let mut driver = started(&committee, validator(0));
    let flow = u64::from(committee.codec().window().flow());
    let pace = millis(driver.machine().profile().tuning().production_interval);

    // Builds follow each other every theta, each extending the previous one before its custody,
    // until the next height would lie more than D above h* and the final height.
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);
    assert_eq!(requested.len() as u64, flow);
    assert_eq!(driver.now().millis(), (flow - 1) * pace);
    assert_eq!(
        driver.machine().durable.state.produced,
        Height::zero(),
        "nothing is signed before its custody"
    );
    assert!(
        driver.clock().deadline(TimerFamily::Production).is_none(),
        "no production deadline is armed"
    );

    for job in &requested {
        let reserved = complete_custody(&mut driver, job);
        sign_all(&mut driver, &committee, reserved.into_capabilities());
    }
    assert_eq!(accepted(&driver).get(), flow);
    let idle = driver.settle(Step::from(StepStatus::Accepted), Until::Quiesce);
    assert!(builds(idle.capabilities()).is_empty(), "the flow bound holds");
}

/// Completes `job` `after` milliseconds later and returns when the next build starts, with it.
fn build_after(
    driver: &mut TestDriver,
    job: BuildJob<Digest>,
    after: u64,
) -> (u64, BuildJob<Digest>) {
    driver.advance(after).unwrap();
    let built = complete_build(driver, job);
    let next = next_build(driver, built.capabilities()).expect("the next build starts");
    (driver.now().millis(), next)
}

#[test]
fn every_build_is_issued_theta_after_the_previous_builds_slot() {
    let committee = committee(68);
    let mut driver = started(&committee, validator(0));
    let pace = millis(driver.machine().profile().tuning().production_interval);
    assert!(pace > 2);

    // The first build after a start is issued at once, the next one theta after it however soon
    // the first returns.
    let first = first_build(&mut driver);
    let (at, second) = build_after(&mut driver, first, 0);
    assert_eq!(at, pace);

    // A build returned after the next slot is followed at once, and the slot it was due at
    // stands, so a slow application does not stretch the pace.
    let (at, third) = build_after(&mut driver, second, pace + 1);
    assert_eq!(at, 2 * pace + 1);
    let (at, fourth) = build_after(&mut driver, third, 0);
    assert_eq!(at, 3 * pace);

    // A producer held up for longer than theta resumes one block per theta, never with a burst
    // of slots already past.
    let (at, fifth) = build_after(&mut driver, fourth, 10 * pace);
    assert_eq!(at, 13 * pace);
    let (at, _) = build_after(&mut driver, fifth, 0);
    assert_eq!(at, 14 * pace);
}

#[test]
fn a_rising_final_height_releases_the_next_window() {
    let committee = committee(61);
    let mut driver = started(&committee, validator(0));
    let flow = u64::from(committee.codec().window().flow());
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);
    let mut headers = Vec::new();
    for job in &requested {
        headers.push(job.header().block_ref::<Sha256>());
        let reserved = complete_custody(&mut driver, job);
        sign_all(&mut driver, &committee, reserved.into_capabilities());
    }

    // Two own blocks become final: the producer may build two heights further.
    driver
        .machine_mut()
        .finalize_chains(&with_own_tip(&committee, headers[1]));
    let woken = driver.settle(Step::from(StepStatus::Accepted), Until::Quiesce);
    let next = next_build(&mut driver, woken.capabilities()).expect("the producer builds again");
    assert_eq!(next.parent(), *headers.last().unwrap());
    let requested = build_until_stopped(&mut driver, next);
    assert_eq!(requested.len(), 2);
    assert_eq!(
        requested.last().unwrap().header().height().get(),
        2 + flow,
        "production stops D above the new final height"
    );
}

#[test]
fn time_held_at_the_flow_bound_counts_from_the_missed_slot_to_the_release() {
    let committee = committee(69);
    let mut driver = started(&committee, validator(0));
    let flow = u64::from(committee.codec().window().flow());
    let pace = millis(driver.machine().profile().tuning().production_interval);
    let holds = |driver: &TestDriver| driver.machine().progress().production_holds;

    // The flow bound is reached by (D - 1) theta, and the next build would have been due at
    // D theta.
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);
    assert_eq!(driver.now().millis(), (flow - 1) * pace);
    let mut headers = Vec::new();
    for job in &requested {
        headers.push(job.header().block_ref::<Sha256>());
        let reserved = complete_custody(&mut driver, job);
        sign_all(&mut driver, &committee, reserved.into_capabilities());
    }
    assert_eq!(
        holds(&driver),
        ProductionHolds::default(),
        "a hold is recorded when it ends"
    );

    // Finality releases the producer 3 theta after its missed slot.
    driver.advance(4 * pace).unwrap();
    driver
        .machine_mut()
        .finalize_chains(&with_own_tip(&committee, headers[0]));
    let woken = driver.settle(Step::from(StepStatus::Accepted), Until::Quiesce);
    assert!(next_build(&mut driver, woken.capabilities()).is_some());
    assert_eq!(
        holds(&driver),
        ProductionHolds {
            millis: 3 * pace,
            holds: 1,
        }
    );
}

#[test]
fn h_star_releases_the_flow_bound_and_d_later_productions_end_own_header_publication() {
    let committee = committee(62);
    let flow = u64::from(committee.codec().window().flow());
    let mut driver = started(&committee, validator(0));

    // The producer runs D above h* and its final height.
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);
    assert_eq!(requested.len() as u64, flow);
    let mut headers = Vec::new();
    for job in &requested {
        headers.push(job.header().block_ref::<Sha256>());
        let reserved = complete_custody(&mut driver, job);
        sign_all(&mut driver, &committee, reserved.into_capabilities());
    }
    assert_eq!(
        published_heights(&driver),
        (1..=flow).map(Height::new).collect::<Vec<_>>(),
        "no header reached the height quorum yet"
    );

    // n - 2f endorsers of the first own header raise h*, releasing height D + 1.
    let now = driver.now();
    for signer in 0..committee.codec().height_quorum() as u32 {
        driver.machine_mut().note_endorsement(
            Participant::new(signer),
            View::new(1),
            headers[0],
            now,
            now,
        );
    }
    let woken = driver.settle(Step::from(StepStatus::Accepted), Until::Quiesce);
    let next = next_build(&mut driver, woken.capabilities()).expect("the producer builds again");
    let requested = build_until_stopped(&mut driver, next);
    assert_eq!(requested.len(), 1);
    for job in &requested {
        let reserved = complete_custody(&mut driver, job);
        sign_all(&mut driver, &committee, reserved.into_capabilities());
    }
    assert_eq!(driver.machine().durable.state.produced.get(), flow + 1);

    // Signing height D + 1 shows the first header reached the quorum, ending its publication.
    assert_eq!(
        published_heights(&driver),
        (2..=flow + 1).map(Height::new).collect::<Vec<_>>()
    );
}

#[test]
fn signatures_are_reserved_over_the_custodied_prefix_in_one_barrier() {
    let committee = committee(63);
    let mut driver = started(&committee, validator(0));
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);
    let [one, two, three, ..] = &requested[..] else {
        panic!("at least three builds are in flight");
    };

    // Custody of later blocks completes first: nothing is signed above an uncustodied block.
    for job in [three, two] {
        let custodied = complete_custody(&mut driver, job);
        assert!(header_signings(custodied.capabilities()).is_empty());
        assert!(custodied.journals().is_empty());
    }
    assert_eq!(driver.machine().durable.state.produced, Height::zero());

    // The lowest custody releases all three reservations, staged in one journal barrier.
    let reserved = complete_custody(&mut driver, one);
    let signed = header_signings(reserved.capabilities())
        .into_iter()
        .map(|(_, header)| header)
        .collect::<Vec<_>>();
    assert_eq!(
        signed,
        vec![
            one.header().clone(),
            two.header().clone(),
            three.header().clone()
        ]
    );
    let barrier = reserved.persist_job();
    let reservations = barrier
        .events()
        .iter()
        .filter(|event| matches!(event.change(), Change::OutboxQueued { .. }))
        .count();
    assert_eq!(reservations, 3);
    assert_eq!(driver.machine().durable.state.produced, Height::new(3));
}

#[test]
fn own_headers_signed_out_of_order_are_accepted_in_height_order() {
    let committee = committee(64);
    let mut driver = started(&committee, validator(0));
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);
    let [one, two, ..] = &requested[..] else {
        panic!("two builds are in flight");
    };
    complete_custody(&mut driver, two);
    let reserved = complete_custody(&mut driver, one);
    let barrier = reserved.persist_job();
    let signings = header_signings(reserved.capabilities());
    let acknowledged = driver.persist(&barrier, Until::Quiesce);
    sign_all(&mut driver, &committee, acknowledged.into_capabilities());

    // The second header's signature completes first: it waits for the first.
    let mut signer = SymbolicSigner::new(committee.signers[0].clone());
    let second = driver
        .execute(&mut signer, &Capability::Released(signings[1].0.clone()))
        .unwrap()
        .flatten()
        .expect("the signature completes");
    let pending = driver.settle(second, Until::Quiesce);
    sign_all(&mut driver, &committee, pending.into_capabilities());
    assert_eq!(accepted(&driver), Height::zero());

    let first = driver
        .execute(&mut signer, &Capability::Released(signings[0].0.clone()))
        .unwrap()
        .flatten()
        .expect("the signature completes");
    let accepting = driver.settle(first, Until::Quiesce);
    sign_all(&mut driver, &committee, accepting.into_capabilities());
    assert_eq!(accepted(&driver), Height::new(2));
}

#[test]
fn a_reserved_header_survives_a_crash_and_its_height_is_never_signed_again() {
    let committee = committee(65);
    let mut driver = started(&committee, validator(0));
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);

    // A reservation that never reached the journal is forgotten: the height is built again.
    let lost = complete_custody(&mut driver, &requested[0]);
    let [(_, header)] = &header_signings(lost.capabilities())[..] else {
        panic!("one header is reserved");
    };
    let header = header.clone();
    let recovered = driver.crash_and_restore().unwrap();
    driver.drain(&mut SymbolicPersistence, recovered.into_capabilities());
    assert_eq!(driver.machine().durable.state.produced, Height::zero());
    let restarted = first_build(&mut driver);
    let rebuilt = build_until_stopped(&mut driver, restarted);
    assert_eq!(rebuilt[0].header(), &header);

    // A durable reservation survives: recovery releases the same signature, and the producer
    // builds above the reserved header without signing its height again.
    let reserved = complete_custody(&mut driver, &rebuilt[0]);
    driver.persist(&reserved.persist_job(), Until::Step);
    let recovered = driver.crash_and_restore().unwrap();
    let acknowledged = driver.persist(&recovered.persist_job(), Until::Step);
    let [(_, released)] = &header_signings(acknowledged.capabilities())[..] else {
        panic!("recovery releases the reserved signature once");
    };
    assert_eq!(released, &header);
    let restarted = first_build(&mut driver);
    let resumed = build_until_stopped(&mut driver, restarted);
    assert_eq!(
        resumed[0].header().parent_ref(),
        header.block_ref::<Sha256>()
    );
    let unhandled = sign_all(&mut driver, &committee, acknowledged.into_capabilities());
    assert!(builds(&unhandled).is_empty());
    assert_eq!(accepted(&driver), Height::new(1));
}

#[test]
fn a_signed_header_above_a_reserved_one_waits_for_it_across_a_crash() {
    let committee = committee(66);
    let mut driver = started(&committee, validator(0));
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);
    complete_custody(&mut driver, &requested[1]);
    let reserved = complete_custody(&mut driver, &requested[0]);
    let signings = header_signings(reserved.capabilities());
    let acknowledged = driver.persist(&reserved.persist_job(), Until::Quiesce);
    sign_all(&mut driver, &committee, acknowledged.into_capabilities());

    // Only the second header's signature completes and becomes durable before the crash.
    let mut signer = SymbolicSigner::new(committee.signers[0].clone());
    let second = driver
        .execute(&mut signer, &Capability::Released(signings[1].0.clone()))
        .unwrap()
        .flatten()
        .expect("the signature completes");
    let signed = driver.settle(second, Until::Persist);
    driver.persist(&signed.persist_job(), Until::Step);

    let recovered = driver.crash_and_restore().unwrap();
    let acknowledged = driver.persist(&recovered.persist_job(), Until::Step);
    assert_eq!(accepted(&driver), Height::zero());
    let released = header_signings(acknowledged.capabilities())
        .into_iter()
        .map(|(_, header)| header)
        .collect::<Vec<_>>();
    assert_eq!(released, vec![requested[0].header().clone()]);
    sign_all(&mut driver, &committee, acknowledged.into_capabilities());
    assert_eq!(accepted(&driver), Height::new(2));
}

#[test]
fn empty_payloads_take_a_height_and_a_declined_build_retries_after_a_vote_interval() {
    let committee = committee(67);
    let mut driver = started(&committee, validator(0));
    let empty = digest(b"empty");
    let job = first_build(&mut driver);
    let built = driver
        .submit(Input::BlockBuilt(BuildCompletion::new(
            job.issued(),
            job.parent(),
            Some(empty),
        )))
        .unwrap();
    let [custody] = &custodies(built.capabilities())[..] else {
        panic!("a built body enters custody before signing");
    };
    assert_eq!(custody.header().body_digest(), empty);
    assert_eq!(custody.header().height(), Height::new(1));
    let next = next_build(&mut driver, built.capabilities()).expect("the next build starts");
    let slot = driver.now();

    // A build that produced nothing takes no height and is retried a vote interval later, or at
    // the next slot if that is later still.
    let declined = driver
        .submit(Input::BlockBuilt(BuildCompletion::new(
            next.issued(),
            next.parent(),
            None,
        )))
        .unwrap();
    assert!(builds(declined.capabilities()).is_empty());
    let interval = millis(driver.machine().profile().tuning().vote_interval);
    let pace = millis(driver.machine().profile().tuning().production_interval);
    let retry_at = driver
        .now()
        .saturating_add(interval)
        .max(slot.saturating_add(pace));
    assert_eq!(
        driver.clock().deadline(TimerFamily::Production),
        Some(retry_at)
    );
    let reserved = complete_custody(&mut driver, custody);
    let unhandled = sign_all(&mut driver, &committee, reserved.into_capabilities());
    assert!(builds(&unhandled).is_empty(), "the deferral holds");
    let ticks = driver
        .advance(retry_at.millis() - driver.now().millis())
        .unwrap();
    let [retry] = builds(
        &ticks
            .into_iter()
            .flat_map(Step::into_capabilities)
            .collect::<Vec<_>>(),
    )[..] else {
        panic!("the deadline starts one build");
    };
    assert_eq!(retry.parent(), custody.header().block_ref::<Sha256>());
}

#[test]
fn a_restart_recalls_every_own_header_still_reserved_or_published() {
    let committee = committee(68);
    let mut driver = started(&committee, validator(0));
    let first = first_build(&mut driver);
    let requested = build_until_stopped(&mut driver, first);
    complete_custody(&mut driver, &requested[1]);
    let reserved = complete_custody(&mut driver, &requested[0]);
    let signings = header_signings(reserved.capabilities());
    let acknowledged = driver.persist(&reserved.persist_job(), Until::Quiesce);
    sign_all(&mut driver, &committee, acknowledged.into_capabilities());

    // The first header is signed and published; the second is still reserved.
    let mut signer = SymbolicSigner::new(committee.signers[0].clone());
    let signed = driver
        .execute(&mut signer, &Capability::Released(signings[0].0.clone()))
        .unwrap()
        .flatten()
        .expect("the signature completes");
    let signed = driver.settle(signed, Until::Persist);
    driver.persist(&signed.persist_job(), Until::Step);

    // A restart loses the relay's staged bodies, so both headers are recalled, which lets the
    // relay serve their bodies when the publications are retried.
    let recovered = driver.crash_and_restore().unwrap();
    let acknowledged = driver.persist(&recovered.persist_job(), Until::Step);
    let mut recalled = recovered
        .capabilities()
        .iter()
        .chain(acknowledged.capabilities())
        .filter_map(|capability| match capability {
            Capability::Application(AppJob::Recall(header)) => Some(header.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    recalled.sort_by_key(TransactionBlockHeader::height);
    assert_eq!(
        recalled,
        vec![requested[0].header().clone(), requested[1].header().clone()]
    );
    assert!(custodies(recovered.capabilities()).is_empty());
}
