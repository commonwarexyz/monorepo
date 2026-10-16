//! The chain layer: the header store, acceptance in full and by adoption, the height quorum, and
//! the staging of acceptances.

use crate::{
    multimmit::{
        algebra::Ancestry as _,
        config::Role,
        machine::{
            capability::{Capability, ChainCommand},
            durability::{
                Acceptance, Change, ChangeKind, DurableEffect, SignRequest, UpdateRequest,
            },
            input::{
                BlockValidity, Input, ObservationStatus, Rejection, StepStatus,
                ValidationCompletion,
            },
            testing::{
                CapabilitiesExt as _, Drive as _, Execution, Executor as _, MachineExt as _,
                SymbolicSigner, Until, cohort,
                fixtures::{
                    Block, TestDriver, block, committee, digest, path, persist_all, produce,
                    quiesce, receive, reference, started, validate, validator,
                },
            },
        },
        types::{Activity, Artifact, BlockRef, ChainId},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::time::Duration;

/// The peer chain the tests accept on.
const CHAIN: ChainId = ChainId::new(1);

/// Records that each of `signers` endorses `tip`, then runs the work it enables and returns
/// the activities it reported.
fn endorse(
    driver: &mut TestDriver,
    signers: &[u32],
    tip: BlockRef<Digest>,
) -> Vec<Activity<MinPk, Digest>> {
    let now = driver.now();
    for signer in signers {
        driver.machine_mut().note_endorsement(
            Participant::new(*signer),
            View::new(1),
            tip,
            now,
            now,
        );
    }
    quiesce(driver)
}

/// Returns the accepted tip height of `chain`, as the chain layer reports it.
fn accepted(driver: &TestDriver, chain: ChainId) -> Height {
    driver.inspect().chain_progress()[chain.index()].accepted()
}

/// Returns the validation commands among `capabilities`.
fn validations(capabilities: &[Capability<MinPk, Digest>]) -> Vec<BlockRef<Digest>> {
    capabilities
        .iter()
        .filter_map(|capability| match capability {
            Capability::Chain(_, ChainCommand::Validate(block)) => Some(reference(block)),
            _ => None,
        })
        .collect()
}

#[test]
fn headers_are_accepted_in_full_in_height_order() {
    let committee = committee(40);
    let mut driver = started(&committee, Role::Observer);
    let blocks = path(&committee, CHAIN, 2);

    // Both headers are buffered and sent to the chain plane at once, the child before its parent.
    let received = receive(&mut driver, &[blocks[1].clone(), blocks[0].clone()]);
    assert_eq!(
        validations(received.capabilities()),
        vec![reference(&blocks[1]), reference(&blocks[0])]
    );

    // A valid child waits for its parent's acceptance.
    assert!(validate(&mut driver, &blocks[1], BlockValidity::Valid).is_empty());
    assert_eq!(accepted(&driver, CHAIN), Height::zero());

    // The parent's verdict accepts both, lowest first, and reports each once it is durable.
    let reported = validate(&mut driver, &blocks[0], BlockValidity::Valid);
    assert_eq!(accepted(&driver, CHAIN), Height::new(2));
    let durable = &driver.machine().durable.state.accepted[CHAIN.index()];
    assert_eq!(
        durable.values().cloned().collect::<Vec<_>>(),
        blocks
            .iter()
            .map(|block| Acceptance::Full(block.clone().into()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        reported,
        blocks
            .iter()
            .map(|block| Activity::HeaderAccepted {
                header: block.header().clone(),
                adopted: None,
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        driver.inspect().cached_artifacts(),
        0,
        "accepted headers leave the artifact store for durable state"
    );
}

#[test]
fn acceptance_reports_wait_for_durability_and_settle_the_plane() {
    let committee = committee(41);
    let mut driver = started(&committee, Role::Observer);
    let blocks = path(&committee, CHAIN, 1);
    receive(&mut driver, &blocks);
    let completion = ValidationCompletion::new(
        driver.machine().generation(),
        reference(&blocks[0]),
        BlockValidity::Valid,
    );
    let step = driver.submit(Input::Validated(completion)).unwrap();
    let staged = driver.settle(step, Until::Persist);
    assert!(
        staged
            .effects()
            .iter()
            .any(|capability| matches!(capability, Capability::Chain(chain, ChainCommand::Accepted(height)) if *chain == CHAIN && *height == Height::new(1))),
        "the plane drops work at or below the accepted tip"
    );
    let job = staged.persist_job();
    assert!(matches!(
        job.events(),
        [event] if matches!(event.change(), Change::Accepted { blocks } if blocks.len() == 1)
    ));
    assert!(
        staged.activities.is_empty(),
        "nothing is reported before it is durable"
    );
    let acknowledged = driver.persist(&job, Until::Step);
    assert!(matches!(
        acknowledged.activities.as_slice(),
        [Activity::HeaderAccepted { adopted: None, .. }]
    ));
}

#[test]
fn acceptance_waits_for_the_height_quorum_within_the_flow_bound() {
    let committee = committee(42);
    let mut driver = started(&committee, Role::Observer);
    let flow = committee.codec().window().flow() as usize;
    let blocks = path(&committee, CHAIN, flow + 1);
    receive(&mut driver, &blocks);
    for block in &blocks {
        validate(&mut driver, block, BlockValidity::Valid);
    }
    assert_eq!(
        accepted(&driver, CHAIN).get(),
        flow as u64,
        "nothing more than D above h* = 0"
    );

    // n - 2f endorsers of the first header raise h* to one, which admits the last header.
    let quorum = committee.codec().height_quorum() as u32;
    endorse(
        &mut driver,
        &(0..quorum - 1).collect::<Vec<_>>(),
        reference(&blocks[0]),
    );
    assert_eq!(
        driver.inspect().chain_progress()[CHAIN.index()].quorum(),
        Height::zero()
    );
    endorse(&mut driver, &[quorum - 1], reference(&blocks[0]));
    assert_eq!(
        driver.inspect().chain_progress()[CHAIN.index()].quorum(),
        Height::new(1)
    );
    assert_eq!(accepted(&driver, CHAIN).get(), flow as u64 + 1);
}

#[test]
fn a_raised_final_height_wakes_acceptance_held_by_the_flow_bound() {
    let committee = committee(55);
    let mut driver = started(&committee, Role::Observer);
    let flow = committee.codec().window().flow() as usize;
    let blocks = path(&committee, CHAIN, flow + 1);
    receive(&mut driver, &blocks);
    for block in &blocks {
        validate(&mut driver, block, BlockValidity::Valid);
    }
    assert_eq!(accepted(&driver, CHAIN).get(), flow as u64);

    // Finalizing the first header lifts the flow bound as the height quorum would.
    let mut tips = committee.genesis().tips().to_vec();
    tips[CHAIN.index()] = reference(&blocks[0]);
    driver.machine_mut().finalize_chains(&tips);
    quiesce(&mut driver);
    assert_eq!(accepted(&driver, CHAIN).get(), flow as u64 + 1);
}

#[test]
fn a_ready_header_held_back_by_the_flow_bound_is_reported_until_accepted() {
    let committee = committee(57);
    let mut driver = started(&committee, Role::Observer);
    let flow = committee.codec().window().flow() as usize;
    let blocks = path(&committee, CHAIN, flow + 2);
    receive(&mut driver, &blocks);
    let held_back = |driver: &TestDriver| driver.machine().components.chain.held_back(CHAIN);
    let refusals = |driver: &TestDriver| driver.machine().progress().refusals.flow;
    for block in &blocks[..flow] {
        validate(&mut driver, block, BlockValidity::Valid);
    }
    // The header above the bound has no verdict yet, so nothing is ready to be held back.
    assert_eq!(accepted(&driver, CHAIN).get(), flow as u64);
    assert!(!held_back(&driver));
    assert_eq!(refusals(&driver), 0);

    validate(&mut driver, &blocks[flow], BlockValidity::Valid);
    assert_eq!(accepted(&driver, CHAIN).get(), flow as u64);
    assert!(held_back(&driver));
    assert_eq!(refusals(&driver), 1);

    // Further acceptance passes over the same held-back height count no new refusal.
    validate(&mut driver, &blocks[flow + 1], BlockValidity::Valid);
    assert!(held_back(&driver));
    assert_eq!(refusals(&driver), 1);

    // Lifting the bound by one height accepts the held header; the next is held back anew.
    let mut tips = committee.genesis().tips().to_vec();
    tips[CHAIN.index()] = reference(&blocks[0]);
    driver.machine_mut().finalize_chains(&tips);
    quiesce(&mut driver);
    assert_eq!(accepted(&driver, CHAIN).get(), flow as u64 + 1);
    assert!(held_back(&driver));
    assert_eq!(refusals(&driver), 2);

    // Once nothing ready is held back, the state clears.
    tips[CHAIN.index()] = reference(&blocks[1]);
    driver.machine_mut().finalize_chains(&tips);
    quiesce(&mut driver);
    assert_eq!(accepted(&driver, CHAIN).get(), flow as u64 + 2);
    assert!(!held_back(&driver));
    assert_eq!(refusals(&driver), 2);
}

#[test]
fn acceptance_stops_d_plus_n_above_the_final_height_however_high_the_height_quorum() {
    let committee = committee(56);
    let mut driver = started(&committee, Role::Observer);
    let window = committee.codec().window();
    let (cap, flow) = (u64::from(window.cap()), u64::from(window.flow()));
    let blocks = path(&committee, CHAIN, window.max_tip_lead() as usize);
    receive(&mut driver, &blocks);
    for block in &blocks {
        validate(&mut driver, block, BlockValidity::Valid);
    }
    assert_eq!(accepted(&driver, CHAIN).get(), flow);
    // The valid header at D + 1 was refused by the flow bound, counted once however many passes
    // re-examined it.
    let refusals = || driver.machine().progress().refusals;
    assert_eq!((refusals().flow, refusals().finality), (1, 0));

    // The validators endorse everything accepted, which raises h* to D. A producer running ahead
    // of finality gains only N more heights: acceptance stops D + N above the final height.
    let quorum = committee.codec().height_quorum() as u32;
    let signers = (0..quorum).collect::<Vec<_>>();
    endorse(&mut driver, &signers, reference(&blocks[flow as usize - 1]));
    assert_eq!(
        driver.inspect().chain_progress()[CHAIN.index()]
            .quorum()
            .get(),
        flow
    );
    assert_eq!(accepted(&driver, CHAIN).get(), flow + cap);
    let refusals = || driver.machine().progress().refusals;
    assert_eq!((refusals().flow, refusals().finality), (1, 1));

    // Each final height raises the bound as far.
    let mut tips = committee.genesis().tips().to_vec();
    tips[CHAIN.index()] = reference(&blocks[cap as usize - 1]);
    driver.machine_mut().finalize_chains(&tips);
    quiesce(&mut driver);
    assert_eq!(accepted(&driver, CHAIN).get(), flow + 2 * cap);
}

#[test]
fn one_header_is_accepted_per_height() {
    let committee = committee(43);
    let mut driver = started(&committee, Role::Observer);
    let genesis = committee.genesis().tips()[CHAIN.index()];
    let first = block(&committee, &genesis, b"first");
    let second = block(&committee, &genesis, b"second");
    receive(&mut driver, &[first.clone(), second.clone()]);
    assert_eq!(driver.inspect().cached_artifacts(), 2);
    validate(&mut driver, &first, BlockValidity::Valid);
    validate(&mut driver, &second, BlockValidity::Valid);
    assert_eq!(accepted(&driver, CHAIN), Height::new(1));
    assert!(matches!(
        driver.machine().durable.state.accepted(CHAIN, Height::new(1)),
        Some(Acceptance::Full(block)) if **block == first
    ));
    assert_eq!(
        driver.inspect().cached_artifacts(),
        0,
        "the competing branch's buffered copy is dropped"
    );

    // A header at or below the accepted tip is no longer buffered.
    let late = block(&committee, &genesis, b"late");
    let observed = driver
        .submit(cohort::<Sha256, _>(vec![Artifact::TransactionBlock(late)]))
        .unwrap();
    assert!(matches!(
        observed.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Rejected(Rejection::TipLead)
    ));
}

#[test]
fn headers_without_a_valid_body_are_adopted_on_alpha_endorsements() {
    let committee = committee(44);
    let mut driver = started(&committee, Role::Observer);
    let alpha = committee.codec().adoption_quorum() as u32;
    let blocks = path(&committee, CHAIN, 2);
    receive(&mut driver, &blocks);
    validate(&mut driver, &blocks[0], BlockValidity::Invalid);
    validate(&mut driver, &blocks[1], BlockValidity::Unavailable);
    assert_eq!(accepted(&driver, CHAIN), Height::zero());

    // One endorser short of alpha adopts nothing; alpha endorsers of the child adopt both.
    endorse(
        &mut driver,
        &(0..alpha - 1).collect::<Vec<_>>(),
        reference(&blocks[1]),
    );
    assert_eq!(accepted(&driver, CHAIN), Height::zero());
    let reported = endorse(&mut driver, &[alpha - 1], reference(&blocks[1]));
    assert_eq!(accepted(&driver, CHAIN), Height::new(2));
    // Each adoption carries the current delay estimate as its body's fetch grace.
    let delta = driver.machine().current_timers().delta;
    assert!(delta > 0);
    let grace = Some(Duration::from_millis(delta));
    assert_eq!(
        reported
            .iter()
            .filter_map(|activity| match activity {
                Activity::HeaderAccepted { header, adopted } => Some((header.clone(), *adopted)),
                _ => None,
            })
            .collect::<Vec<_>>(),
        blocks
            .iter()
            .map(|block| (block.header().clone(), grace))
            .collect::<Vec<_>>()
    );
    let durable = &driver.machine().durable.state.accepted[CHAIN.index()];
    assert!(durable.values().all(Acceptance::adopted));
    assert_eq!(
        durable
            .values()
            .map(|acceptance| acceptance.header().clone())
            .collect::<Vec<_>>(),
        blocks
            .iter()
            .map(|block| block.header().clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_header_accepted_in_full_wins_over_an_adoptable_one_at_its_height() {
    let committee = committee(45);
    let mut driver = started(&committee, Role::Observer);
    let genesis = committee.genesis().tips()[CHAIN.index()];
    let verified = block(&committee, &genesis, b"verified");
    let endorsed = committee.header(&genesis, digest(b"endorsed"));
    let endorsed_ref = endorsed.block_ref::<Sha256>();
    receive(&mut driver, core::slice::from_ref(&verified));
    assert!(driver.machine_mut().hold_header(endorsed));

    // Both become candidates before the next acceptance pass.
    let now = driver.now();
    for signer in 0..committee.codec().adoption_quorum() as u32 {
        driver.machine_mut().note_endorsement(
            Participant::new(signer),
            View::new(1),
            endorsed_ref,
            now,
            now,
        );
    }
    let completion = ValidationCompletion::new(
        driver.machine().generation(),
        reference(&verified),
        BlockValidity::Valid,
    );
    driver.submit(Input::Validated(completion)).unwrap();
    quiesce(&mut driver);
    assert!(matches!(
        driver.machine().durable.state.accepted(CHAIN, Height::new(1)),
        Some(Acceptance::Full(block)) if **block == verified
    ));
}

#[test]
fn endorsements_reach_ancestors_held_after_their_tip() {
    let committee = committee(46);
    let mut driver = started(&committee, Role::Observer);
    let blocks = path(&committee, CHAIN, 3);

    // The top header arrives signed before the middle one is known: its endorsements stop there.
    assert!(driver.machine_mut().hold_header(blocks[0].header().clone()));
    receive(&mut driver, &[blocks[2].clone()]);
    endorse(&mut driver, &[3, 4], reference(&blocks[2]));
    let headers = &driver.machine().chain_layer().headers;
    assert_eq!(
        headers.get(&reference(&blocks[0])).unwrap().endorsements(),
        0
    );
    assert_eq!(accepted(&driver, CHAIN), Height::zero());

    // Rebuilding the middle header passes the endorsements down, which adopts the whole path.
    assert!(driver.machine_mut().hold_header(blocks[1].header().clone()));
    quiesce(&mut driver);
    let headers = &driver.machine().chain_layer().headers;
    assert_eq!(
        headers.get(&reference(&blocks[0])).unwrap().endorsements(),
        2
    );
    assert_eq!(accepted(&driver, CHAIN), Height::new(3));
    assert_eq!(
        headers.ancestor(&reference(&blocks[2]), Height::new(1)),
        Some(reference(&blocks[0]))
    );
    assert_eq!(
        headers.ancestor(&reference(&blocks[2]), Height::zero()),
        Some(committee.genesis().tips()[CHAIN.index()])
    );
}

#[test]
fn endorsements_of_unaccepted_headers_are_signs_of_life() {
    let committee = committee(47);
    let mut driver = started(&committee, Role::Observer);
    let blocks = path(&committee, CHAIN, 1);
    assert!(driver.machine_mut().hold_header(blocks[0].header().clone()));
    let before = driver.machine().chain_layer().last_life(CHAIN);
    driver.advance(10).unwrap();
    endorse(&mut driver, &[0], reference(&blocks[0]));
    let layer = driver.machine().chain_layer();
    assert_eq!(layer.last_life(CHAIN).saturating_since(before), 10);
}

#[test]
fn buffered_headers_are_bounded_by_the_tip_lead_and_the_branches_per_height() {
    let committee = committee(48);
    let mut driver = started(&committee, Role::Observer);
    let lead = committee.codec().window().max_tip_lead() as usize;
    let genesis = committee.genesis().tips()[CHAIN.index()];
    let blocks = path(&committee, CHAIN, lead + 1);
    let branches = [b"a", b"b", b"c"].map(|label| block(&committee, &genesis, label));
    let observed = driver
        .submit(cohort::<Sha256, _>(
            [blocks[lead - 1].clone(), blocks[lead].clone()]
                .into_iter()
                .chain(branches)
                .map(Artifact::TransactionBlock)
                .collect(),
        ))
        .unwrap();
    let StepStatus::Observed(results) = observed.status() else {
        panic!("a cohort is observed");
    };
    let statuses = results
        .iter()
        .map(|result| result.status())
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            ObservationStatus::Scheduled,
            ObservationStatus::Rejected(Rejection::TipLead),
            ObservationStatus::Scheduled,
            ObservationStatus::Scheduled,
            ObservationStatus::Scheduled,
        ],
        "branches are counted once buffered"
    );

    // Once buffered, the per-height branch bound refuses a third branch before verification and
    // drops it after.
    driver.verify(&observed.verify_job(), true, Until::Quiesce);
    assert_eq!(
        driver
            .machine()
            .chain_layer()
            .headers
            .at(CHAIN, Height::new(1))
            .len(),
        2
    );
    let refused = driver
        .submit(cohort::<Sha256, _>(vec![Artifact::TransactionBlock(
            block(&committee, &genesis, b"d"),
        )]))
        .unwrap();
    assert!(matches!(
        refused.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Rejected(Rejection::HeightFull)
    ));
}

#[test]
fn the_header_store_bounds_each_height_and_evicts_unreferenced_headers() {
    let committee = committee(49);
    let mut driver = started(&committee, Role::Observer);
    let genesis = committee.genesis().tips()[CHAIN.index()];
    let participants = committee.codec().participants();
    let headers = (0..=participants)
        .map(|index| committee.header(&genesis, digest(&index.to_be_bytes())))
        .collect::<Vec<_>>();
    for header in &headers {
        assert!(driver.machine_mut().hold_header(header.clone()));
    }
    let held = |driver: &TestDriver| {
        driver
            .machine()
            .chain_layer()
            .headers
            .at(CHAIN, Height::new(1))
            .len()
    };
    assert_eq!(held(&driver), participants + 1);

    // A full height evicts an unendorsed header for a new one.
    let extra = committee.header(&genesis, digest(b"extra"));
    assert!(driver.machine_mut().hold_header(extra));
    assert_eq!(held(&driver), participants + 1);
    assert!(
        driver
            .machine()
            .chain_layer()
            .headers
            .get(&headers[0].block_ref::<Sha256>())
            .is_none()
    );

    // Once every held header is endorsed, nothing is evicted and a new header is refused.
    let now = driver.now();
    for (index, header) in driver
        .machine()
        .chain_layer()
        .headers
        .at(CHAIN, Height::new(1))
        .iter()
        .map(|entry| entry.block())
        .collect::<Vec<_>>()
        .into_iter()
        .enumerate()
    {
        driver.machine_mut().note_endorsement(
            Participant::new(index as u32 % participants as u32),
            View::new(1),
            header,
            now,
            now,
        );
    }
    assert!(!driver.machine_mut().hold_header(headers[0].clone()));

    // A header without a held parent, or more than D + 2N above h*, is not held.
    let gap = committee
        .header(&genesis, digest(b"gap"))
        .block_ref::<Sha256>();
    assert!(
        !driver
            .machine_mut()
            .hold_header(committee.header(&gap, digest(b"orphan")))
    );
    let lead = committee.codec().window().max_tip_lead() as usize;
    let mut parent = committee.genesis().tips()[2];
    let mut path = Vec::new();
    for index in 0..=lead {
        let header = committee.header(&parent, digest(&[0xff, index as u8]));
        parent = header.block_ref::<Sha256>();
        path.push(header);
    }
    let (top, below) = path.split_last().unwrap();
    for header in below {
        assert!(driver.machine_mut().hold_header(header.clone()));
    }
    assert!(!driver.machine_mut().hold_header(top.clone()));

    // Raising the floor drops every header at or below it, and nothing is held there again.
    let layer = &mut driver.machine_mut().components.chain;
    layer.headers.retain_above(CHAIN, Height::new(1));
    assert!(layer.headers.at(CHAIN, Height::new(1)).is_empty());
    assert_eq!(layer.headers.floor(CHAIN), Height::new(1));
    assert!(!driver.machine_mut().hold_header(headers[0].clone()));
}

#[test]
fn rebuilt_branches_never_lock_the_producer_out_of_a_height() {
    let committee = committee(54);
    let mut driver = started(&committee, Role::Observer);
    let genesis = committee.genesis().tips()[CHAIN.index()];
    let participants = committee.codec().participants();
    let held = |driver: &TestDriver, height: u64| {
        driver
            .machine()
            .chain_layer()
            .headers
            .at(CHAIN, Height::new(height))
            .len()
    };

    // Anybody can rebuild unsigned headers from payload hashes: n + 1 two-header branches fill
    // height one, each pinned by a held child but endorsed by nobody.
    for index in 0..=participants {
        let header = committee.header(&genesis, digest(&[0xfe, index as u8]));
        let child = committee.header(&header.block_ref::<Sha256>(), digest(b"child"));
        assert!(driver.machine_mut().hold_header(header));
        assert!(driver.machine_mut().hold_header(child));
    }
    assert_eq!(held(&driver, 1), participants + 1);

    // The producer's header still enters its height, evicting one branch with its child.
    let blocks = path(&committee, CHAIN, 1);
    let received = receive(&mut driver, &blocks);
    assert_eq!(
        validations(received.capabilities()),
        vec![reference(&blocks[0])]
    );
    assert_eq!(held(&driver, 1), participants + 1);
    assert_eq!(held(&driver, 2), participants);

    // Rebuilt headers never evict the producer's.
    for index in 0..=participants {
        let header = committee.header(&genesis, digest(&[0xff, index as u8]));
        assert!(driver.machine_mut().hold_header(header));
    }
    let producer = driver
        .machine()
        .chain_layer()
        .headers
        .get(&reference(&blocks[0]))
        .expect("the producer's header is held");
    assert!(producer.signed.is_some());
    assert_eq!(held(&driver, 2), 0);
}

#[test]
fn acceptances_are_staged_before_an_update_that_could_endorse_them() {
    let committee = committee(50);
    let mut driver = started(&committee, validator(0));
    let reserved = produce(&mut driver);
    let sign = Capability::Released(reserved.released_signing()[0].clone());
    driver.persist(&reserved.persist_job(), Until::Step);
    let mut signer = SymbolicSigner::new(committee.signers[0].clone());
    let Some(Execution::Input(signed)) = signer.execute(&sign, driver.machine().generation())
    else {
        unreachable!("signing completes at once");
    };
    driver.submit(signed).unwrap();

    // Staging the signature accepts the own header at once; its acceptance waits to be staged.
    let staged = driver.poll_with(core::num::NonZeroUsize::MIN).unwrap();
    driver.record(staged.capabilities());
    assert_eq!(accepted(&driver, ChainId::new(0)), Height::new(1));
    assert_eq!(driver.machine().chain_layer().pending().len(), 1);

    // An update reservation follows a flush, so the update's record follows the acceptance.
    driver.machine_mut().flush_acceptances().unwrap();
    assert!(driver.machine().chain_layer().pending().is_empty());
    let content = committee.content(View::new(1), None, false, committee.genesis_endorsement());
    let update = driver
        .machine_mut()
        .reserve_test_effect(DurableEffect::sign(SignRequest::Update(
            UpdateRequest::new(content, 1, Vec::new()),
        )))
        .unwrap();
    driver.record(update.capabilities());
    let events = driver
        .machine()
        .pipeline
        .staged
        .iter()
        .flat_map(|batch| batch.job.events().iter().map(|event| event.change().kind()))
        .collect::<Vec<_>>();
    let accepted_at = events
        .iter()
        .position(|kind| *kind == ChangeKind::Accepted)
        .expect("the acceptance is staged");
    let update_at = events
        .iter()
        .rposition(|kind| *kind == ChangeKind::OutboxQueued)
        .expect("the update is reserved");
    assert!(accepted_at < update_at);
}

#[test]
fn a_restart_rebuilds_the_accepted_paths() {
    let committee = committee(51);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 2);
    receive(&mut driver, &blocks);
    for block in &blocks {
        validate(&mut driver, block, BlockValidity::Valid);
    }

    // The own header is signed, but a crash loses its acceptance before it is staged.
    let reserved = produce(&mut driver);
    let sign = Capability::Released(reserved.released_signing()[0].clone());
    driver.persist(&reserved.persist_job(), Until::Step);
    let mut signer = SymbolicSigner::new(committee.signers[0].clone());
    let Some(Execution::Input(signed)) = signer.execute(&sign, driver.machine().generation())
    else {
        unreachable!("signing completes at once");
    };
    driver.submit(signed).unwrap();
    let staged = driver.poll_with(core::num::NonZeroUsize::MIN).unwrap();
    driver.record(staged.capabilities());
    let job = staged.persist_job();
    assert!(matches!(
        job.events(),
        [event] if matches!(event.change(), Change::SignedArtifacts { .. })
    ));
    driver.persist(&job, Until::Step);
    assert!(driver.machine().durable.state.accepted[0].is_empty());

    let recovered = driver.crash_and_restore().unwrap();
    let mut reported = persist_all(&mut driver, recovered);
    reported.extend(quiesce(&mut driver));
    let accepted_again = reported
        .iter()
        .filter_map(|activity| match activity {
            Activity::HeaderAccepted { header, adopted } => {
                Some((header.block_ref::<Sha256>(), adopted.is_some()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        blocks
            .iter()
            .all(|block| accepted_again.contains(&(reference(block), false))),
        "retained acceptances are reported again: {accepted_again:?}"
    );
    assert_eq!(accepted(&driver, CHAIN), Height::new(2));
    assert_eq!(accepted(&driver, ChainId::new(0)), Height::new(1));
    assert_eq!(driver.machine().durable.state.accepted[0].len(), 1);
    assert_eq!(
        driver
            .machine()
            .chain_layer()
            .headers
            .ancestor(&reference(&blocks[1]), Height::new(1)),
        Some(reference(&blocks[0]))
    );
}

#[test]
fn a_buffered_header_without_its_parent_is_not_linked_until_the_gap_is_held() {
    let committee = committee(53);
    let mut driver = started(&committee, Role::Observer);
    let blocks = path(&committee, CHAIN, 2);
    let linked = |driver: &TestDriver, block: &Block| {
        driver
            .machine()
            .chain_layer()
            .headers
            .get(&reference(block))
            .map(|entry| entry.linked)
    };

    // The second block is buffered, but its ancestry stops at a missing parent.
    receive(&mut driver, std::slice::from_ref(&blocks[1]));
    quiesce(&mut driver);
    assert_eq!(linked(&driver, &blocks[1]), Some(false));

    // Holding the parent links both to genesis.
    receive(&mut driver, std::slice::from_ref(&blocks[0]));
    quiesce(&mut driver);
    assert_eq!(linked(&driver, &blocks[0]), Some(true));
    assert_eq!(linked(&driver, &blocks[1]), Some(true));
}
