//! Forwarding and view entry: every new V-QC is forwarded once, with the V-QCs on its parent chain
//! not forwarded before; the final vote precedes the entry; an assembled V-QC is created,
//! forwarded, and entered; assembly takes the earliest final votes within the size cap; and a
//! restart holds the V-QC the current view was entered on again.

use crate::{
    Viewable as _,
    multimmit::{
        config::Role,
        machine::{
            capability::{Capabilities, Capability, ResolverCommand},
            durability::{Change, DurableEffect, SignRequest},
            input::{BlockValidity, Input, ObservationStatus, StepStatus},
            resolution::{ResolutionCompletion, RetrievalKey},
            testing::{
                Drive as _, Driver, SymbolicPersistence, SymbolicVerifier, cohort,
                executors::SymbolicCrypto,
                fixtures::{
                    TestDriver, block, certifiers, committee, deliver, enter_next_view,
                    final_above, observe, path, profile, quiesce, receive, reference, started,
                    validate, validator, vqc_above, vqc_of,
                },
            },
            view::{
                assemble::{Candidate, Resolution, select},
                proposal::HeldVqc,
            },
        },
        mocks::Committee,
        types::{Artifact, BlockRef, CertificateId, ChainId, LeaderBlock, Vqc},
    },
    types::{Attributable as _, Participant, View},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::{collections::BTreeMap, sync::Arc};

const ONE: View = View::new(1);
const TWO: View = View::new(2);
const CHAIN: ChainId = ChainId::new(1);

/// Returns the V-QCs the journal records as forwarded, in order.
fn forwarded(driver: &TestDriver) -> Vec<CertificateId<Digest>> {
    driver
        .journal()
        .iter()
        .filter_map(|event| match event.change() {
            Change::ArtifactForwarded { artifact, .. } => match artifact.as_ref() {
                Artifact::Vqc(vqc) => Some(vqc.id::<Sha256>()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Returns the genesis tips of `committee` with `tip` on its chain.
fn tips_with(committee: &Committee<MinPk>, tip: BlockRef<Digest>) -> Vec<BlockRef<Digest>> {
    let mut tips = committee.genesis().tips().to_vec();
    tips[tip.chain().index()] = tip;
    tips
}

#[test]
fn a_new_vqc_is_forwarded_once_with_the_ancestors_not_forwarded_before() {
    let committee = committee(210);
    let genesis = HeldVqc::genesis(committee.genesis());
    let tips = committee.genesis().tips().to_vec();
    let mut driver = started(&committee, validator(0));

    let first = vqc_above(&committee, &genesis, false, tips.clone(), &[]);
    let first_id = first.id::<Sha256>();
    enter_next_view(&mut driver, first);
    assert_eq!(forwarded(&driver), vec![first_id]);

    // Another V-QC of view one is not new: it is held, not forwarded.
    let content = final_above(&committee, &genesis, false, tips.clone());
    let contents = (0..5)
        .map(|signer| (Participant::new(signer), content.clone()))
        .collect();
    let second = committee.vqc_from(genesis.id, contents, Vec::new());
    deliver(&mut driver, vec![Artifact::Vqc(second.clone())]);
    let second = driver.machine().held_vqc(&second.id::<Sha256>()).unwrap();
    assert_eq!(forwarded(&driver), vec![first_id]);

    // A new V-QC of view two above it brings it along, lowest view first.
    let third = vqc_above(&committee, &second, true, tips, &[]);
    let third_id = third.id::<Sha256>();
    enter_next_view(&mut driver, third.clone());
    assert_eq!(forwarded(&driver), vec![first_id, second.id, third_id]);
    let step = driver
        .submit(cohort::<Sha256, _>(vec![Artifact::Vqc(third)]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("an observation is classified");
    };
    assert_eq!(results[0].status(), ObservationStatus::Duplicate);
}

#[test]
fn the_final_vote_is_staged_before_the_view_entry() {
    let committee = committee(211);
    let genesis = HeldVqc::genesis(committee.genesis());
    let mut driver = started(&committee, validator(0));
    let vqc = vqc_above(
        &committee,
        &genesis,
        false,
        committee.genesis().tips().to_vec(),
        &[],
    );
    enter_next_view(&mut driver, vqc);
    let position = |matches: &dyn Fn(&Change<MinPk, Digest>) -> bool| {
        driver
            .journal()
            .iter()
            .position(|event| matches(event.change()))
            .expect("the journal records the change")
    };
    let final_vote = position(&|change| match change {
        Change::OutboxQueued { effect, .. } => match effect.as_ref() {
            DurableEffect::Sign(sign) => sign.requests().iter().any(|request| {
                matches!(request, SignRequest::Update(update)
                    if update.content().is_final() && update.content().view() == ONE)
            }),
            DurableEffect::Publish(_) => false,
        },
        _ => false,
    });
    let entry = position(&|change| matches!(change, Change::ViewEntered { .. }));
    assert!(final_vote < entry);
    assert!(driver.machine().final_sent(ONE));
}

#[test]
fn an_assembled_vqc_is_created_forwarded_and_entered() {
    let committee = committee(212);
    let genesis = HeldVqc::genesis(committee.genesis());
    let mut driver = started(&committee, validator(0));
    let content = final_above(
        &committee,
        &genesis,
        false,
        committee.genesis().tips().to_vec(),
    );
    let updates = certifiers(&committee)
        .into_iter()
        .map(|signer| {
            Artifact::Update(committee.update(signer, &content, committee.genesis().tips(), 1))
        })
        .collect();

    // n - f final votes read: the node aggregates them, creates and forwards the V-QC, and enters
    // view two on it.
    let step = observe(&mut driver, updates);
    let mut executors = (
        SymbolicCrypto::new(committee.verifier.clone()),
        SymbolicPersistence,
    );
    driver.drain(&mut executors, step.into_capabilities());
    quiesce(&mut driver);
    assert_eq!(driver.inspect().view(), TWO);
    let created = driver
        .journal()
        .iter()
        .find_map(|event| match event.change() {
            Change::CertificateCreated { artifact } => match artifact.as_ref() {
                Artifact::Vqc(vqc) => Some(vqc.clone()),
                _ => None,
            },
            _ => None,
        })
        .expect("the assembled V-QC is created");
    assert_eq!(created.view(), ONE);
    assert_eq!(created.parent(), genesis.id);
    assert_eq!(
        created.tally().signers().iter().collect::<Vec<_>>(),
        certifiers(&committee)
    );
    assert_eq!(forwarded(&driver), vec![created.id::<Sha256>()]);
    assert!(driver.machine().held_vqc(&created.id::<Sha256>()).is_some());
}

#[test]
fn an_assembled_vqc_counts_final_votes_below_the_parent_base() {
    let committee = committee(215);
    let genesis = HeldVqc::genesis(committee.genesis());
    let blocks = path(&committee, CHAIN, 2);
    let behind = Participant::new(1);
    let ahead = tips_with(&committee, reference(&blocks[1]));
    let genesis_tips = committee.genesis().tips().to_vec();
    let mut driver = started(&committee, validator(0));

    // View one ends at the second block of the chain, although one certifier is still at genesis.
    let finals =
        |tips: &Vec<BlockRef<Digest>>| final_above(&committee, &genesis, false, tips.clone());
    let contents = certifiers(&committee)
        .into_iter()
        .map(|signer| {
            let tips = if signer == behind {
                &genesis_tips
            } else {
                &ahead
            };
            (signer, finals(tips))
        })
        .collect();
    let one = enter_next_view(&mut driver, vqc_of(&committee, &genesis, contents, &blocks));
    assert_eq!(one.tips.as_ref(), ahead.as_slice());

    // Every certifier votes finally in view two as before: the lagging one below the base. Its
    // vote needs no resolution path, so the n - f final votes form a V-QC.
    let updates = certifiers(&committee)
        .into_iter()
        .map(|signer| {
            let tips = if signer == behind {
                &genesis_tips
            } else {
                &ahead
            };
            let content = final_above(&committee, &one, false, tips.clone());
            Artifact::Update(committee.update(signer, &content, tips, 1))
        })
        .collect();
    let step = observe(&mut driver, updates);
    let mut executors = (
        SymbolicCrypto::new(committee.verifier.clone()),
        SymbolicPersistence,
    );
    driver.drain(&mut executors, step.into_capabilities());
    quiesce(&mut driver);
    assert_eq!(driver.inspect().view(), View::new(3));
    let created = driver
        .journal()
        .iter()
        .find_map(|event| match event.change() {
            Change::CertificateCreated { artifact } => match artifact.as_ref() {
                Artifact::Vqc(vqc) if vqc.view() == TWO => Some(vqc.clone()),
                _ => None,
            },
            _ => None,
        })
        .expect("the assembled V-QC is created");
    assert_eq!(created.parent(), one.id);
    assert!(
        created
            .tally()
            .signers()
            .iter()
            .any(|signer| signer == behind)
    );
}

#[test]
fn assembly_takes_the_earliest_finals_and_substitutes_beyond_the_size_cap() {
    let committee = committee(213);
    let genesis = HeldVqc::genesis(committee.genesis());
    let blocks = path(&committee, CHAIN, 3);
    let base = committee.genesis().tips()[CHAIN.index()];
    let candidate = |signer: u32, height: Option<usize>| {
        let tip = height.map_or(base, |height| reference(&blocks[height]));
        let content = final_above(&committee, &genesis, false, tips_with(&committee, tip));
        let resolutions = height
            .map(|height| Resolution {
                from: base,
                blocks: blocks[..=height].iter().map(reference).collect(),
                payloads: blocks[..=height]
                    .iter()
                    .map(|block| block.header().body_digest())
                    .collect(),
            })
            .into_iter()
            .collect();
        Candidate {
            attestation: committee.sign_vote(Participant::new(signer), &content),
            content: Arc::new(content),
            resolutions,
        }
    };
    // The earliest final vote endorses three blocks no other vote names.
    let candidates = [
        candidate(0, Some(2)),
        candidate(1, None),
        candidate(2, None),
        candidate(3, None),
        candidate(4, None),
        candidate(5, None),
    ];
    let signers = |votes: &[(_, crate::multimmit::types::Attestation<MinPk>)]| {
        votes
            .iter()
            .map(|(_, attestation)| attestation.signer().get())
            .collect::<Vec<_>>()
    };
    let round = committee.round(ONE);
    let selection = select(&candidates, round, genesis.id, committee.codec()).unwrap();
    assert_eq!(signers(&selection.votes), vec![0, 1, 2, 3, 4]);
    assert_eq!(selection.paths.len(), 1);
    let vqc = committee.vqc_from(
        genesis.id,
        selection
            .votes
            .iter()
            .map(|(content, attestation)| (attestation.signer(), content.clone()))
            .collect(),
        selection.paths,
    );

    // A cap that fits only agreeing votes drops the deviating one for the next final vote.
    let agreeing = Vqc::<MinPk, Digest>::encode_size(
        &committee.vqc_from(
            genesis.id,
            candidates[1..]
                .iter()
                .map(|candidate| {
                    (
                        candidate.attestation.signer(),
                        candidate.content.as_ref().clone(),
                    )
                })
                .collect(),
            Vec::new(),
        ),
    );
    assert!(vqc.encode_size() > agreeing);
    let capped = committee
        .codec()
        .with_max_vqc_bytes(u32::try_from(agreeing).unwrap())
        .unwrap();
    let selection = select(&candidates, round, genesis.id, capped).unwrap();
    assert_eq!(signers(&selection.votes), vec![1, 2, 3, 4, 5]);
    assert!(selection.paths.is_empty());

    // Without enough candidates that fit, nothing is assembled.
    assert!(select(&candidates[..5], round, genesis.id, capped).is_none());
}

#[test]
fn a_restart_holds_the_entry_vqc_again() {
    let committee = committee(214);
    let leader = committee.config.leader(TWO);
    let own = Participant::new((leader.get() + 1) % committee.codec().participants() as u32);
    let genesis = HeldVqc::genesis(committee.genesis());
    let mut driver = Driver::new(profile(&committee, Role::Validator(own)));
    let start = driver
        .submit(crate::multimmit::machine::input::Input::Start)
        .unwrap();
    driver.drain(&mut SymbolicPersistence, start.into_capabilities());
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

    let recovered = driver.crash_and_restore().unwrap();
    let _: Capabilities<MinPk, Digest> = driver.drain_persisting(recovered);
    assert_eq!(driver.machine().held_vqc(&one.id), Some(one.clone()));

    // A proposal of view two naming it is valid again.
    let block = LeaderBlock::new(committee.round(TWO), one.id, one.history).unwrap();
    let signed = committee.signers[usize::from(leader)]
        .sign_leader_block(block)
        .unwrap();
    deliver(&mut driver, vec![Artifact::LeaderBlock(signed)]);
    assert!(driver.machine().valid_proposal(TWO).is_some());
}

#[test]
fn an_assembled_vqc_records_finals_on_both_branches_of_an_equivocating_producer() {
    let committee = committee(216);
    let genesis = HeldVqc::genesis(committee.genesis());
    let mut driver = started(&committee, validator(0));
    let accepted = path(&committee, CHAIN, 2);
    for block in &accepted {
        receive(&mut driver, std::slice::from_ref(block));
        validate(&mut driver, block, BlockValidity::Valid);
    }
    // The chain's producer also signed another branch of the same height.
    let root = committee.genesis().tips()[CHAIN.index()];
    let fork_one = block(&committee, &root, b"fork one");
    let fork_two = block(&committee, &reference(&fork_one), b"fork two");
    let forks = [&fork_one, &fork_two]
        .map(|block| (reference(block).digest(), block.clone()))
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    // Three certifiers vote finally on the accepted branch and two on the other one, without
    // payload hashes: the node fetches the other branch, tip first, to resolve their votes.
    let signers = certifiers(&committee);
    let updates = signers
        .iter()
        .enumerate()
        .map(|(index, signer)| {
            let tip = if index < 3 {
                reference(&accepted[1])
            } else {
                reference(&fork_two)
            };
            let content = final_above(&committee, &genesis, false, tips_with(&committee, tip));
            Artifact::Update(committee.update(*signer, &content, committee.genesis().tips(), 1))
        })
        .collect();
    let step = observe(&mut driver, updates);
    let mut executors = (
        SymbolicCrypto::new(committee.verifier),
        (SymbolicPersistence, SymbolicVerifier::new(true)),
    );
    let mut pending = driver.drain(&mut executors, step.into_capabilities());
    let mut fetched = Vec::new();
    loop {
        let jobs = pending
            .iter()
            .filter_map(|capability| match capability {
                Capability::Resolver(ResolverCommand::Resolve(job)) => match job.key() {
                    RetrievalKey::Header { digest, .. } => Some((*job, digest)),
                    _ => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        if jobs.is_empty() {
            break;
        }
        pending = Capabilities::new();
        for (job, digest) in jobs {
            fetched.push(digest);
            let answer = Artifact::TransactionBlock(forks[&digest].clone())
                .identify::<Sha256>(&mut Vec::new());
            let step = driver
                .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
                    job, answer,
                )))
                .unwrap();
            pending.extend(driver.drain(&mut executors, step.into_capabilities()));
        }
    }
    assert_eq!(
        fetched,
        vec![reference(&fork_two).digest(), reference(&fork_one).digest()]
    );
    quiesce(&mut driver);

    // The V-QC records all n - f final votes; the base's window block with n - 3f endorsers is
    // the accepted branch's tip.
    assert_eq!(driver.inspect().view(), TWO);
    let created = driver
        .journal()
        .iter()
        .find_map(|event| match event.change() {
            Change::CertificateCreated { artifact } => match artifact.as_ref() {
                Artifact::Vqc(vqc) => Some(vqc.clone()),
                _ => None,
            },
            _ => None,
        })
        .expect("the assembled V-QC is created");
    assert_eq!(created.view(), ONE);
    assert_eq!(
        created.tally().signers().iter().collect::<Vec<_>>(),
        signers
    );
    let held = driver
        .machine()
        .held_vqc(&created.id::<Sha256>())
        .expect("the V-QC is held");
    assert_eq!(held.tips[CHAIN.index()], reference(&accepted[1]));
}
