//! Vote updates this node signs: endorsed tips on the accepted path within declarations, the
//! chains each update names and the payload hashes it carries, and the durable vote watermark
//! across crashes.

use crate::{
    Viewable as _,
    multimmit::{
        config::Role,
        machine::{
            capability::Capability,
            durability::{
                DurableEffect, ProposalParent, ProposalRequest, ReplayError, SignRequest,
                TransitionReason, UpdateRequest,
            },
            input::{BlockValidity, Input, StepError, StepStatus},
            reducer::components::WorkStatus,
            testing::{
                Drive as _, Driver, MachineExt as _, StepExt as _, SymbolicPersistence,
                SymbolicSigner,
                fixtures::{
                    Block, TestDriver, committee, deliver, digest, elapse, observe, path,
                    persist_all, profile, receive, reference, started, validate, validator,
                },
            },
            view::declare::Declarations,
        },
        mocks::Committee,
        types::{Artifact, BlockRef, ChainChange, ChainId, ChainSet, LeaderBlock, VoteContent},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};

const VIEW: View = View::new(1);
const OWN: Participant = Participant::new(0);
const CHAIN: ChainId = ChainId::new(1);

/// Accepts `blocks` of a peer chain in full.
fn accept(driver: &mut TestDriver, blocks: &[Block]) {
    receive(driver, blocks);
    for block in blocks {
        validate(driver, block, BlockValidity::Valid);
    }
}

/// Returns a driver for `leader` whose machine started, proposed for view one, signed its leader
/// block, and voted for it.
fn started_leader(committee: &Committee<MinPk>, leader: Participant) -> TestDriver {
    let mut driver = Driver::new(profile(committee, Role::Validator(leader)));
    let mut signer = (
        SymbolicSigner::new(committee.signers[usize::from(leader)].clone()),
        SymbolicPersistence,
    );
    let start = driver.submit(Input::Start).unwrap();
    driver.drain(&mut signer, start.into_capabilities());
    driver
}

/// Returns this node's endorsed content for `view`.
fn endorsed(
    driver: &TestDriver,
    view: View,
    final_: bool,
    declared: &[u32],
) -> VoteContent<Digest> {
    let machine = driver.machine();
    let mut declarations = Declarations::new(view, machine.profile.codec().chains());
    for chain in declared.iter().copied().map(ChainId::new) {
        declarations.declare(chain, machine.chain_layer().tip(chain));
    }
    machine
        .endorsed_content(view, None, final_, &declarations)
        .unwrap()
}

/// Sends `content` as the next update of its tag, makes the reservation durable, and returns the
/// reserved request.
fn send(
    driver: &mut TestDriver,
    content: VoteContent<Digest>,
) -> Result<UpdateRequest<Digest>, StepError> {
    let now = driver.now();
    let (status, mut capabilities) = driver.machine_mut().send_update(content, now)?;
    assert_eq!(status, WorkStatus::Complete);
    capabilities.extend(driver.machine_mut().emit_staged());
    driver.record(&capabilities);
    persist_all(
        driver,
        crate::multimmit::machine::input::Step::for_tests(
            StepStatus::Accepted,
            capabilities,
            Vec::new(),
        ),
    );
    Ok(driver
        .machine()
        .durable
        .state
        .sign_requests()
        .filter_map(|request| match request {
            SignRequest::Update(update) => Some(update.clone()),
            _ => None,
        })
        .last()
        .expect("an update is reserved"))
}

/// Returns the tips and payload counts `request` names, per chain.
fn named(request: &UpdateRequest<Digest>) -> Vec<(BlockRef<Digest>, usize)> {
    request
        .changes()
        .iter()
        .map(|change: &ChainChange<Digest>| (change.tip(), change.payloads().len()))
        .collect()
}

/// Returns whether `error` refuses a vote watermark advance.
fn refused(error: StepError) -> bool {
    matches!(
        error,
        StepError::DurableTransition {
            source: ReplayError::Transition(TransitionReason::SigningSlot),
            ..
        }
    )
}

#[test]
fn updates_name_the_chains_changed_since_either_previous_update() {
    let committee = committee(90);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 5);
    accept(&mut driver, &blocks[..2]);

    // Update one names chain one against update zero (genesis in view one), with the payload
    // hashes of both blocks it advanced.
    let first = endorsed(&driver, VIEW, false, &[]);
    assert_eq!(first.tips()[CHAIN.index()], reference(&blocks[1]));
    let request = send(&mut driver, first.clone()).unwrap();
    assert_eq!(request.seq(), 1);
    assert_eq!(named(&request), vec![(reference(&blocks[1]), 2)]);
    assert_eq!(
        request.changes()[0].payloads(),
        blocks[..2]
            .iter()
            .map(|block| block.header().body_digest())
            .collect::<Vec<_>>()
    );
    // The pool reads this node's own vote at once.
    assert_eq!(
        driver
            .machine()
            .latest_vote(OWN, VIEW)
            .map(|vote| vote.as_ref()),
        Some(&first)
    );

    // Three blocks later: the path above update zero's tip, which covers update one's.
    accept(&mut driver, &blocks[2..]);
    let second = endorsed(&driver, VIEW, false, &[]);
    let request = send(&mut driver, second.clone()).unwrap();
    assert_eq!(named(&request), vec![(reference(&blocks[4]), 5)]);

    // Unchanged since update two but not since update one: named again with the path above
    // update one's tip.
    let request = send(&mut driver, second.clone()).unwrap();
    assert_eq!(named(&request), vec![(reference(&blocks[4]), 3)]);

    // Unchanged since both: nothing is named.
    let request = send(&mut driver, second).unwrap();
    assert_eq!(request.seq(), 4);
    assert!(request.changes().is_empty());
}

#[test]
fn updates_carry_the_path_above_the_tip_of_update_k_minus_two() {
    let committee = committee(93);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 8);
    // A burst of four blocks, then one block per update: each update reaches below the tip of
    // the update before its predecessor, however far that one advanced.
    let (mut sent, mut held) = (Vec::new(), 0);
    for (accepted, payloads) in [(1, 1), (5, 5), (6, 5), (7, 2), (8, 2)] {
        accept(&mut driver, &blocks[held..accepted]);
        held = accepted;
        let vote = endorsed(&driver, VIEW, false, &[]);
        let request = send(&mut driver, vote).unwrap();
        assert_eq!(
            named(&request),
            vec![(reference(&blocks[accepted - 1]), payloads)]
        );
        sent.push(request);
    }
    // A final vote names every chain, carrying only what moved since update `k - 2`.
    let vote = endorsed(&driver, VIEW, true, &[]);
    let request = send(&mut driver, vote).unwrap();
    assert_eq!(request.changes().len(), committee.codec().chains());
    assert_eq!(request.changes()[CHAIN.index()].payloads().len(), 1);
    assert!(
        request
            .changes()
            .iter()
            .filter(|change| change.chain() != CHAIN)
            .all(|change| change.payloads().is_empty())
    );

    // A reader holding none of the chain's headers that loses update two reads update three
    // at once: it rebuilds the path from the tip update one carried.
    let mut reader = started(&committee, validator(2));
    for request in [&sent[0], &sent[2]] {
        let update = committee.update_with(
            OWN,
            request.content(),
            request.changes().to_vec(),
            request.seq(),
        );
        deliver(&mut reader, vec![Artifact::Update(update)]);
    }
    assert_eq!(
        reader
            .machine()
            .latest_vote(OWN, VIEW)
            .map(|vote| vote.as_ref()),
        Some(sent[2].content())
    );
}

#[test]
fn a_declared_chain_is_endorsed_at_its_declaration() {
    let committee = committee(91);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 3);
    accept(&mut driver, &blocks[..1]);
    let declared = endorsed(&driver, VIEW, false, &[1]);
    send(&mut driver, declared).unwrap();

    // The accepted tip moves on, but the declared chain stays at its declaration height.
    accept(&mut driver, &blocks[1..]);
    let later = endorsed(&driver, VIEW, false, &[1]);
    assert_eq!(later.tips()[CHAIN.index()], reference(&blocks[0]));
    let undeclared = endorsed(&driver, View::new(2), false, &[]);
    assert_eq!(undeclared.tips()[CHAIN.index()], reference(&blocks[2]));
}

#[test]
fn a_declared_chain_is_endorsed_after_retention_drops_the_headers_below_the_tip() {
    let committee = committee(98);
    let mut driver = started(&committee, validator(0));
    let other = ChainId::new(2);
    let blocks = path(&committee, CHAIN, 4);
    let others = path(&committee, other, 4);
    accept(&mut driver, &blocks[..1]);
    accept(&mut driver, &others[..1]);
    // Chain one is declared in a sent vote, chain two only fired: both at the first block.
    let declared = endorsed(&driver, VIEW, false, &[1]);
    send(&mut driver, declared).unwrap();
    let machine = driver.machine();
    let mut declarations = Declarations::recorded(
        VIEW,
        machine.durable.state.watermark.get(&VIEW),
        committee.codec().chains(),
    );
    declarations.declare(other, machine.chain_layer().tip(other));

    // The node catches up and retention raises the header floors above both declarations.
    accept(&mut driver, &blocks[1..]);
    accept(&mut driver, &others[1..]);
    let headers = &mut driver.machine_mut().components.chain.headers;
    headers.retain_above(CHAIN, Height::new(2));
    headers.retain_above(other, Height::new(2));
    let content = driver
        .machine()
        .endorsed_content(VIEW, None, false, &declarations)
        .unwrap();
    assert_eq!(content.tips()[CHAIN.index()], reference(&blocks[0]));
    assert_eq!(content.tips()[other.index()], reference(&others[0]));
    send(&mut driver, content).unwrap();
}

#[test]
fn the_first_update_after_a_restart_names_every_chain() {
    let committee = committee(92);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 3);
    accept(&mut driver, &blocks);
    let vote = endorsed(&driver, VIEW, false, &[]);
    send(&mut driver, vote.clone()).unwrap();
    send(&mut driver, vote.clone()).unwrap();

    let recovered = driver.crash_and_restore().unwrap();
    persist_all(&mut driver, recovered);
    // The pool reads this node's latest vote of the tag from its watermark.
    assert_eq!(
        driver
            .machine()
            .latest_vote(OWN, VIEW)
            .map(|vote| vote.as_ref()),
        Some(&vote)
    );
    let request = send(&mut driver, vote).unwrap();
    assert_eq!(request.seq(), 3);
    let chains = committee.codec().chains();
    assert_eq!(request.changes().len(), chains);
    // Without the previous tip the payload hashes cover as much of the path as allowed.
    assert_eq!(request.changes()[CHAIN.index()].payloads().len(), 3);
}

#[test]
fn a_signature_completing_after_its_update_was_superseded_is_never_published() {
    let committee = committee(99);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 3);
    // Reserves the next update endorsing the accepted tips durably, returning the signing it
    // released.
    let reserve = |driver: &mut TestDriver| {
        let content = endorsed(driver, VIEW, false, &[]);
        let now = driver.now();
        let (status, mut capabilities) = driver.machine_mut().send_update(content, now).unwrap();
        assert_eq!(status, WorkStatus::Complete);
        capabilities.extend(driver.machine_mut().emit_staged());
        driver.record(&capabilities);
        driver.drain(&mut SymbolicPersistence, capabilities)
    };
    let signer = || {
        (
            SymbolicSigner::new(committee.signers[0].clone()),
            SymbolicPersistence,
        )
    };
    let published = |signer: &SymbolicSigner<MinPk>| {
        signer
            .published
            .iter()
            .filter_map(|artifact| match artifact {
                Artifact::Update(update) => Some(update.seq()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    // The signer holds back every signature while three updates of the tag are reserved: update
    // three ends update one's publication duty before update one is signed.
    let mut released = Vec::new();
    for block in blocks.chunks(1) {
        accept(&mut driver, block);
        released.push(reserve(&mut driver));
    }
    assert_eq!(driver.machine().durable.state.signing_reservations(), 2);

    // Update one's late signature is stale; the others are published.
    let mut late = signer();
    for capabilities in released.clone() {
        driver.drain(&mut late, capabilities);
    }
    assert!(driver.inspect().is_live());
    assert_eq!(published(&late.0), vec![2, 3]);

    // A restart before any signature completed re-releases only the updates still to publish.
    let mut restarted = Driver::new(profile(&committee, validator(0)));
    let start = restarted.submit(Input::Start).unwrap();
    restarted.drain(&mut SymbolicPersistence, start.into_capabilities());
    for block in blocks.chunks(1) {
        accept(&mut restarted, block);
        reserve(&mut restarted);
    }
    let recovered = restarted.crash_and_restore().unwrap();
    let mut recovery = signer();
    restarted.drain(&mut recovery, recovered.into_capabilities());
    assert_eq!(published(&recovery.0), vec![2, 3]);
}

#[test]
fn this_nodes_latest_update_of_a_tag_is_served_naming_every_chain() {
    let committee = committee(98);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 2);
    let mut signer = (
        SymbolicSigner::new(committee.signers[0].clone()),
        SymbolicPersistence,
    );
    let chains = committee.codec().chains();

    // Each signed update is served, once durable, naming every chain; update two itself names
    // only the chain that advanced.
    let mut served = Vec::new();
    let mut votes = Vec::new();
    for block in blocks.chunks(1) {
        accept(&mut driver, block);
        let content = endorsed(&driver, VIEW, false, &[]);
        let now = driver.now();
        let (status, mut capabilities) = driver
            .machine_mut()
            .send_update(content.clone(), now)
            .unwrap();
        assert_eq!(status, WorkStatus::Complete);
        capabilities.extend(driver.machine_mut().emit_staged());
        driver.record(&capabilities);
        for capability in driver.drain(&mut signer, capabilities) {
            if let Capability::Acknowledged { retention } = capability {
                served.extend(retention);
            }
        }
        votes.push(content);
    }
    let Some(Artifact::Update(second)) = signer.0.published.last() else {
        panic!("update two is published");
    };
    assert_eq!(second.changes().len(), 1);
    let served = served
        .iter()
        .filter_map(|artifact| match artifact.as_ref() {
            Artifact::Update(update) => Some(update.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(served.len(), 2);
    for ((seq, update), vote) in (1..).zip(&served).zip(&votes) {
        assert_eq!(update.seq(), seq);
        assert_eq!(update.changes().len(), chains);
        let genesis = committee.genesis().tips();
        assert_eq!(&update.content(genesis, committee.codec()).unwrap(), vote);
    }
    assert_eq!(served[1].attestation(), second.attestation());

    // A restart serves the tag's latest signed update again, still naming every chain.
    let recovered = driver.crash_and_restore().unwrap();
    persist_all(&mut driver, recovered);
    let (_, seeded) = driver.machine().resolver_seed();
    let seeded = seeded
        .into_iter()
        .filter_map(|artifact| match artifact {
            Artifact::Update(update) => Some(update),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(seeded, vec![served[1].clone()]);
}

#[test]
fn one_final_vote_per_tag_survives_a_crash() {
    let committee = committee(93);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 2);
    accept(&mut driver, &blocks);
    let last = endorsed(&driver, VIEW, true, &[]);
    send(&mut driver, last.clone()).unwrap();
    let pre_vote = endorsed(&driver, VIEW, false, &[]);
    assert!(refused(send(&mut driver, pre_vote).unwrap_err()));

    let recovered = driver.crash_and_restore().unwrap();
    persist_all(&mut driver, recovered);
    let watermark = &driver.machine().durable.state.watermark[&VIEW];
    assert_eq!(watermark.final_content.as_ref(), Some(&last));
    assert_eq!(
        driver
            .machine()
            .latest_vote(OWN, VIEW)
            .map(|vote| vote.as_ref()),
        Some(&last)
    );
    assert!(refused(send(&mut driver, last.clone()).unwrap_err()));

    // The next view's first update omits every chain unchanged since that final vote.
    let next = endorsed(&driver, View::new(2), false, &[]);
    assert_eq!(next.tips(), last.tips());
    let request = send(&mut driver, next).unwrap();
    assert_eq!(request.content().view(), View::new(2));
    assert!(request.changes().is_empty());
}

#[test]
fn update_tips_must_lie_on_the_accepted_path() {
    let committee: Committee<MinPk> = committee(94);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 1);
    receive(&mut driver, &blocks);
    let mut tips = committee.genesis().tips().to_vec();
    tips[CHAIN.index()] = reference(&blocks[0]);
    let chains = committee.codec().chains();
    let content = committee.content(
        VIEW,
        None,
        false,
        committee.endorsement(ChainSet::empty(chains), tips),
    );
    let request = UpdateRequest::new(content, 1, Vec::new());
    let error = driver
        .machine_mut()
        .reserve_test_effect(DurableEffect::sign(SignRequest::Update(request)))
        .unwrap_err();
    assert!(refused(error));
}

#[test]
fn a_final_vote_names_every_chain() {
    let committee = committee(95);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 1);
    accept(&mut driver, &blocks);
    let vote = endorsed(&driver, VIEW, false, &[]);
    send(&mut driver, vote.clone()).unwrap();
    send(&mut driver, vote).unwrap();
    // Nothing changed since either earlier update, yet the final vote names every chain.
    let last = endorsed(&driver, VIEW, true, &[]);
    let request = send(&mut driver, last).unwrap();
    assert_eq!(request.changes().len(), committee.codec().chains());
}

#[test]
fn the_notarised_leader_block_is_write_once_across_a_crash() {
    let committee = committee(96);
    let mut driver = started(&committee, validator(0));
    let block = committee.leader_block(VIEW);
    let leader = block.block().digest::<Sha256>();
    let voted = observe(&mut driver, vec![Artifact::LeaderBlock(block)]);
    persist_all(&mut driver, voted);
    assert_eq!(driver.machine().notarised(VIEW), Some(leader));

    let recovered = driver.crash_and_restore().unwrap();
    persist_all(&mut driver, recovered);
    assert_eq!(driver.machine().notarised(VIEW), Some(leader));
    // Neither another leader block nor a pre-vote can follow the vote for it in the view.
    let declarations = Declarations::new(VIEW, committee.codec().chains());
    for other in [Some(digest(b"other")), None] {
        let content = driver
            .machine()
            .endorsed_content(VIEW, other, false, &declarations)
            .unwrap();
        assert!(refused(send(&mut driver, content).unwrap_err()));
    }

    // The view layer keeps voting for it: a changed tip is sent with the same leader block.
    let blocks = path(&committee, CHAIN, 1);
    accept(&mut driver, &blocks);
    let eta = driver
        .machine()
        .profile()
        .tuning()
        .vote_interval
        .as_millis() as u64;
    elapse(&mut driver, eta);
    let vote = driver.machine().last_sent(VIEW).unwrap();
    assert_eq!(vote.leader(), Some(leader));
    assert_eq!(vote.tips()[CHAIN.index()], reference(&blocks[0]));
}

#[test]
fn the_leader_block_slot_is_signed_once_across_a_crash() {
    let committee = committee(97);
    let leader = committee.config.leader(VIEW);
    let mut driver = started_leader(&committee, leader);
    assert!(driver.machine().proposed(VIEW));
    let recovered = driver.crash_and_restore().unwrap();
    persist_all(&mut driver, recovered);
    let genesis = committee.genesis();
    let block = LeaderBlock::new(committee.round(VIEW), genesis.vqc(), digest(b"other")).unwrap();
    let request = ProposalRequest::new(block, ProposalParent::Genesis, false);
    let error = driver
        .machine_mut()
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(request)))
        .unwrap_err();
    assert!(refused(error));
}
