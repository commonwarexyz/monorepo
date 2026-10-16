//! The view layer's handlers: the leader's proposal, which leader blocks are valid, votes for a
//! leader block, when the final vote is sent, the late final vote at a view change, optimisations
//! (A) and (B), the adaptive grace, and the update cadence.

use crate::{
    Viewable as _,
    multimmit::{
        config::{Role, Tuning},
        machine::{
            durability::{DurableEffect, Publication, SignRequest},
            input::{BlockValidity, Input, ObservationStatus, Rejection, StepError, StepStatus},
            testing::{
                CapabilitiesExt as _, Drive as _, Driver, MachineExt as _, SymbolicPersistence,
                SymbolicSigner, Until, cohort,
                fixtures::{
                    TestDriver, committee, deliver, digest, elapse, enter_next_view, observe, path,
                    persist_capabilities, profile, quiesce, receive, reference, started,
                    started_with, tuned, undetermined_vqc, validate, validator, vqc_above,
                },
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{Artifact, ChainId, LeaderBlock, SignedLeaderBlock, VoteContent},
    },
    types::{Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::{collections::VecDeque, sync::Arc, time::Duration};

const ONE: View = View::new(1);
const TWO: View = View::new(2);

/// Returns the latest vote this node reserved for `view` since it started.
fn sent(driver: &TestDriver, view: View) -> Option<VoteContent<Digest>> {
    driver
        .machine()
        .last_sent(view)
        .map(|content| content.as_ref().clone())
}

/// Returns the digest of `block`'s leader block.
fn digest_of(block: &SignedLeaderBlock<MinPk, Digest>) -> Digest {
    block.block().digest::<Sha256>()
}

/// Returns the leader block of `view` above `parent`, signed by `signer`.
fn leader_block(
    committee: &Committee<MinPk>,
    signer: Participant,
    view: View,
    parent: &HeldVqc<Digest>,
) -> SignedLeaderBlock<MinPk, Digest> {
    let block = LeaderBlock::new(committee.round(view), parent.id, parent.history).unwrap();
    committee.signers[usize::from(signer)]
        .sign_leader_block(block)
        .unwrap()
}

/// Returns the genesis V-QC as the view layer holds it.
fn genesis(committee: &Committee<MinPk>) -> HeldVqc<Digest> {
    HeldVqc::genesis(committee.genesis())
}

/// Returns `block` with its signature replaced by one of `signer`, which does not lead its view.
fn resigned(
    committee: &Committee<MinPk>,
    block: &SignedLeaderBlock<MinPk, Digest>,
    signer: Participant,
) -> SignedLeaderBlock<MinPk, Digest> {
    let content = committee.content(block.view(), None, false, committee.genesis_endorsement());
    SignedLeaderBlock::new(block.block().clone(), committee.sign_vote(signer, &content))
}

/// Returns the pre-verification outcome of observing `block`.
fn observe_status(
    driver: &mut TestDriver,
    block: SignedLeaderBlock<MinPk, Digest>,
) -> ObservationStatus {
    let step = driver
        .submit(cohort::<Sha256, _>(vec![Artifact::LeaderBlock(block)]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("an observation is classified");
    };
    results[0].status()
}

/// Enters view two on a V-QC of view one whose tips are the genesis tips and whose final votes
/// leave view two's emission state undefined, after a leaderless final vote for view one, and
/// returns that V-QC as the view layer holds it.
fn enter_two(driver: &mut TestDriver, committee: &Committee<MinPk>) -> HeldVqc<Digest> {
    enter_next_view(driver, undetermined_vqc(committee, &genesis(committee)))
}

#[test]
fn the_leader_proposes_once_on_its_parent_and_votes_for_its_block() {
    let committee = committee(100);
    let leader = committee.config.leader(ONE);
    let mut driver = Driver::new(profile(&committee, Role::Validator(leader)));
    let mut signer = (
        SymbolicSigner::new(committee.signers[usize::from(leader)].clone()),
        SymbolicPersistence,
    );
    let start = driver.submit(Input::Start).unwrap();
    driver.drain(&mut signer, start.into_capabilities());

    // The leader block names the genesis V-QC and its commitment, occupies the view's slot, and is
    // published as a proposal.
    let genesis = committee.genesis();
    let expected = committee.leader_block(ONE);
    let state = &driver.machine().durable.state;
    assert_eq!(
        state.leader_blocks.get(&ONE),
        Some(&(genesis.vqc(), genesis.history()))
    );
    assert!(state.outbox.values().any(|entry| matches!(
        entry.publication(),
        Publication::Propose(proposal) if proposal.block().block() == expected.block()
    )));

    // The leader votes for its own block at once.
    assert_eq!(driver.machine().notarised(ONE), Some(digest_of(&expected)));
    assert_eq!(
        sent(&driver, ONE).and_then(|vote| vote.leader()),
        Some(digest_of(&expected))
    );

    // After a crash the slot is held: the leader neither proposes nor signs again.
    let recovered = driver.crash_and_restore().unwrap();
    driver.drain(&mut signer, recovered.into_capabilities());
    assert!(driver.machine().proposed(ONE));
    assert_eq!(driver.machine().durable.state.leader_blocks.len(), 1);
    assert!(
        !driver
            .machine()
            .durable
            .state
            .sign_requests()
            .any(|request| matches!(request, SignRequest::LeaderBlock(_)))
    );
}

#[test]
fn a_valid_proposal_gets_a_vote_at_once() {
    let committee = committee(101);
    let mut driver = started(&committee, validator(0));
    let block = committee.leader_block(ONE);
    observe(&mut driver, vec![Artifact::LeaderBlock(block.clone())]);
    let vote = sent(&driver, ONE).expect("the vote for the leader block is sent at once");
    assert_eq!(vote.leader(), Some(digest_of(&block)));
    assert!(!vote.is_final(), "the trigger does not hold yet");
    assert_eq!(driver.machine().notarised(ONE), Some(digest_of(&block)));
}

#[test]
fn proposals_from_the_wrong_signer_or_outside_the_window_are_refused() {
    let committee = committee(102);
    let mut driver = started(&committee, validator(0));
    let genesis = genesis(&committee);
    // Participant 2 does not lead view one.
    assert_eq!(
        observe_status(
            &mut driver,
            resigned(
                &committee,
                &committee.leader_block(ONE),
                Participant::new(2)
            )
        ),
        ObservationStatus::Rejected(Rejection::Participant)
    );
    // View three is beyond the next view.
    let three = View::new(3);
    let leader = committee.config.leader(three);
    assert_eq!(
        observe_status(
            &mut driver,
            leader_block(&committee, leader, three, &genesis)
        ),
        ObservationStatus::Rejected(Rejection::TagWindow)
    );
}

#[test]
fn a_proposal_with_a_wrong_commitment_or_parent_view_gets_no_vote() {
    let committee = committee(103);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis();

    // The commitment is not the genesis V-QC's.
    let wrong = committee.leader_block_with(ONE, genesis.vqc(), digest(b"wrong"));
    observe(&mut driver, vec![Artifact::LeaderBlock(wrong)]);
    assert_eq!(driver.machine().notarised(ONE), None);
    assert!(sent(&driver, ONE).is_none());

    // A view-two block naming the genesis V-QC names no V-QC of view one.
    let early = committee.leader_block(TWO);
    observe(&mut driver, vec![Artifact::LeaderBlock(early)]);
    assert!(driver.machine().valid_proposal(TWO).is_none());
}

#[test]
fn two_leader_blocks_for_one_view_make_neither_valid() {
    let committee = committee(104);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis();
    let valid = committee.leader_block(ONE);
    let other = committee.leader_block_with(ONE, genesis.vqc(), digest(b"other"));
    observe(
        &mut driver,
        vec![Artifact::LeaderBlock(valid), Artifact::LeaderBlock(other)],
    );
    assert_eq!(driver.machine().notarised(ONE), None);
    assert!(driver.machine().valid_proposal(ONE).is_none());
    // A third block of the equivocating leader is refused before verification.
    let third = committee.leader_block_with(ONE, genesis.vqc(), digest(b"third"));
    assert_eq!(
        observe_status(&mut driver, third),
        ObservationStatus::Rejected(Rejection::Superseded)
    );
}

#[test]
fn the_final_vote_follows_the_trigger_and_the_grace() {
    let committee = committee(105);
    let timers = started(&committee, validator(0)).machine().current_timers();
    assert!(
        timers.grace < timers.stop,
        "the default grace ends before D_stop"
    );

    // Without a leader block: no final vote at the grace while chains are neither declared nor
    // capped; at D_stop every silent chain is declared and the leaderless final vote follows.
    let mut driver = started(&committee, validator(0));
    elapse(&mut driver, timers.grace);
    assert!(!driver.machine().final_sent(ONE));
    elapse(&mut driver, timers.stop - timers.grace);
    let vote = sent(&driver, ONE).expect("a final vote is sent");
    assert!(vote.is_final());
    assert_eq!(vote.leader(), None);
    assert_eq!(vote.declared().len(), committee.codec().chains());

    // With a leader block voted for, the final vote for it follows the trigger alone.
    let mut driver = started(&committee, validator(0));
    let block = committee.leader_block(ONE);
    observe(&mut driver, vec![Artifact::LeaderBlock(block.clone())]);
    elapse(&mut driver, timers.stop);
    let vote = sent(&driver, ONE).expect("a final vote is sent");
    assert!(vote.is_final());
    assert_eq!(vote.leader(), Some(digest_of(&block)));
}

#[test]
fn a_view_change_sends_the_late_final_vote() {
    let committee = committee(106);
    let genesis = genesis(&committee);
    let designated = digest_of(&committee.leader_block(ONE));

    // A V-QC designating a leader block: the final vote is for the block this node builds from
    // the V-QC's parent, without holding it, and declares every chain.
    let mut driver = started(&committee, validator(0));
    let now = driver.now();
    let (_, capabilities) = driver
        .machine_mut()
        .finish_view(&genesis, true, now)
        .unwrap();
    persist_capabilities(&mut driver, capabilities);
    let vote = sent(&driver, ONE).unwrap();
    assert!(vote.is_final());
    assert_eq!(vote.leader(), Some(designated));
    assert_eq!(vote.declared().len(), committee.codec().chains());
    assert_eq!(driver.machine().notarised(ONE), Some(designated));

    // A V-QC designating nothing: a leaderless final vote.
    let mut driver = started(&committee, validator(0));
    let now = driver.now();
    let (_, capabilities) = driver
        .machine_mut()
        .finish_view(&genesis, false, now)
        .unwrap();
    persist_capabilities(&mut driver, capabilities);
    assert_eq!(sent(&driver, ONE).unwrap().leader(), None);

    // A node that voted for a leader block sends its final vote for that block, whatever the V-QC
    // designates; once sent, the V-QC changes nothing.
    let mut driver = started(&committee, validator(0));
    let other = committee.leader_block_with(
        ONE,
        committee.genesis().vqc(),
        committee.genesis().history(),
    );
    observe(&mut driver, vec![Artifact::LeaderBlock(other.clone())]);
    let now = driver.now();
    let (_, capabilities) = driver
        .machine_mut()
        .finish_view(&genesis, false, now)
        .unwrap();
    persist_capabilities(&mut driver, capabilities);
    let vote = sent(&driver, ONE).unwrap();
    assert!(vote.is_final());
    assert_eq!(vote.leader(), Some(digest_of(&other)));
    let (_, capabilities) = driver
        .machine_mut()
        .finish_view(&genesis, true, now)
        .unwrap();
    assert!(capabilities.is_empty());
}

#[test]
fn optimisation_a_ends_a_view_without_a_proposal_at_the_grace() {
    let committee = committee(107);
    let mut driver = started(&committee, validator(0));
    enter_two(&mut driver, &committee);
    let timers = driver.machine().current_timers();
    // View two's emission state is undefined: at the grace the node declares every chain and
    // sends its leaderless final vote, before D_stop declares anything.
    elapse(&mut driver, timers.grace - 1);
    assert!(!driver.machine().final_sent(TWO));
    elapse(&mut driver, 1);
    let vote = sent(&driver, TWO).expect("a final vote is sent at the grace");
    assert!(vote.is_final());
    assert_eq!(vote.leader(), None);
    assert_eq!(vote.declared().len(), committee.codec().chains());
}

#[test]
fn optimisation_b_skips_a_silent_leader_at_entry() {
    let committee = committee(108);
    let leader = committee.config.leader(TWO);
    let silence = started(&committee, validator(0))
        .machine()
        .current_timers()
        .quiet;
    // Every validator but view two's leader is heard from just before the entry.
    let heard = |driver: &mut TestDriver, skip: Option<Participant>| {
        for chain in committee.codec().chain_ids() {
            let producer = committee.config.producer(chain).unwrap();
            if producer == Participant::new(0) || Some(producer) == skip {
                continue;
            }
            receive(driver, &path(&committee, chain, 1));
        }
    };

    let mut driver = started(&committee, validator(0));
    elapse(&mut driver, silence + 1);
    heard(&mut driver, Some(leader));
    enter_two(&mut driver, &committee);
    let vote = sent(&driver, TWO).expect("the leader is skipped at entry");
    assert!(vote.is_final());
    assert_eq!(vote.declared().len(), committee.codec().chains());

    // A leader heard from within t_quiet is not skipped.
    let mut driver = started(&committee, validator(0));
    elapse(&mut driver, silence + 1);
    heard(&mut driver, None);
    enter_two(&mut driver, &committee);
    assert!(!driver.machine().final_sent(TWO));
}

#[test]
fn the_grace_doubles_after_a_late_proposal_and_halves_after_a_vote() {
    let committee = committee(109);
    let mut driver = started(&committee, validator(0));
    let base = driver.machine().current_timers().grace;
    let tips = committee.genesis().tips().to_vec();

    // A valid proposal for view one arrives after this node's leaderless final vote for it: the
    // grace doubles from the next view on.
    let one = enter_two(&mut driver, &committee);
    assert_eq!(driver.machine().current_timers().grace, base);
    deliver(
        &mut driver,
        vec![Artifact::LeaderBlock(committee.leader_block(ONE))],
    );
    assert!(driver.machine().valid_proposal(ONE).is_some());
    let three = View::new(3);
    let two = enter_next_view(
        &mut driver,
        vqc_above(&committee, &one, false, tips.clone(), &[]),
    );
    assert_eq!(driver.machine().current_timers().grace, 2 * base);

    // Voting for a leader block halves it.
    let block = leader_block(&committee, committee.config.leader(three), three, &two);
    deliver(&mut driver, vec![Artifact::LeaderBlock(block.clone())]);
    assert_eq!(driver.machine().notarised(three), Some(digest_of(&block)));
    enter_next_view(&mut driver, vqc_above(&committee, &two, false, tips, &[]));
    assert_eq!(driver.machine().current_timers().grace, base);
}

#[test]
fn a_vote_held_back_by_persistence_halves_the_grace_once() {
    let committee = committee(115);
    // A production seed long enough that the grace's cap, twice `t_max`, stays above four
    // times its floor.
    let tuning = Tuning {
        theta_initial: Duration::from_millis(200),
        ..Tuning::default()
    };
    let mut driver = started_with(tuned(&committee, validator(0), tuning));
    let base = driver.machine().current_timers().grace;
    let tips = committee.genesis().tips().to_vec();

    // Valid proposals for views one and two arrive after this node's leaderless final votes for
    // them: the grace doubles twice.
    let one = enter_two(&mut driver, &committee);
    deliver(
        &mut driver,
        vec![Artifact::LeaderBlock(committee.leader_block(ONE))],
    );
    let two = enter_next_view(
        &mut driver,
        vqc_above(&committee, &one, false, tips.clone(), &[]),
    );
    let late = leader_block(&committee, committee.config.leader(TWO), TWO, &one);
    deliver(&mut driver, vec![Artifact::LeaderBlock(late)]);
    let three = enter_next_view(
        &mut driver,
        vqc_above(&committee, &two, false, tips.clone(), &[]),
    );
    assert_eq!(driver.machine().current_timers().grace, 4 * base);

    // With the persistence pipeline full, the vote for view four's leader block waits, and the
    // view drive retries it on every wake until a barrier is acknowledged.
    let four = View::new(4);
    let mut journals = VecDeque::new();
    let vqc = Arc::new(Artifact::Vqc(committee.vqc(four)));
    let refused = loop {
        match driver
            .machine_mut()
            .reserve_test_effect(DurableEffect::broadcast(Arc::clone(&vqc)))
        {
            Ok(step) => {
                driver.record(step.capabilities());
                journals.extend(
                    step.journals()
                        .into_iter()
                        .map(|journal| journal.job.clone()),
                );
            }
            Err(error) => break error,
        }
    };
    assert_eq!(refused, StepError::PersistenceCapacity);
    let block = leader_block(&committee, committee.config.leader(four), four, &three);
    observe(&mut driver, vec![Artifact::LeaderBlock(block.clone())]);
    for tick in driver.advance(10 * base).unwrap() {
        driver.settle(tick, Until::Quiesce);
    }
    assert_eq!(driver.machine().notarised(four), None);
    while let Some(journal) = journals.pop_front() {
        let step = driver.persist(&journal, Until::Quiesce);
        journals.extend(
            step.journals()
                .into_iter()
                .map(|journal| journal.job.clone()),
        );
    }
    quiesce(&mut driver);
    assert_eq!(driver.machine().notarised(four), Some(digest_of(&block)));
    enter_next_view(&mut driver, vqc_above(&committee, &three, false, tips, &[]));
    assert_eq!(driver.machine().current_timers().grace, 2 * base);
}

#[test]
fn votes_repeat_only_on_change_and_at_most_every_vote_interval() {
    let committee = committee(110);
    let mut driver = started(&committee, validator(0));
    let eta = driver
        .machine()
        .profile()
        .tuning()
        .vote_interval
        .as_millis() as u64;
    // Nothing changed: nothing is sent.
    elapse(&mut driver, eta);
    assert!(sent(&driver, ONE).is_none());

    // An acceptance changes the pre-vote, which waits for the vote interval since the last vote.
    let chain = ChainId::new(1);
    let blocks = path(&committee, chain, 2);
    receive(&mut driver, &blocks[..1]);
    validate(&mut driver, &blocks[0], BlockValidity::Valid);
    let vote = sent(&driver, ONE).expect("the interval since start has passed");
    assert_eq!(vote.tips()[chain.index()], reference(&blocks[0]));
    receive(&mut driver, &blocks[1..]);
    validate(&mut driver, &blocks[1], BlockValidity::Valid);
    assert_eq!(
        sent(&driver, ONE).unwrap().tips()[chain.index()],
        reference(&blocks[0])
    );
    elapse(&mut driver, eta);
    assert_eq!(
        sent(&driver, ONE).unwrap().tips()[chain.index()],
        reference(&blocks[1])
    );
}
