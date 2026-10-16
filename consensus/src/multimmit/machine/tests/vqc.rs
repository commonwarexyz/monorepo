//! The V-QC store: which V-QCs are held, the tips and history each fixes, the final votes it adds
//! to the pool, the bound per view, and discarding once a leader block is pinned.

use crate::{
    Epochable as _,
    multimmit::{
        algebra::reference::{Tree, tip},
        machine::{
            input::{ObservationStatus, Rejection, StepStatus},
            testing::{
                Drive as _, cohort,
                fixtures::{
                    TestDriver, block, certifiers, committee, deliver, digest, enter_next_view,
                    final_above, path, reference, started, validator, vqc_above, vqc_of,
                },
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{self, Artifact, ChainId, ChainSet, FinalTally, HistoryRecord, LeaderBlock, Vqc},
    },
    types::{Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};

const ONE: View = View::new(1);
const TWO: View = View::new(2);
const CHAIN: ChainId = ChainId::new(1);

/// Delivers `vqc` and returns its pre-verification outcome.
fn observe_status(driver: &mut TestDriver, vqc: Vqc<MinPk, Digest>) -> ObservationStatus {
    let step = driver
        .submit(cohort::<Sha256, _>(vec![Artifact::Vqc(vqc)]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("an observation is classified");
    };
    results[0].status()
}

/// Returns the held V-QC `vqc`.
fn held(driver: &TestDriver, vqc: &Vqc<MinPk, Digest>) -> Option<HeldVqc<Digest>> {
    driver.machine().held_vqc(&vqc.id::<Sha256>())
}

/// Returns leaderless final votes of view one by `signers` endorsing the genesis tips and
/// declaring `declared`.
fn genesis_finals(
    committee: &Committee<MinPk>,
    signers: impl IntoIterator<Item = u32>,
    declared: &[u32],
) -> Vec<(Participant, types::VoteContent<Digest>)> {
    let mut chains = ChainSet::empty(committee.codec().chains());
    for chain in declared {
        chains.insert(ChainId::new(*chain));
    }
    let endorsement = committee.endorsement(chains, committee.genesis().tips().to_vec());
    let content = committee.content(ONE, None, true, endorsement);
    signers
        .into_iter()
        .map(|signer| (Participant::new(signer), content.clone()))
        .collect()
}

#[test]
fn a_vqc_is_held_with_the_tips_and_history_the_reference_computes() {
    let committee = committee(200);
    let genesis = HeldVqc::<Digest>::genesis(committee.genesis());
    let blocks = path(&committee, CHAIN, 3);
    let fork = block(
        &committee,
        &committee.genesis().tips()[CHAIN.index()],
        b"fork",
    );

    // Two certifiers endorse the third block, one the second, one a fork, one the genesis object:
    // the second block is the highest with n - 3f endorsers.
    let tips_at = |tip| {
        let mut tips = committee.genesis().tips().to_vec();
        tips[CHAIN.index()] = tip;
        tips
    };
    let endorsed = [
        reference(&blocks[2]),
        reference(&blocks[2]),
        reference(&blocks[1]),
        reference(&fork),
        committee.genesis().tips()[CHAIN.index()],
    ];
    let contents = certifiers(&committee)
        .into_iter()
        .zip(endorsed)
        .map(|(signer, tip)| {
            (
                signer,
                final_above(&committee, &genesis, false, tips_at(tip)),
            )
        })
        .collect::<Vec<_>>();
    let mut headers = blocks.clone();
    headers.push(fork.clone());
    let vqc = vqc_of(&committee, &genesis, contents.clone(), &headers);

    let mut driver = started(&committee, validator(0));
    let entered = enter_next_view(&mut driver, vqc);

    let mut tree = Tree::new(committee.config.epoch());
    let base = committee.genesis().tips()[CHAIN.index()];
    let mut parent = base;
    for block in &blocks {
        parent = tree.extend::<Sha256>(&parent, block.header().body_digest());
    }
    tree.extend::<Sha256>(&base, fork.header().body_digest());
    let votes = contents
        .iter()
        .map(|(signer, content)| (*signer, content.tips()[CHAIN.index()]))
        .collect::<Vec<_>>();
    let expected = tip(
        &tree,
        &base,
        committee.codec().window().cap(),
        committee.codec().tip_quorum(),
        &votes,
    );
    assert_eq!(expected, reference(&blocks[1]));
    let tips = tips_at(expected);
    assert_eq!(entered.tips.as_ref(), tips.as_slice());
    assert_eq!(
        entered.history,
        HistoryRecord::new(genesis.history, tips)
            .unwrap()
            .commitment::<Sha256>()
    );
    let stored = driver.machine().stored_vqc(&entered.id).unwrap();
    assert_eq!(stored.record.commitment::<Sha256>(), entered.history);
    assert_eq!(stored.designated, None);

    // The certificate's final votes count as received, and its paths' headers are held.
    // This node's own late final vote follows them.
    let finals = driver
        .machine()
        .finals(ONE)
        .map(|(sender, _)| sender)
        .collect::<Vec<_>>();
    assert_eq!(finals[..finals.len() - 1], certifiers(&committee));
    assert_eq!(finals.last(), Some(&Participant::new(0)));
    for block in blocks.iter().chain([&fork]) {
        assert!(
            driver
                .machine()
                .chain_layer()
                .headers
                .get(&reference(block))
                .is_some()
        );
    }
}

#[test]
fn malformed_vqcs_are_dropped_without_entering_a_view() {
    let committee = committee(201);
    let genesis = HeldVqc::<Digest>::genesis(committee.genesis());
    let blocks = path(&committee, CHAIN, 1);
    let mut tips = committee.genesis().tips().to_vec();
    tips[CHAIN.index()] = reference(&blocks[0]);
    let dropped = |vqc: Vqc<MinPk, Digest>| {
        let mut driver = started(&committee, validator(0));
        deliver(&mut driver, vec![Artifact::Vqc(vqc.clone())]);
        assert!(held(&driver, &vqc).is_none());
        assert_eq!(driver.inspect().view(), ONE);
        assert!(
            !driver
                .inspect()
                .ready_artifacts()
                .contains(&Artifact::Vqc(vqc).id::<Sha256>())
        );
    };

    // A tip above the base without a resolution path.
    let content = final_above(&committee, &genesis, false, tips);
    let contents = certifiers(&committee)
        .into_iter()
        .map(|signer| (signer, content.clone()))
        .collect();
    dropped(committee.vqc_from(genesis.id, contents, Vec::new()));

    // Votes designating a leader block whose commitment is not the parent's.
    let wrong = LeaderBlock::new(committee.round(ONE), genesis.id, digest(b"wrong history"))
        .unwrap()
        .digest::<Sha256>();
    let content = committee.content(ONE, Some(wrong), true, committee.genesis_endorsement());
    let contents = certifiers(&committee)
        .into_iter()
        .map(|signer| (signer, content.clone()))
        .collect();
    dropped(committee.vqc_from(genesis.id, contents, Vec::new()));

    // A parent of the wrong view: final votes of view two above the genesis V-QC.
    let content = committee.content(TWO, None, true, committee.genesis_endorsement());
    let contents = certifiers(&committee)
        .into_iter()
        .map(|signer| (signer, content.clone()))
        .collect();
    dropped(committee.vqc_from(genesis.id, contents, Vec::new()));

    // A transcript of fewer or more than n - f final votes cannot be built or decoded.
    let quorum = committee.codec().view_quorum() as u32;
    for count in [quorum - 1, quorum + 1] {
        assert_eq!(
            FinalTally::from_contents(
                genesis_finals(&committee, 0..count, &[]),
                Vec::new(),
                committee.codec()
            ),
            Err(types::Error::Quorum)
        );
    }

    // A well-formed one designating the genesis-anchored leader block is held.
    let mut driver = started(&committee, validator(0));
    let vqc = vqc_above(
        &committee,
        &genesis,
        true,
        committee.genesis().tips().to_vec(),
        &[],
    );
    deliver(&mut driver, vec![Artifact::Vqc(vqc.clone())]);
    assert!(held(&driver, &vqc).is_some());
    assert_eq!(driver.inspect().view(), TWO);
}

#[test]
fn a_view_holds_at_most_n_vqcs() {
    let committee = committee(202);
    let participants = committee.codec().participants() as u32;
    let mut driver = started(&committee, validator(0));
    let genesis = HeldVqc::<Digest>::genesis(committee.genesis());
    // Final votes declaring different chains make different V-QCs of one view.
    let declared = (0..participants)
        .map(|chain| vec![chain])
        .chain([vec![0, 1]])
        .collect::<Vec<_>>();
    let vqcs = declared
        .iter()
        .map(|chains| {
            committee.vqc_from(
                genesis.id,
                genesis_finals(&committee, 1..participants, chains),
                Vec::new(),
            )
        })
        .collect::<Vec<_>>();
    for vqc in &vqcs[..participants as usize] {
        deliver(&mut driver, vec![Artifact::Vqc(vqc.clone())]);
        assert!(held(&driver, vqc).is_some());
    }
    assert_eq!(
        observe_status(&mut driver, vqcs[participants as usize].clone()),
        ObservationStatus::Rejected(Rejection::CertificatesFull)
    );
}

#[test]
fn a_vqc_a_leader_block_waits_on_is_held_beyond_the_view_bound() {
    let committee = committee(204);
    let participants = committee.codec().participants() as u32;
    let leader = committee.config.leader(TWO);
    let own = (leader.get() + 1) % participants;
    let genesis = HeldVqc::<Digest>::genesis(committee.genesis());
    let vqcs = (0..participants)
        .map(|chain| vec![chain])
        .chain([vec![0, 1]])
        .map(|chains| {
            committee.vqc_from(
                genesis.id,
                genesis_finals(&committee, 1..participants, &chains),
                Vec::new(),
            )
        })
        .collect::<Vec<_>>();
    let (bound, referenced) = vqcs.split_at(participants as usize);
    let referenced = &referenced[0];
    let parent = enter_next_view(&mut started(&committee, validator(own)), referenced.clone());

    // Other V-QCs fill view one before the leader of view two proposes on another one.
    let mut driver = started(&committee, validator(own));
    for vqc in bound {
        deliver(&mut driver, vec![Artifact::Vqc(vqc.clone())]);
    }
    let block = LeaderBlock::new(committee.round(TWO), parent.id, parent.history).unwrap();
    let signed = committee.signers[usize::from(leader)]
        .sign_leader_block(block)
        .unwrap();
    deliver(&mut driver, vec![Artifact::LeaderBlock(signed)]);
    assert!(driver.machine().valid_proposal(TWO).is_none());

    // The proposal's parent is held although the view is full, and the proposal becomes valid.
    deliver(&mut driver, vec![Artifact::Vqc(referenced.clone())]);
    assert_eq!(held(&driver, referenced), Some(parent));
    assert!(driver.machine().valid_proposal(TWO).is_some());
}

#[test]
fn off_chain_vqcs_are_discarded_once_a_leader_block_is_pinned() {
    let committee = committee(203);
    let genesis = HeldVqc::<Digest>::genesis(committee.genesis());
    let tips = committee.genesis().tips().to_vec();
    let mut driver = started(&committee, validator(0));

    // Two V-QCs of view one: the node enters view two on the first.
    let first = vqc_above(&committee, &genesis, false, tips.clone(), &[]);
    let entered = enter_next_view(&mut driver, first);
    let second = committee.vqc_from(
        genesis.id,
        genesis_finals(&committee, 0..5, &[]),
        Vec::new(),
    );
    deliver(&mut driver, vec![Artifact::Vqc(second.clone())]);
    let second = held(&driver, &second).expect("a second V-QC of a view is held");

    // A V-QC of view two above the second, whose n - f votes are for the leader block naming it,
    // pins that block: the first V-QC of view one is off its chain.
    let third = vqc_above(&committee, &second, true, tips, &[]);
    let pinned = enter_next_view(&mut driver, third);
    assert_eq!(pinned.view, TWO);
    assert!(driver.machine().held_vqc(&entered.id).is_none());
    assert!(driver.machine().held_vqc(&second.id).is_some());
    assert_eq!(
        driver.machine().stored_vqc(&pinned.id).unwrap().designated,
        Some(
            LeaderBlock::new(committee.round(TWO), second.id, second.history)
                .unwrap()
                .digest::<Sha256>()
        )
    );
}
