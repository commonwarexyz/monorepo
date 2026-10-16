//! Scripted twins: each objective equivocation pattern of
//! [`accountability`](crate::multimmit::machine::accountability) quarantines its signer and nobody
//! else, a split that never heals discloses each half to one side only, and a silent leader cannot
//! stop the correct nodes.

use super::twins;
use crate::{
    multimmit::{
        config::Tuning,
        machine::world::{Broadcast, Config, Router, Verification, World},
        mocks::Committee,
        types::{Artifact, BlockRef, ChainId, ChainSet, VoteContent},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest,
};
use std::{collections::BTreeSet, sync::Arc};

/// Simulated time a run may take.
const BUDGET: u64 = 60_000;

/// The Byzantine participant of the scripted worlds.
const BYZANTINE: Participant = Participant::new(5);

/// Returns a world of the five correct participants of a six-member committee; the sixth,
/// [`BYZANTINE`], runs no machine and speaks only through what a test injects.
fn silent(seed: u64) -> World {
    let committee = Committee::builder(seed, 6).build();
    let config = Config {
        nodes: (0..5).map(Participant::new).collect(),
        byzantine: BTreeSet::from([BYZANTINE]),
        tuning: Tuning::default(),
        verification: Verification::Real,
        committee,
    };
    World::new(config, Broadcast)
}

/// Runs the fair suffix until every correct node resolved `views` more views.
fn progress<R: Router>(world: &mut World<R>, views: u64) {
    let furthest = world.resolved_views().into_iter().max().unwrap_or_default();
    let target = View::new(furthest.get() + views);
    world.run_to(BUDGET, target, View::new(target.get() - 1));
}

/// Returns a vote of view one by the committee's scheme.
fn vote(
    committee: &Committee<MinPk>,
    leader: Option<Digest>,
    final_: bool,
    declared: &[u32],
) -> VoteContent<Digest> {
    let chains = committee.codec().chains();
    let declared =
        ChainSet::from_chains(chains, declared.iter().copied().map(ChainId::new)).unwrap();
    let tips = committee.genesis().tips().to_vec();
    committee.content(
        View::new(1),
        leader,
        final_,
        committee.endorsement(declared, tips),
    )
}

/// Returns [`BYZANTINE`]'s update `seq` carrying `content` and naming every chain.
fn update(
    committee: &Committee<MinPk>,
    content: &VoteContent<Digest>,
    seq: u32,
) -> Artifact<MinPk, Digest> {
    let unrelated = committee
        .genesis()
        .tips()
        .iter()
        .map(|tip| BlockRef::new(tip.chain(), tip.height(), Sha256::hash(&[b"unrelated"])))
        .collect::<Vec<_>>();
    Artifact::Update(committee.update(BYZANTINE, content, &unrelated, seq))
}

/// Delivers `statements` to node zero, one message each, runs two more views, and checks that
/// node zero quarantined [`BYZANTINE`] and no node quarantined anyone else.
fn convicts(mut world: World, statements: Vec<Artifact<MinPk, Digest>>) {
    for statement in statements {
        world.inject(0, vec![Arc::new(statement)]);
    }
    progress(&mut world, 2);
    let quarantines = world.oracle().quarantines();
    assert!(
        quarantines.contains(&(0, BYZANTINE)),
        "node zero quarantines the signer: {quarantines:?}"
    );
    assert!(
        quarantines
            .iter()
            .all(|(_, participant)| *participant == BYZANTINE)
    );
}

#[test]
fn two_finals_of_one_tag_quarantine_their_signer() {
    let world = silent(500);
    let committee = world.committee();
    let statements = vec![
        update(committee, &vote(committee, None, true, &[]), 1),
        update(committee, &vote(committee, None, true, &[0]), 2),
    ];
    convicts(world, statements);
}

#[test]
fn votes_for_two_leader_blocks_of_one_view_quarantine_their_signer() {
    let world = silent(501);
    let committee = world.committee();
    let statements = vec![
        update(
            committee,
            &vote(committee, Some(Sha256::hash(&[b"x"])), false, &[]),
            1,
        ),
        update(
            committee,
            &vote(committee, Some(Sha256::hash(&[b"y"])), false, &[]),
            2,
        ),
    ];
    convicts(world, statements);
}

#[test]
fn incomparable_votes_of_one_tag_quarantine_their_signer() {
    let world = silent(502);
    let committee = world.committee();
    let statements = vec![
        update(committee, &vote(committee, None, false, &[0]), 1),
        update(committee, &vote(committee, None, false, &[1]), 2),
    ];
    convicts(world, statements);
}

#[test]
fn a_vote_above_a_final_of_its_tag_quarantines_its_signer() {
    let world = silent(503);
    let committee = world.committee();
    let statements = vec![
        update(committee, &vote(committee, None, true, &[]), 1),
        update(committee, &vote(committee, None, false, &[0]), 2),
    ];
    convicts(world, statements);
}

#[test]
fn two_headers_at_one_height_quarantine_their_producer() {
    let world = silent(504);
    let committee = world.committee();
    // Participant five produces chain five.
    let genesis = committee.genesis().tips()[5];
    let headers = [b"left".as_slice(), b"right"]
        .map(|body| committee.sign_header(committee.header(&genesis, Sha256::hash(&[body]))));
    // Both headers travel in one message, so both are verified before either is accepted.
    let mut world = world;
    world.inject(
        0,
        headers
            .into_iter()
            .map(|header| Arc::new(Artifact::TransactionBlock(header)))
            .collect(),
    );
    convicts(world, Vec::new());
}

#[test]
fn two_leader_blocks_for_one_view_quarantine_their_leader() {
    let mut world = silent(505);
    let view = (2..)
        .map(View::new)
        .find(|view| world.committee().config.leader(*view) == BYZANTINE)
        .expect("the schedule rotates through every participant");
    // Node zero enters the view, holding the V-QC both blocks name as their parent: one block
    // carries the parent's history, the other a forged one.
    world.run_until(BUDGET, |world| world.nodes()[0].machine().view() >= view);
    let (parent, history) = world.entry(0, view);
    let committee = world.committee();
    let statements = vec![
        Artifact::LeaderBlock(committee.leader_block_with(view, parent, history)),
        Artifact::LeaderBlock(committee.leader_block_with(
            view,
            parent,
            Sha256::hash(&[b"forged"]),
        )),
    ];
    convicts(world, statements);
}

#[test]
fn a_producer_splitting_the_correct_nodes_across_its_branches_does_not_stall_assembly() {
    // Participants zero to two see the first half of participant five, three and four the second,
    // and the split never heals: each side's final votes must resolve at the other side's
    // assemblers for a view's V-QC to form.
    let mut world = twins(
        510,
        6,
        &[BYZANTINE.get()],
        |participant, _| participant.get() >= 3,
        Verification::Real,
    );
    progress(&mut world, 8);
    let chain = ChainId::new(BYZANTINE.get());
    let accepted = |node| world.oracle().accepted(node, chain, Height::new(1));
    let first = accepted(0).expect("node zero accepted chain five's first header");
    let second = accepted(3).expect("node three accepted chain five's first header");
    assert_ne!(first, second, "the halves' first headers differ");
    assert!((0..3).all(|node| accepted(node) == Some(first)));
    assert!((3..5).all(|node| accepted(node) == Some(second)));
    assert!(
        world
            .oracle()
            .quarantines()
            .iter()
            .all(|(_, participant)| *participant == BYZANTINE)
    );
    world.check_replay();
}

#[test]
fn two_producers_splitting_the_correct_nodes_differently_keep_views_resolving() {
    // Participants nine and ten equivocate and the split never heals: the nine correct nodes
    // split five to four across chain nine's branches and four to five across chain ten's.
    let mut world = twins(
        512,
        11,
        &[9, 10],
        |participant, twin| match twin {
            0 => participant.get() >= 5,
            _ => participant.get() < 4,
        },
        Verification::Real,
    );
    progress(&mut world, 6);
    assert!(
        world
            .oracle()
            .quarantines()
            .iter()
            .all(|(_, participant)| participant.get() >= 9)
    );
    world.check_replay();
}

#[test]
fn a_silent_leader_cannot_stop_the_correct_nodes() {
    let mut world = silent(511);
    let led = (1..=12)
        .map(View::new)
        .filter(|view| world.committee().config.leader(*view) == BYZANTINE)
        .collect::<Vec<_>>();
    assert!(led.len() >= 2, "the run covers at least two silent views");
    world.run_to(BUDGET, View::new(12), View::new(11));
    assert!(world.oracle().quarantines().is_empty());
    world.check_replay();
}
