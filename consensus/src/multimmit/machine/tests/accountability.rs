//! Accountability: each objective equivocation pattern quarantines its signer once, honest
//! reordering and comparable regressions quarantine nobody, and a certificate relaying a
//! conflicting statement blames the statement's signer, never anyone else.

use crate::{
    multimmit::{
        config::Role,
        machine::{
            accountability::{Equivocation, equivocation},
            capability::Capability,
            testing::{
                CapabilitiesExt as _, Drive as _, Until, cohort,
                fixtures::{
                    Block, TestDriver, block, committee, deliver, digest, reference, started,
                    vqc_above,
                },
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{Artifact, BlockRef, ChainId, ChainSet, LeaderBlock, VoteContent},
    },
    types::{Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};

const ONE: View = View::new(1);
const SENDER: Participant = Participant::new(3);
const FIRST: ChainId = ChainId::new(1);
const SECOND: ChainId = ChainId::new(2);

/// Returns an observer holding one buffered block above genesis on each of [`FIRST`] and
/// [`SECOND`], and those blocks.
fn observer(committee: &Committee<MinPk>) -> (TestDriver, Block, Block) {
    let mut driver = started(committee, Role::Observer);
    let genesis = committee.genesis().tips();
    let first = block(committee, &genesis[FIRST.index()], b"first");
    let second = block(committee, &genesis[SECOND.index()], b"second");
    offer(
        &mut driver,
        vec![
            Artifact::TransactionBlock(first.clone()),
            Artifact::TransactionBlock(second.clone()),
        ],
    );
    (driver, first, second)
}

/// Returns the genesis tips with `raised` substituted on their chains.
fn tips(committee: &Committee<MinPk>, raised: &[BlockRef<Digest>]) -> Vec<BlockRef<Digest>> {
    let mut tips = committee.genesis().tips().to_vec();
    for tip in raised {
        tips[tip.chain().index()] = *tip;
    }
    tips
}

/// Returns a vote of view one for `leader`, final when `final_`, declaring `declared` and
/// endorsing `tips`.
fn vote(
    committee: &Committee<MinPk>,
    leader: Option<Digest>,
    final_: bool,
    declared: &[ChainId],
    tips: Vec<BlockRef<Digest>>,
) -> VoteContent<Digest> {
    let chains = committee.codec().chains();
    let declared = ChainSet::from_chains(chains, declared.iter().copied()).unwrap();
    committee.content(ONE, leader, final_, committee.endorsement(declared, tips))
}

/// Delivers `signer`'s update `seq` carrying `content` and naming every chain, and returns
/// the quarantines its admission issued.
fn send(
    driver: &mut TestDriver,
    committee: &Committee<MinPk>,
    signer: Participant,
    content: &VoteContent<Digest>,
    seq: u32,
) -> Vec<Vec<Participant>> {
    let unrelated = committee
        .genesis()
        .tips()
        .iter()
        .map(|tip| BlockRef::new(tip.chain(), tip.height(), digest(b"unrelated")))
        .collect::<Vec<_>>();
    let update = committee.update(signer, content, &unrelated, seq);
    offer(driver, vec![Artifact::Update(update)])
}

/// Observes `artifacts`, verifies those admission accepted, and returns the quarantines issued.
fn offer(
    driver: &mut TestDriver,
    artifacts: Vec<Artifact<MinPk, Digest>>,
) -> Vec<Vec<Participant>> {
    let observed = driver.submit(cohort::<Sha256, _>(artifacts)).unwrap();
    let job = observed
        .effects()
        .iter()
        .find_map(|capability| match capability {
            Capability::Verify(job) => Some(job.clone()),
            _ => None,
        });
    let step = job.map_or(observed, |job| driver.verify(&job, true, Until::Quiesce));
    step.capabilities
        .iter()
        .filter_map(|capability| match capability {
            Capability::Quarantine(participants) => Some(participants.clone()),
            _ => None,
        })
        .collect()
}

/// Returns the participants the machine proved faulty.
fn quarantined(driver: &TestDriver, committee: &Committee<MinPk>) -> Vec<Participant> {
    (0..committee.codec().participants())
        .map(Participant::from_usize)
        .filter(|participant| driver.machine().quarantined(*participant))
        .collect()
}

#[test]
fn a_correct_senders_votes_of_one_tag_never_equivocate() {
    let committee = committee(600);
    let genesis = committee.genesis().tips();
    let first = reference(&block(&committee, &genesis[FIRST.index()], b"first"));
    let leader = Some(digest(b"leader"));
    let statements = [
        vote(&committee, None, false, &[], tips(&committee, &[])),
        vote(&committee, None, false, &[], tips(&committee, &[first])),
        vote(&committee, leader, false, &[], tips(&committee, &[first])),
        vote(
            &committee,
            leader,
            false,
            &[SECOND],
            tips(&committee, &[first]),
        ),
        vote(
            &committee,
            leader,
            true,
            &[SECOND],
            tips(&committee, &[first]),
        ),
    ];
    for a in &statements {
        for b in &statements {
            assert_eq!(equivocation(a, b), None, "{a:?} and {b:?}");
        }
    }
}

#[test]
fn two_finals_of_one_tag_quarantine_their_signer_once() {
    let committee = committee(601);
    let (mut driver, first, _) = observer(&committee);
    let one = vote(&committee, None, true, &[], tips(&committee, &[]));
    let two = vote(
        &committee,
        None,
        true,
        &[],
        tips(&committee, &[reference(&first)]),
    );
    assert_eq!(equivocation(&one, &two), Some(Equivocation::Finals));

    assert!(send(&mut driver, &committee, SENDER, &one, 1).is_empty());
    // The second final is refused by the pool but verified as evidence.
    assert_eq!(
        send(&mut driver, &committee, SENDER, &two, 2),
        vec![vec![SENDER]]
    );
    assert_eq!(quarantined(&driver, &committee), vec![SENDER]);
    assert_eq!(
        driver
            .machine()
            .latest_vote(SENDER, ONE)
            .map(|vote| vote.as_ref().clone()),
        Some(one),
        "evidence is never read as a vote"
    );

    // Further evidence against a quarantined signer issues nothing.
    let three = vote(&committee, None, true, &[FIRST], tips(&committee, &[]));
    assert!(send(&mut driver, &committee, SENDER, &three, 3).is_empty());
}

#[test]
fn votes_for_two_leader_blocks_quarantine_their_signer() {
    let committee = committee(602);
    let (mut driver, _, _) = observer(&committee);
    let genesis = tips(&committee, &[]);
    let one = vote(&committee, Some(digest(b"x")), false, &[], genesis.clone());
    let two = vote(&committee, Some(digest(b"y")), false, &[], genesis);
    assert_eq!(equivocation(&one, &two), Some(Equivocation::Leaders));
    send(&mut driver, &committee, SENDER, &one, 1);
    assert_eq!(
        send(&mut driver, &committee, SENDER, &two, 2),
        vec![vec![SENDER]]
    );
}

#[test]
fn incomparable_votes_quarantine_and_comparable_regressions_do_not() {
    let committee = committee(603);
    let (mut driver, first, second) = observer(&committee);
    let (first, second) = (reference(&first), reference(&second));
    let high = vote(
        &committee,
        None,
        false,
        &[],
        tips(&committee, &[first, second]),
    );
    let low = vote(&committee, None, false, &[], tips(&committee, &[]));
    let crossed = vote(&committee, None, false, &[], tips(&committee, &[second]));
    let declared = vote(&committee, None, false, &[FIRST], tips(&committee, &[]));
    let other = vote(&committee, None, false, &[SECOND], tips(&committee, &[]));
    assert_eq!(equivocation(&high, &low), None);
    assert_eq!(
        equivocation(&declared, &other),
        Some(Equivocation::Incomparable)
    );
    // Higher tips with fewer declared chains are below neither vote.
    let raised = vote(&committee, None, false, &[], tips(&committee, &[first]));
    assert_eq!(
        equivocation(&declared, &raised),
        Some(Equivocation::Incomparable)
    );
    // A leaderless vote is below the same vote naming a leader block.
    let leading = vote(
        &committee,
        Some(digest(b"x")),
        false,
        &[],
        tips(&committee, &[]),
    );
    assert_eq!(equivocation(&leading, &low), None);

    // A regression lower on every chain, read in order or arriving late, proves nothing.
    let honest = Participant::new(1);
    assert!(send(&mut driver, &committee, honest, &high, 2).is_empty());
    assert!(send(&mut driver, &committee, honest, &low, 1).is_empty());
    assert!(send(&mut driver, &committee, honest, &low, 3).is_empty());

    // One chain higher in each vote proves the signer faulty.
    let faulty = Participant::new(2);
    let only_first = vote(&committee, None, false, &[], tips(&committee, &[first]));
    assert!(send(&mut driver, &committee, faulty, &only_first, 1).is_empty());
    assert_eq!(
        send(&mut driver, &committee, faulty, &crossed, 2),
        vec![vec![faulty]]
    );
    assert_eq!(quarantined(&driver, &committee), vec![faulty]);
}

#[test]
fn a_vote_above_a_final_of_its_tag_quarantines_its_signer() {
    let committee = committee(604);
    let (mut driver, first, _) = observer(&committee);
    let final_ = vote(&committee, None, true, &[], tips(&committee, &[]));
    let after = vote(
        &committee,
        None,
        false,
        &[],
        tips(&committee, &[reference(&first)]),
    );
    assert_eq!(
        equivocation(&final_, &after),
        Some(Equivocation::AfterFinal)
    );
    send(&mut driver, &committee, SENDER, &final_, 1);
    assert_eq!(
        send(&mut driver, &committee, SENDER, &after, 2),
        vec![vec![SENDER]]
    );
}

#[test]
fn two_headers_at_one_height_quarantine_their_producer() {
    let committee = committee(605);
    let (mut driver, first, _) = observer(&committee);
    let genesis = committee.genesis().tips();
    let conflicting = block(&committee, &genesis[FIRST.index()], b"conflicting");
    let producer = committee.config.producer(FIRST).unwrap();
    assert_eq!(
        offer(&mut driver, vec![Artifact::TransactionBlock(conflicting)]),
        vec![vec![producer]]
    );
    assert_eq!(quarantined(&driver, &committee), vec![producer]);

    // The same header again proves nothing new.
    assert!(offer(&mut driver, vec![Artifact::TransactionBlock(first)]).is_empty());
}

#[test]
fn two_leader_blocks_for_one_view_quarantine_the_leader() {
    let committee = committee(606);
    let mut driver = started(&committee, Role::Observer);
    let genesis = committee.genesis();
    let blocks = vec![
        Artifact::LeaderBlock(committee.leader_block(ONE)),
        Artifact::LeaderBlock(committee.leader_block_with(ONE, genesis.vqc(), digest(b"other"))),
    ];
    let leader = committee.config.leader(ONE);
    assert_eq!(offer(&mut driver, blocks), vec![vec![leader]]);
}

#[test]
fn a_certificate_relaying_a_conflicting_statement_blames_only_its_signer() {
    let committee = committee(607);
    let (mut driver, first, _) = observer(&committee);
    let genesis = HeldVqc::genesis(committee.genesis());

    // The sender's leaderless final at the genesis tips, then a V-QC recording its final at a
    // higher tip: the V-QC's aggregate authenticates the second final.
    let final_ = vote(&committee, None, true, &[], tips(&committee, &[]));
    send(&mut driver, &committee, SENDER, &final_, 1);
    let raised = tips(&committee, &[reference(&first)]);
    deliver(
        &mut driver,
        vec![Artifact::Vqc(vqc_above(
            &committee,
            &genesis,
            false,
            raised,
            &[first],
        ))],
    );
    assert_eq!(quarantined(&driver, &committee), vec![SENDER]);

    // A vote for one leader block, then an L-QC recording the same signer's vote for another.
    let leader =
        LeaderBlock::new(committee.round(View::new(2)), genesis.id, genesis.history).unwrap();
    let signer = Participant::new(4);
    let other = committee.content(
        View::new(2),
        Some(digest(b"other")),
        false,
        committee.genesis_endorsement(),
    );
    send(&mut driver, &committee, signer, &other, 1);
    let certified = committee.content(
        View::new(2),
        Some(leader.digest::<Sha256>()),
        false,
        committee.genesis_endorsement(),
    );
    let contents = (1..=5)
        .map(|participant| (Participant::new(participant), certified.clone()))
        .collect();
    deliver(
        &mut driver,
        vec![Artifact::Lqc(committee.lqc_from(leader, contents))],
    );
    assert_eq!(quarantined(&driver, &committee), vec![SENDER, signer]);
}
