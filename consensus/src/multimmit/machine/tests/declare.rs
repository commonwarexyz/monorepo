//! Declarations: every rule adds chains at the accepted tip's height and never withdraws one or
//! moves its height; the sender caps its tips against the base of the leader block it votes for;
//! rule (ii) applies `t_late` after all but `f` chains finished the view.

use crate::{
    multimmit::{
        machine::{
            DeclarationContext, DeclarationRule,
            input::BlockValidity,
            testing::fixtures::{
                Block, PARTICIPANTS, TestDriver, committee, elapse, enter_next_view, observe, path,
                persist_all, persist_capabilities, quiesce, receive, reference, started, validate,
                validator, vqc_above,
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{Artifact, BlockRef, ChainId, ChainSet, LeaderBlock, VoteContent},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};

const ONE: View = View::new(1);
const TWO: View = View::new(2);

/// Accepts `blocks` of a peer chain in full at the driver's current time.
fn accept(driver: &mut TestDriver, blocks: &[Block]) {
    receive(driver, blocks);
    for block in blocks {
        validate(driver, block, BlockValidity::Valid);
    }
}

/// Returns the chains declared for the current vote tag, with their declaration heights.
fn declared(driver: &mut TestDriver) -> Vec<(ChainId, Height)> {
    let chains = driver
        .machine()
        .profile
        .codec()
        .chain_ids()
        .collect::<Vec<_>>();
    let declarations = driver.machine_mut().declarations();
    chains
        .into_iter()
        .filter_map(|chain| Some((chain, declarations.at(chain)?.height())))
        .collect()
}

/// Returns the chains of `committee` other than `skipped`, each with height `height`.
fn every_chain_but(
    committee: &Committee<MinPk>,
    skipped: &[u32],
    height: impl Fn(ChainId) -> u64,
) -> Vec<(ChainId, Height)> {
    committee
        .codec()
        .chain_ids()
        .filter(|chain| !skipped.contains(&chain.get()))
        .map(|chain| (chain, Height::new(height(chain))))
        .collect()
}

/// Returns the latest vote this node reserved for `view`.
fn sent(driver: &TestDriver, view: View) -> VoteContent<Digest> {
    driver.machine().last_sent(view).unwrap().as_ref().clone()
}

/// Sends a leaderless final vote for view one, then enters view two on a V-QC of view one whose
/// tips are `tips`, resolved through `blocks`.
fn enter_two(
    driver: &mut TestDriver,
    committee: &Committee<MinPk>,
    tips: Vec<BlockRef<Digest>>,
    blocks: &[Block],
) -> HeldVqc<Digest> {
    let genesis = HeldVqc::genesis(committee.genesis());
    let now = driver.now();
    let (_, capabilities) = driver
        .machine_mut()
        .finish_view(&genesis, false, now)
        .unwrap();
    persist_capabilities(driver, capabilities);
    enter_next_view(driver, vqc_above(committee, &genesis, false, tips, blocks))
}

/// Delivers the valid leader block of view two above `parent`, which this node votes for.
fn vote_for_two(driver: &mut TestDriver, committee: &Committee<MinPk>, parent: &HeldVqc<Digest>) {
    let block = LeaderBlock::new(committee.round(TWO), parent.id, parent.history).unwrap();
    let signed = committee.signers[usize::from(committee.config.leader(TWO))]
        .sign_leader_block(block)
        .unwrap();
    observe(driver, vec![Artifact::LeaderBlock(signed)]);
    assert!(driver.machine().notarised(TWO).is_some());
}

#[test]
fn a_silent_chain_is_declared_after_d_stop_at_its_tip_for_good() {
    let committee = committee(120);
    let mut driver = started(&committee, validator(0));
    let stop = driver.machine().current_timers().stop;
    let (alive, silent) = (ChainId::new(1), ChainId::new(2));
    let alive_blocks = path(&committee, alive, 2);
    let silent_blocks = path(&committee, silent, 2);
    accept(&mut driver, &alive_blocks[..1]);
    accept(&mut driver, &silent_blocks[..1]);

    // A sign of life keeps the alive chain undeclared; every other chain is silent for D_stop.
    elapse(&mut driver, 200);
    accept(&mut driver, &alive_blocks[1..]);
    elapse(&mut driver, stop - 201);
    assert!(declared(&mut driver).is_empty());
    elapse(&mut driver, 1);
    let expected = every_chain_but(&committee, &[1], |chain| u64::from(chain == silent));
    assert_eq!(declared(&mut driver), expected);
    let counts = driver.machine().inspect().declarations();
    assert_eq!(counts.get(DeclarationRule::Stopped), expected.len() as u64);
    assert_eq!(counts.get(DeclarationRule::ViewChange), 0);

    // The silent chain moves on after its declaration: votes stay at its declaration height.
    accept(&mut driver, &silent_blocks[1..]);
    let eta = driver
        .machine()
        .profile()
        .tuning()
        .vote_interval
        .as_millis() as u64;
    elapse(&mut driver, eta);
    let vote = sent(&driver, ONE);
    assert_eq!(vote.tips()[silent.index()], reference(&silent_blocks[0]));
    assert_eq!(declared(&mut driver), expected);

    // A view change declares the rest, keeping earlier heights (rule (iv)).
    let genesis = HeldVqc::genesis(committee.genesis());
    let now = driver.now();
    let (_, capabilities) = driver
        .machine_mut()
        .finish_view(&genesis, false, now)
        .unwrap();
    persist_capabilities(&mut driver, capabilities);
    let last = sent(&driver, ONE);
    assert!(last.is_final());
    assert_eq!(last.declared().len(), committee.codec().chains());
    assert_eq!(last.tips()[silent.index()], reference(&silent_blocks[0]));
    assert_eq!(last.tips()[alive.index()], reference(&alive_blocks[1]));
    let counts = driver.machine().inspect().declarations();
    assert_eq!(counts.get(DeclarationRule::Stopped), expected.len() as u64);
    assert_eq!(counts.get(DeclarationRule::ViewChange), 1);
}

/// Returns a committee whose five chains are produced by validators one to five, so validator
/// zero's acceptances alone decide which chains are capped. Rule (ii) waits for all but `f = 1`
/// of the chains: four.
fn producers_one_to_five(seed: u64) -> Committee<MinPk> {
    Committee::builder(seed, PARTICIPANTS)
        .producers((1..PARTICIPANTS).map(Participant::new).collect())
        .build()
}

/// Caps chains zero to three of `committee` at this node.
fn cap_four(driver: &mut TestDriver, committee: &Committee<MinPk>) {
    let cap = committee.codec().window().cap() as usize;
    for chain in 0..4 {
        accept(driver, &path(committee, ChainId::new(chain), cap));
    }
}

#[test]
fn a_chain_still_open_t_late_after_all_but_f_chains_finished_is_declared_late() {
    let committee = producers_one_to_five(121);
    let mut driver = started(&committee, validator(0));
    let late = driver.machine().current_timers().late;
    let cap = committee.codec().window().cap() as usize;
    let (fourth, trailing) = (ChainId::new(3), ChainId::new(4));
    let trailing_blocks = path(&committee, trailing, 2);
    accept(&mut driver, &trailing_blocks[..1]);
    for chain in 0..3 {
        accept(&mut driver, &path(&committee, ChainId::new(chain), cap));
    }

    // Three capped chains are fewer than all but f: rule (ii) has not started.
    elapse(&mut driver, late);
    assert!(declared(&mut driver).is_empty());

    // The fourth chain caps; t_late later the trailing chain, alive but behind, is declared at
    // the tip it reached by then.
    accept(&mut driver, &trailing_blocks[1..]);
    accept(&mut driver, &path(&committee, fourth, cap));
    elapse(&mut driver, late - 1);
    assert!(declared(&mut driver).is_empty());
    elapse(&mut driver, 1);
    let counts = driver.machine().inspect().declarations();
    assert_eq!(counts.get(DeclarationRule::Late), 1);

    // Every chain is then capped or declared, and the grace has passed: the final vote follows
    // at once.
    let vote = sent(&driver, ONE);
    assert!(vote.is_final());
    assert_eq!(vote.declared().iter().collect::<Vec<_>>(), vec![trailing]);
    assert_eq!(
        vote.tips()[trailing.index()],
        reference(&trailing_blocks[1])
    );
}

#[test]
fn rule_ii_applies_only_after_entry_and_counts_from_it() {
    let committee = producers_one_to_five(125);
    let mut driver = started(&committee, validator(0));
    let late = driver.machine().current_timers().late;
    let trailing = ChainId::new(4);
    let trailing_blocks = path(&committee, trailing, 2);

    // The final vote of view one, with nothing accepted; this node then pre-votes for view two
    // while all but f chains cap against that vote's tips.
    let genesis = HeldVqc::genesis(committee.genesis());
    let now = driver.now();
    let (_, capabilities) = driver
        .machine_mut()
        .finish_view(&genesis, false, now)
        .unwrap();
    persist_capabilities(&mut driver, capabilities);
    accept(&mut driver, &trailing_blocks[..1]);
    cap_four(&mut driver, &committee);
    elapse(&mut driver, late + 10);
    assert_eq!(driver.machine().vote_tag(), TWO);
    assert!(declared(&mut driver).is_empty());

    // Entering view two starts tquorum at once; rule (ii) applies t_late after the entry.
    let tips = committee.genesis().tips().to_vec();
    enter_next_view(
        &mut driver,
        vqc_above(&committee, &genesis, false, tips, &[]),
    );
    accept(&mut driver, &trailing_blocks[1..]);
    elapse(&mut driver, late - 1);
    assert!(declared(&mut driver).is_empty());
    elapse(&mut driver, 1);
    assert_eq!(declared(&mut driver), vec![(trailing, Height::new(2))]);
    let counts = driver.machine().inspect().declarations();
    assert_eq!(counts.get(DeclarationRule::Late), 1);
}

#[test]
fn a_restart_counts_as_the_entry_for_rule_ii() {
    let committee = producers_one_to_five(128);
    let mut driver = started(&committee, validator(0));
    let late = driver.machine().current_timers().late;
    let trailing = ChainId::new(4);
    accept(&mut driver, &path(&committee, trailing, 1));
    cap_four(&mut driver, &committee);
    elapse(&mut driver, late - 1);

    // tquorum is volatile: after a restart it is counted again from the restart.
    let recovered = driver.crash_and_restore().unwrap();
    persist_all(&mut driver, recovered);
    quiesce(&mut driver);
    elapse(&mut driver, late - 1);
    assert!(declared(&mut driver).is_empty());
    elapse(&mut driver, 1);
    assert_eq!(declared(&mut driver), vec![(trailing, Height::new(1))]);
}

#[test]
fn every_chain_not_capped_is_declared_at_the_view_bound() {
    let committee = committee(122);
    let mut driver = started(&committee, validator(0));
    let timers = driver.machine().current_timers();
    let cap = committee.codec().window().cap() as usize;
    let (capped, alive) = (ChainId::new(1), ChainId::new(2));
    accept(&mut driver, &path(&committee, capped, cap));
    let alive_blocks = path(&committee, alive, 2);
    accept(&mut driver, &alive_blocks[..1]);
    elapse(&mut driver, 200);
    accept(&mut driver, &alive_blocks[1..]);

    // Silent chains are declared at D_stop; the capped chain never is.
    elapse(&mut driver, timers.max - 201);
    let silent = every_chain_but(&committee, &[1, 2], |_| 0);
    assert_eq!(declared(&mut driver), silent);
    assert!(!driver.machine().final_sent(ONE));

    // At t_max the alive chain is declared, the trigger holds, and the final vote follows.
    elapse(&mut driver, 1);
    let vote = sent(&driver, ONE);
    assert!(vote.is_final());
    assert!(!vote.declared().contains(capped));
    assert!(vote.declared().contains(alive));
    assert_eq!(vote.tips()[capped.index()].height().get(), cap as u64);
}

#[test]
fn declarations_record_what_this_node_knew_about_each_chain() {
    let committee = committee(126);
    let mut driver = started(&committee, validator(0));
    let stop = driver.machine().current_timers().stop;
    let cap = committee.codec().window().cap() as usize;
    let (capped, alive) = (ChainId::new(1), ChainId::new(2));
    accept(&mut driver, &path(&committee, capped, cap));
    let alive_blocks = path(&committee, alive, 2);
    accept(&mut driver, &alive_blocks[..1]);
    elapse(&mut driver, 200);
    accept(&mut driver, &alive_blocks[1..]);

    // Rule (i) declares the silent chains, none capped, each silent for exactly D_stop.
    elapse(&mut driver, stop - 200);
    let silent = every_chain_but(&committee, &[1, 2], |_| 0).len() as u64;
    let context = |capped, silent| DeclarationContext {
        capped,
        silent,
        held_back: false,
    };
    let contexts = driver.machine().progress().declaration_contexts;
    assert_eq!(
        contexts.get(DeclarationRule::Stopped, context(false, true)),
        silent
    );
    assert_eq!(
        contexts.silence_millis(DeclarationRule::Stopped),
        silent * stop
    );

    // A view change declares the capped chain, silent since its acceptance, and the alive chain.
    let genesis = HeldVqc::genesis(committee.genesis());
    let now = driver.now();
    let (_, capabilities) = driver
        .machine_mut()
        .finish_view(&genesis, false, now)
        .unwrap();
    persist_capabilities(&mut driver, capabilities);
    let contexts = driver.machine().progress().declaration_contexts;
    let rule = DeclarationRule::ViewChange;
    assert_eq!(contexts.get(rule, context(true, true)), 1);
    assert_eq!(contexts.get(rule, context(false, false)), 1);
    assert_eq!(
        DeclarationContext::ALL
            .into_iter()
            .map(|declared| contexts.get(rule, declared))
            .sum::<u64>(),
        2
    );
    assert_eq!(contexts.silence_millis(rule), stop + (stop - 200));
}

/// Returns whether rule (v) declares every chain of view one at validator zero once validators
/// one to four bind on chain one, by declaring it, at the blocks of the given heights above
/// genesis.
fn splits(heights: [usize; 4]) -> bool {
    let committee = committee(123);
    let chain = ChainId::new(1);
    let blocks = path(&committee, chain, heights.into_iter().max().unwrap());
    let chains = committee.codec().chains();
    let mut declares = ChainSet::empty(chains);
    declares.insert(chain);
    let votes = (1..).zip(heights).map(|(signer, height)| {
        let mut tips = committee.genesis().tips().to_vec();
        tips[chain.index()] = reference(&blocks[height - 1]);
        let content = committee.content(
            ONE,
            None,
            false,
            committee.endorsement(declares.clone(), tips),
        );
        Artifact::Update(committee.update(
            Participant::new(signer),
            &content,
            committee.genesis().tips(),
            1,
        ))
    });
    let mut driver = started(&committee, validator(0));
    accept(&mut driver, &blocks);
    observe(&mut driver, votes.collect());
    let declared = declared(&mut driver);
    assert!(declared.is_empty() || declared.len() == chains);
    !declared.is_empty()
}

#[test]
fn a_split_of_first_binding_votes_declares_every_chain() {
    // Two validators bind at the first block and two at the second: more than f at each, fewer
    // than n - f at the higher one.
    assert!(splits([1, 1, 2, 2]));

    // Agreement at one block is no split.
    assert!(!splits([2, 2, 2, 2]));
}

#[test]
fn first_binding_tips_split_only_inside_the_window() {
    let cap = committee(123).codec().window().cap() as usize;

    // Tips at and above the window end all endorse the window's last block: no split.
    assert!(!splits([cap, cap, cap + 1, cap + 1]));
    assert!(!splits([cap + 1, cap + 1, cap + 2, cap + 2]));

    // Below the window end against the window's last block is a split.
    assert!(splits([cap - 1, cap - 1, cap + 1, cap + 1]));
}

#[test]
fn the_sender_caps_its_tips_against_the_base_of_the_block_it_votes_for() {
    let committee = committee(124);
    let chain = ChainId::new(1);
    let cap = committee.codec().window().cap() as usize;
    let blocks = path(&committee, chain, cap);
    let mut driver = started(&committee, validator(0));
    let mut tips = committee.genesis().tips().to_vec();
    tips[chain.index()] = reference(&blocks[0]);
    let one = enter_two(&mut driver, &committee, tips, &blocks);
    accept(&mut driver, &blocks);

    // Against its last final vote's tips (genesis on the chain) the tip is capped.
    let base = driver.machine().sender_base(TWO).to_vec();
    assert!(base[chain.index()].height().is_zero());
    assert!(driver.machine().capped(chain, &base));

    // Once it votes for a leader block, the base is that block's: one block higher.
    vote_for_two(&mut driver, &committee, &one);
    let base = driver.machine().sender_base(TWO).to_vec();
    assert_eq!(base[chain.index()], reference(&blocks[0]));
    assert!(!driver.machine().capped(chain, &base));
}
