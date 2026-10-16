//! Emission: views determined by `n - f` final votes agree with the algebra reference; an L-QC
//! pins every view its parent's chain resolves back to the last defined one, after an L-QC
//! assembled from the latest signed votes for its leader block; resolutions are reported only once
//! durable, written once, and again after a restart; sweeps of the open view are monotone and
//! coalesced.

use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        algebra::{reference, validate_floor},
        config::Role,
        machine::{
            capability::{Capability, CryptoJob, ResolverCommand},
            durability::Change,
            emit::{UndeterminedChains, undetermined_chains},
            input::Step,
            resolution::RetrievalKey,
            testing::{
                CapabilitiesExt as _, Drive as _, Until, cohort,
                executors::SymbolicCrypto,
                fixtures::{
                    TestDriver, block, committee, deliver, digest, enter_next_view, observe, path,
                    persist_all, quiesce, reference as top, started, undetermined_vqc, vqc_above,
                },
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{
            Activity, Artifact, BlockRef, ChainId, ChainSet, HistoryRecord, LeaderBlock, Lqc,
            Resolution, VoteContent,
        },
    },
    types::{Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_utils::test_rng;
use rand::RngExt as _;
use std::sync::Arc;

const TWO: View = View::new(2);
const THREE: View = View::new(3);
const CHAIN: ChainId = ChainId::new(1);

/// Returns the view's leader block above `parent`.
fn leader_above(committee: &Committee<MinPk>, parent: &HeldVqc<Digest>) -> LeaderBlock<Digest> {
    LeaderBlock::new(
        committee.round(parent.view.next()),
        parent.id,
        parent.history,
    )
    .unwrap()
}

/// Returns `signer`'s vote for `leader` endorsing the genesis tips, final when `final_`.
fn vote_for(
    committee: &Committee<MinPk>,
    leader: &LeaderBlock<Digest>,
    final_: bool,
) -> VoteContent<Digest> {
    committee.content(
        leader.view(),
        Some(leader.digest::<Sha256>()),
        final_,
        committee.genesis_endorsement(),
    )
}

/// Returns the first update of each signer carrying its content, naming every chain.
fn updates(
    committee: &Committee<MinPk>,
    votes: &[(u32, VoteContent<Digest>)],
) -> Vec<Artifact<MinPk, Digest>> {
    let unrelated = committee
        .genesis()
        .tips()
        .iter()
        .map(|tip| BlockRef::new(tip.chain(), tip.height(), digest(b"unrelated")))
        .collect::<Vec<_>>();
    votes
        .iter()
        .map(|(signer, content)| {
            Artifact::Update(committee.update(Participant::new(*signer), content, &unrelated, 1))
        })
        .collect()
}

/// Returns an observer that entered view three on two V-QCs whose final votes determine nothing,
/// so views two and three have no emission state, and those V-QCs.
fn undetermined_three(
    committee: &Committee<MinPk>,
) -> (TestDriver, HeldVqc<Digest>, HeldVqc<Digest>) {
    let mut driver = started(committee, Role::Observer);
    let one = enter_next_view(
        &mut driver,
        undetermined_vqc(committee, &HeldVqc::genesis(committee.genesis())),
    );
    let two = enter_next_view(&mut driver, undetermined_vqc(committee, &one));
    assert_eq!(driver.machine().defined_through(), View::new(1));
    (driver, one, two)
}

/// Makes every barrier `step` leads to durable, checking at each acknowledgement that every view
/// reported resolved has the emission state fixing it in the journal, and returns the activities.
fn persist_checked(
    driver: &mut TestDriver,
    step: Step<MinPk, Digest>,
) -> Vec<Activity<MinPk, Digest>> {
    let mut activities = Vec::new();
    let mut pending = vec![step];
    while let Some(step) = pending.pop() {
        for activity in &step.activities {
            if let Activity::ViewResolved { view, .. } = activity {
                assert!(
                    driver.journal().iter().any(|event| matches!(
                        event.change(),
                        Change::EmissionResolved { view: emitted, .. } if *emitted == view.next()
                    )),
                    "view {view} is reported resolved before its emission is durable"
                );
            }
        }
        activities.extend(step.activities.iter().cloned());
        for journal in step.journals() {
            pending.push(driver.persist(&journal.job, Until::Quiesce));
        }
    }
    activities
}

/// Executes the L-QC aggregation `step` issued and returns the step its completion led to, with
/// nothing made durable.
fn aggregate(
    driver: &mut TestDriver,
    committee: &Committee<MinPk>,
    step: &Step<MinPk, Digest>,
) -> Step<MinPk, Digest> {
    let job = step
        .effects()
        .iter()
        .find(|capability| matches!(capability, Capability::Crypto(CryptoJob::AggregateLqc(_))))
        .cloned()
        .expect("the L-QC aggregation is issued");
    let completed = driver
        .execute(&mut SymbolicCrypto::new(committee.verifier.clone()), &job)
        .unwrap()
        .flatten()
        .expect("the aggregation completes");
    driver.settle(completed, Until::Quiesce)
}

/// An L-QC reported finalized, with the record opening its leader block's history commitment.
type Finalized = (Arc<Lqc<MinPk, Digest>>, Arc<HistoryRecord<Digest>>);

/// Returns the views reported resolved, in order.
fn resolved(activities: &[Activity<MinPk, Digest>]) -> Vec<View> {
    activities
        .iter()
        .filter_map(|activity| match activity {
            Activity::ViewResolved { view, .. } => Some(*view),
            _ => None,
        })
        .collect()
}

/// Returns the L-QCs reported finalized, in order.
fn finalized(activities: &[Activity<MinPk, Digest>]) -> Vec<Finalized> {
    activities
        .iter()
        .filter_map(|activity| match activity {
            Activity::LeaderFinalized { lqc, opening } => {
                Some((Arc::clone(lqc), Arc::clone(opening)))
            }
            _ => None,
        })
        .collect()
}

/// Returns the sweeps reported, in order.
fn sweeps(activities: &[Activity<MinPk, Digest>]) -> Vec<(View, Vec<BlockRef<Digest>>, ChainSet)> {
    activities
        .iter()
        .filter_map(|activity| match activity {
            Activity::ViewSweep {
                view,
                finals,
                settled,
            } => Some((*view, finals.to_vec(), settled.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn determined_views_match_the_reference_on_random_pools() {
    let mut rng = test_rng();
    let committee = committee(300);
    let codec = committee.codec();
    let cap = codec.window().cap();
    let participants = codec.participants();
    let quorum = codec.view_quorum();
    let chains = codec.chains();
    let genesis = committee.genesis().tips().to_vec();
    assert_eq!(quorum, participants - 1);
    let (mut determined, mut undetermined) = (0, 0);
    for _ in 0..32 {
        let mut driver = started(&committee, Role::Observer);
        let mut tree = reference::Tree::new(committee.config.epoch());
        let mut blocks = genesis.iter().map(|tip| vec![*tip]).collect::<Vec<_>>();
        for _ in 0..24 {
            let chain = rng.random_range(1..chains);
            let parent = blocks[chain][rng.random_range(0..blocks[chain].len())];
            if parent.height().get() >= u64::from(2 * cap) {
                continue;
            }
            let body = digest(&rng.random::<[u8; 8]>());
            let header = committee.header(&parent, body);
            assert_eq!(
                tree.extend::<Sha256>(&parent, body),
                header.block_ref::<Sha256>()
            );
            if driver.machine_mut().hold_header(header.clone()) {
                blocks[chain].push(header.block_ref::<Sha256>());
            }
        }

        // Every validator's final vote of view one: mostly one shared tip vector, sometimes its
        // own pick on each chain.
        let shared = blocks
            .iter()
            .map(|chain| chain[rng.random_range(0..chain.len())])
            .collect::<Vec<_>>();
        let finals = (0..participants)
            .map(|signer| {
                let tips = blocks
                    .iter()
                    .zip(&shared)
                    .map(|(chain, tip)| {
                        if rng.random_bool(0.9) {
                            *tip
                        } else {
                            chain[rng.random_range(0..chain.len())]
                        }
                    })
                    .collect::<Vec<_>>();
                let declared = ChainSet::empty(chains);
                let content = committee.content(
                    View::new(1),
                    None,
                    true,
                    committee.endorsement(declared, tips),
                );
                (Participant::from_usize(signer), content)
            })
            .collect::<Vec<_>>();
        for (signer, content) in &finals {
            let now = driver.now();
            driver
                .machine_mut()
                .read_vote(*signer, 1, Arc::new(content.clone()), now, now);
        }
        quiesce(&mut driver);

        // Det(G) of every n - f of the finals (all but one); any two that determine every chain
        // agree.
        let mut expected = None;
        for skipped in 0..participants {
            let group = finals
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != skipped)
                .map(|(_, vote)| vote)
                .collect::<Vec<_>>();
            let det = genesis
                .iter()
                .map(|base| {
                    let votes = group
                        .iter()
                        .map(|(signer, content)| (*signer, content.tips()[base.chain().index()]))
                        .collect::<Vec<_>>();
                    reference::determined(&tree, base, cap, quorum, &votes)
                })
                .collect::<Option<Vec<_>>>();
            if let Some(det) = det {
                assert!(expected.as_ref().is_none_or(|expected| *expected == det));
                expected = Some(det);
            }
        }
        let emission = driver.machine().durable.state.emission.get(&TWO);
        assert_eq!(emission.map(|emission| emission.base().to_vec()), expected);
        if let Some(emission) = emission {
            assert_eq!(emission.by, Resolution::Determined);
            assert_eq!(emission.record.parent(), committee.genesis().history());
            determined += 1;
        } else {
            undetermined += 1;
        }
    }
    assert!(determined > 0 && undetermined > 0);
}

#[test]
fn an_lqc_pins_every_view_back_to_the_last_defined_one_once_durable() {
    let committee = committee(301);
    let (mut driver, one, two) = undetermined_three(&committee);

    // n - f validators vote for view three's leader block, two of them finally: the observer
    // aggregates their latest signed votes into an L-QC.
    let leader = leader_above(&committee, &two);
    let votes = (1..=5)
        .map(|signer| (signer, vote_for(&committee, &leader, signer <= 2)))
        .collect::<Vec<_>>();
    let step = observe(&mut driver, updates(&committee, &votes));
    let staged = aggregate(&mut driver, &committee, &step);
    persist_checked(&mut driver, step);
    assert!(
        resolved(&staged.activities).is_empty() && finalized(&staged.activities).is_empty(),
        "nothing is reported before it is durable"
    );
    let activities = persist_checked(&mut driver, staged);

    // Views one and two resolve to the tips of the V-QCs on the leader block's parent chain,
    // pinned by the L-QC, and the L-QC is reported with the record opening its commitment.
    let reported = finalized(&activities);
    assert_eq!(reported.len(), 1);
    let (lqc, opening) = &reported[0];
    assert_eq!(lqc.leader(), &leader);
    assert_eq!(opening.commitment::<Sha256>(), leader.history());
    let held = |held: &HeldVqc<Digest>| {
        driver
            .machine()
            .stored_vqc(&held.id)
            .unwrap()
            .record
            .clone()
    };
    assert_eq!(**opening, *held(&two));
    assert!(
        validate_floor::<Sha256, MinPk>(lqc, opening, committee.config.epoch(), committee.codec())
            .is_ok()
    );
    let pinned = Resolution::Pinned {
        view: THREE,
        lqc: lqc.id::<Sha256>(),
    };
    let state = &driver.machine().durable.state;
    for (view, record) in [(TWO, held(&one)), (THREE, held(&two))] {
        let emission = &state.emission[&view];
        assert_eq!(emission.record, *record);
        assert_eq!(emission.by, pinned);
    }
    assert_eq!(resolved(&activities), vec![View::new(1), TWO]);
    let Some(Activity::ViewResolved {
        base,
        tips,
        commitment,
        parent_commitment,
        by,
        ..
    }) = activities
        .iter()
        .find(|activity| matches!(activity, Activity::ViewResolved { view, .. } if *view == TWO))
    else {
        unreachable!();
    };
    assert_eq!(**base, *one.tips);
    assert_eq!(**tips, *two.tips);
    assert_eq!(*commitment, two.history);
    assert_eq!(*parent_commitment, one.history);
    assert_eq!(*by, pinned);

    // View one's final votes, read from its V-QC, split on one chain and so failed to determine
    // view two; view two's were never checked, since view two had no defined state.
    let undetermined = driver.machine().progress().pinned_undetermined;
    assert_eq!(undetermined.boundaries, 1);
    assert_eq!(undetermined.chains.split, 1);
    assert_eq!(undetermined.chains.unresolved, 0);

    // The L-QC aggregates the finals first, then the non-final votes, in signer order.
    let contents = lqc.contents::<Sha256>();
    assert_eq!(
        contents
            .iter()
            .map(|(signer, _)| signer.get())
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    assert_eq!(
        contents
            .iter()
            .filter(|(_, content)| content.is_final())
            .count(),
        2
    );
}

#[test]
fn the_lqc_prefers_final_votes_and_identical_contents_share_one_entry() {
    let committee = committee(302);
    let (mut driver, _, two) = undetermined_three(&committee);
    let leader = leader_above(&committee, &two);

    // Six signed votes: four non-final, two final. The finals are taken first, so the signer of
    // the last non-final vote is left out.
    let votes = (0..6)
        .map(|signer| (signer, vote_for(&committee, &leader, signer >= 4)))
        .collect::<Vec<_>>();
    let step = observe(&mut driver, updates(&committee, &votes));
    let staged = aggregate(&mut driver, &committee, &step);
    persist_checked(&mut driver, step);
    let activities = persist_checked(&mut driver, staged);
    let (lqc, _) = &finalized(&activities)[0];
    assert_eq!(
        lqc.tally()
            .signers()
            .iter()
            .map(|signer| signer.get())
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 4, 5]
    );

    // Votes with identical contents need one tally entry and one pairing.
    let (mut driver, _, two) = undetermined_three(&committee);
    let leader = leader_above(&committee, &two);
    let votes = (1..=5)
        .map(|signer| (signer, vote_for(&committee, &leader, false)))
        .collect::<Vec<_>>();
    let step = observe(&mut driver, updates(&committee, &votes));
    let staged = aggregate(&mut driver, &committee, &step);
    persist_checked(&mut driver, step);
    let activities = persist_checked(&mut driver, staged);
    let (lqc, _) = &finalized(&activities)[0];
    assert!(lqc.tally().deviations().is_empty());
}

#[test]
fn a_peer_lqc_pins_its_views_once_its_parent_is_held() {
    let committee = committee(303);
    let (mut driver, one, two) = undetermined_three(&committee);
    let leader = leader_above(&committee, &two);
    let lqc_of = |signers: core::ops::RangeInclusive<u32>| {
        let contents = signers
            .map(|signer| {
                (
                    Participant::new(signer),
                    vote_for(&committee, &leader, false),
                )
            })
            .collect();
        committee.lqc_from(leader.clone(), contents)
    };
    let lqc = lqc_of(1..=5);
    // A second L-QC of the view admitted alongside it is not kept.
    let other = Artifact::Lqc(lqc_of(0..=4));
    let activities = deliver(&mut driver, vec![Artifact::Lqc(lqc.clone()), other.clone()]);
    assert!(driver.machine().store.get(&other.id::<Sha256>()).is_none());
    assert_eq!(resolved(&activities), vec![View::new(1), TWO]);
    let reported = finalized(&activities);
    assert_eq!(*reported[0].0, lqc);
    let state = &driver.machine().durable.state;
    assert_eq!(state.emission[&TWO].base(), &*one.tips);
    assert_eq!(state.emission[&THREE].base(), &*two.tips);
    assert!(
        state
            .local
            .values()
            .any(|artifact| **artifact == Artifact::Lqc(lqc.clone())),
        "the L-QC is made durable"
    );

    // The L-QC arriving again is not verified again.
    let step = driver
        .submit(cohort::<Sha256, _>(vec![Artifact::Lqc(lqc)]))
        .unwrap();
    assert!(
        !step
            .effects()
            .iter()
            .any(|capability| matches!(capability, Capability::Verify(_)))
    );
}

#[test]
fn an_lqc_whose_parent_is_missing_requests_it_and_pins_once_it_is_held() {
    let committee = committee(305);
    let (_, one, two) = undetermined_three(&committee);
    let leader = leader_above(&committee, &two);
    let contents = (1..=5)
        .map(|signer| {
            (
                Participant::new(signer),
                vote_for(&committee, &leader, false),
            )
        })
        .collect();
    let lqc = committee.lqc_from(leader, contents);

    // A node in view two receives the L-QC of view three before the V-QC of view two it names.
    let mut driver = started(&committee, Role::Observer);
    enter_next_view(
        &mut driver,
        undetermined_vqc(&committee, &HeldVqc::genesis(committee.genesis())),
    );
    let step = observe(&mut driver, vec![Artifact::Lqc(lqc.clone())]);
    let parent = RetrievalKey::Vqc(two.id);
    assert!(step.effects().iter().any(|capability| matches!(
        capability,
        Capability::Resolver(ResolverCommand::Resolve(job)) if job.key() == parent
    )));
    let activities = persist_all(&mut driver, step);
    assert!(finalized(&activities).is_empty());

    // The retrieved parent is held, and the L-QC pins views one and two.
    let activities = deliver(
        &mut driver,
        vec![Artifact::Vqc(undetermined_vqc(&committee, &one))],
    );
    assert_eq!(resolved(&activities), vec![View::new(1), TWO]);
    assert_eq!(*finalized(&activities)[0].0, lqc);
}

#[test]
fn a_determined_base_agrees_with_a_later_lqc_and_is_written_once() {
    let committee = committee(304);
    let mut driver = started(&committee, Role::Observer);
    let genesis = HeldVqc::genesis(committee.genesis());
    let tips = committee.genesis().tips().to_vec();

    // The final votes of view one in its V-QC agree: view two's base is determined.
    let activities = deliver(
        &mut driver,
        vec![Artifact::Vqc(vqc_above(
            &committee,
            &genesis,
            false,
            tips.clone(),
            &[],
        ))],
    );
    assert_eq!(resolved(&activities), vec![View::new(1)]);
    let one = driver
        .machine()
        .stored_vqc(&vqc_above(&committee, &genesis, false, tips, &[]).id::<Sha256>())
        .unwrap()
        .held
        .clone();
    let determined = driver.machine().durable.state.emission[&TWO].clone();
    assert_eq!(determined.by, Resolution::Determined);
    assert_eq!(determined.base(), &*one.tips);

    // An L-QC for view two's leader block later finalizes the same base: the emission keeps how it
    // was first fixed, and the L-QC opens to it.
    let leader = leader_above(&committee, &one);
    let contents = (1..=5)
        .map(|signer| {
            (
                Participant::new(signer),
                vote_for(&committee, &leader, false),
            )
        })
        .collect();
    let lqc = committee.lqc_from(leader.clone(), contents);
    let activities = deliver(&mut driver, vec![Artifact::Lqc(lqc)]);
    assert!(resolved(&activities).is_empty());
    let reported = finalized(&activities);
    assert_eq!(reported.len(), 1);
    assert_eq!(*reported[0].1, determined.record);
    assert_eq!(reported[0].1.commitment::<Sha256>(), leader.history());
    assert_eq!(driver.machine().durable.state.emission[&TWO], determined);
    // A determined boundary is never counted as pinned after a failed determination.
    let undetermined = driver.machine().progress().pinned_undetermined;
    assert_eq!(undetermined.boundaries, 0);
}

#[test]
fn undetermined_chains_separate_missing_headers_from_split_votes() {
    let committee = committee(306);
    let genesis = committee.genesis().tips();
    let above =
        |chain: usize, seed: &[u8]| Some(Some(top(&block(&committee, &genesis[chain], seed))));
    let (outside, unresolved) = (Some(None), None);
    // Five votes, quorum four. Chain zero: four agree (determined). Chain one: three resolve
    // (unresolved). Chain two: two and three reach different blocks (split).
    let votes = (0..5)
        .map(|vote| {
            vec![
                if vote < 4 { outside } else { above(0, b"zero") },
                if vote < 3 { outside } else { unresolved },
                if vote < 2 {
                    above(2, b"left")
                } else {
                    above(2, b"right")
                },
            ]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        undetermined_chains(&votes, 3, 4),
        UndeterminedChains {
            unresolved: 1,
            split: 1,
        }
    );
    assert_eq!(
        undetermined_chains(&votes[..4], 1, 4),
        UndeterminedChains::default()
    );
}

#[test]
fn sweeps_report_the_open_view_monotonically_and_once_per_change() {
    let committee = committee(305);
    let mut driver = started(&committee, Role::Observer);
    let genesis = HeldVqc::genesis(committee.genesis());
    let tips = committee.genesis().tips().to_vec();
    enter_next_view(
        &mut driver,
        vqc_above(&committee, &genesis, false, tips.clone(), &[]),
    );
    assert_eq!(driver.machine().defined_through(), TWO);
    let blocks = path(&committee, CHAIN, 2);
    for block in &blocks {
        assert!(driver.machine_mut().hold_header(block.header().clone()));
    }
    let declared = ChainSet::from_chains(committee.codec().chains(), [CHAIN]).unwrap();
    let vote = |height: usize| {
        let mut tips = tips.clone();
        tips[CHAIN.index()] = top(&blocks[height]);
        committee.content(
            TWO,
            None,
            false,
            committee.endorsement(declared.clone(), tips),
        )
    };
    // Validator `signer`'s update `seq` endorsing `blocks[height]`, after one endorsing `previous`.
    let send = |driver: &mut TestDriver, signer: u32, seq: u32, height: usize, previous: &[_]| {
        let update = committee.update(Participant::new(signer), &vote(height), previous, seq);
        sweeps(&deliver(driver, vec![Artifact::Update(update)]))
    };
    let mut moved = tips.clone();
    moved[CHAIN.index()] = top(&blocks[0]);

    // Five validators declare chain one at its first block: it becomes final in view two and
    // settled, reported once.
    let mut reported = Vec::new();
    for signer in 1..=5 {
        reported.extend(send(&mut driver, signer, 1, 0, &tips));
    }
    let first = {
        let mut finals = tips.clone();
        finals[CHAIN.index()] = top(&blocks[0]);
        (TWO, finals, declared.clone())
    };
    assert_eq!(reported, vec![first.clone()]);

    // One validator moves to the second block: nothing changes and nothing is reported.
    reported.extend(send(&mut driver, 1, 2, 1, &moved));
    assert_eq!(reported, vec![first.clone()]);

    // The others follow: the final tip advances, the chain stays settled.
    for signer in 2..=5 {
        reported.extend(send(&mut driver, signer, 2, 1, &moved));
    }
    let mut finals = tips.clone();
    finals[CHAIN.index()] = top(&blocks[1]);
    assert_eq!(reported, vec![first, (TWO, finals, declared)]);
}

#[test]
fn sweeps_tally_each_first_binding_vote_once_and_evaluate_only_changed_chains() {
    let committee = Committee::builder(307, 50).build();
    let chains = committee.codec().chains();
    let mut driver = started(&committee, Role::Observer);
    let genesis = HeldVqc::genesis(committee.genesis());
    let tips = committee.genesis().tips().to_vec();
    enter_next_view(
        &mut driver,
        vqc_above(&committee, &genesis, false, tips.clone(), &[]),
    );
    assert_eq!(driver.machine().defined_through(), TWO);
    let every = ChainSet::from_chains(chains, (0..chains as u32).map(ChainId::new)).unwrap();
    let binding = committee.content(TWO, None, false, committee.endorsement(every, tips));
    let idle = committee.content(TWO, None, false, committee.genesis_endorsement());
    // Delivers validator `signer`'s first update of view two and returns how many first binding
    // tips the sweeps it led to classified, and how many chains they evaluated.
    let send = |driver: &mut TestDriver, signer: u32, content: VoteContent<Digest>| {
        let emitter = &driver.machine().components.emitter;
        let before = (emitter.classified, emitter.evaluations);
        let update = updates(&committee, &[(signer, content)]);
        assert!(sweeps(&deliver(driver, update)).is_empty());
        let emitter = &driver.machine().components.emitter;
        (
            emitter.classified - before.0,
            emitter.evaluations - before.1,
        )
    };

    // Each first binding vote is classified once per chain and changes every chain's tally; ten
    // leave every chain unsettled.
    for signer in 1..=10 {
        assert_eq!(send(&mut driver, signer, binding.clone()), (chains, chains));
    }
    // Votes binding nothing change no tally.
    for signer in 11..=30 {
        assert_eq!(send(&mut driver, signer, idle.clone()), (0, 0));
    }
    // Every tally relates its tips to the base, so newly held headers change nothing either.
    for block in path(&committee, CHAIN, 1) {
        assert!(driver.machine_mut().hold_header(block.header().clone()));
    }
    assert_eq!(send(&mut driver, 31, idle), (0, 0));
}

#[test]
fn sweeps_match_a_from_scratch_evaluation_as_votes_and_headers_arrive() {
    let mut rng = test_rng();
    let mut settles = 0;
    for seed in 0..8 {
        let committee = committee(320 + seed);
        let codec = committee.codec();
        let cap = codec.window().cap() as usize;
        let mut driver = started(&committee, Role::Observer);
        let base = committee.genesis().tips().to_vec();
        // Per chain a path a window and a half long, and a fork from its second block; headers
        // arrive in a random order, interleaved with the votes.
        let mut headers = Vec::new();
        let mut branches = Vec::new();
        for chain in base.iter().map(BlockRef::chain) {
            let trunk = path(&committee, chain, cap + cap / 2);
            let fork = block(&committee, &top(&trunk[1]), b"fork");
            let fork_child = block(&committee, &top(&fork), b"fork child");
            let mut tips = trunk.iter().map(top).collect::<Vec<_>>();
            tips.extend([top(&fork), top(&fork_child)]);
            branches.push(tips);
            headers.extend(trunk);
            headers.extend([fork, fork_child]);
        }
        headers.sort_by_key(|_| rng.random::<u64>());
        let mut seqs = vec![0u32; codec.participants()];
        let mut settled = ChainSet::empty(codec.chains());
        let mut reported = (base.clone(), ChainSet::empty(codec.chains()));
        for step in 0..120 {
            if !headers.is_empty() && rng.random_bool(0.6) {
                let header = headers.swap_remove(rng.random_range(0..headers.len()));
                driver.machine_mut().hold_header(header.header().clone());
            } else {
                // Most tips follow the trunk as it grows, so chains settle; the rest scatter.
                let signer = rng.random_range(0..codec.participants());
                let target = (step / 20).min(cap + cap / 2 - 1);
                let tips = branches
                    .iter()
                    .map(|branch| {
                        if rng.random_bool(0.7) {
                            branch[target]
                        } else {
                            branch[rng.random_range(0..branch.len())]
                        }
                    })
                    .collect::<Vec<_>>();
                let declared = ChainSet::from_chains(
                    codec.chains(),
                    codec.chain_ids().filter(|_| rng.random_bool(0.5)),
                )
                .unwrap();
                let vote = committee.content(
                    View::new(1),
                    None,
                    rng.random_bool(0.1),
                    committee.endorsement(declared, tips),
                );
                seqs[signer] += 1;
                let now = driver.now();
                driver.machine_mut().read_vote(
                    Participant::from_usize(signer),
                    seqs[signer],
                    Arc::new(vote),
                    now,
                    now,
                );
            }
            if let Some((_, finals, set)) = sweeps(&quiesce(&mut driver)).pop() {
                reported = (finals, set);
            }
            let machine = driver.machine();
            for (index, base) in base.iter().enumerate() {
                let final_tip = machine.final_tip(View::new(1), base, *base);
                assert_eq!(reported.0[index], final_tip, "seed {seed} step {step}");
                if machine.settledness(View::new(1), base, &final_tip).settled {
                    settled.insert(base.chain());
                }
            }
            assert_eq!(reported.1, settled, "seed {seed} step {step}");
        }
        settles += settled.iter().count();
    }
    assert!(settles > 0, "some chain settles");
}

#[test]
fn a_restart_reports_the_retained_resolutions_and_finalizations_again() {
    let committee = committee(306);
    let (mut driver, _, two) = undetermined_three(&committee);
    let leader = leader_above(&committee, &two);
    let contents = (1..=5)
        .map(|signer| {
            (
                Participant::new(signer),
                vote_for(&committee, &leader, false),
            )
        })
        .collect();
    let lqc = committee.lqc_from(leader, contents);
    let before = deliver(&mut driver, vec![Artifact::Lqc(lqc.clone())]);

    let recovered = driver.crash_and_restore().unwrap();
    let mut activities = persist_checked(&mut driver, recovered);
    activities.extend(quiesce(&mut driver));
    assert_eq!(resolved(&activities), vec![View::new(1), TWO]);
    let resolutions = |activities: &[Activity<MinPk, Digest>]| {
        activities
            .iter()
            .filter(|activity| matches!(activity, Activity::ViewResolved { .. }))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(resolutions(&activities), resolutions(&before));
    let reported = finalized(&activities);
    assert_eq!(reported.len(), 1);
    assert_eq!(*reported[0].0, lqc);
    assert_eq!(reported, finalized(&before));
}
