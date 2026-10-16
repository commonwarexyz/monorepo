//! Retention: the floor trails the newest finalized view by the retention window, durable state and
//! every store reach a plateau over a long run, and a restart holds the retained V-QCs again on the
//! floor's root, including an entry chain that diverges from the exits.

use crate::{
    multimmit::{
        config::{Role, Tuning},
        machine::{
            capability::{Capability, ResolverCommand},
            input::BlockValidity,
            resolution::RetrievalKey,
            testing::{
                CapabilitiesExt as _, Drive as _,
                fixtures::{
                    Block, TestDriver, committee, deliver, enter_next_view, final_above, path,
                    quiesce, receive, reference, started_with, tuned, validate, validator,
                    vqc_above, vqc_of,
                },
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{Artifact, ChainId, ChainSet, LeaderBlock, Vqc},
    },
    types::{Height, Participant, View, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};

/// The retention window the tests run with.
const WINDOW: u64 = 2;

/// The chain that grows by one block per view.
const CHAIN: ChainId = ChainId::new(1);

/// Returns an observer retaining [`WINDOW`] views below the newest finalized one.
fn observer(committee: &Committee<MinPk>) -> TestDriver {
    let tuning = Tuning {
        view_retention: ViewDelta::new(WINDOW),
        ..Tuning::default()
    };
    started_with(tuned(committee, Role::Observer, tuning))
}

/// Runs the view after `parent`'s: accepts `block` (the next block of [`CHAIN`]) on endorsements
/// of every peer, enters the next view on a V-QC whose final votes for the view's leader block
/// endorse it, and delivers the L-QC of that leader block. Returns the V-QC.
fn run_view(
    driver: &mut TestDriver,
    committee: &Committee<MinPk>,
    parent: &HeldVqc<Digest>,
    block: &Block,
) -> HeldVqc<Digest> {
    let view = parent.view.next();
    receive(driver, std::slice::from_ref(block));
    let now = driver.now();
    for signer in 1..=5 {
        driver.machine_mut().note_endorsement(
            Participant::new(signer),
            view,
            reference(block),
            now,
            now,
        );
    }
    quiesce(driver);
    validate(driver, block, BlockValidity::Valid);

    let mut tips = parent.tips.to_vec();
    tips[CHAIN.index()] = reference(block);
    let held = enter_next_view(
        driver,
        vqc_above(committee, parent, true, tips, std::slice::from_ref(block)),
    );

    let leader = LeaderBlock::new(committee.round(view), parent.id, parent.history).unwrap();
    let vote = committee.content(
        view,
        Some(leader.digest::<Sha256>()),
        false,
        committee.endorsement(
            ChainSet::empty(committee.codec().chains()),
            parent.tips.to_vec(),
        ),
    );
    let contents = (1..=5)
        .map(|signer| (Participant::new(signer), vote.clone()))
        .collect();
    deliver(
        driver,
        vec![Artifact::Lqc(committee.lqc_from(leader, contents))],
    );
    held
}

/// What the node retains, durably and in its volatile stores.
#[derive(Debug, PartialEq, Eq)]
struct Occupancy {
    emissions: usize,
    exits: usize,
    forwarded: usize,
    local: usize,
    accepted: usize,
    durable_artifacts: usize,
    cached_artifacts: usize,
    held_headers: usize,
    held_vqcs: usize,
}

fn occupancy(driver: &TestDriver) -> Occupancy {
    let machine = driver.machine();
    let state = &machine.durable.state;
    let headers = &machine.chain_layer().headers;
    let tip = machine.chain_layer().tip(CHAIN).height().get();
    Occupancy {
        emissions: state.emission.len(),
        exits: state.exits.len(),
        forwarded: state.forwarded_count(),
        local: state.local.len(),
        accepted: state.accepted[CHAIN.index()].len(),
        durable_artifacts: state.artifact_occupancy::<Sha256>(),
        cached_artifacts: driver.inspect().cached_artifacts(),
        held_headers: (headers.floor(CHAIN).get() + 1..=tip)
            .map(|height| headers.at(CHAIN, Height::new(height)).len())
            .sum(),
        held_vqcs: (0..=state.view.get())
            .map(|view| machine.components.vqcs.view_len(View::new(view)))
            .sum(),
    }
}

#[test]
fn a_long_run_keeps_durable_state_and_every_store_on_a_plateau() {
    let committee = committee(500);
    let mut driver = observer(&committee);
    let blocks = path(&committee, CHAIN, 30);
    let mut parent = HeldVqc::genesis(committee.genesis());
    let mut plateau = None;
    for (index, block) in blocks.iter().enumerate() {
        parent = run_view(&mut driver, &committee, &parent, block);
        let finalized = driver.machine().components.emitter.finalized;
        assert_eq!(
            finalized, parent.view,
            "each view's leader block is finalized"
        );
        let state = &driver.machine().durable.state;
        assert_eq!(
            state.retired_view.get(),
            finalized.get().saturating_sub(WINDOW),
            "the floor trails the finalized view by the window"
        );
        assert!(
            state
                .emission
                .last_key_value()
                .is_some_and(|(view, _)| *view > finalized),
            "the newest emission is kept"
        );
        if index == 10 {
            plateau = Some(occupancy(&driver));
        } else if index > 10 {
            assert_eq!(Some(occupancy(&driver)), plateau, "view {}", parent.view);
        }
    }
    let state = &driver.machine().durable.state;
    let base = state.emission[&state.retired_view.next()].base()[CHAIN.index()];
    assert!(
        state.accepted[CHAIN.index()]
            .first_key_value()
            .is_some_and(|(height, _)| *height == base.height()),
        "accepted headers below the retained base are dropped"
    );
    assert_eq!(
        driver.machine().chain_layer().headers.floor(CHAIN).next(),
        base.height()
    );

    // The resolver is told every raised header floor of the chain, ascending, ending at the
    // floor the machine holds.
    let settled = driver
        .settled_headers()
        .iter()
        .filter(|(chain, _)| *chain == CHAIN)
        .map(|(_, height)| *height)
        .collect::<Vec<_>>();
    assert!(settled.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        settled.last().copied(),
        Some(driver.machine().chain_layer().headers.floor(CHAIN))
    );
}

#[test]
fn a_validators_outbox_stays_on_a_plateau_however_long_the_retention_window() {
    let committee = committee(502);
    let tuning = Tuning {
        view_retention: ViewDelta::new(1_000),
        ..Tuning::default()
    };
    let mut driver = started_with(tuned(&committee, validator(0), tuning));
    let blocks = path(&committee, CHAIN, 30);
    let mut parent = HeldVqc::genesis(committee.genesis());
    // The ceiling covers a full leader rotation, so it includes every view this node leads.
    let mut ceiling = 0;
    for (index, block) in blocks.iter().enumerate() {
        parent = run_view(&mut driver, &committee, &parent, block);
        assert!(driver.machine().durable.state.retired_view.is_zero());
        let outbox = driver.inspect().outbox_len();
        if index < 12 {
            ceiling = ceiling.max(outbox);
        } else {
            assert!(outbox <= ceiling, "view {}", parent.view);
        }
    }
}

#[test]
fn a_restart_holds_the_retained_vqcs_on_the_root_and_keeps_going() {
    let committee = committee(501);
    let mut driver = observer(&committee);
    let blocks = path(&committee, CHAIN, 12);
    let mut parent = HeldVqc::genesis(committee.genesis());
    for block in &blocks[..10] {
        parent = run_view(&mut driver, &committee, &parent, block);
    }
    let before = occupancy(&driver);
    let root = driver
        .machine()
        .durable
        .state
        .root
        .clone()
        .expect("views are retired");
    // The lowest retained V-QC on the entry chain descends from the root.
    let machine = driver.machine();
    let mut lowest = machine
        .stored_vqc(&parent.id)
        .expect("the entry V-QC is held");
    while let Some(stored) = machine.stored_vqc(&lowest.parent) {
        lowest = stored;
    }
    assert_eq!(lowest.held.view, machine.durable.state.retired_view.next());
    assert_eq!(lowest.parent, root.vqc);

    driver.crash_and_restore().unwrap();
    quiesce(&mut driver);
    let machine = driver.machine();
    assert_eq!(machine.held_vqc(&parent.id), Some(parent.clone()));
    let held_root = machine.held_vqc(&root.vqc).expect("the root is held");
    assert_eq!(held_root.view, machine.durable.state.retired_view);
    assert_eq!(held_root.history, root.record.commitment::<Sha256>());
    assert_eq!(occupancy(&driver).held_vqcs, before.held_vqcs);

    for block in &blocks[10..] {
        parent = run_view(&mut driver, &committee, &parent, block);
    }
    assert_eq!(driver.machine().components.emitter.finalized, View::new(12));
}

/// Returns a V-QC above `parent` whose final votes by `signers` keep `parent`'s tips and name
/// no leader block, so it designates nothing.
fn leaderless_vqc(
    committee: &Committee<MinPk>,
    parent: &HeldVqc<Digest>,
    signers: impl IntoIterator<Item = u32>,
) -> Vqc<MinPk, Digest> {
    let content = final_above(committee, parent, false, parent.tips.to_vec());
    let contents = signers
        .into_iter()
        .map(|signer| (Participant::new(signer), content.clone()))
        .collect();
    vqc_of(committee, parent, contents, &[])
}

#[test]
fn an_entry_chain_diverging_from_the_exits_survives_retention_and_a_restart() {
    let committee = committee(502);
    let mut driver = observer(&committee);
    let blocks = path(&committee, CHAIN, 8);
    let mut parent = HeldVqc::genesis(committee.genesis());
    for block in &blocks[..2] {
        parent = run_view(&mut driver, &committee, &parent, block);
    }

    // Views three and four designate no leader block. The node exits them on V-QCs of its own
    // (`A3`, `A4`), then learns another chain above view two (`B3`, `B4`) and enters view six on
    // a V-QC of view five above it. `B4` is forwarded and its publication ends at that entry; `B3`
    // lies below the forwarding window and is never forwarded.
    let own = enter_next_view(&mut driver, leaderless_vqc(&committee, &parent, 1..=5));
    enter_next_view(&mut driver, leaderless_vqc(&committee, &own, 1..=5));
    let b3 = leaderless_vqc(&committee, &parent, 0..5);
    deliver(&mut driver, vec![Artifact::Vqc(b3.clone())]);
    let b3 = driver
        .machine()
        .held_vqc(&b3.id::<Sha256>())
        .expect("B3 is held");
    let b4 = leaderless_vqc(&committee, &b3, 0..5);
    let b4_artifact = Artifact::Vqc(b4.clone()).id::<Sha256>();
    deliver(&mut driver, vec![Artifact::Vqc(b4.clone())]);
    let b4 = driver
        .machine()
        .held_vqc(&b4.id::<Sha256>())
        .expect("B4 is held");
    parent = run_view(&mut driver, &committee, &b4, &blocks[2]);

    // The L-QC of view five retires view three on the root `B3`, which passes the divergence:
    // `A3` is dropped, so the exit `A4` can never be held again, while `B4`, the entry parent's
    // parent, stays retained as an ancestor.
    let state = &driver.machine().durable.state;
    assert_eq!(state.view, View::new(6));
    assert_eq!(state.retired_view, View::new(3));
    assert_eq!(state.root.as_ref().map(|root| root.vqc), Some(b3.id));
    assert!(state.ancestors.keys().eq([&b4.id]));
    assert!(
        state.outbox.values().all(|entry| entry
            .publication()
            .artifacts()
            .iter()
            .all(|artifact| artifact.id::<Sha256>() != b4_artifact)),
        "B4's forwarding publication ended"
    );

    // A restart holds the entry chain on the root without retrieving anything.
    let recovered = driver.crash_and_restore().unwrap();
    let requested = recovered
        .effects()
        .iter()
        .filter(|capability| {
            matches!(
                capability,
                Capability::Resolver(ResolverCommand::Resolve(job))
                    if matches!(job.key(), RetrievalKey::Vqc(_))
            )
        })
        .count();
    assert_eq!(requested, 0, "no V-QC is retrieved");
    driver.drain_persisting(recovered);
    quiesce(&mut driver);
    let machine = driver.machine();
    assert_eq!(machine.held_vqc(&b4.id), Some(b4));
    assert_eq!(machine.held_vqc(&parent.id), Some(parent.clone()));
    assert_eq!(machine.components.vqcs.orphan_count(), 0);

    for block in &blocks[3..] {
        parent = run_view(&mut driver, &committee, &parent, block);
    }
    let machine = driver.machine();
    assert_eq!(machine.components.emitter.finalized, View::new(10));
    assert!(
        machine.durable.state.ancestors.is_empty(),
        "retention drops the ancestors once it passes them"
    );
}
