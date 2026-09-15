use stateright::{Checker, Model, Property};
use std::collections::BTreeMap;

// Bootstrap and each epoch's Commit occupy native locations but never enter the ledger.
const OUTPUTS: [(u8, u16, usize); 6] = [
    (1, 2, 0),
    (2, 0, 1),
    (3, 3, 1),
    (5, 5, 2),
    (6, 0, 0),
    (7, 7, 0),
];
const INITIAL_CUSTODY: u16 = 17;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Claim {
    position: u8,
    amount: u16,
    destination: usize,
    root_operations: u8,
    containing_start: u8,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ClaimState {
    finalized: u8,
    fault: bool,
    intervals: BTreeMap<u8, u8>,
    reserve: u16,
    custody: u16,
    released_to: [u16; 3],
    // Ghost issuance and payment identities check the production interval representation.
    issued: u8,
    paid: u8,
    last: Option<u8>,
}

impl Default for ClaimState {
    fn default() -> Self {
        Self {
            finalized: 0,
            fault: false,
            intervals: BTreeMap::new(),
            reserve: 0,
            custody: INITIAL_CUSTODY,
            released_to: [0; 3],
            issued: 0,
            paid: 0,
            last: None,
        }
    }
}

impl ClaimState {
    const fn operations(&self) -> u8 {
        1 + self.finalized * 4
    }

    fn witness(&self, index: usize) -> Claim {
        let (position, amount, destination) = OUTPUTS[index];
        let containing_start = self
            .intervals
            .range(..=position)
            .next_back()
            .filter(|(_, end)| position < **end)
            .map_or(position, |(start, _)| *start);
        Claim {
            position,
            amount,
            destination,
            root_operations: self.operations(),
            containing_start,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimAction {
    Finalize,
    Fault,
    Claim(Claim),
}

#[derive(Clone)]
struct ClaimModel;

impl ClaimModel {
    fn apply(state: &mut ClaimState, claim: Claim) -> bool {
        let Some(index) = OUTPUTS
            .iter()
            .position(|output| *output == (claim.position, claim.amount, claim.destination))
        else {
            return false;
        };
        if claim.root_operations != state.operations() || state.issued & (1 << index) == 0 {
            return false;
        }
        let Some(&end) = state.intervals.get(&claim.containing_start) else {
            return false;
        };
        if claim.position < claim.containing_start || claim.position >= end {
            return false;
        }
        let Some(reserve) = state.reserve.checked_sub(claim.amount) else {
            return false;
        };
        let Some(custody) = state.custody.checked_sub(claim.amount) else {
            return false;
        };
        state.intervals.remove(&claim.containing_start);
        if claim.containing_start < claim.position {
            state
                .intervals
                .insert(claim.containing_start, claim.position);
        }
        if claim.position + 1 < end {
            state.intervals.insert(claim.position + 1, end);
        }
        state.reserve = reserve;
        state.custody = custody;
        state.released_to[claim.destination] += claim.amount;
        state.paid |= 1 << index;
        state.last = Some(claim.position);
        true
    }

    fn finalize(state: &mut ClaimState) -> bool {
        if state.fault || state.finalized == 2 {
            return false;
        }
        let start = state.operations();
        assert!(state.intervals.insert(start, start + 3).is_none());
        let offset = usize::from(state.finalized) * 3;
        for (index, (_, amount, _)) in OUTPUTS.iter().enumerate().skip(offset).take(3) {
            state.reserve += amount;
            state.issued |= 1 << index;
        }
        state.finalized += 1;
        true
    }
}

fn custody_is_conserved(_: &ClaimModel, state: &ClaimState) -> bool {
    state.custody + state.released_to.iter().sum::<u16>() == INITIAL_CUSTODY
}

fn ledger_is_exact(_: &ClaimModel, state: &ClaimState) -> bool {
    let mut actual = Vec::new();
    for (&start, &end) in &state.intervals {
        if start >= end {
            return false;
        }
        actual.extend(start..end);
    }
    let expected = OUTPUTS
        .iter()
        .enumerate()
        .filter(|(index, _)| state.issued & (1 << index) != 0 && state.paid & (1 << index) == 0)
        .map(|(_, (position, _, _))| *position)
        .collect::<Vec<_>>();
    actual == expected && state.intervals.len() <= expected.len() && state.paid & !state.issued == 0
}

fn reserves_are_exact(_: &ClaimModel, state: &ClaimState) -> bool {
    state.reserve
        == OUTPUTS
            .iter()
            .enumerate()
            .filter(|(index, _)| state.issued & (1 << index) != 0 && state.paid & (1 << index) == 0)
            .map(|(_, (_, amount, _))| *amount)
            .sum::<u16>()
}

fn releases_are_exact(_: &ClaimModel, state: &ClaimState) -> bool {
    let mut expected = [0; 3];
    for (index, (_, amount, destination)) in OUTPUTS.iter().enumerate() {
        if state.paid & (1 << index) != 0 {
            expected[*destination] += amount;
        }
    }
    state.released_to == expected
}

impl Model for ClaimModel {
    type State = ClaimState;
    type Action = ClaimAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![ClaimState::default()]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if !state.fault {
            actions.push(ClaimAction::Fault);
            if state.finalized < 2 {
                actions.push(ClaimAction::Finalize);
            }
        }
        for index in 0..OUTPUTS.len() {
            if state.issued & (1 << index) != 0 && state.paid & (1 << index) == 0 {
                actions.push(ClaimAction::Claim(state.witness(index)));
            }
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next = last.clone();
        match action {
            ClaimAction::Finalize => {
                if !Self::finalize(&mut next) {
                    return None;
                }
            }
            ClaimAction::Fault => {
                if next.fault {
                    return None;
                }
                next.fault = true;
            }
            ClaimAction::Claim(claim) => {
                if !Self::apply(&mut next, claim) {
                    return None;
                }
            }
        }
        Some(next)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always("claim custody is conserved", custody_is_conserved),
            Property::always(
                "interval union is issued minus paid native positions",
                ledger_is_exact,
            ),
            Property::always(
                "aggregate reserve equals unpaid amounts",
                reserves_are_exact,
            ),
            Property::always(
                "released destinations and amounts are exact",
                releases_are_exact,
            ),
            Property::sometimes(
                "all withdrawal claims fully drain",
                |_: &Self, s: &ClaimState| {
                    s.finalized == 2 && s.paid == 63 && s.intervals.is_empty() && s.reserve == 0
                },
            ),
            Property::sometimes(
                "fault freezes a claimable prefix and invalidates its suffix",
                |_: &Self, s: &ClaimState| s.fault && s.finalized == 1 && s.paid == 7,
            ),
            Property::sometimes(
                "zero value outputs remain after reserve drains",
                |_: &Self, s: &ClaimState| {
                    s.finalized == 2 && s.reserve == 0 && !s.intervals.is_empty()
                },
            ),
            Property::sometimes(
                "positions may claim in reverse order",
                |_: &Self, s: &ClaimState| s.last == Some(1) && s.paid & (1 << 5) != 0,
            ),
        ]
    }
}

#[cfg(not(test))]
pub(crate) fn explore(address: &str) {
    ClaimModel.checker().threads(1).serve(address);
}

fn assert_rejected_without_mutation(state: &ClaimState, claim: Claim) {
    let mut attempted = state.clone();
    assert!(!ClaimModel::apply(&mut attempted, claim));
    assert_eq!(attempted, *state);
}

#[test]
fn claim_checker_exhausts_every_claim_ordering() {
    let checker = ClaimModel.checker().threads(1).spawn_bfs().join();
    assert!(checker.is_done());
    checker.assert_properties();
}

#[test]
fn claims_reject_inexact_identity_and_replay_without_mutation() {
    let mut state = ClaimState::default();
    ClaimModel::finalize(&mut state);
    let canonical = state.witness(0);
    for claim in [
        Claim {
            root_operations: 1,
            ..canonical
        },
        Claim {
            position: 4,
            ..canonical
        },
        Claim {
            amount: 3,
            ..canonical
        },
        Claim {
            destination: 2,
            ..canonical
        },
        Claim {
            containing_start: 2,
            ..canonical
        },
        state.witness(3),
    ] {
        assert_rejected_without_mutation(&state, claim);
    }
    assert!(ClaimModel::apply(&mut state, canonical));
    assert_rejected_without_mutation(&state, canonical);
}

#[test]
fn first_middle_last_and_zero_claims_split_exactly() {
    for order in [[0, 1, 2], [1, 0, 2], [2, 1, 0]] {
        let mut state = ClaimState::default();
        ClaimModel::finalize(&mut state);
        for index in order {
            let claim = state.witness(index);
            let before = state.reserve;
            assert!(ClaimModel::apply(&mut state, claim));
            if index == 1 {
                assert_eq!(state.reserve, before);
            }
            assert!(ledger_is_exact(&ClaimModel, &state));
        }
        assert!(state.intervals.is_empty());
        assert_eq!(state.reserve, 0);
    }
}

#[test]
fn latest_root_refresh_and_stale_interval_hints_are_independent() {
    let mut state = ClaimState::default();
    ClaimModel::finalize(&mut state);
    let stale = state.witness(2);
    ClaimModel::finalize(&mut state);
    assert_rejected_without_mutation(&state, stale);
    let refreshed = state.witness(2);
    let middle = state.witness(1);
    assert!(ClaimModel::apply(&mut state, middle));
    assert_rejected_without_mutation(&state, refreshed);
    let refreshed = state.witness(2);
    state.fault = true;
    assert!(ClaimModel::apply(&mut state, refreshed));
    assert_rejected_without_mutation(&state, refreshed);
    assert!(ledger_is_exact(&ClaimModel, &state));
}

#[test]
fn withdrawal_claims_update_custody_independently_and_atomically() {
    let mut state = ClaimState::default();
    ClaimModel::finalize(&mut state);
    ClaimModel::finalize(&mut state);
    for (index, reserve, custody) in [(0, 15, 15), (3, 10, 10)] {
        let claim = state.witness(index);
        assert!(ClaimModel::apply(&mut state, claim));
        assert_eq!(state.reserve, reserve);
        assert_eq!(state.custody, custody);
        assert_rejected_without_mutation(&state, claim);
    }
    let claim = state.witness(5);
    state.custody = 1;
    assert_rejected_without_mutation(&state, claim);
}

#[test]
fn claim_always_properties_have_direct_negative_controls() {
    let mut state = ClaimState::default();
    ClaimModel::finalize(&mut state);
    let mut wrong = state.clone();
    wrong.custody -= 1;
    assert!(!custody_is_conserved(&ClaimModel, &wrong));
    let mut wrong = state.clone();
    wrong.reserve -= 1;
    assert!(!reserves_are_exact(&ClaimModel, &wrong));
    let mut wrong = state.clone();
    wrong.intervals.insert(4, 5);
    assert!(!ledger_is_exact(&ClaimModel, &wrong));
    let mut wrong = state;
    wrong.released_to[0] = 1;
    assert!(!releases_are_exact(&ClaimModel, &wrong));
}
