use stateright::{Checker, Model, Property};

const CLAIM_KINDS: usize = 2;
const BATCHES: usize = 2;
const POSITIONS: usize = 2;
const CLAIMS: usize = CLAIM_KINDS * BATCHES * POSITIONS;
const DESTINATIONS: usize = 3;
const INITIAL_RESERVES: [[u16; BATCHES]; CLAIM_KINDS] = [[5, 12], [24, 36]];
const INITIAL_CUSTODY: u16 = 77;
const VALID_CLAIM_MASK: u16 = (1u16 << CLAIMS) - 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ClaimKind {
    WithdrawalOutput,
    ExternalPayout,
}

impl ClaimKind {
    const ALL: [Self; CLAIM_KINDS] = [Self::WithdrawalOutput, Self::ExternalPayout];

    const fn index(self) -> usize {
        match self {
            Self::WithdrawalOutput => 0,
            Self::ExternalPayout => 1,
        }
    }

    const fn root_role(self) -> RootRole {
        match self {
            Self::WithdrawalOutput => RootRole::WithdrawalOutput,
            Self::ExternalPayout => RootRole::Change,
        }
    }

    const fn root_identity(self, batch_id: BatchId) -> RootIdentity {
        match (self, batch_id) {
            (Self::WithdrawalOutput, BatchId::A) => RootIdentity::WithdrawalA,
            (Self::WithdrawalOutput, BatchId::B) => RootIdentity::WithdrawalB,
            (Self::ExternalPayout, BatchId::A) => RootIdentity::ChangeA,
            (Self::ExternalPayout, BatchId::B) => RootIdentity::ChangeB,
        }
    }

    const fn root(self, batch_id: BatchId) -> AuthenticatedRoot {
        AuthenticatedRoot {
            role: self.root_role(),
            identity: self.root_identity(batch_id),
        }
    }

    const fn outputs(self, batch_id: BatchId) -> [ClaimOutput; POSITIONS] {
        match (self, batch_id) {
            (Self::WithdrawalOutput, BatchId::A) => [
                ClaimOutput {
                    position: 0,
                    destination: Destination::Alice,
                    amount: 2,
                },
                ClaimOutput {
                    position: 1,
                    destination: Destination::Bob,
                    amount: 3,
                },
            ],
            (Self::WithdrawalOutput, BatchId::B) => [
                ClaimOutput {
                    position: 0,
                    destination: Destination::Carol,
                    amount: 5,
                },
                ClaimOutput {
                    position: 1,
                    destination: Destination::Alice,
                    amount: 7,
                },
            ],
            (Self::ExternalPayout, BatchId::A) => [
                ClaimOutput {
                    position: 0,
                    destination: Destination::Bob,
                    amount: 11,
                },
                ClaimOutput {
                    position: 1,
                    destination: Destination::Carol,
                    amount: 13,
                },
            ],
            (Self::ExternalPayout, BatchId::B) => [
                ClaimOutput {
                    position: 0,
                    destination: Destination::Alice,
                    amount: 17,
                },
                ClaimOutput {
                    position: 1,
                    destination: Destination::Bob,
                    amount: 19,
                },
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum BatchId {
    A,
    B,
}

impl BatchId {
    const ALL: [Self; BATCHES] = [Self::A, Self::B];

    const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Destination {
    Alice,
    Bob,
    Carol,
}

impl Destination {
    const fn index(self) -> usize {
        match self {
            Self::Alice => 0,
            Self::Bob => 1,
            Self::Carol => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RootRole {
    WithdrawalOutput,
    Change,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RootIdentity {
    WithdrawalA,
    WithdrawalB,
    ChangeA,
    ChangeB,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AuthenticatedRoot {
    role: RootRole,
    identity: RootIdentity,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ClaimOutput {
    position: u8,
    destination: Destination,
    amount: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct OutputOpening {
    root: AuthenticatedRoot,
    position: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Claim {
    kind: ClaimKind,
    batch_id: BatchId,
    output: ClaimOutput,
    opening: OutputOpening,
}

impl Claim {
    const fn canonical(kind: ClaimKind, batch_id: BatchId, position: u8) -> Self {
        Self {
            kind,
            batch_id,
            output: kind.outputs(batch_id)[position as usize],
            opening: OutputOpening {
                root: kind.root(batch_id),
                position,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ClaimKey {
    kind: ClaimKind,
    batch_id: BatchId,
    output_position: u8,
}

impl ClaimKey {
    const fn index(self) -> usize {
        (self.kind.index() * BATCHES + self.batch_id.index()) * POSITIONS
            + self.output_position as usize
    }

    const fn bit(self) -> u16 {
        1u16 << self.index()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ClaimState {
    reserves: [[u16; BATCHES]; CLAIM_KINDS],
    claimable: u16,
    custody: u16,
    released: u16,
    released_to: [u16; DESTINATIONS],
    consumed: u16,
    last: Option<ClaimKey>,
}

impl Default for ClaimState {
    fn default() -> Self {
        Self {
            reserves: INITIAL_RESERVES,
            claimable: INITIAL_CUSTODY,
            custody: INITIAL_CUSTODY,
            released: 0,
            released_to: [0; DESTINATIONS],
            consumed: 0,
            last: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimAction {
    Claim(Claim),
}

#[derive(Clone)]
struct ClaimModel;

impl ClaimModel {
    fn apply(state: &mut ClaimState, claim: Claim) -> bool {
        let position = usize::from(claim.output.position);
        if position >= POSITIONS
            || claim.output != claim.kind.outputs(claim.batch_id)[position]
            || claim.opening.root != claim.kind.root(claim.batch_id)
            || claim.opening.position != claim.output.position
        {
            return false;
        }

        let key = ClaimKey {
            kind: claim.kind,
            batch_id: claim.batch_id,
            output_position: claim.output.position,
        };
        if state.consumed & key.bit() != 0 {
            return false;
        }

        let kind = claim.kind.index();
        let batch = claim.batch_id.index();
        let amount = claim.output.amount;
        let Some(reserve) = state.reserves[kind][batch].checked_sub(amount) else {
            return false;
        };
        let Some(claimable) = state.claimable.checked_sub(amount) else {
            return false;
        };
        let Some(custody) = state.custody.checked_sub(amount) else {
            return false;
        };
        let Some(released) = state.released.checked_add(amount) else {
            return false;
        };
        let destination = claim.output.destination.index();
        let Some(released_to) = state.released_to[destination].checked_add(amount) else {
            return false;
        };
        state.reserves[kind][batch] = reserve;
        state.claimable = claimable;
        state.custody = custody;
        state.released = released;
        state.released_to[destination] = released_to;
        state.consumed |= key.bit();
        state.last = Some(key);
        true
    }

    const fn expected_reserve(state: &ClaimState, kind: ClaimKind, batch_id: BatchId) -> u16 {
        let outputs = kind.outputs(batch_id);
        let mut total = 0;
        let mut position = 0;
        while position < POSITIONS {
            let key = ClaimKey {
                kind,
                batch_id,
                output_position: position as u8,
            };
            if state.consumed & key.bit() == 0 {
                total += outputs[position].amount;
            }
            position += 1;
        }
        total
    }

    fn expected_releases(state: &ClaimState) -> [u16; DESTINATIONS] {
        let mut releases = [0; DESTINATIONS];
        for kind in ClaimKind::ALL {
            for batch_id in BatchId::ALL {
                for output in kind.outputs(batch_id) {
                    let key = ClaimKey {
                        kind,
                        batch_id,
                        output_position: output.position,
                    };
                    if state.consumed & key.bit() != 0 {
                        releases[output.destination.index()] += output.amount;
                    }
                }
            }
        }
        releases
    }
}

fn custody_is_conserved(_: &ClaimModel, state: &ClaimState) -> bool {
    state.custody.checked_add(state.released) == Some(INITIAL_CUSTODY)
        && state.claimable == state.custody
}

fn reserves_are_exact(_: &ClaimModel, state: &ClaimState) -> bool {
    ClaimKind::ALL.into_iter().all(|kind| {
        BatchId::ALL.into_iter().all(|batch_id| {
            state.reserves[kind.index()][batch_id.index()]
                == ClaimModel::expected_reserve(state, kind, batch_id)
        })
    }) && state.claimable == state.reserves.iter().flatten().copied().sum::<u16>()
}

fn consumed_keys_are_exact(_: &ClaimModel, state: &ClaimState) -> bool {
    if state.consumed & !VALID_CLAIM_MASK != 0 {
        return false;
    }

    let Some(last) = state.last else {
        return state.consumed == 0;
    };
    if usize::from(last.output_position) >= POSITIONS {
        return false;
    }
    state.consumed & last.bit() != 0
}

fn releases_are_exact(_: &ClaimModel, state: &ClaimState) -> bool {
    let releases = ClaimModel::expected_releases(state);
    state.released_to == releases && state.released == releases.into_iter().sum::<u16>()
}

const fn key(kind: ClaimKind, batch_id: BatchId, output_position: u8) -> ClaimKey {
    ClaimKey {
        kind,
        batch_id,
        output_position,
    }
}

const fn multiple_positions_in_one_batch(_: &ClaimModel, state: &ClaimState) -> bool {
    state.consumed & key(ClaimKind::WithdrawalOutput, BatchId::A, 0).bit() != 0
        && state.consumed & key(ClaimKind::WithdrawalOutput, BatchId::A, 1).bit() != 0
}

const fn same_position_across_batches(_: &ClaimModel, state: &ClaimState) -> bool {
    state.consumed & key(ClaimKind::ExternalPayout, BatchId::A, 0).bit() != 0
        && state.consumed & key(ClaimKind::ExternalPayout, BatchId::B, 0).bit() != 0
}

const fn same_tuple_across_kinds(_: &ClaimModel, state: &ClaimState) -> bool {
    state.consumed & key(ClaimKind::WithdrawalOutput, BatchId::A, 0).bit() != 0
        && state.consumed & key(ClaimKind::ExternalPayout, BatchId::A, 0).bit() != 0
}

fn reverse_position_order(_: &ClaimModel, state: &ClaimState) -> bool {
    state.last == Some(key(ClaimKind::WithdrawalOutput, BatchId::B, 0))
        && state.consumed & key(ClaimKind::WithdrawalOutput, BatchId::B, 1).bit() != 0
}

const fn every_claim_drains(_: &ClaimModel, state: &ClaimState) -> bool {
    state.consumed == VALID_CLAIM_MASK
        && state.claimable == 0
        && state.custody == 0
        && state.released == INITIAL_CUSTODY
}

impl Model for ClaimModel {
    type State = ClaimState;
    type Action = ClaimAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![ClaimState::default()]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        for kind in ClaimKind::ALL {
            for batch_id in BatchId::ALL {
                for position in 0..POSITIONS as u8 {
                    let key = key(kind, batch_id, position);
                    if state.consumed & key.bit() == 0 {
                        actions.push(ClaimAction::Claim(Claim::canonical(
                            kind, batch_id, position,
                        )));
                    }
                }
            }
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next = last.clone();
        match action {
            ClaimAction::Claim(claim) => Self::apply(&mut next, claim).then_some(next),
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always("claim custody is conserved", custody_is_conserved),
            Property::always(
                "each namespace and batch reserve is exact",
                reserves_are_exact,
            ),
            Property::always(
                "consumed identities are exact kind-batch-position tuples",
                consumed_keys_are_exact,
            ),
            Property::always(
                "released destinations and amounts are exact",
                releases_are_exact,
            ),
            Property::sometimes(
                "multiple positions in one batch claim independently",
                multiple_positions_in_one_batch,
            ),
            Property::sometimes(
                "the same position across batches claims independently",
                same_position_across_batches,
            ),
            Property::sometimes(
                "the same batch-position tuple claims independently across kinds",
                same_tuple_across_kinds,
            ),
            Property::sometimes(
                "positions may claim in reverse order",
                reverse_position_order,
            ),
            Property::sometimes("all claim namespaces fully drain", every_claim_drains),
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
    assert_eq!(checker.unique_state_count(), 1_025);
    checker.assert_properties();
}

#[test]
fn claims_reject_inexact_identity_and_replay_without_mutation() {
    let state = ClaimState::default();
    let canonical = Claim::canonical(ClaimKind::WithdrawalOutput, BatchId::A, 0);

    let mut wrong_kind = canonical;
    wrong_kind.kind = ClaimKind::ExternalPayout;
    assert_rejected_without_mutation(&state, wrong_kind);

    let mut wrong_root_role = canonical;
    wrong_root_role.opening.root.role = RootRole::Change;
    assert_rejected_without_mutation(&state, wrong_root_role);

    let mut wrong_root_identity = canonical;
    wrong_root_identity.opening.root.identity = RootIdentity::WithdrawalB;
    assert_rejected_without_mutation(&state, wrong_root_identity);

    let mut wrong_batch = canonical;
    wrong_batch.batch_id = BatchId::B;
    assert_rejected_without_mutation(&state, wrong_batch);

    let mut wrong_opening_position = canonical;
    wrong_opening_position.opening.position = 1;
    assert_rejected_without_mutation(&state, wrong_opening_position);

    let mut wrong_output_position = canonical;
    wrong_output_position.output.position = 1;
    wrong_output_position.opening.position = 1;
    assert_rejected_without_mutation(&state, wrong_output_position);

    let mut out_of_range_position = canonical;
    out_of_range_position.output.position = POSITIONS as u8;
    out_of_range_position.opening.position = POSITIONS as u8;
    assert_rejected_without_mutation(&state, out_of_range_position);

    let mut wrong_destination = canonical;
    wrong_destination.output.destination = Destination::Carol;
    assert_rejected_without_mutation(&state, wrong_destination);

    let mut wrong_amount = canonical;
    wrong_amount.output.amount += 1;
    assert_rejected_without_mutation(&state, wrong_amount);

    let mut claimed = state;
    assert!(ClaimModel::apply(&mut claimed, canonical));
    assert_rejected_without_mutation(&claimed, canonical);
}

#[test]
fn claim_namespaces_update_custody_independently_and_atomically() {
    let mut state = ClaimState::default();
    let withdrawal = Claim::canonical(ClaimKind::WithdrawalOutput, BatchId::A, 0);
    let payout = Claim::canonical(ClaimKind::ExternalPayout, BatchId::A, 0);

    assert!(ClaimModel::apply(&mut state, withdrawal));
    assert_eq!(state.reserves, [[3, 12], [24, 36]]);
    assert_eq!(state.claimable, 75);
    assert_eq!(state.custody, 75);
    assert_eq!(state.released, 2);
    assert_eq!(state.released_to, [2, 0, 0]);

    assert!(ClaimModel::apply(&mut state, payout));
    assert_eq!(state.reserves, [[3, 12], [13, 36]]);
    assert_eq!(state.claimable, 64);
    assert_eq!(state.custody, 64);
    assert_eq!(state.released, 13);
    assert_eq!(state.released_to, [2, 11, 0]);
    assert_rejected_without_mutation(&state, payout);

    let underfunded = ClaimState {
        custody: 1,
        ..ClaimState::default()
    };
    assert_rejected_without_mutation(&underfunded, withdrawal);
}

#[test]
fn claim_always_properties_have_direct_negative_controls() {
    let wrong_custody = ClaimState {
        custody: INITIAL_CUSTODY - 1,
        ..ClaimState::default()
    };
    assert!(!custody_is_conserved(&ClaimModel, &wrong_custody));

    let wrong_reserve = ClaimState {
        reserves: [[4, 12], [24, 36]],
        claimable: INITIAL_CUSTODY - 1,
        ..ClaimState::default()
    };
    assert!(!reserves_are_exact(&ClaimModel, &wrong_reserve));

    let invalid_last = ClaimState {
        consumed: key(ClaimKind::WithdrawalOutput, BatchId::A, 0).bit(),
        last: Some(key(ClaimKind::ExternalPayout, BatchId::B, 1)),
        ..ClaimState::default()
    };
    assert!(!consumed_keys_are_exact(&ClaimModel, &invalid_last));

    let wrong_release = ClaimState {
        released_to: [1, 0, 0],
        ..ClaimState::default()
    };
    assert!(!releases_are_exact(&ClaimModel, &wrong_release));
}
