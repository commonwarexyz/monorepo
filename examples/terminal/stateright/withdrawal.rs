//! Finite native withdrawal lifecycle and deterministic refinement traces.
//!
//! Each fixture has three close epochs and three immutable signed requests. The
//! first two transfers are one-use environment inputs. Leases remain timely,
//! and at most one admitted predecessor awaits finality. Apply and registration
//! construction are atomic; a new Apply on a frozen epoch is outside this model.
//!
//! Reconciliation has one outstanding genuine certified read. A later read can
//! start only after the previous reply is delivered, so certificate heights are
//! monotonic without a clock in the state. Captured payloads remain immutable
//! across chain progress. Replay of an older certificate is outside this domain.

use stateright::{Checker, Expectation, HasDiscoveries, Model, Property};
use std::collections::{BTreeMap, BTreeSet};

pub type Epoch = u8;
pub type Root = u8;

pub const EPOCHS: usize = 3;
pub const ACCOUNTS: usize = 2;
pub const REQUESTS: usize = 3;
pub const INITIAL_BALANCES: [u64; ACCOUNTS] = [100, 100];
pub const BACKGROUND_LIABILITY: u64 = 200;

const REQUIRED_WITNESSES: [&str; 11] = [
    "intake during active registration",
    "queued tail finalized",
    "queue after freeze requires rebuilt publication",
    "stale fresh reservation released",
    "mixed fresh and queued reconciliation",
    "published registration survives lost response",
    "captured status precedes root advance",
    "captured anchor excludes stale request",
    "captured exclusion loses local boundary race",
    "faulted clean prefix remains claimable",
    "later receipt preserves original acknowledgement",
];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RequestId {
    A0,
    B0,
    A1,
}

impl RequestId {
    pub const ALL: [Self; REQUESTS] = [Self::A0, Self::B0, Self::A1];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn account(self) -> usize {
        match self {
            Self::A0 | Self::A1 => 0,
            Self::B0 => 1,
        }
    }

    pub const fn bit(self) -> u8 {
        1 << self.index()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Withdrawal {
    Amount(u64),
    Close,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Instance {
    pub primary: Withdrawal,
    pub debit: u64,
    pub credit: u64,
}

impl Default for Instance {
    fn default() -> Self {
        Self {
            primary: Withdrawal::Amount(4),
            debit: 98,
            credit: 5,
        }
    }
}

impl Instance {
    pub fn all() -> Vec<Self> {
        [Withdrawal::Amount(4), Withdrawal::Close]
            .into_iter()
            .flat_map(|primary| {
                [0, 98, 100].into_iter().flat_map(move |debit| {
                    [0, 5].into_iter().map(move |credit| Self {
                        primary,
                        debit,
                        credit,
                    })
                })
            })
            .collect()
    }

    pub const fn withdrawal(self, id: RequestId) -> Withdrawal {
        match id {
            RequestId::A0 => self.primary,
            RequestId::B0 => Withdrawal::Amount(3),
            RequestId::A1 => Withdrawal::Amount(1),
        }
    }
}

/// Canonical identity of saved publication material, including opening selection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PacketId {
    pub epoch: Epoch,
    pub requests: u8,
    pub queued: u8,
}

/// Stable native payout-log Append location. Commit locations are never output IDs.
pub type OutputId = u64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransferId {
    Debit,
    Credit,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReadKind {
    Status,
    Withdrawal(usize),
    Anchor(Epoch),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReadPhase {
    Requested,
    Captured,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Action {
    Sign(RequestId),
    Queue(RequestId),
    Apply(RequestId),
    Freeze,
    Publish(PacketId),
    ObserveRegistration,
    Pay(TransferId),
    Cut,
    Admit(Epoch),
    Finalize,
    StartReconcile,
    CaptureRead,
    DeliverRead,
    Restart,
    Fault,
    Refresh(OutputId),
    Claim(OutputId),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Acknowledgement {
    pub epoch: Epoch,
    pub request: RequestId,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Outcome {
    Accepted,
    Rejected,
    Unchanged,
    Acknowledged(Acknowledgement),
    Awaiting(ReadKind, ReadPhase),
}

/// Observations obtainable from SQL, certified native records, and driver messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Projection {
    pub epoch: Epoch,
    pub balances: [u64; ACCOUNTS],
    pub present: [bool; ACCOUNTS],
    pub boundary: [Option<RequestId>; ACCOUNTS],
    pub frozen: bool,
    pub adopted: bool,
    pub faulted: bool,
    pub acknowledgements: [Option<Acknowledgement>; REQUESTS],
    pub receipts: [Option<RequestId>; ACCOUNTS],
    pub anchors: [Option<PacketId>; EPOCHS],
    pub admitted: [bool; EPOCHS],
    pub finalized: Option<Epoch>,
    pub root: Root,
    pub finalized_balances: [u64; ACCOUNTS],
    pub payout_head: u64,
    pub unclaimed: BTreeMap<u64, u64>,
    pub outputs: [[Option<u64>; ACCOUNTS]; EPOCHS],
    /// Certified consumption exists even when its authenticated amount is zero.
    pub released: [[Option<u64>; ACCOUNTS]; EPOCHS],
    /// Oldest finalized unclaimed output discoverable for each account.
    pub claim_head: [Option<OutputId>; ACCOUNTS],
    pub custody: u64,
    pub claimable: u64,
    pub read: Option<(ReadKind, ReadPhase)>,
}

#[derive(Clone, Debug)]
pub struct Trace {
    pub instance: Instance,
    pub name: &'static str,
    pub actions: Vec<Action>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Signed {
    root: Root,
    balance: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Authorization {
    epoch: Epoch,
    reserved: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Close {
    requests: u8,
    outputs: [Option<u64>; ACCOUNTS],
    output_ids: [Option<OutputId>; ACCOUNTS],
    payout_operations: u64,
    successor: [u64; ACCOUNTS],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ClaimCache {
    head: u64,
    start: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Reply {
    Status(Root),
    Withdrawal(Option<RequestId>),
    Anchor(Option<PacketId>),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Reconciliation {
    epoch: Epoch,
    boundary: u8,
    root: Root,
    excluded: u8,
    remaining: u8,
    kind: ReadKind,
    reply: Option<Reply>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct State {
    epoch: Epoch,
    balances: [u64; ACCOUNTS],
    predecessor: [u64; ACCOUNTS],
    signed: [Option<Signed>; REQUESTS],
    authorizations: [Option<Authorization>; REQUESTS],
    prepared: Option<PacketId>,
    adopted: bool,
    faulted: bool,
    packets: BTreeSet<PacketId>,
    paid: u8,
    closes: [Option<Close>; EPOCHS],
    pending: [Option<RequestId>; ACCOUNTS],
    receipts: [Option<RequestId>; ACCOUNTS],
    consumed: u8,
    anchors: [Option<PacketId>; EPOCHS],
    admitted: [bool; EPOCHS],
    root: Root,
    finalized_balances: [u64; ACCOUNTS],
    finalized_payout_head: u64,
    unclaimed: BTreeMap<u64, u64>,
    claim_cache: [Option<ClaimCache>; EPOCHS * ACCOUNTS],
    released: [[Option<u64>; ACCOUNTS]; EPOCHS],
    reconciliation: Option<Reconciliation>,
}

impl State {
    fn claim_head(&self, account: usize) -> Option<OutputId> {
        self.closes
            .iter()
            .enumerate()
            .take(self.root as usize)
            .find_map(|(epoch, close)| {
                close
                    .and_then(|close| close.output_ids[account])
                    .filter(|_| self.released[epoch][account].is_none())
            })
    }

    fn output(&self, id: OutputId) -> Option<(usize, usize, u64)> {
        self.closes.iter().enumerate().find_map(|(epoch, close)| {
            let close = close.as_ref()?;
            close
                .output_ids
                .iter()
                .position(|candidate| *candidate == Some(id))
                .map(|account| (epoch, account, close.outputs[account].unwrap()))
        })
    }

    fn output_id(&self, epoch: usize, account: usize) -> Option<OutputId> {
        self.closes
            .get(epoch)
            .and_then(Option::as_ref)
            .and_then(|close| close.output_ids.get(account).copied().flatten())
    }

    fn claim_slot(&self, id: OutputId) -> Option<usize> {
        self.output(id)
            .map(|(epoch, account, _)| epoch * ACCOUNTS + account)
    }

    fn containing_start(&self, id: OutputId) -> Option<u64> {
        self.unclaimed
            .range(..=id)
            .next_back()
            .and_then(|(start, end)| (id < *end).then_some(*start))
    }

    fn boundary(&self) -> u8 {
        RequestId::ALL.into_iter().fold(0, |mask, id| {
            mask | if self.authorizations[id.index()].is_some_and(|a| a.epoch == self.epoch) {
                id.bit()
            } else {
                0
            }
        })
    }

    fn active(&self) -> Option<PacketId> {
        self.anchors
            .iter()
            .flatten()
            .copied()
            .find(|packet| !self.admitted[packet.epoch as usize])
    }

    fn occupied(&self, account: usize) -> bool {
        self.pending[account].is_some()
            || self.anchors.iter().flatten().any(|packet| {
                packet.epoch >= self.root && contains_account(packet.requests, account)
            })
    }

    fn acknowledgement(&self, id: RequestId) -> Option<Acknowledgement> {
        self.authorizations[id.index()].map(|a| Acknowledgement {
            epoch: a.epoch,
            request: id,
        })
    }
}

fn contains_account(mask: u8, account: usize) -> bool {
    RequestId::ALL
        .into_iter()
        .any(|id| id.account() == account && mask & id.bit() != 0)
}

fn request_for(mask: u8, account: usize) -> Option<RequestId> {
    RequestId::ALL
        .into_iter()
        .find(|id| id.account() == account && mask & id.bit() != 0)
}

const fn canonical(packet: PacketId) -> PacketId {
    PacketId {
        queued: 0,
        ..packet
    }
}

#[derive(Clone, Debug)]
pub struct Transition {
    pub state: State,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug)]
pub struct WithdrawalModel {
    pub instance: Instance,
}

impl Default for WithdrawalModel {
    fn default() -> Self {
        Self::new(Instance::default())
    }
}

impl WithdrawalModel {
    pub const fn new(instance: Instance) -> Self {
        Self { instance }
    }

    pub fn initial_state(&self) -> State {
        State {
            epoch: 0,
            balances: INITIAL_BALANCES,
            predecessor: INITIAL_BALANCES,
            signed: [None; REQUESTS],
            authorizations: [None; REQUESTS],
            prepared: None,
            adopted: false,
            faulted: false,
            packets: BTreeSet::new(),
            paid: u8::from(self.instance.debit == 0) | (u8::from(self.instance.credit == 0) << 1),
            closes: [None; EPOCHS],
            pending: [None; ACCOUNTS],
            receipts: [None; ACCOUNTS],
            consumed: 0,
            anchors: [None; EPOCHS],
            admitted: [false; EPOCHS],
            root: 0,
            finalized_balances: INITIAL_BALANCES,
            finalized_payout_head: 1,
            unclaimed: BTreeMap::new(),
            claim_cache: [None; EPOCHS * ACCOUNTS],
            released: [[None; ACCOUNTS]; EPOCHS],
            reconciliation: None,
        }
    }

    pub fn projection(&self, state: &State) -> Projection {
        let boundary = state.boundary();
        let finalized_outputs = state
            .closes
            .iter()
            .enumerate()
            .take(state.root as usize)
            .flat_map(|(_, close)| close.iter().flat_map(|c| c.outputs.into_iter().flatten()))
            .sum::<u64>();
        let released = state.released.iter().flatten().flatten().sum::<u64>();
        Projection {
            epoch: state.epoch,
            balances: state.balances,
            present: state.balances.map(|balance| balance > 0),
            boundary: std::array::from_fn(|account| request_for(boundary, account)),
            frozen: state.prepared.is_some(),
            adopted: state.adopted,
            faulted: state.faulted,
            acknowledgements: std::array::from_fn(|i| state.acknowledgement(RequestId::ALL[i])),
            receipts: state.receipts,
            anchors: state.anchors,
            admitted: state.admitted,
            finalized: state.root.checked_sub(1),
            root: state.root,
            finalized_balances: state.finalized_balances,
            payout_head: state.finalized_payout_head,
            unclaimed: state.unclaimed.clone(),
            outputs: state
                .closes
                .map(|close| close.map_or([None; ACCOUNTS], |c| c.outputs)),
            released: state.released,
            claim_head: std::array::from_fn(|account| state.claim_head(account)),
            custody: BACKGROUND_LIABILITY + INITIAL_BALANCES.iter().sum::<u64>()
                - finalized_outputs,
            claimable: finalized_outputs - released,
            read: state.reconciliation.map(|r| {
                (
                    r.kind,
                    if r.reply.is_some() {
                        ReadPhase::Captured
                    } else {
                        ReadPhase::Requested
                    },
                )
            }),
        }
    }

    pub fn step(&self, before: &State, action: Action) -> Transition {
        let mut state = before.clone();
        let outcome = self.apply(&mut state, action);
        Transition { state, outcome }
    }

    fn apply(&self, state: &mut State, action: Action) -> Outcome {
        if state.faulted
            && matches!(
                action,
                Action::Sign(_)
                    | Action::Queue(_)
                    | Action::Apply(_)
                    | Action::Freeze
                    | Action::Publish(_)
                    | Action::ObserveRegistration
                    | Action::Pay(_)
                    | Action::Cut
                    | Action::Admit(_)
            )
        {
            return Outcome::Rejected;
        }
        match action {
            Action::Sign(id) => {
                if state.signed[id.index()].is_some() {
                    return Outcome::Unchanged;
                }
                let balance = state.finalized_balances[id.account()];
                if balance == 0 {
                    return Outcome::Rejected;
                }
                state.signed[id.index()] = Some(Signed {
                    root: state.root,
                    balance,
                });
                Outcome::Accepted
            }
            Action::Queue(id) => {
                let Some(signed) = state.signed[id.index()] else {
                    return Outcome::Rejected;
                };
                let eligible = signed.root == state.root
                    && signed.balance > 0
                    && state.consumed & id.bit() == 0
                    && !state.occupied(id.account())
                    && match self.instance.withdrawal(id) {
                        Withdrawal::Amount(amount) => amount <= signed.balance,
                        Withdrawal::Close => true,
                    };
                if eligible {
                    state.pending[id.account()] = Some(id);
                    state.receipts[id.account()] = Some(id);
                    state.consumed |= id.bit();
                    Outcome::Accepted
                } else if state.receipts[id.account()] == Some(id) {
                    // Submission replies are advisory; the exact retained receipt is observable.
                    Outcome::Unchanged
                } else {
                    Outcome::Rejected
                }
            }
            Action::Apply(id) => {
                if let Some(acknowledgement) = state.acknowledgement(id) {
                    return Outcome::Acknowledged(acknowledgement);
                }
                let Some(signed) = state.signed[id.index()] else {
                    return Outcome::Rejected;
                };
                if state.epoch as usize >= EPOCHS
                    || state.prepared.is_some()
                    || contains_account(state.boundary(), id.account())
                {
                    return Outcome::Rejected;
                }
                let queued = state.receipts[id.account()] == Some(id);
                if !queued && (signed.root != state.root || state.predecessor[id.account()] == 0) {
                    return Outcome::Rejected;
                }
                let reserved = match self.instance.withdrawal(id) {
                    Withdrawal::Amount(amount) if amount <= state.balances[id.account()] => {
                        Some(amount)
                    }
                    Withdrawal::Amount(_) if !queued => return Outcome::Rejected,
                    Withdrawal::Amount(_) | Withdrawal::Close => None,
                };
                if let Some(amount) = reserved {
                    state.balances[id.account()] -= amount;
                }
                state.authorizations[id.index()] = Some(Authorization {
                    epoch: state.epoch,
                    reserved,
                });
                Outcome::Acknowledged(Acknowledgement {
                    epoch: state.epoch,
                    request: id,
                })
            }
            Action::Freeze => {
                if state.epoch as usize >= EPOCHS
                    || (state.epoch > 0 && !state.admitted[usize::from(state.epoch - 1)])
                {
                    return Outcome::Rejected;
                }
                let requests = state.boundary();
                let queued = RequestId::ALL
                    .into_iter()
                    .filter(|id| {
                        requests & id.bit() != 0 && state.receipts[id.account()] == Some(*id)
                    })
                    .fold(0, |mask, id| mask | id.bit());
                if RequestId::ALL.into_iter().any(|id| {
                    requests & id.bit() != 0
                        && queued & id.bit() == 0
                        && state.predecessor[id.account()] == 0
                }) {
                    return Outcome::Rejected;
                }
                let packet = PacketId {
                    epoch: state.epoch,
                    requests,
                    queued,
                };
                let changed = state.packets.insert(packet);
                state.prepared = Some(packet);
                if changed {
                    Outcome::Accepted
                } else {
                    Outcome::Unchanged
                }
            }
            Action::Publish(packet) => {
                if !state.packets.contains(&packet) {
                    return Outcome::Rejected;
                }
                if state.anchors[packet.epoch as usize] == Some(canonical(packet)) {
                    return Outcome::Unchanged;
                }
                let next = state
                    .admitted
                    .iter()
                    .take_while(|admitted| **admitted)
                    .count();
                if state.active().is_some() || packet.epoch as usize != next {
                    return Outcome::Rejected;
                }
                for account in 0..ACCOUNTS {
                    if state.pending[account].is_some()
                        && request_for(packet.requests, account) != state.pending[account]
                    {
                        return Outcome::Rejected;
                    }
                }
                let mut extra = 0;
                for id in RequestId::ALL {
                    if packet.requests & id.bit() == 0 || state.pending[id.account()] == Some(id) {
                        continue;
                    }
                    let signed =
                        state.signed[id.index()].expect("saved packets have signed requests");
                    let predecessor = if packet.epoch == 0 {
                        INITIAL_BALANCES
                    } else {
                        state.closes[packet.epoch as usize - 1]
                            .expect("admitted predecessor has a close")
                            .successor
                    };
                    if signed.root != state.root
                        || state.consumed & id.bit() != 0
                        || state.occupied(id.account())
                        || predecessor[id.account()] == 0
                        || matches!(self.instance.withdrawal(id), Withdrawal::Amount(amount) if amount > predecessor[id.account()])
                    {
                        return Outcome::Rejected;
                    }
                    extra |= id.bit();
                }
                if packet.requests & !packet.queued != extra {
                    return Outcome::Rejected;
                }
                state.anchors[packet.epoch as usize] = Some(canonical(packet));
                Outcome::Accepted
            }
            Action::ObserveRegistration => {
                let Some(prepared) = state.prepared else {
                    return Outcome::Rejected;
                };
                if state.anchors[state.epoch as usize] != Some(canonical(prepared)) {
                    return Outcome::Rejected;
                }
                if state.adopted {
                    return Outcome::Unchanged;
                }
                state.adopted = true;
                Outcome::Accepted
            }
            Action::Pay(transfer) => {
                let (epoch, bit, payer, receiver, amount) = match transfer {
                    TransferId::Debit => (0, 1, 0, 1, self.instance.debit),
                    TransferId::Credit => (1, 2, 1, 0, self.instance.credit),
                };
                if state.paid & bit != 0 {
                    return Outcome::Unchanged;
                }
                if state.epoch != epoch
                    || !state.adopted
                    || state.predecessor[payer] == 0
                    || state.balances[payer] < amount
                {
                    return Outcome::Rejected;
                }
                state.balances[payer] -= amount;
                state.balances[receiver] += amount;
                state.paid |= bit;
                Outcome::Accepted
            }
            Action::Cut => {
                if state.epoch as usize >= EPOCHS || !state.adopted {
                    return Outcome::Rejected;
                }
                let requests = state.boundary();
                let mut outputs = [None; ACCOUNTS];
                for id in RequestId::ALL {
                    if requests & id.bit() == 0 {
                        continue;
                    }
                    let authorization =
                        state.authorizations[id.index()].expect("boundary owns authorizations");
                    let tail = state.balances[id.account()] + authorization.reserved.unwrap_or(0);
                    let output = match self.instance.withdrawal(id) {
                        Withdrawal::Amount(amount) if amount <= tail => amount,
                        Withdrawal::Amount(_) => 0,
                        Withdrawal::Close => tail,
                    };
                    outputs[id.account()] = Some(output);
                    state.balances[id.account()] = tail - output;
                }
                let row_start = state
                    .epoch
                    .checked_sub(1)
                    .and_then(|epoch| state.closes[epoch as usize])
                    .map_or(1, |close| close.payout_operations);
                let mut next = row_start;
                let output_ids = std::array::from_fn(|account| {
                    outputs[account].map(|_| {
                        let id = next;
                        next += 1;
                        id
                    })
                });
                state.closes[state.epoch as usize] = Some(Close {
                    requests,
                    outputs,
                    output_ids,
                    payout_operations: next + 1,
                    successor: state.balances,
                });
                state.epoch += 1;
                state.predecessor = state.balances;
                state.prepared = None;
                state.adopted = false;
                Outcome::Accepted
            }
            Action::Admit(epoch) => {
                if state.admitted[epoch as usize] {
                    return Outcome::Unchanged;
                }
                let Some(close) = state.closes[epoch as usize] else {
                    return Outcome::Rejected;
                };
                let Some(active) = state.active() else {
                    return Outcome::Rejected;
                };
                if active.epoch != epoch || active.requests != close.requests {
                    return Outcome::Rejected;
                }
                for id in RequestId::ALL {
                    if close.requests & id.bit() != 0 {
                        if state.pending[id.account()] == Some(id) {
                            state.pending[id.account()] = None;
                        }
                        state.consumed |= id.bit();
                    }
                }
                state.admitted[epoch as usize] = true;
                Outcome::Accepted
            }
            Action::Finalize => {
                if state.root as usize >= EPOCHS || !state.admitted[state.root as usize] {
                    return Outcome::Rejected;
                }
                let close = state.closes[state.root as usize].expect("admission owns a close");
                state.finalized_balances = close.successor;
                let end = close.payout_operations - 1;
                if state.finalized_payout_head < end {
                    state.unclaimed.insert(state.finalized_payout_head, end);
                }
                state.finalized_payout_head = close.payout_operations;
                state.root += 1;
                Outcome::Accepted
            }
            Action::StartReconcile => {
                if state.reconciliation.is_some() {
                    return Outcome::Rejected;
                }
                let boundary = state.boundary();
                if boundary == 0 || state.adopted {
                    return Outcome::Accepted;
                }
                state.reconciliation = Some(Reconciliation {
                    epoch: state.epoch,
                    boundary,
                    root: 0,
                    excluded: 0,
                    remaining: boundary,
                    kind: ReadKind::Status,
                    reply: None,
                });
                Outcome::Awaiting(ReadKind::Status, ReadPhase::Requested)
            }
            Action::CaptureRead => {
                let Some(mut operation) = state.reconciliation else {
                    return Outcome::Rejected;
                };
                if operation.reply.is_some() {
                    return Outcome::Rejected;
                }
                operation.reply = Some(match operation.kind {
                    ReadKind::Status => Reply::Status(state.root),
                    ReadKind::Withdrawal(account) => Reply::Withdrawal(state.receipts[account]),
                    ReadKind::Anchor(epoch) => Reply::Anchor(state.anchors[epoch as usize]),
                });
                state.reconciliation = Some(operation);
                Outcome::Awaiting(operation.kind, ReadPhase::Captured)
            }
            Action::DeliverRead => self.deliver(state),
            Action::Restart => {
                state.reconciliation = None;
                Outcome::Accepted
            }
            Action::Fault => {
                if state.faulted {
                    return Outcome::Unchanged;
                }
                if state.active().is_none() {
                    return Outcome::Rejected;
                }
                state.faulted = true;
                Outcome::Accepted
            }
            Action::Refresh(output) => {
                let Some((epoch, account, _)) = state.output(output) else {
                    return Outcome::Rejected;
                };
                if epoch >= state.root as usize {
                    return Outcome::Rejected;
                }
                let slot = epoch * ACCOUNTS + account;
                state.claim_cache[slot] = Some(ClaimCache {
                    head: state.finalized_payout_head,
                    start: state.containing_start(output),
                });
                Outcome::Accepted
            }
            Action::Claim(output) => {
                let Some((epoch, account, amount)) = state.output(output) else {
                    return Outcome::Rejected;
                };
                let slot = epoch * ACCOUNTS + account;
                let Some(cache) = state.claim_cache[slot] else {
                    return Outcome::Rejected;
                };
                if cache.head != state.finalized_payout_head {
                    return Outcome::Rejected;
                }
                if state.released[epoch][account].is_some() {
                    return Outcome::Unchanged;
                }
                if epoch >= state.root as usize {
                    return Outcome::Rejected;
                }
                let Some(start) = state.containing_start(output) else {
                    return Outcome::Rejected;
                };
                if cache.start != Some(start) {
                    return Outcome::Rejected;
                }
                let end = state
                    .unclaimed
                    .remove(&start)
                    .expect("covering interval exists");
                if start < output {
                    state.unclaimed.insert(start, output);
                }
                if output + 1 < end {
                    state.unclaimed.insert(output + 1, end);
                }
                state.claim_cache[slot] = None;
                state.released[epoch][account] = Some(amount);
                Outcome::Accepted
            }
        }
    }

    fn deliver(&self, state: &mut State) -> Outcome {
        let Some(mut operation) = state.reconciliation else {
            return Outcome::Rejected;
        };
        let Some(reply) = operation.reply.take() else {
            return Outcome::Rejected;
        };
        match reply {
            Reply::Status(root) => operation.root = root,
            Reply::Withdrawal(receipt) => {
                let ReadKind::Withdrawal(account) = operation.kind else {
                    unreachable!()
                };
                let id = request_for(operation.remaining, account)
                    .expect("pending read owns one request");
                if receipt != Some(id) {
                    operation.excluded |= id.bit();
                }
                operation.remaining &= !id.bit();
            }
            Reply::Anchor(anchor) => {
                if anchor.is_none()
                    && state.epoch == operation.epoch
                    && state.boundary() == operation.boundary
                    && !state.adopted
                {
                    for id in RequestId::ALL {
                        if operation.excluded & id.bit() == 0 {
                            continue;
                        }
                        let authorization = state.authorizations[id.index()]
                            .take()
                            .expect("matching boundary owns request");
                        state.balances[id.account()] += authorization.reserved.unwrap_or(0);
                    }
                    state.prepared = None;
                }
                state.reconciliation = None;
                return Outcome::Accepted;
            }
        }
        for account in 0..ACCOUNTS {
            let Some(id) = request_for(operation.remaining, account) else {
                continue;
            };
            if state.signed[id.index()]
                .expect("staged request is signed")
                .root
                == operation.root
            {
                operation.remaining &= !id.bit();
                continue;
            }
            operation.kind = ReadKind::Withdrawal(account);
            state.reconciliation = Some(operation);
            return Outcome::Awaiting(operation.kind, ReadPhase::Requested);
        }
        if operation.excluded == 0 {
            state.reconciliation = None;
            Outcome::Accepted
        } else {
            operation.kind = ReadKind::Anchor(operation.epoch);
            state.reconciliation = Some(operation);
            Outcome::Awaiting(operation.kind, ReadPhase::Requested)
        }
    }

    fn intake_available(&self, state: &State) -> bool {
        if state.faulted {
            return true;
        }
        RequestId::ALL.into_iter().all(|id| {
            let Some(signed) = state.signed[id.index()] else {
                return true;
            };
            let affordable = match self.instance.withdrawal(id) {
                Withdrawal::Amount(amount) => signed.balance >= amount,
                Withdrawal::Close => signed.balance > 0,
            };
            if signed.root != state.root
                || !affordable
                || state.consumed & id.bit() != 0
                || state.pending[id.account()].is_some()
                || state
                    .anchors
                    .iter()
                    .flatten()
                    .any(|a| a.epoch >= state.root && contains_account(a.requests, id.account()))
            {
                return true;
            }
            let result = self.step(state, Action::Queue(id));
            result.outcome == Outcome::Accepted
                && result.state.pending[id.account()] == Some(id)
                && result.state.receipts[id.account()] == Some(id)
                && result.state.anchors == state.anchors
        })
    }

    fn exact_retry(&self, state: &State) -> bool {
        if state.faulted {
            return true;
        }
        RequestId::ALL.into_iter().all(|id| {
            let Some(authorization) = state.authorizations[id.index()] else {
                return true;
            };
            let result = self.step(state, Action::Apply(id));
            result.outcome
                == Outcome::Acknowledged(Acknowledgement {
                    epoch: authorization.epoch,
                    request: id,
                })
                && result.state == *state
        })
    }

    fn staging_available(&self, state: &State) -> bool {
        if state.faulted || state.prepared.is_some() || state.epoch as usize >= EPOCHS {
            return true;
        }
        RequestId::ALL.into_iter().all(|id| {
            let Some(signed) = state.signed[id.index()] else {
                return true;
            };
            if state.authorizations[id.index()].is_some()
                || contains_account(state.boundary(), id.account())
            {
                return true;
            }
            let accepted = state.receipts[id.account()] == Some(id);
            let fresh = signed.root == state.root
                && state.predecessor[id.account()] > 0
                && match self.instance.withdrawal(id) {
                    Withdrawal::Amount(amount) => state.balances[id.account()] >= amount,
                    Withdrawal::Close => true,
                };
            if !accepted && !fresh {
                return true;
            }
            let result = self.step(state, Action::Apply(id));
            result.outcome
                == Outcome::Acknowledged(Acknowledgement {
                    epoch: state.epoch,
                    request: id,
                })
                && result.state.boundary() == state.boundary() | id.bit()
        })
    }

    fn custody(&self, state: &State) -> bool {
        let outputs = state
            .closes
            .iter()
            .flatten()
            .flat_map(|close| close.outputs.into_iter().flatten())
            .sum::<u64>();
        let reserved = state
            .authorizations
            .iter()
            .flatten()
            .filter(|a| a.epoch == state.epoch)
            .filter_map(|a| a.reserved)
            .sum::<u64>();
        if state.balances.iter().sum::<u64>() + reserved + outputs != 200 {
            return false;
        }
        let projection = self.projection(state);
        if projection.custody
            + projection.claimable
            + projection.released.iter().flatten().flatten().sum::<u64>()
            != 400
        {
            return false;
        }
        for epoch in 0..EPOCHS {
            for account in 0..ACCOUNTS {
                let output = state.closes[epoch].and_then(|c| c.outputs[account]);
                if state.released[epoch][account].is_some()
                    && (epoch >= state.root as usize || state.released[epoch][account] != output)
                {
                    return false;
                }
                let Some(id) = state.output_id(epoch, account) else {
                    if output.is_some() {
                        return false;
                    }
                    continue;
                };
                let refreshed = self.step(state, Action::Refresh(id));
                let first = self.step(&refreshed.state, Action::Claim(id));
                let second = self.step(&first.state, Action::Claim(id));
                if state.released[epoch][account].is_none()
                    && output.is_some()
                    && epoch < state.root as usize
                    && (first.outcome != Outcome::Accepted
                        || first.state.released[epoch][account] != output)
                {
                    return false;
                }
                if first.state.released != second.state.released {
                    return false;
                }
                if state.released[epoch][account].is_some() && first.outcome != Outcome::Unchanged {
                    return false;
                }
            }
        }
        let outstanding = state
            .closes
            .iter()
            .enumerate()
            .take(state.root as usize)
            .flat_map(|(_, close)| close.iter())
            .flat_map(|close| close.output_ids.into_iter().flatten())
            .filter(|id| {
                state
                    .output(*id)
                    .is_some_and(|(epoch, account, _)| state.released[epoch][account].is_none())
            })
            .collect::<BTreeSet<_>>();
        let covered = state
            .unclaimed
            .iter()
            .flat_map(|(start, end)| *start..*end)
            .collect::<BTreeSet<_>>();
        if outstanding != covered || state.unclaimed.len() > outstanding.len() {
            return false;
        }
        for account in 0..ACCOUNTS {
            let expected = outstanding.iter().copied().find(|id| {
                state
                    .output(*id)
                    .is_some_and(|(_, output_account, _)| output_account == account)
            });
            if state.claim_head(account) != expected {
                return false;
            }
        }
        true
    }

    fn safe_discard(&self, state: &State) -> bool {
        let next = self.step(state, Action::DeliverRead).state;
        if state.reconciliation.is_some_and(|operation| {
            operation.epoch != state.epoch
                || operation.boundary != state.boundary()
                || state.adopted
        }) && (next.authorizations != state.authorizations
            || next.balances != state.balances
            || next.prepared != state.prepared)
        {
            return false;
        }
        RequestId::ALL.into_iter().all(|id| {
            let Some(authorization) = state.authorizations[id.index()] else {
                return true;
            };
            if next.authorizations[id.index()].is_some() {
                return true;
            }
            let signed = state.signed[id.index()].expect("authorization is signed");
            authorization.epoch == state.epoch
                && signed.root != state.root
                && state.consumed & id.bit() == 0
                && !state
                    .anchors
                    .iter()
                    .flatten()
                    .any(|a| a.epoch == authorization.epoch && a.requests & id.bit() != 0)
        })
    }

    fn cleanup_progress(&self, state: &State) -> bool {
        if state.faulted
            || state.reconciliation.is_some()
            || state.adopted
            || state.epoch as usize >= EPOCHS
            || state.anchors[state.epoch as usize].is_some()
            || (state.epoch > 0 && !state.admitted[usize::from(state.epoch - 1)])
        {
            return true;
        }
        let stale = RequestId::ALL
            .into_iter()
            .filter(|id| {
                state.authorizations[id.index()].is_some_and(|a| a.epoch == state.epoch)
                    && state.signed[id.index()].is_some_and(|s| s.root != state.root)
                    && state.receipts[id.account()] != Some(*id)
            })
            .fold(0, |mask, id| mask | id.bit());
        if stale == 0 {
            return true;
        }
        let mut drained = self.step(state, Action::StartReconcile).state;
        while let Some(operation) = drained.reconciliation {
            let action = if operation.reply.is_some() {
                Action::DeliverRead
            } else {
                Action::CaptureRead
            };
            drained = self.step(&drained, action).state;
        }
        if drained.boundary() != state.boundary() & !stale {
            return false;
        }
        for account in 0..ACCOUNTS {
            let restoration = RequestId::ALL
                .into_iter()
                .filter(|id| id.account() == account && stale & id.bit() != 0)
                .filter_map(|id| state.authorizations[id.index()].and_then(|a| a.reserved))
                .sum::<u64>();
            if drained.balances[account] != state.balances[account] + restoration {
                return false;
            }
        }
        self.step(&drained, Action::Freeze).state.prepared.is_some()
    }

    fn carried_tail(&self, state: &State) -> bool {
        let Some(close) = state.closes[1] else {
            return true;
        };
        if close.requests & RequestId::A0.bit() == 0 || state.receipts[0] != Some(RequestId::A0) {
            return true;
        }
        let tail = 100 - self.instance.debit
            + if state.paid & 2 != 0 {
                self.instance.credit
            } else {
                0
            };
        let expected = match self.instance.primary {
            Withdrawal::Amount(amount) if amount <= tail => amount,
            Withdrawal::Amount(_) => 0,
            Withdrawal::Close => tail,
        };
        close.outputs[0] == Some(expected) && close.successor[0] == tail - expected
    }

    /// Generates deterministic witnesses, followed by explicit retry probes.
    /// Exhaustive safety checking is a separate test; this corpus retains only
    /// named paths, including all twelve successor-tail arithmetic fixtures.
    pub fn generated_traces() -> Vec<Trace> {
        let mut traces = Vec::new();
        for instance in Instance::all() {
            let model = Self::new(instance);
            let comprehensive = instance
                == (Instance {
                    primary: Withdrawal::Amount(4),
                    debit: 0,
                    credit: 5,
                });
            let available = model
                .properties()
                .into_iter()
                .filter(|p| p.expectation == Expectation::Sometimes)
                .map(|p| p.name)
                .collect::<BTreeSet<_>>();
            let names = if comprehensive {
                REQUIRED_WITNESSES.into_iter().collect::<BTreeSet<_>>()
            } else {
                BTreeSet::from(["queued tail finalized"])
            };
            if comprehensive {
                assert_eq!(
                    available, names,
                    "native corpus and witness properties differ"
                );
            } else {
                assert!(
                    names.is_subset(&available),
                    "a required witness property is missing"
                );
            }
            let checker = model
                .checker()
                .threads(1)
                .finish_when(HasDiscoveries::AllOf(names.clone()))
                .spawn_bfs()
                .join();
            for property in model
                .properties()
                .into_iter()
                .filter(|p| p.expectation == Expectation::Always)
            {
                checker.assert_no_discovery(property.name);
            }
            for name in names {
                let path = checker
                    .discovery(name)
                    .unwrap_or_else(|| panic!("missing witness {name}: {instance:?}"));
                let mut state = path.last_state().clone();
                let mut actions = path.into_actions();
                let append = |action, state: &mut State, actions: &mut Vec<Action>| {
                    *state = model.step(state, action).state;
                    actions.push(action);
                };
                if name == "queued tail finalized"
                    || name == "later receipt preserves original acknowledgement"
                {
                    append(Action::Apply(RequestId::A0), &mut state, &mut actions);
                    append(Action::Restart, &mut state, &mut actions);
                    append(Action::Apply(RequestId::A0), &mut state, &mut actions);
                    append(Action::Queue(RequestId::A0), &mut state, &mut actions);
                    let output = state
                        .output_id(1, 0)
                        .expect("finalized tail owns a global payout index");
                    append(Action::Refresh(output), &mut state, &mut actions);
                    append(Action::Claim(output), &mut state, &mut actions);
                    append(Action::Restart, &mut state, &mut actions);
                    append(Action::Refresh(output), &mut state, &mut actions);
                    append(Action::Claim(output), &mut state, &mut actions);
                } else if name == "intake during active registration" {
                    append(Action::Queue(RequestId::A0), &mut state, &mut actions);
                } else if name == "queue after freeze requires rebuilt publication" {
                    let stale = state
                        .prepared
                        .expect("witness retains publication material");
                    assert_eq!(
                        model.step(&state, Action::Publish(stale)).outcome,
                        Outcome::Rejected
                    );
                    append(Action::Publish(stale), &mut state, &mut actions);
                    append(Action::Freeze, &mut state, &mut actions);
                    let rebuilt = state.prepared.expect("registration is rebuilt");
                    assert_ne!(stale, rebuilt);
                    assert_eq!(
                        model.step(&state, Action::Publish(rebuilt)).outcome,
                        Outcome::Accepted
                    );
                    append(Action::Publish(rebuilt), &mut state, &mut actions);
                    append(Action::ObserveRegistration, &mut state, &mut actions);
                } else {
                    if name == "captured anchor excludes stale request"
                        || name == "published registration survives lost response"
                    {
                        append(Action::Restart, &mut state, &mut actions);
                    }
                    if state.reconciliation.is_none() {
                        append(Action::StartReconcile, &mut state, &mut actions);
                    }
                    while let Some(operation) = state.reconciliation {
                        let action = if operation.reply.is_some() {
                            Action::DeliverRead
                        } else {
                            Action::CaptureRead
                        };
                        append(action, &mut state, &mut actions);
                    }
                    if name == "captured status precedes root advance" {
                        append(Action::StartReconcile, &mut state, &mut actions);
                        while let Some(operation) = state.reconciliation {
                            let action = if operation.reply.is_some() {
                                Action::DeliverRead
                            } else {
                                Action::CaptureRead
                            };
                            append(action, &mut state, &mut actions);
                        }
                    }
                    if name == "published registration survives lost response" {
                        append(Action::ObserveRegistration, &mut state, &mut actions);
                    }
                    if state.anchors[1].is_none() && state.prepared.is_none() {
                        let old = state
                            .packets
                            .iter()
                            .find(|p| p.epoch == 1 && p.requests & !state.boundary() != 0)
                            .copied();
                        if let Some(packet) = old {
                            append(Action::Publish(packet), &mut state, &mut actions);
                        }
                        append(Action::Freeze, &mut state, &mut actions);
                        if let Some(packet) = state.prepared {
                            append(Action::Publish(packet), &mut state, &mut actions);
                            append(Action::ObserveRegistration, &mut state, &mut actions);
                        }
                    }
                }
                traces.push(Trace {
                    instance,
                    name,
                    actions,
                });
            }
        }
        traces
    }
}

impl Model for WithdrawalModel {
    type State = State;
    type Action = Action;

    fn init_states(&self) -> Vec<State> {
        vec![self.initial_state()]
    }

    fn actions(&self, state: &State, actions: &mut Vec<Action>) {
        // The fixture signs A0/B0 against the initial finalized root. A1 is a
        // later authorization after A0's own output has reached finality.
        for id in RequestId::ALL {
            let signing_phase = match id {
                RequestId::A0 | RequestId::B0 => state.root == 0 && state.anchors[0].is_some(),
                RequestId::A1 => {
                    state.root >= 2
                        && state.closes[1].is_some_and(|c| c.requests & RequestId::A0.bit() != 0)
                }
            };
            if state.signed[id.index()].is_none() && signing_phase {
                actions.push(Action::Sign(id));
            }
            if state.signed[id.index()].is_some() {
                actions.push(Action::Queue(id));
                if state.prepared.is_none() || state.authorizations[id.index()].is_some() {
                    actions.push(Action::Apply(id));
                }
            }
        }
        if (state.epoch as usize) < EPOCHS {
            actions.push(Action::Freeze);
            actions.push(Action::ObserveRegistration);
            let paid = match state.epoch {
                0 => state.paid & 1 != 0,
                1 => state.paid & 2 != 0,
                _ => true,
            };
            if paid {
                actions.push(Action::Cut)
            }
            if state.epoch == 0 {
                actions.push(Action::Pay(TransferId::Debit))
            }
            if state.epoch == 1 {
                actions.push(Action::Pay(TransferId::Credit))
            }
        }
        actions.extend(state.packets.iter().copied().map(Action::Publish));
        // Serial admission/finality is the explicit timely scheduling fixture;
        // successor registration may still overlap its predecessor's finality.
        if (state.root as usize) < EPOCHS && !state.admitted[state.root as usize] {
            actions.push(Action::Admit(state.root));
        }
        actions.push(Action::Finalize);
        if !state.faulted && state.active().is_some() {
            actions.push(Action::Fault);
        }
        if state.reconciliation.is_none() {
            actions.push(Action::StartReconcile);
        } else {
            actions.push(Action::CaptureRead);
            actions.push(Action::DeliverRead);
        }
        actions.push(Action::Restart);
        for epoch in 0..EPOCHS {
            for account in 0..ACCOUNTS {
                if let Some(output) = state.output_id(epoch, account) {
                    let slot = epoch * ACCOUNTS + account;
                    let current = state.claim_cache[slot].is_some_and(|cache| {
                        cache.head == state.finalized_payout_head
                            && cache.start == state.containing_start(output)
                    });
                    if epoch < state.root as usize
                        && state.released[epoch][account].is_none()
                        && !current
                    {
                        actions.push(Action::Refresh(output));
                    }
                    if current && state.released[epoch][account].is_none() {
                        actions.push(Action::Claim(output));
                    }
                }
            }
        }
    }

    fn next_state(&self, state: &State, action: Action) -> Option<State> {
        let next = self.step(state, action).state;
        (next != *state).then_some(next)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        let mut properties: Vec<Property<Self>> = vec![
            Property::<Self>::always("positive intake remains enabled", Self::intake_available),
            Property::<Self>::always(
                "exact retry returns original acknowledgement",
                Self::exact_retry,
            ),
            Property::<Self>::always(
                "eligible fresh and queued staging remains enabled",
                Self::staging_available,
            ),
            Property::<Self>::always(
                "reservations outputs and payouts conserve custody",
                Self::custody,
            ),
            Property::<Self>::always(
                "reconciliation cannot discard an accepted obligation",
                Self::safe_discard,
            ),
            Property::<Self>::always(
                "delivered exclusion evidence restores registration progress",
                Self::cleanup_progress,
            ),
            Property::<Self>::always(
                "queued carriage settles the successor tail",
                Self::carried_tail,
            ),
            Property::<Self>::sometimes("intake during active registration", |_, s| {
                !s.faulted
                    && s.active().is_some_and(|a| a.epoch == 0)
                    && s.pending[0] == Some(RequestId::A0)
            }),
            Property::<Self>::sometimes("queued tail finalized", |_, s| {
                !s.faulted
                    && s.root >= 2
                    && s.closes[1].is_some_and(|c| c.requests & RequestId::A0.bit() != 0)
                    && s.receipts[0] == Some(RequestId::A0)
            }),
            Property::<Self>::sometimes("faulted clean prefix remains claimable", |_, s| {
                s.faulted
                    && s.root > 0
                    && s.admitted
                        .iter()
                        .skip(s.root as usize)
                        .all(|admitted| !admitted)
                    && s.released
                        .iter()
                        .take(s.root as usize)
                        .flatten()
                        .any(Option::is_some)
            }),
            Property::<Self>::sometimes(
                "queue after freeze requires rebuilt publication",
                |_, s| {
                    !s.faulted
                        && s.epoch == 1
                        && s.root == 0
                        && s.admitted[0]
                        && s.prepared.is_some_and(|packet| {
                            RequestId::ALL.into_iter().any(|id| {
                                packet.requests & id.bit() != 0
                                    && packet.queued & id.bit() == 0
                                    && s.pending[id.account()] == Some(id)
                            })
                        })
                },
            ),
            Property::<Self>::sometimes("stale fresh reservation released", |_, s| {
                stale_released(s, false)
            }),
            Property::<Self>::sometimes("mixed fresh and queued reconciliation", |_, s| {
                stale_released(s, true)
            }),
            Property::<Self>::sometimes("published registration survives lost response", |_, s| {
                !s.faulted
                    && s.root == 1
                    && s.epoch == 1
                    && !s.adopted
                    && s.anchors[1].is_some_and(|p| p.requests != 0)
                    && s.boundary() != 0
            }),
            Property::<Self>::sometimes("captured status precedes root advance", |_, s| {
                !s.faulted
                    && s.reconciliation.is_some_and(
                        |r| matches!(r.reply, Some(Reply::Status(root)) if root < s.root),
                    )
            }),
            Property::<Self>::sometimes("captured anchor excludes stale request", |_, s| {
                !s.faulted
                    && s.reconciliation
                        .is_some_and(|r| r.excluded != 0 && r.reply == Some(Reply::Anchor(None)))
            }),
            Property::<Self>::sometimes("captured exclusion loses local boundary race", |_, s| {
                !s.faulted
                    && s.reconciliation.is_some_and(|r| {
                        r.excluded != 0
                            && r.reply == Some(Reply::Anchor(None))
                            && r.boundary != s.boundary()
                    })
            }),
        ];
        let tail = 100 - self.instance.debit + self.instance.credit;
        if matches!(self.instance.primary, Withdrawal::Amount(amount) if tail != amount && tail > 0)
        {
            properties.push(Property::<Self>::sometimes(
                "later receipt preserves original acknowledgement",
                |_, s| {
                    !s.faulted
                        && s.receipts[0] == Some(RequestId::A1)
                        && s.authorizations[0].is_some_and(|a| a.epoch == 1)
                },
            ));
        }
        properties
    }
}

fn stale_released(state: &State, mixed: bool) -> bool {
    !state.faulted
        && state.epoch == 1
        && state.root == 1
        && state.prepared.is_none()
        && [RequestId::A0, RequestId::B0].into_iter().any(|id| {
            state.authorizations[id.index()].is_none()
                && state.signed[id.index()].is_some_and(|s| s.root == 0)
                && state
                    .packets
                    .iter()
                    .any(|p| p.epoch == 1 && p.requests & id.bit() != 0)
                && (!mixed
                    || [RequestId::A0, RequestId::B0].into_iter().any(|other| {
                        other != id
                            && state.authorizations[other.index()].is_some_and(|a| a.epoch == 1)
                            && state.receipts[other.account()] == Some(other)
                    }))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_all(
        model: &WithdrawalModel,
        state: &mut State,
        actions: impl IntoIterator<Item = Action>,
    ) {
        for action in actions {
            let transition = model.step(state, action);
            assert_ne!(transition.outcome, Outcome::Rejected, "{action:?}");
            *state = transition.state;
        }
    }

    fn close_and_finalize(model: &WithdrawalModel, state: &mut State, epoch: Epoch, requests: u8) {
        let packet = PacketId {
            epoch,
            requests,
            queued: 0,
        };
        apply_all(
            model,
            state,
            [
                Action::Freeze,
                Action::Publish(packet),
                Action::ObserveRegistration,
                Action::Cut,
                Action::Admit(epoch),
                Action::Finalize,
            ],
        );
    }

    #[test]
    fn exhaustive_withdrawal_lifecycle() {
        let mut total = 0;
        for instance in Instance::all() {
            let checker = WithdrawalModel::new(instance)
                .checker()
                .threads(1)
                .spawn_bfs()
                .join();
            assert!(checker.is_done());
            checker.assert_properties();
            eprintln!("{instance:?}: {} states", checker.unique_state_count());
            total += checker.unique_state_count();
        }
        eprintln!("native withdrawal lifecycle: {total} states");
    }

    #[test]
    fn generated_witnesses_are_replayable() {
        let traces = WithdrawalModel::generated_traces();
        assert_eq!(traces.len(), 22);
        assert_eq!(
            traces
                .iter()
                .map(|trace| trace.name)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(REQUIRED_WITNESSES)
        );
        assert_eq!(
            traces
                .iter()
                .filter(|trace| trace.name == "queued tail finalized")
                .count(),
            12
        );
        for trace in traces {
            let model = WithdrawalModel::new(trace.instance);
            let mut state = model.initial_state();
            for action in trace.actions {
                state = model.step(&state, action).state;
            }
            assert!(
                model.custody(&state),
                "{}: {:?}",
                trace.name,
                trace.instance
            );
        }
    }

    #[test]
    fn zero_output_requires_a_certified_claim() {
        let model = WithdrawalModel::new(Instance {
            primary: Withdrawal::Amount(0),
            debit: 0,
            credit: 0,
        });
        let mut state = model.initial_state();
        apply_all(
            &model,
            &mut state,
            [Action::Sign(RequestId::A0), Action::Apply(RequestId::A0)],
        );
        close_and_finalize(&model, &mut state, 0, RequestId::A0.bit());

        let account = RequestId::A0.account();
        let output = state.output_id(0, account).unwrap();
        assert_eq!(state.released[0][account], None);
        let refreshed = model.step(&state, Action::Refresh(output));
        assert_eq!(refreshed.outcome, Outcome::Accepted);
        let claimed = model.step(&refreshed.state, Action::Claim(output));
        assert_eq!(claimed.outcome, Outcome::Accepted);
        assert_eq!(claimed.state.released[0][account], Some(0));
    }

    #[test]
    fn stale_head_and_interval_hint_refresh_the_same_output_identity() {
        let model = WithdrawalModel::default();
        let mut state = model.initial_state();
        apply_all(
            &model,
            &mut state,
            [
                Action::Sign(RequestId::A0),
                Action::Sign(RequestId::B0),
                Action::Apply(RequestId::A0),
                Action::Apply(RequestId::B0),
            ],
        );
        close_and_finalize(
            &model,
            &mut state,
            0,
            RequestId::A0.bit() | RequestId::B0.bit(),
        );
        let first = state.output_id(0, 0).unwrap();
        let second = state.output_id(0, 1).unwrap();
        assert_eq!(second, first + 1);

        apply_all(
            &model,
            &mut state,
            [
                Action::Refresh(first),
                Action::Refresh(second),
                Action::Claim(first),
            ],
        );
        assert_eq!(
            model.step(&state, Action::Claim(second)).outcome,
            Outcome::Rejected
        );
        apply_all(
            &model,
            &mut state,
            [Action::Refresh(second), Action::Claim(second)],
        );

        // An empty finalized epoch changes the current native head without changing identity.
        let model = WithdrawalModel::default();
        let mut state = model.initial_state();
        apply_all(
            &model,
            &mut state,
            [Action::Sign(RequestId::A0), Action::Apply(RequestId::A0)],
        );
        close_and_finalize(&model, &mut state, 0, RequestId::A0.bit());
        let output = state.output_id(0, 0).unwrap();
        apply_all(&model, &mut state, [Action::Refresh(output)]);
        let old_head = state.claim_cache[state.claim_slot(output).unwrap()]
            .unwrap()
            .head;
        close_and_finalize(&model, &mut state, 1, 0);
        assert_ne!(state.finalized_payout_head, old_head);
        assert_eq!(
            model.step(&state, Action::Claim(output)).outcome,
            Outcome::Rejected
        );
        apply_all(
            &model,
            &mut state,
            [Action::Refresh(output), Action::Claim(output)],
        );

        // A different valid path at the same head cannot release the global index twice.
        let released = state.released;
        apply_all(&model, &mut state, [Action::Refresh(output)]);
        assert_eq!(
            model.step(&state, Action::Claim(output)).outcome,
            Outcome::Unchanged
        );
        assert_eq!(state.released, released);
    }

    #[test]
    fn fault_requires_an_active_registration() {
        let model = WithdrawalModel::default();
        let mut state = model.initial_state();
        apply_all(
            &model,
            &mut state,
            [Action::Sign(RequestId::A0), Action::Apply(RequestId::A0)],
        );
        close_and_finalize(&model, &mut state, 0, RequestId::A0.bit());

        let transition = model.step(&state, Action::Fault);
        assert_eq!(transition.outcome, Outcome::Rejected);
        assert_eq!(transition.state, state);
    }

    #[test]
    fn faulted_clean_prefix_claims_without_new_admission() {
        let model = WithdrawalModel::default();
        let mut state = model.initial_state();
        apply_all(
            &model,
            &mut state,
            [
                Action::Sign(RequestId::A0),
                Action::Apply(RequestId::A0),
                Action::Freeze,
                Action::Publish(PacketId {
                    epoch: 0,
                    requests: RequestId::A0.bit(),
                    queued: 0,
                }),
                Action::ObserveRegistration,
                Action::Cut,
                Action::Admit(0),
                Action::Finalize,
                Action::Freeze,
                Action::Publish(PacketId {
                    epoch: 1,
                    requests: 0,
                    queued: 0,
                }),
                Action::ObserveRegistration,
                Action::Fault,
            ],
        );
        let output = state.output_id(0, 0).unwrap();
        let admissions = state.admitted;
        apply_all(
            &model,
            &mut state,
            [Action::Refresh(output), Action::Claim(output)],
        );
        assert_eq!(state.admitted, admissions);
        assert_eq!(
            model.step(&state, Action::Admit(1)).outcome,
            Outcome::Rejected
        );
    }
}
