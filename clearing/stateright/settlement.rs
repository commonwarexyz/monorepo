use super::{
    certification::{self, CertifiedClose},
    challenge::{self, ProvenChallenge},
};
use stateright::{Checker, Model, Property};

pub(crate) const ACCOUNT_COUNT: usize = 3;
const BATCH_COUNT: usize = 5;
const TIME_HORIZON: u8 = 12;
const MAX_ADMISSION_DELAY: u8 = 3;
const MIN_CHALLENGE_DURATION: u8 = 2;
const MAX_CHALLENGE_DURATION: u8 = 2;
const MIN_WITHDRAWAL_NOTICE: u8 = 2;
const MAX_WITHDRAWAL_NOTICE: u8 = 20;
const MAX_DESTINATION_BYTES: usize = 8;
const MAX_SAFETY_ROOTS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Account {
    Alice,
    Bob,
    Carol,
}

impl Account {
    const ALL: [Self; ACCOUNT_COUNT] = [Self::Alice, Self::Bob, Self::Carol];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Alice => 0,
            Self::Bob => 1,
            Self::Carol => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Root {
    R0,
    R1,
    R2,
    R3,
    R4,
    Offset,
    Empty,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct AccountState {
    pub(crate) active: bool,
    pub(crate) balance: u16,
}

const fn active(balance: u16) -> AccountState {
    AccountState {
        active: true,
        balance,
    }
}

const ZERO_STATE: AccountState = AccountState {
    active: false,
    balance: 0,
};
const EMPTY_STATE: [AccountState; ACCOUNT_COUNT] = [ZERO_STATE; ACCOUNT_COUNT];
const S0: [AccountState; ACCOUNT_COUNT] = [active(10), active(5), ZERO_STATE];
const S1: [AccountState; ACCOUNT_COUNT] = [active(8), active(9), ZERO_STATE];
const S2: [AccountState; ACCOUNT_COUNT] = [active(7), active(9), ZERO_STATE];
const S3: [AccountState; ACCOUNT_COUNT] = [active(7), active(7), ZERO_STATE];
const S4: [AccountState; ACCOUNT_COUNT] = [ZERO_STATE, active(7), ZERO_STATE];
const S_OFFSET: [AccountState; ACCOUNT_COUNT] = [active(10), active(3), ZERO_STATE];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Destination {
    Alice,
    Bob,
    Carol,
    TooLong,
}

impl Destination {
    const fn encoded_len(self) -> usize {
        match self {
            Self::Alice | Self::Bob | Self::Carol => 4,
            Self::TooLong => MAX_DESTINATION_BYTES + 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Deployment {
    Current,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum WithdrawalAction {
    Amount(u16),
    Close,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum WithdrawalId {
    Amount,
    Close,
    CloseAfterFault,
    Offset,
}

impl WithdrawalId {
    const ALL: [Self; 4] = [
        Self::Amount,
        Self::Close,
        Self::CloseAfterFault,
        Self::Offset,
    ];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Amount => 0,
            Self::Close => 1,
            Self::CloseAfterFault => 2,
            Self::Offset => 3,
        }
    }

    const fn request(self) -> WithdrawalRequest {
        match self {
            Self::Amount => WithdrawalRequest {
                account: Account::Bob,
                destination: Destination::Bob,
                action: WithdrawalAction::Amount(2),
                deadline: 10,
                deployment: Deployment::Current,
                context_root: Root::R0,
                signature_valid: true,
            },
            Self::Close => WithdrawalRequest {
                account: Account::Alice,
                destination: Destination::Alice,
                action: WithdrawalAction::Close,
                deadline: 11,
                deployment: Deployment::Current,
                context_root: Root::R1,
                signature_valid: true,
            },
            Self::CloseAfterFault => WithdrawalRequest {
                account: Account::Alice,
                destination: Destination::Alice,
                action: WithdrawalAction::Close,
                deadline: 11,
                deployment: Deployment::Current,
                context_root: Root::R0,
                signature_valid: true,
            },
            Self::Offset => WithdrawalRequest {
                account: Account::Bob,
                destination: Destination::Bob,
                action: WithdrawalAction::Amount(2),
                deadline: 2,
                deployment: Deployment::Current,
                context_root: Root::R0,
                signature_valid: true,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum WithdrawalKey {
    Known(WithdrawalId),
    Other,
}

impl WithdrawalKey {
    const COUNT: usize = WithdrawalId::ALL.len() + 1;

    const fn index(self) -> usize {
        match self {
            Self::Known(id) => id.index(),
            Self::Other => WithdrawalId::ALL.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct WithdrawalRequest {
    pub(crate) account: Account,
    pub(crate) destination: Destination,
    pub(crate) action: WithdrawalAction,
    pub(crate) deadline: u8,
    pub(crate) deployment: Deployment,
    pub(crate) context_root: Root,
    pub(crate) signature_valid: bool,
}

impl WithdrawalRequest {
    pub(crate) fn replay_key(self) -> WithdrawalKey {
        WithdrawalId::ALL
            .into_iter()
            .find(|id| {
                let canonical = id.request();
                canonical.account == self.account
                    && canonical.destination == self.destination
                    && canonical.action == self.action
                    && canonical.deadline == self.deadline
                    && canonical.deployment == self.deployment
                    && canonical.context_root == self.context_root
            })
            .map_or(WithdrawalKey::Other, WithdrawalKey::Known)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct StateOpening {
    pub(crate) root: Root,
    pub(crate) account: Account,
    pub(crate) state: AccountState,
    pub(crate) authenticated_state: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct WithdrawalAttempt {
    pub(crate) replay_key: WithdrawalKey,
    pub(crate) request: WithdrawalRequest,
    pub(crate) destination_eligible: bool,
    pub(crate) safety_openings: [Option<StateOpening>; MAX_SAFETY_ROOTS],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum DepositId {
    BobTwo,
    AliceOne,
    BobOne,
}

impl DepositId {
    const ALL: [Self; 3] = [Self::BobTwo, Self::AliceOne, Self::BobOne];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::BobTwo => 0,
            Self::AliceOne => 1,
            Self::BobOne => 2,
        }
    }

    const fn event(self) -> DepositEvent {
        match self {
            Self::BobTwo => DepositEvent {
                account: Account::Bob,
                amount: 2,
            },
            Self::AliceOne => DepositEvent {
                account: Account::Alice,
                amount: 1,
            },
            Self::BobOne => DepositEvent {
                account: Account::Bob,
                amount: 1,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DepositEvent {
    account: Account,
    amount: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Anchor {
    A0,
    A1,
    A2,
    A3,
    Offset,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum RegistrationId {
    B0,
    B1,
    B2,
    B3,
    Offset,
}

impl RegistrationId {
    const ALL: [Self; BATCH_COUNT] = [Self::B0, Self::B1, Self::B2, Self::B3, Self::Offset];

    pub(crate) const fn registration(self) -> Registration {
        match self {
            Self::B0 => Registration {
                epoch: 0,
                predecessor: Root::R0,
                anchor: Anchor::A0,
                predecessor_state: S0,
                deposits: [0, 2, 0],
                withdrawals: [None, None, None],
                admission_deadline: 2,
                challenge_deadline: 4,
            },
            Self::B1 => Registration {
                epoch: 1,
                predecessor: Root::R1,
                anchor: Anchor::A1,
                predecessor_state: S1,
                deposits: [0, 0, 0],
                withdrawals: [None, None, None],
                admission_deadline: 3,
                challenge_deadline: 5,
            },
            Self::B2 => Registration {
                epoch: 2,
                predecessor: Root::R2,
                anchor: Anchor::A2,
                predecessor_state: S2,
                deposits: [0, 0, 0],
                withdrawals: [None, Some(WithdrawalId::Amount.request()), None],
                admission_deadline: 4,
                challenge_deadline: 6,
            },
            Self::B3 => Registration {
                epoch: 3,
                predecessor: Root::R3,
                anchor: Anchor::A3,
                predecessor_state: S3,
                deposits: [0, 0, 0],
                withdrawals: [Some(WithdrawalId::Close.request()), None, None],
                admission_deadline: 6,
                challenge_deadline: 8,
            },
            Self::Offset => Registration {
                epoch: 0,
                predecessor: Root::R0,
                anchor: Anchor::Offset,
                predecessor_state: S0,
                deposits: [0, 0, 0],
                withdrawals: [None, Some(WithdrawalId::Offset.request()), None],
                admission_deadline: 1,
                challenge_deadline: 3,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Registration {
    pub(crate) epoch: u8,
    pub(crate) predecessor: Root,
    pub(crate) anchor: Anchor,
    pub(crate) predecessor_state: [AccountState; ACCOUNT_COUNT],
    pub(crate) deposits: [u16; ACCOUNT_COUNT],
    pub(crate) withdrawals: [Option<WithdrawalRequest>; ACCOUNT_COUNT],
    pub(crate) admission_deadline: u8,
    pub(crate) challenge_deadline: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Batch {
    B0,
    B1,
    B2,
    B3,
    Offset,
}

impl Batch {
    const ALL: [Self; BATCH_COUNT] = [Self::B0, Self::B1, Self::B2, Self::B3, Self::Offset];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::B0 => 0,
            Self::B1 => 1,
            Self::B2 => 2,
            Self::B3 => 3,
            Self::Offset => 4,
        }
    }

    pub(crate) const fn registration(self) -> RegistrationId {
        match self {
            Self::B0 => RegistrationId::B0,
            Self::B1 => RegistrationId::B1,
            Self::B2 => RegistrationId::B2,
            Self::B3 => RegistrationId::B3,
            Self::Offset => RegistrationId::Offset,
        }
    }

    const fn bit(self) -> u8 {
        1 << self.index()
    }

    pub(crate) const fn candidate(self) -> Candidate {
        match self {
            Self::B0 => Candidate {
                registration: RegistrationId::B0,
                epoch: 0,
                predecessor: Root::R0,
                anchor: Anchor::A0,
                successor: Root::R1,
                predecessor_state: S0,
                successor_state: S1,
                deposits: [0, 2, 0],
                withdrawals: [None, None, None],
                admission_deadline: 2,
                challenge_deadline: 4,
                withdrawal_output: None,
                payout_output: None,
            },
            Self::B1 => Candidate {
                registration: RegistrationId::B1,
                epoch: 1,
                predecessor: Root::R1,
                anchor: Anchor::A1,
                successor: Root::R2,
                predecessor_state: S1,
                successor_state: S2,
                deposits: [0, 0, 0],
                withdrawals: [None, None, None],
                admission_deadline: 3,
                challenge_deadline: 5,
                withdrawal_output: None,
                payout_output: Some(Output {
                    position: 1,
                    destination: Destination::Carol,
                    amount: 1,
                }),
            },
            Self::B2 => Candidate {
                registration: RegistrationId::B2,
                epoch: 2,
                predecessor: Root::R2,
                anchor: Anchor::A2,
                successor: Root::R3,
                predecessor_state: S2,
                successor_state: S3,
                deposits: [0, 0, 0],
                withdrawals: [None, Some(WithdrawalId::Amount.request()), None],
                admission_deadline: 4,
                challenge_deadline: 6,
                withdrawal_output: Some(Output {
                    position: 0,
                    destination: Destination::Bob,
                    amount: 2,
                }),
                payout_output: None,
            },
            Self::B3 => Candidate {
                registration: RegistrationId::B3,
                epoch: 3,
                predecessor: Root::R3,
                anchor: Anchor::A3,
                successor: Root::R4,
                predecessor_state: S3,
                successor_state: S4,
                deposits: [0, 0, 0],
                withdrawals: [Some(WithdrawalId::Close.request()), None, None],
                admission_deadline: 6,
                challenge_deadline: 8,
                withdrawal_output: Some(Output {
                    position: 0,
                    destination: Destination::Alice,
                    amount: 7,
                }),
                payout_output: None,
            },
            Self::Offset => Candidate {
                registration: RegistrationId::Offset,
                epoch: 0,
                predecessor: Root::R0,
                anchor: Anchor::Offset,
                successor: Root::Offset,
                predecessor_state: S0,
                successor_state: S_OFFSET,
                deposits: [0, 0, 0],
                withdrawals: [None, Some(WithdrawalId::Offset.request()), None],
                admission_deadline: 1,
                challenge_deadline: 3,
                withdrawal_output: Some(Output {
                    position: 0,
                    destination: Destination::Bob,
                    amount: 2,
                }),
                payout_output: None,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Output {
    pub(crate) position: u8,
    pub(crate) destination: Destination,
    pub(crate) amount: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Candidate {
    pub(crate) registration: RegistrationId,
    pub(crate) epoch: u8,
    pub(crate) predecessor: Root,
    pub(crate) anchor: Anchor,
    pub(crate) successor: Root,
    pub(crate) predecessor_state: [AccountState; ACCOUNT_COUNT],
    pub(crate) successor_state: [AccountState; ACCOUNT_COUNT],
    pub(crate) deposits: [u16; ACCOUNT_COUNT],
    pub(crate) withdrawals: [Option<WithdrawalRequest>; ACCOUNT_COUNT],
    pub(crate) admission_deadline: u8,
    pub(crate) challenge_deadline: u8,
    pub(crate) withdrawal_output: Option<Output>,
    pub(crate) payout_output: Option<Output>,
}

impl Candidate {
    const fn withdrawal_total(self) -> u16 {
        match self.withdrawal_output {
            Some(output) => output.amount,
            None => 0,
        }
    }

    const fn payout_total(self) -> u16 {
        match self.payout_output {
            Some(output) => output.amount,
            None => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ForkRelation {
    SameSend,
    SameIndex,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ChallengeKind {
    LatestAcknowledgedSend,
    HigherShardTip,
    InconsistentReceiptRange,
    ReceiptFork(ForkRelation),
}

impl ChallengeKind {
    pub(crate) const ALL: [Self; 6] = [
        Self::LatestAcknowledgedSend,
        Self::HigherShardTip,
        Self::InconsistentReceiptRange,
        Self::ReceiptFork(ForkRelation::SameSend),
        Self::ReceiptFork(ForkRelation::SameIndex),
        Self::ReceiptFork(ForkRelation::Full),
    ];
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum BatchStatus {
    Inactive,
    Pending,
    Challenged(ChallengeKind),
    Invalidated(Batch),
    Finalized,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Fault {
    Healthy,
    ProvenChallenge {
        batch: Batch,
        kind: ChallengeKind,
    },
    ExpiredDeposit {
        account: Account,
        expired_at: u8,
    },
    ExpiredWithdrawal {
        account: Account,
        expired_at: u8,
    },
    ExpiredRegistration {
        registration: RegistrationId,
        anchor: Anchor,
        epoch: u8,
        expired_at: u8,
    },
}

impl Fault {
    pub(crate) const fn healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Terminal {
    Dormant,
    Claiming {
        frozen_root: Root,
        frozen_state: [AccountState; ACCOUNT_COUNT],
        remaining_state: u16,
        remaining_deposits: u16,
    },
    Settled,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SettlementEdge {
    Initial,
    RecordDeposit(DepositId),
    QueueWithdrawal(WithdrawalKey),
    Register(RegistrationId),
    Admit(Batch),
    Observe,
    Fault,
    Challenge(Batch, ChallengeKind),
    Finalize(Batch),
    ClaimWithdrawal {
        batch: Batch,
        source: Batch,
        position: u8,
    },
    ClaimPayout {
        batch: Batch,
        source: Batch,
        position: u8,
    },
    ClaimDeposit(Account),
    BeginTerminal,
    ClaimState(Account),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SettlementState {
    pub(crate) now: u8,
    pub(crate) expected_epoch: u8,
    pub(crate) current_root: Root,
    pub(crate) current_state: [AccountState; ACCOUNT_COUNT],
    pub(crate) current_liability: u16,
    pub(crate) custody: u16,
    pub(crate) claimable: u16,
    pub(crate) total_in: u16,
    pub(crate) released: u16,
    pub(crate) clean_claim_paid: u16,
    pub(crate) pending_deposits: [u16; ACCOUNT_COUNT],
    pub(crate) deposit_deadlines: [Option<u8>; ACCOUNT_COUNT],
    pub(crate) unfinalized_deposits: [u16; ACCOUNT_COUNT],
    pub(crate) pending_withdrawals: [Option<WithdrawalRequest>; ACCOUNT_COUNT],
    pub(crate) outstanding_withdrawals: [Option<WithdrawalRequest>; ACCOUNT_COUNT],
    pub(crate) registered: Option<RegistrationId>,
    pub(crate) pipeline: Vec<Batch>,
    pub(crate) status: [BatchStatus; BATCH_COUNT],
    pub(crate) fault: Fault,
    pub(crate) clean_prefix_len: u8,
    pub(crate) admission_fence_epoch: Option<u8>,
    pub(crate) invalid_from: Option<Batch>,
    pub(crate) terminal: Terminal,
    pub(crate) withdrawal_reserve: [u16; BATCH_COUNT],
    pub(crate) payout_reserve: [u16; BATCH_COUNT],
    pub(crate) claimed_withdrawals: [Option<u8>; BATCH_COUNT],
    pub(crate) claimed_payouts: [Option<u8>; BATCH_COUNT],
    pub(crate) consumed_state: u8,
    pub(crate) consumed_deposits: u8,
    pub(crate) withdrawal_replay_expiries: [Option<u8>; WithdrawalKey::COUNT],
    pub(crate) finalized_batches: u8,
    pub(crate) invalidated_batches: u8,
    pub(crate) finalized_epochs: Vec<u8>,
    pub(crate) refunded_deposits: [u16; ACCOUNT_COUNT],
    pub(crate) recovered_state: [u16; ACCOUNT_COUNT],
    pub(crate) terminal_withdrawals: [u16; ACCOUNT_COUNT],
    pub(crate) terminal_residuals: [u16; ACCOUNT_COUNT],
    pub(crate) last: SettlementEdge,
}

impl Default for SettlementState {
    fn default() -> Self {
        Self {
            now: 0,
            expected_epoch: 0,
            current_root: Root::R0,
            current_state: S0,
            current_liability: 15,
            custody: 15,
            claimable: 0,
            total_in: 15,
            released: 0,
            clean_claim_paid: 0,
            pending_deposits: [0; ACCOUNT_COUNT],
            deposit_deadlines: [None; ACCOUNT_COUNT],
            unfinalized_deposits: [0; ACCOUNT_COUNT],
            pending_withdrawals: [None; ACCOUNT_COUNT],
            outstanding_withdrawals: [None; ACCOUNT_COUNT],
            registered: None,
            pipeline: Vec::new(),
            status: [BatchStatus::Inactive; BATCH_COUNT],
            fault: Fault::Healthy,
            clean_prefix_len: 0,
            admission_fence_epoch: None,
            invalid_from: None,
            terminal: Terminal::Dormant,
            withdrawal_reserve: [0; BATCH_COUNT],
            payout_reserve: [0; BATCH_COUNT],
            claimed_withdrawals: [None; BATCH_COUNT],
            claimed_payouts: [None; BATCH_COUNT],
            consumed_state: 0,
            consumed_deposits: 0,
            withdrawal_replay_expiries: [None; WithdrawalKey::COUNT],
            finalized_batches: 0,
            invalidated_batches: 0,
            finalized_epochs: Vec::new(),
            refunded_deposits: [0; ACCOUNT_COUNT],
            recovered_state: [0; ACCOUNT_COUNT],
            terminal_withdrawals: [0; ACCOUNT_COUNT],
            terminal_residuals: [0; ACCOUNT_COUNT],
            last: SettlementEdge::Initial,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SettlementAction {
    Observe(u8),
    RecordDeposit(DepositId),
    QueueWithdrawal(WithdrawalAttempt),
    Register(RegistrationId),
    Admit(CertifiedClose),
    Challenge(ProvenChallenge),
    Finalize,
    ClaimWithdrawal {
        batch: Batch,
        source: Batch,
        position: u8,
    },
    ClaimPayout {
        batch: Batch,
        source: Batch,
        position: u8,
    },
    ClaimDeposit(Account),
    BeginTerminal,
    ClaimState(Account),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SettlementModel {
    max_pending: usize,
    deposit_timeout: u8,
    certified_closes: [CertifiedClose; BATCH_COUNT],
}

impl Default for SettlementModel {
    fn default() -> Self {
        Self {
            max_pending: 3,
            deposit_timeout: 2,
            certified_closes: certification::certified_closes(),
        }
    }
}

fn state_liability(state: &[AccountState; ACCOUNT_COUNT]) -> u16 {
    state.iter().map(|account| account.balance).sum()
}

fn array_total(values: &[u16; ACCOUNT_COUNT]) -> u16 {
    values.iter().sum()
}

fn batch_total(values: &[u16; BATCH_COUNT]) -> u16 {
    values.iter().sum()
}

const fn account_bit(account: Account) -> u8 {
    1 << account.index()
}

impl SettlementModel {
    pub(crate) fn with_max_pending(max_pending: usize) -> Self {
        Self {
            max_pending,
            ..Self::default()
        }
    }

    pub(crate) fn call_at(
        self,
        state: &SettlementState,
        now: u8,
        action: SettlementAction,
    ) -> (SettlementState, bool) {
        let observed = if now > state.now {
            self.apply(state, SettlementAction::Observe(now))
                .unwrap_or_else(|| state.clone())
        } else {
            state.clone()
        };
        self.apply(&observed, action)
            .map_or((observed, false), |next| (next, true))
    }

    pub(crate) fn apply(
        self,
        last: &SettlementState,
        action: SettlementAction,
    ) -> Option<SettlementState> {
        let mut state = last.clone();
        match action {
            SettlementAction::Observe(at) => self.observe(&mut state, at)?,
            SettlementAction::RecordDeposit(id) => self.record_deposit(&mut state, id)?,
            SettlementAction::QueueWithdrawal(attempt) => {
                self.queue_withdrawal(&mut state, attempt)?;
            }
            SettlementAction::Register(registration) => {
                self.register(&mut state, registration)?;
            }
            SettlementAction::Admit(certified) => self.admit(&mut state, certified)?,
            SettlementAction::Challenge(proven) => {
                self.challenge(&mut state, proven)?;
            }
            SettlementAction::Finalize => self.finalize(&mut state)?,
            SettlementAction::ClaimWithdrawal {
                batch,
                source,
                position,
            } => {
                self.claim_withdrawal(&mut state, batch, source, position)?;
            }
            SettlementAction::ClaimPayout {
                batch,
                source,
                position,
            } => self.claim_payout(&mut state, batch, source, position)?,
            SettlementAction::ClaimDeposit(account) => {
                self.claim_deposit(&mut state, account)?;
            }
            SettlementAction::BeginTerminal => self.begin_terminal(&mut state)?,
            SettlementAction::ClaimState(account) => self.claim_state(&mut state, account)?,
        }
        Some(state)
    }

    fn operating(state: &SettlementState) -> bool {
        state.fault.healthy() && state.terminal == Terminal::Dormant
    }

    fn head_root(state: &SettlementState) -> Root {
        state
            .pipeline
            .last()
            .map_or(state.current_root, |batch| batch.candidate().successor)
    }

    fn head_state(state: &SettlementState) -> [AccountState; ACCOUNT_COUNT] {
        state.pipeline.last().map_or(state.current_state, |batch| {
            batch.candidate().successor_state
        })
    }

    fn next_admission_epoch(state: &SettlementState) -> u8 {
        state
            .pipeline
            .last()
            .map_or(state.expected_epoch, |batch| batch.candidate().epoch + 1)
    }

    fn boundary_deposits(state: &SettlementState) -> [u16; ACCOUNT_COUNT] {
        let mut deposits = state.pending_deposits;
        for account in Account::ALL {
            let index = account.index();
            if let Some(withdrawal) = state.pending_withdrawals[index]
                && let WithdrawalAction::Amount(amount) = withdrawal.action
                && amount == deposits[index]
            {
                deposits[index] = 0;
            }
        }
        deposits
    }

    fn registration_matches(state: &SettlementState, id: RegistrationId) -> bool {
        let registration = id.registration();
        let base = state
            .pipeline
            .last()
            .map_or(state.now, |tail| tail.candidate().admission_deadline);
        let ordered_deadline = if state.pipeline.is_empty() {
            registration.admission_deadline >= base
        } else {
            registration.admission_deadline > base
        };
        let duration = registration
            .challenge_deadline
            .checked_sub(registration.admission_deadline);
        registration.epoch == Self::next_admission_epoch(state)
            && registration.predecessor == Self::head_root(state)
            && registration.predecessor_state == Self::head_state(state)
            && registration.deposits == Self::boundary_deposits(state)
            && registration.withdrawals == state.pending_withdrawals
            && state.now <= registration.admission_deadline
            && ordered_deadline
            && registration.admission_deadline <= base.saturating_add(MAX_ADMISSION_DELAY)
            && duration.is_some_and(|duration| {
                (MIN_CHALLENGE_DURATION..=MAX_CHALLENGE_DURATION).contains(&duration)
            })
            && registration.admission_deadline < TIME_HORIZON
            && registration.challenge_deadline < TIME_HORIZON
    }

    fn candidate_matches_registration(batch: Batch, id: RegistrationId) -> bool {
        let candidate = batch.candidate();
        let registration = id.registration();
        candidate.registration == id
            && candidate.epoch == registration.epoch
            && candidate.predecessor == registration.predecessor
            && candidate.anchor == registration.anchor
            && candidate.predecessor_state == registration.predecessor_state
            && candidate.deposits == registration.deposits
            && candidate.withdrawals == registration.withdrawals
            && candidate.admission_deadline == registration.admission_deadline
            && candidate.challenge_deadline == registration.challenge_deadline
    }

    fn can_register(self, state: &SettlementState, id: RegistrationId) -> bool {
        Self::operating(state)
            && state.registered.is_none()
            && state.pipeline.len() < self.max_pending
            && Self::registration_matches(state, id)
    }

    fn can_record_deposit(self, state: &SettlementState, id: DepositId) -> bool {
        let event = id.event();
        Self::operating(state)
            && state.registered.is_none()
            && state.consumed_deposits & (1 << id.index()) == 0
            && event.amount > 0
            && state.now.saturating_add(self.deposit_timeout) <= TIME_HORIZON
    }

    const fn withdrawal_affordable(
        request: WithdrawalRequest,
        account_state: AccountState,
    ) -> bool {
        account_state.active
            && match request.action {
                WithdrawalAction::Amount(amount) => amount > 0 && amount <= account_state.balance,
                WithdrawalAction::Close => true,
            }
    }

    pub(crate) fn withdrawal_attempt(
        state: &SettlementState,
        id: WithdrawalId,
    ) -> WithdrawalAttempt {
        let request = id.request();
        let index = request.account.index();
        let mut safety_openings = [None; MAX_SAFETY_ROOTS];
        safety_openings[0] = Some(StateOpening {
            root: state.current_root,
            account: request.account,
            state: state.current_state[index],
            authenticated_state: true,
        });
        for (position, batch) in state.pipeline.iter().copied().enumerate() {
            let candidate = batch.candidate();
            safety_openings[position + 1] = Some(StateOpening {
                root: candidate.successor,
                account: request.account,
                state: candidate.successor_state[index],
                authenticated_state: true,
            });
        }
        WithdrawalAttempt {
            replay_key: WithdrawalKey::Known(id),
            request,
            destination_eligible: true,
            safety_openings,
        }
    }

    fn withdrawal_safe(state: &SettlementState, attempt: &WithdrawalAttempt) -> bool {
        let request = attempt.request;
        let expected_count = state.pipeline.len() + 1;
        if expected_count > MAX_SAFETY_ROOTS
            || attempt.safety_openings[..expected_count]
                .iter()
                .any(Option::is_none)
            || attempt.safety_openings[expected_count..]
                .iter()
                .any(Option::is_some)
        {
            return false;
        }
        attempt.safety_openings[..expected_count]
            .iter()
            .enumerate()
            .all(|(position, opening)| {
                let opening = opening.expect("the exact opening count was checked");
                let (root, account_state) = if position == 0 {
                    (
                        state.current_root,
                        state.current_state[request.account.index()],
                    )
                } else {
                    let candidate = state.pipeline[position - 1].candidate();
                    (
                        candidate.successor,
                        candidate.successor_state[request.account.index()],
                    )
                };
                opening.root == root
                    && opening.account == request.account
                    && opening.state == account_state
                    && opening.authenticated_state
                    && Self::withdrawal_affordable(request, opening.state)
            })
    }

    fn can_queue_withdrawal(state: &SettlementState, attempt: &WithdrawalAttempt) -> bool {
        let request = attempt.request;
        let index = request.account.index();
        let earliest = state.now.saturating_add(MIN_WITHDRAWAL_NOTICE);
        let latest = state.now.saturating_add(MAX_WITHDRAWAL_NOTICE);
        Self::operating(state)
            && state.registered.is_none()
            && attempt.replay_key == request.replay_key()
            && state.withdrawal_replay_expiries[attempt.replay_key.index()].is_none()
            && state.pending_withdrawals[index].is_none()
            && state.outstanding_withdrawals[index].is_none()
            && request.signature_valid
            && request.deployment == Deployment::Current
            && request.context_root == state.current_root
            && request.destination.encoded_len() <= MAX_DESTINATION_BYTES
            && attempt.destination_eligible
            && request.deadline >= earliest
            && request.deadline <= latest
            && request.deadline <= TIME_HORIZON
            && Self::withdrawal_safe(state, attempt)
    }

    fn record_deposit(&self, state: &mut SettlementState, id: DepositId) -> Option<()> {
        if !self.can_record_deposit(state, id) {
            return None;
        }
        let event = id.event();
        let index = event.account.index();
        let deadline = state.now + self.deposit_timeout;
        state.custody = state.custody.checked_add(event.amount)?;
        state.total_in = state.total_in.checked_add(event.amount)?;
        state.pending_deposits[index] = state.pending_deposits[index].checked_add(event.amount)?;
        state.unfinalized_deposits[index] =
            state.unfinalized_deposits[index].checked_add(event.amount)?;
        state.deposit_deadlines[index] =
            Some(state.deposit_deadlines[index].map_or(deadline, |old| old.min(deadline)));
        state.consumed_deposits |= 1 << id.index();
        state.last = SettlementEdge::RecordDeposit(id);
        Some(())
    }

    fn queue_withdrawal(
        &self,
        state: &mut SettlementState,
        attempt: WithdrawalAttempt,
    ) -> Option<()> {
        if !Self::can_queue_withdrawal(state, &attempt) {
            return None;
        }
        let request = attempt.request;
        let index = request.account.index();
        state.pending_withdrawals[index] = Some(request);
        state.outstanding_withdrawals[index] = Some(request);
        state.withdrawal_replay_expiries[attempt.replay_key.index()] = Some(request.deadline);
        state.last = SettlementEdge::QueueWithdrawal(attempt.replay_key);
        Some(())
    }

    fn register(&self, state: &mut SettlementState, id: RegistrationId) -> Option<()> {
        if !self.can_register(state, id) {
            return None;
        }
        state.registered = Some(id);
        state.last = SettlementEdge::Register(id);
        Some(())
    }

    fn admit(&self, state: &mut SettlementState, certified: CertifiedClose) -> Option<()> {
        let batch = certified.batch();
        let candidate = batch.candidate();
        let registration = state.registered?;
        if !Self::operating(state)
            || certified.registration() != registration
            || state.now > candidate.admission_deadline
            || state.pipeline.len() >= self.max_pending
            || !Self::registration_matches(state, registration)
            || !Self::candidate_matches_registration(batch, registration)
        {
            return None;
        }
        for account in Account::ALL {
            let index = account.index();
            let included = candidate.deposits[index];
            let old = state.pending_deposits[index];
            state.pending_deposits[index] = old.checked_sub(included)?;
            if old == included {
                state.deposit_deadlines[index] = None;
            }
        }
        state.pending_withdrawals = [None; ACCOUNT_COUNT];
        state.registered = None;
        state.pipeline.push(batch);
        state.status[batch.index()] = BatchStatus::Pending;
        state.last = SettlementEdge::Admit(batch);
        Some(())
    }

    fn registration_expiry(state: &SettlementState) -> Option<(u8, RegistrationId)> {
        state.registered.map(|id| {
            let registration = id.registration();
            (registration.admission_deadline.saturating_add(1), id)
        })
    }

    fn withdrawal_expiry(state: &SettlementState) -> Option<(u8, Account)> {
        Account::ALL
            .into_iter()
            .filter_map(|account| {
                state.outstanding_withdrawals[account.index()]
                    .map(|request| (request.deadline, account))
            })
            .min_by_key(|(deadline, account)| (*deadline, account.index()))
    }

    fn deposit_expiry(state: &SettlementState) -> Option<(u8, Account)> {
        Account::ALL
            .into_iter()
            .filter(|account| state.pending_deposits[account.index()] > 0)
            .filter_map(|account| {
                state.deposit_deadlines[account.index()].map(|deadline| (deadline, account))
            })
            .min_by_key(|(deadline, account)| (*deadline, account.index()))
    }

    fn observed_fault(state: &SettlementState, at: u8) -> Fault {
        let registration = Self::registration_expiry(state);
        let withdrawal = Self::withdrawal_expiry(state);
        let deposit = Self::deposit_expiry(state);
        let first = registration
            .map(|(deadline, _)| deadline)
            .into_iter()
            .chain(withdrawal.map(|(deadline, _)| deadline))
            .chain(deposit.map(|(deadline, _)| deadline))
            .min();
        let Some(first) = first else {
            return Fault::Healthy;
        };
        if first > at {
            return Fault::Healthy;
        }
        if let Some((first_expired, id)) = registration
            && first_expired == first
        {
            let registration = id.registration();
            return Fault::ExpiredRegistration {
                registration: id,
                anchor: registration.anchor,
                epoch: registration.epoch,
                expired_at: registration.admission_deadline,
            };
        }
        if let Some((deadline, account)) = withdrawal
            && deadline == first
        {
            return Fault::ExpiredWithdrawal {
                account,
                expired_at: deadline,
            };
        }
        let (expired_at, account) = deposit.expect("the minimum deadline has a source");
        Fault::ExpiredDeposit {
            account,
            expired_at,
        }
    }

    fn observe(&self, state: &mut SettlementState, at: u8) -> Option<()> {
        if at <= state.now || at > TIME_HORIZON || state.terminal == Terminal::Settled {
            return None;
        }
        let observed = if state.fault.healthy() {
            Self::observed_fault(state, at)
        } else {
            state.fault
        };
        let newly_faulted = state.fault.healthy() && !observed.healthy();
        if newly_faulted {
            state.admission_fence_epoch = Some(Self::next_admission_epoch(state));
            state.clean_prefix_len = state.pipeline.len() as u8;
            state.registered = None;
        }
        for expiry in &mut state.withdrawal_replay_expiries {
            if expiry.is_some_and(|deadline| deadline <= at) {
                *expiry = None;
            }
        }
        state.now = at;
        state.fault = observed;
        state.last = if newly_faulted {
            SettlementEdge::Fault
        } else {
            SettlementEdge::Observe
        };
        Some(())
    }

    fn challenge(&self, state: &mut SettlementState, proven: ProvenChallenge) -> Option<()> {
        let target = proven.target();
        let kind = proven.kind();
        if state.terminal != Terminal::Dormant
            || state.status[target.index()] != BatchStatus::Pending
            || state.now > target.candidate().challenge_deadline
        {
            return None;
        }
        let target_index = state.pipeline.iter().position(|batch| *batch == target)?;
        let newly_faulted = state.fault.healthy();
        if newly_faulted {
            state.fault = Fault::ProvenChallenge {
                batch: target,
                kind,
            };
            state.admission_fence_epoch = Some(Self::next_admission_epoch(state));
            state.clean_prefix_len = target_index as u8;
            state.registered = None;
        }
        for (index, batch) in state.pipeline.iter().copied().enumerate() {
            if index == target_index {
                state.status[batch.index()] = BatchStatus::Challenged(kind);
            } else if index > target_index {
                state.status[batch.index()] = BatchStatus::Invalidated(target);
            }
            if index >= target_index {
                state.invalidated_batches |= batch.bit();
            }
        }
        state.invalid_from = Some(target);
        state.last = SettlementEdge::Challenge(target, kind);
        Some(())
    }

    fn finalize(&self, state: &mut SettlementState) -> Option<()> {
        if state.terminal != Terminal::Dormant {
            return None;
        }
        let batch = *state.pipeline.first()?;
        let candidate = batch.candidate();
        if state.status[batch.index()] != BatchStatus::Pending
            || state.now <= candidate.challenge_deadline
            || candidate.epoch != state.expected_epoch
        {
            return None;
        }
        let reserve = candidate
            .withdrawal_total()
            .checked_add(candidate.payout_total())?;
        state.custody = state.custody.checked_sub(reserve)?;
        state.claimable = state.claimable.checked_add(reserve)?;
        state.current_root = candidate.successor;
        state.current_state = candidate.successor_state;
        state.current_liability = state_liability(&candidate.successor_state);
        for account in Account::ALL {
            let index = account.index();
            state.unfinalized_deposits[index] =
                state.unfinalized_deposits[index].checked_sub(candidate.deposits[index])?;
            if candidate.withdrawals[index].is_some() {
                state.outstanding_withdrawals[index] = None;
            }
        }
        state.pipeline.remove(0);
        state.status[batch.index()] = BatchStatus::Finalized;
        state.withdrawal_reserve[batch.index()] =
            state.withdrawal_reserve[batch.index()].checked_add(candidate.withdrawal_total())?;
        state.payout_reserve[batch.index()] =
            state.payout_reserve[batch.index()].checked_add(candidate.payout_total())?;
        state.finalized_batches |= batch.bit();
        state.finalized_epochs.push(candidate.epoch);
        state.expected_epoch = state.expected_epoch.checked_add(1)?;
        state.last = SettlementEdge::Finalize(batch);
        Some(())
    }

    fn claim_withdrawal(
        &self,
        state: &mut SettlementState,
        batch: Batch,
        source: Batch,
        position: u8,
    ) -> Option<()> {
        let output = source.candidate().withdrawal_output?;
        let bit = batch.bit();
        if source != batch
            || output.position != position
            || state.finalized_batches & bit == 0
            || state.claimed_withdrawals[batch.index()].is_some()
            || output.amount > state.withdrawal_reserve[batch.index()]
        {
            return None;
        }
        state.claimable = state.claimable.checked_sub(output.amount)?;
        state.released = state.released.checked_add(output.amount)?;
        state.clean_claim_paid = state.clean_claim_paid.checked_add(output.amount)?;
        state.withdrawal_reserve[batch.index()] =
            state.withdrawal_reserve[batch.index()].checked_sub(output.amount)?;
        state.claimed_withdrawals[batch.index()] = Some(position);
        state.last = SettlementEdge::ClaimWithdrawal {
            batch,
            source,
            position,
        };
        Some(())
    }

    fn claim_payout(
        &self,
        state: &mut SettlementState,
        batch: Batch,
        source: Batch,
        position: u8,
    ) -> Option<()> {
        let output = source.candidate().payout_output?;
        let bit = batch.bit();
        if source != batch
            || output.position != position
            || state.finalized_batches & bit == 0
            || state.claimed_payouts[batch.index()].is_some()
            || output.amount > state.payout_reserve[batch.index()]
        {
            return None;
        }
        state.claimable = state.claimable.checked_sub(output.amount)?;
        state.released = state.released.checked_add(output.amount)?;
        state.clean_claim_paid = state.clean_claim_paid.checked_add(output.amount)?;
        state.payout_reserve[batch.index()] =
            state.payout_reserve[batch.index()].checked_sub(output.amount)?;
        state.claimed_payouts[batch.index()] = Some(position);
        state.last = SettlementEdge::ClaimPayout {
            batch,
            source,
            position,
        };
        Some(())
    }

    fn claim_deposit(&self, state: &mut SettlementState, account: Account) -> Option<()> {
        if state.fault.healthy() || state.terminal == Terminal::Settled {
            return None;
        }
        let index = account.index();
        let amount = match state.terminal {
            Terminal::Dormant => state.pending_deposits[index],
            Terminal::Claiming { .. } => state.unfinalized_deposits[index],
            Terminal::Settled => 0,
        };
        if amount == 0 || amount > state.custody {
            return None;
        }
        let mut finishes = false;
        if let Terminal::Claiming {
            frozen_root,
            frozen_state,
            remaining_state,
            remaining_deposits,
        } = state.terminal
        {
            let remaining_deposits = remaining_deposits.checked_sub(amount)?;
            finishes = remaining_state == 0 && remaining_deposits == 0;
            state.terminal = if finishes {
                Terminal::Settled
            } else {
                Terminal::Claiming {
                    frozen_root,
                    frozen_state,
                    remaining_state,
                    remaining_deposits,
                }
            };
        }
        state.custody = state.custody.checked_sub(amount)?;
        state.released = state.released.checked_add(amount)?;
        state.pending_deposits[index] = 0;
        state.deposit_deadlines[index] = None;
        state.unfinalized_deposits[index] =
            state.unfinalized_deposits[index].checked_sub(amount)?;
        state.refunded_deposits[index] = state.refunded_deposits[index].checked_add(amount)?;
        if finishes {
            state.current_root = Root::Empty;
            state.current_state = EMPTY_STATE;
            state.current_liability = 0;
        }
        state.last = SettlementEdge::ClaimDeposit(account);
        Some(())
    }

    fn terminal_can_begin(state: &SettlementState) -> bool {
        state
            .pipeline
            .first()
            .is_none_or(|batch| state.status[batch.index()] != BatchStatus::Pending)
    }

    fn begin_terminal(&self, state: &mut SettlementState) -> Option<()> {
        if state.fault.healthy() || state.terminal == Terminal::Settled {
            return None;
        }
        if matches!(state.terminal, Terminal::Claiming { .. }) {
            return Some(());
        }
        let deposits = array_total(&state.unfinalized_deposits);
        let liability = state.current_liability;
        if !Self::terminal_can_begin(state) || state.custody != liability.checked_add(deposits)? {
            return None;
        }
        let immediately_settled = liability == 0 && deposits == 0;
        state.registered = None;
        state.pipeline.clear();
        state.pending_deposits = [0; ACCOUNT_COUNT];
        state.deposit_deadlines = [None; ACCOUNT_COUNT];
        state.pending_withdrawals = [None; ACCOUNT_COUNT];
        state.withdrawal_replay_expiries = [None; WithdrawalKey::COUNT];
        if immediately_settled {
            state.current_root = Root::Empty;
            state.current_state = EMPTY_STATE;
            state.current_liability = 0;
            state.custody = 0;
            state.terminal = Terminal::Settled;
        } else {
            state.terminal = Terminal::Claiming {
                frozen_root: state.current_root,
                frozen_state: state.current_state,
                remaining_state: liability,
                remaining_deposits: deposits,
            };
        }
        state.last = SettlementEdge::BeginTerminal;
        Some(())
    }

    fn terminal_split(
        state: &SettlementState,
        account: Account,
        balance: u16,
    ) -> Option<(u16, u16)> {
        match state.outstanding_withdrawals[account.index()] {
            None => Some((0, balance)),
            Some(request) => match request.action {
                WithdrawalAction::Amount(amount) => Some((amount, balance.checked_sub(amount)?)),
                WithdrawalAction::Close => Some((balance, 0)),
            },
        }
    }

    fn claim_state(&self, state: &mut SettlementState, account: Account) -> Option<()> {
        let Terminal::Claiming {
            frozen_root,
            frozen_state,
            remaining_state,
            remaining_deposits,
        } = state.terminal
        else {
            return None;
        };
        let index = account.index();
        let account_state = frozen_state[index];
        if !account_state.active
            || account_state.balance == 0
            || state.consumed_state & account_bit(account) != 0
        {
            return None;
        }
        let (withdrawal, residual) = Self::terminal_split(state, account, account_state.balance)?;
        let remaining_state = remaining_state.checked_sub(account_state.balance)?;
        let finishes = remaining_state == 0 && remaining_deposits == 0;
        state.custody = state.custody.checked_sub(account_state.balance)?;
        state.released = state.released.checked_add(account_state.balance)?;
        state.outstanding_withdrawals[index] = None;
        state.consumed_state |= account_bit(account);
        state.recovered_state[index] =
            state.recovered_state[index].checked_add(account_state.balance)?;
        state.terminal_withdrawals[index] =
            state.terminal_withdrawals[index].checked_add(withdrawal)?;
        state.terminal_residuals[index] = state.terminal_residuals[index].checked_add(residual)?;
        if finishes {
            state.current_root = Root::Empty;
            state.current_state = EMPTY_STATE;
            state.current_liability = 0;
            state.terminal = Terminal::Settled;
        } else {
            state.terminal = Terminal::Claiming {
                frozen_root,
                frozen_state,
                remaining_state,
                remaining_deposits,
            };
        }
        state.last = SettlementEdge::ClaimState(account);
        Some(())
    }

    const fn reserve_exact(state: &SettlementState, batch: Batch) -> bool {
        let candidate = batch.candidate();
        let finalized = state.finalized_batches & batch.bit() != 0;
        let withdrawal_claimed = state.claimed_withdrawals[batch.index()].is_some();
        let payout_claimed = state.claimed_payouts[batch.index()].is_some();
        let expected_withdrawal = if finalized && !withdrawal_claimed {
            candidate.withdrawal_total()
        } else {
            0
        };
        let expected_payout = if finalized && !payout_claimed {
            candidate.payout_total()
        } else {
            0
        };
        state.withdrawal_reserve[batch.index()] == expected_withdrawal
            && state.payout_reserve[batch.index()] == expected_payout
    }

    pub(crate) fn fifo_invariant(state: &SettlementState) -> bool {
        if state.pipeline.len() > 3 {
            return false;
        }
        for (left, batch) in state.pipeline.iter().enumerate() {
            if state.pipeline[..left].contains(batch) {
                return false;
            }
            let candidate = batch.candidate();
            let expected_root = if left == 0 {
                state.current_root
            } else {
                state.pipeline[left - 1].candidate().successor
            };
            let expected_state = if left == 0 {
                state.current_state
            } else {
                state.pipeline[left - 1].candidate().successor_state
            };
            if candidate.epoch != state.expected_epoch + left as u8
                || candidate.predecessor != expected_root
                || candidate.predecessor_state != expected_state
                || !matches!(
                    state.status[batch.index()],
                    BatchStatus::Pending | BatchStatus::Challenged(_) | BatchStatus::Invalidated(_)
                )
            {
                return false;
            }
        }
        state
            .finalized_epochs
            .iter()
            .enumerate()
            .all(|(index, epoch)| *epoch == index as u8)
            && state.expected_epoch == state.finalized_epochs.len() as u8
    }

    fn invalidation_invariant(state: &SettlementState) -> bool {
        let Some(target) = state.invalid_from else {
            return true;
        };
        if state.invalidated_batches & target.bit() == 0
            || !matches!(state.status[target.index()], BatchStatus::Challenged(_))
        {
            return false;
        }
        Batch::ALL.into_iter().all(|batch| {
            if state.invalidated_batches & batch.bit() == 0 || batch == target {
                true
            } else {
                state.status[batch.index()] == BatchStatus::Invalidated(target)
            }
        })
    }

    fn active_backing(state: &SettlementState) -> bool {
        match &state.terminal {
            Terminal::Dormant => {
                state.custody
                    == state
                        .current_liability
                        .saturating_add(array_total(&state.unfinalized_deposits))
            }
            Terminal::Claiming {
                remaining_state,
                remaining_deposits,
                ..
            } => {
                state.custody
                    == remaining_state
                        .checked_add(*remaining_deposits)
                        .unwrap_or(u16::MAX)
            }
            Terminal::Settled => state.custody == 0 && state.current_liability == 0,
        }
    }

    fn recovery_exact(state: &SettlementState) -> bool {
        if state.current_liability != state_liability(&state.current_state) {
            return false;
        }
        if !Account::ALL.into_iter().all(|account| {
            let index = account.index();
            state.unfinalized_deposits[index] >= state.pending_deposits[index]
                && state.recovered_state[index]
                    == state.terminal_withdrawals[index] + state.terminal_residuals[index]
        }) {
            return false;
        }
        match &state.terminal {
            Terminal::Dormant => true,
            Terminal::Claiming {
                frozen_root,
                frozen_state,
                remaining_state,
                remaining_deposits,
            } => {
                *frozen_root == state.current_root
                    && *remaining_state
                        == Account::ALL
                            .into_iter()
                            .filter(|account| state.consumed_state & account_bit(*account) == 0)
                            .map(|account| frozen_state[account.index()].balance)
                            .sum::<u16>()
                    && *remaining_deposits == array_total(&state.unfinalized_deposits)
            }
            Terminal::Settled => {
                state.current_root == Root::Empty
                    && state.current_state == EMPTY_STATE
                    && array_total(&state.unfinalized_deposits) == 0
            }
        }
    }

    fn fault_fence(state: &SettlementState) -> bool {
        if state.fault.healthy() {
            state.admission_fence_epoch.is_none()
                && state.clean_prefix_len == 0
                && state.terminal == Terminal::Dormant
        } else {
            state.admission_fence_epoch.is_some()
                && state.registered.is_none()
                && state.clean_prefix_len <= 3
        }
    }

    fn fault_deadline_exact(state: &SettlementState) -> bool {
        match state.fault {
            Fault::Healthy | Fault::ProvenChallenge { .. } => true,
            Fault::ExpiredDeposit {
                account,
                expired_at,
            } => {
                let index = account.index();
                expired_at <= state.now
                    && (state.pending_deposits[index] == 0
                        || state.deposit_deadlines[index] == Some(expired_at))
            }
            Fault::ExpiredWithdrawal {
                account,
                expired_at,
            } => {
                expired_at <= state.now
                    && state.outstanding_withdrawals[account.index()]
                        .is_none_or(|request| request.deadline == expired_at)
            }
            Fault::ExpiredRegistration {
                registration,
                anchor,
                epoch,
                expired_at,
            } => {
                let registered = registration.registration();
                anchor == registered.anchor
                    && epoch == registered.epoch
                    && expired_at == registered.admission_deadline
                    && expired_at < state.now
            }
        }
    }

    fn deadlines_observable(state: &SettlementState) -> bool {
        Account::ALL.into_iter().all(|account| {
            let index = account.index();
            (state.pending_deposits[index] == 0
                || state.deposit_deadlines[index].is_some_and(|deadline| deadline <= TIME_HORIZON))
                && state.outstanding_withdrawals[index]
                    .is_none_or(|request| request.deadline <= TIME_HORIZON)
        }) && state
            .registered
            .is_none_or(|id| id.registration().admission_deadline < TIME_HORIZON)
            && state
                .pipeline
                .iter()
                .all(|batch| batch.candidate().challenge_deadline < TIME_HORIZON)
            && state
                .withdrawal_replay_expiries
                .iter()
                .all(|expiry| expiry.is_none_or(|deadline| deadline > state.now))
    }

    pub(crate) fn hard_fault_has_progress(state: &SettlementState) -> bool {
        if state.fault.healthy() {
            return true;
        }
        match &state.terminal {
            Terminal::Settled => true,
            Terminal::Dormant => {
                Self::terminal_can_begin(state)
                    || state.pipeline.first().is_some_and(|batch| {
                        state.status[batch.index()] == BatchStatus::Pending
                            && batch.candidate().challenge_deadline < TIME_HORIZON
                    })
            }
            Terminal::Claiming {
                frozen_state,
                remaining_state,
                remaining_deposits,
                ..
            } => {
                (*remaining_state == 0
                    || Account::ALL.into_iter().any(|account| {
                        state.consumed_state & account_bit(account) == 0
                            && frozen_state[account.index()].active
                            && frozen_state[account.index()].balance > 0
                    }))
                    && (*remaining_deposits == 0
                        || state.unfinalized_deposits.iter().any(|amount| *amount > 0))
            }
        }
    }

    fn all_invariants(self, state: &SettlementState) -> bool {
        let reserves_exact = Batch::ALL
            .into_iter()
            .all(|batch| Self::reserve_exact(state, batch));
        let finalized_disjoint = state.finalized_batches & state.invalidated_batches == 0;
        let claims_scoped = Batch::ALL.into_iter().all(|batch| {
            let candidate = batch.candidate();
            let finalized = state.finalized_batches & batch.bit() != 0;
            state.claimed_withdrawals[batch.index()].is_none_or(|position| {
                finalized
                    && candidate
                        .withdrawal_output
                        .is_some_and(|output| output.position == position)
            }) && state.claimed_payouts[batch.index()].is_none_or(|position| {
                finalized
                    && candidate
                        .payout_output
                        .is_some_and(|output| output.position == position)
            })
        });
        let custody_conserved = state.custody + state.claimable + state.released == state.total_in
            && state.claimable
                == batch_total(&state.withdrawal_reserve) + batch_total(&state.payout_reserve)
            && state.released
                == state.clean_claim_paid
                    + array_total(&state.refunded_deposits)
                    + array_total(&state.recovered_state);
        let registration_exact = state.registered.is_none_or(|registration| {
            state.fault.healthy()
                && state.terminal == Terminal::Dormant
                && Self::registration_matches(state, registration)
        });
        Self::fifo_invariant(state)
            && Self::invalidation_invariant(state)
            && finalized_disjoint
            && claims_scoped
            && reserves_exact
            && custody_conserved
            && Self::active_backing(state)
            && Self::recovery_exact(state)
            && Self::fault_fence(state)
            && Self::fault_deadline_exact(state)
            && Self::deadlines_observable(state)
            && Self::hard_fault_has_progress(state)
            && registration_exact
            && state.pipeline.len() <= self.max_pending
    }
}

fn all_invariants(model: &SettlementModel, state: &SettlementState) -> bool {
    model.all_invariants(state)
}

const fn custody_conservation(_: &SettlementModel, state: &SettlementState) -> bool {
    state.custody + state.claimable + state.released == state.total_in
}

fn fifo_without_skips(_: &SettlementModel, state: &SettlementState) -> bool {
    SettlementModel::fifo_invariant(state)
}

fn recovery_stays_enabled(_: &SettlementModel, state: &SettlementState) -> bool {
    SettlementModel::hard_fault_has_progress(state)
}

const fn three_pending(_: &SettlementModel, state: &SettlementState) -> bool {
    state.pipeline.len() == 3
}

const fn all_epochs_finalize(_: &SettlementModel, state: &SettlementState) -> bool {
    state.expected_epoch == 4
}

const fn registration_fault(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(state.fault, Fault::ExpiredRegistration { .. })
}

const fn withdrawal_fault(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(state.fault, Fault::ExpiredWithdrawal { .. })
}

const fn deposit_fault(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(state.fault, Fault::ExpiredDeposit { .. })
}

const fn latest_fault(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(
        state.last,
        SettlementEdge::Challenge(_, ChallengeKind::LatestAcknowledgedSend)
    )
}

const fn higher_tip_fault(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(
        state.last,
        SettlementEdge::Challenge(_, ChallengeKind::HigherShardTip)
    )
}

const fn range_fault(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(
        state.last,
        SettlementEdge::Challenge(_, ChallengeKind::InconsistentReceiptRange)
    )
}

const fn same_send_fork(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(
        state.last,
        SettlementEdge::Challenge(_, ChallengeKind::ReceiptFork(ForkRelation::SameSend))
    )
}

const fn same_index_fork(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(
        state.last,
        SettlementEdge::Challenge(_, ChallengeKind::ReceiptFork(ForkRelation::SameIndex))
    )
}

const fn full_fork(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(
        state.last,
        SettlementEdge::Challenge(_, ChallengeKind::ReceiptFork(ForkRelation::Full))
    )
}

fn middle_suffix_invalidated(_: &SettlementModel, state: &SettlementState) -> bool {
    state.clean_prefix_len == 1
        && state.invalid_from == Some(Batch::B1)
        && state.status[Batch::B0.index()] == BatchStatus::Pending
        && matches!(state.status[Batch::B1.index()], BatchStatus::Challenged(_))
        && state.status[Batch::B2.index()] == BatchStatus::Invalidated(Batch::B1)
}

fn front_suffix_invalidated(_: &SettlementModel, state: &SettlementState) -> bool {
    state.clean_prefix_len == 0
        && state.invalid_from == Some(Batch::B0)
        && matches!(state.status[Batch::B0.index()], BatchStatus::Challenged(_))
        && state.status[Batch::B1.index()] == BatchStatus::Invalidated(Batch::B0)
        && state.status[Batch::B2.index()] == BatchStatus::Invalidated(Batch::B0)
}

fn tail_challenged(_: &SettlementModel, state: &SettlementState) -> bool {
    state.clean_prefix_len == 2
        && state.invalid_from == Some(Batch::B2)
        && state.status[Batch::B0.index()] == BatchStatus::Pending
        && state.status[Batch::B1.index()] == BatchStatus::Pending
        && matches!(state.status[Batch::B2.index()], BatchStatus::Challenged(_))
}

fn clean_prefix_finalized_after_fault(_: &SettlementModel, state: &SettlementState) -> bool {
    !state.fault.healthy()
        && state.finalized_batches & Batch::B0.bit() != 0
        && state.invalid_from == Some(Batch::B1)
}

const fn tail_first_two_batch_prefix_drained(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(
        state.fault,
        Fault::ProvenChallenge {
            batch: Batch::B2,
            ..
        }
    ) && state.clean_prefix_len == 2
        && state.finalized_batches & Batch::B0.bit() != 0
        && state.finalized_batches & Batch::B1.bit() != 0
}

const fn registration_prefix_drained(_: &SettlementModel, state: &SettlementState) -> bool {
    matches!(
        state.fault,
        Fault::ExpiredRegistration {
            registration: RegistrationId::B2,
            ..
        }
    ) && state.clean_prefix_len == 2
        && state.finalized_batches & Batch::B0.bit() != 0
        && state.finalized_batches & Batch::B1.bit() != 0
}

const fn payout_reserve_survives_fault(_: &SettlementModel, state: &SettlementState) -> bool {
    !state.fault.healthy() && state.payout_reserve[Batch::B1.index()] == 1
}

fn amount_claimed(_: &SettlementModel, state: &SettlementState) -> bool {
    state.claimed_withdrawals[Batch::B2.index()] == Some(0)
}

fn close_claimed(_: &SettlementModel, state: &SettlementState) -> bool {
    state.claimed_withdrawals[Batch::B3.index()] == Some(0)
}

fn payout_claimed(_: &SettlementModel, state: &SettlementState) -> bool {
    state.claimed_payouts[Batch::B1.index()] == Some(1)
}

fn terminal_recovery_settles(_: &SettlementModel, state: &SettlementState) -> bool {
    state.terminal == Terminal::Settled
        && (array_total(&state.recovered_state) > 0 || array_total(&state.refunded_deposits) > 0)
}

fn front_cut_recovers(_: &SettlementModel, state: &SettlementState) -> bool {
    state.terminal == Terminal::Settled
        && state.clean_prefix_len == 0
        && matches!(
            state.fault,
            Fault::ProvenChallenge {
                batch: Batch::B0,
                ..
            }
        )
        && state.finalized_epochs.is_empty()
        && state.recovered_state == [10, 5, 0]
        && state.refunded_deposits == [0, 2, 0]
        && state.terminal_withdrawals == [0, 2, 0]
        && state.terminal_residuals == [10, 3, 0]
        && state.released == state.total_in
}

fn middle_cut_recovers(_: &SettlementModel, state: &SettlementState) -> bool {
    state.terminal == Terminal::Settled
        && state.clean_prefix_len == 1
        && matches!(
            state.fault,
            Fault::ProvenChallenge {
                batch: Batch::B1,
                ..
            }
        )
        && state.finalized_epochs == [0]
        && state.recovered_state == [8, 9, 0]
        && state.terminal_withdrawals == [0, 2, 0]
        && state.terminal_residuals == [8, 7, 0]
        && state.released == state.total_in
}

fn tail_cut_recovers(_: &SettlementModel, state: &SettlementState) -> bool {
    state.terminal == Terminal::Settled
        && state.clean_prefix_len == 2
        && matches!(
            state.fault,
            Fault::ProvenChallenge {
                batch: Batch::B2,
                ..
            }
        )
        && state.finalized_epochs == [0, 1]
        && state.recovered_state == [7, 9, 0]
        && state.terminal_withdrawals == [0, 2, 0]
        && state.terminal_residuals == [7, 7, 0]
        && state.payout_reserve[Batch::B1.index()] == 1
        && state.claimable == 1
        && state.released + state.claimable == state.total_in
}

fn registration_prefix_recovers(_: &SettlementModel, state: &SettlementState) -> bool {
    state.terminal == Terminal::Settled
        && state.clean_prefix_len == 2
        && matches!(
            state.fault,
            Fault::ExpiredRegistration {
                registration: RegistrationId::B2,
                ..
            }
        )
        && state.finalized_epochs == [0, 1]
        && state.recovered_state == [7, 9, 0]
        && state.terminal_withdrawals == [0, 2, 0]
        && state.terminal_residuals == [7, 7, 0]
        && state.payout_reserve[Batch::B1.index()] == 1
        && state.claimable == 1
        && state.released + state.claimable == state.total_in
}

fn deposit_deadline_is(state: &SettlementState, deadline: u8) -> bool {
    Account::ALL.into_iter().any(|account| {
        let index = account.index();
        state.pending_deposits[index] > 0 && state.deposit_deadlines[index] == Some(deadline)
    })
}

fn withdrawal_deadline_is(state: &SettlementState, deadline: u8) -> bool {
    state
        .outstanding_withdrawals
        .iter()
        .flatten()
        .any(|request| request.deadline == deadline)
}

fn registration_deposit_tie(_: &SettlementModel, state: &SettlementState) -> bool {
    let Fault::ExpiredRegistration { expired_at, .. } = state.fault else {
        return false;
    };
    let Some(first_expired) = expired_at.checked_add(1) else {
        return false;
    };
    deposit_deadline_is(state, first_expired) && !withdrawal_deadline_is(state, first_expired)
}

fn all_three_exact_tie(_: &SettlementModel, state: &SettlementState) -> bool {
    let Fault::ExpiredRegistration { expired_at, .. } = state.fault else {
        return false;
    };
    let Some(first_expired) = expired_at.checked_add(1) else {
        return false;
    };
    deposit_deadline_is(state, first_expired) && withdrawal_deadline_is(state, first_expired)
}

fn exact_admission_boundary(_: &SettlementModel, state: &SettlementState) -> bool {
    state.now == 2 && state.last == SettlementEdge::Admit(Batch::B0)
}

const fn exact_challenge_boundary(_: &SettlementModel, state: &SettlementState) -> bool {
    state.now == Batch::B0.candidate().challenge_deadline
        && matches!(state.last, SettlementEdge::Challenge(Batch::B0, _))
}

fn first_post_deadline_finalization(_: &SettlementModel, state: &SettlementState) -> bool {
    state.now == Batch::B0.candidate().challenge_deadline + 1
        && state.last == SettlementEdge::Finalize(Batch::B0)
}

impl Model for SettlementModel {
    type State = SettlementState;
    type Action = SettlementAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![SettlementState::default()]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if state.terminal != Terminal::Settled {
            for at in state.now + 1..=TIME_HORIZON {
                actions.push(SettlementAction::Observe(at));
            }
        }
        for id in DepositId::ALL {
            if self.can_record_deposit(state, id) {
                actions.push(SettlementAction::RecordDeposit(id));
            }
        }
        for id in WithdrawalId::ALL {
            let attempt = Self::withdrawal_attempt(state, id);
            if Self::can_queue_withdrawal(state, &attempt) {
                actions.push(SettlementAction::QueueWithdrawal(attempt));
            }
        }
        for registration in RegistrationId::ALL {
            if self.can_register(state, registration) {
                actions.push(SettlementAction::Register(registration));
            }
        }
        for batch in Batch::ALL {
            if state.registered.is_some_and(|registration| {
                Self::candidate_matches_registration(batch, registration)
            }) {
                actions.push(SettlementAction::Admit(
                    self.certified_closes[batch.index()],
                ));
            }
            if state.status[batch.index()] == BatchStatus::Pending
                && state.now <= batch.candidate().challenge_deadline
            {
                for proven in challenge::adjudicated_proven_challenges(batch) {
                    actions.push(SettlementAction::Challenge(proven));
                }
            }
            if let Some(output) = batch.candidate().withdrawal_output {
                actions.push(SettlementAction::ClaimWithdrawal {
                    batch,
                    source: batch,
                    position: output.position,
                });
            }
            if let Some(output) = batch.candidate().payout_output {
                actions.push(SettlementAction::ClaimPayout {
                    batch,
                    source: batch,
                    position: output.position,
                });
            }
        }
        actions.push(SettlementAction::Finalize);
        if !state.fault.healthy() {
            for account in Account::ALL {
                actions.push(SettlementAction::ClaimDeposit(account));
                actions.push(SettlementAction::ClaimState(account));
            }
            actions.push(SettlementAction::BeginTerminal);
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        self.apply(last, action)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always("all lifecycle invariants", all_invariants),
            Property::always("custody is conserved", custody_conservation),
            Property::always(
                "epochs finalize in FIFO order without skips",
                fifo_without_skips,
            ),
            Property::always(
                "hard-fault recovery always has an enabled next step",
                recovery_stays_enabled,
            ),
            Property::sometimes("the three-close pipeline is reachable", three_pending),
            Property::sometimes(
                "all four sequential epochs can finalize",
                all_epochs_finalize,
            ),
            Property::sometimes("registration expiry is reachable", registration_fault),
            Property::sometimes("withdrawal expiry is reachable", withdrawal_fault),
            Property::sometimes("deposit expiry is reachable", deposit_fault),
            Property::sometimes("latest-send challenge is reachable", latest_fault),
            Property::sometimes("higher-tip challenge is reachable", higher_tip_fault),
            Property::sometimes("receipt-range challenge is reachable", range_fault),
            Property::sometimes("same-send fork challenge is reachable", same_send_fork),
            Property::sometimes("same-index fork challenge is reachable", same_index_fork),
            Property::sometimes("a full fork challenge is reachable", full_fork),
            Property::sometimes(
                "a middle challenge invalidates its suffix",
                middle_suffix_invalidated,
            ),
            Property::sometimes(
                "a front challenge invalidates its entire suffix",
                front_suffix_invalidated,
            ),
            Property::sometimes("a tail challenge is reachable", tail_challenged),
            Property::sometimes(
                "a tail-first fault can drain its two-batch clean prefix",
                tail_first_two_batch_prefix_drained,
            ),
            Property::sometimes(
                "registration expiry can drain an earlier pending prefix",
                registration_prefix_drained,
            ),
            Property::sometimes(
                "a clean prefix can finalize after a later fault",
                clean_prefix_finalized_after_fault,
            ),
            Property::sometimes(
                "a finalized payout reserve survives a later fault",
                payout_reserve_survives_fault,
            ),
            Property::sometimes("an Amount output is independently claimed", amount_claimed),
            Property::sometimes("a Close output is independently claimed", close_claimed),
            Property::sometimes(
                "an external payout is independently claimed",
                payout_claimed,
            ),
            Property::sometimes(
                "terminal recovery can drain all active custody",
                terminal_recovery_settles,
            ),
            Property::sometimes(
                "terminal recovery completes from a front cut",
                front_cut_recovers,
            ),
            Property::sometimes(
                "terminal recovery completes from a middle cut",
                middle_cut_recovers,
            ),
            Property::sometimes(
                "terminal recovery completes from a tail cut",
                tail_cut_recovers,
            ),
            Property::sometimes(
                "terminal recovery completes after registration expiry with a pending prefix",
                registration_prefix_recovers,
            ),
            Property::sometimes(
                "registration wins an exact tie with a pending deposit",
                registration_deposit_tie,
            ),
            Property::sometimes(
                "registration wins an exact all-three deadline tie",
                all_three_exact_tie,
            ),
            Property::sometimes(
                "admission is inclusive at its exact deadline",
                exact_admission_boundary,
            ),
            Property::sometimes(
                "challenge is inclusive at its exact deadline",
                exact_challenge_boundary,
            ),
            Property::sometimes(
                "finalization begins immediately after the challenge deadline",
                first_post_deadline_finalization,
            ),
        ]
    }
}

#[cfg(not(test))]
pub(crate) fn explore(address: &str) {
    SettlementModel::default()
        .checker()
        .threads(1)
        .serve(address);
}

#[test]
fn settlement_checker_explores_the_complete_finite_graph() {
    let checker = SettlementModel::default()
        .checker()
        .threads(4)
        .spawn_bfs()
        .join();
    assert!(checker.is_done());
    assert_eq!(checker.unique_state_count(), 3_929_740);
    checker.assert_properties();
}

#[test]
fn settlement_invariants_have_negative_controls() {
    let model = SettlementModel::default();
    let skipped = SettlementState {
        expected_epoch: 1,
        ..SettlementState::default()
    };
    assert!(!all_invariants(&model, &skipped));
    assert!(!fifo_without_skips(&model, &skipped));

    let unbacked = SettlementState {
        custody: 14,
        ..SettlementState::default()
    };
    assert!(!custody_conservation(&model, &unbacked));

    let wrong_deposit_deadline = SettlementState {
        now: 2,
        pending_deposits: [1, 0, 0],
        deposit_deadlines: [Some(2), None, None],
        fault: Fault::ExpiredDeposit {
            account: Account::Alice,
            expired_at: 1,
        },
        ..SettlementState::default()
    };
    assert!(!SettlementModel::fault_deadline_exact(
        &wrong_deposit_deadline
    ));

    let request = WithdrawalId::Amount.request();
    let mut outstanding_withdrawals = [None; ACCOUNT_COUNT];
    outstanding_withdrawals[request.account.index()] = Some(request);
    let wrong_withdrawal_deadline = SettlementState {
        now: request.deadline,
        outstanding_withdrawals,
        fault: Fault::ExpiredWithdrawal {
            account: request.account,
            expired_at: request.deadline - 1,
        },
        ..SettlementState::default()
    };
    assert!(!SettlementModel::fault_deadline_exact(
        &wrong_withdrawal_deadline
    ));

    let stranded = SettlementState {
        fault: Fault::ExpiredDeposit {
            account: Account::Alice,
            expired_at: 0,
        },
        admission_fence_epoch: Some(0),
        terminal: Terminal::Claiming {
            frozen_root: Root::R0,
            frozen_state: EMPTY_STATE,
            remaining_state: 1,
            remaining_deposits: 0,
        },
        ..SettlementState::default()
    };
    assert!(!recovery_stays_enabled(&model, &stranded));
}
