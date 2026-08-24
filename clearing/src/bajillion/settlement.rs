//! Bounded admission, challenge timing, custody, and terminal settlement.
//!
//! # Integration contract
//!
//! This module is a runtime-agnostic in-memory transition primitive, not a persistence or asset
//! adapter. The embedding settlement environment must commit each state mutation and its returned
//! custody effects atomically and idempotently. Every public mutation that accepts `now` first
//! observes expired withdrawals; that permanent fence can be the method's only state change even
//! when the requested operation returns an error. Callers must therefore provide one authenticated,
//! monotonic clock and persist mutation-on-error results.
//!
//! Terminal settlement deliberately authenticates and scans the complete surviving state. The
//! survivor is bounded by [`SettlementConfig::max_state_accounts`], while unfinalized deposit
//! records and distinct deposit-only recipients are bounded by
//! [`SettlementConfig::max_deposit_ids`]. Including the bounded pipeline traversal, terminal work
//! is linear in those configured limits, and the payout list contains at most two entries per
//! survivor plus one per retained deposit identifier. Deposit replay state is retained for the
//! deployment lifetime; reaching its limit safely rejects new deposits.
//! Withdrawal replay identifiers are retained only through the configured maximum deadline.

use crate::bajillion::{
    admission::{Committee, bls12381},
    boundary::{
        BoundaryError, DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction,
        WithdrawalBatch, WithdrawalId,
    },
    challenge::{self, Challenge, ChallengeError, ChallengeKind, StateOpening, Verdict},
    commitment::{self, VectorRoot},
    transition::{
        self, BatchId, CloseContext, EpochContext, ExternalPayout, ExternalPayoutClaim, Header,
        RootBundle, StateCache, TerminalProof, TransitionError, WithdrawalClaim,
        verify_terminal_proof_after_header,
    },
};
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};
use bytes::{Bytes, BytesMut};
use commonware_codec::{Encode, RangeCfg, Read};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::{Sequential, Strategy};
use core::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
};
use thiserror::Error;

/// Status of one admitted close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchStatus<D: Digest> {
    /// The close remains challengeable and may finalize at the front of the pipeline.
    Pending,
    /// A receipt contradiction was proven against this close.
    Challenged(ChallengeKind),
    /// An earlier challenged close invalidated this descendant.
    Invalidated(BatchId<D>),
}

/// Header, root witness, exact certificate, and current status retained for an admitted close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBatch<D: Digest> {
    /// Admitted header.
    pub header: Header<D>,
    /// Authenticated opening, change, closing, and slice-layout roots used while pending.
    pub roots: RootBundle<D>,
    /// Exact BLS12-381 MinSig quorum certificate over `header`.
    pub certificate: bls12381::Certificate,
    /// Closing liability derived from the registered custody boundary.
    pub closing_liability: u64,
    /// Current adjudication status.
    pub status: BatchStatus<D>,
}

/// One signed withdrawal together with the exact custody amount released for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalRelease<P: PublicKey, D: Digest> {
    /// Account authorization and opaque payout destination.
    pub request: SignedWithdrawal<P, D>,
    /// Exact custody paid to the request's destination.
    pub amount: u64,
}

/// Result of finalizing the pipeline front.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedBatch<D: Digest> {
    /// Canonical header identifier.
    pub batch_id: BatchId<D>,
    /// Finalized epoch.
    pub epoch: u64,
    /// Newly finalized state root.
    pub closing_state_root: VectorRoot<D>,
    /// Exact withdrawal value moved into the claim reserve.
    pub withdrawal_total: u64,
    /// Exact external-payment value moved into the claim reserve.
    pub payout_total: u64,
    /// Active custody remaining after claim reserves are separated.
    pub custody_balance: u64,
}

/// Permanent reason that new work is fenced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HardFaultReason<P: PublicKey, D: Digest> {
    /// A receipt contradiction invalidated an admitted close.
    ProvenChallenge {
        /// Challenged header.
        batch_id: BatchId<D>,
        /// Proven contradiction family.
        kind: ChallengeKind,
    },
    /// A queued withdrawal remained outstanding through its absolute deadline.
    ExpiredWithdrawal {
        /// Authorizing account.
        account: P,
        /// Inclusive deadline that was observed.
        expired_at: u64,
    },
}

/// One payout produced by terminal settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FaultPayout<P: PublicKey, D: Digest> {
    /// Signed request and exact amount released to its opaque adapter destination.
    QueuedWithdrawal(WithdrawalRelease<P, D>),
    /// Remaining account balance plus every unfinalized deposit for that account.
    ResidualSettlement {
        /// Registered source account and claimant.
        account: P,
        /// Residual custody released to the account.
        amount: u64,
    },
}

/// Complete one-shot terminal settlement of a hard-faulted deployment.
#[derive(Debug)]
pub struct HardFaultSettlement<P: PublicKey, D: Digest> {
    /// Fault that permanently fenced the deployment.
    pub reason: HardFaultReason<P, D>,
    /// First epoch excluded by the admission fence.
    pub admission_fence_epoch: u64,
    /// Earliest receipt-invalidated close, if any.
    pub invalid_from: Option<BatchId<D>>,
    /// Complete zero-liability terminal state.
    pub terminal_state: StateCache<P, D>,
    /// Payouts that exhaust custody.
    pub payouts: Vec<FaultPayout<P, D>>,
    /// Custody exhausted by the payout list.
    pub released_custody: u64,
}

/// Bounds and timing policy for one settlement deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementConfig {
    /// Maximum number of admitted, unfinalized closes.
    pub max_pending_epochs: NonZeroUsize,
    /// Minimum delay from queueing to a withdrawal's absolute deadline.
    pub minimum_withdrawal_notice: NonZeroU64,
    /// Maximum delay from queueing to a withdrawal's absolute deadline.
    pub maximum_withdrawal_notice: NonZeroU64,
    /// Maximum live accounts in every finalized, admitted, or terminal-survivor state.
    pub max_state_accounts: NonZeroUsize,
    /// Maximum retained bytes in an opaque withdrawal destination.
    pub max_destination_bytes: usize,
    /// Maximum external deposit identifiers retained for lifetime replay protection.
    ///
    /// This also bounds unfinalized deposit records and deposit-only terminal payouts.
    pub max_deposit_ids: NonZeroUsize,
    /// Maximum finalized batches retaining at least one unconsumed claim.
    pub max_claimable_batches: NonZeroUsize,
}

impl SettlementConfig {
    /// Creates an explicit settlement policy.
    #[must_use]
    pub const fn new(
        max_pending_epochs: NonZeroUsize,
        minimum_withdrawal_notice: NonZeroU64,
        maximum_withdrawal_notice: NonZeroU64,
        max_state_accounts: NonZeroUsize,
        max_destination_bytes: usize,
        max_deposit_ids: NonZeroUsize,
        max_claimable_batches: NonZeroUsize,
    ) -> Self {
        Self {
            max_pending_epochs,
            minimum_withdrawal_notice,
            maximum_withdrawal_notice,
            max_state_accounts,
            max_destination_bytes,
            max_deposit_ids,
            max_claimable_batches,
        }
    }
}

#[derive(Debug)]
struct RegisteredClose<P: PublicKey, D: Digest> {
    context: CloseContext<P, D>,
    deposits: DepositBatch<P>,
    withdrawals: Vec<SignedWithdrawal<P, D>>,
    exact_amount_total: u64,
    withdrawal_deadline: Option<(u64, P)>,
}

// Admitted boundary records are retained as one allocation plus copy-only offsets. Finalization
// can therefore release their storage without running one destructor per recipient, while a hard
// fault can still reconstruct the exact records that were admitted.
#[derive(Debug)]
struct PackedDeposits<P: PublicKey> {
    encoded: Bytes,
    _public_key: PhantomData<fn() -> P>,
}

impl<P: PublicKey> PackedDeposits<P> {
    fn new(deposits: &DepositBatch<P>) -> Self {
        Self {
            encoded: deposits.encode(),
            _public_key: PhantomData,
        }
    }

    fn decode(&self, maximum: usize) -> Result<DepositBatch<P>, SettlementError> {
        let mut encoded = self.encoded.as_ref();
        let deposits = DepositBatch::read_cfg(&mut encoded, &RangeCfg::new(..=maximum))
            .map_err(|_| SettlementError::DepositWitness)?;
        if !encoded.is_empty() {
            return Err(SettlementError::DepositWitness);
        }
        Ok(deposits)
    }
}

#[derive(Debug)]
struct PackedWithdrawalIndex {
    start: usize,
    end: usize,
    deadline: u64,
}

#[derive(Debug)]
struct PackedWithdrawals<P: PublicKey, D: Digest> {
    encoded: Bytes,
    index: Vec<PackedWithdrawalIndex>,
    _request: PhantomData<fn() -> (P, D)>,
}

impl<P: PublicKey, D: Digest> PackedWithdrawals<P, D> {
    fn new(requests: &[SignedWithdrawal<P, D>]) -> Self {
        let mut encoded = BytesMut::new();
        let mut index = Vec::with_capacity(requests.len());
        for request in requests {
            let encoded_request = request.encode();
            let start = encoded.len();
            encoded.extend_from_slice(&encoded_request);
            index.push(PackedWithdrawalIndex {
                start,
                end: encoded.len(),
                deadline: request.body().deadline(),
            });
        }
        let encoded = encoded.freeze();
        index.sort_unstable_by(|left, right| {
            encoded[left.start..left.start + P::SIZE]
                .cmp(&encoded[right.start..right.start + P::SIZE])
        });
        Self {
            encoded,
            index,
            _request: PhantomData,
        }
    }

    fn find(&self, account: &P) -> Option<&PackedWithdrawalIndex> {
        // SignedWithdrawal starts with its fixed-width account. The index uses that encoding for
        // both sorting and lookup because PublicKey::Ord may use another order.
        self.index
            .binary_search_by(|entry| {
                self.encoded[entry.start..entry.start + P::SIZE].cmp(account.as_ref())
            })
            .ok()
            .map(|position| &self.index[position])
    }

    fn contains(&self, account: &P) -> bool {
        self.find(account).is_some()
    }

    fn deadline(&self, account: &P) -> Option<u64> {
        self.find(account).map(|entry| entry.deadline)
    }

    fn decode(
        &self,
        maximum_destination_bytes: usize,
    ) -> Result<Vec<SignedWithdrawal<P, D>>, SettlementError> {
        self.index
            .iter()
            .map(|entry| {
                let mut encoded = &self.encoded[entry.start..entry.end];
                let request = SignedWithdrawal::read_cfg(
                    &mut encoded,
                    &RangeCfg::new(..=maximum_destination_bytes),
                )
                .map_err(|_| SettlementError::WithdrawalWitness)?;
                if !encoded.is_empty() {
                    return Err(SettlementError::WithdrawalWitness);
                }
                Ok(request)
            })
            .collect()
    }
}

#[derive(Debug)]
struct AdmittedClose<P: PublicKey, D: Digest> {
    context: CloseContext<P, D>,
    deposits: PackedDeposits<P>,
    deposit_total: u64,
    withdrawals: PackedWithdrawals<P, D>,
    withdrawal_total: u64,
    withdrawal_deadline: Option<(u64, P)>,
    payout_total: u64,
}

#[derive(Debug)]
struct PipelineEntry<P: PublicKey, D: Digest> {
    admitted: AdmittedClose<P, D>,
    batch: PendingBatch<D>,
}

#[derive(Debug)]
struct ClaimableBatch<D: Digest> {
    change_root: VectorRoot<D>,
    withdrawal_root: VectorRoot<D>,
    claimed_withdrawals: BTreeSet<u32>,
    claimed_payouts: BTreeSet<u32>,
    withdrawal_remaining: u64,
    payout_remaining: u64,
}

/// Runtime-agnostic chain state for one immutable operator deployment.
///
/// The admitted pipeline is a bounded linear extension of the finalized root. A hard fault
/// permanently rejects new work, while preserving the earlier pending prefix for ordinary
/// challenge and FIFO finalization before one terminal unwind.
///
/// Every method accepting `now` may persist a withdrawal-timeout fence before returning an error.
/// See the [module-level integration contract](self) for clock, durability, and custody-effect
/// requirements.
#[derive(Debug)]
pub struct SettlementChain<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    deployment: H::Digest,
    operator: P,
    certificate_scheme: bls12381::Scheme,
    current_state_root: VectorRoot<H::Digest>,
    current_liability: u64,
    custody_balance: u64,
    claimable_balance: u64,
    claimable_batches: BTreeMap<BatchId<H::Digest>, ClaimableBatch<H::Digest>>,
    consumed_deposit_ids: BTreeSet<H::Digest>,
    consumed_withdrawal_ids: BTreeSet<WithdrawalId<H::Digest>>,
    withdrawal_replay_expiries: BTreeSet<(u64, WithdrawalId<H::Digest>)>,
    pending_deposits: BTreeMap<P, u64>,
    unfinalized_deposit_total: u64,
    pending_withdrawals: BTreeMap<P, SignedWithdrawal<P, H::Digest>>,
    pending_withdrawal_deadlines: BTreeSet<(u64, P)>,
    config: SettlementConfig,
    expected_epoch: u64,
    registered: Option<RegisteredClose<P, H::Digest>>,
    pipeline: VecDeque<PipelineEntry<P, H::Digest>>,
    hard_fault: Option<HardFaultReason<P, H::Digest>>,
    admission_fence_epoch: Option<u64>,
    invalid_from: Option<BatchId<H::Digest>>,
    fault_settled: bool,
    _hasher: PhantomData<fn() -> H>,
}

impl<H, P> SettlementChain<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    /// Creates a deployment from the complete finalized account state.
    pub fn new(
        deployment: H::Digest,
        operator: P,
        committee: Committee,
        current_state: &StateCache<P, H::Digest>,
        expected_epoch: u64,
        config: SettlementConfig,
    ) -> Result<Self, SettlementError> {
        expected_epoch
            .checked_add(1)
            .ok_or(SettlementError::EpochOverflow)?;
        if config.maximum_withdrawal_notice < config.minimum_withdrawal_notice {
            return Err(SettlementError::WithdrawalNoticeOrder);
        }
        if current_state.leaves().len() > config.max_state_accounts.get() {
            return Err(SettlementError::StateCapacity);
        }
        let current_liability = current_state.liability();
        Ok(Self {
            deployment,
            operator,
            certificate_scheme: bls12381::Scheme::verifier(committee),
            current_state_root: current_state.root(),
            current_liability,
            custody_balance: current_liability,
            claimable_balance: 0,
            claimable_batches: BTreeMap::new(),
            consumed_deposit_ids: BTreeSet::new(),
            consumed_withdrawal_ids: BTreeSet::new(),
            withdrawal_replay_expiries: BTreeSet::new(),
            pending_deposits: BTreeMap::new(),
            unfinalized_deposit_total: 0,
            pending_withdrawals: BTreeMap::new(),
            pending_withdrawal_deadlines: BTreeSet::new(),
            config,
            expected_epoch,
            registered: None,
            pipeline: VecDeque::new(),
            hard_fault: None,
            admission_fence_epoch: None,
            invalid_from: None,
            fault_settled: false,
            _hasher: PhantomData,
        })
    }

    const fn ensure_operating(&self) -> Result<(), SettlementError> {
        if self.hard_fault.is_some() {
            return Err(SettlementError::OperatorHardFaulted);
        }
        Ok(())
    }

    fn expired_withdrawal_reason(&self, now: u64) -> Option<HardFaultReason<P, H::Digest>> {
        self.pending_withdrawal_deadlines
            .first()
            .into_iter()
            .chain(
                self.pipeline
                    .iter()
                    .filter_map(|entry| entry.admitted.withdrawal_deadline.as_ref()),
            )
            .min()
            .filter(|(deadline, _)| now >= *deadline)
            .map(|(deadline, account)| HardFaultReason::ExpiredWithdrawal {
                account: account.clone(),
                expired_at: *deadline,
            })
    }

    fn enter_hard_fault(&mut self, reason: HardFaultReason<P, H::Digest>) {
        if self.hard_fault.is_none() {
            self.admission_fence_epoch = Some(
                self.next_admission_epoch()
                    .expect("live admission ancestry cannot overflow"),
            );
            self.hard_fault = Some(reason);

            // Registration is preparation rather than an admitted commitment. Its exact boundary
            // remains in the staging maps and is therefore still included by terminal settlement.
            self.registered = None;
        }
    }

    fn observe_time(&mut self, now: u64) {
        if self.hard_fault.is_none()
            && let Some(reason) = self.expired_withdrawal_reason(now)
        {
            self.enter_hard_fault(reason);
        }
        while let Some((deadline, request_id)) = self.withdrawal_replay_expiries.first().copied() {
            if deadline > now {
                break;
            }
            self.withdrawal_replay_expiries.pop_first();
            self.consumed_withdrawal_ids.remove(&request_id);
        }
    }

    fn ensure_operating_at(&mut self, now: u64) -> Result<(), SettlementError> {
        self.observe_time(now);
        self.ensure_operating()
    }

    fn head_state_root(&self) -> VectorRoot<H::Digest> {
        self.pipeline
            .back()
            .map_or(self.current_state_root, |entry| entry.batch.roots.closing)
    }

    fn head_liability(&self) -> u64 {
        self.pipeline
            .back()
            .map_or(self.current_liability, |entry| {
                entry.batch.closing_liability
            })
    }

    fn next_admission_epoch(&self) -> Result<u64, SettlementError> {
        self.pipeline
            .back()
            .map_or(Ok(self.expected_epoch), |entry| {
                entry
                    .admitted
                    .context
                    .payment()
                    .epoch()
                    .checked_add(1)
                    .ok_or(SettlementError::EpochOverflow)
            })
    }

    fn ensure_deposit_successor_available(&self) -> Result<(), SettlementError> {
        self.next_admission_epoch()?
            .checked_add(1)
            .ok_or(SettlementError::EpochOverflow)?;
        Ok(())
    }

    fn check_phase_custody(&self) -> Result<(), SettlementError> {
        let expected = self
            .current_liability
            .checked_add(self.unfinalized_deposit_total)
            .ok_or(SettlementError::CustodyArithmetic)?;
        if expected != self.custody_balance {
            return Err(SettlementError::CustodyMismatch);
        }
        Ok(())
    }

    fn ensure_deposit_capacity(&self) -> Result<(), SettlementError> {
        if self.consumed_deposit_ids.len() >= self.config.max_deposit_ids.get() {
            return Err(SettlementError::DepositCapacity);
        }
        Ok(())
    }

    /// Records one finalized external deposit event exactly once.
    pub fn record_deposit(
        &mut self,
        now: u64,
        deposit_id: H::Digest,
        account: P,
        amount: u64,
    ) -> Result<(), SettlementError> {
        self.ensure_operating_at(now)?;
        self.ensure_deposit_successor_available()?;
        if self.registered.is_some() {
            return Err(SettlementError::EpochAlreadyActive);
        }
        if amount == 0 {
            return Err(SettlementError::ZeroDeposit);
        }
        if self.consumed_deposit_ids.contains(&deposit_id) {
            return Err(SettlementError::DuplicateDeposit);
        }
        self.ensure_deposit_capacity()?;

        let amount_for_account = self
            .pending_deposits
            .get(&account)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let custody_balance = self
            .custody_balance
            .checked_add(amount)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let unfinalized_deposit_total = self
            .unfinalized_deposit_total
            .checked_add(amount)
            .ok_or(SettlementError::CustodyArithmetic)?;

        self.pending_deposits.insert(account, amount_for_account);
        self.consumed_deposit_ids.insert(deposit_id);
        self.custody_balance = custody_balance;
        self.unfinalized_deposit_total = unfinalized_deposit_total;
        Ok(())
    }

    fn has_unfinalized_withdrawal(&self, account: &P) -> bool {
        self.pending_withdrawals.contains_key(account)
            || self
                .pipeline
                .iter()
                .any(|entry| entry.admitted.withdrawals.contains(account))
    }

    fn unfinalized_withdrawal_deadline(&self, account: &P) -> Option<u64> {
        self.pending_withdrawals
            .get(account)
            .map(|request| request.body().deadline())
            .or_else(|| {
                self.pipeline
                    .iter()
                    .find_map(|entry| entry.admitted.withdrawals.deadline(account))
            })
    }

    /// Queues one account withdrawal after authenticating every root that can survive a cut.
    ///
    /// An `Amount` must be independently affordable at every safety root. An amountless `Close`
    /// requires an active account at each root; the certified close derives its epoch-tail
    /// balance.
    ///
    /// `destination_is_eligible` is the asset adapter's explicit admission predicate for the
    /// opaque signed destination. Eligibility must be stable for every accepted request because
    /// a later terminal unwind must honor the exact bytes without operator cooperation.
    pub fn queue_withdrawal<F>(
        &mut self,
        now: u64,
        request: SignedWithdrawal<P, H::Digest>,
        safety_openings: &[StateOpening<P, H::Digest>],
        destination_is_eligible: F,
    ) -> Result<(), SettlementError>
    where
        F: FnOnce(&Bytes) -> bool,
    {
        self.ensure_operating_at(now)?;
        if self.registered.is_some() {
            return Err(SettlementError::EpochAlreadyActive);
        }
        if request.body().destination().len() > self.config.max_destination_bytes {
            return Err(SettlementError::DestinationTooLarge);
        }
        let request_id = request.id::<H>();
        if self.consumed_withdrawal_ids.contains(&request_id) {
            return Err(SettlementError::DuplicateWithdrawalAuthorization);
        }
        request.verify_context(&self.deployment, &self.current_state_root.digest)?;
        if !destination_is_eligible(request.body().destination()) {
            return Err(SettlementError::IneligibleDestination);
        }
        let minimum_deadline = now
            .checked_add(self.config.minimum_withdrawal_notice.get())
            .ok_or(SettlementError::WithdrawalDeadlineTooSoon)?;
        if request.body().deadline() < minimum_deadline {
            return Err(SettlementError::WithdrawalDeadlineTooSoon);
        }
        let maximum_deadline = now.saturating_add(self.config.maximum_withdrawal_notice.get());
        if request.body().deadline() > maximum_deadline {
            return Err(SettlementError::WithdrawalDeadlineTooLate);
        }
        if self.has_unfinalized_withdrawal(request.account()) {
            return Err(SettlementError::DuplicateWithdrawal);
        }
        let expected_openings = self
            .pipeline
            .len()
            .checked_add(1)
            .ok_or(SettlementError::WithdrawalOpeningCount)?;
        if safety_openings.len() != expected_openings {
            return Err(SettlementError::WithdrawalOpeningCount);
        }
        for (index, opening) in safety_openings.iter().enumerate() {
            let root = if index == 0 {
                self.current_state_root
            } else {
                self.pipeline[index - 1].batch.roots.closing
            };
            opening.proof.verify::<H>(
                crate::bajillion::commitment::VectorKind::State,
                &root,
                opening.leaf.encode().as_ref(),
            )?;
            if &opening.leaf.account != request.account() {
                return Err(SettlementError::WithdrawalOpening);
            }
            let state = opening.leaf.state;
            if !state.active
                || matches!(
                    request.body().action(),
                    WithdrawalAction::Amount(amount) if amount.get() > state.balance
                )
            {
                return Err(SettlementError::WithdrawalBalance);
            }
        }

        let account = request.account().clone();
        let deadline = request.body().deadline();
        self.pending_withdrawals.insert(account.clone(), request);
        self.pending_withdrawal_deadlines
            .insert((deadline, account));
        self.consumed_withdrawal_ids.insert(request_id);
        self.withdrawal_replay_expiries
            .insert((deadline, request_id));
        Ok(())
    }

    /// Returns the exact canonical deposit boundary staged for the next close.
    ///
    /// If an ordinary withdrawal exactly offsets its account's staged deposit, the withdrawal
    /// takes the next slot and the deposit remains staged for its successor. This keeps every
    /// public close row tied to an actual authenticated state change.
    #[must_use]
    pub fn pending_deposits(&self) -> DepositBatch<P> {
        DepositBatch::new(
            self.pending_deposits
                .iter()
                .filter_map(|(account, amount)| {
                    let deferred = self
                        .pending_withdrawals
                        .get(account)
                        .is_some_and(|request| {
                            matches!(
                                request.body().action(),
                                WithdrawalAction::Amount(withdrawal) if withdrawal.get() == *amount
                            )
                        });
                    (!deferred).then(|| {
                        DepositRecord::new(account.clone(), *amount)
                            .expect("staged deposits are positive and checked")
                    })
                })
                .collect(),
        )
        .expect("staged deposit aggregation is canonical and checked")
    }

    /// Returns the exact canonical withdrawal boundary staged for the next close.
    #[must_use]
    pub fn pending_withdrawals(&self) -> WithdrawalBatch<P, H::Digest> {
        WithdrawalBatch::new(self.pending_withdrawals.values().cloned().collect())
            .expect("staged withdrawal aggregation is canonical and checked")
    }

    /// Returns one outstanding withdrawal's absolute deadline.
    #[must_use]
    pub fn pending_withdrawal_deadline(&self, account: &P) -> Option<u64> {
        self.unfinalized_withdrawal_deadline(account)
    }

    /// Returns the finalized root followed by every admitted closing root.
    #[must_use]
    pub fn withdrawal_safety_roots(&self) -> Vec<VectorRoot<H::Digest>> {
        core::iter::once(self.current_state_root)
            .chain(self.pipeline.iter().map(|entry| entry.batch.roots.closing))
            .collect()
    }

    /// Binds a root-independent epoch registration to the pipeline head and registers its boundary.
    pub fn register_epoch(
        &mut self,
        now: u64,
        context: EpochContext<P, H::Digest>,
        deposits: DepositBatch<P>,
        withdrawals: WithdrawalBatch<P, H::Digest>,
    ) -> Result<(), SettlementError> {
        let context = context.bind_settlement_root(self.head_state_root());
        self.register(now, context, deposits, withdrawals)
    }

    /// Registers a close context already bound to the pipeline head and its boundary.
    pub fn register(
        &mut self,
        now: u64,
        context: CloseContext<P, H::Digest>,
        deposits: DepositBatch<P>,
        withdrawals: WithdrawalBatch<P, H::Digest>,
    ) -> Result<(), SettlementError> {
        self.ensure_operating_at(now)?;
        if self.registered.is_some() {
            return Err(SettlementError::EpochAlreadyActive);
        }
        if self.pipeline.len() >= self.config.max_pending_epochs.get() {
            return Err(SettlementError::PipelineFull);
        }
        if now > context.admission_deadline() {
            return Err(SettlementError::AdmissionAfterDeadline);
        }
        if context.deployment() != &self.deployment {
            return Err(SettlementError::Deployment);
        }
        if context.payment().operator() != &self.operator {
            return Err(SettlementError::OperatorMismatch);
        }
        if context.payment().epoch() != self.next_admission_epoch()? {
            return Err(SettlementError::EpochSequence);
        }
        context
            .payment()
            .epoch()
            .checked_add(1)
            .ok_or(SettlementError::EpochOverflow)?;
        if context.opening_root() != &self.head_state_root() {
            return Err(SettlementError::StateAncestry);
        }
        if context.opening_liability() != self.head_liability() {
            return Err(SettlementError::LiabilityAncestry);
        }
        if context.assignment().committee()
            != &self.certificate_scheme.committee().commitment::<H>()
        {
            return Err(SettlementError::CommitteeMismatch);
        }
        if context.deposit_root() != &deposits.root::<H>()?
            || context.withdrawal_root() != &withdrawals.root::<H>()?
        {
            return Err(SettlementError::BoundaryRoot);
        }
        if deposits != self.pending_deposits() {
            return Err(SettlementError::DepositWitness);
        }
        if withdrawals != self.pending_withdrawals() {
            return Err(SettlementError::WithdrawalWitness);
        }
        self.check_phase_custody()?;

        let exact_amount_total = withdrawals.total();
        let withdrawals = self
            .pending_withdrawals
            .values()
            .cloned()
            .collect::<Vec<_>>();
        self.registered = Some(RegisteredClose {
            context,
            deposits,
            withdrawals,
            exact_amount_total,
            withdrawal_deadline: self.pending_withdrawal_deadlines.first().cloned(),
        });
        Ok(())
    }

    /// Admits a contextual header, its root witness, and its exact certificate.
    pub fn admit(
        &mut self,
        now: u64,
        header: Header<H::Digest>,
        roots: RootBundle<H::Digest>,
        terminal_proof: TerminalProof<H::Digest>,
        certificate: bls12381::Certificate,
    ) -> Result<BatchId<H::Digest>, SettlementError> {
        self.ensure_operating_at(now)?;
        if self.pipeline.len() >= self.config.max_pending_epochs.get() {
            return Err(SettlementError::PipelineFull);
        }
        let registered = self
            .registered
            .as_ref()
            .ok_or(SettlementError::NoRegisteredEpoch)?;
        if now > registered.context.admission_deadline() {
            return Err(SettlementError::AdmissionAfterDeadline);
        }
        transition::validate_header::<H, P, H::Digest>(&registered.context, &header, &roots)?;
        if !self.certificate_scheme.verify_exact(&header, &certificate) {
            return Err(SettlementError::InvalidCertificate);
        }
        let totals = verify_terminal_proof_after_header::<H, P, H::Digest>(
            &registered.context,
            &registered.deposits,
            &self.pending_withdrawals(),
            &roots,
            &terminal_proof,
        )?;
        if usize::try_from(terminal_proof.terminal().closing).map_or(true, |closing| {
            closing > self.config.max_state_accounts.get()
        }) {
            return Err(SettlementError::StateCapacity);
        }
        let withdrawal_total = totals.withdrawal;
        if withdrawal_total < registered.exact_amount_total {
            return Err(SettlementError::WithdrawalWitness);
        }
        let payout_total = totals.payout;
        let closing_liability = registered
            .context
            .opening_liability()
            .checked_add(registered.deposits.total())
            .and_then(|liability| liability.checked_sub(withdrawal_total))
            .and_then(|liability| liability.checked_sub(payout_total))
            .ok_or(SettlementError::CustodyArithmetic)?;

        let batch_id = header.batch_id::<H>();
        let registered = self
            .registered
            .take()
            .expect("the registered close was checked above");
        for record in registered.deposits.records() {
            self.pending_deposits
                .remove(record.account())
                .expect("the exact staged deposit was checked above");
        }
        let admitted = AdmittedClose {
            context: registered.context,
            deposit_total: registered.deposits.total(),
            deposits: PackedDeposits::new(&registered.deposits),
            withdrawals: PackedWithdrawals::new(&registered.withdrawals),
            withdrawal_total,
            withdrawal_deadline: registered.withdrawal_deadline,
            payout_total,
        };
        self.pipeline.push_back(PipelineEntry {
            admitted,
            batch: PendingBatch {
                header,
                roots,
                certificate,
                closing_liability,
                status: BatchStatus::Pending,
            },
        });
        self.pending_withdrawals.clear();
        self.pending_withdrawal_deadlines.clear();
        Ok(batch_id)
    }

    /// Adjudicates a typed receipt challenge through the target's inclusive deadline.
    pub fn challenge(
        &mut self,
        now: u64,
        submitted: &Challenge<P, H::Digest>,
    ) -> Result<Verdict, SettlementError> {
        self.challenge_with_strategy(now, submitted, &Sequential)
    }

    /// Adjudicates a typed receipt challenge using the supplied execution strategy.
    pub fn challenge_with_strategy(
        &mut self,
        now: u64,
        submitted: &Challenge<P, H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<Verdict, SettlementError> {
        self.observe_time(now);
        self.challenge_after_observation(now, submitted, strategy)
    }

    /// Bounded-decodes and adjudicates one receipt challenge.
    pub fn challenge_encoded(
        &mut self,
        now: u64,
        encoded: &[u8],
        maximum_bytes: usize,
    ) -> Result<Verdict, SettlementError> {
        self.challenge_encoded_with_strategy(now, encoded, maximum_bytes, &Sequential)
    }

    /// Bounded-decodes and adjudicates one receipt challenge using the supplied strategy.
    pub fn challenge_encoded_with_strategy(
        &mut self,
        now: u64,
        encoded: &[u8],
        maximum_bytes: usize,
        strategy: &impl Strategy,
    ) -> Result<Verdict, SettlementError> {
        self.observe_time(now);
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        let submitted = challenge::decode_bounded(encoded, maximum_bytes)?;
        self.challenge_after_observation(now, &submitted, strategy)
    }

    fn challenge_after_observation(
        &mut self,
        now: u64,
        submitted: &Challenge<P, H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<Verdict, SettlementError> {
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        let index = self
            .pipeline
            .iter()
            .position(|entry| entry.batch.header.batch_id::<H>() == *submitted.batch())
            .ok_or(SettlementError::NoPendingBatch)?;
        match &self.pipeline[index].batch.status {
            BatchStatus::Pending => {}
            BatchStatus::Challenged(_) => return Err(SettlementError::AlreadyChallenged),
            BatchStatus::Invalidated(_) => return Err(SettlementError::BatchInvalidated),
        }

        let verdict = challenge::adjudicate_with_strategy::<H, P>(
            &self.pipeline[index].admitted.context,
            &self.pipeline[index].batch.header,
            &self.pipeline[index].batch.roots,
            now,
            submitted,
            strategy,
        )?;
        if let Verdict::Proven(kind) = verdict {
            let batch_id = self.pipeline[index].batch.header.batch_id::<H>();
            self.pipeline[index].batch.status = BatchStatus::Challenged(kind);
            for descendant in self.pipeline.iter_mut().skip(index + 1) {
                descendant.batch.status = BatchStatus::Invalidated(batch_id);
            }
            self.invalid_from = Some(batch_id);
            self.enter_hard_fault(HardFaultReason::ProvenChallenge { batch_id, kind });
        }
        Ok(verdict)
    }

    /// Finalizes the pending pipeline front after its inclusive challenge window.
    ///
    /// The caller must atomically separate the returned aggregate claim reserve from active
    /// custody with this state mutation. Individual recipients claim later with bounded proofs.
    pub fn finalize(&mut self, now: u64) -> Result<FinalizedBatch<H::Digest>, SettlementError> {
        self.observe_time(now);
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        let next_epoch = self
            .expected_epoch
            .checked_add(1)
            .ok_or(SettlementError::EpochOverflow)?;
        let (
            batch_id,
            epoch,
            closing_state_root,
            closing_liability,
            withdrawal_total,
            payout_total,
            custody_balance,
            claimable_balance,
            unfinalized_deposit_total,
        ) = {
            let entry = self
                .pipeline
                .front()
                .ok_or(SettlementError::NoPendingBatch)?;
            match &entry.batch.status {
                BatchStatus::Pending => {}
                BatchStatus::Challenged(_) | BatchStatus::Invalidated(_) => {
                    return Err(SettlementError::BatchInvalidated);
                }
            }
            if now <= entry.admitted.context.challenge_deadline() {
                return Err(SettlementError::ChallengeWindowOpen);
            }
            let epoch = entry.admitted.context.payment().epoch();
            if epoch != self.expected_epoch {
                return Err(SettlementError::EpochSequence);
            }

            let withdrawal_total = entry.admitted.withdrawal_total;
            let payout_total = entry.admitted.payout_total;
            let reserve_total = withdrawal_total
                .checked_add(payout_total)
                .ok_or(SettlementError::CustodyArithmetic)?;
            let claimable_balance = self
                .claimable_balance
                .checked_add(reserve_total)
                .ok_or(SettlementError::CustodyArithmetic)?;
            let custody_balance = self
                .custody_balance
                .checked_sub(reserve_total)
                .ok_or(SettlementError::CustodyArithmetic)?;
            let unfinalized_deposit_total = self
                .unfinalized_deposit_total
                .checked_sub(entry.admitted.deposit_total)
                .ok_or(SettlementError::CustodyArithmetic)?;
            let closing_liability = entry.batch.closing_liability;
            let expected_custody = closing_liability
                .checked_add(unfinalized_deposit_total)
                .ok_or(SettlementError::CustodyArithmetic)?;
            if custody_balance != expected_custody {
                return Err(SettlementError::CustodyMismatch);
            }
            let batch_id = entry.batch.header.batch_id::<H>();
            if reserve_total != 0 && self.claimable_batches.contains_key(&batch_id) {
                return Err(SettlementError::ClaimBatchCollision);
            }
            if reserve_total != 0
                && self.claimable_batches.len() >= self.config.max_claimable_batches.get()
            {
                return Err(SettlementError::ClaimableBatchCapacity);
            }
            (
                batch_id,
                epoch,
                entry.batch.roots.closing,
                closing_liability,
                withdrawal_total,
                payout_total,
                custody_balance,
                claimable_balance,
                unfinalized_deposit_total,
            )
        };

        let finalized = FinalizedBatch {
            batch_id,
            epoch,
            closing_state_root,
            withdrawal_total,
            payout_total,
            custody_balance,
        };
        let entry = self
            .pipeline
            .pop_front()
            .expect("the finalized pipeline front was checked above");
        self.current_state_root = finalized.closing_state_root;
        self.current_liability = closing_liability;
        self.custody_balance = custody_balance;
        self.claimable_balance = claimable_balance;
        self.unfinalized_deposit_total = unfinalized_deposit_total;

        if withdrawal_total != 0 || payout_total != 0 {
            let replaced = self.claimable_batches.insert(
                batch_id,
                ClaimableBatch {
                    change_root: entry.batch.roots.change,
                    withdrawal_root: *entry.admitted.context.withdrawal_root(),
                    claimed_withdrawals: BTreeSet::new(),
                    claimed_payouts: BTreeSet::new(),
                    withdrawal_remaining: withdrawal_total,
                    payout_remaining: payout_total,
                },
            );
            debug_assert!(replaced.is_none());
        }
        self.expected_epoch = next_epoch;
        Ok(finalized)
    }

    /// Consumes one external-payment claim against a finalized change root.
    ///
    /// The embedding must commit this mutation and the payout effect atomically, using
    /// `(batch_id, claim.position())` as the idempotency key.
    pub fn claim_external_payout(
        &mut self,
        batch_id: BatchId<H::Digest>,
        claim: &ExternalPayoutClaim<P, H::Digest>,
    ) -> Result<ExternalPayout<P>, SettlementError> {
        let payout = {
            let batch = self
                .claimable_batches
                .get(&batch_id)
                .ok_or(SettlementError::ClaimBatchUnavailable)?;
            if batch.claimed_payouts.contains(&claim.position()) {
                return Err(SettlementError::ClaimAlreadyConsumed);
            }
            let payout = claim.verify::<H>(&batch.change_root)?;
            batch
                .payout_remaining
                .checked_sub(payout.amount)
                .ok_or(SettlementError::ClaimReserve)?;
            payout
        };
        let claimable_balance = self
            .claimable_balance
            .checked_sub(payout.amount)
            .ok_or(SettlementError::ClaimReserve)?;
        let remove_batch = {
            let batch = self
                .claimable_batches
                .get_mut(&batch_id)
                .expect("the claimable batch was checked above");
            let inserted = batch.claimed_payouts.insert(claim.position());
            debug_assert!(inserted);
            batch.payout_remaining -= payout.amount;
            batch.payout_remaining == 0 && batch.withdrawal_remaining == 0
        };
        self.claimable_balance = claimable_balance;
        if remove_batch {
            self.claimable_batches.remove(&batch_id);
        }
        Ok(payout)
    }

    /// Consumes one signed-withdrawal claim against a finalized boundary and change root.
    ///
    /// The embedding must commit this mutation and payout atomically, using the finalized batch
    /// identifier and the claim's withdrawal-vector position as the idempotency key.
    pub fn claim_withdrawal(
        &mut self,
        batch_id: BatchId<H::Digest>,
        claim: &WithdrawalClaim<P, H::Digest>,
    ) -> Result<WithdrawalRelease<P, H::Digest>, SettlementError> {
        let (release, position) = {
            let batch = self
                .claimable_batches
                .get(&batch_id)
                .ok_or(SettlementError::ClaimBatchUnavailable)?;
            let amount =
                claim.verify::<H>(&self.deployment, &batch.withdrawal_root, &batch.change_root)?;
            let position = claim.position();
            if batch.claimed_withdrawals.contains(&position) {
                return Err(SettlementError::ClaimAlreadyConsumed);
            }
            batch
                .withdrawal_remaining
                .checked_sub(amount)
                .ok_or(SettlementError::ClaimReserve)?;
            (
                WithdrawalRelease {
                    request: claim.request().clone(),
                    amount,
                },
                position,
            )
        };
        let claimable_balance = self
            .claimable_balance
            .checked_sub(release.amount)
            .ok_or(SettlementError::ClaimReserve)?;
        let remove_batch = {
            let batch = self
                .claimable_batches
                .get_mut(&batch_id)
                .expect("the claimable batch was checked above");
            let inserted = batch.claimed_withdrawals.insert(position);
            debug_assert!(inserted);
            batch.withdrawal_remaining -= release.amount;
            batch.payout_remaining == 0 && batch.withdrawal_remaining == 0
        };
        self.claimable_balance = claimable_balance;
        if remove_batch {
            self.claimable_batches.remove(&batch_id);
        }
        Ok(release)
    }

    /// Removes a registration that admitted no header after its admission deadline.
    pub fn expire_unadmitted(&mut self, now: u64) -> Result<(), SettlementError> {
        self.ensure_operating_at(now)?;
        let registered = self
            .registered
            .as_ref()
            .ok_or(SettlementError::NoRegisteredEpoch)?;
        if now <= registered.context.admission_deadline() {
            return Err(SettlementError::AdmissionWindowOpen);
        }
        self.registered = None;
        Ok(())
    }

    /// Permanently fences the deployment after observing an outstanding withdrawal deadline.
    pub fn fault_expired_withdrawal(
        &mut self,
        now: u64,
    ) -> Result<HardFaultReason<P, H::Digest>, SettlementError> {
        self.ensure_operating()?;
        let reason = self
            .expired_withdrawal_reason(now)
            .ok_or(SettlementError::WithdrawalDeadlineNotReached)?;
        self.enter_hard_fault(reason.clone());
        Ok(reason)
    }

    /// Exhausts custody using the complete last-finalized state preimage.
    ///
    /// The caller must atomically commit the returned payout effects with this state mutation.
    pub fn settle_hard_fault(
        &mut self,
        survivor: &StateCache<P, H::Digest>,
    ) -> Result<HardFaultSettlement<P, H::Digest>, SettlementError> {
        let reason = self
            .hard_fault
            .clone()
            .ok_or(SettlementError::OperatorNotHardFaulted)?;
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        if self
            .pipeline
            .front()
            .is_some_and(|entry| matches!(entry.batch.status, BatchStatus::Pending))
        {
            return Err(SettlementError::PreFaultBatchPending);
        }
        self.validate_survivor(survivor)?;

        let mut terminal_deposits = self.pending_deposits.clone();
        for entry in &self.pipeline {
            let deposits = entry
                .admitted
                .deposits
                .decode(self.config.max_deposit_ids.get())?;
            for record in deposits.records() {
                let amount = terminal_deposits
                    .get(record.account())
                    .copied()
                    .unwrap_or(0)
                    .checked_add(record.amount())
                    .ok_or(SettlementError::CustodyArithmetic)?;
                terminal_deposits.insert(record.account().clone(), amount);
            }
        }
        let deposit_total = terminal_deposits
            .values()
            .try_fold(0_u64, |total, amount| total.checked_add(*amount))
            .ok_or(SettlementError::CustodyArithmetic)?;
        if deposit_total != self.unfinalized_deposit_total {
            return Err(SettlementError::CustodyMismatch);
        }
        if survivor
            .liability()
            .checked_add(deposit_total)
            .ok_or(SettlementError::CustodyArithmetic)?
            != self.custody_balance
        {
            return Err(SettlementError::CustodyMismatch);
        }

        let mut withdrawals = self.pending_withdrawals.clone();
        for entry in &self.pipeline {
            let requests = entry
                .admitted
                .withdrawals
                .decode(self.config.max_destination_bytes)?;
            for request in requests {
                if withdrawals
                    .insert(request.account().clone(), request)
                    .is_some()
                {
                    return Err(SettlementError::WithdrawalWitness);
                }
            }
        }
        let mut payouts = Vec::new();
        let mut released_custody = 0_u64;
        for leaf in survivor.leaves() {
            let source = leaf.account.clone();
            let deposit = terminal_deposits.remove(&source).unwrap_or(0);
            let withdrawal = withdrawals.remove(&source);
            let withdrawal_amount =
                withdrawal
                    .as_ref()
                    .map_or(0, |request| match request.body().action() {
                        WithdrawalAction::Amount(amount) => amount.get(),
                        WithdrawalAction::Close => leaf.state.balance,
                    });
            if let Some(request) = withdrawal {
                if withdrawal_amount > leaf.state.balance {
                    return Err(SettlementError::WithdrawalBalance);
                }
                if withdrawal_amount != 0 {
                    payouts.push(FaultPayout::QueuedWithdrawal(WithdrawalRelease {
                        request,
                        amount: withdrawal_amount,
                    }));
                }
            }

            let residual = leaf
                .state
                .balance
                .checked_sub(withdrawal_amount)
                .and_then(|balance| balance.checked_add(deposit))
                .ok_or(SettlementError::CustodyArithmetic)?;
            if residual > 0 {
                payouts.push(FaultPayout::ResidualSettlement {
                    account: source,
                    amount: residual,
                });
            }
            released_custody = released_custody
                .checked_add(withdrawal_amount)
                .and_then(|total| total.checked_add(residual))
                .ok_or(SettlementError::CustodyArithmetic)?;
        }
        for (account, amount) in terminal_deposits {
            payouts.push(FaultPayout::ResidualSettlement { account, amount });
            released_custody = released_custody
                .checked_add(amount)
                .ok_or(SettlementError::CustodyArithmetic)?;
        }
        if !withdrawals.is_empty() {
            return Err(SettlementError::WithdrawalOpening);
        }
        if released_custody != self.custody_balance {
            return Err(SettlementError::CustodyMismatch);
        }

        let terminal_state = StateCache::new::<H>(Vec::new())?;
        if terminal_state.liability() != 0 {
            return Err(SettlementError::CustodyMismatch);
        }
        let terminal_root = terminal_state.root();
        let settlement = HardFaultSettlement {
            reason,
            admission_fence_epoch: self
                .admission_fence_epoch
                .expect("every hard fault records its admission fence"),
            invalid_from: self.invalid_from,
            terminal_state,
            payouts,
            released_custody,
        };

        self.current_state_root = terminal_root;
        self.current_liability = 0;
        self.custody_balance = 0;
        self.pending_deposits.clear();
        self.pending_withdrawals.clear();
        self.pending_withdrawal_deadlines.clear();
        self.consumed_withdrawal_ids.clear();
        self.withdrawal_replay_expiries.clear();
        self.unfinalized_deposit_total = 0;
        self.pipeline.clear();
        self.registered = None;
        self.fault_settled = true;
        Ok(settlement)
    }

    fn validate_survivor(
        &self,
        survivor: &StateCache<P, H::Digest>,
    ) -> Result<(), SettlementError> {
        if survivor.root() != self.current_state_root {
            return Err(SettlementError::StateAncestry);
        }
        if survivor.liability() != self.current_liability {
            return Err(SettlementError::CustodyMismatch);
        }
        if survivor.leaves().len() > self.config.max_state_accounts.get() {
            return Err(SettlementError::StateCapacity);
        }
        Ok(())
    }

    /// Returns the finalized state root.
    #[must_use]
    pub const fn current_state_root(&self) -> VectorRoot<H::Digest> {
        self.current_state_root
    }

    /// Returns active custody backing live liability and unfinalized deposits.
    #[must_use]
    pub const fn custody_balance(&self) -> u64 {
        self.custody_balance
    }

    /// Returns finalized custody reserved for unconsumed payout and withdrawal claims.
    #[must_use]
    pub const fn claimable_balance(&self) -> u64 {
        self.claimable_balance
    }

    /// Returns the admitted pipeline front.
    #[must_use]
    pub fn pending(&self) -> Option<&PendingBatch<H::Digest>> {
        self.pipeline.front().map(|entry| &entry.batch)
    }

    /// Iterates admitted closes in ancestry order.
    pub fn pending_batches(&self) -> impl ExactSizeIterator<Item = &PendingBatch<H::Digest>> {
        self.pipeline.iter().map(|entry| &entry.batch)
    }

    /// Returns the number of admitted unfinalized closes.
    #[must_use]
    pub fn pending_epoch_count(&self) -> usize {
        self.pipeline.len()
    }

    /// Returns the configured settlement policy.
    #[must_use]
    pub const fn config(&self) -> SettlementConfig {
        self.config
    }

    /// Returns the permanent fault reason, if any.
    #[must_use]
    pub const fn hard_fault(&self) -> Option<&HardFaultReason<P, H::Digest>> {
        self.hard_fault.as_ref()
    }

    /// Returns the first epoch excluded by a permanent admission fence.
    #[must_use]
    pub const fn admission_fence_epoch(&self) -> Option<u64> {
        self.admission_fence_epoch
    }

    /// Returns the earliest receipt-invalidated close, if any.
    #[must_use]
    pub const fn invalid_from(&self) -> Option<BatchId<H::Digest>> {
        self.invalid_from
    }

    /// Returns whether terminal settlement has already exhausted custody.
    #[must_use]
    pub const fn hard_fault_is_settled(&self) -> bool {
        self.fault_settled
    }
}

/// Settlement lifecycle failure.
#[derive(Debug, Error)]
pub enum SettlementError {
    /// An epoch registration is already active.
    #[error("an epoch registration is already active")]
    EpochAlreadyActive,
    /// The admitted pipeline reached its configured capacity.
    #[error("the configured admitted pipeline is full")]
    PipelineFull,
    /// The context names another deployment.
    #[error("close context does not equal the settlement deployment")]
    Deployment,
    /// The context names another receipt-signing operator.
    #[error("close context operator does not equal the settlement operator")]
    OperatorMismatch,
    /// The context epoch is not the unique tail successor.
    #[error("close context is not the unique expected epoch successor")]
    EpochSequence,
    /// A state root does not extend the current authenticated ancestry.
    #[error("state root does not extend the authenticated ancestry")]
    StateAncestry,
    /// A context opening liability does not extend the tail liability.
    #[error("opening liability does not extend the authenticated ancestry")]
    LiabilityAncestry,
    /// The certificate committee differs from the anchor-bound assignment.
    #[error("certificate committee does not match the authenticated assignment")]
    CommitteeMismatch,
    /// Supplied exact batches do not match the context's sealed roots.
    #[error("boundary batches do not match their sealed roots")]
    BoundaryRoot,
    /// Supplied deposits do not equal the exact staged deposit batch.
    #[error("registered deposits do not equal the staged deposit batch")]
    DepositWitness,
    /// Supplied withdrawals do not equal the exact staged withdrawal batch.
    #[error("registered withdrawals do not equal the staged withdrawal batch")]
    WithdrawalWitness,
    /// No finalized claim reserve exists for the requested batch.
    #[error("finalized claim batch is unavailable")]
    ClaimBatchUnavailable,
    /// Two finalized headers resolved to one claim-batch identifier.
    #[error("finalized claim batch identifier collision")]
    ClaimBatchCollision,
    /// Finalized claim batches reached their configured retention bound.
    #[error("the configured finalized claim-batch capacity is full")]
    ClaimableBatchCapacity,
    /// The exact finalized claim was already consumed.
    #[error("finalized claim was already consumed")]
    ClaimAlreadyConsumed,
    /// A claim exceeds its remaining finalized reserve.
    #[error("claim exceeds the finalized reserve")]
    ClaimReserve,
    /// Deposits must carry value.
    #[error("deposit amount must be positive")]
    ZeroDeposit,
    /// An external deposit event identifier was already consumed.
    #[error("external deposit identifier was already consumed")]
    DuplicateDeposit,
    /// The deployment retained its configured maximum number of external deposit identifiers.
    #[error("external deposit replay-protection capacity is exhausted")]
    DepositCapacity,
    /// A withdrawal destination failed the adapter eligibility predicate.
    #[error("withdrawal destination is not accepted by the asset adapter")]
    IneligibleDestination,
    /// A withdrawal destination exceeds the deployment's retained-byte bound.
    #[error("withdrawal destination exceeds the configured byte bound")]
    DestinationTooLarge,
    /// A safety opening does not authenticate the authorizing account.
    #[error("withdrawal opening does not authenticate the requesting account")]
    WithdrawalOpening,
    /// A withdrawal names an inactive account, or an `Amount` exceeds the balance.
    #[error("withdrawal account is inactive or Amount exceeds its balance")]
    WithdrawalBalance,
    /// One account already has an unreleased withdrawal.
    #[error("an account may have at most one unreleased withdrawal")]
    DuplicateWithdrawal,
    /// An exact signed withdrawal authorization was already consumed.
    #[error("signed withdrawal authorization was already consumed")]
    DuplicateWithdrawalAuthorization,
    /// Safety openings do not cover the finalized root and every admitted root exactly.
    #[error("withdrawal openings do not cover all safety roots exactly")]
    WithdrawalOpeningCount,
    /// The signed deadline does not provide the configured notice.
    #[error("withdrawal deadline does not provide the minimum notice")]
    WithdrawalDeadlineTooSoon,
    /// The signed deadline exceeds the deployment's replay-retention horizon.
    #[error("withdrawal deadline exceeds the maximum notice")]
    WithdrawalDeadlineTooLate,
    /// The configured maximum withdrawal notice is shorter than the minimum.
    #[error("maximum withdrawal notice must not be shorter than the minimum")]
    WithdrawalNoticeOrder,
    /// No outstanding withdrawal has reached its inclusive deadline.
    #[error("no outstanding withdrawal has reached its deadline")]
    WithdrawalDeadlineNotReached,
    /// New work is permanently fenced.
    #[error("the settlement deployment is permanently hard-faulted")]
    OperatorHardFaulted,
    /// Terminal settlement was requested before a permanent fault.
    #[error("the settlement deployment has not hard-faulted")]
    OperatorNotHardFaulted,
    /// Terminal settlement already exhausted custody.
    #[error("the hard-faulted deployment was already settled")]
    HardFaultAlreadySettled,
    /// Custody arithmetic overflowed or underflowed.
    #[error("custody arithmetic overflowed or underflowed")]
    CustodyArithmetic,
    /// Custody does not equal finalized liability plus every unfinalized deposit.
    #[error("custody does not match authenticated liability and deposits")]
    CustodyMismatch,
    /// No epoch registration is active.
    #[error("no epoch registration is active")]
    NoRegisteredEpoch,
    /// Registration or admission occurred after the inclusive admission cutoff.
    #[error("close was submitted after its admission deadline")]
    AdmissionAfterDeadline,
    /// The retained certificate is not an exact valid quorum certificate.
    #[error("header certificate is invalid")]
    InvalidCertificate,
    /// No admitted close matches the requested operation.
    #[error("there is no matching admitted close")]
    NoPendingBatch,
    /// A successful challenge was already recorded for the target.
    #[error("a successful challenge was already recorded")]
    AlreadyChallenged,
    /// The target is at or after a proven-invalid ancestor.
    #[error("the close is at or after a proven-invalid ancestor")]
    BatchInvalidated,
    /// A surviving pre-fault close must resolve before terminal settlement.
    #[error("a pre-fault pending close must resolve before terminal settlement")]
    PreFaultBatchPending,
    /// An inclusive admission window remains open for the registered close.
    #[error("the admission window remains open")]
    AdmissionWindowOpen,
    /// An inclusive challenge window remains open.
    #[error("the challenge window remains open")]
    ChallengeWindowOpen,
    /// Advancing the epoch counter would overflow.
    #[error("epoch counter overflow")]
    EpochOverflow,
    /// An initial, admitted, or terminal-survivor state exceeds the live-account bound.
    #[error("state exceeds the configured live-account bound")]
    StateCapacity,
    /// Boundary construction or signature verification failed.
    #[error("invalid boundary: {0}")]
    Boundary(#[from] BoundaryError),
    /// Public transition verification failed.
    #[error("invalid close transition: {0}")]
    Transition(#[from] TransitionError),
    /// Receipt challenge verification failed.
    #[error("invalid challenge: {0}")]
    Challenge(#[from] ChallengeError),
    /// Vector opening or boundary commitment verification failed.
    #[error("invalid vector commitment: {0}")]
    Commitment(#[from] commitment::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        admission::{Committee, bls12381},
        boundary::{SignedWithdrawal, WithdrawalAction, WithdrawalBody},
        commitment::VectorKind,
        credit::{ShardHead, ShardSet},
        payment::{Payment, PaymentError, SignedReceipt, SignedSend},
        state::{AccountRow, AccountState, Prefix, StateLeaf},
        transition::{
            Assignment, Close, CloseLimits, assemble_external_payout_claim,
            assemble_terminal_proof, assemble_withdrawal_claim, build_close, validate_close,
        },
    };
    use alloc::collections::BTreeSet;
    use bytes::BufMut;
    use commonware_codec::{Error as CodecError, FixedSize, ReadExt, Write};
    use commonware_cryptography::{
        Sha256, Signer as _,
        bls12381::primitives::{
            group::{Private as BlsPrivate, Scalar},
            ops::compute_public,
            variant::MinSig,
        },
        sha256::Digest as ShaDigest,
    };
    use commonware_cryptography_curve25519::signing::{
        Signature, SigningKey, StrictVerifyingKey as VerifyingKey,
    };
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{Array, Span, test_rng};
    use core::{fmt, ops::Deref};
    use rand_core::Rng;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    type TestCache = StateCache<VerifyingKey, ShaDigest>;
    type TestChain = SettlementChain<Sha256, VerifyingKey>;
    type TestChallenge = Challenge<VerifyingKey, ShaDigest>;
    type TestClose = Close<VerifyingKey, ShaDigest>;
    type TestContext = CloseContext<VerifyingKey, ShaDigest>;
    type TestDeposits = DepositBatch<VerifyingKey>;
    type TestWithdrawals = WithdrawalBatch<VerifyingKey, ShaDigest>;

    struct Harness {
        chain: TestChain,
        cache: TestCache,
        deployment: ShaDigest,
        operator: SigningKey,
        signer: bls12381::Scheme,
        committee: ShaDigest,
        accounts: Vec<SigningKey>,
    }

    fn state(balance: u64) -> AccountState {
        AccountState {
            balance,
            active: true,
            ..AccountState::default()
        }
    }

    fn config(max_pending_epochs: usize, minimum_withdrawal_notice: u64) -> SettlementConfig {
        SettlementConfig::new(
            NonZeroUsize::new(max_pending_epochs).unwrap(),
            NonZeroU64::new(minimum_withdrawal_notice).unwrap(),
            NonZeroU64::new(1_000).unwrap(),
            NonZeroUsize::new(1_024).unwrap(),
            1_024,
            NonZeroUsize::new(1_024).unwrap(),
            NonZeroUsize::new(1_024).unwrap(),
        )
    }

    fn harness_with_states(
        states: &[AccountState],
        settlement_config: SettlementConfig,
    ) -> Harness {
        let accounts = states
            .iter()
            .enumerate()
            .map(|(index, _)| SigningKey::from_seed(10 + index as u64))
            .collect::<Vec<_>>();
        let mut leaves = accounts
            .iter()
            .zip(states)
            .map(|(account, state)| StateLeaf {
                account: account.public_key(),
                state: *state,
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deployment = Sha256::hash(&[b"settlement-test-deployment"]);
        let operator = SigningKey::from_seed(100);
        let validator_bls = bls_private(101);
        let committee_keys =
            Committee::new(vec![compute_public::<MinSig>(&validator_bls)]).unwrap();
        let committee = committee_keys.commitment::<Sha256>();
        let signer = bls12381::Scheme::signer(committee_keys.clone(), validator_bls).unwrap();
        let chain = SettlementChain::new(
            deployment,
            operator.public_key(),
            committee_keys,
            &cache,
            0,
            settlement_config,
        )
        .unwrap();
        Harness {
            chain,
            cache,
            deployment,
            operator,
            signer,
            committee,
            accounts,
        }
    }

    fn bls_private(seed: u64) -> BlsPrivate {
        let mut rng = test_rng();
        let scalar = rng.next_u64().wrapping_add(seed).max(1);
        BlsPrivate::new(Scalar::from(scalar))
    }

    fn committee(seed: u64) -> Committee {
        let private = bls_private(seed);
        Committee::new(vec![compute_public::<MinSig>(&private)]).unwrap()
    }

    fn harness_with_config(balances: &[u64], settlement_config: SettlementConfig) -> Harness {
        harness_with_states(
            &balances
                .iter()
                .map(|balance| state(*balance))
                .collect::<Vec<_>>(),
            settlement_config,
        )
    }

    fn harness(balances: &[u64]) -> Harness {
        harness_with_config(balances, config(3, 2))
    }

    #[allow(clippy::too_many_arguments)]
    fn context(
        deployment: ShaDigest,
        operator: &SigningKey,
        committee: ShaDigest,
        epoch: u64,
        cache: &TestCache,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> TestContext {
        EpochContext::new::<Sha256>(
            deployment,
            epoch,
            operator.public_key(),
            deposits,
            withdrawals,
            cache.liability(),
            admission_deadline,
            challenge_deadline,
            CloseLimits::protocol_maximum(),
            Assignment::new(committee, 0).unwrap(),
        )
        .and_then(|epoch| epoch.bind::<Sha256>(cache, deposits, withdrawals))
        .unwrap()
    }

    fn empty_close(cache: &TestCache, context: &TestContext) -> TestClose {
        build_close::<Sha256, _, _>(
            cache,
            context,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    fn boundary_close(
        cache: &TestCache,
        context: &TestContext,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
    ) -> (TestClose, TestCache) {
        let mut changed = BTreeSet::new();
        changed.extend(
            deposits
                .records()
                .iter()
                .map(|record| record.account().clone()),
        );
        changed.extend(
            withdrawals
                .requests()
                .iter()
                .map(|request| request.account().clone()),
        );

        let mut prefix = Prefix::default();
        let mut rows = Vec::with_capacity(changed.len());
        let mut shard_sets = Vec::with_capacity(changed.len());
        for account in changed {
            let opening = cache
                .leaves()
                .iter()
                .find(|leaf| leaf.account == account)
                .map_or_else(AccountState::default, |leaf| leaf.state);
            let deposit = deposits.amount_for(&account);
            let withdrawal = withdrawals.request_for(&account);
            let applied = withdrawal.map_or(0, |request| match request.body().action() {
                WithdrawalAction::Amount(amount) => amount.get(),
                WithdrawalAction::Close => opening.balance.checked_add(deposit).unwrap(),
            });
            let mut closing = opening;
            closing.balance = opening
                .balance
                .checked_add(deposit)
                .and_then(|balance| balance.checked_sub(applied))
                .unwrap();
            closing.active = closing.balance > 0;
            let shards = ShardSet::empty(context.payment().epoch(), account.clone());
            prefix = prefix
                .checked_extend(Prefix {
                    deposit,
                    withdrawal: applied,
                    withdrawals: u64::from(withdrawal.is_some()),
                    ..Prefix::default()
                })
                .unwrap();
            rows.push(AccountRow {
                account,
                opening,
                closing,
                outgoing: None,
                credit_root: shards.root::<Sha256>().unwrap(),
                prefix,
            });
            shard_sets.push(shards);
        }
        let close =
            build_close::<Sha256, _, _>(cache, context, deposits, withdrawals, rows, shard_sets)
                .unwrap();
        let changed = close
            .rows
            .iter()
            .map(|row| row.account.clone())
            .collect::<BTreeSet<_>>();
        let mut closing_leaves = cache
            .leaves()
            .iter()
            .filter(|leaf| !changed.contains(&leaf.account))
            .cloned()
            .collect::<Vec<_>>();
        closing_leaves.extend(
            close
                .rows
                .iter()
                .filter(|row| row.closing.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: row.closing,
                }),
        );
        closing_leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let closing = StateCache::new::<Sha256>(closing_leaves).unwrap();
        assert_eq!(closing.root(), close.roots.closing);
        (close, closing)
    }

    fn certificate(
        signer: &bls12381::Scheme,
        context: &TestContext,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
        close: &TestClose,
    ) -> bls12381::Certificate {
        validate_close::<Sha256, _, _>(context, deposits, withdrawals, close).unwrap();
        let vote = signer.sign(&close.header).unwrap();
        signer.assemble_exact([vote]).unwrap()
    }

    fn register_and_admit(
        chain: &mut TestChain,
        signer: &bls12381::Scheme,
        now: u64,
        context: TestContext,
        deposits: TestDeposits,
        withdrawals: TestWithdrawals,
        close: &TestClose,
    ) -> BatchId<ShaDigest> {
        let certificate = certificate(signer, &context, &deposits, &withdrawals, close);
        let terminal_proof = assemble_terminal_proof::<Sha256, _, _>(
            &context,
            &deposits,
            &withdrawals,
            close,
            &Sequential,
        )
        .unwrap();
        chain.register(now, context, deposits, withdrawals).unwrap();
        chain
            .admit(now, close.header, close.roots, terminal_proof, certificate)
            .unwrap()
    }

    fn admit_empty_epoch(
        fixture: &mut Harness,
        epoch: u64,
        now: u64,
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> (TestContext, BatchId<ShaDigest>) {
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            epoch,
            &fixture.cache,
            &deposits,
            &withdrawals,
            admission_deadline,
            challenge_deadline,
        );
        let close = empty_close(&fixture.cache, &close_context);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            now,
            close_context.clone(),
            deposits,
            withdrawals,
            &close,
        );
        (close_context, batch_id)
    }

    fn withdrawal(
        deployment: ShaDigest,
        root: VectorRoot<ShaDigest>,
        account: &SigningKey,
        destination: &'static [u8],
        action: WithdrawalAction,
        deadline: u64,
    ) -> SignedWithdrawal<VerifyingKey, ShaDigest> {
        SignedWithdrawal::sign(
            deployment,
            root.digest,
            Bytes::from_static(destination),
            action,
            deadline,
            account,
        )
    }

    fn amount_action(amount: u64) -> WithdrawalAction {
        WithdrawalAction::Amount(NonZeroU64::new(amount).unwrap())
    }

    struct DropTrackedDestination {
        bytes: &'static [u8],
        drops: Arc<AtomicUsize>,
    }

    impl AsRef<[u8]> for DropTrackedDestination {
        fn as_ref(&self) -> &[u8] {
            self.bytes
        }
    }

    impl Drop for DropTrackedDestination {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    struct ReverseOrderKey([u8; 2]);

    impl Ord for ReverseOrderKey {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            other.0.cmp(&self.0)
        }
    }

    impl PartialOrd for ReverseOrderKey {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl fmt::Display for ReverseOrderKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{:02x}{:02x}", self.0[0], self.0[1])
        }
    }

    impl Deref for ReverseOrderKey {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl AsRef<[u8]> for ReverseOrderKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Write for ReverseOrderKey {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf);
        }
    }

    impl FixedSize for ReverseOrderKey {
        const SIZE: usize = 2;
    }

    impl Read for ReverseOrderKey {
        type Cfg = ();

        fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self(<[u8; 2]>::read(buf)?))
        }
    }

    impl Span for ReverseOrderKey {}
    impl Array for ReverseOrderKey {}

    impl commonware_cryptography::Verifier for ReverseOrderKey {
        type Signature = Signature;

        fn verify(&self, _: &[u8], _: &[u8], _: &Self::Signature) -> bool {
            false
        }
    }

    impl PublicKey for ReverseOrderKey {}

    #[test]
    fn packed_withdrawal_lookup_uses_encoded_key_order() {
        let deployment = Sha256::hash(&[b"packed-withdrawal-order"]);
        let body = |action| WithdrawalBody::new(deployment, deployment, Bytes::new(), action, 10);
        let signature = SigningKey::from_seed(1).sign(b"test", b"test");
        let requests = vec![
            SignedWithdrawal::from_raw_unchecked(
                ReverseOrderKey([1, 0]),
                body(amount_action(1)),
                signature.clone(),
            ),
            SignedWithdrawal::from_raw_unchecked(
                ReverseOrderKey([0, 1]),
                body(WithdrawalAction::Close),
                signature,
            ),
        ];
        assert!(requests[0].account() < requests[1].account());
        assert!(requests[0].account().as_ref() > requests[1].account().as_ref());

        let packed = PackedWithdrawals::new(&requests);
        assert!(packed.contains(requests[0].account()));
        assert!(packed.contains(requests[1].account()));
        let decoded = packed.decode(0).unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(decoded.iter().any(|request| {
            request.account() == requests[1].account()
                && request.body().action() == &WithdrawalAction::Close
        }));
    }

    fn fork_payment(
        context: &TestContext,
        operator: &SigningKey,
        payer: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
    ) -> Payment<VerifyingKey, ShaDigest> {
        let send =
            SignedSend::sign_next(context.payment(), payer, recipient.public_key(), amount, 0)
                .unwrap();
        let receipt =
            SignedReceipt::issue_next::<Sha256, _>(context.payment(), &send, 0, 0, 0, operator)
                .unwrap();
        Payment::new::<Sha256>(context.payment(), send, receipt).unwrap()
    }

    fn external_payout_close(
        cache: &TestCache,
        context: &TestContext,
        operator: &SigningKey,
        payer: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
    ) -> (TestClose, TestCache) {
        let payment = fork_payment(context, operator, payer, recipient, amount);
        let opening = cache
            .leaves()
            .iter()
            .find(|leaf| leaf.account == payer.public_key())
            .expect("test payer is live")
            .state;
        let payer_shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
        let recipient_shards = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, payment.clone())],
        )
        .unwrap();
        let mut pairs = vec![
            (
                AccountRow {
                    account: payer.public_key(),
                    opening,
                    closing: AccountState {
                        balance: opening.balance.checked_sub(amount).unwrap(),
                        cumulative_debit: opening.cumulative_debit.checked_add(amount).unwrap(),
                        ..opening
                    },
                    outgoing: Some(payment),
                    credit_root: payer_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    opening: AccountState::default(),
                    closing: AccountState {
                        cumulative_credit: amount,
                        receipt_count: 1,
                        ..AccountState::default()
                    },
                    outgoing: None,
                    credit_root: recipient_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        let mut prefix = Prefix::default();
        for (row, shards) in &mut pairs {
            let (debit, credit, _) = row.checked_deltas().unwrap();
            prefix = prefix
                .checked_extend(Prefix {
                    debit,
                    credit,
                    payout: if row.opening.active { 0 } else { credit },
                    shards: shards.heads().len() as u64,
                    ..Prefix::default()
                })
                .unwrap();
            row.prefix = prefix;
        }
        let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let close = build_close::<Sha256, _, _>(
            cache,
            context,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            rows,
            shard_sets,
        )
        .unwrap();
        let changed = close
            .rows
            .iter()
            .map(|row| row.account.clone())
            .collect::<BTreeSet<_>>();
        let mut closing = cache
            .leaves()
            .iter()
            .filter(|leaf| !changed.contains(&leaf.account))
            .cloned()
            .collect::<Vec<_>>();
        closing.extend(
            close
                .rows
                .iter()
                .filter(|row| row.closing.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: row.closing,
                }),
        );
        closing.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let closing = StateCache::new::<Sha256>(closing).unwrap();
        assert_eq!(closing.root(), close.roots.closing);
        (close, closing)
    }

    fn internal_payment_and_close(
        cache: &TestCache,
        context: &TestContext,
        operator: &SigningKey,
        payer: &SigningKey,
        recipient: &SigningKey,
        withdrawals: &TestWithdrawals,
        amount: u64,
    ) -> (TestClose, TestCache) {
        let payment = fork_payment(context, operator, payer, recipient, amount);
        let payer_opening = cache.opening(&payer.public_key()).unwrap().leaf.state;
        let recipient_opening = cache.opening(&recipient.public_key()).unwrap().leaf.state;
        let payer_shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
        let recipient_shards = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, payment.clone())],
        )
        .unwrap();
        let mut pairs = vec![
            (
                AccountRow {
                    account: payer.public_key(),
                    opening: payer_opening,
                    closing: AccountState {
                        balance: 0,
                        cumulative_debit: payer_opening
                            .cumulative_debit
                            .checked_add(amount)
                            .unwrap(),
                        active: false,
                        ..payer_opening
                    },
                    outgoing: Some(payment),
                    credit_root: payer_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    opening: recipient_opening,
                    closing: AccountState {
                        balance: recipient_opening.balance.checked_add(amount).unwrap(),
                        cumulative_credit: recipient_opening
                            .cumulative_credit
                            .checked_add(amount)
                            .unwrap(),
                        receipt_count: recipient_opening.receipt_count.checked_add(1).unwrap(),
                        ..recipient_opening
                    },
                    outgoing: None,
                    credit_root: recipient_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        let mut prefix = Prefix::default();
        for (row, shards) in &mut pairs {
            let (debit, credit, _) = row.checked_deltas().unwrap();
            prefix = prefix
                .checked_extend(Prefix {
                    debit,
                    credit,
                    withdrawal: 0,
                    withdrawals: u64::from(row.account == payer.public_key()),
                    shards: shards.heads().len() as u64,
                    ..Prefix::default()
                })
                .unwrap();
            row.prefix = prefix;
        }
        let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let close = build_close::<Sha256, _, _>(
            cache,
            context,
            &DepositBatch::empty(),
            withdrawals,
            rows,
            shard_sets,
        )
        .unwrap();
        let changed = close
            .rows
            .iter()
            .map(|row| row.account.clone())
            .collect::<BTreeSet<_>>();
        let mut closing = cache
            .leaves()
            .iter()
            .filter(|leaf| !changed.contains(&leaf.account))
            .cloned()
            .collect::<Vec<_>>();
        closing.extend(
            close
                .rows
                .iter()
                .filter(|row| row.closing.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: row.closing,
                }),
        );
        closing.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let closing = StateCache::new::<Sha256>(closing).unwrap();
        assert_eq!(closing.root(), close.roots.closing);
        (close, closing)
    }

    #[derive(Clone, Copy)]
    enum ChallengeApi {
        TypedWrapper,
        TypedSequential,
        TypedRayon,
        EncodedWrapper,
        EncodedSequential,
        EncodedRayon,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ChallengeState {
        statuses: Vec<BatchStatus<ShaDigest>>,
        invalid_from: Option<BatchId<ShaDigest>>,
        hard_fault: Option<HardFaultReason<VerifyingKey, ShaDigest>>,
        admission_fence_epoch: Option<u64>,
    }

    fn challenge_pipeline() -> (Harness, TestChallenge, BatchId<ShaDigest>) {
        let mut fixture = harness(&[10, 10, 10]);
        let (first_context, first_id) = admit_empty_epoch(&mut fixture, 0, 1, 2, 10);
        admit_empty_epoch(&mut fixture, 1, 1, 3, 10);
        let left = fork_payment(
            &first_context,
            &fixture.operator,
            &fixture.accounts[0],
            &fixture.accounts[2],
            2,
        );
        let right = fork_payment(
            &first_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[2],
            3,
        );
        let challenge = Challenge::receipt_fork(first_id, left, right);
        (fixture, challenge, first_id)
    }

    fn malformed_fork(challenge: TestChallenge) -> TestChallenge {
        let Challenge::ReceiptFork { batch, left, right } = challenge else {
            unreachable!("challenge_pipeline always constructs a receipt fork")
        };
        let wrong = SigningKey::from_seed(999);
        let left = Payment::from_parts_unchecked(
            left.send().clone(),
            SignedReceipt::sign_body_by_authority(left.receipt().body().clone(), &wrong),
        );
        let right = Payment::from_parts_unchecked(
            SignedSend::sign_body_by_authority(right.send().body().clone(), &wrong),
            right.receipt().clone(),
        );
        Challenge::ReceiptFork {
            batch,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    fn challenge_state(chain: &TestChain) -> ChallengeState {
        ChallengeState {
            statuses: chain
                .pending_batches()
                .map(|batch| batch.status.clone())
                .collect(),
            invalid_from: chain.invalid_from(),
            hard_fault: chain.hard_fault().cloned(),
            admission_fence_epoch: chain.admission_fence_epoch(),
        }
    }

    fn run_challenge_api(
        api: ChallengeApi,
        malformed: bool,
        rayon: &Rayon,
    ) -> (
        Result<Verdict, SettlementError>,
        ChallengeState,
        BatchId<ShaDigest>,
    ) {
        let (mut fixture, challenge, batch) = challenge_pipeline();
        let challenge = if malformed {
            malformed_fork(challenge)
        } else {
            challenge
        };
        let encoded = challenge.encode();
        let result = match api {
            ChallengeApi::TypedWrapper => fixture.chain.challenge(10, &challenge),
            ChallengeApi::TypedSequential => {
                fixture
                    .chain
                    .challenge_with_strategy(10, &challenge, &Sequential)
            }
            ChallengeApi::TypedRayon => {
                fixture.chain.challenge_with_strategy(10, &challenge, rayon)
            }
            ChallengeApi::EncodedWrapper => {
                fixture
                    .chain
                    .challenge_encoded(10, encoded.as_ref(), encoded.len())
            }
            ChallengeApi::EncodedSequential => fixture.chain.challenge_encoded_with_strategy(
                10,
                encoded.as_ref(),
                encoded.len(),
                &Sequential,
            ),
            ChallengeApi::EncodedRayon => fixture.chain.challenge_encoded_with_strategy(
                10,
                encoded.as_ref(),
                encoded.len(),
                rayon,
            ),
        };
        let state = challenge_state(&fixture.chain);
        (result, state, batch)
    }

    #[test]
    fn challenge_strategy_entry_points_have_identical_state_transitions() {
        let rayon = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();
        let apis = [
            ChallengeApi::TypedWrapper,
            ChallengeApi::TypedSequential,
            ChallengeApi::TypedRayon,
            ChallengeApi::EncodedWrapper,
            ChallengeApi::EncodedSequential,
            ChallengeApi::EncodedRayon,
        ];

        let mut proven_state = None;
        for api in apis {
            let (result, state, batch) = run_challenge_api(api, false, &rayon);
            assert_eq!(result.unwrap(), Verdict::Proven(ChallengeKind::ReceiptFork));
            assert_eq!(
                state.statuses,
                vec![
                    BatchStatus::Challenged(ChallengeKind::ReceiptFork),
                    BatchStatus::Invalidated(batch),
                ]
            );
            if let Some(expected) = &proven_state {
                assert_eq!(&state, expected);
            } else {
                proven_state = Some(state);
            }
        }

        let mut malformed_state = None;
        let mut malformed_result = None;
        for api in apis {
            let (result, state, _) = run_challenge_api(api, true, &rayon);
            assert!(matches!(
                &result,
                Err(SettlementError::Challenge(ChallengeError::Payment(
                    PaymentError::InvalidOperatorSignature
                )))
            ));
            assert!(
                state
                    .statuses
                    .iter()
                    .all(|status| matches!(status, BatchStatus::Pending))
            );
            assert_eq!(state.invalid_from, None);
            assert_eq!(state.hard_fault, None);
            let rendered = format!("{result:?}");
            if let Some(expected) = &malformed_result {
                assert_eq!(&rendered, expected);
            } else {
                malformed_result = Some(rendered);
            }
            if let Some(expected) = &malformed_state {
                assert_eq!(&state, expected);
            } else {
                malformed_state = Some(state);
            }
        }
    }

    #[test]
    fn happy_two_slot_pipeline_and_inclusive_deadlines() {
        let mut fixture = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            4,
        );
        let first = empty_close(&fixture.cache, &first_context);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            2,
            first_context,
            deposits.clone(),
            withdrawals.clone(),
            &first,
        );
        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &deposits,
            &withdrawals,
            3,
            5,
        );
        let second = empty_close(&fixture.cache, &second_context);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            3,
            second_context,
            deposits.clone(),
            withdrawals.clone(),
            &second,
        );
        assert_eq!(fixture.chain.pending_epoch_count(), 2);
        assert!(matches!(
            fixture.chain.finalize(4),
            Err(SettlementError::ChallengeWindowOpen)
        ));
        assert_eq!(fixture.chain.finalize(5).unwrap().epoch, 0);
        assert!(matches!(
            fixture.chain.finalize(5),
            Err(SettlementError::ChallengeWindowOpen)
        ));
        assert_eq!(fixture.chain.finalize(6).unwrap().epoch, 1);

        let registered = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            2,
            &fixture.cache,
            &deposits,
            &withdrawals,
            7,
            8,
        );
        fixture
            .chain
            .register(7, registered, deposits, withdrawals)
            .unwrap();
        assert!(matches!(
            fixture.chain.expire_unadmitted(7),
            Err(SettlementError::AdmissionWindowOpen)
        ));
        fixture.chain.expire_unadmitted(8).unwrap();
    }

    #[test]
    fn largest_resolvable_deadlines_retain_inclusive_boundaries() {
        let mut admitted = harness(&[10]);
        admit_empty_epoch(&mut admitted, 0, u64::MAX - 2, u64::MAX - 2, u64::MAX - 1);
        assert!(matches!(
            admitted.chain.finalize(u64::MAX - 1),
            Err(SettlementError::ChallengeWindowOpen)
        ));
        assert_eq!(admitted.chain.finalize(u64::MAX).unwrap().epoch, 0);

        let mut unadmitted = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            unadmitted.deployment,
            &unadmitted.operator,
            unadmitted.committee,
            0,
            &unadmitted.cache,
            &deposits,
            &withdrawals,
            u64::MAX - 2,
            u64::MAX - 1,
        );
        unadmitted
            .chain
            .register(u64::MAX - 2, close_context, deposits, withdrawals)
            .unwrap();
        assert!(matches!(
            unadmitted.chain.expire_unadmitted(u64::MAX - 2),
            Err(SettlementError::AdmissionWindowOpen)
        ));
        unadmitted.chain.expire_unadmitted(u64::MAX - 1).unwrap();
    }

    #[test]
    fn settlement_binds_a_root_independent_epoch_to_its_head() {
        let mut fixture = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            4,
        );
        let epoch = context.epoch_context().clone();

        fixture
            .chain
            .register_epoch(0, epoch, deposits, withdrawals)
            .unwrap();

        assert_eq!(
            fixture
                .chain
                .registered
                .as_ref()
                .unwrap()
                .context
                .opening_root(),
            &fixture.cache.root()
        );
    }

    #[test]
    fn registration_rejects_another_operator_for_the_same_deployment() {
        let mut fixture = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let other_operator = SigningKey::from_seed(999);
        let close_context = context(
            fixture.deployment,
            &other_operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            4,
        );

        assert!(matches!(
            fixture
                .chain
                .register(0, close_context, deposits, withdrawals),
            Err(SettlementError::OperatorMismatch)
        ));
    }

    #[test]
    fn safety_openings_are_exact_and_timeout_observation_is_permanent() {
        let mut fixture = harness(&[10, 7]);
        let account = &fixture.accounts[0];
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"safety-deposit"]),
                account.public_key(),
                2,
            )
            .unwrap();
        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            4,
        );
        let (close, closing) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        let opening = fixture.cache.opening(&account.public_key()).unwrap();
        let closing_opening = closing.opening(&account.public_key()).unwrap();
        let request = withdrawal(
            fixture.deployment,
            fixture.chain.current_state_root(),
            account,
            b"eligible",
            amount_action(4),
            5,
        );
        assert!(matches!(
            fixture
                .chain
                .queue_withdrawal(1, request.clone(), &[], |_| true),
            Err(SettlementError::WithdrawalOpeningCount)
        ));
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                1,
                request.clone(),
                &[closing_opening.clone(), opening.clone()],
                |_| true,
            ),
            Err(SettlementError::Commitment(_))
        ));
        let other = fixture
            .cache
            .opening(&fixture.accounts[1].public_key())
            .unwrap();
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                1,
                request.clone(),
                &[other, closing_opening.clone()],
                |_| true,
            ),
            Err(SettlementError::WithdrawalOpening)
        ));
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                1,
                request.clone(),
                &[opening.clone(), closing_opening.clone()],
                |_| false,
            ),
            Err(SettlementError::IneligibleDestination)
        ));
        let too_large = withdrawal(
            fixture.deployment,
            fixture.chain.current_state_root(),
            account,
            b"eligible",
            amount_action(11),
            5,
        );
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                1,
                too_large,
                &[opening.clone(), closing_opening.clone()],
                |_| true,
            ),
            Err(SettlementError::WithdrawalBalance)
        ));
        let close = withdrawal(
            fixture.deployment,
            fixture.chain.current_state_root(),
            account,
            b"eligible",
            WithdrawalAction::Close,
            5,
        );
        assert_eq!(close.body().action(), &WithdrawalAction::Close);
        fixture
            .chain
            .queue_withdrawal(1, request, &[opening, closing_opening], |_| true)
            .unwrap();
        let second = withdrawal(
            fixture.deployment,
            fixture.chain.current_state_root(),
            account,
            b"other",
            amount_action(3),
            6,
        );
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                1,
                second,
                &[
                    fixture.cache.opening(&account.public_key()).unwrap(),
                    closing.opening(&account.public_key()).unwrap(),
                ],
                |_| true,
            ),
            Err(SettlementError::DuplicateWithdrawal)
        ));

        assert!(matches!(
            fixture.chain.record_deposit(
                5,
                Sha256::hash(&[b"must-not-land"]),
                fixture.accounts[1].public_key(),
                1,
            ),
            Err(SettlementError::OperatorHardFaulted)
        ));
        assert!(matches!(
            fixture.chain.hard_fault(),
            Some(HardFaultReason::ExpiredWithdrawal { expired_at: 5, .. })
        ));
        assert_eq!(fixture.chain.admission_fence_epoch(), Some(1));
    }

    #[test]
    fn intake_limits_notice_and_clean_release_replay_are_exact() {
        let invalid_notice = SettlementConfig::new(
            NonZeroUsize::new(3).unwrap(),
            NonZeroU64::new(5).unwrap(),
            NonZeroU64::new(4).unwrap(),
            NonZeroUsize::new(1_024).unwrap(),
            4,
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(2).unwrap(),
        );
        let invalid_fixture = harness(&[10]);
        assert!(matches!(
            SettlementChain::<Sha256, VerifyingKey>::new(
                invalid_fixture.deployment,
                invalid_fixture.operator.public_key(),
                committee(202),
                &invalid_fixture.cache,
                0,
                invalid_notice,
            ),
            Err(SettlementError::WithdrawalNoticeOrder)
        ));

        let settlement_config = SettlementConfig::new(
            NonZeroUsize::new(3).unwrap(),
            NonZeroU64::new(4).unwrap(),
            NonZeroU64::new(4).unwrap(),
            NonZeroUsize::new(1_024).unwrap(),
            4,
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(2).unwrap(),
        );
        let mut fixture = harness_with_config(&[10, 10], settlement_config);
        let account = &fixture.accounts[0];
        let opening = fixture.cache.opening(&account.public_key()).unwrap();
        let oversized = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"12345",
            amount_action(2),
            9,
        );
        assert!(matches!(
            fixture
                .chain
                .queue_withdrawal(5, oversized, core::slice::from_ref(&opening), |_| true),
            Err(SettlementError::DestinationTooLarge)
        ));
        assert_eq!(
            fixture.chain.pending_withdrawals(),
            WithdrawalBatch::empty()
        );
        assert_eq!(
            fixture
                .chain
                .pending_withdrawal_deadline(&account.public_key()),
            None
        );

        let too_soon = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"1234",
            amount_action(2),
            8,
        );
        assert!(matches!(
            fixture
                .chain
                .queue_withdrawal(5, too_soon, core::slice::from_ref(&opening), |_| true),
            Err(SettlementError::WithdrawalDeadlineTooSoon)
        ));
        let too_late = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"1234",
            amount_action(2),
            10,
        );
        assert!(matches!(
            fixture
                .chain
                .queue_withdrawal(5, too_late, core::slice::from_ref(&opening), |_| true,),
            Err(SettlementError::WithdrawalDeadlineTooLate)
        ));
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"1234",
            amount_action(2),
            9,
        );
        fixture
            .chain
            .queue_withdrawal(5, request.clone(), &[opening], |_| true)
            .unwrap();
        assert_eq!(
            fixture
                .chain
                .pending_withdrawal_deadline(&account.public_key()),
            Some(9)
        );

        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            6,
            7,
        );
        let (close, closing) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &account.public_key(),
            &Sequential,
        )
        .unwrap();
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            6,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        assert_eq!(fixture.chain.finalize(8).unwrap().withdrawal_total, 2);
        assert_eq!(
            fixture.chain.claim_withdrawal(batch_id, &claim).unwrap(),
            WithdrawalRelease {
                request: request.clone(),
                amount: 2,
            }
        );
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claim),
            Err(SettlementError::ClaimBatchUnavailable | SettlementError::ClaimAlreadyConsumed)
        ));
        assert_eq!(
            fixture
                .chain
                .pending_withdrawal_deadline(&account.public_key()),
            None
        );
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                8,
                request.clone(),
                &[closing.opening(&account.public_key()).unwrap()],
                |_| true,
            ),
            Err(SettlementError::DuplicateWithdrawalAuthorization)
        ));
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                9,
                request,
                &[closing.opening(&account.public_key()).unwrap()],
                |_| true,
            ),
            Err(SettlementError::Boundary(BoundaryError::WrongContext))
        ));

        let deposit_account = fixture.accounts[1].public_key();
        let first_deposit_id = Sha256::hash(&[b"capacity-one"]);
        fixture
            .chain
            .record_deposit(9, first_deposit_id, deposit_account.clone(), 1)
            .unwrap();
        fixture
            .chain
            .record_deposit(
                9,
                Sha256::hash(&[b"capacity-two"]),
                deposit_account.clone(),
                1,
            )
            .unwrap();
        assert!(matches!(
            fixture.chain.record_deposit(
                9,
                Sha256::hash(&[b"capacity-three"]),
                deposit_account.clone(),
                1,
            ),
            Err(SettlementError::DepositCapacity)
        ));
        assert_eq!(fixture.chain.pending_deposits().total(), 2);
        assert_eq!(fixture.chain.custody_balance(), 20);

        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &closing,
            &deposits,
            &withdrawals,
            10,
            11,
        );
        let (close, _) = boundary_close(&closing, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            10,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        fixture.chain.finalize(12).unwrap();
        assert!(matches!(
            fixture
                .chain
                .record_deposit(12, first_deposit_id, deposit_account, 1),
            Err(SettlementError::DuplicateDeposit)
        ));
        assert_eq!(fixture.chain.pending_deposits(), DepositBatch::empty());
        assert_eq!(fixture.chain.custody_balance(), 20);
    }

    #[test]
    fn absent_account_deposits_are_staged_atomically() {
        let mut deposits = harness(&[10, 10]);
        let zero_id = Sha256::hash(&[b"zero-then-valid"]);
        let first_account = deposits.accounts[0].public_key();
        assert!(matches!(
            deposits
                .chain
                .record_deposit(0, zero_id, first_account.clone(), 0),
            Err(SettlementError::ZeroDeposit)
        ));
        deposits
            .chain
            .record_deposit(0, zero_id, first_account, 1)
            .unwrap();

        let unknown_id = Sha256::hash(&[b"unknown-then-valid"]);
        let unknown_account = SigningKey::from_seed(999).public_key();
        deposits
            .chain
            .record_deposit(0, unknown_id, unknown_account.clone(), 1)
            .unwrap();
        assert!(matches!(
            deposits
                .chain
                .record_deposit(0, unknown_id, deposits.accounts[1].public_key(), 1,),
            Err(SettlementError::DuplicateDeposit)
        ));
        assert_eq!(deposits.chain.pending_deposits().total(), 2);
        assert!(
            deposits
                .chain
                .pending_deposits()
                .records()
                .iter()
                .any(|record| record.account() == &unknown_account)
        );
        assert_eq!(deposits.chain.custody_balance(), 22);
    }

    #[test]
    fn deposit_creates_account_and_close_removes_it() {
        let mut fixture = harness(&[]);
        let account = SigningKey::from_seed(999);
        let public_key = account.public_key();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"create-account-deposit"]),
                public_key.clone(),
                9,
            )
            .unwrap();

        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let create_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (create, created) =
            boundary_close(&fixture.cache, &create_context, &deposits, &withdrawals);
        assert_eq!(created.leaves().len(), 1);
        assert_eq!(created.leaves()[0].account, public_key);
        assert_eq!(created.leaves()[0].state.balance, 9);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            create_context,
            deposits,
            withdrawals,
            &create,
        );
        fixture.chain.finalize(3).unwrap();
        assert_eq!(fixture.chain.current_state_root(), created.root());

        let request = withdrawal(
            fixture.deployment,
            created.root(),
            &account,
            b"destroy-account-destination",
            WithdrawalAction::Close,
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                3,
                request.clone(),
                &[created.opening(&public_key).unwrap()],
                |_| true,
            )
            .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let destroy_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &created,
            &deposits,
            &withdrawals,
            4,
            5,
        );
        let (destroy, destroyed) =
            boundary_close(&created, &destroy_context, &deposits, &withdrawals);
        assert!(destroyed.leaves().is_empty());
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &destroy,
            &withdrawals,
            &public_key,
            &Sequential,
        )
        .unwrap();
        assert_eq!(
            claim
                .verify::<Sha256>(
                    destroy_context.deployment(),
                    destroy_context.withdrawal_root(),
                    &destroy.roots.change,
                )
                .unwrap(),
            9
        );
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            4,
            destroy_context,
            deposits,
            withdrawals,
            &destroy,
        );
        let finalized = fixture.chain.finalize(6).unwrap();
        assert_eq!(finalized.withdrawal_total, 9);
        assert_eq!(fixture.chain.claimable_balance(), 9);
        assert_eq!(
            fixture.chain.claim_withdrawal(batch_id, &claim).unwrap(),
            WithdrawalRelease { request, amount: 9 }
        );
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claim),
            Err(SettlementError::ClaimBatchUnavailable | SettlementError::ClaimAlreadyConsumed)
        ));
        assert_eq!(fixture.chain.current_state_root(), destroyed.root());
        assert_eq!(fixture.chain.custody_balance(), 0);
    }

    #[test]
    fn external_send_releases_only_after_clean_finalization() {
        let mut fixture = harness(&[100]);
        let payer = &fixture.accounts[0];
        let recipient = SigningKey::from_seed(1_001);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (close, closing) = external_payout_close(
            &fixture.cache,
            &close_context,
            &fixture.operator,
            payer,
            &recipient,
            20,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        assert_eq!(closing.liability(), 80);

        assert_eq!(fixture.chain.custody_balance(), 100);
        assert!(matches!(
            fixture.chain.finalize(2),
            Err(SettlementError::ChallengeWindowOpen)
        ));
        assert_eq!(fixture.chain.custody_balance(), 100);

        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 0);
        assert_eq!(finalized.payout_total, 20);
        assert_eq!(finalized.custody_balance, 80);
        assert_eq!(fixture.chain.custody_balance(), 80);
    }

    #[test]
    fn finalized_external_send_is_reserved_and_claimed_once() {
        let mut fixture = harness(&[100]);
        let payer = &fixture.accounts[0];
        let recipient = SigningKey::from_seed(1_003);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (close, _) = external_payout_close(
            &fixture.cache,
            &close_context,
            &fixture.operator,
            payer,
            &recipient,
            20,
        );
        let claim = assemble_external_payout_claim::<Sha256, _, _>(
            &close,
            &recipient.public_key(),
            &Sequential,
        )
        .unwrap();
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );

        assert!(matches!(
            fixture.chain.claim_external_payout(batch_id, &claim),
            Err(SettlementError::ClaimBatchUnavailable)
        ));
        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.payout_total, 20);
        assert_eq!(finalized.withdrawal_total, 0);
        assert_eq!(fixture.chain.claimable_balance(), 20);

        let release = fixture
            .chain
            .claim_external_payout(batch_id, &claim)
            .unwrap();
        assert_eq!(release.recipient, recipient.public_key());
        assert_eq!(release.amount, 20);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(matches!(
            fixture.chain.claim_external_payout(batch_id, &claim),
            Err(SettlementError::ClaimBatchUnavailable | SettlementError::ClaimAlreadyConsumed)
        ));
    }

    #[test]
    fn close_withdrawal_credit_cannot_consume_an_external_payout_reserve() {
        let mut fixture = harness(&[100]);
        let payer = &fixture.accounts[0];
        let recipient = SigningKey::from_seed(1_005);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (mut close, _) = external_payout_close(
            &fixture.cache,
            &close_context,
            &fixture.operator,
            payer,
            &recipient,
            7,
        );
        let position = close
            .rows
            .binary_search_by(|row| row.account.cmp(&recipient.public_key()))
            .unwrap();
        let previous_prefix = position
            .checked_sub(1)
            .map_or(Prefix::default(), |position| close.rows[position].prefix);
        close.rows[position].prefix = previous_prefix
            .checked_extend(Prefix {
                credit: 7,
                deposit: 5,
                withdrawal: 12,
                withdrawals: 1,
                shards: 1,
                ..Prefix::default()
            })
            .unwrap();

        let mut builder =
            commitment::Builder::<Sha256>::new(VectorKind::Change, close.rows.len() as u32)
                .unwrap();
        for row in &close.rows {
            builder.add_encoded(row.encode().as_ref()).unwrap();
        }
        let changes = builder.build(&Sequential).unwrap();
        let position = position as u32;
        let positions = if position == 0 {
            vec![position]
        } else {
            vec![position - 1, position]
        };
        let predecessor = position
            .checked_sub(1)
            .map(|position| close.rows[position as usize].clone());
        let change_opening = changes.multi_opening(&positions).unwrap();
        let mut encoded = BytesMut::new();
        predecessor.write(&mut encoded);
        close.rows[position as usize].write(&mut encoded);
        change_opening.write(&mut encoded);
        let mut encoded = encoded.freeze();
        let claim = ExternalPayoutClaim::<VerifyingKey, ShaDigest>::read(&mut encoded).unwrap();
        assert!(encoded.is_empty());

        let batch_id = BatchId::new(Sha256::hash(&[b"cross-reserve-payout-claim"]));
        fixture.chain.claimable_balance = 19;
        fixture.chain.claimable_batches.insert(
            batch_id,
            ClaimableBatch {
                change_root: changes.root(),
                withdrawal_root: *close_context.withdrawal_root(),
                claimed_withdrawals: BTreeSet::new(),
                claimed_payouts: BTreeSet::new(),
                withdrawal_remaining: 12,
                payout_remaining: 7,
            },
        );

        assert!(matches!(
            fixture.chain.claim_external_payout(batch_id, &claim),
            Err(SettlementError::Transition(TransitionError::PayoutClaim))
        ));
        assert_eq!(fixture.chain.claimable_balance(), 19);
        let batch = fixture.chain.claimable_batches.get(&batch_id).unwrap();
        assert_eq!(batch.withdrawal_remaining, 12);
        assert_eq!(batch.payout_remaining, 7);
        assert!(batch.claimed_payouts.is_empty());
    }

    #[test]
    fn finalized_claim_batches_are_bounded_before_state_mutation() {
        let mut settlement_config = config(2, 1);
        settlement_config.max_claimable_batches = NonZeroUsize::new(1).unwrap();
        let mut fixture = harness_with_states(&[state(100), state(100)], settlement_config);
        let recipient = SigningKey::from_seed(1_004);

        for epoch in 0..2 {
            let deposits = DepositBatch::empty();
            let withdrawals = WithdrawalBatch::empty();
            let now = 1 + epoch * 3;
            let close_context = context(
                fixture.deployment,
                &fixture.operator,
                fixture.committee,
                epoch,
                &fixture.cache,
                &deposits,
                &withdrawals,
                now,
                now + 1,
            );
            let (close, closing) = external_payout_close(
                &fixture.cache,
                &close_context,
                &fixture.operator,
                &fixture.accounts[usize::try_from(epoch).unwrap()],
                &recipient,
                1,
            );
            register_and_admit(
                &mut fixture.chain,
                &fixture.signer,
                now,
                close_context,
                deposits,
                withdrawals,
                &close,
            );

            if epoch == 0 {
                fixture.chain.finalize(now + 2).unwrap();
                fixture.cache = closing;
            } else {
                let custody = fixture.chain.custody_balance();
                let claimable = fixture.chain.claimable_balance();
                assert!(matches!(
                    fixture.chain.finalize(now + 2),
                    Err(SettlementError::ClaimableBatchCapacity)
                ));
                assert_eq!(fixture.chain.custody_balance(), custody);
                assert_eq!(fixture.chain.claimable_balance(), claimable);
                assert_eq!(fixture.chain.pending_epoch_count(), 1);
            }
        }
    }

    #[test]
    fn finalized_withdrawals_claim_out_of_order_and_drain_one_reserve() {
        let mut fixture = harness(&[10, 20]);
        let queued = fixture
            .accounts
            .iter()
            .enumerate()
            .map(|(index, account)| {
                let amount = 3 + index as u64;
                let request = withdrawal(
                    fixture.deployment,
                    fixture.cache.root(),
                    account,
                    b"withdrawal-destination",
                    amount_action(amount),
                    10,
                );
                let opening = fixture.cache.opening(&account.public_key()).unwrap();
                (account.public_key(), request, opening, amount)
            })
            .collect::<Vec<_>>();
        for (_, request, opening, _) in &queued {
            fixture
                .chain
                .queue_withdrawal(0, request.clone(), core::slice::from_ref(opening), |_| true)
                .unwrap();
        }

        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claims = queued
            .iter()
            .map(|(account, _, _, _)| {
                assemble_withdrawal_claim::<Sha256, _, _>(
                    &close,
                    &withdrawals,
                    account,
                    &Sequential,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 7);
        assert_eq!(fixture.chain.claimable_balance(), 7);

        assert_eq!(
            fixture
                .chain
                .claim_withdrawal(batch_id, &claims[1])
                .unwrap(),
            WithdrawalRelease {
                request: queued[1].1.clone(),
                amount: queued[1].3,
            }
        );
        assert_eq!(fixture.chain.claimable_balance(), queued[0].3);
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claims[1]),
            Err(SettlementError::ClaimAlreadyConsumed)
        ));
        assert_eq!(
            fixture
                .chain
                .claim_withdrawal(batch_id, &claims[0])
                .unwrap(),
            WithdrawalRelease {
                request: queued[0].1.clone(),
                amount: queued[0].3,
            }
        );
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claims[0]),
            Err(SettlementError::ClaimBatchUnavailable)
        ));
    }

    #[test]
    fn finalization_does_not_drop_each_withdrawal_destination() {
        let mut fixture = harness(&[10, 20]);
        let drops = Arc::new(AtomicUsize::new(0));
        for account in &fixture.accounts {
            let request = SignedWithdrawal::sign(
                fixture.deployment,
                fixture.cache.root().digest,
                Bytes::from_owner(DropTrackedDestination {
                    bytes: b"withdrawal-destination",
                    drops: drops.clone(),
                }),
                amount_action(1),
                10,
                account,
            );
            fixture
                .chain
                .queue_withdrawal(
                    0,
                    request,
                    &[fixture.cache.opening(&account.public_key()).unwrap()],
                    |_| true,
                )
                .unwrap();
        }

        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );

        drops.store(0, Ordering::Relaxed);
        fixture.chain.finalize(3).unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn finalized_claim_reserve_survives_descendant_hard_fault() {
        let mut fixture = harness(&[100, 10, 10]);
        let first_recipient = SigningKey::from_seed(1_004);
        let empty = DepositBatch::empty();
        let no_withdrawals = WithdrawalBatch::empty();
        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &empty,
            &no_withdrawals,
            1,
            2,
        );
        let (first, first_closing) = external_payout_close(
            &fixture.cache,
            &first_context,
            &fixture.operator,
            &fixture.accounts[0],
            &first_recipient,
            20,
        );
        let first_claim = assemble_external_payout_claim::<Sha256, _, _>(
            &first,
            &first_recipient.public_key(),
            &Sequential,
        )
        .unwrap();
        let first_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            empty.clone(),
            no_withdrawals.clone(),
            &first,
        );
        fixture.chain.finalize(3).unwrap();
        fixture.cache = first_closing;
        assert_eq!(fixture.chain.custody_balance(), 100);
        assert_eq!(fixture.chain.claimable_balance(), 20);

        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &empty,
            &no_withdrawals,
            4,
            8,
        );
        let second = empty_close(&fixture.cache, &second_context);
        let second_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            4,
            second_context.clone(),
            empty,
            no_withdrawals,
            &second,
        );
        let left = fork_payment(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[0],
            2,
        );
        let right = fork_payment(
            &second_context,
            &fixture.operator,
            &fixture.accounts[2],
            &fixture.accounts[0],
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(8, &Challenge::receipt_fork(second_id, left, right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        let settlement = fixture.chain.settle_hard_fault(&fixture.cache).unwrap();
        assert_eq!(settlement.released_custody, 100);
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(fixture.chain.claimable_balance(), 20);
        assert_eq!(
            fixture
                .chain
                .claim_external_payout(first_id, &first_claim)
                .unwrap(),
            ExternalPayout {
                recipient: first_recipient.public_key(),
                amount: 20,
            }
        );
        assert_eq!(fixture.chain.claimable_balance(), 0);
    }

    #[test]
    fn challenged_external_send_is_not_released() {
        let mut fixture = harness(&[100, 10, 10]);
        let empty = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &empty,
            &withdrawals,
            2,
            6,
        );
        let first = empty_close(&fixture.cache, &first_context);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            empty.clone(),
            withdrawals.clone(),
            &first,
        );

        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &empty,
            &withdrawals,
            3,
            8,
        );
        let recipient = SigningKey::from_seed(1_002);
        let (second, _) = external_payout_close(
            &fixture.cache,
            &second_context,
            &fixture.operator,
            &fixture.accounts[0],
            &recipient,
            20,
        );
        let second_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            2,
            second_context.clone(),
            empty,
            withdrawals,
            &second,
        );
        let left = fork_payment(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[0],
            2,
        );
        let right = fork_payment(
            &second_context,
            &fixture.operator,
            &fixture.accounts[2],
            &fixture.accounts[0],
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(8, &Challenge::receipt_fork(second_id, left, right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        let finalized = fixture.chain.finalize(8).unwrap();
        assert_eq!(finalized.payout_total, 0);
        assert_eq!(finalized.custody_balance, 120);
        let settlement = fixture.chain.settle_hard_fault(&fixture.cache).unwrap();
        assert_eq!(settlement.released_custody, 120);
        assert!(settlement.payouts.iter().all(|payout| match payout {
            FaultPayout::QueuedWithdrawal(_) => true,
            FaultPayout::ResidualSettlement { account, .. } => {
                account != &recipient.public_key()
            }
        }));
    }

    #[test]
    fn mixed_request_local_roots_survive_front_finalization() {
        let mut fixture = harness(&[10, 10]);
        let first_account = &fixture.accounts[0];
        let second_account = &fixture.accounts[1];
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"front-deposit"]),
                second_account.public_key(),
                1,
            )
            .unwrap();
        let deposits = fixture.chain.pending_deposits();
        let empty_withdrawals = WithdrawalBatch::empty();
        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &empty_withdrawals,
            2,
            3,
        );
        let (front, next_cache) = boundary_close(
            &fixture.cache,
            &first_context,
            &deposits,
            &empty_withdrawals,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            deposits,
            empty_withdrawals,
            &front,
        );

        let first_request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            first_account,
            b"first-root",
            amount_action(2),
            100,
        );
        fixture
            .chain
            .queue_withdrawal(
                1,
                first_request.clone(),
                &[
                    fixture.cache.opening(&first_account.public_key()).unwrap(),
                    next_cache.opening(&first_account.public_key()).unwrap(),
                ],
                |_| true,
            )
            .unwrap();
        fixture.chain.finalize(4).unwrap();
        assert_ne!(fixture.cache.root(), fixture.chain.current_state_root());

        let second_request = withdrawal(
            fixture.deployment,
            next_cache.root(),
            second_account,
            b"second-root",
            amount_action(3),
            100,
        );
        fixture
            .chain
            .queue_withdrawal(
                4,
                second_request.clone(),
                &[next_cache.opening(&second_account.public_key()).unwrap()],
                |_| true,
            )
            .unwrap();
        let mixed = fixture.chain.pending_withdrawals();
        assert_eq!(mixed.len(), 2);
        assert_ne!(
            first_request.body().state_root(),
            second_request.body().state_root()
        );

        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &next_cache,
            &DepositBatch::empty(),
            &mixed,
            6,
            7,
        );
        let (close, _) =
            boundary_close(&next_cache, &second_context, &DepositBatch::empty(), &mixed);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            4,
            second_context,
            DepositBatch::empty(),
            mixed,
            &close,
        );
        assert_eq!(fixture.chain.pending_epoch_count(), 1);
    }

    #[test]
    fn successful_challenge_cuts_descendants_but_preserves_prefix() {
        let mut fixture = harness(&[10, 10, 10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            6,
        );
        let first = empty_close(&fixture.cache, &first_context);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            deposits.clone(),
            withdrawals.clone(),
            &first,
        );
        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &deposits,
            &withdrawals,
            3,
            8,
        );
        let second = empty_close(&fixture.cache, &second_context);
        let second_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            second_context.clone(),
            deposits,
            withdrawals,
            &second,
        );
        let left = fork_payment(
            &second_context,
            &fixture.operator,
            &fixture.accounts[0],
            &fixture.accounts[2],
            2,
        );
        let right = fork_payment(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[2],
            3,
        );
        let challenge = Challenge::receipt_fork(second_id, left, right);
        assert_eq!(
            fixture.chain.challenge(8, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );
        let statuses = fixture
            .chain
            .pending_batches()
            .map(|batch| batch.status.clone())
            .collect::<Vec<_>>();
        assert!(matches!(statuses[0], BatchStatus::Pending));
        assert!(matches!(
            statuses[1],
            BatchStatus::Challenged(ChallengeKind::ReceiptFork)
        ));
        assert_eq!(fixture.chain.invalid_from(), Some(second_id));
        assert_eq!(fixture.chain.finalize(8).unwrap().epoch, 0);
        assert!(matches!(
            fixture.chain.finalize(9),
            Err(SettlementError::BatchInvalidated)
        ));
    }

    #[test]
    fn middle_challenge_refunds_the_complete_invalid_suffix() {
        let mut fixture = harness(&[10, 20, 30]);
        let empty_deposits = DepositBatch::empty();
        let empty_withdrawals = WithdrawalBatch::empty();
        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &empty_deposits,
            &empty_withdrawals,
            2,
            6,
        );
        let first = empty_close(&fixture.cache, &first_context);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            empty_deposits,
            empty_withdrawals.clone(),
            &first,
        );

        let middle_account = fixture.accounts[0].public_key();
        fixture
            .chain
            .record_deposit(
                1,
                Sha256::hash(&[b"middle-suffix-deposit"]),
                middle_account.clone(),
                3,
            )
            .unwrap();
        let middle_deposits = fixture.chain.pending_deposits();
        let middle_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &middle_deposits,
            &empty_withdrawals,
            3,
            8,
        );
        let (middle, middle_cache) = boundary_close(
            &fixture.cache,
            &middle_context,
            &middle_deposits,
            &empty_withdrawals,
        );
        let middle_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            2,
            middle_context.clone(),
            middle_deposits,
            empty_withdrawals.clone(),
            &middle,
        );

        let descendant_account = fixture.accounts[1].public_key();
        fixture
            .chain
            .record_deposit(
                2,
                Sha256::hash(&[b"descendant-suffix-deposit"]),
                descendant_account.clone(),
                5,
            )
            .unwrap();
        let descendant_deposits = fixture.chain.pending_deposits();
        let descendant_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            2,
            &middle_cache,
            &descendant_deposits,
            &empty_withdrawals,
            4,
            10,
        );
        let (descendant, _) = boundary_close(
            &middle_cache,
            &descendant_context,
            &descendant_deposits,
            &empty_withdrawals,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            3,
            descendant_context,
            descendant_deposits,
            empty_withdrawals,
            &descendant,
        );

        let left = fork_payment(
            &middle_context,
            &fixture.operator,
            &fixture.accounts[0],
            &fixture.accounts[2],
            2,
        );
        let right = fork_payment(
            &middle_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[2],
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(8, &Challenge::receipt_fork(middle_id, left, right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );
        assert_eq!(
            fixture
                .chain
                .pending_batches()
                .map(|batch| batch.status.clone())
                .collect::<Vec<_>>(),
            vec![
                BatchStatus::Pending,
                BatchStatus::Challenged(ChallengeKind::ReceiptFork),
                BatchStatus::Invalidated(middle_id),
            ]
        );
        assert_eq!(fixture.chain.custody_balance(), 68);
        assert!(matches!(
            fixture.chain.settle_hard_fault(&fixture.cache),
            Err(SettlementError::PreFaultBatchPending)
        ));

        assert_eq!(fixture.chain.finalize(8).unwrap().epoch, 0);
        let settlement = fixture.chain.settle_hard_fault(&fixture.cache).unwrap();
        let residuals = settlement
            .payouts
            .iter()
            .filter_map(|payout| match payout {
                FaultPayout::ResidualSettlement { account, amount } => {
                    Some((account.clone(), *amount))
                }
                FaultPayout::QueuedWithdrawal(_) => None,
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            residuals,
            BTreeMap::from([
                (middle_account, 13),
                (descendant_account, 25),
                (fixture.accounts[2].public_key(), 30),
            ])
        );
        assert_eq!(settlement.payouts.len(), 3);
        assert_eq!(settlement.released_custody, 68);
        assert_eq!(settlement.invalid_from, Some(middle_id));
        assert!(matches!(
            settlement.reason,
            HardFaultReason::ProvenChallenge {
                batch_id,
                kind: ChallengeKind::ReceiptFork,
            } if batch_id == middle_id
        ));
        assert_eq!(settlement.terminal_state.liability(), 0);
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(fixture.chain.pending_epoch_count(), 0);
    }

    #[test]
    fn timeout_fault_keeps_its_fence_while_a_later_challenge_shortens_the_prefix() {
        let mut fixture = harness(&[10, 10, 10]);
        admit_empty_epoch(&mut fixture, 0, 1, 1, 4);
        admit_empty_epoch(&mut fixture, 1, 2, 2, 6);
        let (third_context, third_id) = admit_empty_epoch(&mut fixture, 2, 3, 3, 8);

        let withdrawing = &fixture.accounts[0];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            withdrawing,
            b"timeout-cut",
            amount_action(4),
            5,
        );
        let opening = fixture.cache.opening(&withdrawing.public_key()).unwrap();
        fixture
            .chain
            .queue_withdrawal(
                3,
                request,
                &[opening.clone(), opening.clone(), opening.clone(), opening],
                |_| true,
            )
            .unwrap();
        assert!(matches!(
            fixture.chain.fault_expired_withdrawal(4),
            Err(SettlementError::WithdrawalDeadlineNotReached)
        ));
        let first_reason = fixture.chain.fault_expired_withdrawal(5).unwrap();
        assert!(matches!(
            &first_reason,
            HardFaultReason::ExpiredWithdrawal {
                account,
                expired_at: 5,
            } if account == &withdrawing.public_key()
        ));
        assert_eq!(fixture.chain.admission_fence_epoch(), Some(3));
        assert_eq!(fixture.chain.invalid_from(), None);

        let left = fork_payment(
            &third_context,
            &fixture.operator,
            &fixture.accounts[0],
            &fixture.accounts[2],
            2,
        );
        let right = fork_payment(
            &third_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[2],
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(8, &Challenge::receipt_fork(third_id, left, right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );
        assert_eq!(fixture.chain.hard_fault(), Some(&first_reason));
        assert_eq!(fixture.chain.admission_fence_epoch(), Some(3));
        assert_eq!(fixture.chain.invalid_from(), Some(third_id));
        assert_eq!(
            fixture
                .chain
                .pending_batches()
                .map(|batch| batch.status.clone())
                .collect::<Vec<_>>(),
            vec![
                BatchStatus::Pending,
                BatchStatus::Pending,
                BatchStatus::Challenged(ChallengeKind::ReceiptFork),
            ]
        );
        assert!(matches!(
            fixture.chain.settle_hard_fault(&fixture.cache),
            Err(SettlementError::PreFaultBatchPending)
        ));

        assert_eq!(fixture.chain.finalize(8).unwrap().epoch, 0);
        assert_eq!(fixture.chain.hard_fault(), Some(&first_reason));
        assert!(matches!(
            fixture.chain.settle_hard_fault(&fixture.cache),
            Err(SettlementError::PreFaultBatchPending)
        ));
        assert_eq!(fixture.chain.finalize(8).unwrap().epoch, 1);
        assert_eq!(fixture.chain.hard_fault(), Some(&first_reason));

        let settlement = fixture.chain.settle_hard_fault(&fixture.cache).unwrap();
        assert_eq!(settlement.reason, first_reason);
        assert_eq!(settlement.admission_fence_epoch, 3);
        assert_eq!(settlement.invalid_from, Some(third_id));
        assert_eq!(settlement.released_custody, 30);
        assert_eq!(fixture.chain.custody_balance(), 0);
    }

    #[test]
    fn custody_tracks_all_unfinalized_deposits_exactly_once() {
        let mut fixture = harness(&[10]);
        let account = fixture.accounts[0].public_key();
        let first_id = Sha256::hash(&[b"first-deposit-id"]);
        fixture
            .chain
            .record_deposit(0, first_id, account.clone(), 5)
            .unwrap();
        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            3,
        );
        let (close, closing) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        fixture
            .chain
            .record_deposit(1, Sha256::hash(&[b"second-deposit-id"]), account.clone(), 3)
            .unwrap();
        assert_eq!(fixture.chain.custody_balance(), 18);
        assert_eq!(fixture.chain.pending_deposits().total(), 3);
        assert!(matches!(
            fixture.chain.record_deposit(1, first_id, account, 1),
            Err(SettlementError::DuplicateDeposit)
        ));
        fixture.chain.finalize(4).unwrap();
        assert_eq!(fixture.chain.current_state_root(), closing.root());
        assert_eq!(fixture.chain.custody_balance(), 18);
        assert_eq!(fixture.chain.pending_deposits().total(), 3);
    }

    #[test]
    fn admission_rejects_a_closing_state_above_terminal_capacity() {
        let settlement_config = SettlementConfig::new(
            NonZeroUsize::new(3).unwrap(),
            NonZeroU64::new(2).unwrap(),
            NonZeroU64::new(1_000).unwrap(),
            NonZeroUsize::new(1).unwrap(),
            1_024,
            NonZeroUsize::new(1_024).unwrap(),
            NonZeroUsize::new(1_024).unwrap(),
        );
        let mut fixture = harness_with_config(&[10], settlement_config);
        let created = SigningKey::from_seed(999).public_key();
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"closing-state-capacity"]), created, 1)
            .unwrap();
        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            3,
        );
        let (close, closing) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        assert_eq!(closing.leaves().len(), 2);
        let certificate = certificate(
            &fixture.signer,
            &close_context,
            &deposits,
            &withdrawals,
            &close,
        );
        let terminal_proof = assemble_terminal_proof::<Sha256, _, _>(
            &close_context,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();
        fixture
            .chain
            .register(1, close_context, deposits, withdrawals)
            .unwrap();

        assert!(matches!(
            fixture
                .chain
                .admit(1, close.header, close.roots, terminal_proof, certificate),
            Err(SettlementError::StateCapacity)
        ));
        assert_eq!(fixture.chain.pending_epoch_count(), 0);
        assert_eq!(fixture.chain.pending_deposits().total(), 1);
        assert_eq!(fixture.chain.custody_balance(), 11);
        fixture.chain.expire_unadmitted(3).unwrap();
    }

    #[test]
    fn amountless_close_reserves_the_epoch_tail_balance() {
        let mut fixture = harness(&[10]);
        let account = &fixture.accounts[0];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"close-destination",
            WithdrawalAction::Close,
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &[fixture.cache.opening(&account.public_key()).unwrap()],
                |_| true,
            )
            .unwrap();

        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (close, closing) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        assert_eq!(request.body().action(), &WithdrawalAction::Close);
        assert_eq!(close.rows.last().unwrap().prefix.withdrawal, 10);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );

        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 10);
        assert_eq!(finalized.custody_balance, 0);
        assert_eq!(fixture.chain.current_state_root(), closing.root());
        assert!(closing.leaves().is_empty());
    }

    #[test]
    fn zero_tail_close_finalizes_without_a_claim_reserve() {
        let mut fixture = harness(&[10, 5]);
        let payer = &fixture.accounts[0];
        let recipient = &fixture.accounts[1];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            payer,
            b"zero-tail-close",
            WithdrawalAction::Close,
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request,
                &[fixture.cache.opening(&payer.public_key()).unwrap()],
                |_| true,
            )
            .unwrap();

        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (close, closing) = internal_payment_and_close(
            &fixture.cache,
            &close_context,
            &fixture.operator,
            payer,
            recipient,
            &withdrawals,
            10,
        );
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &payer.public_key(),
            &Sequential,
        )
        .unwrap();
        assert_eq!(
            claim
                .verify::<Sha256>(
                    close_context.deployment(),
                    close_context.withdrawal_root(),
                    &close.roots.change,
                )
                .unwrap(),
            0
        );
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );

        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 0);
        assert_eq!(finalized.payout_total, 0);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert_eq!(fixture.chain.current_state_root(), closing.root());
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claim),
            Err(SettlementError::ClaimBatchUnavailable)
        ));
    }

    #[test]
    fn deposit_after_close_remains_residual_during_timeout_exit() {
        let mut fixture = harness(&[10]);
        let account = &fixture.accounts[0];
        let public_key = account.public_key();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"timeout-exit-destination",
            WithdrawalAction::Close,
            2,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &[fixture.cache.opening(&public_key).unwrap()],
                |_| true,
            )
            .unwrap();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"deposit-after-timeout-exit"]),
                public_key.clone(),
                7,
            )
            .unwrap();

        assert_eq!(fixture.chain.pending_deposits().total(), 7);
        assert_eq!(fixture.chain.custody_balance(), 17);
        fixture.chain.fault_expired_withdrawal(2).unwrap();

        let settlement = fixture.chain.settle_hard_fault(&fixture.cache).unwrap();
        assert_eq!(
            settlement.payouts,
            vec![
                FaultPayout::QueuedWithdrawal(WithdrawalRelease {
                    request,
                    amount: 10,
                }),
                FaultPayout::ResidualSettlement {
                    account: public_key,
                    amount: 7,
                },
            ]
        );
        assert_eq!(settlement.released_custody, 17);
    }

    #[test]
    fn staged_deposit_and_close_compose_in_either_intake_order() {
        for deposit_first in [false, true] {
            let mut fixture = harness(&[10]);
            let account = &fixture.accounts[0];
            let public_key = account.public_key();
            let request = withdrawal(
                fixture.deployment,
                fixture.cache.root(),
                account,
                b"deposit-close-destination",
                WithdrawalAction::Close,
                10,
            );
            let deposit_id = Sha256::hash(&[b"deposit-and-close", &[u8::from(deposit_first)]]);

            if deposit_first {
                fixture
                    .chain
                    .record_deposit(0, deposit_id, public_key.clone(), 7)
                    .unwrap();
            }
            fixture
                .chain
                .queue_withdrawal(
                    0,
                    request.clone(),
                    &[fixture.cache.opening(&public_key).unwrap()],
                    |_| true,
                )
                .unwrap();
            if !deposit_first {
                fixture
                    .chain
                    .record_deposit(0, deposit_id, public_key, 7)
                    .unwrap();
            }

            let deposits = fixture.chain.pending_deposits();
            let withdrawals = fixture.chain.pending_withdrawals();
            let close_context = context(
                fixture.deployment,
                &fixture.operator,
                fixture.committee,
                0,
                &fixture.cache,
                &deposits,
                &withdrawals,
                1,
                2,
            );
            let (close, closing) =
                boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
            assert_eq!(close.rows.last().unwrap().prefix.withdrawal, 17);
            register_and_admit(
                &mut fixture.chain,
                &fixture.signer,
                1,
                close_context,
                deposits,
                withdrawals,
                &close,
            );

            let finalized = fixture.chain.finalize(3).unwrap();
            assert_eq!(finalized.withdrawal_total, 17);
            assert_eq!(finalized.custody_balance, 0);
            assert_eq!(fixture.chain.current_state_root(), closing.root());
            assert!(closing.leaves().is_empty());
        }
    }

    #[test]
    fn equal_ordinary_boundary_prioritizes_exit_and_defers_deposit() {
        let mut fixture = harness(&[10]);
        let account = &fixture.accounts[0];
        let public_key = account.public_key();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"equal-ordinary-deposit"]),
                public_key.clone(),
                4,
            )
            .unwrap();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"equal-ordinary-withdrawal",
            amount_action(4),
            100,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &[fixture.cache.opening(&public_key).unwrap()],
                |_| true,
            )
            .unwrap();

        let first_deposits = fixture.chain.pending_deposits();
        let first_withdrawals = fixture.chain.pending_withdrawals();
        assert_eq!(first_deposits, DepositBatch::empty());
        assert_eq!(
            first_withdrawals,
            WithdrawalBatch::new(vec![request]).unwrap()
        );
        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &first_deposits,
            &first_withdrawals,
            1,
            2,
        );
        let (first_close, first_closing) = boundary_close(
            &fixture.cache,
            &first_context,
            &first_deposits,
            &first_withdrawals,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            first_deposits,
            first_withdrawals,
            &first_close,
        );

        let first_finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(first_finalized.withdrawal_total, 4);
        assert_eq!(first_finalized.custody_balance, 10);
        assert_eq!(first_closing.leaves()[0].state.balance, 6);
        assert_eq!(fixture.chain.pending_deposits().total(), 4);

        let second_deposits = fixture.chain.pending_deposits();
        let second_withdrawals = fixture.chain.pending_withdrawals();
        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &first_closing,
            &second_deposits,
            &second_withdrawals,
            4,
            5,
        );
        let (second_close, second_closing) = boundary_close(
            &first_closing,
            &second_context,
            &second_deposits,
            &second_withdrawals,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            4,
            second_context,
            second_deposits,
            second_withdrawals,
            &second_close,
        );

        let second_finalized = fixture.chain.finalize(6).unwrap();
        assert_eq!(second_finalized.withdrawal_total, 0);
        assert_eq!(second_finalized.custody_balance, 10);
        assert_eq!(second_closing.leaves()[0].state.balance, 10);
        assert_eq!(fixture.chain.pending_deposits(), DepositBatch::empty());
    }

    #[test]
    fn terminal_amountless_close_pays_the_survivor_balance_to_the_destination() {
        let mut fixture = harness(&[10]);
        let source = &fixture.accounts[0];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            source,
            b"terminal-close",
            WithdrawalAction::Close,
            2,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &[fixture.cache.opening(&source.public_key()).unwrap()],
                |_| true,
            )
            .unwrap();
        fixture.chain.fault_expired_withdrawal(2).unwrap();

        let settlement = fixture.chain.settle_hard_fault(&fixture.cache).unwrap();
        assert_eq!(request.body().action(), &WithdrawalAction::Close);
        assert_eq!(
            settlement.payouts,
            vec![FaultPayout::QueuedWithdrawal(WithdrawalRelease {
                request,
                amount: 10,
            })]
        );
        assert_eq!(settlement.released_custody, 10);
    }

    #[test]
    fn terminal_unwind_is_atomic_retryable_exact_and_permanent() {
        let mut fixture = harness(&[10, 5]);
        let source = &fixture.accounts[0];
        let deposited = SigningKey::from_seed(999);
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            source,
            b"opaque-adapter-destination",
            amount_action(4),
            3,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request,
                &[fixture.cache.opening(&source.public_key()).unwrap()],
                |destination| destination == b"opaque-adapter-destination".as_slice(),
            )
            .unwrap();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"terminal-deposit"]),
                deposited.public_key(),
                2,
            )
            .unwrap();
        assert!(matches!(
            fixture.chain.record_deposit(
                3,
                Sha256::hash(&[b"observing-call"]),
                deposited.public_key(),
                1,
            ),
            Err(SettlementError::OperatorHardFaulted)
        ));

        let mut malformed_leaves = fixture.cache.leaves().to_vec();
        malformed_leaves[0].state.balance -= 1;
        let malformed = StateCache::new::<Sha256>(malformed_leaves).unwrap();
        assert!(matches!(
            fixture.chain.settle_hard_fault(&malformed),
            Err(SettlementError::StateAncestry)
        ));
        assert!(!fixture.chain.hard_fault_is_settled());
        assert_eq!(fixture.chain.custody_balance(), 17);
        assert_eq!(fixture.chain.pending_deposits().total(), 2);
        assert_eq!(
            fixture
                .chain
                .pending_withdrawal_deadline(&source.public_key()),
            Some(3)
        );

        let settlement = fixture.chain.settle_hard_fault(&fixture.cache).unwrap();
        assert_eq!(settlement.released_custody, 17);
        assert_eq!(settlement.terminal_state.liability(), 0);
        assert!(settlement.terminal_state.leaves().is_empty());
        assert!(settlement.payouts.iter().any(|payout| matches!(
            payout,
            FaultPayout::QueuedWithdrawal(release)
                if release.request.account() == &source.public_key()
                    && release.request.body().action() == &amount_action(4)
                    && release.amount == 4
                    && release.request.body().destination()
                        == &Bytes::from_static(b"opaque-adapter-destination")
        )));
        assert!(settlement.payouts.iter().any(|payout| matches!(
            payout,
            FaultPayout::ResidualSettlement { account, amount }
                if account == &source.public_key() && *amount == 6
        )));
        assert!(settlement.payouts.iter().any(|payout| matches!(
            payout,
            FaultPayout::ResidualSettlement { account, amount }
                if account == &fixture.accounts[1].public_key() && *amount == 5
        )));
        assert!(settlement.payouts.iter().any(|payout| matches!(
            payout,
            FaultPayout::ResidualSettlement { account, amount }
                if account == &deposited.public_key() && *amount == 2
        )));
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(
            fixture.chain.current_state_root(),
            settlement.terminal_state.root()
        );
        assert!(matches!(
            fixture.chain.settle_hard_fault(&settlement.terminal_state),
            Err(SettlementError::HardFaultAlreadySettled)
        ));
        assert!(matches!(
            fixture.chain.record_deposit(
                4,
                Sha256::hash(&[b"cannot-revive"]),
                source.public_key(),
                1,
            ),
            Err(SettlementError::OperatorHardFaulted)
        ));
    }

    #[test]
    fn arithmetic_failures_do_not_mutate_state() {
        let max_harness = harness(&[u64::MAX]);
        let mut max_chain = max_harness.chain;
        let overflow_id = Sha256::hash(&[b"overflow-deposit"]);
        assert!(matches!(
            max_chain.record_deposit(0, overflow_id, max_harness.accounts[0].public_key(), 1,),
            Err(SettlementError::CustodyArithmetic)
        ));
        assert!(matches!(
            max_chain.record_deposit(0, overflow_id, max_harness.accounts[0].public_key(), 1,),
            Err(SettlementError::CustodyArithmetic)
        ));

        let mut deadline_harness = harness(&[1]);
        let deadline_request = withdrawal(
            deadline_harness.deployment,
            deadline_harness.cache.root(),
            &deadline_harness.accounts[0],
            b"deadline-overflow",
            amount_action(1),
            u64::MAX,
        );
        assert!(matches!(
            deadline_harness.chain.queue_withdrawal(
                u64::MAX,
                deadline_request,
                &[deadline_harness
                    .cache
                    .opening(&deadline_harness.accounts[0].public_key())
                    .unwrap()],
                |_| true,
            ),
            Err(SettlementError::WithdrawalDeadlineTooSoon)
        ));
        let epoch_harness = harness(&[1]);
        assert!(matches!(
            SettlementChain::<Sha256, VerifyingKey>::new(
                epoch_harness.deployment,
                epoch_harness.operator.public_key(),
                committee(202),
                &epoch_harness.cache,
                u64::MAX,
                config(1, 1),
            ),
            Err(SettlementError::EpochOverflow)
        ));
    }
}
