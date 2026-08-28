//! Bounded admission, challenge timing, custody, and terminal settlement.
//!
//! # Integration contract
//!
//! This module is a runtime-agnostic in-memory transition primitive, not a persistence or asset
//! adapter. The embedding settlement environment must commit each state mutation and its returned
//! custody effects atomically and idempotently. Every public mutation that accepts `now` first
//! observes expired liveness deadlines. That permanent fence can be the method's only state
//! change even when the requested operation returns an error. Callers must therefore provide one
//! authenticated, monotonic clock and persist mutation-on-error results.
//!
//! Queued deposits can be returned directly to their fixed accounts after a permanent fault,
//! without a surviving-state witness. Terminal settlement freezes the last finalized state root.
//! Each surviving account then consumes one authenticated opening independently. Starting
//! terminal settlement only traverses the bounded admitted pipeline to recover unfinalized
//! deposits and withdrawals. Deposit replay state is retained for the deployment lifetime.
//! Reaching its limit safely rejects new deposits.
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
        RootBundle, StateCache, TerminalProof, TransitionError, WithdrawalClaim, WithdrawalOutput,
        verify_terminal_proof_after_header,
    },
};
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};
use bytes::{Bytes, BytesMut};
use commonware_codec::{Encode, EncodeSize, RangeCfg, Read, Write};
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

/// Header, root witness, exact certificate, successor liability, and current status retained
/// for an admitted close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBatch<D: Digest> {
    /// Admitted header.
    pub header: Header<D>,
    /// Authenticated change, withdrawal-output, successor-state, and coverage roots.
    pub roots: RootBundle<D>,
    /// Exact BLS12-381 MinSig quorum certificate over `header`.
    pub certificate: bls12381::Certificate,
    /// Successor liability derived from the registered custody boundary.
    pub successor_liability: u64,
    /// Current adjudication status.
    pub status: BatchStatus<D>,
}

/// One queued deposit returned after the operator permanently faults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositRefund<P: PublicKey> {
    /// Account fixed as the refund recipient when the deposit was accepted.
    pub account: P,
    /// Aggregate queued deposit value returned to the account.
    pub amount: u64,
}

/// Result of finalizing the pipeline front.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedBatch<D: Digest> {
    /// Canonical header identifier.
    pub batch_id: BatchId<D>,
    /// Finalized epoch.
    pub epoch: u64,
    /// Newly finalized successor-state root.
    pub successor_root: VectorRoot<D>,
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
    /// A deposit remained outside an admitted close through its inclusion deadline.
    ExpiredDeposit {
        /// Deposited account.
        account: P,
        /// Inclusive deadline that was observed.
        expired_at: u64,
    },
    /// A queued withdrawal remained outstanding through its absolute deadline.
    ExpiredWithdrawal {
        /// Authorizing account.
        account: P,
        /// Inclusive deadline that was observed.
        expired_at: u64,
    },
    /// A registered epoch admitted no close through its admission deadline.
    ExpiredRegistration {
        /// Exact one-shot payment anchor that can no longer be admitted.
        anchor: D,
        /// Epoch whose one-shot payment context can no longer be admitted.
        epoch: u64,
        /// Inclusive admission deadline that was exceeded.
        expired_at: u64,
    },
}

/// Frozen claim boundary for a hard-faulted deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardFaultSettlement<P: PublicKey, D: Digest> {
    /// Fault that permanently fenced the deployment.
    pub reason: HardFaultReason<P, D>,
    /// First epoch excluded by the admission fence.
    pub admission_fence_epoch: u64,
    /// Earliest receipt-invalidated close, if any.
    pub invalid_from: Option<BatchId<D>>,
    /// Last finalized state root against which survivor claims authenticate.
    pub frozen_state_root: VectorRoot<D>,
    /// Aggregate liability committed by the frozen state root.
    pub state_liability: u64,
    /// Aggregate unfinalized deposits available as direct refunds.
    pub unfinalized_deposit_total: u64,
    /// Active custody reserved by terminal state and deposit claims.
    pub custody_balance: u64,
}

/// One independently consumed terminal state claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardFaultRelease<P: PublicKey> {
    /// Account authenticated by the frozen state opening.
    pub account: P,
    /// Signed withdrawal routed to its opaque destination, when one was queued.
    pub withdrawal: Option<WithdrawalOutput>,
    /// Remaining state balance returned directly to the account.
    pub residual: u64,
    /// Total active custody released by this claim.
    pub released_custody: u64,
}

/// Immutable deadline rules for every close in one settlement deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochDeadlinePolicy {
    /// Maximum admission-deadline increment, measured from the pipeline tail's admission
    /// deadline, or from `now` when the pipeline is empty.
    pub max_admission_delay: NonZeroU64,
    /// Minimum interval from an epoch's admission deadline through its challenge deadline.
    pub minimum_challenge_duration: NonZeroU64,
    /// Maximum interval from an epoch's admission deadline through its challenge deadline.
    pub maximum_challenge_duration: NonZeroU64,
}

impl EpochDeadlinePolicy {
    /// Creates deadline rules fixed when the deployment is created.
    #[must_use]
    pub const fn new(
        max_admission_delay: NonZeroU64,
        minimum_challenge_duration: NonZeroU64,
        maximum_challenge_duration: NonZeroU64,
    ) -> Self {
        Self {
            max_admission_delay,
            minimum_challenge_duration,
            maximum_challenge_duration,
        }
    }
}

/// Bounds and timing policy for one settlement deployment.
///
/// The timing parameters carry deploy-time feasibility obligations beyond the
/// orderings [`SettlementChain::new`] enforces. A user chooses each obligation's
/// deadline within the notice window, so an adversarial user can pick the
/// tightest one. The deployment must leave the honest operator room to discharge
/// it, or that user can force an unnecessary permanent hard fault:
///
/// - `minimum_withdrawal_notice` must exceed the worst-case latency from queueing
///   a withdrawal to finalizing the close that carries it. A chain-queued
///   withdrawal is not discharged until its close finalizes, and that close is
///   appended at the pipeline tail: every close already pending when it is queued
///   must finalize first under FIFO, and only then does its own challenge window
///   elapse. The safe notice therefore covers a full pipeline drain plus one more
///   challenge window, on the order of
///   `(max_pending_epochs + 1) * (max_admission_delay + maximum_challenge_duration)`,
///   not merely one challenge window. Sizing it at `minimum_challenge_duration`
///   plus a small constant is only safe when the pipeline is empty at queue time,
///   so it is unsafe under ordinary load: a deeper pipeline makes the required
///   notice larger, not smaller. The operator-carried path is exempt because it
///   is declined at registration when the deadline cannot clear the close's own
///   finalize tick (see `register_close`), but a chain-queued request cannot be
///   declined, so the notice window is the only lever.
/// - `deposit_inclusion_timeout` must exceed the pipeline turnover time: the
///   longest an accepted deposit can wait for a free pipeline slot given
///   `max_pending_epochs` and the challenge cadence. A deposit is discharged at
///   the admission of its close, so this matters only when every slot is
///   occupied and the operator must finalize one first. A queued withdrawal that
///   exactly offsets a staged deposit defers that deposit by one close (keeping
///   its original deadline), so the budget must also cover one extra close for a
///   deposit that can be deferred this way.
///
/// These are operator responsibilities, not enforced invariants, because they
/// couple parameters whose safe margins depend on the deployment's throughput
/// goals. [`SettlementChain::new`] does reject `max_pending_epochs` below two,
/// which cannot leave a free slot for deposits under any timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementConfig {
    /// Maximum number of admitted, unfinalized closes. Must be at least two so
    /// the operator can always reserve a slot to admit a deposit-carrying close.
    pub max_pending_epochs: NonZeroUsize,
    /// Admission and challenge timing fixed before the deployment accepts funds.
    pub epoch_deadlines: EpochDeadlinePolicy,
    /// Maximum time an accepted deposit may remain outside an admitted close.
    pub deposit_inclusion_timeout: NonZeroU64,
    /// Minimum delay from queueing to a withdrawal's absolute deadline.
    pub minimum_withdrawal_notice: NonZeroU64,
    /// Maximum delay from queueing to a withdrawal's absolute deadline.
    pub maximum_withdrawal_notice: NonZeroU64,
    /// Maximum retained bytes in an opaque withdrawal destination.
    pub max_destination_bytes: usize,
    /// Maximum external deposit identifiers retained for lifetime replay protection.
    ///
    /// This also bounds unfinalized deposit records and direct terminal refunds.
    pub max_deposit_ids: NonZeroUsize,
}

impl SettlementConfig {
    /// Creates an explicit settlement policy.
    #[must_use]
    pub const fn new(
        max_pending_epochs: NonZeroUsize,
        epoch_deadlines: EpochDeadlinePolicy,
        deposit_inclusion_timeout: NonZeroU64,
        minimum_withdrawal_notice: NonZeroU64,
        maximum_withdrawal_notice: NonZeroU64,
        max_destination_bytes: usize,
        max_deposit_ids: NonZeroUsize,
    ) -> Self {
        Self {
            max_pending_epochs,
            epoch_deadlines,
            deposit_inclusion_timeout,
            minimum_withdrawal_notice,
            maximum_withdrawal_notice,
            max_destination_bytes,
            max_deposit_ids,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingDeposit {
    amount: u64,
    deadline: u64,
}

#[derive(Debug)]
struct RegisteredClose<P: PublicKey, D: Digest> {
    context: CloseContext<P, D>,
    deposits: DepositBatch<P>,
    withdrawals: WithdrawalBatch<P, D>,
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
        let mut encoded =
            BytesMut::with_capacity(requests.iter().map(EncodeSize::encode_size).sum());
        let mut index = Vec::with_capacity(requests.len());
        for request in requests {
            let start = encoded.len();
            request.write(&mut encoded);
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

    fn deadline(&self, account: &P) -> Option<u64> {
        self.find(account).map(|entry| entry.deadline)
    }

    fn get(
        &self,
        account: &P,
        maximum_destination_bytes: usize,
    ) -> Result<Option<SignedWithdrawal<P, D>>, SettlementError> {
        let Some(entry) = self.find(account) else {
            return Ok(None);
        };
        let mut encoded = &self.encoded[entry.start..entry.end];
        let request =
            SignedWithdrawal::read_cfg(&mut encoded, &RangeCfg::new(..=maximum_destination_bytes))
                .map_err(|_| SettlementError::WithdrawalWitness)?;
        if !encoded.is_empty() {
            return Err(SettlementError::WithdrawalWitness);
        }
        Ok(Some(request))
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
    withdrawal_outputs: VectorRoot<D>,
    claimed_withdrawals: BTreeSet<u32>,
    claimed_payouts: BTreeSet<u32>,
    withdrawal_remaining: u64,
    payout_remaining: u64,
}

#[derive(Debug)]
struct HardFaultClaims<P: PublicKey, D: Digest> {
    frozen_state_root: VectorRoot<D>,
    state_liability: u64,
    remaining_state_liability: u64,
    unfinalized_deposit_total: u64,
    custody_balance: u64,
    deposits: BTreeMap<P, u64>,
    pending_withdrawals: BTreeMap<P, SignedWithdrawal<P, D>>,
    admitted_withdrawals: Vec<PackedWithdrawals<P, D>>,
    claimed_positions: BTreeSet<u32>,
}

/// Runtime-agnostic chain state for one immutable operator deployment.
///
/// The admitted pipeline is a bounded linear extension of the finalized root. A hard fault
/// permanently rejects new work, while preserving the earlier pending prefix for ordinary
/// challenge and FIFO finalization before independent terminal claims.
///
/// Every method accepting `now` may record a permanent deadline fence before returning an
/// error.
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
    committee_commitment: H::Digest,
    current_state_root: VectorRoot<H::Digest>,
    current_liability: u64,
    custody_balance: u64,
    claimable_balance: u64,
    claimable_batches: BTreeMap<BatchId<H::Digest>, ClaimableBatch<H::Digest>>,
    consumed_deposit_ids: BTreeSet<H::Digest>,
    consumed_withdrawal_ids: BTreeSet<WithdrawalId<H::Digest>>,
    withdrawal_replay_expiries: BTreeSet<(u64, WithdrawalId<H::Digest>)>,
    pending_deposits: BTreeMap<P, PendingDeposit>,
    pending_deposit_deadlines: BTreeSet<(u64, P)>,
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
    hard_fault_claims: Option<HardFaultClaims<P, H::Digest>>,
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
        if config.epoch_deadlines.maximum_challenge_duration
            < config.epoch_deadlines.minimum_challenge_duration
        {
            return Err(SettlementError::ChallengeDurationOrder);
        }
        // A single-slot pipeline has no free slot to admit a deposit-carrying
        // close while its one close is in the challenge window, so a deposit
        // recorded then can be stranded past its inclusion deadline. A depth of
        // two or more always leaves the operator a slot to reserve for
        // deposits.
        if config.max_pending_epochs.get() < 2 {
            return Err(SettlementError::PipelineDepthTooShallow);
        }
        let current_liability = current_state.liability();
        Ok(Self {
            deployment,
            operator,

            // The committee is immutable for the deployment, so its commitment
            // is computed once instead of per registration.
            committee_commitment: committee.commitment::<H>(),
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
            pending_deposit_deadlines: BTreeSet::new(),
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
            hard_fault_claims: None,
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

    fn earliest_withdrawal_deadline(&self) -> Option<(u64, P)> {
        self.pending_withdrawal_deadlines
            .first()
            .into_iter()
            .chain(
                self.pipeline
                    .iter()
                    .filter_map(|entry| entry.admitted.withdrawal_deadline.as_ref()),
            )
            .min()
            .cloned()
    }

    fn expired_reason(&self, now: u64) -> Option<HardFaultReason<P, H::Digest>> {
        let deposit = self
            .pending_deposit_deadlines
            .first()
            .filter(|(deadline, _)| now >= *deadline);
        let withdrawal = self
            .earliest_withdrawal_deadline()
            .filter(|(deadline, _)| now >= *deadline);

        // Withdrawal attribution wins when both intake obligations expire at the same timestamp.
        let intake = match (deposit, withdrawal) {
            (Some((deposit_deadline, _)), Some((withdrawal_deadline, account)))
                if withdrawal_deadline <= *deposit_deadline =>
            {
                Some((
                    withdrawal_deadline,
                    HardFaultReason::ExpiredWithdrawal {
                        account,
                        expired_at: withdrawal_deadline,
                    },
                ))
            }
            (Some((deadline, account)), _) => Some((
                *deadline,
                HardFaultReason::ExpiredDeposit {
                    account: account.clone(),
                    expired_at: *deadline,
                },
            )),
            (None, Some((deadline, account))) => Some((
                deadline,
                HardFaultReason::ExpiredWithdrawal {
                    account,
                    expired_at: deadline,
                },
            )),
            (None, None) => None,
        };
        let registration = self.registered.as_ref().and_then(|registered| {
            let deadline = registered.context.admission_deadline();
            (now > deadline).then(|| {
                let first_expired = deadline
                    .checked_add(1)
                    .expect("observing a later timestamp proves the deadline is not maximal");
                (
                    first_expired,
                    HardFaultReason::ExpiredRegistration {
                        anchor: *registered.context.payment().anchor(),
                        epoch: registered.context.payment().epoch(),
                        expired_at: deadline,
                    },
                )
            })
        });

        // At a shared first-fault instant, retain the active payment anchor in the permanent reason.
        // Deposit refunds and signed withdrawals remain independently recoverable either way.
        match (intake, registration) {
            (Some(intake), Some(registration)) if registration.0 <= intake.0 => {
                Some(registration.1)
            }
            (Some((_, reason)), _) | (None, Some((_, reason))) => Some(reason),
            (None, None) => None,
        }
    }

    fn enter_hard_fault(&mut self, reason: HardFaultReason<P, H::Digest>) {
        if self.hard_fault.is_none() {
            self.admission_fence_epoch = Some(
                self.next_admission_epoch()
                    .expect("live admission ancestry cannot overflow"),
            );
            self.hard_fault = Some(reason);

            // Registration activates one payment context but admits no state transition. Staged
            // deposits and chain-queued withdrawals remain owned and reach terminal settlement.
            // Operator-carried extras existed only in this registration: their replay ids were
            // never consumed and their signers recover through ordinary state claims.
            self.registered = None;
        }
    }

    fn observe_time(&mut self, now: u64) {
        if self.hard_fault.is_none()
            && let Some(reason) = self.expired_reason(now)
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

    fn validate_epoch_deadlines(
        &self,
        now: u64,
        context: &CloseContext<P, H::Digest>,
    ) -> Result<(), SettlementError> {
        let previous = self
            .pipeline
            .back()
            .map(|entry| entry.admitted.context.admission_deadline());
        let base = previous.unwrap_or(now);
        if previous.is_some() && context.admission_deadline() <= base {
            return Err(SettlementError::EpochAdmissionDeadlineNotMonotonic);
        }
        let latest = base.saturating_add(self.config.epoch_deadlines.max_admission_delay.get());
        if context.admission_deadline() > latest {
            return Err(SettlementError::EpochAdmissionDeadlineTooLate);
        }
        let challenge_duration = context
            .challenge_deadline()
            .checked_sub(context.admission_deadline())
            .ok_or(SettlementError::EpochChallengeDuration)?;
        if challenge_duration < self.config.epoch_deadlines.minimum_challenge_duration.get()
            || challenge_duration > self.config.epoch_deadlines.maximum_challenge_duration.get()
        {
            return Err(SettlementError::EpochChallengeDuration);
        }
        Ok(())
    }

    fn head_state_root(&self) -> VectorRoot<H::Digest> {
        self.pipeline
            .back()
            .map_or(self.current_state_root, |entry| entry.batch.roots.successor)
    }

    fn head_liability(&self) -> u64 {
        self.pipeline
            .back()
            .map_or(self.current_liability, |entry| {
                entry.batch.successor_liability
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

    fn ensure_epoch_offset_available(&self, offset: u64) -> Result<(), SettlementError> {
        self.next_admission_epoch()?
            .checked_add(offset)
            .ok_or(SettlementError::EpochOverflow)?;
        Ok(())
    }

    // An amount withdrawal leaves one later close available for residual state. An amountless
    // close itself only needs to remain finalizable.
    fn ensure_withdrawal_epoch_available(
        &self,
        action: &WithdrawalAction,
    ) -> Result<(), SettlementError> {
        self.ensure_epoch_offset_available(match action {
            WithdrawalAction::Amount(_) => 2,
            WithdrawalAction::Close => 1,
        })
    }

    // Deposit intake leaves room for inclusion and a later exit. Exact-offset withdrawals defer
    // inclusion by one close and therefore require one additional epoch.
    fn ensure_deposit_epoch_available(&self, deferred: bool) -> Result<(), SettlementError> {
        self.ensure_epoch_offset_available(if deferred { 4 } else { 3 })
    }

    /// Returns whether a pending withdrawal exactly offsets the account's staged deposit.
    ///
    /// An exactly offset deposit defers inclusion by one close while keeping its original
    /// deadline. Embeddings gate intake with this predicate so their accepted shapes match
    /// registration's canonical boundary exactly.
    pub const fn withdrawal_defers_deposit(
        request: &SignedWithdrawal<P, H::Digest>,
        deposit_amount: u64,
    ) -> bool {
        matches!(
            request.body().action(),
            WithdrawalAction::Amount(withdrawal) if withdrawal.get() == deposit_amount
        )
    }

    fn ensure_deposit_capacity(&self) -> Result<(), SettlementError> {
        if self.consumed_deposit_ids.len() >= self.config.max_deposit_ids.get() {
            return Err(SettlementError::DepositCapacity);
        }
        Ok(())
    }

    /// Records one finalized external deposit event exactly once.
    ///
    /// Repeat deposits for one account aggregate into one staged record that keeps the earliest
    /// inclusion deadline.
    pub fn record_deposit(
        &mut self,
        now: u64,
        deposit_id: H::Digest,
        account: P,
        amount: u64,
    ) -> Result<(), SettlementError> {
        self.ensure_operating_at(now)?;
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

        let deadline = now
            .checked_add(self.config.deposit_inclusion_timeout.get())
            .ok_or(SettlementError::DepositDeadlineOverflow)?;
        let previous = self.pending_deposits.get(&account).copied();

        let amount_for_account = previous
            .map_or(0, |deposit| deposit.amount)
            .checked_add(amount)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let deferred = self
            .pending_withdrawals
            .get(&account)
            .is_some_and(|request| Self::withdrawal_defers_deposit(request, amount_for_account));
        self.ensure_deposit_epoch_available(deferred)?;
        let pending = PendingDeposit {
            amount: amount_for_account,
            deadline: previous.map_or(deadline, |deposit| deposit.deadline.min(deadline)),
        };
        let custody_balance = self
            .custody_balance
            .checked_add(amount)
            .ok_or(SettlementError::CustodyArithmetic)?;

        // Deposits are the only operation that increases active plus claimable custody. Keeping
        // their sum representable makes every later finalization an in-domain transfer.
        self.claimable_balance
            .checked_add(custody_balance)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let unfinalized_deposit_total = self
            .unfinalized_deposit_total
            .checked_add(amount)
            .ok_or(SettlementError::CustodyArithmetic)?;

        if let Some(previous) = previous {
            self.pending_deposit_deadlines
                .remove(&(previous.deadline, account.clone()));
        }
        self.pending_deposit_deadlines
            .insert((pending.deadline, account.clone()));
        self.pending_deposits.insert(account, pending);
        self.consumed_deposit_ids.insert(deposit_id);
        self.custody_balance = custody_balance;
        self.unfinalized_deposit_total = unfinalized_deposit_total;
        Ok(())
    }

    fn has_unfinalized_withdrawal(&self, account: &P) -> bool {
        self.unfinalized_withdrawal_deadline(account).is_some()
    }

    /// Returns one staged or admitted-but-unfinalized withdrawal's absolute deadline.
    #[must_use]
    pub fn unfinalized_withdrawal_deadline(&self, account: &P) -> Option<u64> {
        self.pending_withdrawals
            .get(account)
            .map(|request| request.body().deadline())
            .or_else(|| {
                self.pipeline
                    .iter()
                    .find_map(|entry| entry.admitted.withdrawals.deadline(account))
            })
    }

    /// Validates one withdrawal request's shared intake gates and returns its id.
    ///
    /// Both intake paths run this battery: queueing (which then also proves
    /// affordability at every safety root) and operator-carried registration
    /// (which skips the openings because certification settles an uncovered
    /// amount with a zero release).
    fn ensure_withdrawal_intake<F>(
        &self,
        now: u64,
        request: &SignedWithdrawal<P, H::Digest>,
        destination_is_eligible: F,
    ) -> Result<WithdrawalId<H::Digest>, SettlementError>
    where
        F: FnOnce(&Bytes) -> bool,
    {
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
        Ok(request_id)
    }

    /// Queues one account withdrawal after authenticating every root that can survive a cut.
    ///
    /// An `Amount` must be independently affordable at every safety root. An amountless `Close`
    /// requires an active account at each root. The certified close derives its epoch-tail
    /// balance.
    ///
    /// `destination_is_eligible` is the asset adapter's explicit admission predicate for the
    /// opaque signed destination. Eligibility must be stable for every accepted request because
    /// hard-fault claims must honor the exact bytes without operator cooperation.
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
        self.ensure_withdrawal_epoch_available(request.body().action())?;
        if self.registered.is_some() {
            return Err(SettlementError::EpochAlreadyActive);
        }
        let request_id = self.ensure_withdrawal_intake(now, &request, destination_is_eligible)?;
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
                self.pipeline[index - 1].batch.roots.successor
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
        if self
            .pending_deposits
            .get(request.account())
            .is_some_and(|deposit| Self::withdrawal_defers_deposit(&request, deposit.amount))
        {
            self.ensure_deposit_epoch_available(true)?;
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
    /// Deferral considers only chain-queued withdrawals. A close carrying
    /// operator-collected extras must build its boundary with
    /// [`Self::boundary_deposits`] instead.
    #[must_use]
    pub fn pending_deposits(&self) -> DepositBatch<P> {
        self.boundary_deposits(&self.pending_withdrawals())
    }

    /// Returns the exact deposit boundary for a close sealing `withdrawals`.
    ///
    /// If a batch withdrawal exactly offsets its account's staged deposit, the
    /// withdrawal takes the next slot and the deposit remains staged for its
    /// successor. This keeps every public close row tied to an actual
    /// authenticated state change. Deferral consumes one close of the staged
    /// deposit's inclusion deadline, so an operator must only carry an
    /// offsetting extra when that deadline survives the deferral.
    #[must_use]
    pub fn boundary_deposits(
        &self,
        withdrawals: &WithdrawalBatch<P, H::Digest>,
    ) -> DepositBatch<P> {
        DepositBatch::new(
            self.pending_deposits
                .iter()
                .filter_map(|(account, deposit)| {
                    let deferred = withdrawals.request_for(account).is_some_and(|request| {
                        Self::withdrawal_defers_deposit(request, deposit.amount)
                    });
                    (!deferred).then(|| {
                        DepositRecord::new(account.clone(), deposit.amount)
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

    /// Returns the finalized state root followed by every admitted successor-state root.
    #[must_use]
    pub fn withdrawal_safety_roots(&self) -> Vec<VectorRoot<H::Digest>> {
        core::iter::once(self.current_state_root)
            .chain(
                self.pipeline
                    .iter()
                    .map(|entry| entry.batch.roots.successor),
            )
            .collect()
    }

    /// Binds a root-independent epoch registration to the pipeline head and registers its boundary.
    pub fn register_epoch<F>(
        &mut self,
        now: u64,
        context: EpochContext<P, H::Digest>,
        withdrawals: WithdrawalBatch<P, H::Digest>,
        extra_openings: &[StateOpening<P, H::Digest>],
        destination_is_eligible: F,
    ) -> Result<(), SettlementError>
    where
        F: Fn(&Bytes) -> bool,
    {
        let context = context.bind_settlement_root(self.head_state_root());
        self.register_close(
            now,
            context,
            withdrawals,
            extra_openings,
            destination_is_eligible,
        )
    }

    /// Registers a close context already bound to the pipeline head and its boundary.
    ///
    /// The withdrawal batch must contain every chain-queued request verbatim and
    /// may additionally carry operator-collected signed requests, giving an
    /// uncensored signer a single-transaction exit: the claim. A registration is
    /// an immutable admission obligation, so every carried extra must be provably
    /// certifiable here: `extra_openings` holds one predecessor-root state
    /// opening per extra in batch order, proving the account is live and its
    /// amount coverable at registration. Later epoch spending can still lower
    /// the tail, which certification settles with a zero release.
    ///
    /// The deposit boundary is not an input. It is derived here as
    /// [`Self::boundary_deposits`] of the batch, and the context must commit to
    /// exactly that canonical batch through its deposit root.
    pub fn register_close<F>(
        &mut self,
        now: u64,
        context: CloseContext<P, H::Digest>,
        withdrawals: WithdrawalBatch<P, H::Digest>,
        extra_openings: &[StateOpening<P, H::Digest>],
        destination_is_eligible: F,
    ) -> Result<(), SettlementError>
    where
        F: Fn(&Bytes) -> bool,
    {
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
        self.validate_epoch_deadlines(now, &context)?;
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
        if context.predecessor_root() != &self.head_state_root() {
            return Err(SettlementError::StateAncestry);
        }
        if context.predecessor_liability() != self.head_liability() {
            return Err(SettlementError::LiabilityAncestry);
        }
        if context.assignment().committee() != &self.committee_commitment {
            return Err(SettlementError::CommitteeMismatch);
        }
        let deposits = self.boundary_deposits(&withdrawals);
        if context.deposit_root() != &deposits.root::<H>()?
            || context.withdrawal_root() != &withdrawals.root::<H>()?
        {
            return Err(SettlementError::BoundaryRoot);
        }
        // Every chain-queued request must appear verbatim. Operator-carried
        // extras run the shared intake battery, and each must outlive the
        // challenge window so the admitted close can finalize before its
        // deadline can fault. An extra gains the deadline fault guarantee only
        // once its close is admitted; until then the signer's recourse is the
        // queue.
        for (account, pending) in &self.pending_withdrawals {
            if withdrawals.request_for(account) != Some(pending) {
                return Err(SettlementError::WithdrawalWitness);
            }
        }
        let mut openings = extra_openings.iter();
        for request in withdrawals.requests() {
            if self.pending_withdrawals.contains_key(request.account()) {
                continue;
            }
            self.ensure_withdrawal_epoch_available(request.body().action())?;
            self.ensure_withdrawal_intake(now, request, &destination_is_eligible)?;
            // Finalize is legal only at now > challenge_deadline and runs the
            // inclusive expiry sweep first, so the earliest finalizing tick is
            // challenge_deadline + 1. A deadline at that tick would fault
            // before the pop, so the close needs a strictly later deadline.
            let earliest_finalize = context
                .challenge_deadline()
                .checked_add(1)
                .ok_or(SettlementError::EpochOverflow)?;
            if request.body().deadline() <= earliest_finalize {
                return Err(SettlementError::WithdrawalDeadlineTooSoon);
            }
            // One opening against the close predecessor proves the extra is
            // certifiable: the account is a live leaf and the amount is
            // coverable with this close's deposit. Without this proof one bad
            // carried request would wedge the registration into the admission
            // deadline fault.
            let opening = openings
                .next()
                .ok_or(SettlementError::WithdrawalOpeningCount)?;
            opening.proof.verify::<H>(
                crate::bajillion::commitment::VectorKind::State,
                context.predecessor_root(),
                opening.leaf.encode().as_ref(),
            )?;
            if &opening.leaf.account != request.account() {
                return Err(SettlementError::WithdrawalOpening);
            }
            // The deferred-aware boundary was validated above, so an extra
            // that exactly offsets its staged deposit sees a zero deposit here
            // and must be coverable from the balance alone.
            let deposit = deposits.amount_for(request.account());
            if matches!(
                request.body().action(),
                WithdrawalAction::Amount(amount)
                    if u128::from(amount.get())
                        > u128::from(opening.leaf.state.balance) + u128::from(deposit)
            ) {
                return Err(SettlementError::WithdrawalBalance);
            }
            if self
                .pending_deposits
                .get(request.account())
                .is_some_and(|deposit| Self::withdrawal_defers_deposit(request, deposit.amount))
            {
                self.ensure_deposit_epoch_available(true)?;
            }
        }
        if openings.next().is_some() {
            return Err(SettlementError::WithdrawalOpeningCount);
        }

        let withdrawal_deadline = withdrawals
            .requests()
            .iter()
            .map(|request| (request.body().deadline(), request.account().clone()))
            .min();
        self.registered = Some(RegisteredClose {
            context,
            deposits,
            withdrawals,
            withdrawal_deadline,
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
        let registered = self
            .registered
            .as_ref()
            .ok_or(SettlementError::NoRegisteredEpoch)?;
        transition::validate_header::<H, P, H::Digest>(&registered.context, &header, &roots)?;
        if !self.certificate_scheme.verify_exact(&header, &certificate) {
            return Err(SettlementError::InvalidCertificate);
        }

        // The certified release may fall below the batch's requested sum
        // because uncovered amounts release zero. Over-release fails the
        // liability equation inside the terminal proof.
        let (totals, successor_liability) = verify_terminal_proof_after_header::<H, P, H::Digest>(
            &registered.context,
            &registered.deposits,
            &registered.withdrawals,
            &roots,
            &terminal_proof,
        )?;
        let withdrawal_total = totals.withdrawal;
        let payout_total = totals.payout;

        let batch_id = header.batch_id::<H>();
        let registered = self
            .registered
            .take()
            .expect("the registered close was checked above");
        for record in registered.deposits.records() {
            let deposit = self
                .pending_deposits
                .remove(record.account())
                .expect("the exact staged deposit was checked above");
            assert!(
                self.pending_deposit_deadlines
                    .remove(&(deposit.deadline, record.account().clone())),
                "every staged deposit owns one deadline entry"
            );
        }
        // Operator-carried requests consume their replay ids at admission.
        // Chain-queued ids are already consumed, so re-inserting is a no-op.
        for request in registered.withdrawals.requests() {
            let request_id = request.id::<H>();
            self.withdrawal_replay_expiries
                .insert((request.body().deadline(), request_id));
            self.consumed_withdrawal_ids.insert(request_id);
        }
        let admitted = AdmittedClose {
            context: registered.context,
            deposit_total: registered.deposits.total(),
            deposits: PackedDeposits::new(&registered.deposits),
            withdrawals: PackedWithdrawals::new(registered.withdrawals.requests()),
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
                successor_liability,
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
        batch_id: BatchId<H::Digest>,
        submitted: &Challenge<P, H::Digest>,
    ) -> Result<Verdict, SettlementError> {
        self.challenge_with_strategy(now, batch_id, submitted, &Sequential)
    }

    /// Adjudicates a typed receipt challenge using the supplied execution strategy.
    pub fn challenge_with_strategy(
        &mut self,
        now: u64,
        batch_id: BatchId<H::Digest>,
        submitted: &Challenge<P, H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<Verdict, SettlementError> {
        self.observe_time(now);
        self.challenge_after_observation(now, batch_id, submitted, strategy)
    }

    /// Bounded-decodes and adjudicates one receipt challenge.
    pub fn challenge_encoded(
        &mut self,
        now: u64,
        batch_id: BatchId<H::Digest>,
        encoded: &[u8],
        maximum_bytes: usize,
    ) -> Result<Verdict, SettlementError> {
        self.challenge_encoded_with_strategy(now, batch_id, encoded, maximum_bytes, &Sequential)
    }

    /// Bounded-decodes and adjudicates one receipt challenge using the supplied strategy.
    pub fn challenge_encoded_with_strategy(
        &mut self,
        now: u64,
        batch_id: BatchId<H::Digest>,
        encoded: &[u8],
        maximum_bytes: usize,
        strategy: &impl Strategy,
    ) -> Result<Verdict, SettlementError> {
        self.observe_time(now);
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        let submitted = challenge::decode_bounded(encoded, maximum_bytes)?;
        self.challenge_after_observation(now, batch_id, &submitted, strategy)
    }

    fn challenge_after_observation(
        &mut self,
        now: u64,
        batch_id: BatchId<H::Digest>,
        submitted: &Challenge<P, H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<Verdict, SettlementError> {
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        let index = self
            .pipeline
            .iter()
            .position(|entry| entry.batch.header.batch_id::<H>() == batch_id)
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
        let successor_liability = entry.batch.successor_liability;
        let batch_id = entry.batch.header.batch_id::<H>();
        if reserve_total != 0 && self.claimable_batches.contains_key(&batch_id) {
            return Err(SettlementError::ClaimBatchCollision);
        }

        let finalized = FinalizedBatch {
            batch_id,
            epoch,
            successor_root: entry.batch.roots.successor,
            withdrawal_total,
            payout_total,
            custody_balance,
        };
        let entry = self
            .pipeline
            .pop_front()
            .expect("the finalized pipeline front was checked above");
        self.current_state_root = finalized.successor_root;
        self.current_liability = successor_liability;
        self.custody_balance = custody_balance;
        self.claimable_balance = claimable_balance;
        self.unfinalized_deposit_total = unfinalized_deposit_total;

        if withdrawal_total != 0 || payout_total != 0 {
            let replaced = self.claimable_batches.insert(
                batch_id,
                ClaimableBatch {
                    change_root: entry.batch.roots.change,
                    withdrawal_outputs: entry.batch.roots.withdrawal_outputs,
                    claimed_withdrawals: BTreeSet::new(),
                    claimed_payouts: BTreeSet::new(),
                    withdrawal_remaining: withdrawal_total,
                    payout_remaining: payout_total,
                },
            );
            assert!(replaced.is_none());
        }
        self.expected_epoch = next_epoch;
        Ok(finalized)
    }

    /// Consumes one external-payment claim against a finalized change root.
    ///
    /// The embedding must commit this mutation and the payout effect atomically. Its idempotency
    /// namespace must be distinct from withdrawal outputs and keyed by
    /// `(batch_id, claim.position())` within that namespace.
    pub fn claim_external_payout(
        &mut self,
        batch_id: BatchId<H::Digest>,
        claim: &ExternalPayoutClaim<P, H::Digest>,
    ) -> Result<ExternalPayout<P>, ClaimError> {
        let payout = {
            let batch = self
                .claimable_batches
                .get(&batch_id)
                .ok_or(ClaimError::Unavailable)?;
            if batch.claimed_payouts.contains(&claim.position()) {
                return Err(ClaimError::Consumed);
            }
            let payout = claim.verify::<H>(&batch.change_root)?;
            batch
                .payout_remaining
                .checked_sub(payout.amount)
                .ok_or(ClaimError::Reserve)?;
            payout
        };

        // The global reserve always equals the sum of every batch's
        // remainings, so the per-batch gate above already covered this amount.
        let claimable_balance = self
            .claimable_balance
            .checked_sub(payout.amount)
            .expect("claimable balance covers every per-batch reserve");
        let remove_batch = {
            let batch = self
                .claimable_batches
                .get_mut(&batch_id)
                .expect("the claimable batch was checked above");
            let inserted = batch.claimed_payouts.insert(claim.position());
            assert!(inserted);
            batch.payout_remaining -= payout.amount;
            batch.payout_remaining == 0 && batch.withdrawal_remaining == 0
        };
        self.claimable_balance = claimable_balance;
        if remove_batch {
            self.claimable_batches.remove(&batch_id);
        }
        Ok(payout)
    }

    /// Consumes one certified withdrawal output.
    ///
    /// The embedding must commit this mutation and payout atomically. Its idempotency namespace
    /// must be distinct from external payouts and keyed by the finalized batch identifier and the
    /// claim's withdrawal-output position within that namespace.
    pub fn claim_withdrawal(
        &mut self,
        batch_id: BatchId<H::Digest>,
        claim: &WithdrawalClaim<H::Digest>,
    ) -> Result<WithdrawalOutput, ClaimError> {
        let (output, position) = {
            let batch = self
                .claimable_batches
                .get(&batch_id)
                .ok_or(ClaimError::Unavailable)?;
            let position = claim.position();
            if batch.claimed_withdrawals.contains(&position) {
                return Err(ClaimError::Consumed);
            }
            let output = claim.verify::<H>(&batch.withdrawal_outputs)?;
            let amount = output.amount();
            batch
                .withdrawal_remaining
                .checked_sub(amount)
                .ok_or(ClaimError::Reserve)?;
            (output, position)
        };

        // The global reserve always equals the sum of every batch's
        // remainings, so the per-batch gate above already covered this amount.
        let claimable_balance = self
            .claimable_balance
            .checked_sub(output.amount())
            .expect("claimable balance covers every per-batch reserve");
        let remove_batch = {
            let batch = self
                .claimable_batches
                .get_mut(&batch_id)
                .expect("the claimable batch was checked above");
            let inserted = batch.claimed_withdrawals.insert(position);
            assert!(inserted);
            batch.withdrawal_remaining -= output.amount();
            batch.payout_remaining == 0 && batch.withdrawal_remaining == 0
        };
        self.claimable_balance = claimable_balance;
        if remove_batch {
            self.claimable_batches.remove(&batch_id);
        }
        Ok(output)
    }

    /// Permanently fences the deployment after observing its earliest liveness deadline.
    pub fn fault_expired(
        &mut self,
        now: u64,
    ) -> Result<HardFaultReason<P, H::Digest>, SettlementError> {
        self.ensure_operating()?;
        let reason = self
            .expired_reason(now)
            .ok_or(SettlementError::DeadlineNotReached)?;
        self.enter_hard_fault(reason.clone());
        Ok(reason)
    }

    /// Observes outstanding deadlines and consumes one queued deposit refund after a permanent
    /// fault.
    ///
    /// The refund is fixed to `account`, so invoking this method requires no operator or claimant
    /// witness. The embedding must atomically commit the returned payout and this state mutation,
    /// using the account as its idempotency key.
    pub fn claim_pending_deposit(
        &mut self,
        now: u64,
        account: &P,
    ) -> Result<DepositRefund<P>, SettlementError> {
        self.observe_time(now);
        if self.hard_fault.is_none() {
            return Err(SettlementError::OperatorNotHardFaulted);
        }
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }

        if let Some(claims) = self.hard_fault_claims.as_ref() {
            let amount = claims
                .deposits
                .get(account)
                .copied()
                .ok_or(SettlementError::PendingDepositUnavailable)?;
            let custody_balance = self
                .custody_balance
                .checked_sub(amount)
                .ok_or(SettlementError::CustodyArithmetic)?;
            let unfinalized_deposit_total = self
                .unfinalized_deposit_total
                .checked_sub(amount)
                .ok_or(SettlementError::CustodyArithmetic)?;

            let claims = self
                .hard_fault_claims
                .as_mut()
                .expect("terminal claims were checked above");
            claims
                .deposits
                .remove(account)
                .expect("the terminal deposit was checked above");
            self.custody_balance = custody_balance;
            self.unfinalized_deposit_total = unfinalized_deposit_total;
            self.finish_hard_fault_if_drained();
            return Ok(DepositRefund {
                account: account.clone(),
                amount,
            });
        }

        let deposit = self
            .pending_deposits
            .get(account)
            .copied()
            .ok_or(SettlementError::PendingDepositUnavailable)?;
        let custody_balance = self
            .custody_balance
            .checked_sub(deposit.amount)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let unfinalized_deposit_total = self
            .unfinalized_deposit_total
            .checked_sub(deposit.amount)
            .ok_or(SettlementError::CustodyArithmetic)?;

        self.pending_deposits
            .remove(account)
            .expect("the queued deposit was checked above");
        assert!(
            self.pending_deposit_deadlines
                .remove(&(deposit.deadline, account.clone())),
            "every queued deposit owns one deadline entry"
        );
        self.custody_balance = custody_balance;
        self.unfinalized_deposit_total = unfinalized_deposit_total;
        Ok(DepositRefund {
            account: account.clone(),
            amount: deposit.amount,
        })
    }

    /// Freezes the last finalized root for independent terminal claims.
    ///
    /// Starting terminal settlement only recovers the bounded unfinalized pipeline. Each live
    /// account is later released with [`Self::claim_hard_fault`], while deposits remain directly
    /// refundable with [`Self::claim_pending_deposit`].
    pub fn begin_hard_fault_settlement(
        &mut self,
    ) -> Result<HardFaultSettlement<P, H::Digest>, SettlementError> {
        let reason = self
            .hard_fault
            .clone()
            .ok_or(SettlementError::OperatorNotHardFaulted)?;
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        if let Some(claims) = self.hard_fault_claims.as_ref() {
            return Ok(HardFaultSettlement {
                reason,
                admission_fence_epoch: self
                    .admission_fence_epoch
                    .expect("every hard fault records its admission fence"),
                invalid_from: self.invalid_from,
                frozen_state_root: claims.frozen_state_root,
                state_liability: claims.state_liability,
                unfinalized_deposit_total: claims.unfinalized_deposit_total,
                custody_balance: claims.custody_balance,
            });
        }
        if self
            .pipeline
            .front()
            .is_some_and(|entry| matches!(entry.batch.status, BatchStatus::Pending))
        {
            return Err(SettlementError::PreFaultBatchPending);
        }

        let mut terminal_deposits = self
            .pending_deposits
            .iter()
            .map(|(account, deposit)| (account.clone(), deposit.amount))
            .collect::<BTreeMap<_, _>>();
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
        if self
            .current_liability
            .checked_add(deposit_total)
            .ok_or(SettlementError::CustodyArithmetic)?
            != self.custody_balance
        {
            return Err(SettlementError::CustodyMismatch);
        }

        let pending_withdrawals = core::mem::take(&mut self.pending_withdrawals);
        let admitted_withdrawals = self
            .pipeline
            .drain(..)
            .map(|entry| entry.admitted.withdrawals)
            .collect();
        let claims = HardFaultClaims {
            frozen_state_root: self.current_state_root,
            state_liability: self.current_liability,
            remaining_state_liability: self.current_liability,
            unfinalized_deposit_total: deposit_total,
            custody_balance: self.custody_balance,
            deposits: terminal_deposits,
            pending_withdrawals,
            admitted_withdrawals,
            claimed_positions: BTreeSet::new(),
        };
        let settlement = HardFaultSettlement {
            reason,
            admission_fence_epoch: self
                .admission_fence_epoch
                .expect("every hard fault records its admission fence"),
            invalid_from: self.invalid_from,
            frozen_state_root: claims.frozen_state_root,
            state_liability: claims.state_liability,
            unfinalized_deposit_total: claims.unfinalized_deposit_total,
            custody_balance: claims.custody_balance,
        };

        self.pending_deposits.clear();
        self.pending_deposit_deadlines.clear();
        self.pending_withdrawal_deadlines.clear();
        self.consumed_withdrawal_ids.clear();
        self.withdrawal_replay_expiries.clear();
        self.registered = None;
        self.hard_fault_claims = Some(claims);
        self.finish_hard_fault_if_drained();
        Ok(settlement)
    }

    /// Consumes one account from the state root frozen by terminal settlement.
    ///
    /// The embedding must atomically commit the returned payout effects and this mutation, using
    /// the frozen root and opening position as the idempotency key.
    pub fn claim_hard_fault(
        &mut self,
        opening: &StateOpening<P, H::Digest>,
    ) -> Result<HardFaultRelease<P>, SettlementError> {
        if self.hard_fault.is_none() {
            return Err(SettlementError::OperatorNotHardFaulted);
        }
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        let claims = self
            .hard_fault_claims
            .as_ref()
            .ok_or(SettlementError::HardFaultSettlementNotStarted)?;
        if claims.claimed_positions.contains(&opening.proof.position) {
            return Err(SettlementError::ClaimAlreadyConsumed);
        }
        opening.proof.verify::<H>(
            commitment::VectorKind::State,
            &claims.frozen_state_root,
            opening.leaf.encode().as_ref(),
        )?;

        let account = opening.leaf.account.clone();
        let balance = opening.leaf.state.balance;
        let mut request = claims.pending_withdrawals.get(&account).cloned();
        for admitted in &claims.admitted_withdrawals {
            let Some(candidate) = admitted.get(&account, self.config.max_destination_bytes)? else {
                continue;
            };
            if request.replace(candidate).is_some() {
                return Err(SettlementError::WithdrawalWitness);
            }
        }
        // Coverage is all-or-nothing at the frozen root, mirroring the close
        // rule: an operator-carried amount the frozen balance cannot cover
        // routes nothing and the whole balance stays residual, so the claim
        // never wedges.
        let withdrawal_amount =
            request
                .as_ref()
                .map_or(0, |request| match request.body().action() {
                    WithdrawalAction::Amount(amount) if amount.get() <= balance => amount.get(),
                    WithdrawalAction::Amount(_) => 0,
                    WithdrawalAction::Close => balance,
                });
        let residual = balance - withdrawal_amount;
        let remaining_state_liability = claims
            .remaining_state_liability
            .checked_sub(balance)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let custody_balance = self
            .custody_balance
            .checked_sub(balance)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let withdrawal = request
            .as_ref()
            .map(|request| WithdrawalOutput::from_request(request, withdrawal_amount));
        let release = HardFaultRelease {
            account: account.clone(),
            withdrawal,
            residual,
            released_custody: balance,
        };

        let claims = self
            .hard_fault_claims
            .as_mut()
            .expect("terminal claims were checked above");
        let inserted = claims.claimed_positions.insert(opening.proof.position);
        assert!(inserted);
        claims.pending_withdrawals.remove(&account);
        claims.remaining_state_liability = remaining_state_liability;
        self.custody_balance = custody_balance;
        self.finish_hard_fault_if_drained();
        Ok(release)
    }

    fn finish_hard_fault_if_drained(&mut self) {
        let Some(claims) = self.hard_fault_claims.as_ref() else {
            return;
        };

        // The chain counter mirrors the terminal deposit table exactly during
        // the claims phase, so it is the remaining-deposit gate.
        if claims.remaining_state_liability != 0 || self.unfinalized_deposit_total != 0 {
            return;
        }
        assert!(claims.deposits.is_empty());
        assert_eq!(self.custody_balance, 0);

        self.current_state_root = commitment::empty_root::<H>(commitment::VectorKind::State);
        self.current_liability = 0;
        self.custody_balance = 0;
        self.unfinalized_deposit_total = 0;
        self.hard_fault_claims = None;
        self.fault_settled = true;
    }

    /// Returns the finalized state root.
    #[must_use]
    pub const fn current_state_root(&self) -> VectorRoot<H::Digest> {
        self.current_state_root
    }

    /// Returns the next epoch to finalize.
    ///
    /// Together with [`Self::current_state_root`] this is the chain's own coherent
    /// finality fact: the current root covers exactly the epochs below this one.
    #[must_use]
    pub const fn expected_epoch(&self) -> u64 {
        self.expected_epoch
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

/// Batch-claim adjudication failure.
///
/// The taxonomy is the embedding's retry contract. [`Self::Unavailable`] is the only arm that
/// can change with chain state: the batch may not have finalized yet, may be fully drained, or
/// may never exist, and settlement cannot distinguish those cases. Every other arm is final for
/// the exact claim, because it was adjudicated against an immutable finalized batch.
#[derive(Debug, Error)]
pub enum ClaimError {
    /// No batch with this identifier currently holds an unclaimed reserve.
    #[error("claim batch is unavailable")]
    Unavailable,
    /// The exact claim position was already consumed.
    #[error("claim was already consumed")]
    Consumed,
    /// The claimed amount exceeds the batch's remaining reserve.
    #[error("claim exceeds the remaining batch reserve")]
    Reserve,
    /// The claim proof does not verify against the finalized batch.
    #[error(transparent)]
    Proof(#[from] TransitionError),
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
    /// A context predecessor liability does not extend the tail liability.
    #[error("predecessor liability does not extend the authenticated ancestry")]
    LiabilityAncestry,
    /// The certificate committee differs from the anchor-bound assignment.
    #[error("certificate committee does not match the authenticated assignment")]
    CommitteeMismatch,
    /// Supplied exact batches do not match the context's sealed roots.
    #[error("boundary batches do not match their sealed roots")]
    BoundaryRoot,
    /// An admitted close's packed deposit batch does not decode exactly.
    #[error("admitted deposit batch does not decode exactly")]
    DepositWitness,
    /// Supplied withdrawals do not equal the exact staged withdrawal batch.
    #[error("registered withdrawals do not equal the staged withdrawal batch")]
    WithdrawalWitness,
    /// Two finalized headers resolved to one claim-batch identifier.
    #[error("finalized claim batch identifier collision")]
    ClaimBatchCollision,
    /// The exact finalized claim was already consumed.
    #[error("finalized claim was already consumed")]
    ClaimAlreadyConsumed,
    /// Deposits must carry value.
    #[error("deposit amount must be positive")]
    ZeroDeposit,
    /// An external deposit event identifier was already consumed.
    #[error("external deposit identifier was already consumed")]
    DuplicateDeposit,
    /// No queued deposit remains for the requested account.
    #[error("queued deposit is unavailable")]
    PendingDepositUnavailable,
    /// The deployment retained its configured maximum number of external deposit identifiers.
    #[error("external deposit replay-protection capacity is exhausted")]
    DepositCapacity,
    /// A deposit's inclusion deadline cannot be represented by the settlement clock.
    #[error("deposit inclusion deadline overflow")]
    DepositDeadlineOverflow,
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
    /// The signed deadline is too soon: it falls short of the queue's minimum notice or, for an
    /// operator-carried request, does not clear the close's earliest finalizing tick.
    #[error("withdrawal deadline is too soon to finalize safely")]
    WithdrawalDeadlineTooSoon,
    /// The signed deadline exceeds the deployment's replay-retention horizon.
    #[error("withdrawal deadline exceeds the maximum notice")]
    WithdrawalDeadlineTooLate,
    /// The configured maximum withdrawal notice is shorter than the minimum.
    #[error("maximum withdrawal notice must not be shorter than the minimum")]
    WithdrawalNoticeOrder,
    /// The configured maximum challenge duration is shorter than the minimum.
    #[error("maximum challenge duration must not be shorter than the minimum")]
    ChallengeDurationOrder,
    /// The configured pipeline depth cannot guarantee deposit inclusion.
    #[error("max pending epochs must be at least two")]
    PipelineDepthTooShallow,
    /// No outstanding liveness obligation has expired.
    #[error("no outstanding liveness obligation has expired")]
    DeadlineNotReached,
    /// New work is permanently fenced.
    #[error("the settlement deployment is permanently hard-faulted")]
    OperatorHardFaulted,
    /// Terminal settlement was requested before a permanent fault.
    #[error("the settlement deployment has not hard-faulted")]
    OperatorNotHardFaulted,
    /// Terminal settlement already exhausted custody.
    #[error("the hard-faulted deployment was already settled")]
    HardFaultAlreadySettled,
    /// A terminal state claim was submitted before the frozen claim boundary was created.
    #[error("terminal settlement has not started")]
    HardFaultSettlementNotStarted,
    /// Custody arithmetic overflowed or underflowed.
    #[error("custody arithmetic overflowed or underflowed")]
    CustodyArithmetic,
    /// Custody does not equal finalized liability plus every unfinalized deposit.
    #[error("custody does not match authenticated liability and deposits")]
    CustodyMismatch,
    /// No epoch registration is active.
    #[error("no epoch registration is active")]
    NoRegisteredEpoch,
    /// Registration occurred after the inclusive admission cutoff.
    #[error("close was submitted after its admission deadline")]
    AdmissionAfterDeadline,
    /// An epoch's admission deadline exceeds the deployment's configured increment.
    #[error("epoch admission deadline exceeds the deployment policy")]
    EpochAdmissionDeadlineTooLate,
    /// A pipelined epoch does not advance the prior admission deadline.
    #[error("pipelined epoch admission deadlines must increase")]
    EpochAdmissionDeadlineNotMonotonic,
    /// An epoch's challenge interval falls outside the deployment's configured bounds.
    #[error("epoch challenge deadline falls outside the deployment policy")]
    EpochChallengeDuration,
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
    /// An inclusive challenge window remains open.
    #[error("the challenge window remains open")]
    ChallengeWindowOpen,
    /// Advancing the epoch counter would overflow.
    #[error("epoch counter overflow")]
    EpochOverflow,
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
        challenge::RangeLower,
        commitment::VectorKind,
        credit::{ShardHead, ShardSet},
        payment::{Payment, PaymentError, PaymentWitness, ReceiptBody, SignedReceipt, SignedSend},
        state::{AccountChange, AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
        transition::{
            Assignment, ChallengeIndex, Close, CloseLimits, assemble_external_payout_claim,
            assemble_terminal_proof, assemble_withdrawal_claim, build_close, validate_close,
        },
    };
    use alloc::collections::BTreeSet;
    use bytes::BufMut;
    use commonware_codec::{Decode, Error as CodecError, FixedSize, ReadExt, Write};
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
            EpochDeadlinePolicy::new(
                NonZeroU64::new(1_000).unwrap(),
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(1_000).unwrap(),
            ),
            NonZeroU64::new(1_000).unwrap(),
            NonZeroU64::new(minimum_withdrawal_notice).unwrap(),
            NonZeroU64::new(1_000).unwrap(),
            1_024,
            NonZeroUsize::new(1_024).unwrap(),
        )
    }

    #[test]
    fn registration_enforces_the_deployment_deadline_policy() {
        fn policy() -> SettlementConfig {
            SettlementConfig::new(
                NonZeroUsize::new(3).unwrap(),
                EpochDeadlinePolicy::new(
                    NonZeroU64::new(3).unwrap(),
                    NonZeroU64::new(2).unwrap(),
                    NonZeroU64::new(2).unwrap(),
                ),
                NonZeroU64::new(1_000).unwrap(),
                NonZeroU64::new(2).unwrap(),
                NonZeroU64::new(1_000).unwrap(),
                1_024,
                NonZeroUsize::new(1_024).unwrap(),
            )
        }

        let register = |admission_deadline, challenge_deadline| {
            let mut fixture = harness_with_config(&[10], policy());
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
                admission_deadline,
                challenge_deadline,
            );
            let result = fixture
                .chain
                .register_close(0, context, withdrawals, &[], |_| true);
            (fixture, result)
        };

        let (fixture, result) = register(3, 5);
        assert!(result.is_ok());
        assert!(fixture.chain.registered.is_some());

        let (fixture, result) = register(4, 6);
        assert!(matches!(
            result,
            Err(SettlementError::EpochAdmissionDeadlineTooLate)
        ));
        assert!(fixture.chain.registered.is_none());

        for challenge_deadline in [4, 6] {
            let (fixture, result) = register(3, challenge_deadline);
            assert!(matches!(
                result,
                Err(SettlementError::EpochChallengeDuration)
            ));
            assert!(fixture.chain.registered.is_none());
        }

        let mut fixture = harness_with_config(&[10], policy());
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
            3,
            5,
        );
        let first = empty_close(&fixture.cache, &first_context);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            0,
            first_context,
            deposits.clone(),
            withdrawals.clone(),
            &[],
            &first,
        );
        for (admission_deadline, challenge_deadline, expected) in [
            (3, 5, SettlementError::EpochAdmissionDeadlineNotMonotonic),
            (7, 9, SettlementError::EpochAdmissionDeadlineTooLate),
        ] {
            let context = context(
                fixture.deployment,
                &fixture.operator,
                fixture.committee,
                1,
                &fixture.cache,
                &deposits,
                &withdrawals,
                admission_deadline,
                challenge_deadline,
            );
            let result = fixture
                .chain
                .register_close(1, context, withdrawals.clone(), &[], |_| true);
            assert_eq!(
                core::mem::discriminant(&result.unwrap_err()),
                core::mem::discriminant(&expected)
            );
            assert!(fixture.chain.registered.is_none());
        }

        let context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &deposits,
            &withdrawals,
            4,
            6,
        );
        fixture
            .chain
            .register_close(1, context, withdrawals, &[], |_| true)
            .unwrap();

        let base = harness(&[10]);
        let mut invalid_policy = policy();
        invalid_policy.epoch_deadlines.minimum_challenge_duration = NonZeroU64::new(3).unwrap();
        assert!(matches!(
            SettlementChain::<Sha256, VerifyingKey>::new(
                base.deployment,
                base.operator.public_key(),
                committee(211),
                &base.cache,
                0,
                invalid_policy,
            ),
            Err(SettlementError::ChallengeDurationOrder)
        ));
    }

    #[test]
    fn hard_fault_recovery_claims_the_frozen_state_incrementally() {
        let mut fixture = harness(&[7, 11]);
        let withdrawing = &fixture.accounts[0];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            withdrawing,
            b"terminal-destination",
            amount_action(2),
            2,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &[fixture.cache.opening(&withdrawing.public_key()).unwrap()],
                |_| true,
            )
            .unwrap();
        fixture.chain.fault_expired(2).unwrap();

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.frozen_state_root, fixture.cache.root());
        assert_eq!(settlement.state_liability, 18);
        assert_eq!(settlement.unfinalized_deposit_total, 0);
        assert_eq!(settlement.custody_balance, 18);

        let other = fixture
            .cache
            .opening(&fixture.accounts[1].public_key())
            .unwrap();
        let release = fixture.chain.claim_hard_fault(&other).unwrap();
        assert!(release.withdrawal.is_none());
        assert_eq!(release.residual, 11);
        assert_eq!(release.released_custody, 11);
        assert_eq!(fixture.chain.current_state_root(), fixture.cache.root());
        assert!(matches!(
            fixture.chain.claim_hard_fault(&other),
            Err(SettlementError::ClaimAlreadyConsumed)
        ));

        let opening = fixture.cache.opening(&withdrawing.public_key()).unwrap();
        let release = fixture.chain.claim_hard_fault(&opening).unwrap();
        assert_withdrawal_output(release.withdrawal.as_ref().unwrap(), &request, 2);
        assert_eq!(release.residual, 5);
        assert_eq!(release.released_custody, 7);
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(
            fixture.chain.current_state_root(),
            commitment::empty_root::<Sha256>(VectorKind::State)
        );
        assert!(fixture.chain.hard_fault_is_settled());
    }

    #[test]
    fn hard_fault_claim_recovers_an_admitted_withdrawal() {
        let mut fixture = harness(&[7, 11, 13]);
        let withdrawing = &fixture.accounts[0];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            withdrawing,
            b"admitted-terminal-destination",
            amount_action(2),
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &[fixture.cache.opening(&withdrawing.public_key()).unwrap()],
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
            5,
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &[],
            &close,
        );
        let left = fork_payment(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            &fixture.accounts[2],
            2,
        );
        let right = fork_payment(
            &close_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[2],
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(5, batch_id, &Challenge::receipt_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        fixture.chain.begin_hard_fault_settlement().unwrap();
        let release = fixture
            .chain
            .claim_hard_fault(&fixture.cache.opening(&withdrawing.public_key()).unwrap())
            .unwrap();
        assert_withdrawal_output(release.withdrawal.as_ref().unwrap(), &request, 2);
        assert_eq!(release.residual, 5);
        assert_eq!(release.released_custody, 7);
    }

    #[test]
    fn hard_fault_claim_degrades_an_uncovered_carried_amount() {
        let mut fixture = harness(&[7, 11, 13]);
        let withdrawing = fixture.accounts[0].clone();
        // Covered at the close predecessor through the staged deposit, but the
        // hard fault freezes the older root where the balance is only 7. The
        // queue's safety openings would have refused this request, so only the
        // carried path can reach the frozen-root shortfall.
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &withdrawing,
            b"carried-terminal-destination",
            amount_action(9),
            10,
        );
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"carried-cover"]),
                withdrawing.public_key(),
                10,
            )
            .unwrap();

        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::new(vec![request.clone()]).unwrap();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            5,
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &[fixture.cache.opening(&withdrawing.public_key()).unwrap()],
            &close,
        );
        let left = fork_payment(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            &fixture.accounts[2],
            2,
        );
        let right = fork_payment(
            &close_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[2],
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(5, batch_id, &Challenge::receipt_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        fixture.chain.begin_hard_fault_settlement().unwrap();
        let release = fixture
            .chain
            .claim_hard_fault(&fixture.cache.opening(&withdrawing.public_key()).unwrap())
            .unwrap();
        // The carried amount exceeds the frozen balance, so the claim routes
        // nothing to the destination and the whole balance stays residual.
        assert_withdrawal_output(release.withdrawal.as_ref().unwrap(), &request, 0);
        assert_eq!(release.residual, 7);
        assert_eq!(release.released_custody, 7);
    }

    #[test]
    fn hard_fault_claim_recovers_an_admitted_amountless_close() {
        let mut fixture = harness(&[7, 11, 13]);
        let closer = &fixture.accounts[0];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            closer,
            b"admitted-full-tail-destination",
            WithdrawalAction::Close,
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &[fixture.cache.opening(&closer.public_key()).unwrap()],
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
            5,
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &[],
            &close,
        );
        assert_eq!(fixture.chain.pending_epoch_count(), 1);
        assert_eq!(fixture.chain.current_state_root(), fixture.cache.root());

        let left = fork_payment(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            &fixture.accounts[2],
            2,
        );
        let right = fork_payment(
            &close_context,
            &fixture.operator,
            &fixture.accounts[1],
            &fixture.accounts[2],
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(5, batch_id, &Challenge::receipt_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.frozen_state_root, fixture.cache.root());
        assert_eq!(settlement.state_liability, 31);
        assert_eq!(settlement.custody_balance, 31);

        let opening = fixture.cache.opening(&closer.public_key()).unwrap();
        let release = fixture.chain.claim_hard_fault(&opening).unwrap();
        assert_eq!(request.body().action(), &WithdrawalAction::Close);
        let withdrawal = release.withdrawal.as_ref().unwrap();
        assert_eq!(
            withdrawal.destination(),
            &Bytes::from_static(b"admitted-full-tail-destination")
        );
        assert_eq!(withdrawal.amount(), 7);
        assert_eq!(release.residual, 0);
        assert_eq!(release.released_custody, 7);
        assert_eq!(fixture.chain.custody_balance(), 24);
        assert!(matches!(
            fixture.chain.claim_hard_fault(&opening),
            Err(SettlementError::ClaimAlreadyConsumed)
        ));

        for (account, balance) in fixture.accounts[1..].iter().zip([11, 13]) {
            let release = fixture
                .chain
                .claim_hard_fault(&fixture.cache.opening(&account.public_key()).unwrap())
                .unwrap();
            assert!(release.withdrawal.is_none());
            assert_eq!(release.residual, balance);
            assert_eq!(release.released_custody, balance);
        }
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert!(fixture.chain.hard_fault_is_settled());
    }

    #[test]
    fn expired_registered_sender_flows_recover_every_custody_bucket_once() {
        let mut fixture = harness(&[20, 15, 10]);
        let payer = fixture.accounts[0].public_key();
        let amount_account = fixture.accounts[1].public_key();
        let close_account = fixture.accounts[2].public_key();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"registered-sender-flow-deposit"]),
                payer.clone(),
                7,
            )
            .unwrap();
        let amount_request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &fixture.accounts[1],
            b"amount-fault-destination",
            amount_action(4),
            10,
        );
        let close_request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &fixture.accounts[2],
            b"close-fault-destination",
            WithdrawalAction::Close,
            10,
        );
        for (account, request) in [
            (&amount_account, amount_request.clone()),
            (&close_account, close_request.clone()),
        ] {
            fixture
                .chain
                .queue_withdrawal(
                    0,
                    request,
                    &[fixture.cache.opening(account).unwrap()],
                    |_| true,
                )
                .unwrap();
        }
        let deposits = fixture.chain.pending_deposits();
        let withdrawals = fixture.chain.pending_withdrawals();
        let registered = context(
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
        let anchor = *registered.payment().anchor();
        let accepted_payment = fork_payment(
            &registered,
            &fixture.operator,
            &fixture.accounts[0],
            &fixture.accounts[1],
            3,
        );
        assert_eq!(accepted_payment.amount(), 3);
        fixture
            .chain
            .register_close(0, registered, withdrawals, &[], |_| true)
            .unwrap();

        assert_eq!(
            fixture.chain.fault_expired(2).unwrap(),
            HardFaultReason::ExpiredRegistration {
                anchor,
                epoch: 0,
                expired_at: 1,
            }
        );
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.state_liability, 45);
        assert_eq!(settlement.unfinalized_deposit_total, 7);
        assert_eq!(settlement.custody_balance, 52);
        assert_eq!(fixture.chain.claimable_balance(), 0);

        let payer_opening = fixture.cache.opening(&payer).unwrap();
        let payer_release = fixture.chain.claim_hard_fault(&payer_opening).unwrap();
        assert!(payer_release.withdrawal.is_none());
        assert_eq!(payer_release.residual, 20);
        assert_eq!(payer_release.released_custody, 20);
        assert!(matches!(
            fixture.chain.claim_hard_fault(&payer_opening),
            Err(SettlementError::ClaimAlreadyConsumed)
        ));

        let amount_release = fixture
            .chain
            .claim_hard_fault(&fixture.cache.opening(&amount_account).unwrap())
            .unwrap();
        assert_withdrawal_output(
            amount_release.withdrawal.as_ref().unwrap(),
            &amount_request,
            4,
        );
        assert_eq!(amount_release.residual, 11);
        assert_eq!(amount_release.released_custody, 15);

        let close_release = fixture
            .chain
            .claim_hard_fault(&fixture.cache.opening(&close_account).unwrap())
            .unwrap();
        assert_withdrawal_output(
            close_release.withdrawal.as_ref().unwrap(),
            &close_request,
            10,
        );
        assert_eq!(close_release.residual, 0);
        assert_eq!(close_release.released_custody, 10);

        let refund = fixture.chain.claim_pending_deposit(2, &payer).unwrap();
        assert_eq!(refund.account, payer);
        assert_eq!(refund.amount, 7);
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert!(fixture.chain.hard_fault_is_settled());
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

    fn claim_frozen_state(
        chain: &mut TestChain,
        cache: &TestCache,
    ) -> Vec<HardFaultRelease<VerifyingKey>> {
        cache
            .leaves()
            .iter()
            .map(|leaf| {
                let opening = cache.opening(&leaf.account).unwrap();
                chain.claim_hard_fault(&opening).unwrap()
            })
            .collect()
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
            let predecessor = cache
                .leaves()
                .iter()
                .find(|leaf| leaf.account == account)
                .map_or_else(AccountState::default, |leaf| leaf.state);
            let deposit = deposits.amount_for(&account);
            let withdrawal = withdrawals.request_for(&account);
            let applied = withdrawal.map_or(0, |request| match request.body().action() {
                WithdrawalAction::Amount(amount) => amount.get(),
                WithdrawalAction::Close => predecessor.balance.checked_add(deposit).unwrap(),
            });
            let mut successor = predecessor;
            successor.balance = predecessor
                .balance
                .checked_add(deposit)
                .and_then(|balance| balance.checked_sub(applied))
                .unwrap();
            successor.active = successor.balance > 0;
            let shards = ShardSet::empty(context.payment().epoch(), account.clone());
            let output = withdrawal.map_or(SettlementOutput::None, |_| {
                SettlementOutput::Withdrawal(applied)
            });
            prefix = prefix
                .checked_extend(Prefix {
                    deposit,
                    withdrawal: applied,
                    withdrawal_count: u64::from(withdrawal.is_some()),
                    ..Prefix::default()
                })
                .unwrap();
            rows.push(AccountRow {
                account,
                predecessor,
                successor,
                outgoing: None,
                output,
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
        let mut successor_leaves = cache
            .leaves()
            .iter()
            .filter(|leaf| !changed.contains(&leaf.account))
            .cloned()
            .collect::<Vec<_>>();
        successor_leaves.extend(
            close
                .rows
                .iter()
                .filter(|row| row.successor.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: row.successor,
                }),
        );
        successor_leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let successor = StateCache::new::<Sha256>(successor_leaves).unwrap();
        assert_eq!(successor.root(), close.roots.successor);
        (close, successor)
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

    #[allow(clippy::too_many_arguments)]
    fn register_and_admit(
        chain: &mut TestChain,
        signer: &bls12381::Scheme,
        now: u64,
        context: TestContext,
        deposits: TestDeposits,
        withdrawals: TestWithdrawals,
        extra_openings: &[StateOpening<VerifyingKey, ShaDigest>],
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
        chain
            .register_close(now, context, withdrawals, extra_openings, |_| true)
            .unwrap();
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
            &[],
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

    fn assert_withdrawal_output(
        output: &WithdrawalOutput,
        request: &SignedWithdrawal<VerifyingKey, ShaDigest>,
        amount: u64,
    ) {
        assert_eq!(output.destination(), request.body().destination());
        assert_eq!(output.amount(), amount);
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
        assert!(packed.deadline(requests[0].account()).is_some());
        assert!(packed.deadline(requests[1].account()).is_some());
        assert_eq!(
            packed.get(requests[0].account(), 0).unwrap(),
            Some(requests[0].clone())
        );
        assert_eq!(
            packed.get(requests[1].account(), 0).unwrap(),
            Some(requests[1].clone())
        );
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
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            context.payment(),
            &send,
            &recipient.public_key(),
            0,
            0,
            0,
            operator,
        )
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
        let predecessor = cache
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
                    predecessor,
                    successor: AccountState {
                        balance: predecessor.balance.checked_sub(amount).unwrap(),
                        cumulative_debit: predecessor.cumulative_debit.checked_add(amount).unwrap(),
                        ..predecessor
                    },
                    outgoing: Some(payment),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    predecessor: AccountState::default(),
                    successor: AccountState {
                        cumulative_credit: amount,
                        receipt_count: 1,
                        ..AccountState::default()
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        let mut prefix = Prefix::default();
        for (row, shards) in &mut pairs {
            let (debit, credit, _) = row.checked_deltas().unwrap();
            let payout = if row.predecessor.active { 0 } else { credit };
            row.output = if payout == 0 {
                SettlementOutput::None
            } else {
                SettlementOutput::ExternalPayout(payout)
            };
            prefix = prefix
                .checked_extend(Prefix {
                    debit,
                    credit,
                    payout,
                    shard_count: shards.heads().len() as u64,
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
        let mut successor = cache
            .leaves()
            .iter()
            .filter(|leaf| !changed.contains(&leaf.account))
            .cloned()
            .collect::<Vec<_>>();
        successor.extend(
            close
                .rows
                .iter()
                .filter(|row| row.successor.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: row.successor,
                }),
        );
        successor.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let successor = StateCache::new::<Sha256>(successor).unwrap();
        assert_eq!(successor.root(), close.roots.successor);
        (close, successor)
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
        let payer_predecessor = cache.opening(&payer.public_key()).unwrap().leaf.state;
        let recipient_predecessor = cache.opening(&recipient.public_key()).unwrap().leaf.state;
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
                    predecessor: payer_predecessor,
                    successor: AccountState {
                        balance: 0,
                        cumulative_debit: payer_predecessor
                            .cumulative_debit
                            .checked_add(amount)
                            .unwrap(),
                        active: false,
                        ..payer_predecessor
                    },
                    outgoing: Some(payment),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    predecessor: recipient_predecessor,
                    successor: AccountState {
                        balance: recipient_predecessor.balance.checked_add(amount).unwrap(),
                        cumulative_credit: recipient_predecessor
                            .cumulative_credit
                            .checked_add(amount)
                            .unwrap(),
                        receipt_count: recipient_predecessor.receipt_count.checked_add(1).unwrap(),
                        ..recipient_predecessor
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        let mut prefix = Prefix::default();
        for (row, shards) in &mut pairs {
            let (debit, credit, _) = row.checked_deltas().unwrap();
            let closes_account = row.account == payer.public_key();
            let withdrawal = 0;
            row.output = if closes_account {
                SettlementOutput::Withdrawal(withdrawal)
            } else {
                SettlementOutput::None
            };
            prefix = prefix
                .checked_extend(Prefix {
                    debit,
                    credit,
                    withdrawal,
                    withdrawal_count: u64::from(closes_account),
                    shard_count: shards.heads().len() as u64,
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
        let mut successor = cache
            .leaves()
            .iter()
            .filter(|leaf| !changed.contains(&leaf.account))
            .cloned()
            .collect::<Vec<_>>();
        successor.extend(
            close
                .rows
                .iter()
                .filter(|row| row.successor.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: row.successor,
                }),
        );
        successor.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let successor = StateCache::new::<Sha256>(successor).unwrap();
        assert_eq!(successor.root(), close.roots.successor);
        (close, successor)
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

    fn challenge_pipeline(malformed: bool) -> (Harness, TestChallenge, BatchId<ShaDigest>) {
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
        let (left, right) = if malformed {
            let wrong = SigningKey::from_seed(999);
            (
                Payment::from_parts_unchecked(
                    left.send().clone(),
                    SignedReceipt::sign_body_by_authority(left.receipt().body().clone(), &wrong),
                ),
                Payment::from_parts_unchecked(
                    SignedSend::sign_body_by_authority(right.send().body().clone(), &wrong),
                    right.receipt().clone(),
                ),
            )
        } else {
            (left, right)
        };
        let challenge = Challenge::receipt_fork(&left, &right);
        (fixture, challenge, first_id)
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
        let (mut fixture, challenge, batch) = challenge_pipeline(malformed);
        let encoded = challenge.encode();
        let result = match api {
            ChallengeApi::TypedWrapper => fixture.chain.challenge(10, batch, &challenge),
            ChallengeApi::TypedSequential => {
                fixture
                    .chain
                    .challenge_with_strategy(10, batch, &challenge, &Sequential)
            }
            ChallengeApi::TypedRayon => fixture
                .chain
                .challenge_with_strategy(10, batch, &challenge, rayon),
            ChallengeApi::EncodedWrapper => {
                fixture
                    .chain
                    .challenge_encoded(10, batch, encoded.as_ref(), encoded.len())
            }
            ChallengeApi::EncodedSequential => fixture.chain.challenge_encoded_with_strategy(
                10,
                batch,
                encoded.as_ref(),
                encoded.len(),
                &Sequential,
            ),
            ChallengeApi::EncodedRayon => fixture.chain.challenge_encoded_with_strategy(
                10,
                batch,
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
    fn explicit_batch_id_routes_challenge_to_exact_pending_batch() {
        let mut fixture = harness(&[10, 10, 10]);
        admit_empty_epoch(&mut fixture, 0, 1, 2, 10);
        let (second_context, second_id) = admit_empty_epoch(&mut fixture, 1, 1, 3, 10);
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
        let challenge = Challenge::receipt_fork(&left, &right);

        assert_eq!(
            fixture.chain.challenge(10, second_id, &challenge).unwrap(),
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
            ]
        );
        assert_eq!(fixture.chain.invalid_from(), Some(second_id));
    }

    #[test]
    fn higher_shard_tip_fault_releases_sender() {
        let mut fixture = harness(&[10]);
        let recipient = SigningKey::from_seed(1_006);
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
            10,
        );
        let (close, _) = external_payout_close(
            &fixture.cache,
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            &recipient,
            2,
        );
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &[],
            &close,
        );

        let payment = close
            .rows
            .iter()
            .find_map(|row| row.outgoing.clone())
            .expect("the close has one outgoing payment");
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            close_context.payment(),
            payment.send(),
            payment.recipient(),
            payment.receipt().body().shard(),
            payment.receipt().body().cumulative_shard_credit(),
            payment.receipt().body().index(),
            &fixture.operator,
        )
        .unwrap();
        let payment =
            Payment::new::<Sha256>(close_context.payment(), payment.send().clone(), receipt)
                .unwrap();

        let index = ChallengeIndex::new::<Sha256>(&close_context, &close).unwrap();
        let recipient = payment.recipient().clone();
        let recipient_position = close
            .rows
            .binary_search_by(|row| row.account.cmp(&recipient))
            .unwrap();
        let recipient_lookup = index
            .higher_shard_tip_lookup::<Sha256>(
                &recipient,
                Some(&close.shard_sets[recipient_position]),
                payment.receipt().body().shard(),
            )
            .unwrap();
        let challenge = Challenge::HigherShardTip {
            payment: alloc::boxed::Box::new(PaymentWitness::from_payment(&payment)),
            recipient: alloc::boxed::Box::new(recipient_lookup),
        };

        assert_eq!(
            fixture.chain.challenge(10, batch_id, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::HigherShardTip)
        );
        assert_eq!(
            fixture
                .chain
                .pending_batches()
                .map(|batch| batch.status.clone())
                .collect::<Vec<_>>(),
            vec![BatchStatus::Challenged(ChallengeKind::HigherShardTip)]
        );
        assert_eq!(fixture.chain.invalid_from(), Some(batch_id));

        let terminal = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(terminal.frozen_state_root, fixture.cache.root());
        assert_eq!(terminal.custody_balance, 10);
        assert_eq!(fixture.chain.claimable_balance(), 0);

        let payer = fixture.accounts[0].public_key();
        let opening = fixture.cache.opening(&payer).unwrap();
        let release = fixture.chain.claim_hard_fault(&opening).unwrap();
        assert_eq!(release.account, payer);
        assert_eq!(release.residual, 10);
        assert_eq!(release.released_custody, 10);
        assert!(release.withdrawal.is_none());
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert!(fixture.chain.hard_fault_is_settled());
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
            &[],
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
            &[],
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
        let registered_anchor = *registered.payment().anchor();
        fixture
            .chain
            .register_close(7, registered, withdrawals, &[], |_| true)
            .unwrap();
        assert!(matches!(
            fixture.chain.fault_expired(7),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert_eq!(
            fixture.chain.fault_expired(8).unwrap(),
            HardFaultReason::ExpiredRegistration {
                anchor: registered_anchor,
                epoch: 2,
                expired_at: 7,
            }
        );
    }

    #[test]
    fn registration_retries_cannot_skip_an_epoch() {
        let mut fixture = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let skipped_genesis = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            3,
        );
        assert!(matches!(
            fixture
                .chain
                .register_close(1, skipped_genesis, withdrawals.clone(), &[], |_| true),
            Err(SettlementError::EpochSequence)
        ));

        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            3,
        );
        let first = empty_close(&fixture.cache, &first_context);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            deposits.clone(),
            withdrawals.clone(),
            &[],
            &first,
        );

        let skipped_successor = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            2,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            4,
        );
        assert!(matches!(
            fixture
                .chain
                .register_close(2, skipped_successor, withdrawals.clone(), &[], |_| true),
            Err(SettlementError::EpochSequence)
        ));

        let successor = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            4,
        );
        fixture
            .chain
            .register_close(2, successor, withdrawals, &[], |_| true)
            .unwrap();
        assert_eq!(fixture.chain.pending_epoch_count(), 1);
    }

    #[test]
    fn expired_registration_permanently_fences_its_payment_context() {
        let mut fixture = harness(&[10]);
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"registered-boundary"]),
                fixture.accounts[0].public_key(),
                7,
            )
            .unwrap();
        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let registered = context(
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
        let registered_anchor = *registered.payment().anchor();
        fixture
            .chain
            .register_close(0, registered, withdrawals, &[], |_| true)
            .unwrap();

        assert!(matches!(
            fixture.chain.fault_expired(1),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert!(matches!(
            fixture.chain.record_deposit(
                2,
                Sha256::hash(&[b"post-admission-expiry"]),
                fixture.accounts[0].public_key(),
                1,
            ),
            Err(SettlementError::OperatorHardFaulted)
        ));

        assert_eq!(
            fixture.chain.hard_fault(),
            Some(&HardFaultReason::ExpiredRegistration {
                anchor: registered_anchor,
                epoch: 0,
                expired_at: 1,
            })
        );
        assert_eq!(fixture.chain.admission_fence_epoch(), Some(0));
        assert_eq!(
            fixture
                .chain
                .claim_pending_deposit(2, &fixture.accounts[0].public_key())
                .unwrap()
                .amount,
            7
        );
        assert!(matches!(
            fixture.chain.record_deposit(
                2,
                Sha256::hash(&[b"after-permanent-fence"]),
                fixture.accounts[0].public_key(),
                1,
            ),
            Err(SettlementError::OperatorHardFaulted)
        ));
    }

    #[test]
    fn registered_anchor_wins_a_same_instant_deposit_expiry() {
        let mut settlement_config = config(3, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(2).unwrap();
        let mut fixture = harness_with_config(&[10], settlement_config);
        let account = fixture.accounts[0].public_key();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"registration-deposit-expiry-tie"]),
                account.clone(),
                7,
            )
            .unwrap();
        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let registered = context(
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
        let anchor = *registered.payment().anchor();
        fixture
            .chain
            .register_close(0, registered, withdrawals, &[], |_| true)
            .unwrap();

        assert_eq!(
            fixture.chain.fault_expired(2).unwrap(),
            HardFaultReason::ExpiredRegistration {
                anchor,
                epoch: 0,
                expired_at: 1,
            }
        );
        assert_eq!(
            fixture.chain.claim_pending_deposit(2, &account).unwrap(),
            DepositRefund { account, amount: 7 }
        );
    }

    #[test]
    fn late_admission_persists_the_registration_fault() {
        let mut fixture = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let registered = context(
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
        let anchor = *registered.payment().anchor();
        let (close, _) = boundary_close(&fixture.cache, &registered, &deposits, &withdrawals);
        let terminal_proof = assemble_terminal_proof::<Sha256, _, _>(
            &registered,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();
        let certificate = certificate(
            &fixture.signer,
            &registered,
            &deposits,
            &withdrawals,
            &close,
        );
        fixture
            .chain
            .register_close(0, registered, withdrawals, &[], |_| true)
            .unwrap();

        assert!(matches!(
            fixture
                .chain
                .admit(2, close.header, close.roots, terminal_proof, certificate),
            Err(SettlementError::OperatorHardFaulted)
        ));
        assert_eq!(
            fixture.chain.hard_fault(),
            Some(&HardFaultReason::ExpiredRegistration {
                anchor,
                epoch: 0,
                expired_at: 1,
            })
        );
    }

    #[test]
    fn open_registration_slot_has_no_heartbeat_deadline() {
        let mut fixture = harness(&[10]);

        assert!(matches!(
            fixture.chain.fault_expired(u64::MAX),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert!(fixture.chain.hard_fault().is_none());
    }

    #[test]
    fn stale_unaccepted_registration_leaves_the_slot_open() {
        let mut fixture = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let stale = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            3,
        );

        assert!(matches!(
            fixture
                .chain
                .register_close(2, stale, withdrawals.clone(), &[], |_| true),
            Err(SettlementError::AdmissionAfterDeadline)
        ));
        assert!(fixture.chain.hard_fault().is_none());

        let fresh = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            4,
            6,
        );
        let anchor = *fresh.payment().anchor();
        fixture
            .chain
            .register_close(2, fresh, withdrawals, &[], |_| true)
            .unwrap();

        assert_eq!(
            fixture
                .chain
                .registered
                .as_ref()
                .map(|registered| registered.context.payment().anchor()),
            Some(&anchor)
        );
        assert!(fixture.chain.hard_fault().is_none());
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
        let registered_anchor = *close_context.payment().anchor();
        unadmitted
            .chain
            .register_close(u64::MAX - 2, close_context, withdrawals, &[], |_| true)
            .unwrap();
        assert!(matches!(
            unadmitted.chain.fault_expired(u64::MAX - 2),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert_eq!(
            unadmitted.chain.fault_expired(u64::MAX - 1).unwrap(),
            HardFaultReason::ExpiredRegistration {
                anchor: registered_anchor,
                epoch: 0,
                expired_at: u64::MAX - 2,
            }
        );
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
            .register_epoch(0, epoch, withdrawals, &[], |_| true)
            .unwrap();

        assert_eq!(
            fixture
                .chain
                .registered
                .as_ref()
                .unwrap()
                .context
                .predecessor_root(),
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
                .register_close(0, close_context, withdrawals, &[], |_| true),
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
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &[],
            &close,
        );
        let predecessor_opening = fixture.cache.opening(&account.public_key()).unwrap();
        let successor_opening = successor.opening(&account.public_key()).unwrap();
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
                &[successor_opening.clone(), predecessor_opening.clone()],
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
                &[other, successor_opening.clone()],
                |_| true,
            ),
            Err(SettlementError::WithdrawalOpening)
        ));
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                1,
                request.clone(),
                &[predecessor_opening.clone(), successor_opening.clone()],
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
                &[predecessor_opening.clone(), successor_opening.clone()],
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
            .queue_withdrawal(
                1,
                request,
                &[predecessor_opening, successor_opening],
                |_| true,
            )
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
                    successor.opening(&account.public_key()).unwrap(),
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
    fn carried_withdrawal_clears_without_queueing() {
        let mut fixture = harness(&[10, 10]);
        let account = fixture.accounts[0].clone();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &account,
            b"exit",
            amount_action(4),
            9,
        );
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![request.clone()]).unwrap();
        assert_eq!(
            fixture.chain.pending_withdrawals(),
            WithdrawalBatch::empty()
        );
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
        let (close, successor) =
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
            5,
            close_context,
            deposits.clone(),
            withdrawals,
            &[fixture.cache.opening(&account.public_key()).unwrap()],
            &close,
        );
        assert_eq!(
            fixture
                .chain
                .unfinalized_withdrawal_deadline(&account.public_key()),
            Some(9)
        );
        assert_eq!(fixture.chain.finalize(8).unwrap().withdrawal_total, 4);
        let output = fixture.chain.claim_withdrawal(batch_id, &claim).unwrap();
        assert_withdrawal_output(&output, &request, 4);
        assert_eq!(
            fixture
                .chain
                .unfinalized_withdrawal_deadline(&account.public_key()),
            None
        );

        // Admission consumed the replay id, so the same authorization can
        // neither be re-queued nor carried again.
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                8,
                request.clone(),
                &[successor.opening(&account.public_key()).unwrap()],
                |_| true,
            ),
            Err(SettlementError::DuplicateWithdrawalAuthorization)
        ));
        let replay = WithdrawalBatch::new(vec![request]).unwrap();
        let replay_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &successor,
            &deposits,
            &replay,
            11,
            12,
        );
        assert!(matches!(
            fixture
                .chain
                .register_close(8, replay_context, replay, &[], |_| true),
            Err(SettlementError::DuplicateWithdrawalAuthorization)
        ));
    }

    #[test]
    fn carried_withdrawal_registration_gates_are_exact() {
        let mut fixture = harness(&[10, 10, 10]);
        let deposits = DepositBatch::empty();
        let queued_signer = fixture.accounts[1].clone();
        let extra_signer = fixture.accounts[0].clone();
        let fresh_signer = fixture.accounts[2].clone();
        let queued = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &queued_signer,
            b"queued",
            amount_action(2),
            9,
        );
        let opening = fixture.cache.opening(&queued_signer.public_key()).unwrap();
        fixture
            .chain
            .queue_withdrawal(3, queued.clone(), core::slice::from_ref(&opening), |_| true)
            .unwrap();

        // A batch that drops the chain-queued request never registers.
        let missing = WithdrawalBatch::new(vec![withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &extra_signer,
            b"extra",
            amount_action(4),
            9,
        )])
        .unwrap();
        let missing_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &missing,
            6,
            7,
        );
        assert!(matches!(
            fixture
                .chain
                .register_close(5, missing_context, missing, &[], |_| true),
            Err(SettlementError::WithdrawalWitness)
        ));

        // A carried deadline at the earliest finalizing tick (challenge
        // deadline + 1) cannot register: the inclusive expiry sweep would fault
        // on the exact tick the close first becomes finalizable.
        let horizon = WithdrawalBatch::new(vec![
            queued.clone(),
            withdrawal(
                fixture.deployment,
                fixture.cache.root(),
                &extra_signer,
                b"extra",
                amount_action(4),
                8,
            ),
        ])
        .unwrap();
        let horizon_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &horizon,
            6,
            7,
        );
        assert!(matches!(
            fixture
                .chain
                .register_close(4, horizon_context, horizon, &[], |_| true),
            Err(SettlementError::WithdrawalDeadlineTooSoon)
        ));

        // Notice bounds apply to carried requests at registration time.
        let late = WithdrawalBatch::new(vec![
            queued.clone(),
            withdrawal(
                fixture.deployment,
                fixture.cache.root(),
                &extra_signer,
                b"extra",
                amount_action(4),
                1_006,
            ),
        ])
        .unwrap();
        let late_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &late,
            6,
            7,
        );
        assert!(matches!(
            fixture
                .chain
                .register_close(5, late_context, late, &[], |_| true),
            Err(SettlementError::WithdrawalDeadlineTooLate)
        ));

        // The asset adapter's predicate gates carried destinations.
        let carried = WithdrawalBatch::new(vec![
            queued,
            withdrawal(
                fixture.deployment,
                fixture.cache.root(),
                &extra_signer,
                b"extra",
                amount_action(4),
                9,
            ),
        ])
        .unwrap();
        let carried_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &carried,
            6,
            7,
        );
        assert!(matches!(
            fixture.chain.register_close(
                5,
                carried_context,
                carried,
                &[],
                |destination: &Bytes| destination.as_ref() != b"extra".as_slice(),
            ),
            Err(SettlementError::IneligibleDestination)
        ));

        // The gates left nothing staged: the queued-only close still clears.
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
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            5,
            close_context,
            deposits.clone(),
            withdrawals,
            &[],
            &close,
        );

        // An account with an admitted-unfinalized withdrawal cannot carry another.
        let duplicate = WithdrawalBatch::new(vec![withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &queued_signer,
            b"again",
            amount_action(1),
            10,
        )])
        .unwrap();
        let duplicate_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &successor,
            &deposits,
            &duplicate,
            8,
            9,
        );
        assert!(matches!(
            fixture
                .chain
                .register_close(6, duplicate_context, duplicate, &[], |_| true),
            Err(SettlementError::DuplicateWithdrawal)
        ));

        // A carried request must bind the finalized root, not an unfinalized
        // successor.
        let stale = WithdrawalBatch::new(vec![withdrawal(
            fixture.deployment,
            successor.root(),
            &fresh_signer,
            b"fresh",
            amount_action(4),
            11,
        )])
        .unwrap();
        let stale_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &successor,
            &deposits,
            &stale,
            8,
            9,
        );
        assert!(matches!(
            fixture
                .chain
                .register_close(6, stale_context, stale, &[], |_| true),
            Err(SettlementError::Boundary(BoundaryError::WrongContext))
        ));

        // Every extra needs exactly one predecessor-root opening for its own
        // account: a registration is an immutable admission obligation, so an
        // unprovable extra cannot be allowed to wedge it.
        let valid = WithdrawalBatch::new(vec![withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &fresh_signer,
            b"fresh",
            amount_action(4),
            11,
        )])
        .unwrap();
        let valid_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &successor,
            &deposits,
            &valid,
            8,
            9,
        );
        let opening = successor.opening(&fresh_signer.public_key()).unwrap();
        assert!(matches!(
            fixture
                .chain
                .register_close(6, valid_context.clone(), valid.clone(), &[], |_| true,),
            Err(SettlementError::WithdrawalOpeningCount)
        ));
        assert!(matches!(
            fixture.chain.register_close(
                6,
                valid_context.clone(),
                valid.clone(),
                &[opening.clone(), opening.clone()],
                |_| true,
            ),
            Err(SettlementError::WithdrawalOpeningCount)
        ));
        assert!(matches!(
            fixture.chain.register_close(
                6,
                valid_context.clone(),
                valid.clone(),
                &[successor.opening(&queued_signer.public_key()).unwrap()],
                |_| true,
            ),
            Err(SettlementError::WithdrawalOpening)
        ));

        // A valid carried request registers once the gates pass.
        fixture
            .chain
            .register_close(6, valid_context, valid, &[opening], |_| true)
            .unwrap();
    }

    #[test]
    fn new_rejects_a_single_slot_pipeline() {
        let fixture = harness(&[10]);
        assert!(matches!(
            SettlementChain::<Sha256, VerifyingKey>::new(
                fixture.deployment,
                fixture.operator.public_key(),
                committee(206),
                &fixture.cache,
                0,
                config(1, 1),
            ),
            Err(SettlementError::PipelineDepthTooShallow)
        ));
        SettlementChain::<Sha256, VerifyingKey>::new(
            fixture.deployment,
            fixture.operator.public_key(),
            committee(206),
            &fixture.cache,
            0,
            config(2, 1),
        )
        .expect("a two-slot pipeline is accepted");
    }

    #[test]
    fn carried_amount_must_be_coverable_at_registration() {
        let mut fixture = harness(&[10, 10]);
        let signer = fixture.accounts[0].clone();

        // An amount the predecessor balance plus this close's deposit cannot
        // cover would seal an uncertifiable boundary. The deadline clears the
        // finalize horizon so the coverage check is what rejects it.
        let unaffordable = WithdrawalBatch::new(vec![withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &signer,
            b"exit",
            amount_action(11),
            11,
        )])
        .unwrap();
        let deposits = DepositBatch::empty();
        let unaffordable_epoch = EpochContext::new::<Sha256>(
            fixture.deployment,
            0,
            fixture.operator.public_key(),
            &deposits,
            &unaffordable,
            fixture.cache.liability(),
            6,
            8,
            CloseLimits::protocol_maximum(),
            Assignment::new(fixture.committee, 0).unwrap(),
        )
        .unwrap();
        let opening = fixture.cache.opening(&signer.public_key()).unwrap();
        assert!(matches!(
            fixture.chain.register_epoch(
                4,
                unaffordable_epoch,
                unaffordable,
                core::slice::from_ref(&opening),
                |_| true,
            ),
            Err(SettlementError::WithdrawalBalance)
        ));
    }

    #[test]
    fn carried_offset_defers_the_deposit_to_the_successor_close() {
        let mut fixture = harness(&[10, 10]);
        let signer = fixture.accounts[0].clone();

        // A deposit lands after the operator collected the exactly-offsetting
        // request. The close defers the deposit instead of sealing a no-op
        // row, so the registration composes gracefully.
        fixture
            .chain
            .record_deposit(4, Sha256::hash(&[b"offset-cover"]), signer.public_key(), 4)
            .unwrap();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &signer,
            b"exit",
            amount_action(4),
            9,
        );
        let offset = WithdrawalBatch::new(vec![request.clone()]).unwrap();
        let deferred = fixture.chain.boundary_deposits(&offset);
        assert_eq!(deferred, DepositBatch::empty());
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deferred,
            &offset,
            6,
            7,
        );
        let (close, successor) = boundary_close(&fixture.cache, &close_context, &deferred, &offset);
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &offset,
            &signer.public_key(),
            &Sequential,
        )
        .unwrap();
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            5,
            close_context,
            deferred,
            offset,
            &[fixture.cache.opening(&signer.public_key()).unwrap()],
            &close,
        );

        // The deferred deposit stays staged with its deadline intact and rides
        // the successor close.
        assert_eq!(
            fixture
                .chain
                .pending_deposits()
                .amount_for(&signer.public_key()),
            4
        );
        assert_eq!(fixture.chain.finalize(8).unwrap().withdrawal_total, 4);
        assert_withdrawal_output(
            &fixture.chain.claim_withdrawal(batch_id, &claim).unwrap(),
            &request,
            4,
        );

        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let successor_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &successor,
            &deposits,
            &withdrawals,
            11,
            12,
        );
        let (successor_close, settled) =
            boundary_close(&successor, &successor_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            9,
            successor_context,
            deposits,
            withdrawals,
            &[],
            &successor_close,
        );
        assert_eq!(
            fixture
                .chain
                .pending_deposits()
                .amount_for(&signer.public_key()),
            0
        );
        assert_eq!(
            settled
                .opening(&signer.public_key())
                .unwrap()
                .leaf
                .state
                .balance,
            10
        );
    }

    #[test]
    fn intake_limits_notice_and_clean_release_replay_are_exact() {
        let invalid_notice = SettlementConfig::new(
            NonZeroUsize::new(3).unwrap(),
            EpochDeadlinePolicy::new(
                NonZeroU64::new(1_000).unwrap(),
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(1_000).unwrap(),
            ),
            NonZeroU64::new(1_000).unwrap(),
            NonZeroU64::new(5).unwrap(),
            NonZeroU64::new(4).unwrap(),
            4,
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
            EpochDeadlinePolicy::new(
                NonZeroU64::new(1_000).unwrap(),
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(1_000).unwrap(),
            ),
            NonZeroU64::new(1_000).unwrap(),
            NonZeroU64::new(4).unwrap(),
            NonZeroU64::new(4).unwrap(),
            4,
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
                .unfinalized_withdrawal_deadline(&account.public_key()),
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
                .unfinalized_withdrawal_deadline(&account.public_key()),
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
        let (close, successor) =
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
            &[],
            &close,
        );
        assert_eq!(fixture.chain.finalize(8).unwrap().withdrawal_total, 2);
        let output = fixture.chain.claim_withdrawal(batch_id, &claim).unwrap();
        assert_withdrawal_output(&output, &request, 2);
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claim),
            Err(ClaimError::Unavailable | ClaimError::Consumed)
        ));
        assert_eq!(
            fixture
                .chain
                .unfinalized_withdrawal_deadline(&account.public_key()),
            None
        );
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                8,
                request.clone(),
                &[successor.opening(&account.public_key()).unwrap()],
                |_| true,
            ),
            Err(SettlementError::DuplicateWithdrawalAuthorization)
        ));
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                9,
                request,
                &[successor.opening(&account.public_key()).unwrap()],
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
            &successor,
            &deposits,
            &withdrawals,
            10,
            11,
        );
        let (close, _) = boundary_close(&successor, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            10,
            close_context,
            deposits,
            withdrawals,
            &[],
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
    fn expired_deposit_is_claimable_without_a_survivor() {
        let mut settlement_config = config(3, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
        let mut fixture = harness_with_config(&[], settlement_config);
        let account = SigningKey::from_seed(999).public_key();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"expiring-registered-deposit"]),
                account.clone(),
                7,
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
            6,
            7,
        );
        fixture
            .chain
            .register_close(1, close_context, withdrawals, &[], |_| true)
            .unwrap();
        assert!(matches!(
            fixture.chain.claim_pending_deposit(4, &account),
            Err(SettlementError::OperatorNotHardFaulted)
        ));
        assert_eq!(fixture.chain.pending_deposits().total(), 7);
        assert!(fixture.chain.hard_fault().is_none());

        let refund = fixture.chain.claim_pending_deposit(5, &account).unwrap();
        let reason = fixture.chain.hard_fault().cloned().unwrap();
        assert_eq!(
            reason,
            HardFaultReason::ExpiredDeposit {
                account: account.clone(),
                expired_at: 5,
            }
        );
        assert_eq!(
            refund,
            DepositRefund {
                account: account.clone(),
                amount: 7,
            }
        );
        assert!(matches!(
            fixture.chain.claim_pending_deposit(5, &account),
            Err(SettlementError::PendingDepositUnavailable)
        ));
        assert_eq!(fixture.chain.pending_deposits(), DepositBatch::empty());
        assert_eq!(fixture.chain.custody_balance(), 0);

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.reason, reason);
        assert_eq!(settlement.frozen_state_root, fixture.cache.root());
        assert_eq!(settlement.state_liability, 0);
        assert_eq!(settlement.unfinalized_deposit_total, 0);
        assert_eq!(settlement.custody_balance, 0);
        assert!(fixture.chain.hard_fault_is_settled());
        assert_eq!(fixture.chain.custody_balance(), 0);
    }

    #[test]
    fn admitted_deposit_discharges_its_inclusion_deadline() {
        let mut settlement_config = config(3, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(3).unwrap();
        let mut fixture = harness_with_config(&[], settlement_config);
        let account = SigningKey::from_seed(999).public_key();
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"included-before-deadline"]), account, 7)
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
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            2,
            close_context,
            deposits,
            withdrawals,
            &[],
            &close,
        );
        assert!(matches!(
            fixture.chain.fault_expired(3),
            Err(SettlementError::DeadlineNotReached)
        ));
        fixture.chain.finalize(5).unwrap();
        assert_eq!(fixture.chain.current_state_root(), successor.root());
    }

    #[test]
    fn same_account_deposits_keep_the_earliest_deadline() {
        let mut settlement_config = config(3, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
        let mut fixture = harness_with_config(&[], settlement_config);
        let account = SigningKey::from_seed(999).public_key();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"earlier-account-deposit"]),
                account.clone(),
                2,
            )
            .unwrap();
        fixture
            .chain
            .record_deposit(
                2,
                Sha256::hash(&[b"later-account-deposit"]),
                account.clone(),
                3,
            )
            .unwrap();

        assert_eq!(fixture.chain.pending_deposits().total(), 5);
        assert_eq!(
            fixture.chain.fault_expired(5).unwrap(),
            HardFaultReason::ExpiredDeposit {
                account,
                expired_at: 5,
            }
        );
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
            &[],
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
        let output = claim
            .verify::<Sha256>(&destroy.roots.withdrawal_outputs)
            .unwrap();
        assert_withdrawal_output(&output, &request, 9);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            4,
            destroy_context,
            deposits,
            withdrawals,
            &[],
            &destroy,
        );
        let finalized = fixture.chain.finalize(6).unwrap();
        assert_eq!(finalized.withdrawal_total, 9);
        assert_eq!(fixture.chain.claimable_balance(), 9);
        let output = fixture.chain.claim_withdrawal(batch_id, &claim).unwrap();
        assert_withdrawal_output(&output, &request, 9);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claim),
            Err(ClaimError::Unavailable | ClaimError::Consumed)
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
        let (close, successor) = external_payout_close(
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
            &[],
            &close,
        );
        assert_eq!(successor.liability(), 80);

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
            &[],
            &close,
        );

        assert!(matches!(
            fixture.chain.claim_external_payout(batch_id, &claim),
            Err(ClaimError::Unavailable)
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
            Err(ClaimError::Unavailable | ClaimError::Consumed)
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
        close.rows[position].output = SettlementOutput::Withdrawal(12);

        let mut builder =
            commitment::Builder::<Sha256>::new(VectorKind::Change, close.rows.len() as u32)
                .unwrap();
        let leaves = close
            .rows
            .iter()
            .zip(&close.shard_sets)
            .map(|(row, shards)| AccountChange::from_row::<Sha256>(row, shards).unwrap())
            .collect::<Vec<_>>();
        let guards = leaves
            .iter()
            .map(|leaf| leaf.guard::<Sha256>())
            .collect::<Vec<_>>();
        for guard in &guards {
            builder.add_encoded(guard.encode().as_ref()).unwrap();
        }
        let changes = builder.build(&Sequential).unwrap();
        let position = position as u32;
        let mut encoded = BytesMut::new();
        leaves[position as usize].write(&mut encoded);
        changes.opening(position).unwrap().write(&mut encoded);
        let mut encoded = encoded.freeze();
        let claim = ExternalPayoutClaim::<VerifyingKey, ShaDigest>::read(&mut encoded).unwrap();
        assert!(encoded.is_empty());

        let batch_id = BatchId::new(Sha256::hash(&[b"cross-reserve-payout-claim"]));
        fixture.chain.claimable_balance = 19;
        fixture.chain.claimable_batches.insert(
            batch_id,
            ClaimableBatch {
                change_root: changes.root(),
                withdrawal_outputs: close.roots.withdrawal_outputs,
                claimed_withdrawals: BTreeSet::new(),
                claimed_payouts: BTreeSet::new(),
                withdrawal_remaining: 12,
                payout_remaining: 7,
            },
        );

        assert!(matches!(
            fixture.chain.claim_external_payout(batch_id, &claim),
            Err(ClaimError::Proof(TransitionError::PayoutClaim))
        ));
        assert_eq!(fixture.chain.claimable_balance(), 19);
        let batch = fixture.chain.claimable_batches.get(&batch_id).unwrap();
        assert_eq!(batch.withdrawal_remaining, 12);
        assert_eq!(batch.payout_remaining, 7);
        assert!(batch.claimed_payouts.is_empty());
    }

    #[test]
    fn finalized_claim_batches_do_not_block_later_finalization() {
        let mut fixture = harness_with_states(&[state(100), state(100)], config(2, 1));
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
            let (close, successor) = external_payout_close(
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
                &[],
                &close,
            );

            fixture.chain.finalize(now + 2).unwrap();
            fixture.cache = successor;
        }

        assert_eq!(fixture.chain.pending_epoch_count(), 0);
        assert_eq!(fixture.chain.claimable_batches.len(), 2);
        assert_eq!(fixture.chain.claimable_balance(), 2);
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
            &[],
            &close,
        );
        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 7);
        assert_eq!(fixture.chain.claimable_balance(), 7);

        let destination = claims[1].output().destination();
        let mut malformed = claims[1].encode().to_vec();
        let destination_offset = malformed
            .windows(destination.len())
            .position(|window| window == destination.as_ref())
            .expect("the encoded claim contains its destination");
        malformed[destination_offset] ^= 1;
        let malformed =
            WithdrawalClaim::<ShaDigest>::decode_cfg(malformed.as_slice(), &(..=usize::MAX).into())
                .unwrap();
        assert_eq!(malformed.position(), claims[1].position());
        let claimable_before = fixture.chain.claimable_balance();
        let batch_before = fixture.chain.claimable_batches.get(&batch_id).unwrap();
        let reserve_before = batch_before.withdrawal_remaining;
        let consumed_before = batch_before.claimed_withdrawals.len();
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &malformed),
            Err(ClaimError::Proof(TransitionError::Commitment(_)))
        ));
        let batch_after = fixture.chain.claimable_batches.get(&batch_id).unwrap();
        assert_eq!(fixture.chain.claimable_balance(), claimable_before);
        assert_eq!(batch_after.withdrawal_remaining, reserve_before);
        assert_eq!(batch_after.claimed_withdrawals.len(), consumed_before);

        let output = fixture
            .chain
            .claim_withdrawal(batch_id, &claims[1])
            .unwrap();
        assert_withdrawal_output(&output, &queued[1].1, queued[1].3);
        assert_eq!(fixture.chain.claimable_balance(), queued[0].3);
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claims[1]),
            Err(ClaimError::Consumed)
        ));
        let output = fixture
            .chain
            .claim_withdrawal(batch_id, &claims[0])
            .unwrap();
        assert_withdrawal_output(&output, &queued[0].1, queued[0].3);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claims[0]),
            Err(ClaimError::Unavailable)
        ));
    }

    #[test]
    fn withdrawal_replay_key_includes_the_finalized_batch() {
        let mut fixture = harness(&[20]);
        let account = fixture.accounts[0].public_key();
        let first_request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &fixture.accounts[0],
            b"first-batch-destination",
            amount_action(3),
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                first_request.clone(),
                &[fixture.cache.opening(&account).unwrap()],
                |_| true,
            )
            .unwrap();
        let deposits = DepositBatch::empty();
        let first_withdrawals = fixture.chain.pending_withdrawals();
        let first_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &first_withdrawals,
            1,
            2,
        );
        let (first_close, first_successor) = boundary_close(
            &fixture.cache,
            &first_context,
            &deposits,
            &first_withdrawals,
        );
        let first_claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &first_close,
            &first_withdrawals,
            &account,
            &Sequential,
        )
        .unwrap();
        let first_batch = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            deposits.clone(),
            first_withdrawals,
            &[],
            &first_close,
        );
        fixture.chain.finalize(3).unwrap();
        fixture.cache = first_successor;

        let second_request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &fixture.accounts[0],
            b"second-batch-destination",
            amount_action(4),
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                3,
                second_request.clone(),
                &[fixture.cache.opening(&account).unwrap()],
                |_| true,
            )
            .unwrap();
        let second_withdrawals = fixture.chain.pending_withdrawals();
        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &deposits,
            &second_withdrawals,
            4,
            5,
        );
        let (second_close, second_successor) = boundary_close(
            &fixture.cache,
            &second_context,
            &deposits,
            &second_withdrawals,
        );
        let second_claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &second_close,
            &second_withdrawals,
            &account,
            &Sequential,
        )
        .unwrap();
        let second_batch = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            4,
            second_context,
            deposits,
            second_withdrawals,
            &[],
            &second_close,
        );
        fixture.chain.finalize(6).unwrap();
        fixture.cache = second_successor;
        assert_eq!(first_claim.position(), 0);
        assert_eq!(second_claim.position(), 0);
        assert_eq!(fixture.chain.claimable_balance(), 7);

        assert!(matches!(
            fixture.chain.claim_withdrawal(second_batch, &first_claim),
            Err(ClaimError::Proof(_))
        ));
        assert_eq!(fixture.chain.claimable_balance(), 7);
        assert_withdrawal_output(
            &fixture
                .chain
                .claim_withdrawal(first_batch, &first_claim)
                .unwrap(),
            &first_request,
            3,
        );
        assert!(matches!(
            fixture.chain.claim_withdrawal(first_batch, &first_claim),
            Err(ClaimError::Unavailable)
        ));
        assert_withdrawal_output(
            &fixture
                .chain
                .claim_withdrawal(second_batch, &second_claim)
                .unwrap(),
            &second_request,
            4,
        );
        assert!(matches!(
            fixture.chain.claim_withdrawal(second_batch, &second_claim),
            Err(ClaimError::Unavailable)
        ));
        assert_eq!(fixture.chain.claimable_balance(), 0);
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
            &[],
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
        let (first, first_successor) = external_payout_close(
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
            &[],
            &first,
        );
        fixture.chain.finalize(3).unwrap();
        fixture.cache = first_successor;
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
            &[],
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
                .challenge(8, second_id, &Challenge::receipt_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.custody_balance, 100);
        assert_eq!(
            claim_frozen_state(&mut fixture.chain, &fixture.cache)
                .iter()
                .map(|release| release.released_custody)
                .sum::<u64>(),
            100
        );
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
    fn finalized_withdrawal_reserve_survives_descendant_hard_fault() {
        let mut fixture = harness(&[10, 10, 10]);
        let account = fixture.accounts[0].public_key();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &fixture.accounts[0],
            b"surviving-finalized-withdrawal",
            amount_action(4),
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &[fixture.cache.opening(&account).unwrap()],
                |_| true,
            )
            .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let first_context = context(
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
        let (first, first_successor) =
            boundary_close(&fixture.cache, &first_context, &deposits, &withdrawals);
        let claim =
            assemble_withdrawal_claim::<Sha256, _, _>(&first, &withdrawals, &account, &Sequential)
                .unwrap();
        let first_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            first_context,
            deposits.clone(),
            withdrawals,
            &[],
            &first,
        );
        fixture.chain.finalize(3).unwrap();
        fixture.cache = first_successor;
        assert_eq!(fixture.chain.custody_balance(), 26);
        assert_eq!(fixture.chain.claimable_balance(), 4);

        let no_withdrawals = WithdrawalBatch::empty();
        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.cache,
            &deposits,
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
            deposits,
            no_withdrawals,
            &[],
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
                .challenge(8, second_id, &Challenge::receipt_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.custody_balance, 26);
        assert_eq!(
            claim_frozen_state(&mut fixture.chain, &fixture.cache)
                .iter()
                .map(|release| release.released_custody)
                .sum::<u64>(),
            26
        );
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(fixture.chain.claimable_balance(), 4);
        assert!(matches!(
            fixture.chain.claim_withdrawal(second_id, &claim),
            Err(ClaimError::Unavailable)
        ));
        assert_eq!(fixture.chain.claimable_balance(), 4);
        assert_withdrawal_output(
            &fixture.chain.claim_withdrawal(first_id, &claim).unwrap(),
            &request,
            4,
        );
        assert!(matches!(
            fixture.chain.claim_withdrawal(first_id, &claim),
            Err(ClaimError::Unavailable)
        ));
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
            &[],
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
            &[],
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
                .challenge(8, second_id, &Challenge::receipt_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        let finalized = fixture.chain.finalize(8).unwrap();
        assert_eq!(finalized.payout_total, 0);
        assert_eq!(finalized.custody_balance, 120);
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.custody_balance, 120);
        let releases = claim_frozen_state(&mut fixture.chain, &fixture.cache);
        assert_eq!(
            releases
                .iter()
                .map(|release| release.released_custody)
                .sum::<u64>(),
            120
        );
        assert!(
            releases
                .iter()
                .all(|release| release.account != recipient.public_key())
        );
    }

    #[test]
    fn invalidated_descendant_send_returns_the_payer_to_the_clean_prefix() {
        let mut fixture = harness(&[100, 10, 10]);
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
            &[],
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
            2,
            second_context.clone(),
            deposits.clone(),
            withdrawals.clone(),
            &[],
            &second,
        );

        let third_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            2,
            &fixture.cache,
            &deposits,
            &withdrawals,
            4,
            10,
        );
        let external = SigningKey::from_seed(1_003);
        let (third, _) = external_payout_close(
            &fixture.cache,
            &third_context,
            &fixture.operator,
            &fixture.accounts[0],
            &external,
            20,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            3,
            third_context,
            deposits,
            withdrawals,
            &[],
            &third,
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
                .challenge(8, second_id, &Challenge::receipt_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );
        assert_eq!(fixture.chain.finalize(8).unwrap().epoch, 0);

        let terminal = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(terminal.frozen_state_root, fixture.cache.root());
        assert_eq!(fixture.chain.claimable_balance(), 0);
        let payer = fixture.accounts[0].public_key();
        let release = fixture
            .chain
            .claim_hard_fault(&fixture.cache.opening(&payer).unwrap())
            .unwrap();
        assert_eq!(release.residual, 100);
        assert_eq!(release.released_custody, 100);
        assert!(release.withdrawal.is_none());
        for account in &fixture.accounts[1..] {
            fixture
                .chain
                .claim_hard_fault(&fixture.cache.opening(&account.public_key()).unwrap())
                .unwrap();
        }
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert!(fixture.chain.hard_fault_is_settled());
    }

    #[test]
    fn omitted_acknowledged_send_returns_the_payer_to_the_finalized_state() {
        let mut fixture = harness(&[10, 20]);
        let payer = &fixture.accounts[0];
        let recipient = &fixture.accounts[1];
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
            4,
        );
        let acknowledged = fork_payment(&close_context, &fixture.operator, payer, recipient, 3);
        let close = empty_close(&fixture.cache, &close_context);
        let index = ChallengeIndex::new::<Sha256>(&close_context, &close).unwrap();
        let payer_lookup = index
            .account_lookup(&fixture.cache, &payer.public_key())
            .unwrap();
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &[],
            &close,
        );

        assert_eq!(
            fixture
                .chain
                .challenge(
                    4,
                    batch_id,
                    &Challenge::LatestAcknowledgedSend {
                        payment: Box::new(PaymentWitness::from_payment(&acknowledged)),
                        payer: Box::new(payer_lookup),
                    },
                )
                .unwrap(),
            Verdict::Proven(ChallengeKind::LatestAcknowledgedSend)
        );
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.frozen_state_root, fixture.cache.root());
        assert_eq!(settlement.custody_balance, 30);
        assert_eq!(fixture.chain.claimable_balance(), 0);

        let payer_opening = fixture.cache.opening(&payer.public_key()).unwrap();
        let payer_release = fixture.chain.claim_hard_fault(&payer_opening).unwrap();
        assert!(payer_release.withdrawal.is_none());
        assert_eq!(payer_release.residual, 10);
        assert_eq!(payer_release.released_custody, 10);
        assert!(matches!(
            fixture.chain.claim_hard_fault(&payer_opening),
            Err(SettlementError::ClaimAlreadyConsumed)
        ));
        let recipient_release = fixture
            .chain
            .claim_hard_fault(&fixture.cache.opening(&recipient.public_key()).unwrap())
            .unwrap();
        assert_eq!(recipient_release.residual, 20);
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert!(fixture.chain.hard_fault_is_settled());
    }

    #[test]
    fn inconsistent_receipt_range_fault_releases_the_frozen_sender() {
        let mut fixture = harness(&[10, 20]);
        let payer = &fixture.accounts[0];
        let recipient = &fixture.accounts[1];
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
            4,
        );
        let close = empty_close(&fixture.cache, &close_context);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &[],
            &close,
        );
        let send =
            SignedSend::sign_next(close_context.payment(), payer, recipient.public_key(), 5, 0)
                .unwrap();
        let receipt = SignedReceipt::sign_body_by_authority(
            ReceiptBody::from_raw_unchecked(
                *close_context.payment().anchor(),
                close_context.payment().epoch(),
                recipient.public_key(),
                0,
                5,
                send.tx_id::<Sha256>(),
                4,
                1,
            ),
            &fixture.operator,
        );
        let impossible = Payment::new::<Sha256>(close_context.payment(), send, receipt).unwrap();

        assert_eq!(
            fixture
                .chain
                .challenge(
                    4,
                    batch_id,
                    &Challenge::InconsistentReceiptRange {
                        upper: Box::new(PaymentWitness::from_payment(&impossible)),
                        lower: RangeLower::ShardStart,
                    },
                )
                .unwrap(),
            Verdict::Proven(ChallengeKind::InconsistentReceiptRange)
        );
        assert_eq!(
            fixture.chain.hard_fault(),
            Some(&HardFaultReason::ProvenChallenge {
                batch_id,
                kind: ChallengeKind::InconsistentReceiptRange,
            })
        );

        let terminal = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(terminal.frozen_state_root, fixture.cache.root());
        let payer_opening = fixture.cache.opening(&payer.public_key()).unwrap();
        let release = fixture.chain.claim_hard_fault(&payer_opening).unwrap();
        assert_eq!(release.residual, 10);
        assert_eq!(release.released_custody, 10);
        assert!(release.withdrawal.is_none());
        let recipient_opening = fixture.cache.opening(&recipient.public_key()).unwrap();
        fixture.chain.claim_hard_fault(&recipient_opening).unwrap();
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert!(fixture.chain.hard_fault_is_settled());
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
            &[],
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
            &[],
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
            &[],
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
            &[],
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
        let challenge = Challenge::receipt_fork(&left, &right);
        assert_eq!(
            fixture.chain.challenge(8, second_id, &challenge).unwrap(),
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
            &[],
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
            &[],
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
            &[],
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
                .challenge(8, middle_id, &Challenge::receipt_fork(&left, &right))
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
            fixture.chain.begin_hard_fault_settlement(),
            Err(SettlementError::PreFaultBatchPending)
        ));

        assert_eq!(fixture.chain.finalize(8).unwrap().epoch, 0);
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        let residuals = claim_frozen_state(&mut fixture.chain, &fixture.cache)
            .into_iter()
            .map(|release| (release.account, release.residual))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            residuals,
            BTreeMap::from([
                (middle_account.clone(), 10),
                (descendant_account.clone(), 20),
                (fixture.accounts[2].public_key(), 30),
            ])
        );
        assert_eq!(settlement.state_liability, 60);
        assert_eq!(settlement.unfinalized_deposit_total, 8);
        assert_eq!(settlement.custody_balance, 68);
        assert_eq!(
            fixture
                .chain
                .claim_pending_deposit(8, &middle_account)
                .unwrap(),
            DepositRefund {
                account: middle_account,
                amount: 3,
            }
        );
        assert_eq!(
            fixture
                .chain
                .claim_pending_deposit(8, &descendant_account)
                .unwrap(),
            DepositRefund {
                account: descendant_account,
                amount: 5,
            }
        );
        assert_eq!(settlement.invalid_from, Some(middle_id));
        assert!(matches!(
            settlement.reason,
            HardFaultReason::ProvenChallenge {
                batch_id,
                kind: ChallengeKind::ReceiptFork,
            } if batch_id == middle_id
        ));
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(fixture.chain.pending_epoch_count(), 0);
        assert!(fixture.chain.hard_fault_is_settled());
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
            fixture.chain.fault_expired(4),
            Err(SettlementError::DeadlineNotReached)
        ));
        let first_reason = fixture.chain.fault_expired(5).unwrap();
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
                .challenge(8, third_id, &Challenge::receipt_fork(&left, &right))
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
            fixture.chain.begin_hard_fault_settlement(),
            Err(SettlementError::PreFaultBatchPending)
        ));

        assert_eq!(fixture.chain.finalize(8).unwrap().epoch, 0);
        assert_eq!(fixture.chain.hard_fault(), Some(&first_reason));
        assert!(matches!(
            fixture.chain.begin_hard_fault_settlement(),
            Err(SettlementError::PreFaultBatchPending)
        ));
        assert_eq!(fixture.chain.finalize(8).unwrap().epoch, 1);
        assert_eq!(fixture.chain.hard_fault(), Some(&first_reason));

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.reason, first_reason);
        assert_eq!(settlement.admission_fence_epoch, 3);
        assert_eq!(settlement.invalid_from, Some(third_id));
        assert_eq!(settlement.custody_balance, 30);
        assert_eq!(
            claim_frozen_state(&mut fixture.chain, &fixture.cache)
                .iter()
                .map(|release| release.released_custody)
                .sum::<u64>(),
            30
        );
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
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &[],
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
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert_eq!(fixture.chain.custody_balance(), 18);
        assert_eq!(fixture.chain.pending_deposits().total(), 3);
    }

    #[test]
    fn settlement_adds_no_account_limit_below_the_protocol_limit() {
        let mut fixture = harness_with_config(&[10], config(3, 2));
        let created = SigningKey::from_seed(999).public_key();
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"successor-state-capacity"]), created, 1)
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
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        assert_eq!(successor.leaves().len(), 2);
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
            .register_close(1, close_context, withdrawals, &[], |_| true)
            .unwrap();

        fixture
            .chain
            .admit(1, close.header, close.roots, terminal_proof, certificate)
            .unwrap();
        assert_eq!(fixture.chain.pending_epoch_count(), 1);
        assert_eq!(fixture.chain.pending_deposits(), DepositBatch::empty());
        assert_eq!(fixture.chain.custody_balance(), 11);
        fixture.chain.finalize(4).unwrap();
        assert_eq!(fixture.chain.current_state_root(), successor.root());
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
        let (close, successor) =
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
            &[],
            &close,
        );

        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 10);
        assert_eq!(finalized.custody_balance, 0);
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert!(successor.leaves().is_empty());
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
        let (close, successor) = internal_payment_and_close(
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
        let output = claim
            .verify::<Sha256>(&close.roots.withdrawal_outputs)
            .unwrap();
        assert_eq!(
            output.destination(),
            &Bytes::from_static(b"zero-tail-close")
        );
        assert_eq!(output.amount(), 0);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &[],
            &close,
        );

        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 0);
        assert_eq!(finalized.payout_total, 0);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert!(matches!(
            fixture.chain.claim_withdrawal(batch_id, &claim),
            Err(ClaimError::Unavailable)
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
        fixture.chain.fault_expired(2).unwrap();

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.state_liability, 10);
        assert_eq!(settlement.unfinalized_deposit_total, 7);
        assert_eq!(settlement.custody_balance, 17);
        let release = fixture
            .chain
            .claim_hard_fault(&fixture.cache.opening(&public_key).unwrap())
            .unwrap();
        assert_withdrawal_output(release.withdrawal.as_ref().unwrap(), &request, 10);
        assert_eq!(release.residual, 0);
        assert_eq!(
            fixture.chain.claim_pending_deposit(2, &public_key).unwrap(),
            DepositRefund {
                account: public_key,
                amount: 7,
            }
        );
        assert!(fixture.chain.hard_fault_is_settled());
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
            let (close, successor) =
                boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
            assert_eq!(close.rows.last().unwrap().prefix.withdrawal, 17);
            register_and_admit(
                &mut fixture.chain,
                &fixture.signer,
                1,
                close_context,
                deposits,
                withdrawals,
                &[],
                &close,
            );

            let finalized = fixture.chain.finalize(3).unwrap();
            assert_eq!(finalized.withdrawal_total, 17);
            assert_eq!(finalized.custody_balance, 0);
            assert_eq!(fixture.chain.current_state_root(), successor.root());
            assert!(successor.leaves().is_empty());
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
        let (first_close, first_successor) = boundary_close(
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
            &[],
            &first_close,
        );

        let first_finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(first_finalized.withdrawal_total, 4);
        assert_eq!(first_finalized.custody_balance, 10);
        assert_eq!(first_successor.leaves()[0].state.balance, 6);
        assert_eq!(fixture.chain.pending_deposits().total(), 4);

        let second_deposits = fixture.chain.pending_deposits();
        let second_withdrawals = fixture.chain.pending_withdrawals();
        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &first_successor,
            &second_deposits,
            &second_withdrawals,
            4,
            5,
        );
        let (second_close, second_successor) = boundary_close(
            &first_successor,
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
            &[],
            &second_close,
        );

        let second_finalized = fixture.chain.finalize(6).unwrap();
        assert_eq!(second_finalized.withdrawal_total, 0);
        assert_eq!(second_finalized.custody_balance, 10);
        assert_eq!(second_successor.leaves()[0].state.balance, 10);
        assert_eq!(fixture.chain.pending_deposits(), DepositBatch::empty());
    }

    #[test]
    fn exactly_offset_deposit_keeps_its_deadline_until_the_successor() {
        let mut settlement_config = config(3, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
        let mut fixture = harness_with_config(&[10], settlement_config);
        let account = &fixture.accounts[0];
        let public_key = account.public_key();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"deferred-deposit-deadline"]),
                public_key.clone(),
                4,
            )
            .unwrap();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"deferred-deposit-withdrawal",
            amount_action(4),
            100,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request,
                &[fixture.cache.opening(&public_key).unwrap()],
                |_| true,
            )
            .unwrap();

        let deposits = fixture.chain.pending_deposits();
        let withdrawals = fixture.chain.pending_withdrawals();
        assert!(deposits.is_empty());
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
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            close_context,
            deposits,
            withdrawals,
            &[],
            &close,
        );
        fixture.chain.finalize(3).unwrap();
        assert_eq!(fixture.chain.pending_deposits().total(), 4);

        assert_eq!(
            fixture.chain.fault_expired(5).unwrap(),
            HardFaultReason::ExpiredDeposit {
                account: public_key.clone(),
                expired_at: 5,
            }
        );
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.state_liability, 6);
        assert_eq!(settlement.unfinalized_deposit_total, 4);
        assert_eq!(settlement.custody_balance, 10);
        let release = fixture
            .chain
            .claim_hard_fault(&successor.opening(&public_key).unwrap())
            .unwrap();
        assert!(release.withdrawal.is_none());
        assert_eq!(release.residual, 6);
        assert_eq!(
            fixture.chain.claim_pending_deposit(5, &public_key).unwrap(),
            DepositRefund {
                account: public_key,
                amount: 4,
            }
        );
        assert_eq!(fixture.chain.claimable_balance(), 4);
    }

    #[test]
    fn withdrawal_wins_an_equal_deposit_expiry_tie() {
        let mut settlement_config = config(3, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
        let mut fixture = harness_with_config(&[10, 10], settlement_config);
        let withdrawing = &fixture.accounts[0];
        let depositing = fixture.accounts[1].public_key();
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"equal-expiry-deposit"]), depositing, 1)
            .unwrap();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            withdrawing,
            b"equal-expiry-withdrawal",
            amount_action(1),
            5,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request,
                &[fixture.cache.opening(&withdrawing.public_key()).unwrap()],
                |_| true,
            )
            .unwrap();

        assert_eq!(
            fixture.chain.fault_expired(5).unwrap(),
            HardFaultReason::ExpiredWithdrawal {
                account: withdrawing.public_key(),
                expired_at: 5,
            }
        );
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
        fixture.chain.fault_expired(2).unwrap();

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.state_liability, 10);
        let release = fixture
            .chain
            .claim_hard_fault(&fixture.cache.opening(&source.public_key()).unwrap())
            .unwrap();
        assert_eq!(request.body().action(), &WithdrawalAction::Close);
        assert_withdrawal_output(release.withdrawal.as_ref().unwrap(), &request, 10);
        assert_eq!(release.residual, 0);
        assert_eq!(release.released_custody, 10);
    }

    #[test]
    fn terminal_claims_are_atomic_retryable_exact_and_permanent() {
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
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(
            fixture.chain.begin_hard_fault_settlement().unwrap(),
            settlement
        );
        assert_eq!(settlement.state_liability, 15);
        assert_eq!(settlement.unfinalized_deposit_total, 2);
        assert_eq!(settlement.custody_balance, 17);
        assert!(matches!(
            fixture
                .chain
                .claim_hard_fault(&malformed.opening(&source.public_key()).unwrap()),
            Err(SettlementError::Commitment(_))
        ));
        assert!(!fixture.chain.hard_fault_is_settled());
        assert_eq!(fixture.chain.custody_balance(), 17);
        assert_eq!(fixture.chain.pending_deposits(), DepositBatch::empty());
        assert_eq!(
            fixture
                .chain
                .unfinalized_withdrawal_deadline(&source.public_key()),
            None
        );

        let source_opening = fixture.cache.opening(&source.public_key()).unwrap();
        let release = fixture.chain.claim_hard_fault(&source_opening).unwrap();
        let withdrawal = release.withdrawal.as_ref().unwrap();
        assert_eq!(
            withdrawal.destination(),
            &Bytes::from_static(b"opaque-adapter-destination")
        );
        assert_eq!(withdrawal.amount(), 4);
        assert_eq!(release.residual, 6);
        assert_eq!(release.released_custody, 10);
        assert!(matches!(
            fixture.chain.claim_hard_fault(&source_opening),
            Err(SettlementError::ClaimAlreadyConsumed)
        ));

        let release = fixture
            .chain
            .claim_hard_fault(
                &fixture
                    .cache
                    .opening(&fixture.accounts[1].public_key())
                    .unwrap(),
            )
            .unwrap();
        assert!(release.withdrawal.is_none());
        assert_eq!(release.residual, 5);
        assert_eq!(release.released_custody, 5);
        assert_eq!(
            fixture
                .chain
                .claim_pending_deposit(3, &deposited.public_key())
                .unwrap(),
            DepositRefund {
                account: deposited.public_key(),
                amount: 2,
            }
        );
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(
            fixture.chain.current_state_root(),
            commitment::empty_root::<Sha256>(VectorKind::State)
        );
        assert!(matches!(
            fixture.chain.begin_hard_fault_settlement(),
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
    fn deposit_intake_preserves_a_post_inclusion_exit_epoch() {
        let fixture = harness(&[1]);
        let mut chain = SettlementChain::<Sha256, VerifyingKey>::new(
            fixture.deployment,
            fixture.operator.public_key(),
            committee(205),
            &fixture.cache,
            u64::MAX - 2,
            config(2, 1),
        )
        .unwrap();
        let deposit_id = Sha256::hash(&[b"post-inclusion-exit-horizon"]);

        assert!(matches!(
            chain.record_deposit(0, deposit_id, fixture.accounts[0].public_key(), 1,),
            Err(SettlementError::EpochOverflow)
        ));
        assert_eq!(chain.custody_balance(), 1);
        assert_eq!(chain.pending_deposits(), DepositBatch::empty());
        assert!(chain.hard_fault().is_none());
    }

    #[test]
    fn exact_offset_deferral_preserves_a_post_inclusion_exit_epoch() {
        let deposit_first = harness(&[10]);
        let account = &deposit_first.accounts[0];
        let public_key = account.public_key();
        let mut chain = SettlementChain::<Sha256, VerifyingKey>::new(
            deposit_first.deployment,
            deposit_first.operator.public_key(),
            committee(206),
            &deposit_first.cache,
            u64::MAX - 3,
            config(2, 1),
        )
        .unwrap();
        chain
            .record_deposit(
                0,
                Sha256::hash(&[b"deposit-first-horizon"]),
                public_key.clone(),
                1,
            )
            .unwrap();
        let request = withdrawal(
            deposit_first.deployment,
            deposit_first.cache.root(),
            account,
            b"deposit-first-horizon",
            amount_action(1),
            2,
        );
        assert!(matches!(
            chain.queue_withdrawal(
                0,
                request,
                &[deposit_first.cache.opening(&public_key).unwrap()],
                |_| true,
            ),
            Err(SettlementError::EpochOverflow)
        ));
        assert_eq!(chain.pending_deposits().total(), 1);
        assert_eq!(chain.pending_withdrawals(), WithdrawalBatch::empty());

        let withdrawal_first = harness(&[10]);
        let account = &withdrawal_first.accounts[0];
        let public_key = account.public_key();
        let mut chain = SettlementChain::<Sha256, VerifyingKey>::new(
            withdrawal_first.deployment,
            withdrawal_first.operator.public_key(),
            committee(207),
            &withdrawal_first.cache,
            u64::MAX - 3,
            config(2, 1),
        )
        .unwrap();
        let request = withdrawal(
            withdrawal_first.deployment,
            withdrawal_first.cache.root(),
            account,
            b"withdrawal-first-horizon",
            amount_action(1),
            2,
        );
        chain
            .queue_withdrawal(
                0,
                request,
                &[withdrawal_first.cache.opening(&public_key).unwrap()],
                |_| true,
            )
            .unwrap();
        let deposit_id = Sha256::hash(&[b"withdrawal-first-horizon"]);
        assert!(matches!(
            chain.record_deposit(0, deposit_id, public_key.clone(), 1),
            Err(SettlementError::EpochOverflow)
        ));
        assert_eq!(chain.pending_deposits(), DepositBatch::empty());
        chain.record_deposit(0, deposit_id, public_key, 2).unwrap();
        assert_eq!(chain.pending_deposits().total(), 2);
        assert!(chain.hard_fault().is_none());
    }

    #[test]
    fn intake_stops_before_the_last_representable_close() {
        let deposit_fixture = harness(&[1]);
        let mut deposit_chain = SettlementChain::<Sha256, VerifyingKey>::new(
            deposit_fixture.deployment,
            deposit_fixture.operator.public_key(),
            committee(202),
            &deposit_fixture.cache,
            u64::MAX - 1,
            config(2, 1),
        )
        .unwrap();
        assert!(matches!(
            deposit_chain.record_deposit(
                0,
                Sha256::hash(&[b"exhausted-epoch-deposit"]),
                deposit_fixture.accounts[0].public_key(),
                1,
            ),
            Err(SettlementError::EpochOverflow)
        ));
        assert_eq!(deposit_chain.custody_balance(), 1);
        assert_eq!(deposit_chain.pending_deposits(), DepositBatch::empty());

        let withdrawal_fixture = harness(&[1]);
        let mut withdrawal_chain = SettlementChain::<Sha256, VerifyingKey>::new(
            withdrawal_fixture.deployment,
            withdrawal_fixture.operator.public_key(),
            committee(203),
            &withdrawal_fixture.cache,
            u64::MAX - 1,
            config(2, 1),
        )
        .unwrap();
        let request = withdrawal(
            withdrawal_fixture.deployment,
            withdrawal_fixture.cache.root(),
            &withdrawal_fixture.accounts[0],
            b"exhausted-epoch-withdrawal",
            amount_action(1),
            2,
        );
        assert!(matches!(
            withdrawal_chain.queue_withdrawal(
                0,
                request,
                &[withdrawal_fixture
                    .cache
                    .opening(&withdrawal_fixture.accounts[0].public_key())
                    .unwrap()],
                |_| true,
            ),
            Err(SettlementError::EpochOverflow)
        ));
        assert_eq!(
            withdrawal_chain.pending_withdrawals(),
            WithdrawalBatch::empty()
        );
    }

    #[test]
    fn partial_withdrawal_can_finish_with_the_last_finalizable_close() {
        let mut fixture = harness(&[2]);
        fixture.chain.expected_epoch = u64::MAX - 2;
        let account = &fixture.accounts[0];
        let public_key = account.public_key();
        let partial = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"penultimate-partial-withdrawal",
            amount_action(1),
            20,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                partial,
                &[fixture.cache.opening(&public_key).unwrap()],
                |_| true,
            )
            .unwrap();

        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let partial_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            u64::MAX - 2,
            &fixture.cache,
            &deposits,
            &withdrawals,
            1,
            2,
        );
        let (partial_close, partial_successor) =
            boundary_close(&fixture.cache, &partial_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            1,
            partial_context,
            deposits,
            withdrawals,
            &[],
            &partial_close,
        );
        fixture.chain.finalize(3).unwrap();
        assert_eq!(partial_successor.leaves()[0].state.balance, 1);

        let close = withdrawal(
            fixture.deployment,
            partial_successor.root(),
            account,
            b"last-finalizable-close",
            WithdrawalAction::Close,
            20,
        );
        fixture
            .chain
            .queue_withdrawal(
                3,
                close,
                &[partial_successor.opening(&public_key).unwrap()],
                |_| true,
            )
            .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = fixture.chain.pending_withdrawals();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            u64::MAX - 1,
            &partial_successor,
            &deposits,
            &withdrawals,
            4,
            5,
        );
        let (close, successor) =
            boundary_close(&partial_successor, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            4,
            close_context,
            deposits,
            withdrawals,
            &[],
            &close,
        );
        fixture.chain.finalize(6).unwrap();
        assert!(successor.is_empty());
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert!(fixture.chain.hard_fault().is_none());
    }

    #[test]
    fn deposit_rejects_combined_holdings_overflow_atomically() {
        let mut fixture = harness(&[u64::MAX]);
        let account = &fixture.accounts[0];
        let public_key = account.public_key();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            account,
            b"maximum-reserve",
            amount_action(u64::MAX),
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request,
                &[fixture.cache.opening(&public_key).unwrap()],
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
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &public_key,
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
            &[],
            &close,
        );
        fixture.chain.finalize(3).unwrap();
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(fixture.chain.claimable_balance(), u64::MAX);

        let deposit_id = Sha256::hash(&[b"combined-holdings-overflow"]);
        let recipient = SigningKey::from_seed(999).public_key();
        assert!(matches!(
            fixture
                .chain
                .record_deposit(3, deposit_id, recipient.clone(), 1),
            Err(SettlementError::CustodyArithmetic)
        ));
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(fixture.chain.claimable_balance(), u64::MAX);
        assert_eq!(fixture.chain.pending_deposits(), DepositBatch::empty());
        assert!(fixture.chain.hard_fault().is_none());

        fixture.chain.claim_withdrawal(batch_id, &claim).unwrap();
        fixture
            .chain
            .record_deposit(3, deposit_id, recipient, 1)
            .unwrap();
        assert_eq!(fixture.chain.custody_balance(), 1);
        assert_eq!(fixture.chain.pending_deposits().total(), 1);
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

        let mut settlement_config = config(2, 1);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
        let deadline_harness = harness(&[1]);
        let mut deposit_deadline_chain = SettlementChain::<Sha256, VerifyingKey>::new(
            deadline_harness.deployment,
            deadline_harness.operator.public_key(),
            committee(204),
            &deadline_harness.cache,
            0,
            settlement_config,
        )
        .unwrap();
        assert!(matches!(
            deposit_deadline_chain.record_deposit(
                u64::MAX - 4,
                Sha256::hash(&[b"deposit-deadline-overflow"]),
                deadline_harness.accounts[0].public_key(),
                1,
            ),
            Err(SettlementError::DepositDeadlineOverflow)
        ));
        assert_eq!(deposit_deadline_chain.custody_balance(), 1);
        assert_eq!(
            deposit_deadline_chain.pending_deposits(),
            DepositBatch::empty()
        );

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
                config(2, 1),
            ),
            Err(SettlementError::EpochOverflow)
        ));
    }

    mod refinement {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/stateright/refinement.rs"
        ));
    }
}
