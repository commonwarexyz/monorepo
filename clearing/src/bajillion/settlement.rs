//! Close admission, challenge timing, custody, and terminal settlement.
//!
//! # Integration contract
//!
//! This module is a runtime-agnostic in-memory transition primitive, not a persistence or asset
//! adapter. The embedding settlement environment must commit each state mutation and its returned
//! custody effects atomically and idempotently. Every public mutation that accepts `now` first
//! observes expired liveness deadlines. That permanent fence can be the method's only state
//! change even when the requested operation returns an error. Callers must therefore provide one
//! authenticated, monotonic clock and persist mutation-on-error results. [`SettlementChain`]
//! implements the codec traits for that persistence, and its [`Read`] impl states the decode
//! integrity contract the embedding must establish.
//!
//! Deposits and chain-queued withdrawals receive consecutive inbox indices. Settlement retains
//! chain-queued requests, per-account deposit totals, and deposit deadlines, but not individual
//! deposits. The embedding stores each deposit under `(deployment, index)` and supplies the
//! aggregate of a pulled prefix at registration.
//!
//! Queued deposits can be returned directly to their fixed accounts after a permanent fault,
//! without a surviving-state witness. Terminal settlement freezes the last finalized state root.
//! Each surviving account then consumes one authenticated opening independently. Starting
//! terminal settlement only traverses the admitted pipeline to recover unfinalized
//! deposits and withdrawals. Deposit replay state is retained for the deployment lifetime.
//! Reaching its limit safely rejects new deposits.
//! Withdrawal replay identifiers are retained only through the configured maximum deadline.

use crate::bajillion::{
    admission::{Committee, bls12381},
    boundary::{
        BoundaryError, DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch,
        WithdrawalId,
    },
    challenge::{self, Challenge, ChallengeError, ChallengeKind, Verdict},
    commitment,
    logs::{Floors, Heads, LogHead},
    qmdb::{self, StateOpening, StateRoot},
    transition::{
        self, BatchId, CloseContext, EpochContext, Header, RootBundle, TransitionError,
        WithdrawalClaim, WithdrawalOutput,
    },
};
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};
use bytes::{BufMut, Bytes, BytesMut};
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::merkle::{Family as _, mmr};
use core::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
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

/// Header, root witness, certificate, successor liability, and current status retained
/// for an admitted close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBatch<D: Digest> {
    /// Admitted header.
    pub header: Header<D>,
    /// Authenticated activity, withdrawal-output, and successor-state roots.
    pub roots: RootBundle<D>,
    /// Certified withdrawal reserve amount.
    pub withdrawal_total: u64,
    /// BLS12-381 MinSig quorum certificate over `header`.
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
    pub successor_root: StateRoot<D>,
    /// Exact withdrawal value moved into the claim reserve.
    pub withdrawal_total: u64,
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
    /// A deposit remained unpulled by every registration through its inclusion deadline.
    ExpiredDeposit {
        /// Account of the latest deposit recorded with that deadline.
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
    /// The admission frontier admitted no close through its admission deadline.
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
    pub frozen_state_root: StateRoot<D>,
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
///
/// Only the admission frontier carries deadlines. Settlement assigns them when an epoch becomes
/// the frontier: at its registration when no earlier epoch awaits admission, otherwise at its
/// predecessor's admission. The operator proposes no timing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochDeadlinePolicy {
    /// Interval from the time an epoch becomes the admission frontier through its inclusive
    /// admission deadline.
    pub admission_delay: NonZeroU64,
    /// Interval from an epoch's admission deadline through its challenge deadline.
    pub challenge_duration: NonZeroU64,
}

impl EpochDeadlinePolicy {
    /// Creates deadline rules fixed when the deployment is created.
    #[must_use]
    pub const fn new(admission_delay: NonZeroU64, challenge_duration: NonZeroU64) -> Self {
        Self {
            admission_delay,
            challenge_duration,
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
/// - `minimum_withdrawal_notice` must cover registration, admission, and FIFO
///   finalization of the close carrying a queued withdrawal. An epoch receives
///   its deadlines when it becomes the admission frontier, one admission delay
///   after the previous admission, so the carrying close also waits for every
///   registration queued ahead of it. It then waits for the latest challenge
///   deadline in its prefix and for the deployment to process the preceding
///   finalizations. The withdrawal deadline must be strictly later than its
///   finalization time because expiry is observed before finalization.
///   Operator-carried requests are checked at registration against the
///   earliest challenge deadline their close can receive.
/// - `deposit_inclusion_timeout` must cover the registration that pulls a
///   deposit: the embedding's observation of it, at most one dwell of the
///   epoch that takes it, and that registration's inclusion. Registration
///   never waits for earlier closes, so registrations queued ahead do not
///   count against the timeout. Pulls are prefixes, so an embedding that
///   bounds the withdrawals one registration carries must also cover the
///   registrations that drain the chain-queued withdrawals recorded ahead of
///   the deposit. Pulling discharges the inclusion obligation,
///   and no timer applies to the deposit afterward. It follows its epoch.
///   That epoch's admission carries it into the admitted close, and a hard
///   fault before that admission makes it refundable. No bound limits how
///   long a pulled deposit waits behind earlier registrations.
///
/// The deployment must size these windows for its scheduling and finalization
/// cadence. The primitive enforces deadlines and ancestry without limiting the
/// number of registrations awaiting admission or admitted closes awaiting
/// finality. An operator that queues registrations past a withdrawal deadline
/// is faulted when that deadline expires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementConfig {
    /// Admission and challenge timing fixed before the deployment accepts funds.
    pub epoch_deadlines: EpochDeadlinePolicy,
    /// Maximum time a recorded deposit may remain unpulled by every registration.
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
        epoch_deadlines: EpochDeadlinePolicy,
        deposit_inclusion_timeout: NonZeroU64,
        minimum_withdrawal_notice: NonZeroU64,
        maximum_withdrawal_notice: NonZeroU64,
        max_destination_bytes: usize,
        max_deposit_ids: NonZeroUsize,
    ) -> Self {
        Self {
            epoch_deadlines,
            deposit_inclusion_timeout,
            minimum_withdrawal_notice,
            maximum_withdrawal_notice,
            max_destination_bytes,
            max_deposit_ids,
        }
    }
}

// Deposits recorded with one inclusion deadline, ending one past the last of them.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Run<P: PublicKey> {
    end: u64,
    deadline: u64,
    // Account of the deposit at `end - 1`.
    account: P,
}

// A chain-queued withdrawal, its inbox index, and whether a live registration carries it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Queued<P: PublicKey, D: Digest> {
    index: u64,
    request: SignedWithdrawal<P, D>,
    // Not encoded. Decoding rebuilds it from the frontier and the queue.
    carried: bool,
}

// The admission frontier, bound to the admitted head.
#[derive(Debug)]
struct RegisteredClose<P: PublicKey, D: Digest> {
    context: CloseContext<P, D>,
    deposits: DepositBatch<P>,
    withdrawals: WithdrawalBatch<P, D>,
    withdrawal_deadline: Option<(u64, P)>,
}

// A registered epoch behind the frontier. Promotion binds its predecessor and deadlines and keeps
// the floors captured at registration.
#[derive(Debug)]
struct QueuedEpoch<P: PublicKey, D: Digest> {
    context: EpochContext<P, D>,
    floors: Floors,
    deposits: DepositBatch<P>,
    withdrawals: WithdrawalBatch<P, D>,
    withdrawal_deadline: Option<(u64, P)>,
}

/// The admission frontier: the bound context with the exact boundary batches
/// it committed at registration. Served by [`SettlementChain::registered`] for
/// the certification window.
#[derive(Debug)]
pub struct Registered<'a, P: PublicKey, D: Digest> {
    /// The frontier's close context bound to the admitted head.
    pub context: &'a CloseContext<P, D>,
    /// The exact deposit boundary the context commits.
    pub deposits: &'a DepositBatch<P>,
    /// The exact withdrawal batch the context commits.
    pub withdrawals: &'a WithdrawalBatch<P, D>,
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
        let mut encoded = commonware_codec::Copying(self.encoded.as_ref());
        let deposits = DepositBatch::read_cfg(&mut encoded, &RangeCfg::new(..=maximum))
            .map_err(|_| SettlementError::DepositWitness)?;
        if !encoded.0.is_empty() {
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
    fn new(batch: &WithdrawalBatch<P, D>) -> Self {
        let requests = batch.requests();
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
        Self {
            encoded,
            index,
            _request: PhantomData,
        }
    }

    fn find(&self, account: &P) -> Option<&PackedWithdrawalIndex> {
        // WithdrawalBatch orders the fixed-width account prefixes by encoded bytes;
        // PublicKey::Ord may use another order.
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
        let mut encoded = commonware_codec::Copying(&self.encoded[entry.start..entry.end]);
        let request =
            SignedWithdrawal::read_cfg(&mut encoded, &RangeCfg::new(..=maximum_destination_bytes))
                .map_err(|_| SettlementError::WithdrawalWitness)?;
        if !encoded.0.is_empty() {
            return Err(SettlementError::WithdrawalWitness);
        }
        Ok(Some(request))
    }
}

// Returns the earliest signed deadline in a withdrawal boundary and its account.
fn earliest_withdrawal<P: PublicKey, D: Digest>(
    withdrawals: &WithdrawalBatch<P, D>,
) -> Option<(u64, P)> {
    withdrawals
        .requests()
        .iter()
        .map(|request| (request.body().deadline(), request.account().clone()))
        .min()
}

// Marks every chain-queued request that one of the `live` registration batches carries verbatim.
fn mark_carried<'a, P, D>(
    pending: &mut BTreeMap<P, Queued<P, D>>,
    live: impl IntoIterator<Item = &'a WithdrawalBatch<P, D>>,
) where
    P: PublicKey + 'a,
    D: Digest + 'a,
{
    for batch in live {
        for request in batch.requests() {
            if let Some(queued) = pending.get_mut(request.account())
                && &queued.request == request
            {
                queued.carried = true;
            }
        }
    }
}

#[derive(Debug)]
struct AdmittedClose<P: PublicKey, D: Digest> {
    context: CloseContext<P, D>,
    deposits: PackedDeposits<P>,
    deposit_total: u64,
    withdrawals: PackedWithdrawals<P, D>,
    withdrawal_deadline: Option<(u64, P)>,
}

#[derive(Debug)]
struct PipelineEntry<P: PublicKey, D: Digest> {
    admitted: AdmittedClose<P, D>,
    batch: PendingBatch<D>,
}

/// One nonempty disjoint range of consumed native payout-log locations.
///
/// The embedding stores this value in its authenticated ledger under `(deployment, start)`.
/// A claim reads the exact neighboring ranges from one snapshot and atomically applies the
/// returned merged range with the asset release. Ranges contain both paid Append locations and
/// known non-payout Commit locations from finalized closes, so membership does not prove that a
/// payout existed. The genesis Commit at location zero is excluded. If `U` Append outputs remain
/// unpaid, canonical maximal ranges number at most `U + 1`: every range except possibly the last
/// must be followed by a distinct unpaid Append location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedRange {
    /// Inclusive first consumed location.
    pub start: u64,
    /// Exclusive last consumed location.
    pub end: u64,
}
impl ClaimedRange {
    /// Returns whether this value is a valid nonempty range of native locations.
    pub fn is_valid(&self) -> bool {
        self.start > 0 && self.start < self.end && self.end <= *mmr::Family::MAX_LEAVES
    }

    /// Inserts one consumed location using its predecessor-or-containing and strict successor.
    ///
    /// The neighbors must come from the same authenticated ordered-map snapshot. Coverage by an
    /// existing range is rejected. Only ranges touching the inserted location are merged.
    pub fn insert(index: u64, neighbors: &[Option<Self>; 2]) -> Result<Self, ClaimError> {
        if index == 0 || index >= *mmr::Family::MAX_LEAVES {
            return Err(ClaimError::Unavailable);
        }
        let [before, after] = *neighbors;
        if before.is_some_and(|range| !range.is_valid() || range.start > index || range.end > index)
            || after.is_some_and(|range| !range.is_valid() || range.start <= index)
        {
            return Err(ClaimError::Unavailable);
        }

        let next = index.checked_add(1).ok_or(ClaimError::Unavailable)?;
        Ok(Self {
            start: before
                .filter(|range| range.end == index)
                .map_or(index, |range| range.start),
            end: after
                .filter(|range| range.start == next)
                .map_or(next, |range| range.end),
        })
    }
}
#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for ClaimedRange {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let start = u.int_in_range(1..=*mmr::Family::MAX_LEAVES - 1)?;
        Ok(Self {
            start,
            end: u.int_in_range(start + 1..=*mmr::Family::MAX_LEAVES)?,
        })
    }
}
impl Write for ClaimedRange {
    fn write(&self, buf: &mut impl BufMut) {
        self.start.write(buf);
        self.end.write(buf);
    }
}
impl FixedSize for ClaimedRange {
    const SIZE: usize = u64::SIZE * 2;
}
impl Read for ClaimedRange {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let value = Self {
            start: u64::read(buf)?,
            end: u64::read(buf)?,
        };
        if !value.is_valid() {
            return Err(CodecError::Invalid("ClaimedRange", "invalid range"));
        }
        Ok(value)
    }
}

/// Atomic claimed-range merge and asset release for one verified payout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimEffect {
    /// Stable native Append location consumed by this effect.
    pub index: u64,
    /// Destination and amount authenticated by the latest finalized payout head.
    pub output: WithdrawalOutput,
    /// Claimed range to upsert after removing a merged strict successor, if any.
    pub claimed: ClaimedRange,
}

#[derive(Debug)]
struct HardFaultClaims<P: PublicKey, D: Digest> {
    frozen_state_root: StateRoot<D>,
    state_liability: u64,
    remaining_state_liability: u64,
    unfinalized_deposit_total: u64,
    custody_balance: u64,
    deposits: BTreeMap<P, u64>,
    pending_withdrawals: BTreeMap<P, SignedWithdrawal<P, D>>,
    admitted_withdrawals: Vec<PackedWithdrawals<P, D>>,
    claimed_accounts: BTreeSet<P>,
}

/// Initial settlement state supplied by trusted deployment configuration.
///
/// The configuration must bind the root and operation count to the supplied accounts.
/// Constructing this descriptor checks account ordering and liability arithmetic; it does
/// not prove that the accounts produce the configured QMDB root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Genesis<D: Digest> {
    root: StateRoot<D>,
    operations: u64,
    liability: u64,
}

impl<D: Digest> Genesis<D> {
    /// Checks canonical, strictly increasing account keys and derives their total liability.
    /// The root and operation count must come from trusted setup for these accounts.
    pub fn new(
        root: StateRoot<D>,
        operations: u64,
        accounts: &[(qmdb::AccountKey, qmdb::Balance)],
    ) -> Result<Self, qmdb::Error> {
        if accounts.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(qmdb::Error::Order);
        }
        let liability = accounts.iter().try_fold(0u64, |total, (_, balance)| {
            total
                .checked_add(balance.get())
                .ok_or(qmdb::Error::Arithmetic)
        })?;
        Ok(Self {
            root,
            operations,
            liability,
        })
    }

    /// Returns the configured state root.
    pub const fn root(&self) -> StateRoot<D> {
        self.root
    }

    /// Returns the configured QMDB operation count for historical proof queries.
    pub const fn operations(&self) -> u64 {
        self.operations
    }

    /// Returns the total positive account balance.
    pub const fn liability(&self) -> u64 {
        self.liability
    }
}

/// Runtime-agnostic chain state for one immutable operator deployment.
///
/// The admitted pipeline is a linear extension of the finalized root. Registered epochs wait in
/// FIFO order behind one admission frontier, which is the only registration bound to a
/// predecessor and deadlines. A hard fault permanently rejects new work and drops every
/// registration, while preserving the earlier pending prefix for ordinary challenge and FIFO
/// finalization before independent terminal claims.
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
    current_state_root: StateRoot<H::Digest>,
    finalized_logs: Heads<H::Digest>,
    finalized_rows: Range<u64>,
    current_liability: u64,
    custody_balance: u64,
    claimable_balance: u64,
    consumed_deposit_ids: BTreeSet<H::Digest>,
    consumed_withdrawal_ids: BTreeSet<WithdrawalId<H::Digest>>,
    withdrawal_replay_expiries: BTreeSet<(u64, WithdrawalId<H::Digest>)>,
    // Inbox length: the index the next deposit or chain-queued withdrawal receives.
    intake: u64,
    // First inbox index no registration has pulled.
    pulled: u64,
    // Unadmitted deposit totals by account: unpulled, pulled by a live registration, or pulled by
    // a registration a fault dropped.
    pending_deposits: BTreeMap<P, u64>,
    // Inclusion deadlines of unpulled deposits, run-length encoded. While operating, the runs
    // cover exactly the unpulled deposits, and both their ends and deadlines strictly increase.
    runs: VecDeque<Run<P>>,
    unfinalized_deposit_total: u64,
    // Chain-queued withdrawals awaiting admission, by account. While operating, an uncarried
    // request sits at or past `pulled`.
    pending_withdrawals: BTreeMap<P, Queued<P, H::Digest>>,
    pending_withdrawal_deadlines: BTreeSet<(u64, P)>,
    config: SettlementConfig,
    expected_epoch: u64,
    registered: Option<RegisteredClose<P, H::Digest>>,
    queued: VecDeque<QueuedEpoch<P, H::Digest>>,
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
    /// Creates a deployment from its trusted initial state.
    pub fn new(
        deployment: H::Digest,
        operator: P,
        committee: Committee,
        current_state: &Genesis<H::Digest>,
        expected_epoch: u64,
        config: SettlementConfig,
    ) -> Result<Self, SettlementError> {
        expected_epoch
            .checked_add(1)
            .ok_or(SettlementError::EpochOverflow)?;
        if config.maximum_withdrawal_notice < config.minimum_withdrawal_notice {
            return Err(SettlementError::WithdrawalNoticeOrder);
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
            finalized_logs: Heads::empty::<P, H>(),
            finalized_rows: 0..0,
            current_liability,
            custody_balance: current_liability,
            claimable_balance: 0,
            consumed_deposit_ids: BTreeSet::new(),
            consumed_withdrawal_ids: BTreeSet::new(),
            withdrawal_replay_expiries: BTreeSet::new(),
            intake: 0,
            pulled: 0,
            pending_deposits: BTreeMap::new(),
            runs: VecDeque::new(),
            unfinalized_deposit_total: 0,
            pending_withdrawals: BTreeMap::new(),
            pending_withdrawal_deadlines: BTreeSet::new(),
            config,
            expected_epoch,
            registered: None,
            queued: VecDeque::new(),
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
        // Only unpulled deposits carry inclusion deadlines, and a pulled deposit follows its
        // epoch. Deposits share one timeout, so the front run holds the earliest deadline.
        let deposit = self
            .runs
            .front()
            .filter(|run| now >= run.deadline)
            .map(|run| (run.deadline, &run.account));
        let withdrawal = self
            .earliest_withdrawal_deadline()
            .filter(|(deadline, _)| now >= *deadline);

        // Withdrawal attribution wins when both intake obligations expire at the same timestamp.
        let intake = match (deposit, withdrawal) {
            (Some((deposit_deadline, _)), Some((withdrawal_deadline, account)))
                if withdrawal_deadline <= deposit_deadline =>
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
                deadline,
                HardFaultReason::ExpiredDeposit {
                    account: account.clone(),
                    expired_at: deadline,
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

            // Registration activates payment contexts but admits no state transition. Unadmitted
            // deposits, pulled or not, and pending chain-queued withdrawals remain owned and reach
            // terminal settlement. Operator-carried extras existed only in these registrations:
            // their replay ids were never consumed and their signers recover through ordinary
            // state claims, as do the signers of the queued requests they superseded. Refundable
            // deposits carry no inclusion deadline.
            self.registered = None;
            self.queued.clear();
            self.runs.clear();
            for queued in self.pending_withdrawals.values_mut() {
                queued.carried = false;
            }
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

    // Returns the admission and challenge deadlines of an epoch that becomes the frontier at
    // `now`. The challenge deadline leaves one later timestamp for finalization or expiry.
    fn frontier_deadlines(&self, now: u64) -> Result<(u64, u64), SettlementError> {
        let policy = self.config.epoch_deadlines;
        let admission = now
            .checked_add(policy.admission_delay.get())
            .ok_or(SettlementError::EpochDeadlineOverflow)?;
        let challenge = admission
            .checked_add(policy.challenge_duration.get())
            .filter(|deadline| *deadline < u64::MAX)
            .ok_or(SettlementError::EpochDeadlineOverflow)?;
        Ok((admission, challenge))
    }

    fn head_state_root(&self) -> StateRoot<H::Digest> {
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

    /// Returns the next epoch to admit: the frontier's epoch whenever any epoch is registered.
    pub fn next_admission_epoch(&self) -> Result<u64, SettlementError> {
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

    /// Returns the next epoch to register.
    ///
    /// Registered epochs are exactly those from [`Self::next_admission_epoch`] up to this one,
    /// exclusive.
    pub fn next_registration_epoch(&self) -> Result<u64, SettlementError> {
        let tail = self
            .queued
            .back()
            .map(|queued| queued.context.payment().epoch())
            .or_else(|| {
                self.registered
                    .as_ref()
                    .map(|registered| registered.context.payment().epoch())
            });
        tail.map_or_else(
            || self.next_admission_epoch(),
            |epoch| epoch.checked_add(1).ok_or(SettlementError::EpochOverflow),
        )
    }

    fn ensure_epoch_offset_available(&self, offset: u64) -> Result<(), SettlementError> {
        self.next_registration_epoch()?
            .checked_add(offset)
            .ok_or(SettlementError::EpochOverflow)?;
        Ok(())
    }

    // Intake targets the next registration. An amount withdrawal also leaves one later close for
    // residual state. An amountless close only needs to remain finalizable.
    fn ensure_withdrawal_epoch_available(
        &self,
        action: &WithdrawalAction,
    ) -> Result<(), SettlementError> {
        let offset = match action {
            WithdrawalAction::Amount(_) => 2,
            WithdrawalAction::Close => 1,
        };
        self.ensure_epoch_offset_available(offset)
    }

    fn ensure_deposit_capacity(&self) -> Result<(), SettlementError> {
        if self.consumed_deposit_ids.len() >= self.config.max_deposit_ids.get() {
            return Err(SettlementError::DepositCapacity);
        }
        Ok(())
    }

    /// Records one finalized external deposit event exactly once and returns its inbox index.
    ///
    /// The deposit enters the inbox without an epoch, so it never changes a registered boundary.
    /// Its inclusion deadline applies until a registration pulls its index. Afterward no timer
    /// applies, and the deposit follows the pulling epoch to admission, or to a refund if a hard
    /// fault precedes that admission. Every deposit shares one timeout, so under the monotonic
    /// clock the oldest unpulled deposit is always the next to expire.
    ///
    /// # Panics
    ///
    /// Panics if `now` is earlier than the time an unpulled deposit was recorded, which the
    /// monotonic clock contract forbids.
    pub fn record_deposit(
        &mut self,
        now: u64,
        deposit_id: H::Digest,
        account: P,
        amount: u64,
    ) -> Result<u64, SettlementError> {
        self.ensure_operating_at(now)?;
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
        let extend = self.runs.back().is_some_and(|run| {
            assert!(
                run.deadline <= deadline,
                "settlement time must be monotonic"
            );
            run.deadline == deadline
        });
        let amount_for_account = self
            .pending_deposits
            .get(&account)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(SettlementError::CustodyArithmetic)?;
        // Leave room for deposit inclusion and a later account exit.
        self.ensure_epoch_offset_available(3)?;
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
        let index = self.intake;
        let intake = index
            .checked_add(1)
            .ok_or(SettlementError::IntakeOverflow)?;

        // Deposits recorded at one instant share a deadline and extend one run.
        if extend {
            let run = self.runs.back_mut().expect("the extended run was checked");
            run.end = intake;
            run.account = account.clone();
        } else {
            self.runs.push_back(Run {
                end: intake,
                deadline,
                account: account.clone(),
            });
        }
        self.pending_deposits.insert(account, amount_for_account);
        self.consumed_deposit_ids.insert(deposit_id);
        self.custody_balance = custody_balance;
        self.unfinalized_deposit_total = unfinalized_deposit_total;
        self.intake = intake;
        Ok(index)
    }

    fn has_unfinalized_withdrawal(&self, account: &P) -> bool {
        self.unfinalized_withdrawal_deadline(account).is_some()
    }

    /// Returns one staged, registered, or admitted-but-unfinalized withdrawal's deadline.
    #[must_use]
    pub fn unfinalized_withdrawal_deadline(&self, account: &P) -> Option<u64> {
        self.pending_withdrawals
            .get(account)
            .map(|pending| pending.request.body().deadline())
            .or_else(|| self.carried_withdrawal_deadline(account))
    }

    // Returns the deadline of a withdrawal a live registration or an unfinalized admitted close
    // carries for `account`.
    fn carried_withdrawal_deadline(&self, account: &P) -> Option<u64> {
        self.registered
            .as_ref()
            .and_then(|registered| registered.withdrawals.request_for(account))
            .map(|request| request.body().deadline())
            .or_else(|| {
                self.queued
                    .iter()
                    .find_map(|queued| queued.withdrawals.request_for(account))
                    .map(|request| request.body().deadline())
            })
            .or_else(|| {
                self.pipeline
                    .iter()
                    .find_map(|entry| entry.admitted.withdrawals.deadline(account))
            })
    }

    /// Validates one withdrawal request's shared intake gates, other than the one unfinalized
    /// withdrawal per account, and returns its id.
    ///
    /// Both intake paths check the finalized authorization root. Queueing also proves
    /// affordability there. Certification derives the release from the carrying epoch's final
    /// balance.
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
        Ok(request_id)
    }

    /// Queues one withdrawal against the current finalized account balance and returns its inbox
    /// index.
    ///
    /// An `Amount` must be affordable at intake, and a `Close` requires a positive balance.
    /// Intake remains available while epochs are registered without changing any registered
    /// boundary. The registration that pulls the request's index must carry it verbatim unless an
    /// earlier registration carried it early or superseded it with a fresh extra. Its certified
    /// close derives the release from the account's final balance, which may have changed through
    /// intervening payments.
    ///
    /// `destination_is_eligible` is the asset adapter's explicit admission predicate for the
    /// opaque signed destination. Eligibility must be stable for every accepted request because
    /// hard-fault claims must honor the exact bytes without operator cooperation.
    pub fn queue_withdrawal<F>(
        &mut self,
        now: u64,
        request: SignedWithdrawal<P, H::Digest>,
        opening: &StateOpening<P, H::Digest>,
        destination_is_eligible: F,
    ) -> Result<u64, SettlementError>
    where
        F: FnOnce(&Bytes) -> bool,
    {
        self.ensure_operating_at(now)?;
        self.ensure_withdrawal_epoch_available(request.body().action())?;
        let request_id = self.ensure_withdrawal_intake(now, &request, destination_is_eligible)?;
        if self.has_unfinalized_withdrawal(request.account()) {
            return Err(SettlementError::DuplicateWithdrawal);
        }
        let balance = opening.verify::<H>(&self.current_state_root)?.get();
        if &opening.account != request.account() {
            return Err(SettlementError::WithdrawalOpening);
        }
        if matches!(request.body().action(), WithdrawalAction::Amount(amount) if amount.get() > balance)
        {
            return Err(SettlementError::WithdrawalBalance);
        }
        let index = self.intake;
        let intake = index
            .checked_add(1)
            .ok_or(SettlementError::IntakeOverflow)?;

        let account = request.account().clone();
        let deadline = request.body().deadline();
        self.pending_withdrawals.insert(
            account.clone(),
            Queued {
                index,
                request,
                carried: false,
            },
        );
        self.pending_withdrawal_deadlines
            .insert((deadline, account));
        self.consumed_withdrawal_ids.insert(request_id);
        self.withdrawal_replay_expiries
            .insert((deadline, request_id));
        self.intake = intake;
        Ok(index)
    }

    /// Returns the inbox length: the index the next deposit or chain-queued withdrawal receives.
    #[must_use]
    pub const fn intake(&self) -> u64 {
        self.intake
    }

    /// Returns the first inbox index no registration has pulled. The next registration pulls
    /// from here.
    #[must_use]
    pub const fn pulled(&self) -> u64 {
        self.pulled
    }

    /// Returns the chain-queued withdrawals a registration pulling the inbox up to `end` must
    /// carry, in canonical account order: every uncarried request recorded before `end`.
    #[must_use]
    pub fn pending_withdrawals(&self, end: u64) -> WithdrawalBatch<P, H::Digest> {
        WithdrawalBatch::new(
            self.pending_withdrawals
                .values()
                .filter(|queued| !queued.carried && queued.index < end)
                .map(|queued| queued.request.clone())
                .collect(),
        )
        .expect("pending withdrawals hold one request per account")
    }

    /// Registers the next epoch and its exact boundary, pulling the inbox up to `end`.
    ///
    /// Registration requires only that the previous epoch is registered: it does not wait for
    /// that epoch's close to be built, certified, or admitted. It pulls the inbox indices from
    /// [`Self::pulled`] up to `end`, exclusive, and `end` must not exceed [`Self::intake`].
    /// Supply `deposits` as the per-account aggregate of exactly the deposits recorded at those
    /// indices, read from the embedding's own records. Settlement checks it against the
    /// context's deposit root, so intake recorded later cannot change the boundary, and against
    /// each account's unpulled total. Settlement keeps no per-index amounts, so it cannot detect
    /// an omitted deposit, which would stay pending without a deadline until a hard fault
    /// refunds it. Pulling discharges the pulled deposits' inclusion deadlines. They leave
    /// pending custody when this epoch is admitted, and a hard fault before that admission makes
    /// them refundable, however many registrations wait ahead. The epoch joins the FIFO queue
    /// with the log floors captured now. When no earlier epoch awaits admission it becomes the
    /// admission frontier immediately: settlement binds it to its own admitted head, including
    /// the predecessor liability, and assigns its deadlines from `now`.
    ///
    /// The withdrawal batch must contain every uncarried chain-queued request recorded before
    /// `end` verbatim. It may carry an uncarried chain-queued request recorded later, which is
    /// then carried early, and operator-collected signed requests, giving an uncensored signer a
    /// single-transaction exit: the claim. A request a live registration already carries is
    /// rejected. Fresh extras run the shared intake checks at the finalized authorization root
    /// and carry no balance proof. Certification derives every release from the carrying epoch's
    /// final balance, including a zero release when an `Amount` is not covered.
    ///
    /// A fresh extra supersedes a different uncarried chain-queued request for its account
    /// recorded at or past `end`, which no pull owes yet. The signer authorized both, so the
    /// extra becomes the account's one unfinalized withdrawal. The superseded request leaves the
    /// inbox obligations, keeps its replay id consumed, and reaches no terminal claim. Intake
    /// recorded after the boundary was built therefore cannot fail the registration.
    ///
    /// # Panics
    ///
    /// Panics if `deposits` credits an account more than its unpulled deposits.
    pub fn register_epoch<F>(
        &mut self,
        now: u64,
        context: EpochContext<P, H::Digest>,
        end: u64,
        deposits: DepositBatch<P>,
        withdrawals: WithdrawalBatch<P, H::Digest>,
        destination_is_eligible: F,
    ) -> Result<(), SettlementError>
    where
        F: Fn(&Bytes) -> bool,
    {
        self.ensure_operating_at(now)?;
        if context.deployment() != &self.deployment {
            return Err(SettlementError::Deployment);
        }
        if context.payment().operator() != &self.operator {
            return Err(SettlementError::OperatorMismatch);
        }
        let epoch = context.payment().epoch();
        if epoch != self.next_registration_epoch()? {
            return Err(SettlementError::EpochSequence);
        }
        epoch.checked_add(1).ok_or(SettlementError::EpochOverflow)?;
        if context.committee() != &self.committee_commitment {
            return Err(SettlementError::CommitteeMismatch);
        }
        if end < self.pulled || end > self.intake {
            return Err(SettlementError::IntakeRange);
        }
        if context.deposit_root() != &deposits.root::<H>()?
            || context.withdrawal_root() != &withdrawals.root::<H>()?
        {
            return Err(SettlementError::BoundaryRoot);
        }
        if !context.verify_anchor::<H>() {
            return Err(TransitionError::EpochAnchor.into());
        }

        // Pulled deposits leave pending custody only at admission, so an account's unpulled total
        // is its pending total less what the live registrations pulled.
        for record in deposits.records() {
            let account = record.account();
            let unpulled = self
                .registered
                .iter()
                .map(|registered| &registered.deposits)
                .chain(self.queued.iter().map(|queued| &queued.deposits))
                .try_fold(
                    self.pending_deposits.get(account).copied().unwrap_or(0),
                    |unpulled, pulled| unpulled.checked_sub(pulled.amount_for(account)),
                )
                .expect("live registrations pull only pending deposits");
            assert!(
                record.amount() <= unpulled,
                "the deposit batch exceeds the account's unpulled deposits"
            );
        }

        // A new frontier receives these deadlines. Behind the frontier, they are the earliest
        // deadlines this epoch can receive, since it is promoted no earlier than now.
        let (admission_deadline, challenge_deadline) = self.frontier_deadlines(now)?;

        // Every uncarried chain-queued request the pull reaches must appear
        // verbatim. Operator-carried extras run the shared intake battery,
        // and each deadline must clear the earliest tick this close can
        // finalize. That tick is exact for a new frontier. A queued epoch is
        // checked against the deadlines it would receive if promoted now, so
        // a later promotion can move its challenge window past an extra, and
        // the extra's expiry then faults the operator. An extra gains the
        // deadline fault guarantee once its close is admitted.
        // Before admission, the chained admission deadlines protect progress.
        for queued in self.pending_withdrawals.values() {
            if !queued.carried
                && queued.index < end
                && withdrawals.request_for(queued.request.account()) != Some(&queued.request)
            {
                return Err(SettlementError::WithdrawalWitness);
            }
        }
        let mut latest_challenge_deadline = None;
        let mut superseded = Vec::new();
        for request in withdrawals.requests() {
            // An uncarried chain-queued request skips intake wherever it sits in the inbox, so a
            // request recorded at or past `end` is carried early. A request some live
            // registration already carries cannot be carried again. Another request for the same
            // account runs the full battery.
            let queued = self.pending_withdrawals.get(request.account());
            if let Some(queued) = queued
                && &queued.request == request
            {
                if queued.carried {
                    return Err(SettlementError::DuplicateWithdrawal);
                }
                continue;
            }
            self.ensure_withdrawal_epoch_available(request.body().action())?;
            self.ensure_withdrawal_intake(now, request, &destination_is_eligible)?;

            // The pull check above leaves only a queued request recorded at or past `end`, which
            // this extra supersedes unless a live registration carries it.
            if self
                .carried_withdrawal_deadline(request.account())
                .is_some()
            {
                return Err(SettlementError::DuplicateWithdrawal);
            }
            if queued.is_some() {
                superseded.push(request.account().clone());
            }

            // Finalize is legal only at now > challenge_deadline and runs the
            // inclusive expiry sweep first. FIFO also holds this close behind
            // every earlier close, so its finalization also waits for their
            // challenge windows. The earliest finalizing tick is therefore one
            // past the latest of those deadlines, and a deadline at that tick
            // would fault before the pop, so the close needs a strictly later
            // one.
            let earliest_finalize = latest_challenge_deadline
                .get_or_insert_with(|| {
                    self.pipeline
                        .iter()
                        .map(|entry| entry.admitted.context.challenge_deadline())
                        .chain(
                            self.registered
                                .as_ref()
                                .map(|registered| registered.context.challenge_deadline()),
                        )
                        .fold(challenge_deadline, u64::max)
                })
                .checked_add(1)
                .ok_or(SettlementError::EpochOverflow)?;
            if request.body().deadline() <= earliest_finalize {
                return Err(SettlementError::WithdrawalDeadlineTooSoon);
            }
        }

        mark_carried(&mut self.pending_withdrawals, [&withdrawals]);
        for account in superseded {
            let queued = self
                .pending_withdrawals
                .remove(&account)
                .expect("the superseded request was checked above");
            self.pending_withdrawal_deadlines
                .remove(&(queued.request.body().deadline(), account));
        }
        let withdrawal_deadline = earliest_withdrawal(&withdrawals);
        self.queued.push_back(QueuedEpoch {
            context,
            floors: self.registration_floors(),
            deposits,
            withdrawals,
            withdrawal_deadline,
        });

        // Pulled deposits carry no inclusion deadline. A run the pull splits keeps its deadline,
        // which its unpulled tail shares.
        while self.runs.front().is_some_and(|run| run.end <= end) {
            self.runs.pop_front();
        }
        self.pulled = end;
        self.promote(admission_deadline, challenge_deadline);
        Ok(())
    }

    // Binds the queue front once no earlier epoch awaits admission. Its predecessor root, log
    // heads, account rows, and liability come only from the admitted head.
    fn promote(&mut self, admission_deadline: u64, challenge_deadline: u64) {
        if self.registered.is_some() || self.hard_fault.is_some() {
            return;
        }
        let Some(queued) = self.queued.pop_front() else {
            return;
        };
        let context = queued.context.bind_settlement(
            self.head_state_root(),
            self.head_logs(),
            self.head_rows(),
            self.head_liability(),
            admission_deadline,
            challenge_deadline,
            queued.floors,
        );
        self.registered = Some(RegisteredClose {
            context,
            deposits: queued.deposits,
            withdrawals: queued.withdrawals,
            withdrawal_deadline: queued.withdrawal_deadline,
        });
    }

    /// Admits the frontier's header, its root witness, and its certificate.
    ///
    /// The next queued epoch, if any, becomes the frontier at this admission and receives its
    /// deadlines from `now`.
    pub fn admit(
        &mut self,
        now: u64,
        header: Header<H::Digest>,
        roots: RootBundle<H::Digest>,
        withdrawal_total: u64,
        certificate: bls12381::Certificate,
    ) -> Result<BatchId<H::Digest>, SettlementError> {
        self.ensure_operating_at(now)?;
        let registered = self
            .registered
            .as_ref()
            .ok_or(SettlementError::NoRegisteredEpoch)?;
        transition::validate_header::<H, P, H::Digest>(
            &registered.context,
            &header,
            &roots,
            withdrawal_total,
        )?;
        if !self.certificate_scheme.verify(&header, &certificate) {
            return Err(SettlementError::InvalidCertificate);
        }

        let successor_liability = transition::validate_close_amounts::<H, P, H::Digest>(
            &registered.context,
            &registered.deposits,
            &registered.withdrawals,
            &roots,
            withdrawal_total,
        )?;
        let promotion = if self.queued.is_empty() {
            None
        } else {
            Some(self.frontier_deadlines(now)?)
        };

        let batch_id = header.batch_id::<H>();
        let registered = self
            .registered
            .take()
            .expect("the registered close was checked above");

        // Registration pulled only recorded deposits, and only admission reduces their totals.
        for record in registered.deposits.records() {
            let remaining = {
                let total = self
                    .pending_deposits
                    .get_mut(record.account())
                    .expect("registration pulled only recorded deposits");
                *total = total
                    .checked_sub(record.amount())
                    .expect("registration pulled only recorded deposits");
                *total
            };
            if remaining == 0 {
                self.pending_deposits.remove(record.account());
            }
        }
        // Operator-carried requests consume their replay ids at admission.
        // Chain-queued ids are already consumed, so re-inserting is a no-op.
        for request in registered.withdrawals.requests() {
            if let Some(queued) = self.pending_withdrawals.get(request.account())
                && &queued.request == request
            {
                assert!(
                    queued.carried,
                    "the admitted registration carries the request"
                );
                self.pending_withdrawals.remove(request.account());
                self.pending_withdrawal_deadlines
                    .remove(&(request.body().deadline(), request.account().clone()));
            }
            let request_id = request.id::<H>();
            self.withdrawal_replay_expiries
                .insert((request.body().deadline(), request_id));
            self.consumed_withdrawal_ids.insert(request_id);
        }
        let admitted = AdmittedClose {
            context: registered.context,
            deposit_total: registered.deposits.total(),
            deposits: PackedDeposits::new(&registered.deposits),
            withdrawals: PackedWithdrawals::new(&registered.withdrawals),
            withdrawal_deadline: registered.withdrawal_deadline,
        };
        self.pipeline.push_back(PipelineEntry {
            admitted,
            batch: PendingBatch {
                header,
                roots,
                withdrawal_total,
                certificate,
                successor_liability,
                status: BatchStatus::Pending,
            },
        });
        if let Some((admission_deadline, challenge_deadline)) = promotion {
            self.promote(admission_deadline, challenge_deadline);
        }
        Ok(batch_id)
    }

    /// Adjudicates a typed challenge through the target's inclusive deadline.
    pub fn challenge(
        &mut self,
        now: u64,
        batch_id: BatchId<H::Digest>,
        submitted: &Challenge<P, H::Digest>,
    ) -> Result<Verdict, SettlementError> {
        self.observe_time(now);
        self.challenge_after_observation(now, batch_id, submitted)
    }

    /// Bounded-decodes and adjudicates one challenge.
    pub fn challenge_encoded(
        &mut self,
        now: u64,
        batch_id: BatchId<H::Digest>,
        encoded: &[u8],
        maximum_bytes: usize,
    ) -> Result<Verdict, SettlementError> {
        self.observe_time(now);
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        let submitted = challenge::decode_bounded(encoded, maximum_bytes)?;
        self.challenge_after_observation(now, batch_id, &submitted)
    }

    fn challenge_after_observation(
        &mut self,
        now: u64,
        batch_id: BatchId<H::Digest>,
        submitted: &Challenge<P, H::Digest>,
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

        if now > self.pipeline[index].admitted.context.challenge_deadline() {
            return Err(SettlementError::Challenge(ChallengeError::Expired));
        }
        let verdict = challenge::adjudicate::<H, P, H::Digest>(
            &self.pipeline[index].admitted.context,
            &self.pipeline[index].batch.header,
            &self.pipeline[index].batch.roots,
            self.pipeline[index].batch.withdrawal_total,
            submitted,
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
    /// Insert the returned trailing Commit location into the authenticated claimed-range map
    /// atomically with this mutation and the custody transfer. A Commit can never contain a
    /// payout, including when the finalized close contains no outputs.
    pub fn finalize(
        &mut self,
        now: u64,
    ) -> Result<(FinalizedBatch<H::Digest>, u64), SettlementError> {
        self.observe_time(now);
        if self.fault_settled {
            return Err(SettlementError::HardFaultAlreadySettled);
        }
        let entry = self
            .pipeline
            .front()
            .ok_or(SettlementError::NoPendingBatch)?;
        let next_epoch = self
            .expected_epoch
            .checked_add(1)
            .ok_or(SettlementError::EpochOverflow)?;
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
        if entry.admitted.context.predecessor_logs() != &self.finalized_logs {
            return Err(SettlementError::StateAncestry);
        }
        let rows = entry
            .batch
            .roots
            .activity_range(&entry.admitted.context)
            .expect("admission validated the activity range");
        let commit_index = entry
            .batch
            .roots
            .withdrawal_outputs
            .operations
            .checked_sub(1)
            .filter(|index| *index >= self.finalized_logs.payouts.operations)
            .ok_or(SettlementError::StateAncestry)?;

        let withdrawal_total = entry.batch.withdrawal_total;
        let claimable_balance = self
            .claimable_balance
            .checked_add(withdrawal_total)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let custody_balance = self
            .custody_balance
            .checked_sub(withdrawal_total)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let unfinalized_deposit_total = self
            .unfinalized_deposit_total
            .checked_sub(entry.admitted.deposit_total)
            .ok_or(SettlementError::CustodyArithmetic)?;
        let successor_liability = entry.batch.successor_liability;
        let batch_id = entry.batch.header.batch_id::<H>();

        let finalized = FinalizedBatch {
            batch_id,
            epoch,
            successor_root: entry.batch.roots.successor,
            withdrawal_total,
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

        self.finalized_logs = entry.batch.roots.logs();
        self.finalized_rows = rows.start..rows.end;
        self.expected_epoch = next_epoch;
        Ok((finalized, commit_index))
    }

    /// Consumes one payout under the current finalized cumulative head.
    ///
    /// Supply the claimed range immediately before or containing the location and its strict
    /// successor from the same authenticated checkpoint as this chain. Delete a merged successor,
    /// upsert the returned range, and release the asset atomically. The semantic effect identity is
    /// `(deployment, claim.position())`; refreshed proof bytes do not change it. This method
    /// remains available after a fault.
    pub fn claim_withdrawal(
        &mut self,
        neighbors: &[Option<ClaimedRange>; 2],
        claim: &WithdrawalClaim<H::Digest>,
    ) -> Result<ClaimEffect, ClaimError> {
        let index = claim.position();
        let claimed = ClaimedRange::insert(index, neighbors)?;
        if neighbors
            .iter()
            .flatten()
            .any(|range| range.end > self.finalized_logs.payouts.operations)
            || claimed.end > self.finalized_logs.payouts.operations
        {
            return Err(ClaimError::Unavailable);
        }
        let output = claim.verify::<H>(&self.finalized_logs.payouts)?;
        let aggregate = self
            .claimable_balance
            .checked_sub(output.amount())
            .ok_or(ClaimError::Reserve)?;
        self.claimable_balance = aggregate;
        Ok(ClaimEffect {
            index,
            output,
            claimed,
        })
    }

    /// Returns the two latest FIFO-finalized cumulative log heads.
    pub const fn finalized_logs(&self) -> Heads<H::Digest> {
        self.finalized_logs
    }

    /// Returns the only payout head currently approved for withdrawal claims.
    pub const fn finalized_payouts(&self) -> LogHead<H::Digest> {
        self.finalized_logs.payouts
    }

    /// Returns the exact log predecessor of the next registration.
    pub fn head_logs(&self) -> Heads<H::Digest> {
        self.pipeline
            .back()
            .map_or(self.finalized_logs, |entry| entry.batch.roots.logs())
    }

    /// Returns the account rows of the close the next frontier binds as its predecessor.
    ///
    /// The interval is empty before the first close and after a close with no rows.
    pub fn head_rows(&self) -> Range<u64> {
        self.pipeline.back().map_or_else(
            || self.finalized_rows.clone(),
            |entry| {
                let rows = entry
                    .batch
                    .roots
                    .activity_range(&entry.admitted.context)
                    .expect("admission validated the activity range");
                rows.start..rows.end
            },
        )
    }

    /// Returns canonical log floors for a new immutable registration.
    ///
    /// Registration captures these floors, and they stay fixed while the epoch waits in the
    /// queue.
    pub const fn registration_floors(&self) -> Floors {
        Floors {
            activity: self.finalized_logs.activity.operations - 1,
            payouts: self.finalized_logs.payouts.operations - 1,
        }
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

    /// Observes outstanding deadlines and consumes one account's queued deposit refund after a
    /// permanent fault.
    ///
    /// The refund returns every unadmitted deposit of `account` once: those no registration
    /// pulled and those pulled by a registration the fault dropped. Invoking this method
    /// requires no operator or claimant witness. The embedding must atomically commit the payout
    /// and state mutation. A refund identity includes the deployment, account, and whether
    /// terminal settlement has started: an account can receive a staged refund and later recover
    /// deposits from invalidated closes. Bind retries to that phase so an earlier request cannot
    /// consume the later refund.
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

        let amount = self
            .pending_deposits
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

        self.pending_deposits
            .remove(account)
            .expect("the queued deposit was checked above");
        self.custody_balance = custody_balance;
        self.unfinalized_deposit_total = unfinalized_deposit_total;
        Ok(DepositRefund {
            account: account.clone(),
            amount,
        })
    }

    /// Freezes the last finalized root for independent terminal claims.
    ///
    /// Starting terminal settlement only recovers the unfinalized pipeline. Each live
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

        // Unadmitted deposits already include those pulled by the dropped registrations.
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
        if self
            .current_liability
            .checked_add(deposit_total)
            .ok_or(SettlementError::CustodyArithmetic)?
            != self.custody_balance
        {
            return Err(SettlementError::CustodyMismatch);
        }

        let pending_withdrawals = core::mem::take(&mut self.pending_withdrawals)
            .into_iter()
            .map(|(account, queued)| (account, queued.request))
            .collect();
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
            claimed_accounts: BTreeSet::new(),
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
        self.runs.clear();
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
    /// the deployment, frozen root and account as the idempotency key.
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
        if claims.claimed_accounts.contains(&opening.account) {
            return Err(SettlementError::ClaimAlreadyConsumed);
        }
        let balance = opening.verify::<H>(&claims.frozen_state_root)?.get();
        let account = opening.account.clone();
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
        let inserted = claims.claimed_accounts.insert(account.clone());
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

        self.current_liability = 0;
        self.custody_balance = 0;
        self.unfinalized_deposit_total = 0;
        self.hard_fault_claims = None;
        self.fault_settled = true;
    }

    /// Returns the finalized state root.
    #[must_use]
    pub const fn current_state_root(&self) -> StateRoot<H::Digest> {
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

    /// Returns finalized custody reserved for unconsumed withdrawal claims.
    #[must_use]
    pub const fn claimable_balance(&self) -> u64 {
        self.claimable_balance
    }

    /// Returns the admission frontier: the bound context with the exact
    /// boundary batches it committed.
    ///
    /// The frontier is the earliest registered epoch awaiting admission. It
    /// holds from its promotion until it is admitted or its admission deadline
    /// expires, which is exactly the certification window. Any hard fault
    /// retires it early, and an expired deadline is observed at the next
    /// mutating call that accepts `now`, so an already-expired frontier may
    /// still be served until then. Validators seal dealings against this
    /// registration instead of any operator-supplied context. Later
    /// registrations wait in FIFO order without a bound predecessor or
    /// deadlines.
    #[must_use]
    pub fn registered(&self) -> Option<Registered<'_, P, H::Digest>> {
        self.registered.as_ref().map(|registered| Registered {
            context: &registered.context,
            deposits: &registered.deposits,
            withdrawals: &registered.withdrawals,
        })
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

    /// Returns whether terminal settlement has begun, including after custody is exhausted.
    #[must_use]
    pub const fn hard_fault_settlement_started(&self) -> bool {
        self.hard_fault_claims.is_some() || self.fault_settled
    }

    // Nested configuration and fault values are encoded only as part of a chain checkpoint.

    fn write_config(config: &SettlementConfig, buf: &mut impl BufMut) {
        config.epoch_deadlines.admission_delay.write(buf);
        config.epoch_deadlines.challenge_duration.write(buf);
        config.deposit_inclusion_timeout.write(buf);
        config.minimum_withdrawal_notice.write(buf);
        config.maximum_withdrawal_notice.write(buf);
        (config.max_destination_bytes as u64).write(buf);
        (config.max_deposit_ids.get() as u64).write(buf);
    }

    const fn size_config(_: &SettlementConfig) -> usize {
        7 * u64::SIZE
    }

    fn read_config(buf: &mut impl Buf) -> Result<SettlementConfig, CodecError> {
        const CONTEXT: &str = "clearing::SettlementConfig";
        let epoch_deadlines =
            EpochDeadlinePolicy::new(NonZeroU64::read(buf)?, NonZeroU64::read(buf)?);
        let deposit_inclusion_timeout = NonZeroU64::read(buf)?;
        let minimum_withdrawal_notice = NonZeroU64::read(buf)?;
        let maximum_withdrawal_notice = NonZeroU64::read(buf)?;
        let max_destination_bytes = usize::try_from(u64::read(buf)?)
            .map_err(|_| CodecError::Invalid(CONTEXT, "destination bound is unrepresentable"))?;
        let max_deposit_ids = usize::try_from(u64::read(buf)?)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(CodecError::Invalid(
                CONTEXT,
                "deposit bound is zero or unrepresentable",
            ))?;
        Ok(SettlementConfig::new(
            epoch_deadlines,
            deposit_inclusion_timeout,
            minimum_withdrawal_notice,
            maximum_withdrawal_notice,
            max_destination_bytes,
            max_deposit_ids,
        ))
    }

    const fn challenge_kind_tag(kind: ChallengeKind) -> u8 {
        match kind {
            ChallengeKind::HigherAckDebit => 0,
            ChallengeKind::HigherAckEntry => 1,
            ChallengeKind::AckFork => 2,
        }
    }

    const fn challenge_kind_from_tag(tag: u8) -> Result<ChallengeKind, CodecError> {
        Ok(match tag {
            0 => ChallengeKind::HigherAckDebit,
            1 => ChallengeKind::HigherAckEntry,
            2 => ChallengeKind::AckFork,
            tag => return Err(CodecError::InvalidEnum(tag)),
        })
    }

    fn write_status(status: &BatchStatus<H::Digest>, buf: &mut impl BufMut) {
        match status {
            BatchStatus::Pending => 0_u8.write(buf),
            BatchStatus::Challenged(kind) => {
                1_u8.write(buf);
                Self::challenge_kind_tag(*kind).write(buf);
            }
            BatchStatus::Invalidated(batch_id) => {
                2_u8.write(buf);
                batch_id.write(buf);
            }
        }
    }

    fn size_status(status: &BatchStatus<H::Digest>) -> usize {
        1 + match status {
            BatchStatus::Pending => 0,
            BatchStatus::Challenged(_) => 1,
            BatchStatus::Invalidated(batch_id) => batch_id.encode_size(),
        }
    }

    fn read_status(buf: &mut impl Buf) -> Result<BatchStatus<H::Digest>, CodecError> {
        match u8::read(buf)? {
            0 => Ok(BatchStatus::Pending),
            1 => Ok(BatchStatus::Challenged(Self::challenge_kind_from_tag(
                u8::read(buf)?,
            )?)),
            2 => Ok(BatchStatus::Invalidated(BatchId::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }

    fn write_reason(reason: &HardFaultReason<P, H::Digest>, buf: &mut impl BufMut) {
        match reason {
            HardFaultReason::ProvenChallenge { batch_id, kind } => {
                0_u8.write(buf);
                batch_id.write(buf);
                Self::challenge_kind_tag(*kind).write(buf);
            }
            HardFaultReason::ExpiredDeposit {
                account,
                expired_at,
            } => {
                1_u8.write(buf);
                account.write(buf);
                expired_at.write(buf);
            }
            HardFaultReason::ExpiredWithdrawal {
                account,
                expired_at,
            } => {
                2_u8.write(buf);
                account.write(buf);
                expired_at.write(buf);
            }
            HardFaultReason::ExpiredRegistration {
                anchor,
                epoch,
                expired_at,
            } => {
                3_u8.write(buf);
                anchor.write(buf);
                epoch.write(buf);
                expired_at.write(buf);
            }
        }
    }

    fn size_reason(reason: &HardFaultReason<P, H::Digest>) -> usize {
        1 + match reason {
            HardFaultReason::ProvenChallenge { batch_id, .. } => batch_id.encode_size() + 1,
            HardFaultReason::ExpiredDeposit { account, .. }
            | HardFaultReason::ExpiredWithdrawal { account, .. } => {
                account.encode_size() + u64::SIZE
            }
            HardFaultReason::ExpiredRegistration { anchor, .. } => {
                anchor.encode_size() + 2 * u64::SIZE
            }
        }
    }

    fn read_reason(buf: &mut impl Buf) -> Result<HardFaultReason<P, H::Digest>, CodecError> {
        match u8::read(buf)? {
            0 => Ok(HardFaultReason::ProvenChallenge {
                batch_id: BatchId::read(buf)?,
                kind: Self::challenge_kind_from_tag(u8::read(buf)?)?,
            }),
            1 => Ok(HardFaultReason::ExpiredDeposit {
                account: P::read(buf)?,
                expired_at: u64::read(buf)?,
            }),
            2 => Ok(HardFaultReason::ExpiredWithdrawal {
                account: P::read(buf)?,
                expired_at: u64::read(buf)?,
            }),
            3 => Ok(HardFaultReason::ExpiredRegistration {
                anchor: H::Digest::read(buf)?,
                epoch: u64::read(buf)?,
                expired_at: u64::read(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }

    /// Writes packed withdrawals as a count followed by the packed bytes.
    ///
    /// The packed bytes are the concatenated canonical request encodings, so
    /// the reader recovers them by decoding that many requests in order.
    fn write_packed_withdrawals(packed: &PackedWithdrawals<P, H::Digest>, buf: &mut impl BufMut) {
        packed.index.len().write(buf);
        buf.put_slice(&packed.encoded);
    }

    fn size_packed_withdrawals(packed: &PackedWithdrawals<P, H::Digest>) -> usize {
        packed.index.len().encode_size() + packed.encoded.len()
    }

    /// Reads packed withdrawals, returning the rebuilt pack and the earliest
    /// signed deadline among the requests.
    #[allow(clippy::type_complexity)]
    fn read_packed_withdrawals(
        buf: &mut impl Buf,
        bounds: &Bounds,
    ) -> Result<(PackedWithdrawals<P, H::Digest>, Option<(u64, P)>), CodecError> {
        let requests = WithdrawalBatch::<P, H::Digest>::read_cfg(
            buf,
            &(
                RangeCfg::new(0..=bounds.items),
                RangeCfg::new(0..=bounds.destination),
            ),
        )?;
        let deadline = earliest_withdrawal(&requests);
        Ok((PackedWithdrawals::new(&requests), deadline))
    }

    fn write_pipeline_entry(entry: &PipelineEntry<P, H::Digest>, buf: &mut impl BufMut) {
        entry.admitted.context.write(buf);
        buf.put_slice(&entry.admitted.deposits.encoded);
        Self::write_packed_withdrawals(&entry.admitted.withdrawals, buf);
        entry.batch.header.write(buf);
        entry.batch.roots.write(buf);
        entry.batch.withdrawal_total.write(buf);
        entry.batch.certificate.write(buf);
        Self::write_status(&entry.batch.status, buf);
    }

    fn size_pipeline_entry(entry: &PipelineEntry<P, H::Digest>) -> usize {
        entry.admitted.context.encode_size()
            + entry.admitted.deposits.encoded.len()
            + Self::size_packed_withdrawals(&entry.admitted.withdrawals)
            + u64::SIZE
            + entry.batch.header.encode_size()
            + entry.batch.roots.encode_size()
            + entry.batch.certificate.encode_size()
            + Self::size_status(&entry.batch.status)
    }

    fn read_pipeline_entry(
        buf: &mut impl Buf,
        bounds: &Bounds,
        committee: usize,
    ) -> Result<PipelineEntry<P, H::Digest>, CodecError> {
        let context = CloseContext::read(buf)?;
        let deposits = DepositBatch::<P>::read_cfg(buf, &RangeCfg::new(0..=bounds.items))?;
        let (withdrawals, withdrawal_deadline) = Self::read_packed_withdrawals(buf, bounds)?;
        let header = Header::read(buf)?;
        let roots = RootBundle::read(buf)?;
        let withdrawal_total = u64::read(buf)?;
        let certificate = bls12381::Certificate::read_cfg(buf, &committee)?;
        let successor_liability = transition::checked_successor_liability(
            context.predecessor_liability(),
            deposits.total(),
            withdrawal_total,
        )
        .map_err(|_| CodecError::Invalid("SettlementChain", "invalid successor liability"))?;
        let admitted = AdmittedClose {
            context,
            deposit_total: deposits.total(),
            deposits: PackedDeposits::new(&deposits),
            withdrawals,
            withdrawal_deadline,
        };
        let batch = PendingBatch {
            header,
            roots,
            withdrawal_total,
            certificate,
            successor_liability,
            status: Self::read_status(buf)?,
        };
        Ok(PipelineEntry { admitted, batch })
    }

    fn write_registered(registered: &RegisteredClose<P, H::Digest>, buf: &mut impl BufMut) {
        registered.context.write(buf);
        registered.deposits.write(buf);
        registered.withdrawals.write(buf);
    }

    fn size_registered(registered: &RegisteredClose<P, H::Digest>) -> usize {
        registered.context.encode_size()
            + registered.deposits.encode_size()
            + registered.withdrawals.encode_size()
    }

    fn read_registered(
        buf: &mut impl Buf,
        bounds: &Bounds,
    ) -> Result<RegisteredClose<P, H::Digest>, CodecError> {
        let context = CloseContext::read(buf)?;
        let deposits = DepositBatch::<P>::read_cfg(buf, &RangeCfg::new(0..=bounds.items))?;
        let withdrawals = WithdrawalBatch::<P, H::Digest>::read_cfg(
            buf,
            &(
                RangeCfg::new(0..=bounds.items),
                RangeCfg::new(0..=bounds.destination),
            ),
        )?;
        let withdrawal_deadline = earliest_withdrawal(&withdrawals);
        Ok(RegisteredClose {
            context,
            deposits,
            withdrawals,
            withdrawal_deadline,
        })
    }

    fn write_queued(queued: &QueuedEpoch<P, H::Digest>, buf: &mut impl BufMut) {
        queued.context.write(buf);
        queued.floors.write(buf);
        queued.deposits.write(buf);
        queued.withdrawals.write(buf);
    }

    fn size_queued(queued: &QueuedEpoch<P, H::Digest>) -> usize {
        queued.context.encode_size()
            + queued.floors.encode_size()
            + queued.deposits.encode_size()
            + queued.withdrawals.encode_size()
    }

    fn read_queued(
        buf: &mut impl Buf,
        bounds: &Bounds,
    ) -> Result<QueuedEpoch<P, H::Digest>, CodecError> {
        let context = EpochContext::read(buf)?;
        let floors = Floors::read(buf)?;
        let deposits = DepositBatch::<P>::read_cfg(buf, &RangeCfg::new(0..=bounds.items))?;
        let withdrawals = WithdrawalBatch::<P, H::Digest>::read_cfg(
            buf,
            &(
                RangeCfg::new(0..=bounds.items),
                RangeCfg::new(0..=bounds.destination),
            ),
        )?;
        let withdrawal_deadline = earliest_withdrawal(&withdrawals);
        Ok(QueuedEpoch {
            context,
            floors,
            deposits,
            withdrawals,
            withdrawal_deadline,
        })
    }

    fn write_claims(claims: &HardFaultClaims<P, H::Digest>, buf: &mut impl BufMut) {
        claims.frozen_state_root.write(buf);
        claims.state_liability.write(buf);
        claims.remaining_state_liability.write(buf);
        claims.unfinalized_deposit_total.write(buf);
        claims.custody_balance.write(buf);
        claims.deposits.write(buf);
        claims.pending_withdrawals.write(buf);
        claims.admitted_withdrawals.len().write(buf);
        for admitted in &claims.admitted_withdrawals {
            Self::write_packed_withdrawals(admitted, buf);
        }
        claims.claimed_accounts.write(buf);
    }

    fn size_claims(claims: &HardFaultClaims<P, H::Digest>) -> usize {
        claims.frozen_state_root.encode_size()
            + 4 * u64::SIZE
            + claims.deposits.encode_size()
            + claims.pending_withdrawals.encode_size()
            + claims.admitted_withdrawals.len().encode_size()
            + claims
                .admitted_withdrawals
                .iter()
                .map(Self::size_packed_withdrawals)
                .sum::<usize>()
            + claims.claimed_accounts.encode_size()
    }

    fn read_claims(
        buf: &mut impl Buf,
        bounds: &Bounds,
    ) -> Result<HardFaultClaims<P, H::Digest>, CodecError> {
        let frozen_state_root = StateRoot::read(buf)?;
        let state_liability = u64::read(buf)?;
        let remaining_state_liability = u64::read(buf)?;
        let unfinalized_deposit_total = u64::read(buf)?;
        let custody_balance = u64::read(buf)?;
        let deposits =
            BTreeMap::<P, u64>::read_cfg(buf, &(RangeCfg::new(0..=bounds.items), ((), ())))?;
        let pending_withdrawals = BTreeMap::<P, SignedWithdrawal<P, H::Digest>>::read_cfg(
            buf,
            &(
                RangeCfg::new(0..=bounds.items),
                ((), RangeCfg::new(0..=bounds.destination)),
            ),
        )?;
        let admitted = usize::read_cfg(buf, &RangeCfg::new(0..=bounds.items))?;
        let mut admitted_withdrawals = Vec::with_capacity(admitted.min(buf.remaining()));
        for _ in 0..admitted {
            admitted_withdrawals.push(Self::read_packed_withdrawals(buf, bounds)?.0);
        }
        let claimed_accounts =
            BTreeSet::<P>::read_cfg(buf, &(RangeCfg::new(0..=bounds.items), ()))?;
        Ok(HardFaultClaims {
            frozen_state_root,
            state_liability,
            remaining_state_liability,
            unfinalized_deposit_total,
            custody_balance,
            deposits,
            pending_withdrawals,
            admitted_withdrawals,
            claimed_accounts,
        })
    }
}

/// Decode bounds for one persisted [`SettlementChain`].
///
/// Every bound must dominate the deployment maxima its collections can
/// reach, or state the chain honestly persisted fails to decode at restart.
/// `items` must cover [`SettlementConfig::max_deposit_ids`], the admitted closes
/// awaiting finality, the deployment's account cardinality, and all withdrawal
/// identifiers retained within the maximum notice window.
/// Registrations queued behind the admission frontier have no count bound: only
/// the encoded bytes limit them, and each boundary batch within them is bounded
/// by `items`.
/// Claimed range records are fixed-size values in the external ledger. `destination` must
/// be at least [`SettlementConfig::max_destination_bytes`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bounds {
    /// Maximum committee members.
    pub committee: usize,
    /// Maximum elements decoded into any one retained collection.
    pub items: usize,
    /// Maximum bytes in one withdrawal destination.
    pub destination: usize,
}

impl<P: PublicKey> Write for Run<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.end.write(buf);
        self.deadline.write(buf);
        self.account.write(buf);
    }
}

impl<P: PublicKey> FixedSize for Run<P> {
    const SIZE: usize = 2 * u64::SIZE + P::SIZE;
}

impl<P: PublicKey> Read for Run<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            end: u64::read(buf)?,
            deadline: u64::read(buf)?,
            account: P::read(buf)?,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for Queued<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.request.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Queued<P, D> {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + self.request.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for Queued<P, D> {
    /// Maximum encoded destination length.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, destination: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            index: u64::read(buf)?,
            request: SignedWithdrawal::read_cfg(buf, destination)?,
            carried: false,
        })
    }
}

impl<H, P> Write for SettlementChain<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.operator.write(buf);
        self.certificate_scheme.committee().write(buf);
        self.current_state_root.write(buf);
        self.finalized_logs.write(buf);
        self.finalized_rows.start.write(buf);
        self.finalized_rows.end.write(buf);
        self.current_liability.write(buf);
        self.custody_balance.write(buf);
        self.claimable_balance.write(buf);
        self.consumed_deposit_ids.write(buf);
        self.withdrawal_replay_expiries.write(buf);
        self.intake.write(buf);
        self.pulled.write(buf);
        self.pending_deposits.write(buf);
        self.runs.len().write(buf);
        for run in &self.runs {
            run.write(buf);
        }
        self.unfinalized_deposit_total.write(buf);
        self.pending_withdrawals.write(buf);
        Self::write_config(&self.config, buf);
        self.expected_epoch.write(buf);
        match &self.registered {
            None => 0_u8.write(buf),
            Some(registered) => {
                1_u8.write(buf);
                Self::write_registered(registered, buf);
            }
        }
        self.queued.len().write(buf);
        for queued in &self.queued {
            Self::write_queued(queued, buf);
        }
        self.pipeline.len().write(buf);
        for entry in &self.pipeline {
            Self::write_pipeline_entry(entry, buf);
        }
        match &self.hard_fault {
            None => 0_u8.write(buf),
            Some(reason) => {
                1_u8.write(buf);
                Self::write_reason(reason, buf);
            }
        }
        self.admission_fence_epoch.write(buf);
        self.invalid_from.write(buf);
        match &self.hard_fault_claims {
            None => 0_u8.write(buf),
            Some(claims) => {
                1_u8.write(buf);
                Self::write_claims(claims, buf);
            }
        }
        self.fault_settled.write(buf);
    }
}

impl<H, P> EncodeSize for SettlementChain<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
            + self.operator.encode_size()
            + self.certificate_scheme.committee().encode_size()
            + self.current_state_root.encode_size()
            + self.finalized_logs.encode_size()
            + 5 * u64::SIZE
            + self.consumed_deposit_ids.encode_size()
            + self.withdrawal_replay_expiries.encode_size()
            + 2 * u64::SIZE
            + self.pending_deposits.encode_size()
            + self.runs.len().encode_size()
            + self.runs.len() * Run::<P>::SIZE
            + u64::SIZE
            + self.pending_withdrawals.encode_size()
            + Self::size_config(&self.config)
            + u64::SIZE
            + 1
            + self.registered.as_ref().map_or(0, Self::size_registered)
            + self.queued.len().encode_size()
            + self.queued.iter().map(Self::size_queued).sum::<usize>()
            + self.pipeline.len().encode_size()
            + self
                .pipeline
                .iter()
                .map(Self::size_pipeline_entry)
                .sum::<usize>()
            + 1
            + self.hard_fault.as_ref().map_or(0, Self::size_reason)
            + self.admission_fence_epoch.encode_size()
            + self.invalid_from.encode_size()
            + 1
            + self.hard_fault_claims.as_ref().map_or(0, Self::size_claims)
            + self.fault_settled.encode_size()
    }
}

impl<H, P> Read for SettlementChain<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Cfg = Bounds;

    /// Decodes a chain persisted by [`Write`].
    ///
    /// Decoding is structural: collections are bounded by [`Bounds`] and every
    /// nested codec validates its own shape, but the semantic invariants that
    /// [`SettlementChain::new`] and each mutation maintain (custody equations,
    /// anchor derivations, pipeline ancestry) are not re-proven. The caller
    /// must therefore only decode encodings whose integrity is established
    /// externally, for example bytes committed under a certified state root.
    /// Derived lookup structures are rebuilt from the decoded authoritative
    /// state, so `encode(decode(bytes)) == bytes` for accepted inputs.
    fn read_cfg(buf: &mut impl Buf, bounds: &Self::Cfg) -> Result<Self, CodecError> {
        let deployment = H::Digest::read(buf)?;
        let operator = P::read(buf)?;
        let committee = Committee::read_cfg(buf, &bounds.committee)?;
        let committee_len = committee.members().len();
        let committee_commitment = committee.commitment::<H>();
        let certificate_scheme = bls12381::Scheme::verifier(committee);
        let current_state_root = StateRoot::read(buf)?;
        let finalized_logs = Heads::read(buf)?;
        let finalized_rows = u64::read(buf)?..u64::read(buf)?;
        let current_liability = u64::read(buf)?;
        let custody_balance = u64::read(buf)?;
        let claimable_balance = u64::read(buf)?;
        let consumed_deposit_ids =
            BTreeSet::<H::Digest>::read_cfg(buf, &(RangeCfg::new(0..=bounds.items), ()))?;
        let withdrawal_replay_expiries = BTreeSet::<(u64, WithdrawalId<H::Digest>)>::read_cfg(
            buf,
            &(RangeCfg::new(0..=bounds.items), ((), ())),
        )?;
        let consumed_withdrawal_ids = withdrawal_replay_expiries
            .iter()
            .map(|(_, request_id)| *request_id)
            .collect();
        let intake = u64::read(buf)?;
        let pulled = u64::read(buf)?;
        let pending_deposits =
            BTreeMap::<P, u64>::read_cfg(buf, &(RangeCfg::new(0..=bounds.items), ((), ())))?;
        let runs = VecDeque::from(Vec::<Run<P>>::read_cfg(
            buf,
            &(RangeCfg::new(0..=bounds.items), ()),
        )?);
        let unfinalized_deposit_total = u64::read(buf)?;
        let mut pending_withdrawals = BTreeMap::<P, Queued<P, H::Digest>>::read_cfg(
            buf,
            &(
                RangeCfg::new(0..=bounds.items),
                ((), RangeCfg::new(0..=bounds.destination)),
            ),
        )?;
        let pending_withdrawal_deadlines = pending_withdrawals
            .iter()
            .map(|(account, queued)| (queued.request.body().deadline(), account.clone()))
            .collect();
        let config = Self::read_config(buf)?;
        let expected_epoch = u64::read(buf)?;
        let registered = match u8::read(buf)? {
            0 => None,
            1 => Some(Self::read_registered(buf, bounds)?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        let count = usize::read_cfg(buf, &RangeCfg::new(..))?;
        let mut queued = VecDeque::with_capacity(
            count.min(buf.remaining() / EpochContext::<P, H::Digest>::SIZE),
        );
        for _ in 0..count {
            queued.push_back(Self::read_queued(buf, bounds)?);
        }
        let entries = usize::read_cfg(buf, &RangeCfg::new(0..=bounds.items))?;
        let mut pipeline = VecDeque::with_capacity(entries.min(buf.remaining()));
        for _ in 0..entries {
            pipeline.push_back(Self::read_pipeline_entry(buf, bounds, committee_len)?);
        }
        let hard_fault = match u8::read(buf)? {
            0 => None,
            1 => Some(Self::read_reason(buf)?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        let admission_fence_epoch = Option::<u64>::read(buf)?;
        let invalid_from = Option::<BatchId<H::Digest>>::read(buf)?;
        let hard_fault_claims = match u8::read(buf)? {
            0 => None,
            1 => Some(Self::read_claims(buf, bounds)?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        let fault_settled = bool::read(buf)?;
        mark_carried(
            &mut pending_withdrawals,
            registered
                .iter()
                .map(|registered| &registered.withdrawals)
                .chain(queued.iter().map(|queued| &queued.withdrawals)),
        );
        Ok(Self {
            deployment,
            operator,
            certificate_scheme,
            committee_commitment,
            current_state_root,
            finalized_logs,
            finalized_rows,
            current_liability,
            custody_balance,
            claimable_balance,
            consumed_deposit_ids,
            consumed_withdrawal_ids,
            withdrawal_replay_expiries,
            intake,
            pulled,
            pending_deposits,
            runs,
            unfinalized_deposit_total,
            pending_withdrawals,
            pending_withdrawal_deadlines,
            config,
            expected_epoch,
            registered,
            queued,
            pipeline,
            hard_fault,
            admission_fence_epoch,
            invalid_from,
            hard_fault_claims,
            fault_settled,
            _hasher: PhantomData,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<H, P> arbitrary::Arbitrary<'_> for SettlementChain<H, P>
where
    H: Hasher,
    H::Digest: for<'a> arbitrary::Arbitrary<'a>,
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        fn small(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<usize> {
            u.int_in_range(0..=2)
        }
        fn kind(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<ChallengeKind> {
            u.choose(&[
                ChallengeKind::HigherAckDebit,
                ChallengeKind::HigherAckEntry,
                ChallengeKind::AckFork,
            ])
            .copied()
        }
        fn reason<H, P>(
            u: &mut arbitrary::Unstructured<'_>,
        ) -> arbitrary::Result<HardFaultReason<P, H::Digest>>
        where
            H: Hasher,
            H::Digest: for<'a> arbitrary::Arbitrary<'a>,
            P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
        {
            Ok(match u.int_in_range(0..=3)? {
                0 => HardFaultReason::ProvenChallenge {
                    batch_id: u.arbitrary()?,
                    kind: kind(u)?,
                },
                1 => HardFaultReason::ExpiredDeposit {
                    account: u.arbitrary()?,
                    expired_at: u.arbitrary()?,
                },
                2 => HardFaultReason::ExpiredWithdrawal {
                    account: u.arbitrary()?,
                    expired_at: u.arbitrary()?,
                },
                _ => HardFaultReason::ExpiredRegistration {
                    anchor: u.arbitrary()?,
                    epoch: u.arbitrary()?,
                    expired_at: u.arbitrary()?,
                },
            })
        }
        type Packed<H, P> = (
            PackedWithdrawals<P, <H as Hasher>::Digest>,
            Option<(u64, P)>,
        );
        fn packed<H, P>(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Packed<H, P>>
        where
            H: Hasher,
            H::Digest: for<'a> arbitrary::Arbitrary<'a>,
            P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
            P::Signature: for<'a> arbitrary::Arbitrary<'a>,
        {
            let mut requests = (0..small(u)?)
                .map(|_| u.arbitrary::<SignedWithdrawal<P, H::Digest>>())
                .collect::<arbitrary::Result<Vec<_>>>()?;
            requests.sort_unstable_by(|a, b| a.account().as_ref().cmp(b.account().as_ref()));
            requests.dedup_by(|a, b| a.account().as_ref() == b.account().as_ref());
            let requests =
                WithdrawalBatch::new(requests).map_err(|_| arbitrary::Error::IncorrectFormat)?;
            let deadline = earliest_withdrawal(&requests);
            Ok((PackedWithdrawals::new(&requests), deadline))
        }

        let committee: Committee = u.arbitrary()?;
        let committee_commitment = committee.commitment::<H>();
        let certificate_scheme = bls12381::Scheme::verifier(committee);

        let withdrawal_replay_expiries: BTreeSet<(u64, WithdrawalId<H::Digest>)> = u.arbitrary()?;
        let consumed_withdrawal_ids = withdrawal_replay_expiries
            .iter()
            .map(|(_, request_id)| *request_id)
            .collect();
        let pulled = u.int_in_range(0..=u64::MAX - 8)?;
        let mut intake = pulled;
        let mut pending_deposits = BTreeMap::new();
        for _ in 0..small(u)? {
            pending_deposits.insert(u.arbitrary::<P>()?, u.arbitrary::<u64>()?);
        }
        let mut runs = VecDeque::new();
        let mut deadline = u.arbitrary::<u64>()?;
        for _ in 0..small(u)? {
            intake += u.int_in_range(1..=2)?;
            deadline = deadline.saturating_add(u.int_in_range(1..=4)?);
            runs.push_back(Run {
                end: intake,
                deadline,
                account: u.arbitrary()?,
            });
        }
        let mut pending_withdrawals = BTreeMap::new();
        for _ in 0..small(u)? {
            let request: SignedWithdrawal<P, H::Digest> = u.arbitrary()?;
            pending_withdrawals.insert(
                request.account().clone(),
                Queued {
                    index: u.int_in_range(pulled..=intake)?,
                    request,
                    carried: false,
                },
            );
            intake += 1;
        }
        let pending_withdrawal_deadlines = pending_withdrawals
            .iter()
            .map(|(account, queued)| (queued.request.body().deadline(), account.clone()))
            .collect();
        let nonzero_u64 = |u: &mut arbitrary::Unstructured<'_>| -> arbitrary::Result<NonZeroU64> {
            Ok(NonZeroU64::new(u.arbitrary::<u64>()?.max(1)).expect("value is at least one"))
        };
        let config = SettlementConfig::new(
            EpochDeadlinePolicy::new(nonzero_u64(u)?, nonzero_u64(u)?),
            nonzero_u64(u)?,
            nonzero_u64(u)?,
            nonzero_u64(u)?,
            u.int_in_range(0..=1_024)?,
            NonZeroUsize::new(u.int_in_range(1..=1_024)?).expect("range starts above zero"),
        );
        let registered = if u.arbitrary()? {
            let deposits: DepositBatch<P> = u.arbitrary()?;
            // The frontier can carry a chain-queued request, which decoding marks carried.
            let withdrawals: WithdrawalBatch<P, H::Digest> =
                match pending_withdrawals.values().next() {
                    Some(queued) if u.arbitrary()? => {
                        WithdrawalBatch::new(vec![queued.request.clone()])
                            .map_err(|_| arbitrary::Error::IncorrectFormat)?
                    }
                    _ => u.arbitrary()?,
                };
            let withdrawal_deadline = earliest_withdrawal(&withdrawals);
            Some(RegisteredClose {
                context: u.arbitrary()?,
                deposits,
                withdrawals,
                withdrawal_deadline,
            })
        } else {
            None
        };
        let mut queued = VecDeque::new();
        if registered.is_some() {
            for _ in 0..small(u)? {
                let deposits: DepositBatch<P> = u.arbitrary()?;
                let withdrawals: WithdrawalBatch<P, H::Digest> = u.arbitrary()?;
                let withdrawal_deadline = earliest_withdrawal(&withdrawals);
                queued.push_back(QueuedEpoch {
                    context: u.arbitrary()?,
                    floors: u.arbitrary()?,
                    deposits,
                    withdrawals,
                    withdrawal_deadline,
                });
            }
        }
        let mut pipeline = VecDeque::new();
        for _ in 0..small(u)? {
            let deposits: DepositBatch<P> = u.arbitrary()?;
            let (withdrawals, withdrawal_deadline) = packed::<H, P>(u)?;
            let status = match u.int_in_range(0..=2)? {
                0 => BatchStatus::Pending,
                1 => BatchStatus::Challenged(kind(u)?),
                _ => BatchStatus::Invalidated(u.arbitrary()?),
            };
            let context: CloseContext<P, H::Digest> = u.arbitrary()?;
            let available =
                u128::from(context.predecessor_liability()) + u128::from(deposits.total());
            let withdrawal_total = u128::from(u.arbitrary::<u64>()?)
                .min(available)
                .max(available.saturating_sub(u128::from(u64::MAX)));
            let withdrawal_total = withdrawal_total as u64;
            let successor_liability = (available - u128::from(withdrawal_total)) as u64;
            pipeline.push_back(PipelineEntry {
                admitted: AdmittedClose {
                    context,
                    deposit_total: deposits.total(),
                    deposits: PackedDeposits::new(&deposits),
                    withdrawals,
                    withdrawal_deadline,
                },
                batch: PendingBatch {
                    header: u.arbitrary()?,
                    roots: u.arbitrary()?,
                    withdrawal_total,
                    certificate: u.arbitrary()?,
                    successor_liability,
                    status,
                },
            });
        }
        let hard_fault = if u.arbitrary()? {
            Some(reason::<H, P>(u)?)
        } else {
            None
        };
        let hard_fault_claims = if u.arbitrary()? {
            let mut admitted_withdrawals = Vec::new();
            for _ in 0..small(u)? {
                admitted_withdrawals.push(packed::<H, P>(u)?.0);
            }
            let mut pending_withdrawals = BTreeMap::new();
            for _ in 0..small(u)? {
                let request: SignedWithdrawal<P, H::Digest> = u.arbitrary()?;
                pending_withdrawals.insert(request.account().clone(), request);
            }
            Some(HardFaultClaims {
                frozen_state_root: u.arbitrary()?,
                state_liability: u.arbitrary()?,
                remaining_state_liability: u.arbitrary()?,
                unfinalized_deposit_total: u.arbitrary()?,
                custody_balance: u.arbitrary()?,
                deposits: u.arbitrary()?,
                pending_withdrawals,
                admitted_withdrawals,
                claimed_accounts: u.arbitrary()?,
            })
        } else {
            None
        };
        mark_carried(
            &mut pending_withdrawals,
            registered
                .iter()
                .map(|registered| &registered.withdrawals)
                .chain(queued.iter().map(|queued| &queued.withdrawals)),
        );
        Ok(Self {
            deployment: u.arbitrary()?,
            operator: u.arbitrary()?,
            certificate_scheme,
            committee_commitment,
            current_state_root: u.arbitrary()?,
            finalized_logs: u.arbitrary()?,
            finalized_rows: u.arbitrary()?,
            current_liability: u.arbitrary()?,
            custody_balance: u.arbitrary()?,
            claimable_balance: u.arbitrary()?,
            consumed_deposit_ids: u.arbitrary()?,
            consumed_withdrawal_ids,
            withdrawal_replay_expiries,
            intake,
            pulled,
            pending_deposits,
            runs,
            unfinalized_deposit_total: u.arbitrary()?,
            pending_withdrawals,
            pending_withdrawal_deadlines,
            config,
            expected_epoch: u.arbitrary()?,
            registered,
            queued,
            pipeline,
            hard_fault,
            admission_fence_epoch: u.arbitrary()?,
            invalid_from: u.arbitrary()?,
            hard_fault_claims,
            fault_settled: u.arbitrary()?,
            _hasher: PhantomData,
        })
    }
}

/// Payout adjudication failure. Refresh both the latest-root proof and claimed neighbors on retry.
#[derive(Debug, Error)]
pub enum ClaimError {
    /// The supplied claimed neighbors are invalid or already cover this location.
    #[error("claimed payout neighbors are unavailable")]
    Unavailable,
    /// The output exceeds the aggregate unpaid reserve.
    #[error("claim exceeds the aggregate reserve")]
    Reserve,
    /// The proof does not authenticate the output at the current finalized head.
    #[error(transparent)]
    Proof(#[from] TransitionError),
}

/// Settlement lifecycle failure.
#[derive(Debug, Error)]
pub enum SettlementError {
    /// The context names another deployment.
    #[error("close context does not equal the settlement deployment")]
    Deployment,
    /// The context names another receipt-signing operator.
    #[error("close context operator does not equal the settlement operator")]
    OperatorMismatch,
    /// The context epoch is not the next epoch to register.
    #[error("close context is not the next epoch to register")]
    EpochSequence,
    /// A state root does not extend the current authenticated ancestry.
    #[error("state root does not extend the authenticated ancestry")]
    StateAncestry,
    /// The certificate committee differs from the anchor-bound committee.
    #[error("certificate committee does not match the authenticated committee")]
    CommitteeMismatch,
    /// Supplied exact batches do not match the context's sealed roots.
    #[error("boundary batches do not match their sealed roots")]
    BoundaryRoot,
    /// An admitted close's packed deposit batch does not decode exactly.
    #[error("admitted deposit batch does not decode exactly")]
    DepositWitness,
    /// Registered withdrawals omit or alter a chain-queued request in the pulled inbox prefix.
    #[error("registered withdrawals do not carry every request queued in their inbox prefix")]
    WithdrawalWitness,
    /// A registration's inbox end precedes the first unpulled index or exceeds the inbox.
    #[error("registration inbox end is outside the unpulled inbox")]
    IntakeRange,
    /// The inbox index would overflow.
    #[error("inbox index overflow")]
    IntakeOverflow,
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
    /// A balance opening does not authenticate the authorizing account.
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
    /// No registered epoch awaits admission.
    #[error("no registered epoch awaits admission")]
    NoRegisteredEpoch,
    /// An admission frontier's deadlines cannot be represented by the settlement clock.
    #[error("epoch deadlines exceed the settlement clock")]
    EpochDeadlineOverflow,
    /// The retained certificate does not meet the minimum valid quorum.
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
    /// A Current account proof failed verification.
    #[error("invalid account proof: {0}")]
    State(#[from] qmdb::Error),
    /// Vector opening or boundary commitment verification failed.
    #[error("invalid vector commitment: {0}")]
    Commitment(#[from] commitment::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        boundary::{DepositRecord, WithdrawalBody},
        challenge::{AccountLookup, AckWitness, ChangeAbsence, EntryWitness, HigherEntryLookup},
        commitment::{VectorKind, VectorRoot},
        custody::Epoch,
        logs::{Floors, Heads},
        payment::{SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck, VectorSendBody},
        qmdb::{Mutations, StateHead, StateLookup, account_key},
        state::SettlementOutput,
        tests::{Accepted, TestState, new_state, replay_state},
        transition::{
            ActivityRange, CloseLimits, OperatorKey, OperatorVariant, Terminal,
            prepare_close_with_strategy, validate_close_with_strategy,
        },
        vector::{OutEntry, OutVector},
    };
    use commonware_codec::{Copying, Decode, DecodeExt, Error as CodecError, FixedSize, ReadExt};
    use commonware_cryptography::{
        Sha256, Signer as _,
        bls12381::primitives::{
            group::{Private as BlsPrivate, Scalar},
            ops::{compute_public, sign_message},
            variant::MinSig,
        },
        sha256::Digest as ShaDigest,
    };
    use commonware_cryptography_curve25519::signing::{
        BatchVerifier as PaymentBatchVerifier, Signature, SigningKey,
        StrictVerifyingKey as VerifyingKey,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{Array, Span, test_rng};
    use core::{fmt, future::Future, ops::Deref};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    type TestChallenge = Challenge<VerifyingKey, ShaDigest>;
    type TestClose = crate::bajillion::transition::Close<VerifyingKey, ShaDigest>;
    // The fixture checkpoints the active machine, independently retained claim records, and the
    // deposits the embedding stores by inbox index until a registration pulls them.
    struct TestChain {
        active: SettlementChain<Sha256, VerifyingKey>,
        intervals: BTreeMap<u64, u64>,
        deposits: BTreeMap<u64, (VerifyingKey, u64)>,
    }

    impl Deref for TestChain {
        type Target = SettlementChain<Sha256, VerifyingKey>;
        fn deref(&self) -> &Self::Target {
            &self.active
        }
    }

    impl core::ops::DerefMut for TestChain {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.active
        }
    }

    impl TestChain {
        fn new(
            deployment: ShaDigest,
            operator: VerifyingKey,
            committee: Committee,
            current_state: &Genesis<ShaDigest>,
            expected_epoch: u64,
            config: SettlementConfig,
        ) -> Result<Self, SettlementError> {
            Ok(Self {
                active: SettlementChain::new(
                    deployment,
                    operator,
                    committee,
                    current_state,
                    expected_epoch,
                    config,
                )?,
                intervals: BTreeMap::new(),
                deposits: BTreeMap::new(),
            })
        }

        // Records a deposit and stores it under its inbox index, as the embedding does.
        fn record_deposit(
            &mut self,
            now: u64,
            deposit_id: ShaDigest,
            account: VerifyingKey,
            amount: u64,
        ) -> Result<u64, SettlementError> {
            let index = self
                .active
                .record_deposit(now, deposit_id, account.clone(), amount)?;
            self.deposits.insert(index, (account, amount));
            Ok(index)
        }

        // Aggregates the stored deposits from the first unpulled index up to `end`.
        fn deposits_to(&self, end: u64) -> TestDeposits {
            let start = self.active.pulled();
            let mut totals = BTreeMap::<VerifyingKey, u64>::new();
            for (account, amount) in self
                .deposits
                .range(start..end.max(start))
                .map(|(_, deposit)| deposit)
            {
                *totals.entry(account.clone()).or_default() += amount;
            }
            DepositBatch::new(
                totals
                    .into_iter()
                    .map(|(account, amount)| DepositRecord::new(account, amount).unwrap())
                    .collect(),
            )
            .unwrap()
        }

        // Aggregates every unpulled deposit.
        fn pending_deposits(&self) -> TestDeposits {
            self.deposits_to(self.active.intake())
        }

        // Returns the chain-queued withdrawals a pull of the whole inbox must carry.
        fn pending_withdrawals(&self) -> TestWithdrawals {
            self.active.pending_withdrawals(self.active.intake())
        }

        // Pulls the inbox up to `end` with the stored aggregate of its deposits, then deletes the
        // pulled records as the embedding does.
        fn register_through<F: Fn(&Bytes) -> bool>(
            &mut self,
            now: u64,
            context: EpochContext<VerifyingKey, ShaDigest>,
            end: u64,
            withdrawals: TestWithdrawals,
            eligible: F,
        ) -> Result<(), SettlementError> {
            let start = self.active.pulled();
            let deposits = self.deposits_to(end);
            self.active
                .register_epoch(now, context, end, deposits, withdrawals, eligible)?;
            self.deposits
                .retain(|index, _| !(start..end).contains(index));
            Ok(())
        }

        // Registers the next epoch with a pull of the whole inbox.
        fn register_epoch<F: Fn(&Bytes) -> bool>(
            &mut self,
            now: u64,
            context: EpochContext<VerifyingKey, ShaDigest>,
            withdrawals: TestWithdrawals,
            eligible: F,
        ) -> Result<(), SettlementError> {
            let end = self.active.intake();
            self.register_through(now, context, end, withdrawals, eligible)
        }

        fn finalize(&mut self, now: u64) -> Result<FinalizedBatch<ShaDigest>, SettlementError> {
            let (batch, commit_index) = self.active.finalize(now)?;
            self.insert_claimed(commit_index)
                .expect("a newly finalized commit is not already claimed");
            Ok(batch)
        }

        fn claimed_neighbors(&self, index: u64) -> [Option<ClaimedRange>; 2] {
            let before = self
                .intervals
                .range(..=index)
                .next_back()
                .map(|(&start, &end)| ClaimedRange { start, end });
            let after = self
                .intervals
                .range((
                    core::ops::Bound::Excluded(index),
                    core::ops::Bound::Unbounded,
                ))
                .next()
                .map(|(&start, &end)| ClaimedRange { start, end });
            [before, after]
        }

        fn apply_claimed(&mut self, neighbors: [Option<ClaimedRange>; 2], claimed: ClaimedRange) {
            if let Some(after) = neighbors[1]
                && claimed.end == after.end
            {
                assert_eq!(self.intervals.remove(&after.start), Some(after.end));
            }
            let replaced = self.intervals.insert(claimed.start, claimed.end);
            if neighbors[0].is_some_and(|before| before.start == claimed.start) {
                assert_eq!(replaced, neighbors[0].map(|before| before.end));
            } else {
                assert_eq!(replaced, None);
            }
        }

        fn insert_claimed(&mut self, index: u64) -> Result<ClaimedRange, ClaimError> {
            let neighbors = self.claimed_neighbors(index);
            let claimed = ClaimedRange::insert(index, &neighbors)?;
            self.apply_claimed(neighbors, claimed);
            Ok(claimed)
        }

        fn claim_withdrawal(
            &mut self,
            claim: &WithdrawalClaim<ShaDigest>,
        ) -> Result<WithdrawalOutput, ClaimError> {
            let neighbors = self.claimed_neighbors(claim.position());
            let effect = self.active.claim_withdrawal(&neighbors, claim)?;
            assert_eq!(self.insert_claimed(effect.index)?, effect.claimed);
            Ok(effect.output)
        }

        // Registers the epoch of an expected bound context. When the epoch becomes the frontier,
        // settlement must bind exactly that context.
        fn register<F: Fn(&Bytes) -> bool>(
            &mut self,
            now: u64,
            context: TestContext,
            withdrawals: TestWithdrawals,
            eligible: F,
        ) -> Result<(), SettlementError> {
            let epoch = context.payment().epoch();
            self.register_epoch(now, context.epoch_context().clone(), withdrawals, eligible)?;
            if let Some(registered) = self.active.registered()
                && registered.context.payment().epoch() == epoch
            {
                assert_eq!(registered.context, &context);
            }
            Ok(())
        }

        // Returns a clone of the bound admission frontier.
        fn frontier(&self) -> TestContext {
            self.active
                .registered()
                .expect("an epoch awaits admission")
                .context
                .clone()
        }
    }

    impl Write for TestChain {
        fn write(&self, buf: &mut impl BufMut) {
            self.active.write(buf);
            self.intervals.write(buf);
            self.deposits.write(buf);
        }
    }
    impl EncodeSize for TestChain {
        fn encode_size(&self) -> usize {
            self.active.encode_size() + self.intervals.encode_size() + self.deposits.encode_size()
        }
    }
    impl Read for TestChain {
        type Cfg = Bounds;
        fn read_cfg(buf: &mut impl Buf, bounds: &Bounds) -> Result<Self, CodecError> {
            Ok(Self {
                active: SettlementChain::read_cfg(buf, bounds)?,
                intervals: BTreeMap::read_cfg(buf, &(RangeCfg::new(0..=bounds.items), ((), ())))?,
                deposits: BTreeMap::read_cfg(
                    buf,
                    &(RangeCfg::new(0..=bounds.items), ((), ((), ()))),
                )?,
            })
        }
    }
    type TestCache = Snapshot;
    type TestContext = CloseContext<VerifyingKey, ShaDigest>;
    type TestDeposits = DepositBatch<VerifyingKey>;
    type TestWithdrawals = WithdrawalBatch<VerifyingKey, ShaDigest>;

    #[test]
    fn claimed_ranges_merge_in_every_order_and_accept_the_maximum_endpoint() {
        fn insert(intervals: &mut BTreeMap<u64, u64>, index: u64) {
            let before = intervals
                .range(..=index)
                .next_back()
                .map(|(&start, &end)| ClaimedRange { start, end });
            let after = intervals
                .range((
                    core::ops::Bound::Excluded(index),
                    core::ops::Bound::Unbounded,
                ))
                .next()
                .map(|(&start, &end)| ClaimedRange { start, end });
            let claimed = ClaimedRange::insert(index, &[before, after]).unwrap();
            if after.is_some_and(|after| claimed.end == after.end) {
                intervals.remove(&after.unwrap().start);
            }
            intervals.insert(claimed.start, claimed.end);
        }

        for first in 1..=4 {
            for second in 1..=4 {
                for third in 1..=4 {
                    for fourth in 1..=4 {
                        let order = [first, second, third, fourth];
                        if BTreeSet::from(order).len() != order.len() {
                            continue;
                        }
                        let mut intervals = BTreeMap::new();
                        for index in order {
                            insert(&mut intervals, index);
                        }
                        assert_eq!(intervals, BTreeMap::from([(1, 5)]));
                    }
                }
            }
        }

        let max = *mmr::Family::MAX_LEAVES;
        let claimed = ClaimedRange::insert(max - 1, &[None, None]).unwrap();
        assert_eq!(
            claimed,
            ClaimedRange {
                start: max - 1,
                end: max
            }
        );
        assert_eq!(ClaimedRange::decode(claimed.encode()).unwrap(), claimed);
    }

    #[test]
    fn claimed_ranges_reject_invalid_bounds_neighbors_and_duplicates() {
        let max = *mmr::Family::MAX_LEAVES;
        assert!(matches!(
            ClaimedRange::insert(0, &[None, None]),
            Err(ClaimError::Unavailable)
        ));
        assert!(matches!(
            ClaimedRange::insert(max, &[None, None]),
            Err(ClaimError::Unavailable)
        ));
        assert!(matches!(
            ClaimedRange::insert(u64::MAX, &[None, None]),
            Err(ClaimError::Unavailable)
        ));
        assert!(matches!(
            ClaimedRange::insert(
                4,
                &[
                    Some(ClaimedRange { start: 2, end: 5 }),
                    Some(ClaimedRange { start: 6, end: 7 }),
                ],
            ),
            Err(ClaimError::Unavailable)
        ));
        assert!(matches!(
            ClaimedRange::insert(
                4,
                &[
                    Some(ClaimedRange { start: 5, end: 6 }),
                    Some(ClaimedRange { start: 7, end: 8 }),
                ],
            ),
            Err(ClaimError::Unavailable)
        ));
        assert!(matches!(
            ClaimedRange::insert(
                4,
                &[
                    Some(ClaimedRange { start: 1, end: 3 }),
                    Some(ClaimedRange { start: 4, end: 5 }),
                ],
            ),
            Err(ClaimError::Unavailable)
        ));

        for range in [
            ClaimedRange { start: 0, end: 1 },
            ClaimedRange { start: 1, end: 1 },
            ClaimedRange {
                start: max - 1,
                end: u64::MAX,
            },
        ] {
            assert!(ClaimedRange::decode(range.encode()).is_err());
        }
    }

    #[test]
    fn configured_genesis_checks_canonical_accounts_and_liability() {
        let root = StateRoot::new(Sha256::hash(&[b"configured-genesis"]));
        let first = qmdb::AccountKey::new([1; 32]);
        let second = qmdb::AccountKey::new([2; 32]);
        let one = NonZeroU64::new(1).unwrap();
        let maximum = NonZeroU64::new(u64::MAX).unwrap();

        let empty = Genesis::new(root, 1, &[]).unwrap();
        assert_eq!(empty.root(), root);
        assert_eq!(empty.operations(), 1);
        assert_eq!(empty.liability(), 0);
        let full = Genesis::new(root, 7, &[(first.clone(), maximum)]).unwrap();
        assert_eq!(full.liability(), u64::MAX);
        assert_eq!(full.operations(), 7);
        let accounts = [(first.clone(), one), (second.clone(), one)];
        assert_eq!(Genesis::new(root, 9, &accounts).unwrap().liability(), 2);
        assert!(matches!(
            Genesis::new(root, 9, &[(second.clone(), one), (first.clone(), one)]),
            Err(qmdb::Error::Order)
        ));
        assert!(matches!(
            Genesis::new(root, 9, &[(first.clone(), one), (first.clone(), one)]),
            Err(qmdb::Error::Order)
        ));
        assert!(matches!(
            Genesis::new(root, 9, &[(first, maximum), (second, one)]),
            Err(qmdb::Error::Arithmetic)
        ));
    }

    #[test]
    fn configured_genesis_matches_validated_head_and_initial_custody() {
        let fixture = harness(&[5, 7]);
        let head = fixture.cache.head();
        let accounts = fixture
            .cache
            .balances()
            .into_iter()
            .map(|(key, balance)| {
                (
                    account_key(&key).unwrap(),
                    NonZeroU64::new(balance).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let configured = Genesis::new(head.root(), head.operations(), &accounts).unwrap();
        assert_eq!(configured.root(), head.root());
        assert_eq!(configured.operations(), head.operations());
        assert_eq!(configured.liability(), 12);
        let chain = TestChain::new(
            fixture.deployment,
            fixture.operator.public_key(),
            committee(101),
            &configured,
            0,
            config(1),
        )
        .unwrap();
        assert_eq!(chain.current_state_root, configured.root());
        assert_eq!(chain.current_liability, 12);
        assert_eq!(chain.custody_balance, 12);
    }

    // Test snapshots retain accepted heads and mutations for deterministic model transitions.
    #[derive(Clone)]
    struct Snapshot {
        history: Vec<Accepted>,
        liability: u64,
    }

    impl Snapshot {
        fn new(balances: Vec<(VerifyingKey, u64)>) -> Self {
            let liability = balances
                .iter()
                .try_fold(0u64, |total, (_, balance)| total.checked_add(*balance))
                .unwrap();
            deterministic::Runner::default().start(|runtime| async move {
                let mut mutations = balances
                    .iter()
                    .map(|(account, balance)| {
                        (account_key(account).unwrap(), NonZeroU64::new(*balance))
                    })
                    .collect::<Mutations>();
                mutations.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                let state = new_state(runtime, "snapshot", balances).await;
                Self {
                    history: vec![Accepted::genesis(&state, mutations)],
                    liability,
                }
            })
        }

        fn extended(&self, accepted: Accepted, liability: u64) -> Self {
            let mut history = self.history.clone();
            history.push(accepted);
            Self { history, liability }
        }

        fn head(&self) -> &StateHead<ShaDigest> {
            &self
                .history
                .last()
                .expect("genesis is always accepted")
                .head
        }
        fn root(&self) -> StateRoot<ShaDigest> {
            self.head().root()
        }
        fn liability(&self) -> u64 {
            self.liability
        }

        fn configured_state(&self) -> Genesis<ShaDigest> {
            let accounts = self
                .balances()
                .into_iter()
                .map(|(account, balance)| {
                    (
                        account_key(&account).unwrap(),
                        NonZeroU64::new(balance).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let configured =
                Genesis::new(self.root(), self.head().operations(), &accounts).unwrap();
            assert_eq!(configured.liability(), self.liability);
            configured
        }

        async fn reopen(&self, runtime: deterministic::Context, prefix: &str) -> TestState {
            replay_state(runtime, prefix, &self.history).await.unwrap()
        }

        fn with_state<T, F, Fut>(&self, prefix: &'static str, f: F) -> T
        where
            F: FnOnce(TestState) -> Fut,
            Fut: Future<Output = T>,
        {
            let snapshot = self.clone();
            deterministic::Runner::default().start(|runtime| async move {
                let state = snapshot.reopen(runtime, prefix).await;
                f(state).await
            })
        }

        fn opening(
            &self,
            account: &VerifyingKey,
        ) -> Result<StateOpening<VerifyingKey, ShaDigest>, qmdb::Error> {
            let account = account.clone();
            self.with_state("opening", |state| async move {
                state.state().opening(account).await
            })
        }

        fn lookup(&self, account: &VerifyingKey) -> StateLookup<ShaDigest> {
            let key = account_key(account).unwrap();
            self.with_state("lookup", |state| async move {
                state.state().lookup(&key).await.unwrap()
            })
        }

        fn account_lookup(
            &self,
            context: &TestContext,
            roots: &RootBundle<ShaDigest>,
            account: &VerifyingKey,
        ) -> AccountLookup<VerifyingKey, ShaDigest> {
            let epoch = context.payment().epoch();
            let range = roots.activity_range(context).unwrap();
            let account = account.clone();
            self.with_state("account-lookup", |state| async move {
                let view = Epoch::at(state.logs(), epoch, range).await.unwrap();
                view.account_lookup(state.logs(), &account).await.unwrap()
            })
        }

        fn higher_entry_lookup(
            &self,
            context: &TestContext,
            roots: &RootBundle<ShaDigest>,
            payer: &VerifyingKey,
            recipient: &VerifyingKey,
        ) -> HigherEntryLookup<VerifyingKey, ShaDigest> {
            let epoch = context.payment().epoch();
            let range = roots.activity_range(context).unwrap();
            let payer = payer.clone();
            let recipient = recipient.clone();
            self.with_state("higher-entry-lookup", |state| async move {
                let view = Epoch::at(state.logs(), epoch, range).await.unwrap();
                view.higher_entry_lookup(state.logs(), &payer, &recipient)
                    .await
                    .unwrap()
            })
        }

        fn payout_claim(
            &self,
            head: &LogHead<ShaDigest>,
            position: u64,
        ) -> WithdrawalClaim<ShaDigest> {
            let head = *head;
            self.with_state("payout-claim", |state| async move {
                let (opening, operations) = state
                    .logs()
                    .payout_opening(&head, position, NonZeroU64::MIN)
                    .await
                    .unwrap();
                let [crate::bajillion::logs::PayoutOperation::Append(output)] =
                    operations.as_slice()
                else {
                    panic!("a one-output proof contains its payout append");
                };
                WithdrawalClaim::new(output.clone(), opening)
            })
        }

        fn balances(&self) -> Vec<(VerifyingKey, u64)> {
            let mut balances = BTreeMap::new();
            for batch in &self.history {
                for (key, value) in &batch.mutations {
                    match value {
                        Some(value) => {
                            balances.insert(key.clone(), *value);
                        }
                        None => {
                            balances.remove(key);
                        }
                    }
                }
            }
            balances
                .into_iter()
                .map(|(key, value)| {
                    (
                        VerifyingKey::decode(Copying(key.as_ref())).unwrap(),
                        value.get(),
                    )
                })
                .collect()
        }

        fn logs(&self) -> Heads<ShaDigest> {
            self.history.last().unwrap().logs
        }

        // Returns the account rows of the latest close, empty at genesis.
        fn rows(&self) -> Range<u64> {
            match self.history.as_slice() {
                [.., previous, last] => {
                    let start = previous.logs.activity.operations;
                    start..start + last.activity.rows().len() as u64
                }
                _ => 0..0,
            }
        }

        // Finds `payer`'s vector root in the latest close by a linear scan.
        fn predecessor(&self, payer: &VerifyingKey) -> VectorRoot<ShaDigest> {
            self.history
                .last()
                .expect("genesis is always accepted")
                .activity
                .rows()
                .iter()
                .find(|row| row.account() == payer)
                .map_or_else(
                    || commitment::empty_root::<Sha256>(VectorKind::OutEntry),
                    |row| row.send_root(),
                )
        }

        fn synthetic_next(&self, updates: Mutations, liability: u64) -> Self {
            let snapshot = self.clone();
            deterministic::Runner::default().start(|runtime| async move {
                let state = snapshot.reopen(runtime, "next").await;
                let prepared = state
                    .state()
                    .prepare(state.state().head(), updates)
                    .await
                    .unwrap();
                let logs = state
                    .logs()
                    .prepare(
                        state.logs().head(),
                        crate::bajillion::logs::ActivityInput::new(vec![], Vec::new()),
                        vec![],
                        Floors {
                            activity: snapshot.logs().activity.floor,
                            payouts: snapshot.logs().payouts.floor,
                        },
                    )
                    .await
                    .unwrap();
                snapshot.extended(
                    Accepted {
                        head: *prepared.head(),
                        mutations: prepared.mutations().to_vec(),
                        logs: *logs.head(),
                        activity: crate::bajillion::logs::ActivityInput::new(vec![], Vec::new()),
                        outputs: vec![],
                    },
                    liability,
                )
            })
        }

        fn refresh(
            &self,
            claim: &WithdrawalClaim<ShaDigest>,
            head: &crate::bajillion::logs::LogHead<ShaDigest>,
        ) -> WithdrawalClaim<ShaDigest> {
            let refreshed = self.payout_claim(head, claim.position());
            assert_eq!(refreshed.output(), claim.output());
            refreshed
        }
    }

    struct Harness {
        chain: TestChain,
        cache: TestCache,
        empty_cache: TestCache,
        deployment: ShaDigest,
        operator: SigningKey,
        operator_ack: BlsPrivate,
        operator_bls: OperatorKey,
        signer: bls12381::Scheme,
        committee: ShaDigest,
        accounts: Vec<SigningKey>,
    }

    // Default admission delay and challenge duration: a frontier promoted at `t` must be admitted
    // by `t + 1` and finalizes after `t + 2`.
    const DELAY: u64 = 1;
    const WINDOW: u64 = 1;

    fn config(minimum_withdrawal_notice: u64) -> SettlementConfig {
        SettlementConfig::new(
            EpochDeadlinePolicy::new(
                NonZeroU64::new(DELAY).unwrap(),
                NonZeroU64::new(WINDOW).unwrap(),
            ),
            NonZeroU64::new(1_000).unwrap(),
            NonZeroU64::new(minimum_withdrawal_notice).unwrap(),
            NonZeroU64::new(1_000).unwrap(),
            1_024,
            NonZeroUsize::new(1_024).unwrap(),
        )
    }

    fn harness_with_config(balances: &[u64], settlement_config: SettlementConfig) -> Harness {
        let mut accounts = balances
            .iter()
            .enumerate()
            .map(|(index, _)| SigningKey::from_seed(10 + index as u64))
            .collect::<Vec<_>>();
        accounts.sort_unstable_by_key(SigningKey::public_key);
        let initial_balances = accounts
            .iter()
            .zip(balances)
            .filter(|(_, balance)| **balance > 0)
            .map(|(account, balance)| (account.public_key(), *balance))
            .collect::<Vec<_>>();
        let mut original_allocations = initial_balances
            .iter()
            .map(|(account, balance)| {
                (
                    account_key(account).unwrap(),
                    NonZeroU64::new(*balance).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        original_allocations.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let cache = Snapshot::new(initial_balances);
        let genesis = Genesis::new(
            cache.root(),
            cache.head().operations(),
            &original_allocations,
        )
        .unwrap();
        let deployment = Sha256::hash(&[b"settlement-test-deployment"]);
        let operator = SigningKey::from_seed(100);
        let validator = BlsPrivate::new(Scalar::from(101_u64));
        let committee_keys = Committee::new(vec![compute_public::<MinSig>(&validator)]).unwrap();
        let committee = committee_keys.commitment::<Sha256>();
        let signer = bls12381::Scheme::signer(committee_keys.clone(), validator).unwrap();
        let operator_ack = BlsPrivate::new(Scalar::from(777_u64));
        let operator_bls = compute_public::<OperatorVariant>(&operator_ack);
        let chain = TestChain::new(
            deployment,
            operator.public_key(),
            committee_keys,
            &genesis,
            0,
            settlement_config,
        )
        .unwrap();
        Harness {
            chain,
            empty_cache: cache.clone(),
            cache,
            deployment,
            operator,
            operator_ack,
            operator_bls,
            signer,
            committee,
            accounts,
        }
    }

    fn harness(balances: &[u64]) -> Harness {
        harness_with_config(balances, config(2))
    }

    fn epoch_context(
        deployment: ShaDigest,
        operator: &SigningKey,
        committee: ShaDigest,
        epoch: u64,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
    ) -> EpochContext<VerifyingKey, ShaDigest> {
        EpochContext::new::<Sha256>(
            deployment,
            epoch,
            operator.public_key(),
            deposits,
            withdrawals,
            CloseLimits::protocol_maximum(),
            committee,
        )
        .unwrap()
    }

    // The context settlement binds when `epoch` becomes the frontier at `now` under the default
    // policy, extending `cache`.
    #[allow(clippy::too_many_arguments)]
    fn context(
        deployment: ShaDigest,
        operator: &SigningKey,
        committee: ShaDigest,
        epoch: u64,
        cache: &TestCache,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
        now: u64,
        floors: Floors,
    ) -> TestContext {
        bound(
            epoch_context(
                deployment,
                operator,
                committee,
                epoch,
                deposits,
                withdrawals,
            ),
            cache,
            now + DELAY,
            now + DELAY + WINDOW,
            floors,
        )
    }

    // Binds an epoch context to `cache` with explicit deadlines.
    fn bound(
        epoch: EpochContext<VerifyingKey, ShaDigest>,
        cache: &TestCache,
        admission_deadline: u64,
        challenge_deadline: u64,
        floors: Floors,
    ) -> TestContext {
        epoch.bind_settlement(
            cache.root(),
            cache.logs(),
            cache.rows(),
            cache.liability(),
            admission_deadline,
            challenge_deadline,
            floors,
        )
    }

    fn withdrawal(
        deployment: ShaDigest,
        root: StateRoot<ShaDigest>,
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

    fn round_trip(chain: &TestChain) -> TestChain {
        let encoded = chain.encode();
        assert_eq!(encoded.len(), chain.encode_size());
        let decoded = TestChain::decode_cfg(
            encoded.clone(),
            &Bounds {
                committee: 16,
                items: 1024,
                destination: 1024,
            },
        )
        .unwrap();
        assert_eq!(decoded.encode(), encoded);
        decoded
    }

    fn empty_roots(snapshot: &Snapshot, context: &TestContext) -> RootBundle<ShaDigest> {
        RootBundle {
            change: snapshot.logs().activity,
            row_count: 0,
            withdrawal_outputs: snapshot.logs().payouts,
            successor: snapshot.root(),
            successor_operations: snapshot.head().operations(),
            successor_sync_boundary: snapshot.head().sync_boundary(),
            proposal: crate::bajillion::transition::ProposalId::for_dealing::<Sha256, _>(
                context.epoch_context(),
                &[],
            ),
        }
    }

    fn certify(
        signer: &bls12381::Scheme,
        ctx: &TestContext,
        roots: &RootBundle<ShaDigest>,
        withdrawal_total: u64,
    ) -> (Header<ShaDigest>, bls12381::Certificate) {
        let header = Header::new::<Sha256, VerifyingKey>(ctx, roots, withdrawal_total);
        let certificate = signer.assemble([signer.sign(&header).unwrap()]).unwrap();
        (header, certificate)
    }

    // Registers and admits an empty epoch at `admit_at`. Its challenge deadline is
    // `admit_at + DELAY + WINDOW`.
    fn admit_empty(
        fixture: &mut Harness,
        cache: &Snapshot,
        epoch: u64,
        admit_at: u64,
    ) -> (Snapshot, BatchId<ShaDigest>, TestContext) {
        let next = cache.synthetic_next(vec![], cache.liability());
        let ctx = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            epoch,
            cache,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            admit_at,
            fixture.chain.registration_floors(),
        );
        let roots = empty_roots(&next, &ctx);
        let withdrawal_total = 0;
        let (header, certificate) = certify(&fixture.signer, &ctx, &roots, withdrawal_total);
        fixture
            .chain
            .register(admit_at, ctx.clone(), WithdrawalBatch::empty(), |_| true)
            .unwrap();
        let batch = fixture
            .chain
            .admit(admit_at, header, roots, withdrawal_total, certificate)
            .unwrap();
        (next, batch, ctx)
    }

    fn omitted_ack(fixture: &Harness, ctx: &TestContext) -> Challenge<VerifyingKey, ShaDigest> {
        let body = VectorSendBody::new(
            ctx.payment(),
            fixture.accounts[0].public_key(),
            1,
            1,
            commitment::empty_root::<Sha256>(VectorKind::OutEntry),
        );
        let ack = VectorAck::sign_by_authorities(
            body,
            commitment::empty_root::<Sha256>(VectorKind::OutEntry),
            &fixture.accounts[0],
            &fixture.operator,
        );
        Challenge::HigherAckDebit {
            ack: Box::new(AckWitness::from_ack(&ack)),
            payer: Box::new(AccountLookup::Absent(ChangeAbsence {
                predecessor: None,
                successor: None,
                opening: None,
            })),
        }
    }

    #[test]
    fn certified_withdrawal_total_binds_reserves_and_registered_deposits() {
        let mut fixture = harness(&[10]);
        let account = fixture.accounts[0].public_key();
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"deposit"]), account.clone(), 5)
            .unwrap();
        let deposits = fixture.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let ctx = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            0,
            fixture.chain.registration_floors(),
        );
        let next = fixture.cache.synthetic_next(
            vec![(account_key(&account).unwrap(), NonZeroU64::new(15))],
            15,
        );
        let roots = empty_roots(&next, &ctx);
        let withdrawal_total = 0;
        let (header, certificate) = certify(&fixture.signer, &ctx, &roots, withdrawal_total);
        fixture
            .chain
            .register(0, ctx, withdrawals, |_| true)
            .unwrap();
        let before = fixture.chain.encode();
        assert!(
            fixture
                .chain
                .admit(1, header, roots, 1, certificate.clone())
                .is_err()
        );
        assert_eq!(fixture.chain.encode(), before);
        fixture
            .chain
            .admit(1, header, roots, withdrawal_total, certificate)
            .unwrap();
        assert_eq!(fixture.chain.pending().unwrap().successor_liability, 15);
        fixture.chain = round_trip(&fixture.chain);
        assert!(matches!(
            fixture.chain.finalize(2),
            Err(SettlementError::ChallengeWindowOpen)
        ));
        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.custody_balance, 15);
        assert_eq!(fixture.chain.current_state_root(), next.root());
        assert_eq!(fixture.chain.unfinalized_deposit_total, 0);
    }

    #[test]
    fn withdrawal_intake_remains_valid_after_admitted_successors() {
        let mut fixture = harness(&[10]);
        let genesis = fixture.cache.clone();
        let account = fixture.accounts[0].public_key();
        let opening = genesis.opening(&account).unwrap();
        let request = withdrawal(
            fixture.deployment,
            genesis.root(),
            &fixture.accounts[0],
            b"exit",
            WithdrawalAction::Close,
            20,
        );
        let (first, _, _) = admit_empty(&mut fixture, &genesis, 0, 1);
        let (second, _, _) = admit_empty(&mut fixture, &first, 1, 2);
        let before = fixture.chain.encode();
        assert!(
            fixture
                .chain
                .queue_withdrawal(
                    2,
                    request.clone(),
                    &second.opening(&account).unwrap(),
                    |_| true
                )
                .is_err()
        );
        assert_eq!(fixture.chain.encode(), before);
        fixture
            .chain
            .queue_withdrawal(2, request, &opening, |_| true)
            .unwrap();
        assert!(matches!(
            fixture.chain.finalize(2),
            Err(SettlementError::ChallengeWindowOpen)
        ));
        fixture.chain.finalize(4).unwrap();
        fixture.chain.finalize(5).unwrap();
        fixture.chain.fault_expired(21).unwrap();
        let frozen = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(frozen.frozen_state_root, second.root());
        let release = fixture
            .chain
            .claim_hard_fault(&second.opening(&account).unwrap())
            .unwrap();
        assert_eq!(release.withdrawal.unwrap().amount(), 10);
        assert_eq!(release.residual, 0);
        assert!(fixture.chain.hard_fault_is_settled());
    }

    #[test]
    fn recovery_uses_frozen_root_and_account_identity_across_restart() {
        let mut fixture = harness(&[10, 5]);
        let refund = SigningKey::from_seed(500).public_key();
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"unfinalized"]), refund.clone(), 7)
            .unwrap();
        fixture.chain.fault_expired(1_001).unwrap();
        let frozen = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(frozen.state_liability, 15);
        let a = fixture.accounts[0].public_key();
        let b = fixture.accounts[1].public_key();
        let opening = fixture.cache.opening(&a).unwrap();
        let mut wrong = opening.clone();
        wrong.account = b.clone();
        let before = fixture.chain.encode();
        assert!(fixture.chain.claim_hard_fault(&wrong).is_err());
        assert_eq!(fixture.chain.encode(), before);
        let next = fixture
            .cache
            .synthetic_next(vec![(account_key(&a).unwrap(), NonZeroU64::new(9))], 14);
        assert!(
            fixture
                .chain
                .claim_hard_fault(&next.opening(&a).unwrap())
                .is_err()
        );
        assert_eq!(
            fixture.chain.claim_hard_fault(&opening).unwrap().residual,
            10
        );
        fixture.chain = round_trip(&fixture.chain);
        let independently_served = fixture.cache.opening(&a).unwrap();
        assert!(matches!(
            fixture.chain.claim_hard_fault(&independently_served),
            Err(SettlementError::ClaimAlreadyConsumed)
        ));
        assert_eq!(
            fixture
                .chain
                .claim_hard_fault(&fixture.cache.opening(&b).unwrap())
                .unwrap()
                .residual,
            5
        );
        assert!(!fixture.chain.hard_fault_is_settled());
        assert_eq!(
            fixture
                .chain
                .claim_pending_deposit(1_002, &refund)
                .unwrap()
                .amount,
            7
        );
        assert!(fixture.chain.hard_fault_is_settled());
        assert_eq!(fixture.chain.current_state_root(), frozen.frozen_state_root);
        assert_eq!(fixture.chain.custody_balance(), 0);
        round_trip(&fixture.chain);
    }

    #[test]
    fn omitted_epoch_receipt_cuts_suffix_then_freezes_surviving_prefix() {
        let mut fixture = harness(&[10]);
        let genesis = fixture.cache.clone();
        let (first, _, _) = admit_empty(&mut fixture, &genesis, 0, 1);
        let (second, batch, ctx) = admit_empty(&mut fixture, &first, 1, 2);
        let challenge = omitted_ack(&fixture, &ctx);
        let encoded = challenge.encode();
        assert_eq!(
            fixture
                .chain
                .challenge_encoded(3, batch, &encoded, encoded.len())
                .unwrap(),
            Verdict::Proven(ChallengeKind::HigherAckDebit)
        );
        assert!(matches!(
            fixture.chain.begin_hard_fault_settlement(),
            Err(SettlementError::PreFaultBatchPending)
        ));
        fixture.chain.finalize(11).unwrap();
        let frozen = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(frozen.frozen_state_root, first.root());
        let account = fixture.accounts[0].public_key();
        assert!(
            fixture
                .chain
                .claim_hard_fault(&second.opening(&account).unwrap())
                .is_err()
        );
        assert_eq!(
            fixture
                .chain
                .claim_hard_fault(&first.opening(&account).unwrap())
                .unwrap()
                .released_custody,
            10
        );
        assert!(fixture.chain.hard_fault_is_settled());
    }

    #[test]
    fn expired_registration_fence_survives_failed_admission_and_codec() {
        let mut fixture = harness(&[10]);
        let ctx = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            0,
            fixture.chain.registration_floors(),
        );
        let next = fixture
            .cache
            .synthetic_next(vec![], fixture.cache.liability());
        let roots = empty_roots(&next, &ctx);
        let withdrawal_total = 0;
        let (header, certificate) = certify(&fixture.signer, &ctx, &roots, withdrawal_total);
        fixture
            .chain
            .register(0, ctx, WithdrawalBatch::empty(), |_| true)
            .unwrap();
        assert!(matches!(
            fixture
                .chain
                .admit(2, header, roots, withdrawal_total, certificate),
            Err(SettlementError::OperatorHardFaulted)
        ));
        fixture.chain = round_trip(&fixture.chain);
        assert_eq!(fixture.chain.admission_fence_epoch(), Some(0));
        assert!(matches!(
            fixture.chain.record_deposit(
                2,
                Sha256::hash(&[b"late"]),
                fixture.accounts[0].public_key(),
                1
            ),
            Err(SettlementError::OperatorHardFaulted)
        ));
        fixture.chain.begin_hard_fault_settlement().unwrap();
        fixture
            .chain
            .claim_hard_fault(
                &fixture
                    .cache
                    .opening(&fixture.accounts[0].public_key())
                    .unwrap(),
            )
            .unwrap();
        assert!(fixture.chain.hard_fault_is_settled());
    }

    struct Built {
        prepared: TestClose,
        predecessor: Snapshot,
        successor: Snapshot,
    }
    impl Deref for Built {
        type Target = TestClose;
        fn deref(&self) -> &TestClose {
            &self.prepared
        }
    }
    impl Built {
        fn withdrawal_claim(&self, account: &VerifyingKey) -> WithdrawalClaim<ShaDigest> {
            let index = self
                .prepared
                .rows
                .iter()
                .filter(|row| matches!(row.output, SettlementOutput::Withdrawal(_)))
                .position(|row| &row.account == account)
                .expect("the account has a withdrawal output");
            let position = self
                .predecessor
                .logs()
                .payouts
                .operations
                .checked_add(u64::try_from(index).unwrap())
                .unwrap();
            let claim = self
                .successor
                .payout_claim(&self.prepared.roots.withdrawal_outputs, position);
            assert_eq!(claim.output(), &self.prepared.withdrawal_outputs()[index]);
            claim
        }
    }
    fn build(
        cache: &Snapshot,
        context: &TestContext,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
        terminals: Vec<Terminal<VerifyingKey, ShaDigest>>,
    ) -> (Built, Snapshot) {
        let predecessor = cache.clone();
        let snapshot = cache.clone();
        let context = context.clone();
        let deposits = deposits.clone();
        let withdrawals = withdrawals.clone();
        let (prepared, successor) = deterministic::Runner::default().start(|runtime| async move {
            let state = snapshot.reopen(runtime, "close").await;
            let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &context,
                &deposits,
                &withdrawals,
                terminals,
                &Sequential,
            )
            .await
            .unwrap();
            let successor_liability = transition::checked_successor_liability(
                context.predecessor_liability(),
                deposits.total(),
                prepared.close().withdrawal_total,
            )
            .unwrap();
            let accepted = Accepted::prepared(&prepared);
            let (_, close) = Box::pin(prepared.apply::<_, Sha256>(state)).await.unwrap();
            (close, snapshot.extended(accepted, successor_liability))
        });
        (
            Built {
                prepared,
                predecessor,
                successor: successor.clone(),
            },
            successor,
        )
    }
    fn empty_close(cache: &Snapshot, context: &TestContext) -> Built {
        build(
            cache,
            context,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            vec![],
        )
        .0
    }
    fn boundary_close(
        cache: &Snapshot,
        context: &TestContext,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
    ) -> (Built, Snapshot) {
        build(cache, context, deposits, withdrawals, vec![])
    }
    fn certificate(
        signer: &bls12381::Scheme,
        operator_bls: &OperatorKey,
        context: &TestContext,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
        close: &Built,
    ) -> bls12381::Certificate {
        let snapshot = close.predecessor.clone();
        let context = context.clone();
        let deposits = deposits.clone();
        let withdrawals = withdrawals.clone();
        let bytes = close.prepared.encoded().clone();
        let expected = close.header;
        deterministic::Runner::default().start(|runtime| async move {
            let state = snapshot.reopen(runtime, "validation").await;
            let dealing =
                crate::bajillion::posted::decode::<VerifyingKey, ShaDigest>(bytes, &context)
                    .unwrap();
            let validated =
                validate_close_with_strategy::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                    &state,
                    &context,
                    operator_bls,
                    &deposits,
                    &withdrawals,
                    dealing,
                    &mut test_rng(),
                    &Sequential,
                )
                .await
                .unwrap();
            assert_eq!(validated.close().header, expected);
        });
        signer
            .assemble([signer.sign(&close.header).unwrap()])
            .unwrap()
    }
    #[allow(clippy::too_many_arguments)]
    fn register_and_admit(
        chain: &mut TestChain,
        signer: &bls12381::Scheme,
        operator_bls: &OperatorKey,
        now: u64,
        context: TestContext,
        deposits: TestDeposits,
        withdrawals: TestWithdrawals,
        close: &Built,
    ) -> BatchId<ShaDigest> {
        let certificate = certificate(
            signer,
            operator_bls,
            &context,
            &deposits,
            &withdrawals,
            close,
        );
        chain.register(now, context, withdrawals, |_| true).unwrap();
        chain
            .admit(
                now,
                close.header,
                close.roots,
                close.withdrawal_total,
                certificate,
            )
            .unwrap()
    }
    // Registers and admits an empty epoch at `now` through real close construction. Its
    // challenge deadline is `now + DELAY + WINDOW`.
    fn admit_empty_epoch(
        fixture: &mut Harness,
        epoch: u64,
        now: u64,
    ) -> (TestContext, BatchId<ShaDigest>) {
        let snapshot = fixture.empty_cache.clone();
        assert_eq!(snapshot.root(), fixture.chain.head_state_root());
        let context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            epoch,
            &snapshot,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            now,
            fixture.chain.registration_floors(),
        );
        let close = empty_close(&snapshot, &context);
        let batch = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            now,
            context.clone(),
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            &close,
        );
        fixture.empty_cache = close.successor.clone();
        (context, batch)
    }
    fn claim_frozen_state(
        chain: &mut TestChain,
        cache: &Snapshot,
    ) -> Vec<HardFaultRelease<VerifyingKey>> {
        assert_eq!(cache.root(), chain.current_state_root());
        cache
            .balances()
            .into_iter()
            .map(|(account, _)| {
                chain
                    .claim_hard_fault(&cache.opening(&account).unwrap())
                    .unwrap()
            })
            .collect()
    }
    fn bls_private(seed: u64) -> BlsPrivate {
        BlsPrivate::new(Scalar::from(seed))
    }
    fn committee(seed: u64) -> Committee {
        Committee::new(vec![compute_public::<MinSig>(&bls_private(seed))]).unwrap()
    }
    fn payment_close(
        cache: &Snapshot,
        context: &TestContext,
        operator_ack: &BlsPrivate,
        payer: &SigningKey,
        recipient: &SigningKey,
        withdrawals: &TestWithdrawals,
        amount: u64,
    ) -> (Built, Snapshot) {
        let vector = OutVector::new(
            context.payment().epoch(),
            payer.public_key(),
            vec![OutEntry {
                recipient: recipient.public_key(),
                cumulative: amount,
                count: 1,
            }],
        )
        .unwrap();
        let body = VectorSendBody::new(
            context.payment(),
            payer.public_key(),
            1,
            amount,
            vector.root::<Sha256, ShaDigest>().unwrap(),
        );
        let authorization =
            SendAuthorization::sign(body, cache.predecessor(&payer.public_key()), payer);
        let operator_signature = sign_message::<OperatorVariant>(
            operator_ack,
            VECTOR_ACK_AGGREGATE_NAMESPACE,
            authorization.message().as_ref(),
        );
        build(
            cache,
            context,
            &DepositBatch::empty(),
            withdrawals,
            vec![Terminal {
                authorization,
                vector,
                operator_signature,
            }],
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

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
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

    fn fork_ack(
        context: &TestContext,
        operator: &SigningKey,
        payer: &SigningKey,
        seq: u64,
        amount: u64,
    ) -> VectorAck<VerifyingKey, ShaDigest> {
        let vector = OutVector::new(
            context.payment().epoch(),
            payer.public_key(),
            vec![OutEntry {
                recipient: SigningKey::from_seed(9_999).public_key(),
                cumulative: amount,
                count: 1,
            }],
        )
        .unwrap();
        let body = VectorSendBody::new(
            context.payment(),
            payer.public_key(),
            seq,
            amount,
            vector.root::<Sha256, ShaDigest>().unwrap(),
        );
        VectorAck::sign_by_authorities(
            body,
            commitment::empty_root::<Sha256>(VectorKind::OutEntry),
            payer,
            operator,
        )
    }

    fn ack_fork(
        left: &VectorAck<VerifyingKey, ShaDigest>,
        right: &VectorAck<VerifyingKey, ShaDigest>,
    ) -> TestChallenge {
        Challenge::AckFork {
            left: Box::new(AckWitness::from_ack(left)),
            right: Box::new(AckWitness::from_ack(right)),
        }
    }

    fn virtual_payment_close(
        cache: &TestCache,
        context: &TestContext,
        operator_ack: &BlsPrivate,
        payer: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
    ) -> (Built, TestCache) {
        payment_close(
            cache,
            context,
            operator_ack,
            payer,
            recipient,
            &WithdrawalBatch::empty(),
            amount,
        )
    }

    fn internal_payment_and_close(
        cache: &TestCache,
        context: &TestContext,
        operator_ack: &BlsPrivate,
        payer: &SigningKey,
        recipient: &SigningKey,
        withdrawals: &TestWithdrawals,
        amount: u64,
    ) -> (Built, TestCache) {
        payment_close(
            cache,
            context,
            operator_ack,
            payer,
            recipient,
            withdrawals,
            amount,
        )
    }

    #[derive(Clone, Copy)]
    enum ChallengeApi {
        Typed,
        Encoded,
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
        let (first_context, first_id) = admit_empty_epoch(&mut fixture, 0, 1);
        admit_empty_epoch(&mut fixture, 1, 1);
        let left = fork_ack(
            &first_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = if malformed {
            // A countersignature from a key other than the operator's makes the evidence
            // unauthenticated rather than a contradiction.
            let wrong = SigningKey::from_seed(999);
            fork_ack(&first_context, &wrong, &fixture.accounts[0], 1, 3)
        } else {
            fork_ack(
                &first_context,
                &fixture.operator,
                &fixture.accounts[0],
                1,
                3,
            )
        };
        let challenge = ack_fork(&left, &right);
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
    ) -> (
        Result<Verdict, SettlementError>,
        ChallengeState,
        BatchId<ShaDigest>,
    ) {
        let (mut fixture, challenge, batch) = challenge_pipeline(malformed);
        let encoded = challenge.encode();
        let result = match api {
            ChallengeApi::Typed => fixture.chain.challenge(3, batch, &challenge),
            ChallengeApi::Encoded => {
                fixture
                    .chain
                    .challenge_encoded(3, batch, encoded.as_ref(), encoded.len())
            }
        };
        let state = challenge_state(&fixture.chain);
        (result, state, batch)
    }

    #[test]
    fn decoded_anchor_is_rejected_before_registration_and_valid_retry_survives_restart() {
        let mut fixture = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let valid = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            0,
            fixture.chain.registration_floors(),
        );
        let mut encoded = valid.encode().to_vec();
        encoded[0] ^= 1;
        let inconsistent = TestContext::decode(encoded).unwrap();
        assert!(!inconsistent.epoch_context().verify_anchor::<Sha256>());
        let before = fixture.chain.encode();
        assert!(matches!(
            fixture
                .chain
                .register(0, inconsistent, withdrawals.clone(), |_| true),
            Err(SettlementError::Transition(TransitionError::EpochAnchor))
        ));
        assert_eq!(fixture.chain.encode(), before);

        let mut idle = round_trip(&fixture.chain);
        assert!(matches!(
            idle.fault_expired(3),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert!(idle.registered().is_none());
        assert!(idle.hard_fault().is_none());
        assert_eq!(idle.admission_fence_epoch(), None);

        fixture.chain = round_trip(&fixture.chain);
        fixture
            .chain
            .register(0, valid.clone(), withdrawals.clone(), |_| true)
            .unwrap();
        fixture.chain = round_trip(&fixture.chain);
        assert_eq!(fixture.chain.registered().unwrap().context, &valid);
        let close = empty_close(&fixture.cache, &valid);
        let certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &valid,
            &deposits,
            &withdrawals,
            &close,
        );
        let batch = fixture
            .chain
            .admit(
                0,
                close.header,
                close.roots,
                close.withdrawal_total,
                certificate,
            )
            .unwrap();
        assert_eq!(fixture.chain.finalize(5).unwrap().batch_id, batch);
        assert!(fixture.chain.hard_fault().is_none());
    }

    /// A frontier's deadlines come only from the deployment policy and the time it becomes the
    /// frontier. Deadlines the settlement clock cannot represent reject before any mutation.
    #[test]
    fn registration_derives_deadlines_from_the_deployment_policy() {
        fn policy() -> SettlementConfig {
            SettlementConfig::new(
                EpochDeadlinePolicy::new(NonZeroU64::new(3).unwrap(), NonZeroU64::new(2).unwrap()),
                NonZeroU64::new(1_000).unwrap(),
                NonZeroU64::new(2).unwrap(),
                NonZeroU64::new(1_000).unwrap(),
                1_024,
                NonZeroUsize::new(1_024).unwrap(),
            )
        }
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();

        // Registration with an empty frontier binds the head and assigns both deadlines from now.
        let mut fixture = harness_with_config(&[10], policy());
        let epoch = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &deposits,
            &withdrawals,
        );
        let floors = fixture.chain.registration_floors();
        fixture
            .chain
            .register_epoch(5, epoch.clone(), withdrawals.clone(), |_| true)
            .unwrap();
        assert_eq!(
            fixture.chain.frontier(),
            bound(epoch.clone(), &fixture.cache, 8, 10, floors)
        );

        // The last representable challenge deadline is u64::MAX - 1, which leaves one later
        // timestamp for finalization. One tick later the registration rejects without mutation.
        let mut edge = harness_with_config(&[10], policy());
        let before = edge.chain.encode();
        assert!(matches!(
            edge.chain
                .register_epoch(u64::MAX - 5, epoch.clone(), withdrawals.clone(), |_| true),
            Err(SettlementError::EpochDeadlineOverflow)
        ));
        assert_eq!(edge.chain.encode(), before);
        edge.chain
            .register_epoch(u64::MAX - 6, epoch.clone(), withdrawals, |_| true)
            .unwrap();
        assert_eq!(
            edge.chain.frontier(),
            bound(epoch, &edge.cache, u64::MAX - 3, u64::MAX - 1, floors)
        );
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
                &fixture.cache.opening(&withdrawing.public_key()).unwrap(),
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
        assert_eq!(fixture.chain.current_state_root(), fixture.cache.root());
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
                &fixture.cache.opening(&withdrawing.public_key()).unwrap(),
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
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &close,
        );
        let left = fork_ack(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = fork_ack(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(3, batch_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
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
        // The staged deposit lets the carrying epoch's tail cover the amount,
        // while the frozen finalized balance alone cannot.
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
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &close,
        );
        let left = fork_ack(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = fork_ack(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(3, batch_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
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
                &fixture.cache.opening(&closer.public_key()).unwrap(),
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
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &close,
        );
        assert_eq!(fixture.chain.pending_epoch_count(), 1);
        assert_eq!(fixture.chain.current_state_root(), fixture.cache.root());

        let left = fork_ack(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = fork_ack(
            &close_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(3, batch_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
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
                .queue_withdrawal(0, request, &fixture.cache.opening(account).unwrap(), |_| {
                    true
                })
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
            0,
            fixture.chain.registration_floors(),
        );
        let anchor = *registered.payment().anchor();
        let accepted_payment = fork_ack(&registered, &fixture.operator, &fixture.accounts[0], 1, 3);
        assert_eq!(accepted_payment.body().cumulative_debit(), 3);
        fixture
            .chain
            .register(0, registered, withdrawals, |_| true)
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

        let batch = WithdrawalBatch::new(requests.clone()).unwrap();
        let packed = PackedWithdrawals::new(&batch);
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

    #[test]
    fn challenge_entry_points_have_identical_state_transitions() {
        let apis = [ChallengeApi::Typed, ChallengeApi::Encoded];

        for malformed in [false, true] {
            let (reference_result, reference_state, _) = run_challenge_api(apis[0], malformed);
            for api in &apis[1..] {
                let (result, state, _) = run_challenge_api(*api, malformed);
                match (&reference_result, &result) {
                    (Ok(left), Ok(right)) => assert_eq!(left, right),
                    (Err(_), Err(_)) => {}
                    (left, right) => {
                        panic!("challenge APIs disagree: {left:?} vs {right:?}")
                    }
                }
                assert_eq!(state, reference_state);
            }
            if malformed {
                assert!(reference_result.is_err());
                assert!(
                    reference_state
                        .statuses
                        .iter()
                        .all(|status| matches!(status, BatchStatus::Pending))
                );
            } else {
                assert_eq!(
                    reference_result.as_ref().unwrap(),
                    &Verdict::Proven(ChallengeKind::AckFork)
                );
            }
        }
    }

    #[test]
    fn explicit_batch_id_routes_challenge_to_exact_pending_batch() {
        let mut fixture = harness(&[10, 10, 10]);
        admit_empty_epoch(&mut fixture, 0, 1);
        let (second_context, second_id) = admit_empty_epoch(&mut fixture, 1, 1);
        let left = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            3,
        );
        let challenge = ack_fork(&left, &right);

        assert_eq!(
            fixture.chain.challenge(3, second_id, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );
        assert_eq!(
            fixture
                .chain
                .pending_batches()
                .map(|batch| batch.status.clone())
                .collect::<Vec<_>>(),
            vec![
                BatchStatus::Pending,
                BatchStatus::Challenged(ChallengeKind::AckFork),
            ]
        );
        assert_eq!(fixture.chain.invalid_from(), Some(second_id));
    }

    #[test]
    fn higher_ack_entry_fault_releases_sender() {
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
            fixture.chain.registration_floors(),
        );
        let (close, _) = virtual_payment_close(
            &fixture.cache,
            &close_context,
            &fixture.operator_ack,
            &fixture.accounts[0],
            &recipient,
            2,
        );
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &close,
        );

        // The operator acknowledged a later batch crediting the recipient above the committed
        // terminal entry, and the recipient retained the entry receipt.
        let payer = &fixture.accounts[0];
        let retained_vector = OutVector::new(
            close_context.payment().epoch(),
            payer.public_key(),
            vec![OutEntry {
                recipient: recipient.public_key(),
                cumulative: 3,
                count: 2,
            }],
        )
        .unwrap();
        let retained_body = VectorSendBody::new(
            close_context.payment(),
            payer.public_key(),
            2,
            3,
            retained_vector.root::<Sha256, ShaDigest>().unwrap(),
        );
        let retained_ack = VectorAck::sign_by_authorities(
            retained_body,
            fixture.cache.predecessor(&payer.public_key()),
            payer,
            &fixture.operator,
        );
        let opening = match retained_vector
            .lookup::<Sha256, ShaDigest>(&recipient.public_key())
            .unwrap()
        {
            crate::bajillion::vector::OutTipLookup::Present { opening, .. } => opening,
            crate::bajillion::vector::OutTipLookup::Absent { .. } => {
                panic!("retained entry is present")
            }
        };
        let entry = EntryWitness {
            ack: AckWitness::from_ack(&retained_ack),
            recipient: recipient.public_key(),
            cumulative: 3,
            count: 2,
            opening,
        };

        let sender_lookup = close.successor.higher_entry_lookup(
            &close_context,
            &close.roots,
            &payer.public_key(),
            &recipient.public_key(),
        );
        let challenge = Challenge::HigherAckEntry {
            entry: Box::new(entry),
            sender: Box::new(sender_lookup),
        };

        assert_eq!(
            fixture.chain.challenge(3, batch_id, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::HigherAckEntry)
        );
        assert_eq!(
            fixture
                .chain
                .pending_batches()
                .map(|batch| batch.status.clone())
                .collect::<Vec<_>>(),
            vec![BatchStatus::Challenged(ChallengeKind::HigherAckEntry)]
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
    fn admitted_closes_extend_before_finality_across_checkpoint() {
        // A long challenge window keeps every admitted close pending through the loop.
        const WINDOW: u64 = 100;
        let mut settlement_config = config(2);
        settlement_config.epoch_deadlines.challenge_duration = NonZeroU64::new(WINDOW).unwrap();
        let mut fixture = harness_with_config(&[10], settlement_config);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let mut batches = Vec::new();
        for epoch in 0..8 {
            let close_context = bound(
                epoch_context(
                    fixture.deployment,
                    &fixture.operator,
                    fixture.committee,
                    epoch,
                    &deposits,
                    &withdrawals,
                ),
                &fixture.cache,
                epoch + 1 + DELAY,
                epoch + 1 + DELAY + WINDOW,
                fixture.chain.registration_floors(),
            );
            let close = empty_close(&fixture.cache, &close_context);
            batches.push(register_and_admit(
                &mut fixture.chain,
                &fixture.signer,
                &fixture.operator_bls,
                epoch + 1,
                close_context,
                deposits.clone(),
                withdrawals.clone(),
                &close,
            ));
            fixture.cache = close.successor.clone();
            assert_eq!(fixture.chain.pending_epoch_count(), epoch as usize + 1);
            assert_eq!(fixture.chain.expected_epoch(), 0);
            assert!(matches!(
                fixture.chain.finalize(epoch + 1),
                Err(SettlementError::ChallengeWindowOpen)
            ));
            if epoch == 4 {
                assert!(matches!(
                    TestChain::decode_cfg(
                        fixture.chain.encode(),
                        &Bounds {
                            committee: 16,
                            items: 4,
                            destination: 1024,
                        },
                    ),
                    Err(CodecError::InvalidLength(_))
                ));
                fixture.chain = round_trip(&fixture.chain);
            }
        }
        fixture.chain = round_trip(&fixture.chain);
        for (epoch, batch_id) in batches.into_iter().enumerate() {
            let deadline = epoch as u64 + 1 + DELAY + WINDOW;
            assert!(matches!(
                fixture.chain.finalize(deadline),
                Err(SettlementError::ChallengeWindowOpen)
            ));
            let finalized = fixture.chain.finalize(deadline + 1).unwrap();
            assert_eq!(finalized.epoch, epoch as u64);
            assert_eq!(finalized.batch_id, batch_id);
        }
        assert_eq!(fixture.chain.pending_epoch_count(), 0);
        assert_eq!(fixture.chain.expected_epoch(), 8);
        assert!(fixture.chain.hard_fault().is_none());
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
            fixture.chain.registration_floors(),
        );
        let first = empty_close(&fixture.cache, &first_context);
        let first_state = first.successor.clone();
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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
            &first_state,
            &deposits,
            &withdrawals,
            3,
            fixture.chain.registration_floors(),
        );
        let second = empty_close(&first_state, &second_context);
        let second_state = second.successor.clone();
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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

        // Pin the registered() accessor to the certification window: absent
        // before registration, the exact bound context and boundary batches
        // while the slot is live, and absent again once the slot retires.
        assert!(fixture.chain.registered().is_none());
        let registered = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            2,
            &second_state,
            &deposits,
            &withdrawals,
            6,
            fixture.chain.registration_floors(),
        );
        let registered_anchor = *registered.payment().anchor();
        fixture
            .chain
            .register(6, registered.clone(), withdrawals.clone(), |_| true)
            .unwrap();
        let live = fixture
            .chain
            .registered()
            .expect("the slot is live through its admission deadline");
        assert_eq!(live.context, &registered);
        assert_eq!(live.deposits, &deposits);
        assert_eq!(live.withdrawals, &withdrawals);
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
        assert!(fixture.chain.registered().is_none());
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
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture
                .chain
                .register(1, skipped_genesis, withdrawals.clone(), |_| true),
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
            fixture.chain.registration_floors(),
        );
        let first = empty_close(&fixture.cache, &first_context);
        let first_state = first.successor.clone();
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            first_context,
            deposits.clone(),
            withdrawals.clone(),
            &first,
        );

        let skipped_successor = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            2,
            &first_state,
            &deposits,
            &withdrawals,
            2,
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture
                .chain
                .register(2, skipped_successor, withdrawals.clone(), |_| true),
            Err(SettlementError::EpochSequence)
        ));

        let successor = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &first_state,
            &deposits,
            &withdrawals,
            2,
            fixture.chain.registration_floors(),
        );
        fixture
            .chain
            .register(2, successor, withdrawals, |_| true)
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
            0,
            fixture.chain.registration_floors(),
        );
        let registered_anchor = *registered.payment().anchor();
        fixture
            .chain
            .register(0, registered, withdrawals, |_| true)
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

    /// A registration and an unpulled deposit that expire at one instant attribute the fault to
    /// the registration, and the deposit stays refundable.
    #[test]
    fn registered_anchor_wins_a_same_instant_deposit_expiry() {
        let mut settlement_config = config(2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(2).unwrap();
        let mut fixture = harness_with_config(&[10], settlement_config);
        let account = fixture.accounts[0].public_key();
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
            0,
            fixture.chain.registration_floors(),
        );
        let anchor = *registered.payment().anchor();
        fixture
            .chain
            .register(0, registered, withdrawals, |_| true)
            .unwrap();

        // The deposit enters the inbox unpulled, and its deadline is the first instant after the
        // frontier's admission deadline.
        assert_eq!(
            fixture
                .chain
                .record_deposit(
                    0,
                    Sha256::hash(&[b"registration-deposit-expiry-tie"]),
                    account.clone(),
                    7,
                )
                .unwrap(),
            0
        );
        assert_eq!(
            fixture.chain.runs,
            VecDeque::from([Run {
                end: 1,
                deadline: 2,
                account: account.clone(),
            }])
        );
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
            0,
            fixture.chain.registration_floors(),
        );
        let anchor = *registered.payment().anchor();
        let (close, _) = boundary_close(&fixture.cache, &registered, &deposits, &withdrawals);
        let withdrawal_total = close.withdrawal_total;
        let certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &registered,
            &deposits,
            &withdrawals,
            &close,
        );
        fixture
            .chain
            .register(0, registered, withdrawals, |_| true)
            .unwrap();

        assert!(matches!(
            fixture
                .chain
                .admit(2, close.header, close.roots, withdrawal_total, certificate,),
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

    /// After an idle gap, a registration that becomes the frontier takes its deadlines from its
    /// own registration time rather than from any earlier admission.
    #[test]
    fn idle_registration_binds_deadlines_from_its_own_time() {
        let mut fixture = harness(&[10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();

        // Epoch 0 is admitted at 1 and finalized after its challenge window.
        admit_empty_epoch(&mut fixture, 0, 1);
        fixture.chain.finalize(1 + DELAY + WINDOW + 1).unwrap();

        // Nothing awaits admission until epoch 1 registers at 40.
        let fresh = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &fixture.empty_cache,
            &deposits,
            &withdrawals,
            40,
            fixture.chain.registration_floors(),
        );
        assert_eq!(fresh.admission_deadline(), 40 + DELAY);
        fixture
            .chain
            .register(40, fresh.clone(), withdrawals, |_| true)
            .unwrap();
        assert_eq!(fixture.chain.frontier(), fresh);
        assert!(matches!(
            fixture.chain.fault_expired(40 + DELAY),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert!(fixture.chain.hard_fault().is_none());
    }

    #[test]
    fn largest_resolvable_deadlines_retain_inclusive_boundaries() {
        let mut admitted = harness(&[10]);
        admit_empty_epoch(&mut admitted, 0, u64::MAX - 3);
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
            u64::MAX - 3,
            unadmitted.chain.registration_floors(),
        );
        let registered_anchor = *close_context.payment().anchor();
        unadmitted
            .chain
            .register(u64::MAX - 3, close_context, withdrawals, |_| true)
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
            0,
            fixture.chain.registration_floors(),
        );
        let epoch = context.epoch_context().clone();

        fixture
            .chain
            .register_epoch(0, epoch, withdrawals, |_| true)
            .unwrap();

        let bound = fixture.chain.frontier();
        assert_eq!(bound.predecessor_root(), &fixture.cache.root());
        assert_eq!(bound.predecessor_liability(), fixture.cache.liability());
        assert_eq!(bound, context);
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
            0,
            fixture.chain.registration_floors(),
        );

        assert!(matches!(
            fixture
                .chain
                .register(0, close_context, withdrawals, |_| true),
            Err(SettlementError::OperatorMismatch)
        ));
    }

    #[test]
    fn finalized_openings_are_exact_and_timeout_observation_is_permanent() {
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
            1,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            close_context,
            deposits,
            withdrawals,
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
                .queue_withdrawal(1, request.clone(), &successor_opening, |_| true,),
            Err(SettlementError::State(_))
        ));
        let other = fixture
            .cache
            .opening(&fixture.accounts[1].public_key())
            .unwrap();
        assert!(matches!(
            fixture
                .chain
                .queue_withdrawal(1, request.clone(), &other, |_| true,),
            Err(SettlementError::WithdrawalOpening)
        ));
        assert!(matches!(
            fixture
                .chain
                .queue_withdrawal(1, request.clone(), &predecessor_opening, |_| false,),
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
            fixture
                .chain
                .queue_withdrawal(1, too_large, &predecessor_opening, |_| true,),
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
            .queue_withdrawal(1, request, &predecessor_opening, |_| true)
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
                &fixture.cache.opening(&account.public_key()).unwrap(),
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
    fn withdrawal_intake_survives_an_active_registration() {
        for (debit, credit) in [(0, 0), (8, 0), (10, 0), (10, 5)] {
            for action in [amount_action(4), WithdrawalAction::Close] {
                let mut fixture = harness(&[10, 10]);
                let account = fixture.accounts[0].clone();
                let peer = fixture.accounts[1].clone();
                let deposits = DepositBatch::empty();
                let empty = WithdrawalBatch::empty();
                let first = context(
                    fixture.deployment,
                    &fixture.operator,
                    fixture.committee,
                    0,
                    &fixture.cache,
                    &deposits,
                    &empty,
                    0,
                    fixture.chain.registration_floors(),
                );
                fixture
                    .chain
                    .register(0, first.clone(), empty.clone(), |_| true)
                    .unwrap();
                let (active, successor) = if debit == 0 {
                    boundary_close(&fixture.cache, &first, &deposits, &empty)
                } else {
                    payment_close(
                        &fixture.cache,
                        &first,
                        &fixture.operator_ack,
                        &account,
                        &peer,
                        &empty,
                        debit,
                    )
                };
                let request = withdrawal(
                    fixture.deployment,
                    fixture.cache.root(),
                    &account,
                    b"exit",
                    action,
                    20,
                );
                fixture
                    .chain
                    .queue_withdrawal(
                        1,
                        request.clone(),
                        &fixture.cache.opening(&account.public_key()).unwrap(),
                        |_| true,
                    )
                    .expect("withdrawal intake remains available during an active epoch");
                fixture.chain = round_trip(&fixture.chain);
                let registered = fixture.chain.registered().unwrap();
                assert_eq!(registered.context, &first);
                assert!(registered.withdrawals.is_empty());

                let certificate = certificate(
                    &fixture.signer,
                    &fixture.operator_bls,
                    &first,
                    &deposits,
                    &empty,
                    &active,
                );
                fixture
                    .chain
                    .admit(
                        1,
                        active.header,
                        active.roots,
                        active.withdrawal_total,
                        certificate,
                    )
                    .unwrap();
                fixture.chain = round_trip(&fixture.chain);
                let withdrawals = fixture.chain.pending_withdrawals();
                assert_eq!(withdrawals.requests(), core::slice::from_ref(&request));
                assert_eq!(
                    fixture
                        .chain
                        .unfinalized_withdrawal_deadline(&account.public_key()),
                    Some(20)
                );

                let second = context(
                    fixture.deployment,
                    &fixture.operator,
                    fixture.committee,
                    1,
                    &successor,
                    &deposits,
                    &withdrawals,
                    3,
                    fixture.chain.registration_floors(),
                );
                let (close, final_state) = if credit == 0 {
                    boundary_close(&successor, &second, &deposits, &withdrawals)
                } else {
                    payment_close(
                        &successor,
                        &second,
                        &fixture.operator_ack,
                        &peer,
                        &account,
                        &withdrawals,
                        credit,
                    )
                };
                let claim = close.withdrawal_claim(&account.public_key());
                register_and_admit(
                    &mut fixture.chain,
                    &fixture.signer,
                    &fixture.operator_bls,
                    3,
                    second,
                    deposits,
                    withdrawals,
                    &close,
                );
                fixture.chain = round_trip(&fixture.chain);
                assert!(fixture.chain.pending_withdrawals().is_empty());
                fixture.chain.finalize(6).unwrap();
                fixture.chain.finalize(6).unwrap();
                let tail = 10 - debit + credit;
                let release = match request.body().action() {
                    WithdrawalAction::Amount(amount) => {
                        if tail >= amount.get() {
                            amount.get()
                        } else {
                            0
                        }
                    }
                    WithdrawalAction::Close => tail,
                };
                let output = claim
                    .verify::<Sha256>(&close.roots.withdrawal_outputs)
                    .unwrap();
                assert_withdrawal_output(&output, &request, release);
                if release == 0 {
                    assert_eq!(fixture.chain.claimable_balance(), 0);
                } else {
                    assert_eq!(fixture.chain.claim_withdrawal(&claim).unwrap(), output);
                }
                assert_eq!(fixture.chain.current_state_root(), final_state.root());
                assert_eq!(fixture.chain.custody_balance(), 20 - release);
                assert!(fixture.chain.hard_fault().is_none());
            }
        }
    }

    #[test]
    fn registered_withdrawals_reserve_the_account_slot_without_consuming_later_intake() {
        let mut fixture = harness(&[10, 10]);
        let first = fixture.accounts[0].clone();
        let second = fixture.accounts[1].clone();
        let carried = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &first,
            b"carried",
            amount_action(4),
            20,
        );
        let queued = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &second,
            b"queued",
            amount_action(2),
            9,
        );
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![carried.clone()]).unwrap();
        let context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            0,
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&fixture.cache, &context, &deposits, &withdrawals);
        fixture
            .chain
            .register(0, context.clone(), withdrawals.clone(), |_| true)
            .unwrap();
        assert_eq!(
            fixture
                .chain
                .unfinalized_withdrawal_deadline(&first.public_key()),
            Some(20)
        );
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                1,
                carried,
                &fixture.cache.opening(&first.public_key()).unwrap(),
                |_| true,
            ),
            Err(SettlementError::DuplicateWithdrawal)
        ));
        fixture
            .chain
            .queue_withdrawal(
                1,
                queued.clone(),
                &fixture.cache.opening(&second.public_key()).unwrap(),
                |_| true,
            )
            .unwrap();
        let certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &context,
            &deposits,
            &withdrawals,
            &close,
        );
        fixture
            .chain
            .admit(
                1,
                close.header,
                close.roots,
                close.withdrawal_total,
                certificate,
            )
            .unwrap();
        fixture.chain = round_trip(&fixture.chain);
        assert_eq!(fixture.chain.pending_withdrawals().requests(), &[queued]);
        fixture.chain.finalize(5).unwrap();
        assert!(matches!(
            fixture
                .chain
                .record_deposit(9, Sha256::hash(&[b"late"]), first.public_key(), 1),
            Err(SettlementError::OperatorHardFaulted)
        ));
        assert!(matches!(
            fixture.chain.hard_fault(),
            Some(HardFaultReason::ExpiredWithdrawal { account, expired_at: 9 })
                if account == &second.public_key()
        ));
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
            5,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claim = close.withdrawal_claim(&account.public_key());
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            5,
            close_context,
            deposits.clone(),
            withdrawals,
            &close,
        );
        assert_eq!(
            fixture
                .chain
                .unfinalized_withdrawal_deadline(&account.public_key()),
            Some(9)
        );
        assert_eq!(fixture.chain.finalize(8).unwrap().withdrawal_total, 4);
        let output = fixture.chain.claim_withdrawal(&claim).unwrap();
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
                &successor.opening(&account.public_key()).unwrap(),
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
            8,
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture.chain.register(8, replay_context, replay, |_| true),
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
            .queue_withdrawal(3, queued.clone(), &opening, |_| true)
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
            5,
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture
                .chain
                .register(5, missing_context, missing, |_| true),
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
            5,
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture
                .chain
                .register(5, horizon_context, horizon, |_| true),
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
            5,
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture.chain.register(5, late_context, late, |_| true),
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
            5,
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture.chain.register(
                5,
                carried_context,
                carried,
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
            5,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            5,
            close_context,
            deposits.clone(),
            withdrawals,
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
            6,
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture
                .chain
                .register(6, duplicate_context, duplicate, |_| true),
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
            6,
            fixture.chain.registration_floors(),
        );
        assert!(matches!(
            fixture.chain.register(6, stale_context, stale, |_| true),
            Err(SettlementError::Boundary(BoundaryError::WrongContext))
        ));

        // A fresh extra carries no balance proof: its release is resolved from the carrying
        // epoch's tail.
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
            6,
            fixture.chain.registration_floors(),
        );
        fixture
            .chain
            .register(6, valid_context, valid, |_| true)
            .unwrap();
    }

    /// A fresh extra's deadline must clear the earliest tick its close can finalize. The frontier
    /// knows its challenge deadline exactly. A queued epoch is checked against the deadlines it
    /// would receive if promoted immediately, and an operator that later promotes it too late for
    /// the extra is faulted by the extra's expiry.
    #[test]
    fn carried_deadline_must_clear_the_earliest_finalizing_tick() {
        let policy = SettlementConfig::new(
            EpochDeadlinePolicy::new(NonZeroU64::new(10).unwrap(), NonZeroU64::new(10).unwrap()),
            NonZeroU64::new(1_000).unwrap(),
            NonZeroU64::new(2).unwrap(),
            NonZeroU64::new(1_000).unwrap(),
            1_024,
            NonZeroUsize::new(1_024).unwrap(),
        );
        let mut fixture = harness_with_config(&[10, 10], policy);
        let first_signer = fixture.accounts[0].clone();
        let second_signer = fixture.accounts[1].clone();
        let deposits = DepositBatch::empty();
        let extra = |fixture: &Harness, signer: &SigningKey, deadline: u64| {
            WithdrawalBatch::new(vec![withdrawal(
                fixture.deployment,
                fixture.cache.root(),
                signer,
                b"extra",
                amount_action(4),
                deadline,
            )])
            .unwrap()
        };
        let register =
            |fixture: &mut Harness, now: u64, epoch: u64, withdrawals: TestWithdrawals| {
                let context = epoch_context(
                    fixture.deployment,
                    &fixture.operator,
                    fixture.committee,
                    epoch,
                    &deposits,
                    &withdrawals,
                );
                fixture
                    .chain
                    .register_epoch(now, context, withdrawals, |_| true)
            };

        // Epoch 0 becomes the frontier at 0 with challenge deadline 20, so it can first
        // finalize at 21. A deadline at 21 would expire on that tick.
        let early = extra(&fixture, &first_signer, 21);
        assert!(matches!(
            register(&mut fixture, 0, 0, early),
            Err(SettlementError::WithdrawalDeadlineTooSoon)
        ));
        assert!(fixture.chain.registered().is_none());
        let first_withdrawals = extra(&fixture, &first_signer, 22);
        register(&mut fixture, 0, 0, first_withdrawals.clone()).unwrap();
        let first = fixture.chain.frontier();
        assert_eq!(first.challenge_deadline(), 20);

        // Epoch 1 queues behind it at 5. Promoted at once it would receive challenge deadline
        // 25, so its extra needs a deadline after 26.
        let early = extra(&fixture, &second_signer, 26);
        assert!(matches!(
            register(&mut fixture, 5, 1, early),
            Err(SettlementError::WithdrawalDeadlineTooSoon)
        ));
        assert_eq!(fixture.chain.next_registration_epoch().unwrap(), 1);
        let second_withdrawals = extra(&fixture, &second_signer, 27);
        register(&mut fixture, 5, 1, second_withdrawals.clone()).unwrap();
        assert_eq!(fixture.chain.next_registration_epoch().unwrap(), 2);
        assert_eq!(fixture.chain.frontier(), first);

        // The operator admits epoch 0 only at its admission deadline, so epoch 1 receives
        // challenge deadline 30. Nothing rejects that schedule.
        let (close, successor) =
            boundary_close(&fixture.cache, &first, &deposits, &first_withdrawals);
        let first_certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &first,
            &deposits,
            &first_withdrawals,
            &close,
        );
        fixture
            .chain
            .admit(
                10,
                close.header,
                close.roots,
                close.withdrawal_total,
                first_certificate,
            )
            .unwrap();
        let second = fixture.chain.frontier();
        assert_eq!(
            (second.admission_deadline(), second.challenge_deadline()),
            (20, 30)
        );
        let (close, _) = boundary_close(&successor, &second, &deposits, &second_withdrawals);
        let second_certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &second,
            &deposits,
            &second_withdrawals,
            &close,
        );
        fixture
            .chain
            .admit(
                20,
                close.header,
                close.roots,
                close.withdrawal_total,
                second_certificate,
            )
            .unwrap();

        // Epoch 0 finalizes before its extra expires. Epoch 1 cannot finalize before 31, so its
        // extra's expiry at 27 faults the deployment.
        fixture.chain.finalize(21).unwrap();
        assert!(matches!(
            fixture.chain.fault_expired(26),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert_eq!(
            fixture.chain.fault_expired(27).unwrap(),
            HardFaultReason::ExpiredWithdrawal {
                account: second_signer.public_key(),
                expired_at: 27,
            }
        );
    }

    #[test]
    fn registration_rejects_forged_identity_and_boundaries() {
        let mut fixture = harness(&[10, 10]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let valid = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            4,
            fixture.chain.registration_floors(),
        );
        let forged_root = VectorRoot {
            digest: Sha256::hash(&[b"forged-root"]),
        };
        let rebuild = |deployment: ShaDigest,
                       deposit_root: VectorRoot<ShaDigest>,
                       withdrawal_root: VectorRoot<ShaDigest>,
                       committee: ShaDigest| {
            EpochContext::from_parts(
                valid.payment().clone(),
                deployment,
                deposit_root,
                withdrawal_root,
                *valid.limits(),
                committee,
            )
        };
        let deployment = fixture.deployment;
        let deposit_root = *valid.deposit_root();
        let withdrawal_root = *valid.withdrawal_root();
        let assignment = *valid.committee();
        let foreign_committee = committee(206).commitment::<Sha256>();

        // Settlement binds the predecessor root, log heads, and liability itself, so the
        // registration carries no ancestry to forge. Only identity and boundaries remain.
        let forged = [
            (
                rebuild(
                    Sha256::hash(&[b"other-deployment"]),
                    deposit_root,
                    withdrawal_root,
                    assignment,
                ),
                SettlementError::Deployment,
            ),
            (
                rebuild(deployment, deposit_root, withdrawal_root, foreign_committee),
                SettlementError::CommitteeMismatch,
            ),
            (
                rebuild(deployment, forged_root, withdrawal_root, assignment),
                SettlementError::BoundaryRoot,
            ),
            (
                rebuild(deployment, deposit_root, forged_root, assignment),
                SettlementError::BoundaryRoot,
            ),
        ];
        for (context, expected) in forged {
            let before = fixture.chain.encode();
            let result = fixture
                .chain
                .register_epoch(4, context, WithdrawalBatch::empty(), |_| true);
            assert_eq!(
                core::mem::discriminant(&result.unwrap_err()),
                core::mem::discriminant(&expected)
            );
            assert_eq!(fixture.chain.encode(), before);
        }

        // The same parts assembled honestly register, so the gates and not the
        // fixture rejected the forgeries.
        fixture
            .chain
            .register(4, valid, WithdrawalBatch::empty(), |_| true)
            .unwrap();
        assert!(fixture.chain.registered.is_some());
    }

    /// A fresh extra carries no balance proof. An `Amount` its epoch's tail cannot cover still
    /// registers, and certification releases zero for it.
    #[test]
    fn uncovered_carried_amount_registers_and_releases_zero() {
        let mut fixture = harness(&[10, 10]);
        let signer = fixture.accounts[0].clone();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &signer,
            b"exit",
            amount_action(11),
            11,
        );
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![request.clone()]).unwrap();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            4,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claim = close.withdrawal_claim(&signer.public_key());
        assert_eq!(close.withdrawal_total, 0);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            4,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        fixture.chain.finalize(4 + DELAY + WINDOW + 1).unwrap();
        let output = claim
            .verify::<Sha256>(&close.roots.withdrawal_outputs)
            .unwrap();
        assert_withdrawal_output(&output, &request, 0);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert_eq!(fixture.chain.custody_balance(), 20);
    }

    #[test]
    fn offset_boundaries_settle_together_across_intake_orders_and_restart() {
        for queued in [false, true] {
            for order in 0..3 {
                let mut policy = config(2);
                policy.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
                let mut fixture = harness_with_config(&[10], policy);
                let signer = fixture.accounts[0].clone();
                let account = signer.public_key();
                let request = withdrawal(
                    fixture.deployment,
                    fixture.cache.root(),
                    &signer,
                    b"offset-exit",
                    amount_action(4),
                    20,
                );
                let first = match order {
                    0 => 4,
                    1 => 0,
                    _ => 3,
                };
                if first > 0 {
                    fixture
                        .chain
                        .record_deposit(0, Sha256::hash(&[b"offset-first"]), account.clone(), first)
                        .unwrap();
                }
                if queued {
                    fixture
                        .chain
                        .queue_withdrawal(
                            0,
                            request.clone(),
                            &fixture.cache.opening(&account).unwrap(),
                            |_| true,
                        )
                        .unwrap();
                }
                if first < 4 {
                    fixture
                        .chain
                        .record_deposit(
                            0,
                            Sha256::hash(&[b"offset-last"]),
                            account.clone(),
                            4 - first,
                        )
                        .unwrap();
                }
                fixture.chain = round_trip(&fixture.chain);
                let deposits =
                    DepositBatch::new(vec![DepositRecord::new(account.clone(), 4).unwrap()])
                        .unwrap();
                let withdrawals = WithdrawalBatch::new(vec![request.clone()]).unwrap();
                assert_eq!(fixture.chain.pending_deposits(), deposits);
                let ctx = context(
                    fixture.deployment,
                    &fixture.operator,
                    fixture.committee,
                    0,
                    &fixture.cache,
                    &deposits,
                    &withdrawals,
                    0,
                    fixture.chain.registration_floors(),
                );
                let (close, successor) =
                    boundary_close(&fixture.cache, &ctx, &deposits, &withdrawals);
                assert_eq!(successor.balances(), fixture.cache.balances());
                assert!(matches!(
                    successor.account_lookup(&ctx, &close.roots, &account),
                    AccountLookup::Present(_)
                ));
                let claim = close.withdrawal_claim(&account);
                register_and_admit(
                    &mut fixture.chain,
                    &fixture.signer,
                    &fixture.operator_bls,
                    0,
                    ctx,
                    deposits,
                    withdrawals,
                    &close,
                );
                fixture.chain = round_trip(&fixture.chain);
                assert!(fixture.chain.pending_deposits().is_empty());
                let finalized = fixture.chain.finalize(3).unwrap();
                assert_eq!(finalized.withdrawal_total, 4);
                assert_eq!(fixture.chain.custody_balance(), 10);
                assert_eq!(fixture.chain.claimable_balance(), 4);
                fixture.chain = round_trip(&fixture.chain);
                assert!(matches!(
                    fixture.chain.fault_expired(5),
                    Err(SettlementError::DeadlineNotReached)
                ));
                assert_withdrawal_output(
                    &fixture.chain.claim_withdrawal(&claim).unwrap(),
                    &request,
                    4,
                );
                assert!(fixture.chain.claim_withdrawal(&claim).is_err());
                assert_eq!(fixture.chain.custody_balance(), 10);
                assert_eq!(fixture.chain.claimable_balance(), 0);
            }
        }
    }

    #[test]
    fn intake_limits_notice_and_clean_release_replay_are_exact() {
        let invalid_notice = SettlementConfig::new(
            EpochDeadlinePolicy::new(
                NonZeroU64::new(DELAY).unwrap(),
                NonZeroU64::new(WINDOW).unwrap(),
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
                &invalid_fixture.cache.configured_state(),
                0,
                invalid_notice,
            ),
            Err(SettlementError::WithdrawalNoticeOrder)
        ));

        let settlement_config = SettlementConfig::new(
            EpochDeadlinePolicy::new(
                NonZeroU64::new(DELAY).unwrap(),
                NonZeroU64::new(WINDOW).unwrap(),
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
                .queue_withdrawal(5, oversized, &opening, |_| true),
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
                .queue_withdrawal(5, too_soon, &opening, |_| true),
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
                .queue_withdrawal(5, too_late, &opening, |_| true,),
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
            .queue_withdrawal(5, request.clone(), &opening, |_| true)
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
            5,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claim = close.withdrawal_claim(&account.public_key());
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            5,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        assert_eq!(fixture.chain.finalize(8).unwrap().withdrawal_total, 2);
        let output = fixture.chain.claim_withdrawal(&claim).unwrap();
        assert_withdrawal_output(&output, &request, 2);
        assert!(matches!(
            fixture.chain.claim_withdrawal(&claim),
            Err(ClaimError::Unavailable)
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
                &successor.opening(&account.public_key()).unwrap(),
                |_| true,
            ),
            Err(SettlementError::DuplicateWithdrawalAuthorization)
        ));
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                9,
                request,
                &successor.opening(&account.public_key()).unwrap(),
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
            9,
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&successor, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            9,
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
    fn expired_deposit_is_claimable_without_a_survivor() {
        let mut settlement_config = config(2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
        let mut fixture = harness_with_config(&[], settlement_config);
        let account = SigningKey::from_seed(999).public_key();
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"expiring-unpulled-deposit"]),
                account.clone(),
                7,
            )
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
        assert!(fixture.chain.pending_deposits.is_empty());
        assert!(fixture.chain.runs.is_empty());
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

    /// Pulling a deposit disarms its inclusion deadline. Admission and finalization then follow
    /// the epoch without reviving it.
    #[test]
    fn registered_deposit_discharges_its_inclusion_deadline() {
        let mut settlement_config = config(2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(3).unwrap();
        let mut fixture = harness_with_config(&[], settlement_config);
        let account = SigningKey::from_seed(999).public_key();

        // Record a deposit whose inclusion deadline is 3.
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"included-before-deadline"]), account, 7)
            .unwrap();

        // Register epoch 0 at 2, which pulls the deposit, then admit it.
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
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            2,
            close_context,
            deposits,
            withdrawals,
            &close,
        );

        // The pulled deposit carries no deadline, so its expiry instant does not fault.
        assert!(fixture.chain.runs.is_empty());
        assert!(matches!(
            fixture.chain.fault_expired(3),
            Err(SettlementError::DeadlineNotReached)
        ));

        // The epoch finalizes with the pulled deposit.
        fixture.chain.finalize(5).unwrap();
        assert_eq!(fixture.chain.current_state_root(), successor.root());
    }

    /// Each deposit keeps the deadline of its own recording time, even when an earlier deposit
    /// of the same account is pending. Without a pull the earlier one expires first. A pull of
    /// only the earlier one leaves the later one expiring at its own deadline.
    #[test]
    fn later_deposit_keeps_its_own_deadline() {
        let mut settlement_config = policy(10, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
        let record = |fixture: &mut Harness, account: &VerifyingKey| {
            for (now, label, amount) in [
                (0, b"earlier-account-deposit".as_slice(), 2),
                (2, b"later-account-deposit".as_slice(), 3),
            ] {
                fixture
                    .chain
                    .record_deposit(now, Sha256::hash(&[label]), account.clone(), amount)
                    .unwrap();
            }
        };

        // Two deposits of one account form two runs, and the earlier one expires at 5.
        let mut fixture = harness_with_config(&[], settlement_config);
        let account = SigningKey::from_seed(999).public_key();
        record(&mut fixture, &account);
        assert_eq!(fixture.chain.pending_deposits().total(), 5);
        assert_eq!(fixture.chain.runs.len(), 2);
        assert_eq!(
            fixture.chain.fault_expired(5).unwrap(),
            HardFaultReason::ExpiredDeposit {
                account: account.clone(),
                expired_at: 5,
            }
        );

        // Pulling only the earlier deposit at 3 leaves the later one armed until 7.
        let mut pulled = harness_with_config(&[], settlement_config);
        record(&mut pulled, &account);
        let deposits = pulled.chain.deposits_to(1);
        let context = epoch_context(
            pulled.deployment,
            &pulled.operator,
            pulled.committee,
            0,
            &deposits,
            &WithdrawalBatch::empty(),
        );
        pulled
            .chain
            .register_through(3, context, 1, WithdrawalBatch::empty(), |_| true)
            .unwrap();
        assert_eq!(pulled.chain.registered().unwrap().deposits.total(), 2);
        for now in [5, 6] {
            assert!(matches!(
                pulled.chain.fault_expired(now),
                Err(SettlementError::DeadlineNotReached)
            ));
        }
        assert_eq!(
            pulled.chain.fault_expired(7).unwrap(),
            HardFaultReason::ExpiredDeposit {
                account,
                expired_at: 7,
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
            0,
            fixture.chain.registration_floors(),
        );
        let (create, created) =
            boundary_close(&fixture.cache, &create_context, &deposits, &withdrawals);
        assert_eq!(created.head().live_accounts(), 1);
        assert_eq!(created.balances()[0].0, public_key);
        assert_eq!(created.balances()[0].1, 9);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
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
                &created.opening(&public_key).unwrap(),
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
            3,
            fixture.chain.registration_floors(),
        );
        let (destroy, destroyed) =
            boundary_close(&created, &destroy_context, &deposits, &withdrawals);
        assert!(destroyed.balances().is_empty());
        let claim = destroy.withdrawal_claim(&public_key);
        let output = claim
            .verify::<Sha256>(&destroy.roots.withdrawal_outputs)
            .unwrap();
        assert_withdrawal_output(&output, &request, 9);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            3,
            destroy_context,
            deposits,
            withdrawals,
            &destroy,
        );
        let finalized = fixture.chain.finalize(6).unwrap();
        assert_eq!(finalized.withdrawal_total, 9);
        assert_eq!(fixture.chain.claimable_balance(), 9);
        let output = fixture.chain.claim_withdrawal(&claim).unwrap();
        assert_withdrawal_output(&output, &request, 9);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(matches!(
            fixture.chain.claim_withdrawal(&claim),
            Err(ClaimError::Unavailable)
        ));
        assert_eq!(fixture.chain.current_state_root(), destroyed.root());
        assert_eq!(fixture.chain.custody_balance(), 0);
    }

    #[test]
    fn first_credit_to_absent_recipient_preserves_liability_custody_and_reserves() {
        let mut fixture = harness(&[100]);
        let payer = &fixture.accounts[0];
        let recipient = SigningKey::from_seed(1_001);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        assert!(fixture.cache.opening(&recipient.public_key()).is_err());
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            0,
            fixture.chain.registration_floors(),
        );
        let (close, successor) = payment_close(
            &fixture.cache,
            &close_context,
            &fixture.operator_ack,
            payer,
            &recipient,
            &withdrawals,
            20,
        );

        assert_eq!(close.withdrawal_total, 0);
        assert_eq!(successor.liability(), 100);
        assert_eq!(
            successor
                .opening(&payer.public_key())
                .unwrap()
                .verify::<Sha256>(&successor.root())
                .unwrap()
                .get(),
            80
        );
        assert_eq!(
            successor
                .opening(&recipient.public_key())
                .unwrap()
                .verify::<Sha256>(&successor.root())
                .unwrap()
                .get(),
            20
        );

        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        assert_eq!(fixture.chain.pending().unwrap().successor_liability, 100);
        assert_eq!(fixture.chain.custody_balance(), 100);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(matches!(
            fixture.chain.finalize(2),
            Err(SettlementError::ChallengeWindowOpen)
        ));
        assert_eq!(fixture.chain.current_state_root(), fixture.cache.root());
        assert_eq!(fixture.chain.custody_balance(), 100);
        assert_eq!(fixture.chain.claimable_balance(), 0);

        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 0);
        assert_eq!(finalized.custody_balance, 100);
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert_eq!(fixture.chain.custody_balance(), 100);
        assert_eq!(fixture.chain.claimable_balance(), 0);
    }

    #[test]
    fn virtual_credit_recreates_closed_account_without_replenishing_consumed_claim() {
        let mut fixture = harness(&[10, 20]);
        let closed = &fixture.accounts[0];
        let payer = &fixture.accounts[1];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            closed,
            b"closed-account-withdrawal",
            WithdrawalAction::Close,
            10,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request.clone(),
                &fixture.cache.opening(&closed.public_key()).unwrap(),
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
            0,
            fixture.chain.registration_floors(),
        );
        let (close, closed_state) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claim = close.withdrawal_claim(&closed.public_key());
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            close_context,
            deposits.clone(),
            withdrawals,
            &close,
        );
        fixture.chain.finalize(3).unwrap();
        assert_withdrawal_output(
            &fixture.chain.claim_withdrawal(&claim).unwrap(),
            &request,
            10,
        );
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 3)]));
        assert_eq!(fixture.chain.claimable_balance(), 0);

        let withdrawals = WithdrawalBatch::empty();
        let credit_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &closed_state,
            &deposits,
            &withdrawals,
            3,
            fixture.chain.registration_floors(),
        );
        let (credit, recreated) = payment_close(
            &closed_state,
            &credit_context,
            &fixture.operator_ack,
            payer,
            closed,
            &withdrawals,
            4,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            3,
            credit_context,
            deposits,
            withdrawals,
            &credit,
        );
        fixture.chain.finalize(6).unwrap();

        assert_eq!(
            recreated
                .opening(&closed.public_key())
                .unwrap()
                .verify::<Sha256>(&recreated.root())
                .unwrap()
                .get(),
            4
        );
        assert_eq!(fixture.chain.custody_balance(), 20);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 4)]));
        assert!(matches!(
            fixture.chain.claim_withdrawal(&claim),
            Err(ClaimError::Unavailable)
        ));
    }

    #[test]
    fn finalized_first_credit_survives_later_invalidated_virtual_credit() {
        let mut fixture = harness(&[100, 10]);
        let first_recipient = SigningKey::from_seed(1_002);
        let second_recipient = SigningKey::from_seed(1_003);
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
            0,
            fixture.chain.registration_floors(),
        );
        let (first, first_successor) = payment_close(
            &fixture.cache,
            &first_context,
            &fixture.operator_ack,
            &fixture.accounts[0],
            &first_recipient,
            &withdrawals,
            20,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            first_context,
            deposits.clone(),
            withdrawals.clone(),
            &first,
        );
        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.custody_balance, 110);
        assert_eq!(fixture.chain.claimable_balance(), 0);

        let second_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &first_successor,
            &deposits,
            &withdrawals,
            6,
            fixture.chain.registration_floors(),
        );
        let (second, second_successor) = payment_close(
            &first_successor,
            &second_context,
            &fixture.operator_ack,
            &fixture.accounts[0],
            &second_recipient,
            &withdrawals,
            7,
        );
        let second_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            6,
            second_context.clone(),
            deposits,
            withdrawals,
            &second,
        );
        let left = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            1,
            2,
        );
        let right = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(8, second_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.frozen_state_root, first_successor.root());
        assert_eq!(settlement.state_liability, 110);
        assert_eq!(settlement.custody_balance, 110);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(
            fixture
                .chain
                .claim_hard_fault(
                    &second_successor
                        .opening(&second_recipient.public_key())
                        .unwrap()
                )
                .is_err()
        );
        assert_eq!(
            fixture
                .chain
                .claim_hard_fault(
                    &first_successor
                        .opening(&first_recipient.public_key())
                        .unwrap()
                )
                .unwrap()
                .residual,
            20
        );
        assert_eq!(
            fixture
                .chain
                .claim_hard_fault(
                    &first_successor
                        .opening(&fixture.accounts[0].public_key())
                        .unwrap(),
                )
                .unwrap()
                .residual,
            80
        );
        assert_eq!(
            fixture
                .chain
                .claim_hard_fault(
                    &first_successor
                        .opening(&fixture.accounts[1].public_key())
                        .unwrap(),
                )
                .unwrap()
                .residual,
            10
        );
        assert!(fixture.chain.hard_fault_is_settled());
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(fixture.chain.claimable_balance(), 0);
    }

    #[test]
    fn finalized_claim_batches_do_not_block_later_finalization() {
        let mut fixture = harness_with_config(&[100, 100], config(1));
        let mut settled_size = None;

        for epoch in 0..6 {
            let deposits = DepositBatch::empty();
            let now = 1 + epoch * 3;
            let account = &fixture.accounts[epoch as usize % 2];
            let request = withdrawal(
                fixture.deployment,
                fixture.cache.root(),
                account,
                b"retained-claim",
                amount_action(1),
                now + 4,
            );
            fixture
                .chain
                .queue_withdrawal(
                    now,
                    request,
                    &fixture.cache.opening(&account.public_key()).unwrap(),
                    |_| true,
                )
                .unwrap();
            let withdrawals = fixture.chain.pending_withdrawals();
            let close_context = context(
                fixture.deployment,
                &fixture.operator,
                fixture.committee,
                epoch,
                &fixture.cache,
                &deposits,
                &withdrawals,
                now,
                fixture.chain.registration_floors(),
            );
            let (close, successor) =
                boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
            register_and_admit(
                &mut fixture.chain,
                &fixture.signer,
                &fixture.operator_bls,
                now,
                close_context,
                deposits,
                withdrawals,
                &close,
            );

            fixture.chain.finalize(now + 3).unwrap();
            fixture.cache = successor;
            let size = fixture.chain.active.encode_size();
            assert_eq!(*settled_size.get_or_insert(size), size);
        }

        assert_eq!(fixture.chain.pending_epoch_count(), 0);
        assert_eq!(fixture.chain.intervals.len(), 6);
        assert_eq!(fixture.chain.claimable_balance(), 6);
    }

    #[test]
    fn claimed_ranges_collapse_finalized_empty_close_commits() {
        let mut fixture = harness(&[]);

        admit_empty_epoch(&mut fixture, 0, 0);
        fixture.chain.finalize(3).unwrap();
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 2)]));

        admit_empty_epoch(&mut fixture, 1, 3);
        fixture.chain.finalize(6).unwrap();
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 3)]));
        fixture.chain = round_trip(&fixture.chain);
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 3)]));
    }

    #[test]
    fn claimed_withdrawals_reject_invalid_proofs_and_drain_reserve() {
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
                .queue_withdrawal(0, request.clone(), opening, |_| true)
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
            0,
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claims = queued
            .iter()
            .map(|(account, _, _, _)| close.withdrawal_claim(account))
            .collect::<Vec<_>>();
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 7);
        assert_eq!(fixture.chain.claimable_balance(), 7);

        for neighbors in [
            [
                Some(ClaimedRange {
                    start: claims[0].position(),
                    end: claims[0].position() + 1,
                }),
                None,
            ],
            [
                Some(ClaimedRange {
                    start: 0,
                    end: claims[0].position(),
                }),
                None,
            ],
        ] {
            let before = fixture.chain.active.encode();
            assert!(
                fixture
                    .chain
                    .active
                    .claim_withdrawal(&neighbors, &claims[0])
                    .is_err()
            );
            assert_eq!(fixture.chain.active.encode(), before);
        }

        let destination = claims[1].output().destination();
        let mut malformed = claims[1].encode().to_vec();
        let destination_offset = malformed
            .windows(destination.len())
            .position(|window| window == destination.as_ref())
            .expect("the encoded claim contains its destination");
        malformed[destination_offset] ^= 1;
        let malformed =
            WithdrawalClaim::<ShaDigest>::decode_cfg(malformed, &(..=usize::MAX).into()).unwrap();
        assert_eq!(malformed.position(), claims[1].position());
        let claimable_before = fixture.chain.claimable_balance();
        let intervals_before = fixture.chain.intervals.clone();
        assert!(matches!(
            fixture.chain.claim_withdrawal(&malformed),
            Err(ClaimError::Proof(TransitionError::Logs(_)))
        ));
        assert_eq!(fixture.chain.claimable_balance(), claimable_before);
        assert_eq!(fixture.chain.intervals, intervals_before);

        let output = fixture.chain.claim_withdrawal(&claims[1]).unwrap();
        assert_withdrawal_output(&output, &queued[1].1, queued[1].3);
        assert_eq!(fixture.chain.claimable_balance(), queued[0].3);
        assert!(matches!(
            fixture.chain.claim_withdrawal(&claims[1]),
            Err(ClaimError::Unavailable)
        ));
        let output = fixture.chain.claim_withdrawal(&claims[0]).unwrap();
        assert_withdrawal_output(&output, &queued[0].1, queued[0].3);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(matches!(
            fixture.chain.claim_withdrawal(&claims[0]),
            Err(ClaimError::Unavailable)
        ));
    }

    #[test]
    fn claimed_ranges_collapse_inter_close_commits() {
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
                &fixture.cache.opening(&account).unwrap(),
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
            0,
            fixture.chain.registration_floors(),
        );
        let (first_close, first_successor) = boundary_close(
            &fixture.cache,
            &first_context,
            &deposits,
            &first_withdrawals,
        );
        let first_claim = first_close.withdrawal_claim(&account);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            first_context,
            deposits.clone(),
            first_withdrawals,
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
                &fixture.cache.opening(&account).unwrap(),
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
            3,
            fixture.chain.registration_floors(),
        );
        let (second_close, second_successor) = boundary_close(
            &fixture.cache,
            &second_context,
            &deposits,
            &second_withdrawals,
        );
        let second_claim = second_close.withdrawal_claim(&account);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            3,
            second_context,
            deposits,
            second_withdrawals,
            &second_close,
        );
        fixture.chain.finalize(6).unwrap();
        fixture.cache = second_successor;
        assert_eq!(first_claim.position(), 1);
        assert_eq!(second_claim.position(), 3);
        assert_eq!(fixture.chain.claimable_balance(), 7);
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(2, 3), (4, 5)]));

        assert!(matches!(
            fixture.chain.claim_withdrawal(&first_claim),
            Err(ClaimError::Proof(_))
        ));
        assert_eq!(fixture.chain.claimable_balance(), 7);
        let before = fixture.chain.encode();
        assert!(fixture.chain.claim_withdrawal(&first_claim).is_err());
        assert_eq!(fixture.chain.encode(), before);
        let first_claim = fixture
            .cache
            .refresh(&first_claim, &fixture.chain.finalized_payouts());
        assert_withdrawal_output(
            &fixture.chain.claim_withdrawal(&first_claim).unwrap(),
            &first_request,
            3,
        );
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 3), (4, 5)]));
        assert!(matches!(
            fixture.chain.claim_withdrawal(&first_claim),
            Err(ClaimError::Unavailable)
        ));
        assert_withdrawal_output(
            &fixture.chain.claim_withdrawal(&second_claim).unwrap(),
            &second_request,
            4,
        );
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 5)]));
        assert!(matches!(
            fixture.chain.claim_withdrawal(&second_claim),
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
                    &fixture.cache.opening(&account.public_key()).unwrap(),
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
            0,
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
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
                &fixture.cache.opening(&account).unwrap(),
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
            0,
            fixture.chain.registration_floors(),
        );
        let (first, first_successor) =
            boundary_close(&fixture.cache, &first_context, &deposits, &withdrawals);
        let claim = first.withdrawal_claim(&account);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            first_context,
            deposits.clone(),
            withdrawals,
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
            6,
            fixture.chain.registration_floors(),
        );
        let second = empty_close(&fixture.cache, &second_context);
        let second_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            6,
            second_context.clone(),
            deposits,
            no_withdrawals,
            &second,
        );
        let left = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            1,
            2,
        );
        let right = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(8, second_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
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
        assert_withdrawal_output(
            &fixture.chain.claim_withdrawal(&claim).unwrap(),
            &request,
            4,
        );
        assert!(matches!(
            fixture.chain.claim_withdrawal(&claim),
            Err(ClaimError::Unavailable)
        ));
        assert_eq!(fixture.chain.claimable_balance(), 0);
    }

    #[test]
    fn challenged_virtual_credit_is_not_released() {
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
            1,
            fixture.chain.registration_floors(),
        );
        let first = empty_close(&fixture.cache, &first_context);
        let first_state = first.successor.clone();
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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
            &first_state,
            &empty,
            &withdrawals,
            2,
            fixture.chain.registration_floors(),
        );
        let recipient = SigningKey::from_seed(1_002);
        let (second, _) = virtual_payment_close(
            &first_state,
            &second_context,
            &fixture.operator_ack,
            &fixture.accounts[0],
            &recipient,
            20,
        );
        let second_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            2,
            second_context.clone(),
            empty,
            withdrawals,
            &second,
        );
        let left = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            1,
            2,
        );
        let right = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(4, second_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );

        let finalized = fixture.chain.finalize(4).unwrap();
        assert_eq!(finalized.custody_balance, 120);
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.custody_balance, 120);
        let releases = claim_frozen_state(&mut fixture.chain, &first_state);
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
            1,
            fixture.chain.registration_floors(),
        );
        let first = empty_close(&fixture.cache, &first_context);
        let first_state = first.successor.clone();
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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
            &first_state,
            &deposits,
            &withdrawals,
            2,
            fixture.chain.registration_floors(),
        );
        let second = empty_close(&first_state, &second_context);
        let second_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            2,
            second_context.clone(),
            deposits.clone(),
            withdrawals.clone(),
            &second,
        );

        let second_state = second.successor.clone();
        let third_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            2,
            &second_state,
            &deposits,
            &withdrawals,
            3,
            fixture.chain.registration_floors(),
        );
        let recipient = SigningKey::from_seed(1_003);
        let (third, _) = virtual_payment_close(
            &second_state,
            &third_context,
            &fixture.operator_ack,
            &fixture.accounts[0],
            &recipient,
            20,
        );
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            3,
            third_context,
            deposits,
            withdrawals,
            &third,
        );

        let left = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            1,
            2,
        );
        let right = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[1],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(4, second_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );
        assert_eq!(fixture.chain.finalize(4).unwrap().epoch, 0);

        let terminal = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(terminal.frozen_state_root, first_state.root());
        assert_eq!(fixture.chain.claimable_balance(), 0);
        let payer = fixture.accounts[0].public_key();
        let release = fixture
            .chain
            .claim_hard_fault(&first_state.opening(&payer).unwrap())
            .unwrap();
        assert_eq!(release.residual, 100);
        assert_eq!(release.released_custody, 100);
        assert!(release.withdrawal.is_none());
        for account in &fixture.accounts[1..] {
            fixture
                .chain
                .claim_hard_fault(&first_state.opening(&account.public_key()).unwrap())
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
            fixture.chain.registration_floors(),
        );
        let acknowledged = fork_ack(&close_context, &fixture.operator, payer, 1, 3);
        let close = empty_close(&fixture.cache, &close_context);
        let payer_lookup =
            close
                .successor
                .account_lookup(&close_context, &close.roots, &payer.public_key());
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            close_context,
            deposits,
            withdrawals,
            &close,
        );

        assert_eq!(
            fixture
                .chain
                .challenge(
                    3,
                    batch_id,
                    &Challenge::HigherAckDebit {
                        ack: Box::new(AckWitness::from_ack(&acknowledged)),
                        payer: Box::new(payer_lookup),
                    },
                )
                .unwrap(),
            Verdict::Proven(ChallengeKind::HigherAckDebit)
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
    fn ack_fork_fault_releases_the_frozen_sender() {
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
            fixture.chain.registration_floors(),
        );
        let close = empty_close(&fixture.cache, &close_context);
        let batch_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            close_context.clone(),
            deposits,
            withdrawals,
            &close,
        );
        let left = fork_ack(&close_context, &fixture.operator, payer, 1, 4);
        let right = fork_ack(&close_context, &fixture.operator, payer, 1, 5);

        assert_eq!(
            fixture
                .chain
                .challenge(3, batch_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );
        assert_eq!(
            fixture.chain.hard_fault(),
            Some(&HardFaultReason::ProvenChallenge {
                batch_id,
                kind: ChallengeKind::AckFork,
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
            1,
            fixture.chain.registration_floors(),
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
            &fixture.operator_bls,
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
                &fixture.cache.opening(&first_account.public_key()).unwrap(),
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
                &next_cache.opening(&second_account.public_key()).unwrap(),
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
            4,
            fixture.chain.registration_floors(),
        );
        let (close, _) =
            boundary_close(&next_cache, &second_context, &DepositBatch::empty(), &mixed);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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
            1,
            fixture.chain.registration_floors(),
        );
        let first = empty_close(&fixture.cache, &first_context);
        let first_state = first.successor.clone();
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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
            &first_state,
            &deposits,
            &withdrawals,
            1,
            fixture.chain.registration_floors(),
        );
        let second = empty_close(&first_state, &second_context);
        let second_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            1,
            second_context.clone(),
            deposits,
            withdrawals,
            &second,
        );
        let left = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            3,
        );
        let challenge = ack_fork(&left, &right);
        assert_eq!(
            fixture.chain.challenge(3, second_id, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );
        let statuses = fixture
            .chain
            .pending_batches()
            .map(|batch| batch.status.clone())
            .collect::<Vec<_>>();
        assert!(matches!(statuses[0], BatchStatus::Pending));
        assert!(matches!(
            statuses[1],
            BatchStatus::Challenged(ChallengeKind::AckFork)
        ));
        assert_eq!(fixture.chain.invalid_from(), Some(second_id));
        assert_eq!(fixture.chain.finalize(4).unwrap().epoch, 0);
        assert!(matches!(
            fixture.chain.finalize(5),
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
            1,
            fixture.chain.registration_floors(),
        );
        let first = empty_close(&fixture.cache, &first_context);
        let first_state = first.successor.clone();
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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
            &first_state,
            &middle_deposits,
            &empty_withdrawals,
            2,
            fixture.chain.registration_floors(),
        );
        let (middle, middle_cache) = boundary_close(
            &first_state,
            &middle_context,
            &middle_deposits,
            &empty_withdrawals,
        );
        let middle_id = register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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
            3,
            fixture.chain.registration_floors(),
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
            &fixture.operator_bls,
            3,
            descendant_context,
            descendant_deposits,
            empty_withdrawals,
            &descendant,
        );

        let left = fork_ack(
            &middle_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = fork_ack(
            &middle_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(4, middle_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );
        assert_eq!(
            fixture
                .chain
                .pending_batches()
                .map(|batch| batch.status.clone())
                .collect::<Vec<_>>(),
            vec![
                BatchStatus::Pending,
                BatchStatus::Challenged(ChallengeKind::AckFork),
                BatchStatus::Invalidated(middle_id),
            ]
        );
        assert_eq!(fixture.chain.custody_balance(), 68);
        assert!(matches!(
            fixture.chain.begin_hard_fault_settlement(),
            Err(SettlementError::PreFaultBatchPending)
        ));

        assert_eq!(fixture.chain.finalize(4).unwrap().epoch, 0);
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        let residuals = claim_frozen_state(&mut fixture.chain, &first_state)
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
                kind: ChallengeKind::AckFork,
            } if batch_id == middle_id
        ));
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert_eq!(fixture.chain.pending_epoch_count(), 0);
        assert!(fixture.chain.hard_fault_is_settled());
    }

    #[test]
    fn timeout_fault_keeps_its_fence_while_a_later_challenge_shortens_the_prefix() {
        let mut fixture = harness(&[10, 10, 10]);
        admit_empty_epoch(&mut fixture, 0, 1);
        admit_empty_epoch(&mut fixture, 1, 2);
        let (third_context, third_id) = admit_empty_epoch(&mut fixture, 2, 3);

        let withdrawing = &fixture.accounts[0];
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            withdrawing,
            b"timeout-cut",
            amount_action(4),
            5,
        );
        let mut snapshot = fixture.cache.clone();
        let openings = (0..4)
            .map(|_| {
                let opening = snapshot.opening(&withdrawing.public_key()).unwrap();
                snapshot = snapshot.synthetic_next(vec![], snapshot.liability());
                opening
            })
            .collect::<Vec<_>>();
        fixture
            .chain
            .queue_withdrawal(3, request, &openings[0], |_| true)
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

        let left = fork_ack(
            &third_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = fork_ack(
            &third_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(5, third_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
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
                BatchStatus::Challenged(ChallengeKind::AckFork),
            ]
        );
        assert!(matches!(
            fixture.chain.begin_hard_fault_settlement(),
            Err(SettlementError::PreFaultBatchPending)
        ));

        assert_eq!(fixture.chain.finalize(5).unwrap().epoch, 0);
        assert_eq!(fixture.chain.hard_fault(), Some(&first_reason));
        assert!(matches!(
            fixture.chain.begin_hard_fault_settlement(),
            Err(SettlementError::PreFaultBatchPending)
        ));
        assert_eq!(fixture.chain.finalize(5).unwrap().epoch, 1);
        assert_eq!(fixture.chain.hard_fault(), Some(&first_reason));

        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.reason, first_reason);
        assert_eq!(settlement.admission_fence_epoch, 3);
        assert_eq!(settlement.invalid_from, Some(third_id));
        assert_eq!(settlement.custody_balance, 30);
        assert_eq!(
            claim_frozen_state(
                &mut fixture.chain,
                &fixture
                    .cache
                    .synthetic_next(vec![], fixture.cache.liability())
                    .synthetic_next(vec![], fixture.cache.liability())
            )
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
            1,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
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
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert_eq!(fixture.chain.custody_balance(), 18);
        assert_eq!(fixture.chain.pending_deposits().total(), 3);
    }

    #[test]
    fn settlement_adds_no_account_limit_below_the_protocol_limit() {
        let mut fixture = harness_with_config(&[10], config(2));
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
            1,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        assert_eq!(successor.head().live_accounts(), 2);
        let certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &close_context,
            &deposits,
            &withdrawals,
            &close,
        );
        let withdrawal_total = close.withdrawal_total;
        fixture
            .chain
            .register(1, close_context, withdrawals, |_| true)
            .unwrap();

        fixture
            .chain
            .admit(1, close.header, close.roots, withdrawal_total, certificate)
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
                &fixture.cache.opening(&account.public_key()).unwrap(),
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
            0,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        assert_eq!(request.body().action(), &WithdrawalAction::Close);
        assert_eq!(close.withdrawal_total, 10);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            close_context,
            deposits,
            withdrawals,
            &close,
        );

        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 10);
        assert_eq!(finalized.custody_balance, 0);
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert!(successor.balances().is_empty());
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
                &fixture.cache.opening(&payer.public_key()).unwrap(),
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
            0,
            fixture.chain.registration_floors(),
        );
        let (close, successor) = internal_payment_and_close(
            &fixture.cache,
            &close_context,
            &fixture.operator_ack,
            payer,
            recipient,
            &withdrawals,
            10,
        );
        let claim = close.withdrawal_claim(&payer.public_key());
        let output = claim
            .verify::<Sha256>(&close.roots.withdrawal_outputs)
            .unwrap();
        assert_eq!(
            output.destination(),
            &Bytes::from_static(b"zero-tail-close")
        );
        assert_eq!(output.amount(), 0);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            close_context,
            deposits,
            withdrawals,
            &close,
        );

        let finalized = fixture.chain.finalize(3).unwrap();
        assert_eq!(finalized.withdrawal_total, 0);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert_eq!(fixture.chain.intervals.len(), 1);
        let custody = fixture.chain.custody_balance();
        let output = fixture.chain.claim_withdrawal(&claim).unwrap();
        assert_eq!(output.amount(), 0);
        assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 3)]));
        assert_eq!(fixture.chain.custody_balance(), custody);
        assert_eq!(fixture.chain.claimable_balance(), 0);
        assert!(fixture.chain.claim_withdrawal(&claim).is_err());
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
                &fixture.cache.opening(&public_key).unwrap(),
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
                    &fixture.cache.opening(&public_key).unwrap(),
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
                0,
                fixture.chain.registration_floors(),
            );
            let (close, successor) =
                boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
            assert_eq!(close.withdrawal_total, 17);
            register_and_admit(
                &mut fixture.chain,
                &fixture.signer,
                &fixture.operator_bls,
                0,
                close_context,
                deposits,
                withdrawals,
                &close,
            );

            let finalized = fixture.chain.finalize(3).unwrap();
            assert_eq!(finalized.withdrawal_total, 17);
            assert_eq!(finalized.custody_balance, 0);
            assert_eq!(fixture.chain.current_state_root(), successor.root());
            assert!(successor.balances().is_empty());
        }
    }

    #[test]
    fn withdrawal_wins_an_equal_deposit_expiry_tie() {
        let mut settlement_config = config(2);
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
                &fixture.cache.opening(&withdrawing.public_key()).unwrap(),
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
                &fixture.cache.opening(&source.public_key()).unwrap(),
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
                &fixture.cache.opening(&source.public_key()).unwrap(),
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

        let malformed = fixture.cache.synthetic_next(
            vec![(
                account_key(&source.public_key()).unwrap(),
                NonZeroU64::new(
                    fixture
                        .cache
                        .opening(&source.public_key())
                        .unwrap()
                        .balance
                        .get()
                        - 1,
                ),
            )],
            14,
        );
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
            Err(SettlementError::State(_))
        ));
        assert!(!fixture.chain.hard_fault_is_settled());
        assert_eq!(fixture.chain.custody_balance(), 17);
        assert!(fixture.chain.pending_deposits.is_empty());
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
        assert_eq!(fixture.chain.current_state_root(), fixture.cache.root());
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
            &fixture.cache.configured_state(),
            u64::MAX - 2,
            config(1),
        )
        .unwrap();
        let deposit_id = Sha256::hash(&[b"post-inclusion-exit-horizon"]);

        assert!(matches!(
            chain.record_deposit(0, deposit_id, fixture.accounts[0].public_key(), 1,),
            Err(SettlementError::EpochOverflow)
        ));
        assert_eq!(chain.custody_balance(), 1);
        assert!(chain.pending_deposits.is_empty());
        assert_eq!(chain.intake(), 0);
        assert!(chain.hard_fault().is_none());
    }

    #[test]
    fn offset_boundary_fits_the_normal_deposit_epoch_horizon() {
        for deposit_first in [false, true] {
            let fixture = harness(&[10]);
            let signer = &fixture.accounts[0];
            let account = signer.public_key();
            let mut chain = SettlementChain::<Sha256, VerifyingKey>::new(
                fixture.deployment,
                fixture.operator.public_key(),
                committee(206),
                &fixture.cache.configured_state(),
                u64::MAX - 3,
                config(1),
            )
            .unwrap();
            let id = Sha256::hash(&[b"offset-epoch-horizon"]);
            if deposit_first {
                chain.record_deposit(0, id, account.clone(), 1).unwrap();
            }
            let request = withdrawal(
                fixture.deployment,
                fixture.cache.root(),
                signer,
                b"offset-horizon",
                amount_action(1),
                2,
            );
            chain
                .queue_withdrawal(
                    0,
                    request,
                    &fixture.cache.opening(&account).unwrap(),
                    |_| true,
                )
                .unwrap();
            if !deposit_first {
                chain.record_deposit(0, id, account, 1).unwrap();
            }
            assert_eq!(chain.pending_deposits.values().sum::<u64>(), 1);
            assert_eq!(chain.pending_withdrawals(chain.intake()).len(), 1);
            assert!(chain.hard_fault().is_none());
        }
    }

    #[test]
    fn intake_stops_before_the_last_representable_close() {
        let deposit_fixture = harness(&[1]);
        let mut deposit_chain = SettlementChain::<Sha256, VerifyingKey>::new(
            deposit_fixture.deployment,
            deposit_fixture.operator.public_key(),
            committee(202),
            &deposit_fixture.cache.configured_state(),
            u64::MAX - 1,
            config(1),
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
        assert!(deposit_chain.pending_deposits.is_empty());
        assert_eq!(deposit_chain.intake(), 0);

        let withdrawal_fixture = harness(&[1]);
        let mut withdrawal_chain = SettlementChain::<Sha256, VerifyingKey>::new(
            withdrawal_fixture.deployment,
            withdrawal_fixture.operator.public_key(),
            committee(203),
            &withdrawal_fixture.cache.configured_state(),
            u64::MAX - 1,
            config(1),
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
                &withdrawal_fixture
                    .cache
                    .opening(&withdrawal_fixture.accounts[0].public_key())
                    .unwrap(),
                |_| true,
            ),
            Err(SettlementError::EpochOverflow)
        ));
        assert!(withdrawal_chain.pending_withdrawals.is_empty());
        assert_eq!(withdrawal_chain.intake(), 0);
    }

    #[test]
    fn active_withdrawal_intake_reserves_the_next_carrying_epoch() {
        for action in [amount_action(1), WithdrawalAction::Close] {
            let offset = match action {
                WithdrawalAction::Amount(_) => 2,
                WithdrawalAction::Close => 1,
            };
            for (remaining, accepted) in [(offset + 1, true), (offset, false)] {
                let mut fixture = harness(&[2]);
                fixture.chain.expected_epoch = u64::MAX - remaining;
                let empty = WithdrawalBatch::empty();
                let context = context(
                    fixture.deployment,
                    &fixture.operator,
                    fixture.committee,
                    fixture.chain.expected_epoch,
                    &fixture.cache,
                    &DepositBatch::empty(),
                    &empty,
                    0,
                    fixture.chain.registration_floors(),
                );
                fixture.chain.register(0, context, empty, |_| true).unwrap();
                let account = &fixture.accounts[0];
                let request = withdrawal(
                    fixture.deployment,
                    fixture.cache.root(),
                    account,
                    b"active-epoch-exit",
                    action,
                    20,
                );
                let result = fixture.chain.queue_withdrawal(
                    0,
                    request,
                    &fixture.cache.opening(&account.public_key()).unwrap(),
                    |_| true,
                );
                if accepted {
                    result.unwrap();
                    assert_eq!(fixture.chain.pending_withdrawals().requests().len(), 1);
                } else {
                    assert!(matches!(result, Err(SettlementError::EpochOverflow)));
                    assert!(fixture.chain.pending_withdrawals().is_empty());
                }
                assert!(fixture.chain.registered().unwrap().withdrawals.is_empty());
            }
        }
    }

    #[test]
    fn partial_withdrawal_can_finish_with_the_last_finalizable_close() {
        let mut fixture = harness(&[2]);
        fixture.chain = TestChain::new(
            fixture.deployment,
            fixture.operator.public_key(),
            committee(101),
            &fixture.cache.configured_state(),
            u64::MAX - 2,
            config(2),
        )
        .unwrap();
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
                &fixture.cache.opening(&public_key).unwrap(),
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
            0,
            fixture.chain.registration_floors(),
        );
        let (partial_close, partial_successor) =
            boundary_close(&fixture.cache, &partial_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            partial_context,
            deposits,
            withdrawals,
            &partial_close,
        );
        fixture.chain.finalize(3).unwrap();
        assert_eq!(partial_successor.balances()[0].1, 1);

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
                &partial_successor.opening(&public_key).unwrap(),
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
            3,
            fixture.chain.registration_floors(),
        );
        let (close, successor) =
            boundary_close(&partial_successor, &close_context, &deposits, &withdrawals);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            3,
            close_context,
            deposits,
            withdrawals,
            &close,
        );
        fixture.chain.finalize(6).unwrap();
        assert_eq!(successor.head().live_accounts(), 0);
        assert_eq!(fixture.chain.current_state_root(), successor.root());
        assert_eq!(fixture.chain.custody_balance(), 0);
        assert!(fixture.chain.hard_fault().is_none());
        assert_eq!(fixture.chain.expected_epoch, u64::MAX);
        assert!(fixture.chain.pending().is_none());
        let before = fixture.chain.encode();
        assert!(matches!(
            fixture.chain.finalize(7),
            Err(SettlementError::NoPendingBatch)
        ));
        assert_eq!(fixture.chain.encode(), before);
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
                &fixture.cache.opening(&public_key).unwrap(),
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
            0,
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claim = close.withdrawal_claim(&public_key);
        register_and_admit(
            &mut fixture.chain,
            &fixture.signer,
            &fixture.operator_bls,
            0,
            close_context,
            deposits,
            withdrawals,
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

        fixture.chain.claim_withdrawal(&claim).unwrap();
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

        let mut settlement_config = config(1);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(5).unwrap();
        let deadline_harness = harness(&[1]);
        let mut deposit_deadline_chain = SettlementChain::<Sha256, VerifyingKey>::new(
            deadline_harness.deployment,
            deadline_harness.operator.public_key(),
            committee(204),
            &deadline_harness.cache.configured_state(),
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
        assert!(deposit_deadline_chain.pending_deposits.is_empty());
        assert!(deposit_deadline_chain.runs.is_empty());
        assert_eq!(deposit_deadline_chain.intake(), 0);

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
                &deadline_harness
                    .cache
                    .opening(&deadline_harness.accounts[0].public_key())
                    .unwrap(),
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
                &epoch_harness.cache.configured_state(),
                u64::MAX,
                config(1),
            ),
            Err(SettlementError::EpochOverflow)
        ));
    }

    #[test]
    fn codec_round_trips_and_preserves_behavior() {
        let mut fixture = harness(&[10, 10]);
        let signer = fixture.accounts[0].clone();
        round_trip(&fixture.chain);

        // Stage a deposit and a queued withdrawal.
        fixture
            .chain
            .record_deposit(
                1,
                Sha256::hash(&[b"round-trip-deposit"]),
                fixture.accounts[1].public_key(),
                3,
            )
            .unwrap();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &signer,
            b"exit",
            amount_action(4),
            9,
        );
        let opening = fixture.cache.opening(&signer.public_key()).unwrap();
        fixture
            .chain
            .queue_withdrawal(1, request, &opening, |_| true)
            .unwrap();
        round_trip(&fixture.chain);

        // Build a certified close over the staged boundary and register it.
        let withdrawals = fixture.chain.pending_withdrawals();
        let deposits = fixture.chain.pending_deposits();
        let close_context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &fixture.cache,
            &deposits,
            &withdrawals,
            2,
            fixture.chain.registration_floors(),
        );
        let (close, _) = boundary_close(&fixture.cache, &close_context, &deposits, &withdrawals);
        let claim = close.withdrawal_claim(&signer.public_key());
        let certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &close_context,
            &deposits,
            &withdrawals,
            &close,
        );
        let withdrawal_total = close.withdrawal_total;
        fixture
            .chain
            .register(2, close_context, withdrawals, |_| true)
            .unwrap();
        let mut decoded = round_trip(&fixture.chain);

        // Admission, finalization, and the certified claim behave identically
        // on the original and the decoded chain, and their encodings stay in
        // lockstep.
        let batch_id = fixture
            .chain
            .admit(
                2,
                close.header,
                close.roots,
                withdrawal_total,
                certificate.clone(),
            )
            .unwrap();
        assert_eq!(
            decoded
                .admit(2, close.header, close.roots, withdrawal_total, certificate,)
                .unwrap(),
            batch_id
        );
        assert_eq!(decoded.encode(), fixture.chain.encode());
        round_trip(&fixture.chain);

        let finalized = fixture.chain.finalize(8).unwrap();
        assert_eq!(decoded.finalize(8).unwrap(), finalized);
        let released = fixture.chain.claim_withdrawal(&claim).unwrap();
        assert_eq!(decoded.claim_withdrawal(&claim).unwrap(), released);
        assert_eq!(decoded.encode(), fixture.chain.encode());
        assert_eq!(
            decoded.current_state_root(),
            fixture.chain.current_state_root()
        );
        assert_eq!(decoded.expected_epoch(), fixture.chain.expected_epoch());
        assert_eq!(decoded.custody_balance(), fixture.chain.custody_balance());
        assert_eq!(
            decoded.claimable_balance(),
            fixture.chain.claimable_balance()
        );
        round_trip(&fixture.chain);
    }

    #[test]
    fn codec_round_trips_a_hard_faulted_chain() {
        let mut fixture = harness(&[10]);
        let account = fixture.accounts[0].public_key();
        fixture
            .chain
            .record_deposit(
                1,
                Sha256::hash(&[b"round-trip-expiring"]),
                account.clone(),
                2,
            )
            .unwrap();

        // The deposit deadline (1 + 1_000) expires and permanently faults.
        assert!(matches!(
            fixture.chain.fault_expired(1_001),
            Ok(HardFaultReason::ExpiredDeposit { .. })
        ));
        let mut decoded = round_trip(&fixture.chain);

        // Terminal settlement and every terminal claim behave identically on
        // the original and the decoded chain.
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(decoded.begin_hard_fault_settlement().unwrap(), settlement);
        assert_eq!(decoded.encode(), fixture.chain.encode());
        decoded = round_trip(&fixture.chain);

        let releases = claim_frozen_state(&mut fixture.chain, &fixture.cache);
        assert_eq!(claim_frozen_state(&mut decoded, &fixture.cache), releases);
        let refund = fixture
            .chain
            .claim_pending_deposit(1_002, &account)
            .unwrap();
        assert_eq!(
            decoded.claim_pending_deposit(1_002, &account).unwrap(),
            refund
        );
        assert!(fixture.chain.hard_fault_is_settled());
        assert!(decoded.hard_fault_is_settled());
        assert_eq!(decoded.encode(), fixture.chain.encode());
        round_trip(&fixture.chain);
    }

    mod refinement {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/stateright/refinement.rs"
        ));
    }

    #[test]
    fn registration_floors_remain_immutable_when_predecessor_finalizes_before_vote() {
        let mut fixture = harness(&[10]);
        let genesis = fixture.cache.clone();
        let (predecessor, _, _) = admit_empty(&mut fixture, &genesis, 0, 0);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &predecessor,
            &deposits,
            &withdrawals,
            2,
            fixture.chain.registration_floors(),
        );
        let before = context.floors();
        let (close, _) = boundary_close(&predecessor, &context, &deposits, &withdrawals);
        fixture
            .chain
            .register(2, context.clone(), withdrawals.clone(), |_| true)
            .unwrap();
        let first = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &context,
            &deposits,
            &withdrawals,
            &close,
        );
        fixture.chain.finalize(3).unwrap();
        assert_ne!(fixture.chain.registration_floors(), before);
        let second = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &context,
            &deposits,
            &withdrawals,
            &close,
        );
        assert_eq!(first, second);
        assert_eq!(context.floors(), before);
        fixture
            .chain
            .admit(3, close.header, close.roots, close.withdrawal_total, second)
            .unwrap();
    }

    #[test]
    fn native_claimed_ledger_first_middle_last_and_replay_survive_restart() {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut fixture = harness(&[10, 20, 30]);
            for account in &fixture.accounts {
                let request = withdrawal(
                    fixture.deployment,
                    fixture.cache.root(),
                    account,
                    b"claimed-ledger",
                    amount_action(1),
                    10,
                );
                fixture
                    .chain
                    .queue_withdrawal(
                        0,
                        request,
                        &fixture.cache.opening(&account.public_key()).unwrap(),
                        |_| true,
                    )
                    .unwrap();
            }
            let deposits = DepositBatch::empty();
            let withdrawals = fixture.chain.pending_withdrawals();
            let context = context(
                fixture.deployment,
                &fixture.operator,
                fixture.committee,
                0,
                &fixture.cache,
                &deposits,
                &withdrawals,
                0,
                fixture.chain.registration_floors(),
            );
            let (close, _) = boundary_close(&fixture.cache, &context, &deposits, &withdrawals);
            let claims = fixture
                .accounts
                .iter()
                .map(|account| close.withdrawal_claim(&account.public_key()))
                .collect::<Vec<_>>();
            register_and_admit(
                &mut fixture.chain,
                &fixture.signer,
                &fixture.operator_bls,
                0,
                context,
                deposits,
                withdrawals,
                &close,
            );
            fixture.chain.finalize(3).unwrap();
            assert_eq!(fixture.chain.finalized_payouts().operations, 5);
            let mut claimed = BTreeSet::from([4]);
            let mut unpaid = BTreeSet::from([1, 2, 3]);
            assert_eq!(fixture.chain.intervals, BTreeMap::from([(4, 5)]));
            assert!(fixture.chain.intervals.len() <= unpaid.len() + 1);
            for index in order {
                let position = claims[index].position();
                assert!(claimed.insert(position));
                assert!(unpaid.remove(&position));
                assert_eq!(
                    fixture
                        .chain
                        .claim_withdrawal(&claims[index])
                        .unwrap()
                        .amount(),
                    1
                );
                let actual = fixture
                    .chain
                    .intervals
                    .iter()
                    .flat_map(|(&start, &end)| start..end)
                    .collect::<BTreeSet<_>>();
                assert_eq!(actual, claimed);
                assert!(fixture.chain.intervals.len() <= unpaid.len() + 1);
                assert_eq!(fixture.chain.claimable_balance(), unpaid.len() as u64);
                fixture.chain = round_trip(&fixture.chain);
                let before = fixture.chain.encode();
                assert!(fixture.chain.claim_withdrawal(&claims[index]).is_err());
                assert_eq!(fixture.chain.encode(), before);
            }
            assert_eq!(fixture.chain.intervals, BTreeMap::from([(1, 5)]));
        }
    }

    fn policy(admission_delay: u64, challenge_duration: u64) -> SettlementConfig {
        let mut settlement_config = config(2);
        settlement_config.epoch_deadlines = EpochDeadlinePolicy::new(
            NonZeroU64::new(admission_delay).unwrap(),
            NonZeroU64::new(challenge_duration).unwrap(),
        );
        settlement_config
    }

    // Registers the next epoch with a pull of the whole inbox, the chain-queued requests it must
    // carry, and `extras`.
    fn register_next(
        fixture: &mut Harness,
        now: u64,
        extras: Vec<SignedWithdrawal<VerifyingKey, ShaDigest>>,
    ) -> Result<(), SettlementError> {
        let epoch = fixture.chain.next_registration_epoch()?;
        let deposits = fixture.chain.pending_deposits();
        let mut requests = fixture.chain.pending_withdrawals().requests().to_vec();
        requests.extend(extras);
        let withdrawals = WithdrawalBatch::new(requests).unwrap();
        let context = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            epoch,
            &deposits,
            &withdrawals,
        );
        fixture
            .chain
            .register_epoch(now, context, withdrawals, |_| true)
    }

    // Builds the frontier's boundary close on `cache` and admits it at `now`.
    fn admit_frontier(
        fixture: &mut Harness,
        now: u64,
        cache: &Snapshot,
    ) -> (Built, BatchId<ShaDigest>, TestContext) {
        let registered = fixture
            .chain
            .registered()
            .expect("an epoch awaits admission");
        let context = registered.context.clone();
        let deposits = registered.deposits.clone();
        let withdrawals = registered.withdrawals.clone();
        let (close, _) = boundary_close(cache, &context, &deposits, &withdrawals);
        let certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &context,
            &deposits,
            &withdrawals,
            &close,
        );
        let batch = fixture
            .chain
            .admit(
                now,
                close.header,
                close.roots,
                close.withdrawal_total,
                certificate,
            )
            .unwrap();
        (close, batch, context)
    }

    /// Registrations wait behind the frontier in FIFO order. Promotion binds each epoch to the
    /// admitted head with deadlines from the admission instant, while the floors captured at
    /// registration stay fixed across a finalization in between.
    #[test]
    fn queued_epochs_promote_in_fifo_order_with_fixed_floors() {
        let mut fixture = harness_with_config(&[10], policy(10, 2));
        let genesis = fixture.cache.clone();

        // Epoch 0 is admitted at 0, so it can finalize after 12.
        register_next(&mut fixture, 0, vec![]).unwrap();
        let (first, _, _) = admit_frontier(&mut fixture, 0, &genesis);
        let floors = fixture.chain.registration_floors();

        // At 3, epoch 1 becomes the frontier and epoch 2 queues behind it.
        register_next(&mut fixture, 3, vec![]).unwrap();
        register_next(&mut fixture, 3, vec![]).unwrap();
        assert_eq!(fixture.chain.next_admission_epoch().unwrap(), 1);
        assert_eq!(fixture.chain.next_registration_epoch().unwrap(), 3);
        let second = fixture.chain.frontier();
        assert_eq!(second.payment().epoch(), 1);
        assert_eq!(
            (second.admission_deadline(), second.challenge_deadline()),
            (13, 15)
        );
        assert_eq!(fixture.chain.queued.len(), 1);
        assert_eq!(fixture.chain.queued[0].floors, floors);

        // Epoch 2's close cannot be admitted ahead of epoch 1.
        let queued = fixture.chain.queued[0].context.clone();
        let early = bound(queued.clone(), &first.successor, 13, 15, floors);
        let close = empty_close(&first.successor, &early);
        let early_certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &early,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            &close,
        );
        let before = fixture.chain.encode();
        assert!(
            fixture
                .chain
                .admit(
                    3,
                    close.header,
                    close.roots,
                    close.withdrawal_total,
                    early_certificate,
                )
                .is_err()
        );
        assert_eq!(fixture.chain.encode(), before);

        // Finalizing epoch 0 advances the registration floors, but not epoch 2's captured ones.
        fixture.chain.finalize(13).unwrap();
        assert_ne!(fixture.chain.registration_floors(), floors);

        // Admitting epoch 1 at 13 promotes epoch 2 onto its successor with deadlines from 13.
        let (second_close, _, _) = admit_frontier(&mut fixture, 13, &first.successor);
        assert_eq!(
            fixture.chain.frontier(),
            bound(queued, &second_close.successor, 23, 25, floors)
        );
        assert!(fixture.chain.queued.is_empty());
        admit_frontier(&mut fixture, 13, &second_close.successor);
        assert_eq!(fixture.chain.pending_epoch_count(), 2);
        assert_eq!(fixture.chain.next_registration_epoch().unwrap(), 3);
    }

    // Builds a close on `cache` in which `payer` pays `recipient`, validates it as every signer
    // does, and admits it as the frontier at `now`.
    fn admit_payment(
        fixture: &mut Harness,
        now: u64,
        cache: &Snapshot,
        payer: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
    ) -> (Built, TestContext) {
        let context = fixture.chain.frontier();
        let withdrawals = WithdrawalBatch::empty();
        let (close, _) = payment_close(
            cache,
            &context,
            &fixture.operator_ack,
            payer,
            recipient,
            &withdrawals,
            amount,
        );
        let certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &context,
            &DepositBatch::empty(),
            &withdrawals,
            &close,
        );
        fixture
            .chain
            .admit(
                now,
                close.header,
                close.roots,
                close.withdrawal_total,
                certificate,
            )
            .unwrap();
        (close, context)
    }

    /// A queued epoch promoted at its predecessor's admission binds the account rows of that
    /// pending close, where validators find the payer's signed predecessor.
    #[test]
    fn promotion_binds_pending_predecessor_rows() {
        let mut fixture = harness_with_config(&[10, 10], policy(10, 2));
        let genesis = fixture.cache.clone();
        let (payer, recipient) = (fixture.accounts[0].clone(), fixture.accounts[1].clone());

        // Epoch 0 becomes the frontier without predecessor rows, and epoch 1 queues behind it.
        register_next(&mut fixture, 0, vec![]).unwrap();
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert!(fixture.chain.frontier().predecessor_range().is_none());
        assert_eq!(fixture.chain.head_rows(), 0..0);

        // Admitting epoch 0's payment promotes epoch 1 onto that pending close's rows.
        let (first, context) = admit_payment(&mut fixture, 1, &genesis, &payer, &recipient, 3);
        let rows = first.roots.activity_range(&context).unwrap();
        assert!(rows.start < rows.end);
        assert_eq!(fixture.chain.head_rows(), rows.start..rows.end);
        assert_eq!(fixture.chain.frontier().predecessor_range(), Some(rows));

        // The payer's next payment verifies against its root in those rows.
        admit_payment(&mut fixture, 2, &first.successor, &payer, &recipient, 2);
    }

    // Admits epoch 0 with one payment at 0 and finalizes it at 13, returning the close and its
    // account rows.
    fn finalize_payment(
        fixture: &mut Harness,
        payer: &SigningKey,
        recipient: &SigningKey,
    ) -> (Built, ActivityRange<ShaDigest>) {
        let genesis = fixture.cache.clone();
        register_next(fixture, 0, vec![]).unwrap();
        let (close, context) = admit_payment(fixture, 0, &genesis, payer, recipient, 3);
        let rows = close.roots.activity_range(&context).unwrap();
        assert!(rows.start < rows.end);
        fixture.chain.finalize(13).unwrap();
        assert_eq!(fixture.chain.pending_epoch_count(), 0);
        (close, rows)
    }

    /// Once finalization drains the pipeline, the next registration becomes the frontier at
    /// once and binds the finalized close's rows.
    #[test]
    fn promotion_after_finalization_binds_finalized_rows() {
        let mut fixture = harness_with_config(&[10, 10], policy(10, 2));
        let (payer, recipient) = (fixture.accounts[0].clone(), fixture.accounts[1].clone());

        // Epoch 0's payment finalizes before epoch 1 registers.
        let (first, rows) = finalize_payment(&mut fixture, &payer, &recipient);
        assert_eq!(fixture.chain.head_rows(), rows.start..rows.end);

        // Epoch 1 registers into the empty queue and binds the finalized rows.
        register_next(&mut fixture, 14, vec![]).unwrap();
        assert_eq!(fixture.chain.frontier().predecessor_range(), Some(rows));

        // The payer's next payment verifies against its root in those rows.
        admit_payment(&mut fixture, 14, &first.successor, &payer, &recipient, 2);
    }

    /// The finalized rows survive a codec round trip, and the decoded chain binds them to its
    /// next frontier exactly as the original does.
    #[test]
    fn finalized_rows_survive_codec_round_trip() {
        let mut fixture = harness_with_config(&[10, 10], policy(10, 2));
        let (payer, recipient) = (fixture.accounts[0].clone(), fixture.accounts[1].clone());

        // The finalized rows decode unchanged.
        let (_, rows) = finalize_payment(&mut fixture, &payer, &recipient);
        let mut decoded = round_trip(&fixture.chain);
        assert_eq!(decoded.finalized_rows, rows.start..rows.end);

        // Both chains bind the same rows to epoch 1.
        let context = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
        );
        for chain in [&mut fixture.chain, &mut decoded] {
            chain
                .register_epoch(14, context.clone(), WithdrawalBatch::empty(), |_| true)
                .unwrap();
        }
        assert_eq!(decoded.frontier(), fixture.chain.frontier());
        assert_eq!(decoded.frontier().predecessor_range(), Some(rows));
    }

    /// Only the frontier carries deadlines, so a queued epoch cannot expire. Promotion assigns
    /// deadlines from the admission instant, and the frontier's expiry drops the queue while the
    /// queued epoch's deposit stays refundable. A promotion the settlement clock cannot represent
    /// rejects the admission before any mutation.
    #[test]
    fn only_the_frontier_carries_deadlines_and_expires() {
        let mut fixture = harness_with_config(&[10], policy(5, 2));
        let genesis = fixture.cache.clone();
        let account = fixture.accounts[0].public_key();

        // Epoch 0 becomes the frontier at 0 and epoch 1 queues behind it with a deposit.
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert_eq!(
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[b"queued-deposit"]), account.clone(), 3)
                .unwrap(),
            0
        );
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert!(matches!(
            fixture.chain.fault_expired(5),
            Err(SettlementError::DeadlineNotReached)
        ));

        // Admission at the inclusive deadline promotes epoch 1 with deadlines from 5, not 0.
        admit_frontier(&mut fixture, 5, &genesis);
        let frontier = fixture.chain.frontier();
        assert_eq!(
            (frontier.admission_deadline(), frontier.challenge_deadline()),
            (10, 12)
        );

        // The promoted frontier expires one tick after its own deadline and drops the queue.
        assert!(matches!(
            fixture.chain.fault_expired(10),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert_eq!(
            fixture.chain.fault_expired(11).unwrap(),
            HardFaultReason::ExpiredRegistration {
                anchor: *frontier.payment().anchor(),
                epoch: 1,
                expired_at: 10,
            }
        );
        assert!(fixture.chain.registered().is_none());
        assert_eq!(
            fixture.chain.claim_pending_deposit(11, &account).unwrap(),
            DepositRefund { account, amount: 3 }
        );

        // Admitting at the frontier's last instant would promote past the settlement clock.
        let mut edge = harness_with_config(&[10], policy(5, 2));
        register_next(&mut edge, u64::MAX - 8, vec![]).unwrap();
        register_next(&mut edge, u64::MAX - 8, vec![]).unwrap();
        let mut earlier = round_trip(&edge.chain);
        let registered = edge.chain.registered().unwrap();
        let context = registered.context.clone();
        let close = empty_close(&edge.cache, &context);
        let edge_certificate = certificate(
            &edge.signer,
            &edge.operator_bls,
            &context,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            &close,
        );
        let before = edge.chain.encode();
        assert!(matches!(
            edge.chain.admit(
                u64::MAX - 3,
                close.header,
                close.roots,
                close.withdrawal_total,
                edge_certificate.clone(),
            ),
            Err(SettlementError::EpochDeadlineOverflow)
        ));
        assert_eq!(edge.chain.encode(), before);

        // The same admission at the registration instant leaves room for the promotion.
        earlier
            .admit(
                u64::MAX - 8,
                close.header,
                close.roots,
                close.withdrawal_total,
                edge_certificate,
            )
            .unwrap();
        assert_eq!(earlier.frontier().challenge_deadline(), u64::MAX - 1);
    }

    /// A deposit before a registration is pulled by it and loses its inclusion deadline, and a
    /// deposit for the same account after the registration stays in the inbox with its own
    /// deadline. Admitting the pulling epoch removes only its deposits, custody equals liability
    /// plus every unfinalized deposit, and the epoch horizon counts registered epochs once.
    #[test]
    fn deposits_on_both_sides_of_a_pull_keep_their_epochs() {
        let mut fixture = harness(&[10]);
        let genesis = fixture.cache.clone();
        let account = fixture.accounts[0].public_key();

        // The first deposit is pulled by epoch 0's registration, which disarms its deadline.
        assert_eq!(
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[b"pulled"]), account.clone(), 5)
                .unwrap(),
            0
        );
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert_eq!(fixture.chain.registered().unwrap().deposits.total(), 5);
        assert_eq!(fixture.chain.pulled(), 1);
        assert!(fixture.chain.runs.is_empty());

        // A later deposit for the same account enters the inbox with its own deadline.
        assert_eq!(
            fixture
                .chain
                .record_deposit(1, Sha256::hash(&[b"later"]), account.clone(), 3)
                .unwrap(),
            1
        );
        assert_eq!(
            fixture.chain.pending_deposits(),
            DepositBatch::new(vec![DepositRecord::new(account.clone(), 3).unwrap()]).unwrap()
        );
        assert_eq!(
            fixture.chain.runs,
            VecDeque::from([Run {
                end: 2,
                deadline: 1_001,
                account: account.clone(),
            }])
        );
        assert_eq!(
            fixture.chain.pending_deposits,
            BTreeMap::from([(account.clone(), 8)])
        );
        assert_eq!(fixture.chain.custody_balance(), 18);
        assert_eq!(fixture.chain.unfinalized_deposit_total, 8);

        // A registration committing to the account's total instead of its unpulled deposit
        // fails the root check.
        let stale =
            DepositBatch::new(vec![DepositRecord::new(account.clone(), 8).unwrap()]).unwrap();
        let before = fixture.chain.encode();
        assert!(matches!(
            fixture.chain.register_epoch(
                1,
                epoch_context(
                    fixture.deployment,
                    &fixture.operator,
                    fixture.committee,
                    1,
                    &stale,
                    &WithdrawalBatch::empty(),
                ),
                WithdrawalBatch::empty(),
                |_| true,
            ),
            Err(SettlementError::BoundaryRoot)
        ));
        assert_eq!(fixture.chain.encode(), before);

        // Admitting epoch 0 removes only its pulled deposit.
        let (first, _, _) = admit_frontier(&mut fixture, 1, &genesis);
        assert_eq!(fixture.chain.runs.len(), 1);
        assert_eq!(
            fixture.chain.pending_deposits,
            BTreeMap::from([(account, 3)])
        );
        assert_eq!(
            fixture.chain.custody_balance(),
            fixture.chain.current_liability + fixture.chain.unfinalized_deposit_total
        );

        // Epoch 1 pulls the later deposit, and both epochs finalize.
        register_next(&mut fixture, 1, vec![]).unwrap();
        let (second, _, _) = admit_frontier(&mut fixture, 1, &first.successor);
        fixture.chain.finalize(3).unwrap();
        fixture.chain.finalize(4).unwrap();
        assert_eq!(fixture.chain.current_state_root(), second.successor.root());
        assert_eq!(fixture.chain.current_liability, 18);
        assert_eq!(fixture.chain.custody_balance(), 18);
        assert_eq!(fixture.chain.unfinalized_deposit_total, 0);
        assert!(fixture.chain.pending_deposits.is_empty());

        // The horizon is measured from the next registration, so each registered epoch counts
        // once. A deposit needs three representable epochs after its own.
        let mut horizon = harness(&[10]);
        let account = horizon.accounts[0].public_key();
        horizon.chain.expected_epoch = u64::MAX - 4;
        register_next(&mut horizon, 0, vec![]).unwrap();
        horizon
            .chain
            .record_deposit(0, Sha256::hash(&[b"horizon"]), account.clone(), 1)
            .unwrap();
        register_next(&mut horizon, 0, vec![]).unwrap();
        let before = horizon.chain.encode();
        assert!(matches!(
            horizon
                .chain
                .record_deposit(0, Sha256::hash(&[b"beyond"]), account, 1),
            Err(SettlementError::EpochOverflow)
        ));
        assert_eq!(horizon.chain.encode(), before);
    }

    /// Pulled deposits never expire, however many registrations wait ahead of them.
    ///
    /// Three epochs queue behind the frontier, each pulling one deposit whose inclusion deadline
    /// is 3. Every frontier is admitted at its own chained admission deadline, so the last
    /// deposit waits for four admissions, far past that deadline, without a fault. All four
    /// closes finalize and credit the deposits.
    #[test]
    fn pulled_deposits_behind_a_deep_queue_never_expire() {
        let mut settlement_config = policy(5, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(2).unwrap();
        let mut fixture = harness_with_config(&[10], settlement_config);
        let account = fixture.accounts[0].public_key();

        // Epoch 0 becomes the frontier at 0, and each queued epoch pulls one deposit at 1.
        register_next(&mut fixture, 0, vec![]).unwrap();
        for epoch in 1..=3_u64 {
            let id = Sha256::hash(&[b"queued", &epoch.to_be_bytes()]);
            assert_eq!(
                fixture
                    .chain
                    .record_deposit(1, id, account.clone(), 1)
                    .unwrap(),
                epoch - 1
            );
            assert_eq!(
                fixture.chain.runs,
                VecDeque::from([Run {
                    end: epoch,
                    deadline: 3,
                    account: account.clone(),
                }])
            );
            register_next(&mut fixture, 1, vec![]).unwrap();
            assert!(fixture.chain.runs.is_empty());
        }

        // Each frontier is admitted at its own admission deadline, five after the previous one.
        let mut cache = fixture.cache.clone();
        for now in [5, 10, 15, 20] {
            assert!(matches!(
                fixture.chain.fault_expired(now),
                Err(SettlementError::DeadlineNotReached)
            ));
            let (close, _, _) = admit_frontier(&mut fixture, now, &cache);
            cache = close.successor.clone();
        }
        assert!(fixture.chain.hard_fault().is_none());

        // The four closes finalize after the last challenge deadline and credit every deposit.
        for _ in 0..4 {
            fixture.chain.finalize(23).unwrap();
        }
        assert_eq!(fixture.chain.current_state_root(), cache.root());
        assert_eq!(fixture.chain.current_liability, 13);
        assert_eq!(fixture.chain.custody_balance(), 13);
        assert_eq!(fixture.chain.unfinalized_deposit_total, 0);
    }

    /// An unpulled deposit expires exactly at its inclusion deadline while earlier epochs are
    /// registered, and a pull before that instant disarms it. A partial pull disarms only the
    /// deposits it reaches, so a later deposit still expires at its own height.
    #[test]
    fn unpulled_deposit_expires_at_its_height() {
        let mut settlement_config = policy(10, 2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(3).unwrap();

        // Epoch 0 is registered, and a deposit at 1 enters the inbox with deadline 4.
        let mut fixture = harness_with_config(&[10], settlement_config);
        let account = fixture.accounts[0].public_key();
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert_eq!(
            fixture
                .chain
                .record_deposit(1, Sha256::hash(&[b"unpulled"]), account.clone(), 2)
                .unwrap(),
            0
        );

        // Without a pull, the deposit expires at 4 and not before.
        assert!(matches!(
            fixture.chain.fault_expired(3),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert_eq!(
            fixture.chain.fault_expired(4).unwrap(),
            HardFaultReason::ExpiredDeposit {
                account: account.clone(),
                expired_at: 4,
            }
        );
        assert_eq!(
            fixture.chain.claim_pending_deposit(4, &account).unwrap(),
            DepositRefund {
                account: account.clone(),
                amount: 2,
            }
        );

        // Registering epoch 1 at 3 pulls the deposit, so its deadline passes without a fault.
        let mut pulled = harness_with_config(&[10], settlement_config);
        register_next(&mut pulled, 0, vec![]).unwrap();
        pulled
            .chain
            .record_deposit(1, Sha256::hash(&[b"unpulled"]), account.clone(), 2)
            .unwrap();
        register_next(&mut pulled, 3, vec![]).unwrap();
        assert!(matches!(
            pulled.chain.fault_expired(4),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert_eq!(pulled.chain.queued[0].deposits.total(), 2);

        // A pull at 3 that reaches only the deposit recorded at 1 leaves the deposit recorded
        // at 2 armed, and it expires at 5.
        let mut partial = harness_with_config(&[10], settlement_config);
        register_next(&mut partial, 0, vec![]).unwrap();
        for (now, label) in [(1, b"first".as_slice()), (2, b"second".as_slice())] {
            partial
                .chain
                .record_deposit(now, Sha256::hash(&[label]), account.clone(), 1)
                .unwrap();
        }
        let deposits = partial.chain.deposits_to(1);
        let context = epoch_context(
            partial.deployment,
            &partial.operator,
            partial.committee,
            1,
            &deposits,
            &WithdrawalBatch::empty(),
        );
        partial
            .chain
            .register_through(3, context, 1, WithdrawalBatch::empty(), |_| true)
            .unwrap();
        assert_eq!(
            partial.chain.runs,
            VecDeque::from([Run {
                end: 2,
                deadline: 5,
                account: account.clone(),
            }])
        );
        assert!(matches!(
            partial.chain.fault_expired(4),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert_eq!(
            partial.chain.fault_expired(5).unwrap(),
            HardFaultReason::ExpiredDeposit {
                account,
                expired_at: 5,
            }
        );
    }

    /// A withdrawal queued while an epoch is registered enters the inbox, and the registration
    /// that pulls its index must carry it verbatim. A later registration carrying it again, or
    /// carrying another request for the same account, duplicates its unfinalized withdrawal.
    #[test]
    fn queued_withdrawal_is_carried_by_the_registration_that_pulls_it() {
        let mut fixture = harness(&[10, 10]);
        let signer = fixture.accounts[0].clone();
        let account = signer.public_key();
        let epoch = |fixture: &Harness, epoch: u64, withdrawals: &TestWithdrawals| {
            epoch_context(
                fixture.deployment,
                &fixture.operator,
                fixture.committee,
                epoch,
                &DepositBatch::empty(),
                withdrawals,
            )
        };

        // Queued while epoch 0 is registered, the request enters the inbox at index 0.
        register_next(&mut fixture, 0, vec![]).unwrap();
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &signer,
            b"pulled",
            amount_action(4),
            20,
        );
        assert_eq!(
            fixture
                .chain
                .queue_withdrawal(
                    0,
                    request.clone(),
                    &fixture.cache.opening(&account).unwrap(),
                    |_| true,
                )
                .unwrap(),
            0
        );
        assert!(fixture.chain.registered().unwrap().withdrawals.is_empty());
        assert!(fixture.chain.active.pending_withdrawals(0).is_empty());
        assert_eq!(
            fixture.chain.pending_withdrawals().requests(),
            core::slice::from_ref(&request)
        );

        // Epoch 1 must carry it when it pulls index 0, after which no later pull owes it.
        let omitted = WithdrawalBatch::empty();
        let context = epoch(&fixture, 1, &omitted);
        assert!(matches!(
            fixture.chain.register_epoch(0, context, omitted, |_| true),
            Err(SettlementError::WithdrawalWitness)
        ));
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert_eq!(
            fixture.chain.queued[0].withdrawals.requests(),
            core::slice::from_ref(&request)
        );
        assert!(fixture.chain.pending_withdrawals().is_empty());

        // Carrying it again in epoch 2 duplicates its unfinalized withdrawal.
        let before = fixture.chain.encode();
        let recarried = WithdrawalBatch::new(vec![request]).unwrap();
        let context = epoch(&fixture, 2, &recarried);
        assert!(matches!(
            fixture
                .chain
                .register_epoch(0, context, recarried, |_| true),
            Err(SettlementError::DuplicateWithdrawal)
        ));

        // Another request for the same account duplicates its unfinalized withdrawal.
        let other = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &signer,
            b"other",
            amount_action(3),
            20,
        );
        let duplicate = WithdrawalBatch::new(vec![other]).unwrap();
        let context = epoch(&fixture, 2, &duplicate);
        assert!(matches!(
            fixture
                .chain
                .register_epoch(0, context, duplicate, |_| true),
            Err(SettlementError::DuplicateWithdrawal)
        ));
        assert_eq!(fixture.chain.encode(), before);
    }

    /// Intake recorded after the operator fixes its pull cannot change the registered boundary,
    /// even a deposit and a chain-queued withdrawal that execute just ahead of the registration.
    /// The registration pulls exactly its prefix, and the later intake waits for the next pull,
    /// which must carry the later request.
    #[test]
    fn later_intake_leaves_a_pulled_prefix_registrable() {
        let mut fixture = harness(&[10, 10]);
        let genesis = fixture.cache.clone();
        let depositor = fixture.accounts[0].public_key();
        let signer = fixture.accounts[1].clone();

        // The operator fixes a pull of the first deposit.
        assert_eq!(
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[b"prefix"]), depositor.clone(), 5)
                .unwrap(),
            0
        );
        let deposits = fixture.chain.deposits_to(1);
        let context = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &deposits,
            &WithdrawalBatch::empty(),
        );

        // A deposit and a chain-queued withdrawal land before the registration executes.
        assert_eq!(
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[b"later"]), depositor.clone(), 3)
                .unwrap(),
            1
        );
        let request = withdrawal(
            fixture.deployment,
            genesis.root(),
            &signer,
            b"later",
            amount_action(4),
            20,
        );
        assert_eq!(
            fixture
                .chain
                .queue_withdrawal(
                    0,
                    request.clone(),
                    &genesis.opening(&signer.public_key()).unwrap(),
                    |_| true,
                )
                .unwrap(),
            2
        );

        // The registration pulls exactly its prefix and owes nothing for the later request.
        fixture
            .chain
            .register_through(0, context, 1, WithdrawalBatch::empty(), |_| true)
            .unwrap();
        assert_eq!(fixture.chain.registered().unwrap().deposits, &deposits);
        assert_eq!((fixture.chain.intake(), fixture.chain.pulled()), (3, 1));
        assert_eq!(
            fixture.chain.runs,
            VecDeque::from([Run {
                end: 2,
                deadline: 1_000,
                account: depositor.clone(),
            }])
        );
        assert_eq!(
            fixture.chain.pending_deposits,
            BTreeMap::from([(depositor, 8)])
        );

        // The next registration pulls the later intake and must carry the later request.
        let later = fixture.chain.deposits_to(3);
        assert_eq!(later.total(), 3);
        let omitted = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &later,
            &WithdrawalBatch::empty(),
        );
        let before = fixture.chain.encode();
        assert!(matches!(
            fixture
                .chain
                .register_through(0, omitted, 3, WithdrawalBatch::empty(), |_| true),
            Err(SettlementError::WithdrawalWitness)
        ));
        assert_eq!(fixture.chain.encode(), before);
        let carried = WithdrawalBatch::new(vec![request]).unwrap();
        let context = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &later,
            &carried,
        );
        fixture
            .chain
            .register_through(0, context, 3, carried, |_| true)
            .unwrap();
        assert_eq!(fixture.chain.pulled(), 3);
        assert!(fixture.chain.runs.is_empty());
    }

    /// A registration may carry a chain-queued request recorded at or past the end of its pull,
    /// which carries it early. The next pull owes nothing for it, carrying it again is rejected,
    /// and admission removes it. A restarted chain rebuilds the carriage and behaves identically.
    /// A fault before admission sends the request to terminal claims.
    #[test]
    fn queued_request_beyond_the_prefix_is_carried_once() {
        let mut fixture = harness_with_config(&[10, 10], policy(10, 2));
        let genesis = fixture.cache.clone();
        let depositor = fixture.accounts[0].public_key();
        let signer = fixture.accounts[1].clone();
        let account = signer.public_key();
        let request = withdrawal(
            fixture.deployment,
            genesis.root(),
            &signer,
            b"early",
            amount_action(4),
            20,
        );
        let early = WithdrawalBatch::new(vec![request.clone()]).unwrap();
        let queue = |fixture: &mut Harness| {
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[b"early-deposit"]), depositor.clone(), 2)
                .unwrap();
            fixture
                .chain
                .queue_withdrawal(
                    0,
                    request.clone(),
                    &genesis.opening(&account).unwrap(),
                    |_| true,
                )
                .unwrap()
        };
        let context =
            |fixture: &Harness, epoch: u64, deposits: &TestDeposits, carried: &TestWithdrawals| {
                epoch_context(
                    fixture.deployment,
                    &fixture.operator,
                    fixture.committee,
                    epoch,
                    deposits,
                    carried,
                )
            };

        // A deposit at index 0 precedes the request at index 1.
        assert_eq!(queue(&mut fixture), 1);

        // Epoch 0 pulls only index 0 and carries the request early.
        assert!(fixture.chain.active.pending_withdrawals(1).is_empty());
        let deposits = fixture.chain.deposits_to(1);
        let first = context(&fixture, 0, &deposits, &early);
        fixture
            .chain
            .register_through(0, first, 1, early.clone(), |_| true)
            .unwrap();
        assert!(fixture.chain.pending_withdrawals[&account].carried);
        assert_eq!(fixture.chain.pulled(), 1);

        // The next pull reaches the request's index but owes nothing for it, including after a
        // restart.
        assert!(fixture.chain.active.pending_withdrawals(2).is_empty());
        let mut restarted = round_trip(&fixture.chain);
        assert!(restarted.pending_withdrawals[&account].carried);
        assert!(restarted.active.pending_withdrawals(2).is_empty());

        // Carrying it again is rejected on both chains without mutation.
        let recarried = context(&fixture, 1, &DepositBatch::empty(), &early);
        for chain in [&mut fixture.chain, &mut restarted] {
            let before = chain.encode();
            assert!(matches!(
                chain.register_through(0, recarried.clone(), 2, early.clone(), |_| true),
                Err(SettlementError::DuplicateWithdrawal)
            ));
            assert_eq!(chain.encode(), before);
        }

        // Epoch 1 pulls index 1 without the request, and admitting epoch 0 removes it.
        let second = context(
            &fixture,
            1,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
        );
        let registered = fixture.chain.registered().unwrap();
        let frontier = registered.context.clone();
        let withdrawals = registered.withdrawals.clone();
        let (close, _) = boundary_close(&genesis, &frontier, &deposits, &withdrawals);
        let close_certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &frontier,
            &deposits,
            &withdrawals,
            &close,
        );
        for chain in [&mut fixture.chain, &mut restarted] {
            chain
                .register_through(0, second.clone(), 2, WithdrawalBatch::empty(), |_| true)
                .unwrap();
            chain
                .admit(
                    1,
                    close.header,
                    close.roots,
                    close.withdrawal_total,
                    close_certificate.clone(),
                )
                .unwrap();
            assert!(chain.pending_withdrawals.is_empty());
        }
        assert_eq!(restarted.encode(), fixture.chain.encode());
        assert_withdrawal_output(close.withdrawal_claim(&account).output(), &request, 4);

        // A fault before admission clears the carriage and sends the request to terminal
        // claims, and the deposit the dropped registration pulled is refunded.
        let mut faulted = harness_with_config(&[10, 10], policy(10, 2));
        assert_eq!(queue(&mut faulted), 1);
        let deposits = faulted.chain.deposits_to(1);
        let first = context(&faulted, 0, &deposits, &early);
        faulted
            .chain
            .register_through(0, first, 1, early, |_| true)
            .unwrap();
        assert!(matches!(
            faulted.chain.fault_expired(11),
            Ok(HardFaultReason::ExpiredRegistration { epoch: 0, .. })
        ));
        assert!(!faulted.chain.pending_withdrawals[&account].carried);
        faulted.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(
            faulted.chain.claim_pending_deposit(11, &depositor).unwrap(),
            DepositRefund {
                account: depositor.clone(),
                amount: 2,
            }
        );
        let release = faulted
            .chain
            .claim_hard_fault(&genesis.opening(&account).unwrap())
            .unwrap();
        assert_withdrawal_output(release.withdrawal.as_ref().unwrap(), &request, 4);
        assert_eq!(release.residual, 6);
    }

    /// A fresh extra supersedes a different request its account queues on chain after the
    /// boundary is built, because that request sits at or past the pull's end. The registration
    /// succeeds, the queued request leaves every inbox obligation with its replay id consumed,
    /// and the next pull owes nothing for it. A restarted chain behaves identically, admission
    /// releases the extra, and a fault before admission leaves the signer its state claim alone.
    #[test]
    fn fresh_extra_supersedes_a_later_queued_request() {
        let mut fixture = harness_with_config(&[10, 10], policy(10, 2));
        let genesis = fixture.cache.clone();
        let depositor = fixture.accounts[0].public_key();
        let signer = fixture.accounts[1].clone();
        let account = signer.public_key();
        let opening = genesis.opening(&account).unwrap();
        let extra = withdrawal(
            fixture.deployment,
            genesis.root(),
            &signer,
            b"extra",
            amount_action(3),
            20,
        );
        let queued = withdrawal(
            fixture.deployment,
            genesis.root(),
            &signer,
            b"queued",
            amount_action(4),
            20,
        );
        let carried = WithdrawalBatch::new(vec![extra.clone()]).unwrap();
        let build = |fixture: &mut Harness| {
            fixture
                .chain
                .record_deposit(
                    0,
                    Sha256::hash(&[b"superseding-deposit"]),
                    depositor.clone(),
                    2,
                )
                .unwrap();
            let deposits = fixture.chain.deposits_to(1);
            let context = epoch_context(
                fixture.deployment,
                &fixture.operator,
                fixture.committee,
                0,
                &deposits,
                &carried,
            );
            (deposits, context)
        };
        let queue = |fixture: &mut Harness| {
            fixture
                .chain
                .queue_withdrawal(0, queued.clone(), &opening, |_| true)
                .unwrap()
        };

        // The operator builds epoch 0 over the deposit at index 0 with the extra, and the
        // account queues another request at index 1 before the registration executes.
        let (deposits, first) = build(&mut fixture);
        assert_eq!(queue(&mut fixture), 1);

        // The registration succeeds and the queued request leaves the inbox obligations.
        fixture
            .chain
            .register_through(0, first, 1, carried.clone(), |_| true)
            .unwrap();
        assert!(fixture.chain.pending_withdrawals.is_empty());
        assert!(fixture.chain.pending_withdrawal_deadlines.is_empty());
        let mut restarted = round_trip(&fixture.chain);

        // Neither request can be queued again, and another extra for the account is rejected.
        let another = withdrawal(
            fixture.deployment,
            genesis.root(),
            &signer,
            b"another",
            amount_action(1),
            30,
        );
        let rejected = WithdrawalBatch::new(vec![another]).unwrap();
        let rejected_context = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &DepositBatch::empty(),
            &rejected,
        );
        for chain in [&mut fixture.chain, &mut restarted] {
            let before = chain.encode();
            assert!(matches!(
                chain.queue_withdrawal(0, queued.clone(), &opening, |_| true),
                Err(SettlementError::DuplicateWithdrawalAuthorization)
            ));
            assert!(matches!(
                chain.queue_withdrawal(0, extra.clone(), &opening, |_| true),
                Err(SettlementError::DuplicateWithdrawal)
            ));
            assert!(matches!(
                chain.register_through(0, rejected_context.clone(), 2, rejected.clone(), |_| true),
                Err(SettlementError::DuplicateWithdrawal)
            ));
            assert_eq!(chain.encode(), before);
        }

        // The next pull reaches index 1 and owes nothing for it, and admitting epoch 0 releases
        // the extra.
        let second = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
        );
        let registered = fixture.chain.registered().unwrap();
        let frontier = registered.context.clone();
        let withdrawals = registered.withdrawals.clone();
        let (close, _) = boundary_close(&genesis, &frontier, &deposits, &withdrawals);
        let close_certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &frontier,
            &deposits,
            &withdrawals,
            &close,
        );
        for chain in [&mut fixture.chain, &mut restarted] {
            assert!(chain.active.pending_withdrawals(2).is_empty());
            chain
                .register_through(0, second.clone(), 2, WithdrawalBatch::empty(), |_| true)
                .unwrap();
            chain
                .admit(
                    1,
                    close.header,
                    close.roots,
                    close.withdrawal_total,
                    close_certificate.clone(),
                )
                .unwrap();
        }
        assert_eq!(restarted.encode(), fixture.chain.encode());
        assert_withdrawal_output(close.withdrawal_claim(&account).output(), &extra, 3);

        // A fault before admission drops the extra, and the superseded request reaches no
        // terminal claim, so the signer recovers its whole balance through its state claim.
        let mut faulted = harness_with_config(&[10, 10], policy(10, 2));
        let (_, first) = build(&mut faulted);
        assert_eq!(queue(&mut faulted), 1);
        faulted
            .chain
            .register_through(0, first, 1, carried, |_| true)
            .unwrap();
        assert!(matches!(
            faulted.chain.fault_expired(11),
            Ok(HardFaultReason::ExpiredRegistration { epoch: 0, .. })
        ));
        faulted.chain.begin_hard_fault_settlement().unwrap();
        let release = faulted.chain.claim_hard_fault(&opening).unwrap();
        assert!(release.withdrawal.is_none());
        assert_eq!(release.residual, 10);
    }

    /// A chain-queued request superseded by an operator-carried extra, followed by a hard fault
    /// before the carrying epoch is admitted, leaves the signer its whole finalized balance and
    /// every unadmitted deposit. Neither request pays, custody drains exactly, and a second claim
    /// is rejected.
    #[test]
    fn superseded_request_recovers_every_unit_after_a_hard_fault() {
        let mut fixture = harness_with_config(&[10, 10], policy(10, 2));
        let (payer, signer) = (fixture.accounts[0].clone(), fixture.accounts[1].clone());
        let account = signer.public_key();

        // Epoch 0's payment of 3 to the signer finalizes at 13, so the finalized balance is 13.
        // The signer then deposits 5 at index 0.
        let (first, _) = finalize_payment(&mut fixture, &payer, &signer);
        let finalized = &first.successor;
        let opening = finalized.opening(&account).unwrap();
        let balance = opening.balance.get();
        assert_eq!(balance, 13);
        fixture
            .chain
            .record_deposit(14, Sha256::hash(&[b"recovered-pulled"]), account.clone(), 5)
            .unwrap();

        // The signer queues a request at index 1. Epoch 1 pulls only index 0 and carries a fresh
        // extra for the signer, which supersedes the queued request.
        let queued = withdrawal(
            fixture.deployment,
            finalized.root(),
            &signer,
            b"queued",
            amount_action(4),
            40,
        );
        let extra = withdrawal(
            fixture.deployment,
            finalized.root(),
            &signer,
            b"extra",
            amount_action(3),
            40,
        );
        assert_eq!(
            fixture
                .chain
                .queue_withdrawal(14, queued, &opening, |_| true)
                .unwrap(),
            1
        );
        let carried = WithdrawalBatch::new(vec![extra]).unwrap();
        let deposits = fixture.chain.deposits_to(1);
        let context = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &deposits,
            &carried,
        );
        fixture
            .chain
            .register_through(14, context, 1, carried, |_| true)
            .unwrap();
        assert!(fixture.chain.pending_withdrawals.is_empty());
        assert!(fixture.chain.pending_withdrawal_deadlines.is_empty());

        // A later deposit of 2 stays unpulled.
        fixture
            .chain
            .record_deposit(
                15,
                Sha256::hash(&[b"recovered-unpulled"]),
                account.clone(),
                2,
            )
            .unwrap();
        let deposited = 7;

        // The frontier's admission deadline at 24 expires at 25 and drops epoch 1 with its
        // extra. The faulted chain survives a restart.
        assert!(matches!(
            fixture.chain.fault_expired(25),
            Ok(HardFaultReason::ExpiredRegistration { epoch: 1, .. })
        ));
        let mut chain = round_trip(&fixture.chain);
        let custody = chain.custody_balance() + chain.claimable_balance();
        assert_eq!(custody, 20 + deposited);

        // Terminal settlement freezes the finalized root with both deposits refundable.
        let settlement = chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.frozen_state_root, finalized.root());
        assert_eq!(settlement.state_liability, 20);
        assert_eq!(settlement.unfinalized_deposit_total, deposited);
        assert_eq!(settlement.custody_balance, custody);

        // The signer's state claim routes neither request and returns the whole balance, and a
        // second claim is rejected.
        let release = chain.claim_hard_fault(&opening).unwrap();
        assert_eq!(
            release,
            HardFaultRelease {
                account: account.clone(),
                withdrawal: None,
                residual: balance,
                released_custody: balance,
            }
        );
        assert!(matches!(
            chain.claim_hard_fault(&opening),
            Err(SettlementError::ClaimAlreadyConsumed)
        ));

        // The refund returns both unadmitted deposits once.
        let refund = chain.claim_pending_deposit(26, &account).unwrap();
        assert_eq!(refund.amount, deposited);
        assert!(matches!(
            chain.claim_pending_deposit(26, &account),
            Err(SettlementError::PendingDepositUnavailable)
        ));
        assert_eq!(release.residual + refund.amount, balance + deposited);

        // The payer's claim drains custody, and every claim and refund sums to the custody the
        // fault froze.
        let payer_release = chain
            .claim_hard_fault(&finalized.opening(&payer.public_key()).unwrap())
            .unwrap();
        assert!(payer_release.withdrawal.is_none());
        assert_eq!(
            release.released_custody + payer_release.released_custody + refund.amount,
            custody
        );
        assert!(chain.hard_fault_is_settled());
        assert_eq!(chain.custody_balance(), 0);
        assert_eq!(chain.claimable_balance(), 0);
        assert_eq!(chain.unfinalized_deposit_total, 0);
        assert!(chain.pending_deposits.is_empty());
        assert!(chain.pending_withdrawals.is_empty());
        assert!(matches!(
            chain.claim_hard_fault(&opening),
            Err(SettlementError::HardFaultAlreadySettled)
        ));
    }

    /// A deposit batch that credits an account more than its unpulled deposits is API misuse, and
    /// registration panics at the cause. Deposits a live registration already pulled no longer
    /// count as unpulled.
    #[test]
    #[should_panic(expected = "the deposit batch exceeds the account's unpulled deposits")]
    fn deposit_batch_beyond_unpulled_deposits_panics() {
        let mut fixture = harness_with_config(&[10, 10], policy(10, 2));
        let depositor = fixture.accounts[0].public_key();

        // Epoch 0 pulls the first deposit.
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"pulled-deposit"]), depositor.clone(), 2)
            .unwrap();
        let deposits = fixture.chain.deposits_to(1);
        let first = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            0,
            &deposits,
            &WithdrawalBatch::empty(),
        );
        fixture
            .chain
            .register_through(0, first, 1, WithdrawalBatch::empty(), |_| true)
            .unwrap();

        // Epoch 1 pulls the second deposit but credits both.
        fixture
            .chain
            .record_deposit(
                0,
                Sha256::hash(&[b"unpulled-deposit"]),
                depositor.clone(),
                1,
            )
            .unwrap();
        let inflated = DepositBatch::new(vec![DepositRecord::new(depositor, 3).unwrap()]).unwrap();
        let second = epoch_context(
            fixture.deployment,
            &fixture.operator,
            fixture.committee,
            1,
            &inflated,
            &WithdrawalBatch::empty(),
        );
        let _ = fixture.chain.active.register_epoch(
            0,
            second,
            2,
            inflated,
            WithdrawalBatch::empty(),
            |_| true,
        );
    }

    /// Deposits recorded at one instant share a run, so the runs never outnumber the distinct
    /// recording instants within one timeout, however many deposits arrive. The oldest unpulled
    /// deposit expires first, attributed to the latest deposit of its instant.
    #[test]
    fn deadline_runs_coalesce_per_instant() {
        let mut settlement_config = config(2);
        settlement_config.deposit_inclusion_timeout = NonZeroU64::new(4).unwrap();
        let mut fixture = harness_with_config(&[10, 10], settlement_config);
        let accounts = [
            fixture.accounts[0].public_key(),
            fixture.accounts[1].public_key(),
        ];

        // Eight deposits at each of four instants form one run per instant.
        for now in 0..4_u64 {
            for offset in 0..8_u64 {
                let id = Sha256::hash(&[&now.to_be_bytes(), &offset.to_be_bytes()]);
                fixture
                    .chain
                    .record_deposit(now, id, accounts[(offset % 2) as usize].clone(), 1)
                    .unwrap();
            }
        }
        assert_eq!(fixture.chain.intake(), 32);
        assert_eq!(
            fixture.chain.runs,
            (0..4_u64)
                .map(|now| Run {
                    end: (now + 1) * 8,
                    deadline: now + 4,
                    account: accounts[1].clone(),
                })
                .collect::<VecDeque<_>>()
        );

        // The first instant's deposits expire first, attributed to its latest deposit.
        assert!(matches!(
            fixture.chain.fault_expired(3),
            Err(SettlementError::DeadlineNotReached)
        ));
        assert_eq!(
            fixture.chain.fault_expired(4).unwrap(),
            HardFaultReason::ExpiredDeposit {
                account: accounts[1].clone(),
                expired_at: 4,
            }
        );
        assert!(fixture.chain.runs.is_empty());
    }

    /// Admitting an epoch subtracts exactly its pulled deposits from each account's pending
    /// total and removes an account only when nothing of it remains.
    #[test]
    fn admission_removes_only_its_pulled_deposits() {
        let mut fixture = harness_with_config(&[10, 10], policy(10, 2));
        let genesis = fixture.cache.clone();
        let first = fixture.accounts[0].public_key();
        let second = fixture.accounts[1].public_key();

        // Epoch 0 pulls one deposit of each account, and the first account deposits again.
        for (label, account, amount) in [
            (b"first".as_slice(), &first, 5),
            (b"second".as_slice(), &second, 2),
        ] {
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[label]), account.clone(), amount)
                .unwrap();
        }
        register_next(&mut fixture, 0, vec![]).unwrap();
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"again"]), first.clone(), 3)
            .unwrap();

        // Admission leaves only the unpulled deposit, and custody still balances.
        admit_frontier(&mut fixture, 0, &genesis);
        assert_eq!(fixture.chain.pending_deposits, BTreeMap::from([(first, 3)]));
        assert_eq!(fixture.chain.custody_balance(), 30);
        assert_eq!(
            fixture.chain.custody_balance(),
            fixture.chain.current_liability + fixture.chain.unfinalized_deposit_total
        );
    }

    /// A refund returns every unadmitted deposit of an account once: deposits no registration
    /// pulled and deposits pulled by registrations the fault dropped, but not a deposit an
    /// admitted close already carries.
    #[test]
    fn refund_adds_unadmitted_deposits_once() {
        let mut fixture = harness_with_config(&[10], policy(10, 2));
        let genesis = fixture.cache.clone();
        let account = fixture.accounts[0].public_key();
        let deposit = |fixture: &mut Harness, amount: u64| {
            fixture
                .chain
                .record_deposit(
                    0,
                    Sha256::hash(&[&amount.to_be_bytes()]),
                    account.clone(),
                    amount,
                )
                .unwrap();
        };

        // Epoch 0 pulls 1 and is admitted while 2 waits, so admission leaves 2 pending.
        deposit(&mut fixture, 1);
        register_next(&mut fixture, 0, vec![]).unwrap();
        deposit(&mut fixture, 2);
        let (first, _, _) = admit_frontier(&mut fixture, 0, &genesis);
        assert_eq!(
            fixture.chain.pending_deposits,
            BTreeMap::from([(account.clone(), 2)])
        );

        // Epoch 1 pulls 2 as the frontier, epoch 2 pulls 4 behind it, and 8 stays unpulled.
        register_next(&mut fixture, 0, vec![]).unwrap();
        deposit(&mut fixture, 4);
        register_next(&mut fixture, 0, vec![]).unwrap();
        deposit(&mut fixture, 8);
        assert_eq!(
            fixture.chain.pending_deposits,
            BTreeMap::from([(account.clone(), 14)])
        );
        assert_eq!(fixture.chain.custody_balance(), 25);

        // The frontier expires at 11 and drops both registrations.
        assert!(matches!(
            fixture.chain.fault_expired(11),
            Ok(HardFaultReason::ExpiredRegistration { epoch: 1, .. })
        ));
        assert!(fixture.chain.runs.is_empty());

        // The refund returns the three unadmitted deposits once.
        assert_eq!(
            fixture.chain.claim_pending_deposit(11, &account).unwrap(),
            DepositRefund {
                account: account.clone(),
                amount: 14,
            }
        );
        assert!(matches!(
            fixture.chain.claim_pending_deposit(11, &account),
            Err(SettlementError::PendingDepositUnavailable)
        ));
        assert_eq!(fixture.chain.custody_balance(), 11);

        // The admitted close finalizes with its deposit, and state claims drain the rest.
        fixture.chain.finalize(13).unwrap();
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.unfinalized_deposit_total, 0);
        let released = claim_frozen_state(&mut fixture.chain, &first.successor)
            .iter()
            .map(|release| release.released_custody)
            .sum::<u64>();
        assert_eq!(released, 11);
        assert!(fixture.chain.hard_fault_is_settled());
    }

    /// A registration cannot pull before the first unpulled index or past the inbox, and either
    /// rejection leaves the chain unchanged. The remaining inbox then registers.
    #[test]
    fn pull_range_is_bounded_by_the_inbox() {
        let mut fixture = harness(&[10]);
        let account = fixture.accounts[0].public_key();
        for label in [b"first".as_slice(), b"second".as_slice()] {
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[label]), account.clone(), 1)
                .unwrap();
        }
        let context = |fixture: &Harness, epoch: u64, deposits: &TestDeposits| {
            epoch_context(
                fixture.deployment,
                &fixture.operator,
                fixture.committee,
                epoch,
                deposits,
                &WithdrawalBatch::empty(),
            )
        };

        // Epoch 0 pulls the first deposit.
        let deposits = fixture.chain.deposits_to(1);
        let first = context(&fixture, 0, &deposits);
        fixture
            .chain
            .register_through(0, first, 1, WithdrawalBatch::empty(), |_| true)
            .unwrap();

        // Ends before the pulled prefix or past the inbox are rejected without mutation.
        let before = fixture.chain.encode();
        for (end, deposits) in [
            (0, DepositBatch::empty()),
            (3, fixture.chain.deposits_to(2)),
        ] {
            let second = context(&fixture, 1, &deposits);
            assert!(matches!(
                fixture.chain.active.register_epoch(
                    0,
                    second,
                    end,
                    deposits,
                    WithdrawalBatch::empty(),
                    |_| true,
                ),
                Err(SettlementError::IntakeRange)
            ));
            assert_eq!(fixture.chain.encode(), before);
        }

        // The exact remaining inbox registers.
        let deposits = fixture.chain.deposits_to(2);
        let second = context(&fixture, 1, &deposits);
        fixture
            .chain
            .register_through(0, second, 2, WithdrawalBatch::empty(), |_| true)
            .unwrap();
        assert_eq!(fixture.chain.pulled(), 2);
    }

    /// A full inbox counter rejects a deposit and a chain-queued withdrawal before any mutation.
    #[test]
    fn full_inbox_rejects_intake_before_mutation() {
        let mut fixture = harness(&[10]);
        let signer = fixture.accounts[0].clone();
        let account = signer.public_key();
        fixture.chain.intake = u64::MAX;
        fixture.chain.pulled = u64::MAX;
        let before = fixture.chain.encode();
        assert!(matches!(
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[b"overflow"]), account.clone(), 1),
            Err(SettlementError::IntakeOverflow)
        ));
        assert_eq!(fixture.chain.encode(), before);
        let request = withdrawal(
            fixture.deployment,
            fixture.cache.root(),
            &signer,
            b"overflow",
            amount_action(1),
            20,
        );
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                0,
                request,
                &fixture.cache.opening(&account).unwrap(),
                |_| true,
            ),
            Err(SettlementError::IntakeOverflow)
        ));
        assert_eq!(fixture.chain.encode(), before);
    }

    /// A carried withdrawal resolves from its epoch's final tail. An Amount below or equal to the
    /// tail releases in full, one above it releases zero, and a Close sweeps the tail. A credit in
    /// the carrying epoch can lift a fresh Amount over its payer's opening balance.
    #[test]
    fn amount_and_close_resolve_from_the_carrying_epoch_tail() {
        let mut fixture = harness(&[10, 10, 10, 10]);
        let genesis = fixture.cache.clone();
        let signers = fixture.accounts.clone();
        let request = |signer: &SigningKey, destination: &'static [u8], action| {
            withdrawal(
                fixture.deployment,
                genesis.root(),
                signer,
                destination,
                action,
                20,
            )
        };

        // Queued requests below and equal to the tail and a Close, plus a fresh Amount above it.
        let below = request(&signers[0], b"below", amount_action(9));
        let equal = request(&signers[1], b"equal", amount_action(10));
        let close = request(&signers[2], b"close", WithdrawalAction::Close);
        let above = request(&signers[3], b"above", amount_action(11));
        for queued in [&below, &equal, &close] {
            fixture
                .chain
                .queue_withdrawal(
                    0,
                    queued.clone(),
                    &genesis.opening(queued.account()).unwrap(),
                    |_| true,
                )
                .unwrap();
        }
        assert!(matches!(
            fixture.chain.queue_withdrawal(
                0,
                above.clone(),
                &genesis.opening(above.account()).unwrap(),
                |_| true,
            ),
            Err(SettlementError::WithdrawalBalance)
        ));
        register_next(&mut fixture, 0, vec![above.clone()]).unwrap();
        let (built, _, _) = admit_frontier(&mut fixture, 0, &genesis);
        for (request, amount) in [(&below, 9), (&equal, 10), (&close, 10), (&above, 0)] {
            let claim = built.withdrawal_claim(request.account());
            assert_withdrawal_output(claim.output(), request, amount);
        }
        assert_eq!(built.withdrawal_total, 29);
        fixture.chain.finalize(3).unwrap();
        assert_eq!(fixture.chain.claimable_balance(), 29);
        assert_eq!(fixture.chain.current_liability, 11);

        // A credit of 2 in the carrying epoch lifts a fresh Amount of 12 over a balance of 10.
        let mut credited = harness(&[10, 10]);
        let genesis = credited.cache.clone();
        let receiver = credited.accounts[0].clone();
        let payer = credited.accounts[1].clone();
        let lifted = withdrawal(
            credited.deployment,
            genesis.root(),
            &receiver,
            b"lifted",
            amount_action(12),
            20,
        );
        register_next(&mut credited, 0, vec![lifted.clone()]).unwrap();
        let context = credited.chain.frontier();
        let withdrawals = credited.chain.registered().unwrap().withdrawals.clone();
        let (paid, _) = payment_close(
            &genesis,
            &context,
            &credited.operator_ack,
            &payer,
            &receiver,
            &withdrawals,
            2,
        );
        let claim = paid.withdrawal_claim(&receiver.public_key());
        assert_withdrawal_output(claim.output(), &lifted, 12);
        let paid_certificate = certificate(
            &credited.signer,
            &credited.operator_bls,
            &context,
            &DepositBatch::empty(),
            &withdrawals,
            &paid,
        );
        credited
            .chain
            .admit(
                0,
                paid.header,
                paid.roots,
                paid.withdrawal_total,
                paid_certificate,
            )
            .unwrap();
        credited.chain.finalize(3).unwrap();
        assert_eq!(
            credited.chain.claim_withdrawal(&claim).unwrap().amount(),
            12
        );
    }

    /// The frontier's predecessor liability comes only from settlement's admitted head: the
    /// previous liability plus the predecessor's pulled deposits minus its certified withdrawals.
    #[test]
    fn promotion_binds_the_liability_recurrence_from_the_admitted_head() {
        let mut fixture = harness(&[10, 10]);
        let genesis = fixture.cache.clone();
        let depositor = fixture.accounts[0].public_key();
        let withdrawer = fixture.accounts[1].clone();

        // Epoch 0 pulls a deposit of 5 and a queued withdrawal of 4 over a liability of 20.
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"recurrence"]), depositor, 5)
            .unwrap();
        let request = withdrawal(
            fixture.deployment,
            genesis.root(),
            &withdrawer,
            b"recurrence",
            amount_action(4),
            20,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request,
                &genesis.opening(&withdrawer.public_key()).unwrap(),
                |_| true,
            )
            .unwrap();
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert_eq!(fixture.chain.frontier().predecessor_liability(), 20);

        // Epoch 1 queues without a liability and binds 20 + 5 - 4 at epoch 0's admission.
        register_next(&mut fixture, 0, vec![]).unwrap();
        let (first, _, _) = admit_frontier(&mut fixture, 1, &genesis);
        assert_eq!(first.withdrawal_total, 4);
        assert_eq!(fixture.chain.pending().unwrap().successor_liability, 21);
        let second = fixture.chain.frontier();
        assert_eq!(second.predecessor_liability(), 21);
        assert_eq!(second.predecessor_liability(), first.successor.liability());
        assert_eq!(second.predecessor_root(), &first.successor.root());
    }

    /// A proven challenge behind a clean admitted prefix drops the frontier and the queue. The
    /// clean prefix still finalizes, each account's deposits are refunded exactly once across the
    /// dropped registrations, the unpulled inbox, and the invalidated close, and state claims
    /// recover the frozen root.
    #[test]
    fn challenge_with_queued_epochs_refunds_every_deposit_exactly() {
        let mut fixture = harness(&[10, 10]);
        let genesis = fixture.cache.clone();
        let first_account = fixture.accounts[0].public_key();
        let second_account = fixture.accounts[1].public_key();
        let deposit = |fixture: &mut Harness, label: &[u8], account: &VerifyingKey, amount| {
            fixture
                .chain
                .record_deposit(0, Sha256::hash(&[label]), account.clone(), amount)
                .unwrap()
        };

        // Epochs 0 and 1 are admitted with deposits of 1 and 2 for the first account.
        assert_eq!(deposit(&mut fixture, b"first", &first_account, 1), 0);
        register_next(&mut fixture, 0, vec![]).unwrap();
        let (first, _, _) = admit_frontier(&mut fixture, 0, &genesis);
        assert_eq!(deposit(&mut fixture, b"second", &first_account, 2), 1);
        register_next(&mut fixture, 0, vec![]).unwrap();
        let (_, second_id, second_context) = admit_frontier(&mut fixture, 0, &first.successor);

        // Epoch 2 is the frontier and epoch 3 queues behind it, with more intake beyond both.
        assert_eq!(deposit(&mut fixture, b"third", &second_account, 3), 2);
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert_eq!(deposit(&mut fixture, b"fourth", &first_account, 4), 3);
        register_next(&mut fixture, 0, vec![]).unwrap();
        assert_eq!(deposit(&mut fixture, b"fifth", &second_account, 5), 4);
        assert_eq!(fixture.chain.custody_balance(), 35);

        // A proven fork against epoch 1 drops both registrations.
        let left = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            2,
        );
        let right = fork_ack(
            &second_context,
            &fixture.operator,
            &fixture.accounts[0],
            1,
            3,
        );
        assert_eq!(
            fixture
                .chain
                .challenge(0, second_id, &ack_fork(&left, &right))
                .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );
        assert!(fixture.chain.registered().is_none());
        assert!(fixture.chain.queued.is_empty());
        assert_eq!(fixture.chain.admission_fence_epoch(), Some(2));

        // Before terminal settlement, the second account's pulled and unpulled deposits refund
        // together.
        assert_eq!(
            fixture
                .chain
                .claim_pending_deposit(0, &second_account)
                .unwrap(),
            DepositRefund {
                account: second_account.clone(),
                amount: 8,
            }
        );
        assert!(matches!(
            fixture.chain.claim_pending_deposit(0, &second_account),
            Err(SettlementError::PendingDepositUnavailable)
        ));

        // The clean prefix finalizes. Terminal settlement then adds the first account's deposit
        // in the dropped registration to its deposit in the invalidated close.
        fixture.chain.finalize(3).unwrap();
        let settlement = fixture.chain.begin_hard_fault_settlement().unwrap();
        assert_eq!(settlement.frozen_state_root, first.successor.root());
        assert_eq!(settlement.unfinalized_deposit_total, 6);
        assert_eq!(
            fixture
                .chain
                .claim_pending_deposit(3, &first_account)
                .unwrap(),
            DepositRefund {
                account: first_account,
                amount: 6,
            }
        );
        let released = claim_frozen_state(&mut fixture.chain, &first.successor)
            .iter()
            .map(|release| release.released_custody)
            .sum::<u64>();
        assert_eq!(released, 21);
        assert!(fixture.chain.hard_fault_is_settled());
        assert_eq!(fixture.chain.custody_balance(), 0);
    }

    /// Queued registrations, the inbox counters, deadline runs, and carried withdrawals survive a
    /// codec round trip and keep behaving identically, including after a fault clears the runs
    /// and the carriage. Every truncation and a hostile queue count fail to decode.
    #[test]
    fn codec_round_trips_queued_and_faulted_states_and_rejects_hostile_input() {
        let bounds = Bounds {
            committee: 16,
            items: 1024,
            destination: 1024,
        };
        let mut fixture = harness(&[10, 10]);
        let genesis = fixture.cache.clone();
        let depositor = fixture.accounts[0].public_key();
        let signer = fixture.accounts[1].clone();

        // A lone frontier encodes an empty queue.
        register_next(&mut fixture, 0, vec![]).unwrap();
        let lone = fixture.chain.active.encode();

        // Epochs 1 and 2 queue around a deposit and a withdrawal, and more intake follows.
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"codec-deposit"]), depositor, 2)
            .unwrap();
        register_next(&mut fixture, 0, vec![]).unwrap();
        let request = withdrawal(
            fixture.deployment,
            genesis.root(),
            &signer,
            b"codec",
            amount_action(1),
            20,
        );
        fixture
            .chain
            .queue_withdrawal(
                0,
                request,
                &genesis.opening(&signer.public_key()).unwrap(),
                |_| true,
            )
            .unwrap();
        register_next(&mut fixture, 0, vec![]).unwrap();
        fixture
            .chain
            .record_deposit(0, Sha256::hash(&[b"codec-next"]), signer.public_key(), 1)
            .unwrap();
        assert_eq!(fixture.chain.queued.len(), 2);
        assert_eq!((fixture.chain.intake(), fixture.chain.pulled()), (3, 2));
        assert_eq!(fixture.chain.runs.len(), 1);
        assert!(fixture.chain.pending_withdrawals[&signer.public_key()].carried);
        let mut decoded = round_trip(&fixture.chain);
        assert!(decoded.pending_withdrawals[&signer.public_key()].carried);
        assert_eq!(decoded.runs, fixture.chain.runs);

        // Admission promotes the same epoch on both chains.
        let registered = fixture.chain.registered().unwrap();
        let context = registered.context.clone();
        let close = empty_close(&genesis, &context);
        let close_certificate = certificate(
            &fixture.signer,
            &fixture.operator_bls,
            &context,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            &close,
        );
        for chain in [&mut fixture.chain, &mut decoded] {
            chain
                .admit(
                    0,
                    close.header,
                    close.roots,
                    close.withdrawal_total,
                    close_certificate.clone(),
                )
                .unwrap();
        }
        assert_eq!(decoded.encode(), fixture.chain.encode());

        // Expiry of the promoted frontier drops the queue, the runs, and the carriage, while the
        // unpulled deposit and the dropped registration's request stay pending. The structural
        // codec still round-trips the faulted state.
        assert!(matches!(
            fixture.chain.fault_expired(2),
            Ok(HardFaultReason::ExpiredRegistration { epoch: 1, .. })
        ));
        assert_eq!(fixture.chain.next_registration_epoch().unwrap(), 1);
        assert!(fixture.chain.runs.is_empty());
        assert_eq!(
            fixture.chain.pending_deposits.get(&signer.public_key()),
            Some(&1)
        );
        assert!(!fixture.chain.pending_withdrawals[&signer.public_key()].carried);
        let faulted = round_trip(&fixture.chain);
        assert_eq!(faulted.hard_fault(), fixture.chain.hard_fault());
        assert!(!faulted.pending_withdrawals[&signer.public_key()].carried);

        // Every truncation fails to decode.
        let encoded = fixture.chain.active.encode();
        for length in 0..encoded.len() {
            assert!(
                SettlementChain::<Sha256, VerifyingKey>::decode_cfg(
                    encoded.slice(..length),
                    &bounds
                )
                .is_err()
            );
        }

        // The lone frontier's queue count is followed by six empty trailing fields. A hostile
        // count fails when the entries run out instead of allocating for the count.
        let offset = lone.len() - 7;
        assert!(lone[offset..].iter().all(|byte| *byte == 0));
        let mut hostile = lone.to_vec();
        hostile.splice(
            offset..=offset,
            usize::try_from(u32::MAX).unwrap().encode().to_vec(),
        );
        assert!(
            SettlementChain::<Sha256, VerifyingKey>::decode_cfg(Bytes::from(hostile), &bounds)
                .is_err()
        );
    }
}
