//! In-memory settlement-chain owner for the three-process terminal.

use crate::{
    protocol::{
        DepositEvent, INITIAL_BALANCE, Key, MAX_ACCOUNTS, SQLITE_U64_MAX, SettlementResult,
        committee, deployment, ensure_amount_withdrawal_horizon, ensure_balance_intake_horizon,
        ensure_close_horizon, epoch_context, identities, openable_epoch_after, operator_key,
        settlement_config,
    },
    store::MAX_DESTINATION_BYTES,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{StateOpening, Verdict},
    commitment::VectorRoot,
    settlement::{
        ClaimError, DepositRefund, FinalizedBatch, HardFaultRelease, HardFaultSettlement,
        SettlementChain, SettlementError,
    },
    state::{AccountState, StateLeaf},
    transition::{
        BatchId, ExternalPayout, ExternalPayoutClaim, Header, RootBundle, StateCache,
        TerminalProof, WithdrawalClaim, WithdrawalOutput,
    },
};
use commonware_cryptography::{Sha256, sha256::Digest};
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    time::{Duration, Instant},
};

const LOGICAL_TICK: Duration = Duration::from_secs(30);

type WithdrawalClaimKey = (BatchId<Digest>, u32);
type ClaimedWithdrawal = (WithdrawalClaim<Digest>, WithdrawalOutput);
type PayoutClaimKey = (BatchId<Digest>, u32);
type ClaimedPayout = (ExternalPayoutClaim<Key, Digest>, ExternalPayout<Key>);
type ProvenChallenge = (Bytes, Verdict);
type HardFaultClaimKey = (Digest, u32);
type HardFaultClaim = (StateOpening<Key, Digest>, HardFaultRelease<Key>);

type FinalizedAdmission = (SettlementSubmission, FinalizedBatch<Digest>);

/// Bounded response-loss replay state. The map and insertion order are updated together so
/// evicting an acknowledgement can never evict authoritative settlement state.
struct ReplayCache<K, V> {
    entries: BTreeMap<K, V>,
    order: VecDeque<K>,
    capacity: NonZeroUsize,
}

impl<K: Clone + Ord, V> ReplayCache<K, V> {
    const fn new(capacity: NonZeroUsize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    fn insert(&mut self, key: K, value: V) {
        debug_assert!(!self.entries.contains_key(&key));
        self.order.push_back(key.clone());
        self.entries.insert(key, value);
        if self.entries.len() > self.capacity.get() {
            let oldest = self
                .order
                .pop_front()
                .expect("a replay entry was inserted above");
            let removed = self.entries.remove(&oldest);
            debug_assert!(removed.is_some());
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SettlementSubmission {
    pub(crate) epoch: u64,
    pub(crate) predecessor_liability: u64,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) terminal_proof: TerminalProof<Digest>,
    pub(crate) certificate: commonware_clearing::bajillion::admission::bls12381::Certificate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionOutcome {
    Pending,
    Finalized(FinalizedBatch<Digest>),
}

/// One finalized-batch claim resolution, split by whether the exact claim can ever succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClaimOutcome<T> {
    /// The claim was released against a finalized batch.
    Released(T),
    /// The batch is not claimable now. It may simply not have finalized yet, so the exact
    /// claim must be retried later and never discarded.
    Unavailable,
    /// The claim was adjudicated against an immutable finalized batch and rejected. The
    /// verdict can never change, so the claimant must discard the claim.
    Invalid,
}

/// Maps one chain claim rejection onto the retry contract: an unavailable batch is the only
/// state-dependent answer, and every adjudicated rejection is final for the exact claim.
fn claim_rejection<T>(error: ClaimError) -> ClaimOutcome<T> {
    match error {
        ClaimError::Unavailable => ClaimOutcome::Unavailable,
        ClaimError::Consumed | ClaimError::Reserve | ClaimError::Proof(_) => ClaimOutcome::Invalid,
    }
}

/// The claim roots of one finalized batch.
///
/// Wallets verify claim evidence locally against these roots, so the record must outlive
/// the chain's claimable reserve, which drains once every claim is consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClaimRoots {
    pub(crate) withdrawal_outputs: VectorRoot<Digest>,
    pub(crate) change: VectorRoot<Digest>,
}

/// What settlement holds for one epoch: the registered payment anchor, and the admitted
/// close's identity and roots once a close is admitted.
///
/// This is the anchor for both intake and reconciliation. A recipient records a pair as
/// reliance-grade only when its context anchor matches `anchor` here, and it decides coverage
/// of a held receipt only against `admitted`, never against operator-claimed roots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EpochRoots {
    /// The registered payment context anchor, present from registration onward.
    pub(crate) anchor: Digest,
    /// The admitted close, present once a close is admitted for the epoch.
    pub(crate) admitted: Option<AdmittedRoots>,
}

/// The identity and change root of the close admitted for one epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedRoots {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) change: VectorRoot<Digest>,
    /// Whether the close finalized. While false, its inclusive challenge window is open.
    pub(crate) finalized: bool,
}

/// Whether settlement holds a custody record for one exact deposit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DepositPresence {
    /// The exact event is recorded, so its custody moved.
    Recorded,
    /// The id is unknown, so no custody moved and the event is safe to abandon.
    Unknown,
}

impl From<&SettlementResult> for SettlementSubmission {
    fn from(result: &SettlementResult) -> Self {
        Self {
            epoch: result.epoch,
            predecessor_liability: result.epoch_context.predecessor_liability(),
            deposits: result.deposits.clone(),
            withdrawals: result.withdrawals.clone(),
            header: result.header,
            roots: result.roots,
            terminal_proof: result.terminal_proof.clone(),
            certificate: result.certificate.clone(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SettlementStatus {
    pub(crate) now: u64,
    pub(crate) deployment: Digest,
    pub(crate) state_root: VectorRoot<Digest>,
    /// Highest finalized epoch. Epochs finalize in order, so the state root covers every
    /// epoch at or below it.
    pub(crate) last_finalized: Option<u64>,
    pub(crate) custody_balance: u64,
    pub(crate) claimable_balance: u64,
    pub(crate) hard_faulted: bool,
}

#[derive(Clone)]
struct RegisteredEpoch {
    epoch: u64,
    predecessor_liability: u64,
    anchor: Digest,
    deposits: DepositBatch<Key>,
    staged_root: VectorRoot<Digest>,
    withdrawals: WithdrawalBatch<Key, Digest>,
    admitted: Option<SettlementSubmission>,
}

struct LivenessClock {
    logical_start: u64,
    started_at: Instant,
}

/// Settlement state is authoritative for custody, boundary admission, and claim replay.
pub(crate) struct Settlement {
    chain: SettlementChain<Sha256, Key>,
    now: u64,
    liveness_clock: Option<LivenessClock>,
    registered: Option<RegisteredEpoch>,
    deposits: BTreeMap<Digest, DepositEvent>,
    /// The claim roots of every finalized batch, about 100 bytes per epoch. Claims stay
    /// claimable indefinitely and claimants verify operator-served evidence against these
    /// roots, so unlike the bounded replay caches this record is never evicted.
    finalized_batches: BTreeMap<BatchId<Digest>, ClaimRoots>,
    /// The batch finalized for each epoch. Recipients anchor reconciliation by epoch, so
    /// like the claim roots this record is never evicted.
    finalized_epochs: BTreeMap<u64, BatchId<Digest>>,
    /// The registered payment anchor of each epoch. Recipients anchor intake by epoch, so
    /// this record is retained past registration and admission and is never evicted.
    epoch_anchors: BTreeMap<u64, Digest>,
    /// The admitted close of each epoch, retained past a proven challenge that clears the live
    /// registration so a recipient can still anchor reconciliation on it. Never evicted.
    admitted_epochs: BTreeMap<u64, (BatchId<Digest>, VectorRoot<Digest>)>,
    finalized_replays: ReplayCache<u64, FinalizedAdmission>,
    challenge_replays: ReplayCache<BatchId<Digest>, ProvenChallenge>,
    withdrawal_replays: BTreeMap<WithdrawalClaimKey, ClaimedWithdrawal>,
    payout_replays: BTreeMap<PayoutClaimKey, ClaimedPayout>,
    hard_fault_begin_replay: Option<HardFaultSettlement<Key, Digest>>,
    hard_fault_claim_replays: ReplayCache<HardFaultClaimKey, HardFaultClaim>,
    deposit_refund_replays: ReplayCache<Key, DepositRefund<Key>>,
}

/// The demo asset adapter admits any non-empty destination within the operator bound.
const fn eligible(destination: &Bytes) -> bool {
    !destination.is_empty() && destination.len() <= MAX_DESTINATION_BYTES
}

impl Settlement {
    pub(crate) fn new() -> Result<Self> {
        Self::with_config(settlement_config(), 0)
    }

    /// Opens a settlement whose first boundary epoch is `epoch`, for horizon tests.
    #[cfg(test)]
    pub(crate) fn at_epoch(epoch: u64) -> Result<Self> {
        Self::with_config(settlement_config(), epoch)
    }

    fn with_config(
        config: commonware_clearing::bajillion::settlement::SettlementConfig,
        epoch: u64,
    ) -> Result<Self> {
        let finalized_replays = config.max_pending_epochs;
        let challenge_replays = config.max_pending_epochs;
        let hard_fault_claim_replays =
            NonZeroUsize::new(MAX_ACCOUNTS).expect("terminal account bound is nonzero");
        let deposit_refund_replays = config.max_deposit_ids;
        let mut leaves = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let state = StateCache::new::<Sha256>(leaves).context("construct settlement genesis")?;
        let chain = SettlementChain::new(
            deployment(),
            operator_key(),
            committee()?,
            &state,
            epoch,
            config,
        )
        .context("construct settlement chain")?;
        Ok(Self {
            chain,
            now: 0,
            liveness_clock: None,
            registered: None,
            deposits: BTreeMap::new(),
            finalized_batches: BTreeMap::new(),
            finalized_epochs: BTreeMap::new(),
            epoch_anchors: BTreeMap::new(),
            admitted_epochs: BTreeMap::new(),
            finalized_replays: ReplayCache::new(finalized_replays),
            challenge_replays: ReplayCache::new(challenge_replays),
            withdrawal_replays: BTreeMap::new(),
            payout_replays: BTreeMap::new(),
            hard_fault_begin_replay: None,
            hard_fault_claim_replays: ReplayCache::new(hard_fault_claim_replays),
            deposit_refund_replays: ReplayCache::new(deposit_refund_replays),
        })
    }

    fn start_liveness_clock(&mut self) {
        if self.liveness_clock.is_none() {
            self.liveness_clock = Some(LivenessClock {
                logical_start: self.now,
                started_at: Instant::now(),
            });
        }
    }

    fn restart_liveness_clock(&mut self) {
        self.liveness_clock = Some(LivenessClock {
            logical_start: self.now,
            started_at: Instant::now(),
        });
    }

    const fn advance_to(&mut self, now: u64) -> bool {
        if self.liveness_clock.is_none() {
            return false;
        }
        if now <= self.now {
            return false;
        }
        self.now = now;
        true
    }

    fn finalize_admitted_if_ready(&mut self) -> Result<bool> {
        let Some(submission) = self
            .registered
            .as_ref()
            .and_then(|registered| registered.admitted.clone())
        else {
            return Ok(false);
        };
        let context = epoch_context(
            submission.epoch,
            &submission.deposits,
            &submission.withdrawals,
            submission.predecessor_liability,
        )?;
        if self.now <= context.challenge_deadline() {
            return Ok(false);
        }
        let finalized = self
            .chain
            .finalize(self.now)
            .context("finalize close on settlement")?;
        self.liveness_clock = None;
        self.registered = None;
        self.finalized_batches.insert(
            finalized.batch_id,
            ClaimRoots {
                withdrawal_outputs: submission.roots.withdrawal_outputs,
                change: submission.roots.change,
            },
        );
        self.finalized_epochs
            .insert(submission.epoch, finalized.batch_id);
        self.finalized_replays
            .insert(submission.epoch, (submission, finalized));
        Ok(true)
    }

    /// Returns the logical time a call arriving now observes: the running liveness
    /// clock's wall-clock reading, or the current time while no clock runs.
    ///
    /// Observation is split from application so the observed value can be recorded
    /// before it takes effect. Startup replay feeds the recorded value back through
    /// [`Self::observe_at`], which keeps fault timing bit-exact.
    pub(crate) fn observe_now(&self) -> u64 {
        let Some(clock) = &self.liveness_clock else {
            return self.now;
        };
        let ticks = clock.started_at.elapsed().as_secs() / LOGICAL_TICK.as_secs();
        self.now.max(clock.logical_start.saturating_add(ticks))
    }

    /// Applies one observed logical time. A call carrying `now` first observes every
    /// liveness deadline, which can finalize an admitted close or record a permanent
    /// fault before the call's own operation runs.
    pub(crate) fn observe_at(&mut self, now: u64) -> Result<()> {
        if !self.advance_to(now) {
            return Ok(());
        }
        if self.finalize_admitted_if_ready()? {
            return Ok(());
        }
        if self.chain.hard_fault().is_none()
            && let Err(error) = self.chain.fault_expired(self.now)
            && !matches!(error, SettlementError::DeadlineNotReached)
        {
            return Err(error).context("observe settlement liveness deadline");
        }
        if self.chain.hard_fault().is_some()
            && !self
                .registered
                .as_ref()
                .is_some_and(|registered| registered.admitted.is_some())
        {
            self.registered = None;
            self.liveness_clock = None;
        }
        Ok(())
    }

    /// Re-anchors the liveness clock after startup replay. Logical time advances only
    /// while the process serves, so downtime never counts against a liveness deadline.
    pub(crate) fn resume(&mut self) {
        if self.liveness_clock.is_some() {
            self.restart_liveness_clock();
        }
    }

    pub(crate) const fn now(&self) -> u64 {
        self.now
    }

    #[cfg(test)]
    pub(crate) fn advance_logical_time(&mut self, ticks: u64) -> Result<()> {
        let Some(target) = self
            .liveness_clock
            .as_ref()
            .map(|clock| clock.logical_start.saturating_add(ticks))
        else {
            return Ok(());
        };
        self.observe_at(target)
    }

    /// Observed target `ticks` past the current time, or `None` while no liveness
    /// clock runs. Relative to the current time rather than the clock anchor because
    /// reopening a store re-anchors the clock.
    #[cfg(test)]
    pub(crate) fn tick_target(&self, ticks: u64) -> Option<u64> {
        self.liveness_clock
            .as_ref()
            .map(|_| self.now.saturating_add(ticks))
    }

    pub(crate) fn status(&mut self) -> Result<SettlementStatus> {
        // The root and the finality horizon come from the chain's one coherent fact, so
        // the pair served to wallets can never desync.
        Ok(SettlementStatus {
            now: self.now,
            deployment: deployment(),
            state_root: self.chain.current_state_root(),
            last_finalized: self.chain.expected_epoch().checked_sub(1),
            custody_balance: self.chain.custody_balance(),
            claimable_balance: self.chain.claimable_balance(),
            hard_faulted: self.chain.hard_fault().is_some(),
        })
    }

    /// Returns the claim roots of a finalized batch, or `None` while it is unknown.
    ///
    /// An unknown batch is an availability signal, never a verdict: the batch may simply
    /// not have finalized yet.
    pub(crate) fn claim_roots(&mut self, batch_id: BatchId<Digest>) -> Result<Option<ClaimRoots>> {
        Ok(self.finalized_batches.get(&batch_id).copied())
    }

    /// Returns what settlement holds for one epoch: its registered payment anchor, and the
    /// admitted close's identity and roots once a close is admitted.
    ///
    /// `None` means the epoch was never registered, an availability signal, never a verdict.
    /// This read anchors both intake and reconciliation, so it serves only settlement's own
    /// registration and admission record and never an operator claim.
    pub(crate) fn epoch_roots(&mut self, epoch: u64) -> Result<Option<EpochRoots>> {
        let Some(anchor) = self.epoch_anchors.get(&epoch).copied() else {
            return Ok(None);
        };

        // The admitted record is retained by epoch, so it survives both finalization and a
        // proven challenge that clears the live registration. Finalization is read separately.
        let admitted = self
            .admitted_epochs
            .get(&epoch)
            .map(|(batch_id, change)| AdmittedRoots {
                batch_id: *batch_id,
                change: *change,
                finalized: self.finalized_epochs.contains_key(&epoch),
            });
        Ok(Some(EpochRoots { anchor, admitted }))
    }

    pub(crate) fn deposit(&mut self, event: DepositEvent) -> Result<()> {
        ensure!(
            identities()
                .iter()
                .any(|identity| identity.key == event.account),
            "deposit account is not a configured terminal agent"
        );
        if let Some(existing) = self.deposits.get(&event.id) {
            ensure!(
                existing.account == event.account && existing.amount == event.amount,
                "deposit id was reused for another event"
            );
            return Ok(());
        }
        ensure!(
            self.registered.is_none(),
            "the next settlement epoch is already registered"
        );
        ensure_balance_intake_horizon(self.next_boundary_epoch())?;

        // The example operator persists monetary values in SQLite INTEGER columns. Apply that
        // deployment-wide domain before settlement takes custody so operator credit cannot fail.
        let holdings = self
            .chain
            .custody_balance()
            .checked_add(self.chain.claimable_balance())
            .and_then(|balance| balance.checked_add(event.amount))
            .context("settlement holdings overflow")?;
        ensure!(
            holdings <= SQLITE_U64_MAX,
            "deposit exceeds the operator storage domain"
        );
        self.chain
            .record_deposit(self.now, event.id, event.account.clone(), event.amount)
            .context("record custody deposit")?;
        self.deposits.insert(event.id, event);
        self.start_liveness_clock();
        Ok(())
    }

    pub(crate) fn confirm_deposit(&mut self, event: &DepositEvent) -> Result<DepositPresence> {
        ensure!(
            self.chain.hard_fault().is_none(),
            "settlement deployment is permanently hard-faulted"
        );
        let Some(existing) = self.deposits.get(&event.id) else {
            return Ok(DepositPresence::Unknown);
        };
        ensure!(
            existing.account == event.account && existing.amount == event.amount,
            "deposit id was recorded for another event"
        );
        Ok(DepositPresence::Recorded)
    }

    /// Confirms one payment context is the live registration.
    ///
    /// Only the live submit path needs this gate. A send resolved after its epoch was cut
    /// concludes commitment from a finalized state root instead, which is post-registration
    /// by definition, so no finalized history is served here.
    pub(crate) fn confirm_registration(
        &mut self,
        epoch: u64,
        anchor: &Digest,
        state_root: &VectorRoot<Digest>,
    ) -> Result<()> {
        ensure!(
            self.chain.hard_fault().is_none(),
            "payment registration is no longer live"
        );
        let registered = self
            .registered
            .as_ref()
            .filter(|registered| registered.epoch == epoch)
            .context("payment registration is no longer live")?;
        ensure!(
            registered.anchor == *anchor && self.chain.current_state_root() == *state_root,
            "payment registration does not match"
        );
        Ok(())
    }

    pub(crate) fn queue_withdrawal(
        &mut self,
        request: SignedWithdrawal<Key, Digest>,
        openings: Vec<StateOpening<Key, Digest>>,
    ) -> Result<()> {
        let pending = self.chain.pending_withdrawals();
        if let Some(existing) = pending.request_for(request.account()) {
            ensure!(
                existing == &request,
                "account already queued another withdrawal"
            );
            return Ok(());
        }
        ensure!(
            self.registered.is_none(),
            "the next settlement epoch is already registered"
        );
        let epoch = self.next_boundary_epoch();
        match request.body().action() {
            WithdrawalAction::Amount(_) => ensure_amount_withdrawal_horizon(epoch)?,
            WithdrawalAction::Close => ensure_close_horizon(epoch)?,
        }
        self.chain
            .queue_withdrawal(self.now, request, &openings, eligible)
            .context("queue settlement withdrawal")?;
        self.start_liveness_clock();
        Ok(())
    }

    pub(crate) fn register_epoch(
        &mut self,
        epoch: u64,
        predecessor_liability: u64,
        deposits_root: VectorRoot<Digest>,
        staged_root: VectorRoot<Digest>,
        withdrawals: WithdrawalBatch<Key, Digest>,
        openings: &[StateOpening<Key, Digest>],
    ) -> Result<()> {
        if let Some(existing) = self
            .registered
            .as_ref()
            .filter(|entry| entry.epoch == epoch)
        {
            let registered_root = existing
                .deposits
                .root::<Sha256>()
                .context("commit registered deposit boundary")?;
            ensure!(
                existing.predecessor_liability == predecessor_liability
                    && registered_root == deposits_root
                    && existing.staged_root == staged_root
                    && existing.withdrawals == withdrawals,
                "epoch registration changed after it was accepted"
            );
            return Ok(());
        }
        let expected = self.next_boundary_epoch();
        ensure!(
            epoch == expected,
            "settlement boundary epoch is not consecutive"
        );
        openable_epoch_after(epoch)?;
        ensure!(
            self.registered.is_none(),
            "another payment context is already registered"
        );

        // The full staged view must agree before the boundary is derived: a deferral
        // hides its account from both derived boundaries, so root equality alone cannot
        // see a deposit the operator never credited.
        let staged = self.chain.boundary_deposits(&WithdrawalBatch::empty());
        ensure!(
            staged
                .root::<Sha256>()
                .context("commit staged deposit view")?
                == staged_root,
            "operator staged deposits differ from settlement"
        );

        // The canonical boundary is settlement's own custody record with the chain's
        // deferral rule applied: a carried extra that exactly offsets a staged deposit
        // defers that deposit to a successor epoch. The operator commits the root of the
        // boundary it built its context from, so a diverging deposit view (for example, a
        // lost operator credit) is rejected here without consuming the registration slot,
        // instead of registering an epoch that could never be admitted.
        let deposits = self.chain.boundary_deposits(&withdrawals);
        let derived_root = deposits
            .root::<Sha256>()
            .context("commit derived deposit boundary")?;
        ensure!(
            derived_root == deposits_root,
            "operator deposit boundary differs from settlement"
        );

        // The submitted batch may carry operator-collected requests beyond the queued set,
        // but every queued request must still appear verbatim.
        let pending = self.chain.pending_withdrawals();
        for queued in pending.requests() {
            ensure!(
                withdrawals.request_for(queued.account()) == Some(queued),
                "operator withdrawal boundary omits a queued settlement withdrawal"
            );
        }

        // A registration is an immutable admission obligation, so the chain proves every
        // carried extra certifiable with one predecessor-root opening in batch order.
        let extra_openings = withdrawals
            .requests()
            .iter()
            .filter(|request| pending.request_for(request.account()).is_none())
            .map(|request| {
                openings
                    .iter()
                    .find(|opening| &opening.leaf.account == request.account())
                    .cloned()
                    .context("registration is missing an opening for a carried withdrawal")
            })
            .collect::<Result<Vec<_>>>()?;
        let context = epoch_context(epoch, &deposits, &withdrawals, predecessor_liability)?;
        let anchor = *context.payment().anchor();
        self.chain
            .register_epoch(
                self.now,
                context,
                withdrawals.clone(),
                &extra_openings,
                eligible,
            )
            .context("register exact payment context")?;
        self.registered = Some(RegisteredEpoch {
            epoch,
            predecessor_liability,
            anchor,
            deposits,
            staged_root,
            withdrawals,
            admitted: None,
        });
        self.epoch_anchors.insert(epoch, anchor);
        self.start_liveness_clock();
        Ok(())
    }

    const fn next_boundary_epoch(&self) -> u64 {
        self.chain.expected_epoch()
    }

    pub(crate) fn admit_submission(
        &mut self,
        submission: SettlementSubmission,
    ) -> Result<AdmissionOutcome> {
        if let Some((existing, finalized)) = self.finalized_replays.get(&submission.epoch) {
            ensure!(
                existing == &submission,
                "another close already finalized for this epoch"
            );
            return Ok(AdmissionOutcome::Finalized(*finalized));
        }
        ensure!(
            submission.epoch >= self.chain.expected_epoch(),
            "settlement admission replay expired"
        );
        let boundary = self
            .registered
            .as_ref()
            .context("settlement epoch was not registered")?;
        ensure!(
            boundary.epoch == submission.epoch
                && boundary.predecessor_liability == submission.predecessor_liability
                && boundary.deposits == submission.deposits
                && boundary.withdrawals == submission.withdrawals,
            "close does not match the registered settlement epoch"
        );
        let context = epoch_context(
            submission.epoch,
            &submission.deposits,
            &submission.withdrawals,
            submission.predecessor_liability,
        )?;
        let challenge_deadline = context.challenge_deadline();
        if let Some(admitted) = &boundary.admitted {
            ensure!(
                admitted == &submission,
                "another certified close is already pending finalization"
            );
        } else {
            let can_fast_forward = submission
                .withdrawals
                .requests()
                .iter()
                .all(|request| request.body().deadline() > challenge_deadline);
            self.chain
                .admit(
                    self.now,
                    submission.header,
                    submission.roots,
                    submission.terminal_proof.clone(),
                    submission.certificate.clone(),
                )
                .context("admit certified close on settlement")?;
            // Retain the admitted close by epoch so a recipient can still anchor on it after a
            // proven challenge clears the live registration. This lets a wallet that crashed
            // between a proven verdict and recording it re-mark from the idempotent resubmission.
            self.admitted_epochs.insert(
                submission.epoch,
                (
                    submission.header.batch_id::<Sha256>(),
                    submission.roots.change,
                ),
            );
            self.registered
                .as_mut()
                .expect("the registered epoch was checked above")
                .admitted = Some(submission);
            if can_fast_forward {
                self.now = challenge_deadline;
                self.restart_liveness_clock();
            }
            return Ok(AdmissionOutcome::Pending);
        }
        if self.now <= challenge_deadline {
            return Ok(AdmissionOutcome::Pending);
        }
        anyhow::bail!("admitted close was not finalized after its challenge deadline")
    }

    #[cfg(test)]
    pub(crate) fn admit(
        &mut self,
        submission: SettlementSubmission,
    ) -> Result<FinalizedBatch<Digest>> {
        let retry = submission.clone();
        match self.admit_submission(submission)? {
            AdmissionOutcome::Finalized(finalized) => Ok(finalized),
            AdmissionOutcome::Pending => {
                self.advance_logical_time(1)?;
                match self.admit_submission(retry)? {
                    AdmissionOutcome::Finalized(finalized) => Ok(finalized),
                    AdmissionOutcome::Pending => anyhow::bail!("test admission remained pending"),
                }
            }
        }
    }

    pub(crate) fn challenge_encoded(
        &mut self,
        batch_id: BatchId<Digest>,
        encoded: Bytes,
        maximum_bytes: usize,
    ) -> Result<Verdict> {
        if let Some((existing, verdict)) = self.challenge_replays.get(&batch_id) {
            ensure!(
                existing == &encoded,
                "challenge evidence changed after it was proven"
            );
            return Ok(*verdict);
        }
        let verdict = self
            .chain
            .challenge_encoded(self.now, batch_id, &encoded, maximum_bytes)
            .context("adjudicate encoded challenge")?;
        if matches!(verdict, Verdict::Proven(_)) {
            self.challenge_replays.insert(batch_id, (encoded, verdict));
            self.registered = None;
            self.liveness_clock = None;
        }
        Ok(verdict)
    }

    pub(crate) fn begin_hard_fault_settlement(
        &mut self,
    ) -> Result<HardFaultSettlement<Key, Digest>> {
        if let Some(settlement) = &self.hard_fault_begin_replay {
            return Ok(settlement.clone());
        }
        let settlement = self
            .chain
            .begin_hard_fault_settlement()
            .context("begin terminal hard-fault settlement")?;
        self.hard_fault_begin_replay = Some(settlement.clone());
        Ok(settlement)
    }

    pub(crate) fn claim_hard_fault(
        &mut self,
        opening: &StateOpening<Key, Digest>,
    ) -> Result<HardFaultRelease<Key>> {
        let frozen_state_root = self
            .hard_fault_begin_replay
            .as_ref()
            .context("terminal hard-fault settlement has not begun")?
            .frozen_state_root;
        let key = (frozen_state_root.digest, opening.proof.position);
        if let Some((existing, release)) = self.hard_fault_claim_replays.get(&key) {
            ensure!(
                existing == opening,
                "terminal state claim position was reused"
            );
            return Ok(release.clone());
        }
        let release = self
            .chain
            .claim_hard_fault(opening)
            .context("claim terminal hard-fault state")?;
        self.hard_fault_claim_replays
            .insert(key, (opening.clone(), release.clone()));
        Ok(release)
    }

    pub(crate) fn claim_pending_deposit(&mut self, account: &Key) -> Result<DepositRefund<Key>> {
        if let Some(refund) = self.deposit_refund_replays.get(account) {
            return Ok(refund.clone());
        }
        let refund = self
            .chain
            .claim_pending_deposit(self.now, account)
            .context("claim terminal pending deposit")?;
        self.deposit_refund_replays
            .insert(account.clone(), refund.clone());
        Ok(refund)
    }

    pub(crate) fn claim_withdrawal(
        &mut self,
        batch_id: BatchId<Digest>,
        claim: &WithdrawalClaim<Digest>,
    ) -> Result<ClaimOutcome<WithdrawalOutput>> {
        let key = (batch_id, claim.position());
        if let Some((existing, release)) = self.withdrawal_replays.get(&key) {
            if existing == claim {
                return Ok(ClaimOutcome::Released(release.clone()));
            }

            // The recorded release consumed this position with different evidence, so this
            // exact claim can never succeed.
            return Ok(ClaimOutcome::Invalid);
        }
        let release = match self.chain.claim_withdrawal(batch_id, claim) {
            Ok(release) => release,
            Err(error) => return Ok(claim_rejection(error)),
        };
        self.withdrawal_replays
            .insert(key, (claim.clone(), release.clone()));
        Ok(ClaimOutcome::Released(release))
    }

    pub(crate) fn claim_external_payout(
        &mut self,
        batch_id: BatchId<Digest>,
        claim: &ExternalPayoutClaim<Key, Digest>,
    ) -> Result<ClaimOutcome<ExternalPayout<Key>>> {
        let key = (batch_id, claim.position());
        if let Some((existing, payout)) = self.payout_replays.get(&key) {
            if existing == claim {
                return Ok(ClaimOutcome::Released(payout.clone()));
            }

            // The recorded release consumed this position with different evidence, so this
            // exact claim can never succeed.
            return Ok(ClaimOutcome::Invalid);
        }
        let payout = match self.chain.claim_external_payout(batch_id, claim) {
            Ok(payout) => payout,
            Err(error) => return Ok(claim_rejection(error)),
        };
        self.payout_replays
            .insert(key, (claim.clone(), payout.clone()));
        Ok(ClaimOutcome::Released(payout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Protocol, wallets};
    use bytes::Bytes;
    use commonware_clearing::bajillion::{
        boundary::DepositRecord,
        challenge::{Challenge, ChallengeKind},
        credit::ShardSet,
        payment::{Payment, SignedReceipt, SignedSend},
        settlement::HardFaultReason,
        state::{AccountRow, Prefix, SettlementOutput},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_utils::TestRng;
    use std::num::NonZeroU64;

    fn empty_root() -> VectorRoot<Digest> {
        DepositBatch::<Key>::empty().root::<Sha256>().unwrap()
    }

    fn admission_fixture() -> (
        Settlement,
        SettlementSubmission,
        SettlementResult,
        StateCache<Key, Digest>,
        Protocol,
        DepositEvent,
    ) {
        let mut settlement = Settlement::new().unwrap();
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let mut predecessor = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        predecessor.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let state = StateCache::new::<Sha256>(predecessor.clone()).unwrap();
        let account = predecessor[0].account.clone();
        let deposit = DepositEvent {
            id: Sha256::hash(&[b"admission-fixture-deposit"]),
            account: account.clone(),
            amount: 1,
        };
        settlement.deposit(deposit.clone()).unwrap();
        let deposits =
            DepositBatch::new(vec![DepositRecord::new(account.clone(), 1).unwrap()]).unwrap();
        settlement
            .register_epoch(
                0,
                400,
                deposits.root::<Sha256>().unwrap(),
                deposits.root::<Sha256>().unwrap(),
                WithdrawalBatch::empty(),
                &[],
            )
            .unwrap();

        let predecessor_state = predecessor[0].state;
        let successor_state = AccountState {
            balance: predecessor_state.balance + 1,
            ..predecessor_state
        };
        let row = AccountRow {
            account: account.clone(),
            predecessor: predecessor_state,
            successor: successor_state,
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix {
                deposit: 1,
                ..Prefix::default()
            },
        };
        let mut successor = predecessor;
        successor[0].state = successor_state;
        let registration = protocol
            .registration(0, deposits, WithdrawalBatch::empty(), 400)
            .unwrap();
        let prepared = protocol
            .prepare(
                registration,
                vec![deposit.clone()],
                state.leaves().to_vec(),
                vec![row],
                vec![ShardSet::empty(0, account)],
                successor,
            )
            .unwrap();
        let result = protocol.complete(prepared, &mut TestRng::new(91)).unwrap();
        let submission = SettlementSubmission::from(&result);
        (settlement, submission, result, state, protocol, deposit)
    }

    fn receipt_fork(result: &SettlementResult, protocol: &Protocol) -> Challenge<Key, Digest> {
        let wallets = wallets();
        let recipient = wallets[2].public_key();
        let payment = |payer: usize, amount| {
            let send = SignedSend::sign_next(
                &result.payment_context,
                wallets[payer].signer(),
                recipient.clone(),
                amount,
                0,
            )
            .unwrap();
            let receipt = SignedReceipt::issue_next::<Sha256, _>(
                &result.payment_context,
                &send,
                &recipient,
                0,
                0,
                0,
                protocol.operator(),
            )
            .unwrap();
            Payment::new::<Sha256>(&result.payment_context, send, receipt).unwrap()
        };
        Challenge::receipt_fork(&payment(0, 2), &payment(1, 3))
    }

    #[test]
    fn replay_cache_evicts_only_its_oldest_acknowledgement() {
        let mut cache = ReplayCache::new(NonZeroUsize::new(2).unwrap());
        cache.insert(1, "one");
        cache.insert(2, "two");
        cache.insert(3, "three");

        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&"two"));
        assert_eq!(cache.get(&3), Some(&"three"));
    }

    #[test]
    fn admission_stays_pending_through_the_inclusive_deadline() {
        let (mut settlement, submission, result, _, _, _) = admission_fixture();
        let challenge_deadline = result.epoch_context.challenge_deadline();

        assert_eq!(
            settlement.admit_submission(submission.clone()).unwrap(),
            AdmissionOutcome::Pending
        );
        assert_eq!(settlement.status().unwrap().now, challenge_deadline);
        assert_eq!(
            settlement.admit_submission(submission.clone()).unwrap(),
            AdmissionOutcome::Pending
        );

        settlement.advance_logical_time(1).unwrap();
        let finalized = match settlement.admit_submission(submission.clone()).unwrap() {
            AdmissionOutcome::Pending => panic!("admission remained pending after its deadline"),
            AdmissionOutcome::Finalized(finalized) => finalized,
        };
        assert_eq!(finalized.batch_id, result.finalized.batch_id);
        assert_eq!(
            settlement.admit_submission(submission.clone()).unwrap(),
            AdmissionOutcome::Finalized(finalized)
        );

        // Finalization retains the batch's claim roots forever, keyed by its identity.
        assert_eq!(
            settlement.claim_roots(finalized.batch_id).unwrap(),
            Some(ClaimRoots {
                withdrawal_outputs: result.roots.withdrawal_outputs,
                change: result.roots.change,
            })
        );
        assert_eq!(
            settlement
                .claim_roots(BatchId::new(Sha256::hash(&[b"unknown-claim-batch"])))
                .unwrap(),
            None
        );

        let mut conflicting = submission;
        conflicting.predecessor_liability -= 1;
        assert!(settlement.admit_submission(conflicting).is_err());
    }

    #[test]
    fn admitted_close_finalizes_after_its_deadline_without_operator_retry() {
        let (mut settlement, submission, result, _, _, _) = admission_fixture();

        assert_eq!(
            settlement.admit_submission(submission.clone()).unwrap(),
            AdmissionOutcome::Pending
        );
        settlement.advance_logical_time(1).unwrap();

        let status = settlement.status().unwrap();
        assert_eq!(status.state_root, result.finalized.successor_root);
        assert_eq!(
            settlement.admit_submission(submission).unwrap(),
            AdmissionOutcome::Finalized(result.finalized)
        );
    }

    #[test]
    fn proven_challenge_replays_only_for_exact_evidence_while_pending() {
        let (mut settlement, submission, result, _, protocol, _) = admission_fixture();
        let batch_id = result.finalized.batch_id;
        assert_eq!(
            settlement.admit_submission(submission).unwrap(),
            AdmissionOutcome::Pending
        );
        let evidence = receipt_fork(&result, &protocol).encode();

        let verdict = settlement
            .challenge_encoded(batch_id, evidence.clone(), evidence.len())
            .unwrap();
        assert_eq!(verdict, Verdict::Proven(ChallengeKind::ReceiptFork));
        assert_eq!(
            settlement
                .challenge_encoded(batch_id, evidence.clone(), evidence.len())
                .unwrap(),
            verdict
        );
        let mut conflicting = evidence.to_vec();
        conflicting.push(0);
        assert!(
            settlement
                .challenge_encoded(batch_id, Bytes::from(conflicting), evidence.len() + 1)
                .is_err()
        );
        assert!(settlement.status().unwrap().hard_faulted);
    }

    #[test]
    fn hard_fault_begin_claim_and_refund_replay_after_full_settlement() {
        let (mut settlement, submission, result, state, protocol, deposit) = admission_fixture();
        let batch_id = result.finalized.batch_id;
        assert_eq!(
            settlement.admit_submission(submission).unwrap(),
            AdmissionOutcome::Pending
        );
        let evidence = receipt_fork(&result, &protocol).encode();
        assert!(matches!(
            settlement
                .challenge_encoded(batch_id, evidence.clone(), evidence.len())
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        ));

        let snapshot = settlement.begin_hard_fault_settlement().unwrap();
        assert_eq!(snapshot.state_liability, 400);
        assert_eq!(snapshot.unfinalized_deposit_total, 1);
        assert_eq!(settlement.begin_hard_fault_settlement().unwrap(), snapshot);

        let openings = state
            .leaves()
            .iter()
            .map(|leaf| state.opening(&leaf.account).unwrap())
            .collect::<Vec<_>>();
        let first = settlement.claim_hard_fault(&openings[0]).unwrap();
        assert_eq!(first.released_custody, INITIAL_BALANCE);
        assert_eq!(settlement.claim_hard_fault(&openings[0]).unwrap(), first);
        let mut conflicting = openings[0].clone();
        conflicting.leaf.state.balance -= 1;
        assert!(settlement.claim_hard_fault(&conflicting).is_err());
        for opening in &openings[1..] {
            settlement.claim_hard_fault(opening).unwrap();
        }

        let refund = settlement.claim_pending_deposit(&deposit.account).unwrap();
        assert_eq!(refund.amount, deposit.amount);
        assert_eq!(settlement.status().unwrap().custody_balance, 0);
        assert_eq!(
            settlement
                .challenge_encoded(batch_id, evidence.clone(), evidence.len())
                .unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );
        assert_eq!(settlement.begin_hard_fault_settlement().unwrap(), snapshot);
        assert_eq!(settlement.claim_hard_fault(&openings[0]).unwrap(), first);
        assert_eq!(
            settlement.claim_pending_deposit(&deposit.account).unwrap(),
            refund
        );
    }

    #[test]
    fn deposit_ids_are_idempotent_but_bound_to_one_event() {
        let mut settlement = Settlement::new().unwrap();
        let account = identities()[0].key.clone();
        let event = DepositEvent {
            id: Sha256::hash(&[b"deposit-id"]),
            account,
            amount: 7,
        };
        settlement.deposit(event.clone()).unwrap();
        settlement.deposit(event.clone()).unwrap();
        assert_eq!(
            settlement.confirm_deposit(&event).unwrap(),
            DepositPresence::Recorded
        );

        let conflicting = DepositEvent { amount: 8, ..event };
        assert!(settlement.deposit(conflicting.clone()).is_err());
        assert!(settlement.confirm_deposit(&conflicting).is_err());
        assert_eq!(settlement.status().unwrap().custody_balance, 407);
    }

    #[test]
    fn deposit_rejects_values_outside_the_operator_storage_domain() {
        let mut settlement = Settlement::new().unwrap();
        let before = settlement.status().unwrap();
        let event = DepositEvent {
            id: Sha256::hash(&[b"oversized-deposit"]),
            account: identities()[0].key.clone(),
            amount: i64::MAX as u64,
        };

        assert!(settlement.deposit(event.clone()).is_err());
        assert_eq!(
            settlement.confirm_deposit(&event).unwrap(),
            DepositPresence::Unknown
        );
        assert_eq!(
            settlement.status().unwrap().custody_balance,
            before.custody_balance
        );
    }

    #[test]
    fn epoch_registration_is_idempotent_and_rejects_late_custody_events() {
        let mut settlement = Settlement::new().unwrap();
        settlement
            .register_epoch(
                0,
                400,
                empty_root(),
                empty_root(),
                WithdrawalBatch::empty(),
                &[],
            )
            .unwrap();
        settlement
            .register_epoch(
                0,
                400,
                empty_root(),
                empty_root(),
                WithdrawalBatch::empty(),
                &[],
            )
            .unwrap();
        let event = DepositEvent {
            id: Sha256::hash(&[b"late-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };
        assert!(settlement.deposit(event).is_err());
    }

    #[test]
    fn epoch_registration_activates_its_exact_payment_anchor() {
        let mut settlement = Settlement::new().unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = epoch_context(0, &deposits, &withdrawals, 400).unwrap();
        let anchor = *context.payment().anchor();
        let admission_deadline = context.admission_deadline();

        settlement
            .register_epoch(0, 400, empty_root(), empty_root(), withdrawals, &[])
            .unwrap();

        assert_eq!(
            settlement
                .chain
                .fault_expired(admission_deadline + 1)
                .unwrap(),
            HardFaultReason::ExpiredRegistration {
                anchor,
                epoch: 0,
                expired_at: admission_deadline,
            }
        );
    }

    #[test]
    fn registration_query_is_exact_retryable_and_rejects_fault() {
        let mut settlement = Settlement::new().unwrap();
        let predecessor_state_root = settlement.status().unwrap().state_root;
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = epoch_context(0, &deposits, &withdrawals, 400).unwrap();
        let anchor = *context.payment().anchor();

        assert!(
            settlement
                .confirm_registration(0, &anchor, &predecessor_state_root)
                .is_err()
        );
        settlement
            .register_epoch(0, 400, empty_root(), empty_root(), withdrawals, &[])
            .unwrap();
        for _ in 0..2 {
            settlement
                .confirm_registration(0, &anchor, &predecessor_state_root)
                .unwrap();
        }
        assert!(
            settlement
                .confirm_registration(1, &anchor, &predecessor_state_root)
                .is_err()
        );
        assert!(
            settlement
                .confirm_registration(
                    0,
                    &Sha256::hash(&[b"another-payment-anchor"]),
                    &predecessor_state_root,
                )
                .is_err()
        );
        assert!(
            settlement
                .confirm_registration(
                    0,
                    &anchor,
                    &VectorRoot {
                        digest: Sha256::hash(&[b"another-predecessor-state-root"]),
                    },
                )
                .is_err()
        );

        settlement
            .advance_logical_time(context.admission_deadline() + 1)
            .unwrap();
        assert!(settlement.status().unwrap().hard_faulted);
        assert!(
            settlement
                .confirm_registration(0, &anchor, &predecessor_state_root)
                .is_err()
        );
    }

    #[test]
    fn registration_query_is_live_through_admission_only() {
        let (mut settlement, submission, result, _, _, _) = admission_fixture();
        let epoch = result.payment_context.epoch();
        let anchor = *result.payment_context.anchor();

        settlement
            .confirm_registration(epoch, &anchor, &result.predecessor_root)
            .unwrap();
        assert_eq!(
            settlement.admit_submission(submission).unwrap(),
            AdmissionOutcome::Pending
        );
        settlement
            .confirm_registration(epoch, &anchor, &result.predecessor_root)
            .unwrap();

        // Finalization retires the live slot. A send resolved after the cut concludes
        // commitment from the finalized root instead of this query.
        settlement.advance_logical_time(1).unwrap();
        assert!(settlement.registered.is_none());
        assert!(
            settlement
                .confirm_registration(epoch, &anchor, &result.predecessor_root)
                .is_err()
        );
        assert_eq!(settlement.status().unwrap().last_finalized, Some(epoch));
    }

    #[test]
    fn idle_open_slot_has_no_logical_clock_obligation() {
        let mut settlement = Settlement::new().unwrap();

        settlement.advance_logical_time(u64::MAX).unwrap();

        let status = settlement.status().unwrap();
        assert_eq!(status.now, 0);
        assert!(!status.hard_faulted);
    }

    #[test]
    fn delayed_registration_remains_available_while_deposit_is_live() {
        let mut settlement = Settlement::new().unwrap();
        settlement
            .deposit(DepositEvent {
                id: Sha256::hash(&[b"delayed-registration-deposit"]),
                account: identities()[0].key.clone(),
                amount: 7,
            })
            .unwrap();

        settlement.advance_logical_time(2).unwrap();
        let status = settlement.status().unwrap();
        assert_eq!(status.now, 2);
        assert!(!status.hard_faulted);

        let deposits_root = settlement
            .chain
            .pending_deposits()
            .root::<Sha256>()
            .unwrap();
        settlement
            .register_epoch(
                0,
                400,
                deposits_root,
                deposits_root,
                WithdrawalBatch::empty(),
                &[],
            )
            .unwrap();
        assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);
    }

    #[test]
    fn delayed_registration_remains_available_while_withdrawal_is_live() {
        let mut settlement = Settlement::new().unwrap();
        let wallet = crate::protocol::wallets().remove(0);
        let mut leaves = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let account = wallet.public_key();
        let request = SignedWithdrawal::sign(
            deployment(),
            cache.root().digest,
            Bytes::from_static(b"delayed-withdrawal"),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            50,
            wallet.signer(),
        );
        let opening = cache.opening(&account).unwrap();
        settlement.queue_withdrawal(request, vec![opening]).unwrap();

        settlement.advance_logical_time(2).unwrap();
        let status = settlement.status().unwrap();
        assert_eq!(status.now, 2);
        assert!(!status.hard_faulted);

        let withdrawals = settlement.chain.pending_withdrawals();
        settlement
            .register_epoch(0, 400, empty_root(), empty_root(), withdrawals, &[])
            .unwrap();
        assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);
    }

    #[test]
    fn divergent_deposit_boundary_is_rejected_without_consuming_the_slot() {
        let mut settlement = Settlement::new().unwrap();
        let event = DepositEvent {
            id: Sha256::hash(&[b"lost-apply-window-deposit"]),
            account: identities()[0].key.clone(),
            amount: 7,
        };
        settlement.deposit(event).unwrap();

        // An operator whose credit was lost still believes the boundary is empty. The
        // divergent commitment fails cleanly and keeps the slot open.
        let error = settlement
            .register_epoch(
                0,
                400,
                empty_root(),
                empty_root(),
                WithdrawalBatch::empty(),
                &[],
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("operator staged deposits differ from settlement"),
            "unexpected error: {error:#}"
        );
        assert!(settlement.registered.is_none());

        // After the operator applies the deposit, its healed view registers the epoch.
        let deposits_root = settlement
            .chain
            .pending_deposits()
            .root::<Sha256>()
            .unwrap();
        settlement
            .register_epoch(
                0,
                400,
                deposits_root,
                deposits_root,
                WithdrawalBatch::empty(),
                &[],
            )
            .unwrap();
        assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);
    }

    #[test]
    fn carried_offset_withdrawal_defers_the_staged_deposit_and_registers() {
        let mut settlement = Settlement::new().unwrap();
        let signers = wallets();
        let account = signers[0].public_key();
        settlement
            .deposit(DepositEvent {
                id: Sha256::hash(&[b"carried-offset-deposit"]),
                account: account.clone(),
                amount: 7,
            })
            .unwrap();

        let mut leaves = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();

        // A carried extra exactly offsetting the staged deposit reaches the chain at
        // registration. The chain defers the deposit to a successor epoch, and the
        // boundary this epoch registers is empty.
        let carried = SignedWithdrawal::sign(
            deployment(),
            cache.root().digest,
            Bytes::from_static(b"carried-offset-withdrawal"),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            50,
            signers[0].signer(),
        );
        let withdrawals = WithdrawalBatch::new(vec![carried]).unwrap();
        assert_eq!(
            settlement
                .chain
                .boundary_deposits(&withdrawals)
                .root::<Sha256>()
                .unwrap(),
            empty_root()
        );
        let staged_root = settlement
            .chain
            .boundary_deposits(&WithdrawalBatch::empty())
            .root::<Sha256>()
            .unwrap();
        settlement
            .register_epoch(
                0,
                400,
                empty_root(),
                staged_root,
                withdrawals,
                &[cache.opening(&account).unwrap()],
            )
            .unwrap();
        assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);
        assert_eq!(settlement.chain.pending_deposits().amount_for(&account), 7);
    }

    #[test]
    fn register_epoch_carries_extras_but_requires_every_queued_withdrawal() {
        let mut settlement = Settlement::new().unwrap();
        let signers = wallets();
        let mut leaves = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let queued_account = signers[0].public_key();
        let queued = SignedWithdrawal::sign(
            deployment(),
            cache.root().digest,
            Bytes::from_static(b"queued-withdrawal"),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            50,
            signers[0].signer(),
        );
        let opening = cache.opening(&queued_account).unwrap();
        settlement
            .queue_withdrawal(queued.clone(), vec![opening])
            .unwrap();

        let error = settlement
            .register_epoch(
                0,
                400,
                empty_root(),
                empty_root(),
                WithdrawalBatch::empty(),
                &[],
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("omits a queued settlement withdrawal"),
            "unexpected error: {error:#}"
        );

        let carried_account = signers[1].public_key();
        let carried = SignedWithdrawal::sign(
            deployment(),
            cache.root().digest,
            Bytes::from_static(b"carried-withdrawal"),
            WithdrawalAction::Amount(NonZeroU64::new(9).unwrap()),
            50,
            signers[1].signer(),
        );
        let withdrawals = WithdrawalBatch::new(vec![queued.clone(), carried]).unwrap();

        // The carried extra registers only with a predecessor-root opening proving it
        // certifiable. The queued request needs none.
        let error = settlement
            .register_epoch(0, 400, empty_root(), empty_root(), withdrawals.clone(), &[])
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("missing an opening"),
            "unexpected error: {error:#}"
        );
        settlement
            .register_epoch(
                0,
                400,
                empty_root(),
                empty_root(),
                withdrawals,
                &[cache.opening(&carried_account).unwrap()],
            )
            .unwrap();
        assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);

        // Only the queued request occupies the chain's pending set. The carried extra was
        // admitted at registration and never touches the queue.
        let pending = settlement.chain.pending_withdrawals();
        assert_eq!(pending.requests(), [queued]);
    }

    #[test]
    fn registered_epoch_expires_after_its_inclusive_window_and_refunds_deposits() {
        let mut settlement = Settlement::new().unwrap();
        let account = identities()[0].key.clone();
        let event = DepositEvent {
            id: Sha256::hash(&[b"registered-expiry-refund"]),
            account: account.clone(),
            amount: 7,
        };
        settlement.deposit(event).unwrap();
        let deposits = settlement.chain.pending_deposits();
        let withdrawals = WithdrawalBatch::empty();
        let admission_deadline = epoch_context(0, &deposits, &withdrawals, 400)
            .unwrap()
            .admission_deadline();
        settlement
            .register_epoch(
                0,
                400,
                deposits.root::<Sha256>().unwrap(),
                deposits.root::<Sha256>().unwrap(),
                withdrawals,
                &[],
            )
            .unwrap();

        settlement.advance_logical_time(admission_deadline).unwrap();
        assert!(!settlement.status().unwrap().hard_faulted);
        settlement
            .advance_logical_time(admission_deadline + 1)
            .unwrap();
        let status = settlement.status().unwrap();
        assert_eq!(status.now, admission_deadline + 1);
        assert!(status.hard_faulted);
        assert!(settlement.registered.is_none());
        let refund = settlement.chain.claim_pending_deposit(2, &account).unwrap();
        assert_eq!(refund.account, account);
        assert_eq!(refund.amount, 7);
    }

    #[test]
    fn a_successor_context_opens_only_after_its_predecessor_finalizes() {
        let (mut settlement, submission, result, _, _, deposit) = admission_fixture();
        let successor_liability = result
            .epoch_context
            .predecessor_liability()
            .checked_add(deposit.amount)
            .unwrap();

        assert!(
            settlement
                .register_epoch(
                    1,
                    successor_liability,
                    empty_root(),
                    empty_root(),
                    WithdrawalBatch::empty(),
                    &[],
                )
                .is_err()
        );
        assert_eq!(
            settlement.admit_submission(submission).unwrap(),
            AdmissionOutcome::Pending
        );
        assert_eq!(
            settlement.status().unwrap().now,
            result.epoch_context.challenge_deadline()
        );
        assert!(
            settlement
                .register_epoch(
                    1,
                    successor_liability,
                    empty_root(),
                    empty_root(),
                    WithdrawalBatch::empty(),
                    &[],
                )
                .is_err()
        );

        settlement.advance_logical_time(1).unwrap();
        settlement
            .register_epoch(
                1,
                successor_liability,
                empty_root(),
                empty_root(),
                WithdrawalBatch::empty(),
                &[],
            )
            .unwrap();
    }

    #[test]
    fn intake_stops_before_the_terminal_clock_exhausts() {
        let terminal_epoch = crate::protocol::TERMINAL_EPOCH;
        let event = DepositEvent {
            id: Sha256::hash(&[b"terminal-clock-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };

        let mut deposit = Settlement::at_epoch(terminal_epoch).unwrap();
        let before = deposit.status().unwrap();
        assert!(deposit.deposit(event.clone()).is_err());
        assert_eq!(
            deposit.confirm_deposit(&event).unwrap(),
            DepositPresence::Unknown
        );
        assert_eq!(
            deposit.status().unwrap().custody_balance,
            before.custody_balance
        );

        let mut registration = Settlement::at_epoch(terminal_epoch).unwrap();
        assert!(
            registration
                .register_epoch(
                    terminal_epoch,
                    400,
                    empty_root(),
                    empty_root(),
                    WithdrawalBatch::empty(),
                    &[],
                )
                .is_err()
        );
        assert!(registration.registered.is_none());
    }

    #[test]
    fn deposit_intake_stops_while_the_epoch_context_remains_representable() {
        let terminal_epoch = crate::protocol::TERMINAL_EPOCH;
        let epoch = terminal_epoch - 2;
        let event = DepositEvent {
            id: Sha256::hash(&[b"post-inclusion-exit-clock-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };
        let mut settlement = Settlement::at_epoch(epoch).unwrap();

        let before = settlement.status().unwrap();
        assert!(settlement.deposit(event.clone()).is_err());
        assert_eq!(
            settlement.confirm_deposit(&event).unwrap(),
            DepositPresence::Unknown
        );
        assert_eq!(
            settlement.status().unwrap().custody_balance,
            before.custody_balance
        );
        assert!(
            epoch_context(
                epoch,
                &DepositBatch::empty(),
                &WithdrawalBatch::empty(),
                400,
            )
            .is_ok()
        );
    }
}
