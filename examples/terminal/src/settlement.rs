//! In-memory settlement-chain owner for the three-process terminal.

use crate::{
    protocol::{
        DepositEvent, INITIAL_BALANCE, Key, MAX_WITHDRAWALS, SQLITE_U64_MAX, SettlementResult,
        committee, deployment, ensure_amount_withdrawal_horizon, ensure_balance_intake_horizon,
        ensure_close_horizon, epoch_context, identities, openable_epoch_after, operator_key,
        settlement_config,
    },
    store::MAX_DESTINATION_BYTES,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::StateOpening,
    commitment::VectorRoot,
    settlement::{FinalizedBatch, SettlementChain, SettlementError, WithdrawalRelease},
    state::{AccountState, StateLeaf},
    transition::{
        BatchId, ExternalPayout, ExternalPayoutClaim, Header, RootBundle, StateCache,
        TerminalProof, WithdrawalClaim,
    },
};
use commonware_cryptography::{Sha256, sha256::Digest};
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
};

type WithdrawalClaimKey = (BatchId<Digest>, u32);
type ClaimedWithdrawal = (WithdrawalClaim<Key, Digest>, WithdrawalRelease<Key, Digest>);
type PayoutClaimKey = (BatchId<Digest>, u32);
type ClaimedPayout = (ExternalPayoutClaim<Key, Digest>, ExternalPayout<Key>);

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

#[derive(Clone)]
pub(crate) struct SettlementSubmission {
    pub(crate) epoch: u64,
    pub(crate) opening_liability: u64,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) terminal_proof: TerminalProof<Digest>,
    pub(crate) certificate: commonware_clearing::bajillion::admission::bls12381::Certificate,
}

impl From<&SettlementResult> for SettlementSubmission {
    fn from(result: &SettlementResult) -> Self {
        Self {
            epoch: result.epoch,
            opening_liability: result.epoch_context.opening_liability(),
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
    pub(crate) custody_balance: u64,
    pub(crate) claimable_balance: u64,
}

#[derive(Clone)]
struct FrozenBoundary {
    epoch: u64,
    deposits: DepositBatch<Key>,
    withdrawals: WithdrawalBatch<Key, Digest>,
}

/// Settlement state is authoritative for custody, boundary admission, and claim replay.
pub(crate) struct Settlement {
    chain: SettlementChain<Sha256, Key>,
    now: u64,
    frozen: VecDeque<FrozenBoundary>,
    deposits: BTreeMap<Digest, DepositEvent>,
    last_finalized_epoch: Option<u64>,
    finalized_replays: ReplayCache<u64, FinalizedBatch<Digest>>,
    withdrawal_replays: ReplayCache<WithdrawalClaimKey, ClaimedWithdrawal>,
    payout_replays: ReplayCache<PayoutClaimKey, ClaimedPayout>,
}

impl Settlement {
    pub(crate) fn new() -> Result<Self> {
        Self::with_config(settlement_config())
    }

    #[cfg(test)]
    pub(crate) fn set_claim_replay_capacity(&mut self, capacity: NonZeroUsize) {
        debug_assert!(self.withdrawal_replays.entries.is_empty());
        debug_assert!(self.payout_replays.entries.is_empty());
        self.withdrawal_replays = ReplayCache::new(capacity);
        self.payout_replays = ReplayCache::new(capacity);
    }

    fn with_config(
        config: commonware_clearing::bajillion::settlement::SettlementConfig,
    ) -> Result<Self> {
        let finalized_replays = config.max_pending_epochs;
        let claim_replays =
            NonZeroUsize::new(MAX_WITHDRAWALS).expect("claim replay bound is nonzero");
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
            0,
            config,
        )
        .context("construct settlement chain")?;
        Ok(Self {
            chain,
            now: 0,
            frozen: VecDeque::new(),
            deposits: BTreeMap::new(),
            last_finalized_epoch: None,
            finalized_replays: ReplayCache::new(finalized_replays),
            withdrawal_replays: ReplayCache::new(claim_replays),
            payout_replays: ReplayCache::new(claim_replays),
        })
    }

    pub(crate) fn status(&self) -> SettlementStatus {
        SettlementStatus {
            now: self.now,
            deployment: deployment(),
            state_root: self.chain.current_state_root(),
            custody_balance: self.chain.custody_balance(),
            claimable_balance: self.chain.claimable_balance(),
        }
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
            self.frozen.is_empty(),
            "the next settlement boundary is already frozen"
        );
        ensure_balance_intake_horizon(self.next_boundary_epoch()?)?;

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
        if let Some(withdrawal) = self.chain.pending_withdrawals().request_for(&event.account) {
            let deposited = self
                .chain
                .pending_deposits()
                .amount_for(&event.account)
                .checked_add(event.amount)
                .context("account deposit total overflow")?;
            if let WithdrawalAction::Amount(amount) = withdrawal.body().action() {
                ensure!(
                    amount.get() != deposited,
                    "this terminal does not defer an exactly offset deposit"
                );
            }
        }
        self.chain
            .record_deposit(self.now, event.id, event.account.clone(), event.amount)
            .context("record custody deposit")?;
        self.deposits.insert(event.id, event);
        Ok(())
    }

    pub(crate) fn confirm_deposit(&self, event: &DepositEvent) -> Result<()> {
        let existing = self
            .deposits
            .get(&event.id)
            .context("deposit is not recorded by settlement")?;
        ensure!(
            existing.account == event.account && existing.amount == event.amount,
            "deposit id was recorded for another event"
        );
        Ok(())
    }

    pub(crate) fn confirm_withdrawal(&self, request: &SignedWithdrawal<Key, Digest>) -> Result<()> {
        let pending = self.chain.pending_withdrawals();
        let existing = pending
            .request_for(request.account())
            .context("withdrawal is not queued by settlement")?;
        ensure!(
            existing == request,
            "account queued another settlement withdrawal"
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
            self.frozen.is_empty(),
            "the next settlement boundary is already frozen"
        );
        let epoch = self.next_boundary_epoch()?;
        match request.body().action() {
            WithdrawalAction::Amount(_) => ensure_amount_withdrawal_horizon(epoch)?,
            WithdrawalAction::Close => ensure_close_horizon(epoch)?,
        }
        let deposited = self.chain.pending_deposits().amount_for(request.account());
        if let WithdrawalAction::Amount(amount) = request.body().action() {
            ensure!(
                deposited == 0 || amount.get() != deposited,
                "this terminal does not defer an exactly offset deposit"
            );
        }
        self.chain
            .queue_withdrawal(self.now, request, &openings, |destination| {
                !destination.is_empty() && destination.len() <= MAX_DESTINATION_BYTES
            })
            .context("queue settlement withdrawal")
    }

    pub(crate) fn freeze(
        &mut self,
        epoch: u64,
        deposits: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
    ) -> Result<()> {
        if let Some(existing) = self.frozen.iter().find(|boundary| boundary.epoch == epoch) {
            ensure!(
                existing.deposits == deposits && existing.withdrawals == withdrawals,
                "epoch boundary changed after it was frozen"
            );
            return Ok(());
        }
        let expected = self.next_boundary_epoch()?;
        ensure!(
            epoch == expected,
            "settlement boundary epoch is not consecutive"
        );
        openable_epoch_after(epoch)?;
        ensure!(
            self.frozen.len() < self.chain.config().max_pending_epochs.get(),
            "settlement boundary pipeline reached its configured capacity"
        );
        if self.frozen.is_empty() {
            ensure!(
                self.chain.pending_deposits() == deposits,
                "operator deposit boundary differs from settlement"
            );
            ensure!(
                self.chain.pending_withdrawals() == withdrawals,
                "operator withdrawal boundary differs from settlement"
            );
        } else {
            ensure!(
                deposits.is_empty() && withdrawals.is_empty(),
                "a pipelined future boundary must be empty in this operator"
            );
        }
        self.frozen.push_back(FrozenBoundary {
            epoch,
            deposits,
            withdrawals,
        });
        Ok(())
    }

    fn next_boundary_epoch(&self) -> Result<u64> {
        self.frozen
            .back()
            .map_or_else(
                || {
                    self.last_finalized_epoch
                        .map_or(Some(0), |epoch| epoch.checked_add(1))
                },
                |tail| tail.epoch.checked_add(1),
            )
            .context("settlement epoch overflow")
    }

    pub(crate) fn admit(
        &mut self,
        submission: SettlementSubmission,
    ) -> Result<FinalizedBatch<Digest>> {
        let batch_id = submission.header.batch_id::<Sha256>();
        if let Some(finalized) = self.finalized_replays.get(&submission.epoch) {
            ensure!(
                finalized.batch_id == batch_id,
                "another close already finalized for this epoch"
            );
            return Ok(*finalized);
        }
        ensure!(
            self.last_finalized_epoch
                .is_none_or(|epoch| submission.epoch > epoch),
            "settlement admission replay expired"
        );
        let boundary = self
            .frozen
            .front()
            .context("settlement boundary was not frozen")?;
        ensure!(
            boundary.epoch == submission.epoch
                && boundary.deposits == submission.deposits
                && boundary.withdrawals == submission.withdrawals,
            "close does not match the frozen settlement boundary"
        );
        let context = epoch_context(
            submission.epoch,
            &submission.deposits,
            &submission.withdrawals,
            submission.opening_liability,
        )?;
        if let Some(pending) = self.chain.pending() {
            ensure!(
                pending.header == submission.header
                    && pending.roots == submission.roots
                    && pending.certificate == submission.certificate,
                "another certified close is already pending finalization"
            );
        } else {
            let admission = self.chain.admit(
                self.now,
                submission.header,
                submission.roots,
                submission.terminal_proof.clone(),
                submission.certificate.clone(),
            );
            match admission {
                Ok(_) => {}
                Err(SettlementError::NoRegisteredEpoch) => {
                    self.chain
                        .register_epoch(
                            self.now,
                            context.clone(),
                            submission.deposits,
                            submission.withdrawals,
                        )
                        .context("register close on settlement")?;
                    self.chain
                        .admit(
                            self.now,
                            submission.header,
                            submission.roots,
                            submission.terminal_proof,
                            submission.certificate,
                        )
                        .context("admit certified close on settlement")?;
                }
                Err(error) => return Err(error).context("admit certified close on settlement"),
            }
        }
        let finalize_at = context
            .challenge_deadline()
            .checked_add(1)
            .context("settlement deadline overflow")?;
        let finalized = self
            .chain
            .finalize(finalize_at)
            .context("finalize close on settlement")?;
        self.now = finalize_at;
        self.frozen.pop_front();
        self.last_finalized_epoch = Some(submission.epoch);
        self.finalized_replays.insert(submission.epoch, finalized);
        Ok(finalized)
    }

    pub(crate) fn claim_withdrawal(
        &mut self,
        batch_id: BatchId<Digest>,
        claim: &WithdrawalClaim<Key, Digest>,
    ) -> Result<WithdrawalRelease<Key, Digest>> {
        let key = (batch_id, claim.position());
        if let Some((existing, release)) = self.withdrawal_replays.get(&key) {
            ensure!(existing == claim, "withdrawal claim position was reused");
            return Ok(release.clone());
        }
        let release = self
            .chain
            .claim_withdrawal(batch_id, claim)
            .context("claim finalized withdrawal")?;
        self.withdrawal_replays
            .insert(key, (claim.clone(), release.clone()));
        Ok(release)
    }

    pub(crate) fn claim_external_payout(
        &mut self,
        batch_id: BatchId<Digest>,
        claim: &ExternalPayoutClaim<Key, Digest>,
    ) -> Result<ExternalPayout<Key>> {
        let key = (batch_id, claim.position());
        if let Some((existing, payout)) = self.payout_replays.get(&key) {
            ensure!(existing == claim, "external payout position was reused");
            return Ok(payout.clone());
        }
        let payout = self
            .chain
            .claim_external_payout(batch_id, claim)
            .context("claim finalized external payout")?;
        self.payout_replays
            .insert(key, (claim.clone(), payout.clone()));
        Ok(payout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher, Sha256};

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
        settlement.confirm_deposit(&event).unwrap();

        let conflicting = DepositEvent { amount: 8, ..event };
        assert!(settlement.deposit(conflicting.clone()).is_err());
        assert!(settlement.confirm_deposit(&conflicting).is_err());
        assert_eq!(settlement.status().custody_balance, 407);
    }

    #[test]
    fn deposit_rejects_values_outside_the_operator_storage_domain() {
        let mut settlement = Settlement::new().unwrap();
        let before = settlement.status();
        let event = DepositEvent {
            id: Sha256::hash(&[b"oversized-deposit"]),
            account: identities()[0].key.clone(),
            amount: i64::MAX as u64,
        };

        assert!(settlement.deposit(event.clone()).is_err());
        assert!(settlement.confirm_deposit(&event).is_err());
        assert_eq!(settlement.status().custody_balance, before.custody_balance);
    }

    #[test]
    fn a_frozen_boundary_is_idempotent_and_rejects_late_custody_events() {
        let mut settlement = Settlement::new().unwrap();
        settlement
            .freeze(0, DepositBatch::empty(), WithdrawalBatch::empty())
            .unwrap();
        settlement
            .freeze(0, DepositBatch::empty(), WithdrawalBatch::empty())
            .unwrap();
        let event = DepositEvent {
            id: Sha256::hash(&[b"late-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };
        assert!(settlement.deposit(event).is_err());
    }

    #[test]
    fn frozen_boundaries_are_limited_by_the_settlement_pipeline() {
        let mut settlement = Settlement::new().unwrap();
        for epoch in 0..settlement.chain.config().max_pending_epochs.get() {
            settlement
                .freeze(
                    u64::try_from(epoch).unwrap(),
                    DepositBatch::empty(),
                    WithdrawalBatch::empty(),
                )
                .unwrap();
        }

        assert!(
            settlement
                .freeze(
                    u64::try_from(settlement.chain.config().max_pending_epochs.get()).unwrap(),
                    DepositBatch::empty(),
                    WithdrawalBatch::empty(),
                )
                .is_err()
        );
    }

    #[test]
    fn intake_stops_before_the_terminal_clock_exhausts() {
        let terminal_epoch = (u64::MAX - 2) / 10;
        let event = DepositEvent {
            id: Sha256::hash(&[b"terminal-clock-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };

        let mut deposit = Settlement::new().unwrap();
        deposit.last_finalized_epoch = Some(terminal_epoch - 1);
        let before = deposit.status();
        assert!(deposit.deposit(event.clone()).is_err());
        assert!(deposit.confirm_deposit(&event).is_err());
        assert_eq!(deposit.status().custody_balance, before.custody_balance);

        let mut replay = Settlement::new().unwrap();
        replay.deposit(event.clone()).unwrap();
        replay.last_finalized_epoch = Some(terminal_epoch - 1);
        replay.deposit(event).unwrap();

        let mut freeze = Settlement::new().unwrap();
        freeze.last_finalized_epoch = Some(terminal_epoch - 1);
        assert!(
            freeze
                .freeze(
                    terminal_epoch,
                    DepositBatch::empty(),
                    WithdrawalBatch::empty(),
                )
                .is_err()
        );
        assert!(freeze.frozen.is_empty());
    }

    #[test]
    fn deposit_intake_stops_while_the_boundary_can_still_freeze() {
        let terminal_epoch = (u64::MAX - 2) / 10;
        let epoch = terminal_epoch - 2;
        let event = DepositEvent {
            id: Sha256::hash(&[b"post-inclusion-exit-clock-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };
        let mut settlement = Settlement::new().unwrap();
        settlement.last_finalized_epoch = Some(epoch - 1);

        let before = settlement.status();
        assert!(settlement.deposit(event.clone()).is_err());
        assert!(settlement.confirm_deposit(&event).is_err());
        assert_eq!(settlement.status().custody_balance, before.custody_balance);
        settlement
            .freeze(epoch, DepositBatch::empty(), WithdrawalBatch::empty())
            .unwrap();
        assert_eq!(settlement.frozen.front().unwrap().epoch, epoch);
    }
}
