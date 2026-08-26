#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, assigned_slice_indices, bls12381, seal},
    boundary::{
        DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch,
        WithdrawalId,
    },
    challenge::{
        AccountLookup, Challenge, ChallengeKind, RangeLower, RowOpening, StateLookup, StateOpening,
        Verdict,
    },
    commitment::{self, VectorKind, VectorRoot},
    credit::{ShardHead, ShardSet},
    payment::{Payment, ReceiptBody, SignedReceipt, SignedSend},
    settlement::{
        BatchStatus, EpochDeadlinePolicy, HardFaultReason, HardFaultSettlement, PendingBatch,
        SettlementChain, SettlementConfig, WithdrawalRelease,
    },
    state::{AccountRow, AccountState, Prefix, StateLeaf},
    transition::{
        Assignment, BatchId, Close, CloseContext, CloseLimits, EpochContext, ExternalPayout,
        StateCache, TerminalProof, assemble_slices, assemble_terminal_proof,
        assemble_withdrawal_claim, build_close, validate_close,
    },
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::compute_public,
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_ACCOUNTS: usize = 4;
const MAX_ACTIONS: usize = 24;
const MAX_PENDING_EPOCHS: usize = 3;
const MAX_DESTINATION_BYTES: usize = 16;
const MAX_EPOCH_ADMISSION_DELAY: u64 = 6;
const CHALLENGE_DURATION: u64 = 2;
const DEPOSIT_INCLUSION_TIMEOUT: u64 = 6;
const MINIMUM_WITHDRAWAL_NOTICE: u64 = 2;
const MAXIMUM_WITHDRAWAL_NOTICE: u64 = 1_000;
const MAX_DEPOSIT_IDS: usize = 4;

type TestCache = StateCache<VerifyingKey, Digest>;
type TestChain = SettlementChain<Sha256, VerifyingKey>;
type TestChallenge = Challenge<VerifyingKey, Digest>;
type TestClose = Close<VerifyingKey, Digest>;
type TestContext = CloseContext<VerifyingKey, Digest>;
type TestDeposits = DepositBatch<VerifyingKey>;
type TestWithdrawals = WithdrawalBatch<VerifyingKey, Digest>;
type TestTerminalProof = TerminalProof<Digest>;
type Certificate = bls12381::Certificate;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    seed: u64,
    account_count: u8,
    balances: [u8; MAX_ACCOUNTS],
    actions: Vec<Action>,
}

#[derive(Arbitrary, Debug)]
enum Action {
    Deposit {
        tick: u8,
        account: u8,
        amount: u8,
        mutation: u8,
    },
    Withdrawal {
        tick: u8,
        account: u8,
        amount: u8,
        destination: u64,
        destination_len: u8,
        closes_account: bool,
        mutation: u8,
    },
    Register {
        tick: u8,
        mutated: bool,
    },
    RegisterPayout {
        tick: u8,
        payer: u8,
        amount: u8,
        mutated: bool,
    },
    Admit {
        tick: u8,
        mutated: bool,
    },
    Finalize {
        tick: u8,
        early: bool,
    },
    ExpireUnadmitted {
        tick: u8,
        inclusive_boundary: bool,
    },
    ExplicitTimeout {
        tick: u8,
        before_deadline: bool,
    },
    ImplicitTimeout {
        tick: u8,
        before_deadline: bool,
    },
    Challenge {
        tick: u8,
        slot: u8,
        encoded: bool,
        mutation: u8,
    },
    ClaimPendingDeposit {
        tick: u8,
        account: u8,
    },
    BeginHardFaultSettlement,
    ClaimHardFault {
        account: u8,
        mutation: u8,
    },
}

#[derive(Clone)]
struct Prepared {
    opening: TestCache,
    context: TestContext,
    deposits: TestDeposits,
    withdrawals: TestWithdrawals,
    withdrawal_releases: Vec<WithdrawalRelease<VerifyingKey, Digest>>,
    external_payouts: Vec<ExternalPayout<VerifyingKey>>,
    terminal_proof: TestTerminalProof,
    close: TestClose,
    closing: TestCache,
}

#[derive(Clone)]
struct Slot {
    opening: TestCache,
    close: TestClose,
    context: TestContext,
    deposits: TestDeposits,
    withdrawal_releases: Vec<WithdrawalRelease<VerifyingKey, Digest>>,
    external_payouts: Vec<ExternalPayout<VerifyingKey>>,
    header: commonware_clearing::bajillion::transition::Header<Digest>,
    certificate: bls12381::Certificate,
    closing: TestCache,
    status: BatchStatus<Digest>,
}

impl Slot {
    fn batch_id(&self) -> BatchId<Digest> {
        self.header.batch_id::<Sha256>()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    state_root: VectorRoot<Digest>,
    custody: u64,
    claimable: u64,
    deposits: TestDeposits,
    withdrawals: TestWithdrawals,
    safety_roots: Vec<VectorRoot<Digest>>,
    batches: Vec<PendingBatch<Digest>>,
    deadlines: Vec<Option<u64>>,
    hard_fault: Option<HardFaultReason<VerifyingKey, Digest>>,
    fence: Option<u64>,
    invalid_from: Option<BatchId<Digest>>,
    settled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutcomeClass {
    Success,
    Error,
}

impl OutcomeClass {
    fn of<T, E>(result: &Result<T, E>) -> Self {
        if result.is_ok() {
            Self::Success
        } else {
            Self::Error
        }
    }
}

#[derive(Clone, Debug)]
struct ObservedFault {
    reason: HardFaultReason<VerifyingKey, Digest>,
    fence: u64,
}

#[derive(Clone, Debug, Default)]
struct TimeObservation {
    fault: Option<ObservedFault>,
}

#[derive(Clone, Debug)]
struct ActionOutcome {
    class: OutcomeClass,
    observed_fault: Option<ObservedFault>,
}

impl ActionOutcome {
    fn new(class: OutcomeClass, observation: Option<&TimeObservation>) -> Self {
        Self {
            class,
            observed_fault: observation.and_then(|observation| observation.fault.clone()),
        }
    }
}

struct Harness {
    seed: u64,
    chain: TestChain,
    deployment: Digest,
    operator: SigningKey,
    validator: bls12381::Scheme,
    committee_digest: Digest,
    accounts: Vec<SigningKey>,
    now: u64,
    finalized: TestCache,
    expected_epoch: u64,
    slots: VecDeque<Slot>,
    registered: Option<Prepared>,
    staged_deposits: BTreeMap<VerifyingKey, u64>,
    staged_deposit_deadlines: BTreeMap<VerifyingKey, u64>,
    staged_withdrawals: BTreeMap<VerifyingKey, SignedWithdrawal<VerifyingKey, Digest>>,
    outstanding: BTreeMap<VerifyingKey, SignedWithdrawal<VerifyingKey, Digest>>,
    consumed_deposit_ids: BTreeSet<Digest>,
    withdrawal_replays: BTreeMap<WithdrawalId<Digest>, u64>,
    authorization_history: Vec<SignedWithdrawal<VerifyingKey, Digest>>,
    custody: u64,
    claimable: u64,
    hard_fault: Option<HardFaultReason<VerifyingKey, Digest>>,
    fence: Option<u64>,
    invalid_from: Option<BatchId<Digest>>,
    hard_fault_settlement: Option<HardFaultSettlement<VerifyingKey, Digest>>,
    claimed_hard_fault_accounts: BTreeSet<VerifyingKey>,
    settled: bool,
}

impl Harness {
    fn new(input: &FuzzInput) -> Self {
        let accounts = (0..MAX_ACCOUNTS)
            .map(|index| {
                SigningKey::from_seed(input.seed.wrapping_add(0x100).wrapping_add(index as u64))
            })
            .collect::<Vec<_>>();
        let account_count = usize::from(input.account_count % MAX_ACCOUNTS as u8) + 1;
        let mut leaves = accounts
            .iter()
            .take(account_count)
            .enumerate()
            .map(|(index, account)| StateLeaf {
                account: account.public_key(),
                state: AccountState {
                    balance: u64::from(input.balances[index] % 8) + 1,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let finalized = StateCache::new::<Sha256>(leaves)
            .expect("bounded canonical account state must construct");
        let seed = input.seed.to_be_bytes();
        let deployment = Sha256::hash(&[b"settlement-stateful-fuzz", &seed]);
        let operator = SigningKey::from_seed(input.seed ^ 0xa5a5_a5a5_a5a5_a5a5);
        let validator_bls = Private::new(Scalar::from((input.seed ^ 0x1357_9bdf_2468_ace0).max(1)));
        let committee = Committee::new(vec![compute_public::<MinSig>(&validator_bls)])
            .expect("one validator is an exact 3f+1 committee");
        let committee_digest = committee.commitment::<Sha256>();
        let validator = bls12381::Scheme::signer(committee.clone(), validator_bls)
            .expect("deterministic validator belongs to its committee");
        let config = SettlementConfig::new(
            NonZeroUsize::new(MAX_PENDING_EPOCHS).unwrap(),
            EpochDeadlinePolicy::new(
                NonZeroU64::new(MAX_EPOCH_ADMISSION_DELAY).unwrap(),
                NonZeroU64::new(CHALLENGE_DURATION).unwrap(),
                NonZeroU64::new(CHALLENGE_DURATION).unwrap(),
            ),
            NonZeroU64::new(DEPOSIT_INCLUSION_TIMEOUT).unwrap(),
            NonZeroU64::new(MINIMUM_WITHDRAWAL_NOTICE).unwrap(),
            NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).unwrap(),
            MAX_DESTINATION_BYTES,
            NonZeroUsize::new(MAX_DEPOSIT_IDS).unwrap(),
        );
        let chain = SettlementChain::new(
            deployment,
            operator.public_key(),
            committee.clone(),
            &finalized,
            0,
            config,
        )
        .expect("bounded settlement fixture must construct");
        let custody = finalized.liability();
        Self {
            seed: input.seed,
            chain,
            deployment,
            operator,
            validator,
            committee_digest,
            accounts,
            now: 0,
            finalized,
            expected_epoch: 0,
            slots: VecDeque::new(),
            registered: None,
            staged_deposits: BTreeMap::new(),
            staged_deposit_deadlines: BTreeMap::new(),
            staged_withdrawals: BTreeMap::new(),
            outstanding: BTreeMap::new(),
            consumed_deposit_ids: BTreeSet::new(),
            withdrawal_replays: BTreeMap::new(),
            authorization_history: Vec::new(),
            custody,
            claimable: 0,
            hard_fault: None,
            fence: None,
            invalid_from: None,
            hard_fault_settlement: None,
            claimed_hard_fault_accounts: BTreeSet::new(),
            settled: false,
        }
    }

    fn run(mut self, actions: &[Action]) {
        self.assert_invariants();
        for (step, action) in actions.iter().take(MAX_ACTIONS).enumerate() {
            self.apply(step as u64, action);
        }
    }

    fn apply(&mut self, step: u64, action: &Action) {
        let before = self.snapshot();
        let before_fault = self.hard_fault.clone();
        let before_fence = self.fence;
        let before_invalid = self.invalid_from;
        let before_invalid_epoch = before_invalid.and_then(|batch| self.batch_epoch(batch));
        let before_deposits = self.consumed_deposit_ids.clone();
        let was_settled = self.settled;

        let outcome = match action {
            Action::Deposit {
                tick,
                account,
                amount,
                mutation,
            } => self.deposit(step, *tick, *account, *amount, *mutation),
            Action::Withdrawal {
                tick,
                account,
                amount,
                destination,
                destination_len,
                closes_account,
                mutation,
            } => self.withdrawal(
                *tick,
                *account,
                *amount,
                *destination,
                *destination_len,
                *closes_account,
                *mutation,
            ),
            Action::Register { tick, mutated } => self.register(*tick, *mutated),
            Action::RegisterPayout {
                tick,
                payer,
                amount,
                mutated,
            } => self.register_payout(*tick, *payer, *amount, *mutated),
            Action::Admit { tick, mutated } => self.admit(*tick, *mutated),
            Action::Finalize { tick, early } => self.finalize(*tick, *early),
            Action::ExpireUnadmitted {
                tick,
                inclusive_boundary,
            } => self.expire_unadmitted(*tick, *inclusive_boundary),
            Action::ExplicitTimeout {
                tick,
                before_deadline,
            } => self.explicit_timeout(*tick, *before_deadline),
            Action::ImplicitTimeout {
                tick,
                before_deadline,
            } => self.implicit_timeout(step, *tick, *before_deadline),
            Action::Challenge {
                tick,
                slot,
                encoded,
                mutation,
            } => self.challenge(step, *tick, *slot, *encoded, *mutation),
            Action::ClaimPendingDeposit { tick, account } => {
                self.claim_pending_deposit(*tick, *account)
            }
            Action::BeginHardFaultSettlement => self.begin_hard_fault_settlement(),
            Action::ClaimHardFault { account, mutation } => {
                self.claim_hard_fault(*account, *mutation)
            }
        };

        let after = self.snapshot();
        if outcome.class == OutcomeClass::Error {
            Self::assert_error_atomicity(&before, &after, outcome.observed_fault.as_ref());
        }
        if let Some(reason) = before_fault {
            assert_eq!(self.hard_fault.as_ref(), Some(&reason));
        }
        if let Some(fence) = before_fence {
            assert_eq!(self.fence, Some(fence));
        }
        if let Some(old) = before_invalid {
            let new = self
                .invalid_from
                .expect("an established invalid cut cannot disappear");
            if new != old && !self.settled {
                let old_epoch = before_invalid_epoch.expect("old cut was admitted");
                let new_epoch = self.batch_epoch(new).expect("new cut remains admitted");
                assert!(
                    new_epoch < old_epoch,
                    "invalid cut can only move toward the front"
                );
            }
        }
        assert!(before_deposits.is_subset(&self.consumed_deposit_ids));
        if was_settled {
            assert_eq!(before, after, "terminal settlement is permanent");
        }
        self.assert_invariants();
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            state_root: self.chain.current_state_root(),
            custody: self.chain.custody_balance(),
            claimable: self.chain.claimable_balance(),
            deposits: self.chain.pending_deposits(),
            withdrawals: self.chain.pending_withdrawals(),
            safety_roots: self.chain.withdrawal_safety_roots(),
            batches: self.chain.pending_batches().cloned().collect(),
            deadlines: self
                .accounts
                .iter()
                .map(|account| {
                    self.chain
                        .pending_withdrawal_deadline(&account.public_key())
                })
                .collect(),
            hard_fault: self.chain.hard_fault().cloned(),
            fence: self.chain.admission_fence_epoch(),
            invalid_from: self.chain.invalid_from(),
            settled: self.chain.hard_fault_is_settled(),
        }
    }

    fn assert_error_atomicity(
        before: &Snapshot,
        after: &Snapshot,
        observed_fault: Option<&ObservedFault>,
    ) {
        let mut expected = before.clone();
        if let Some(observed) = observed_fault {
            assert!(expected.hard_fault.is_none());
            assert!(expected.fence.is_none());
            expected.hard_fault = Some(observed.reason.clone());
            expected.fence = Some(observed.fence);
        }
        assert_eq!(&expected, after);
    }

    fn assert_invariants(&self) {
        assert!(self.slots.len() <= MAX_PENDING_EPOCHS);
        assert_eq!(self.chain.pending_epoch_count(), self.slots.len());
        let expected_state_root = if self.settled {
            commitment::empty_root::<Sha256>(VectorKind::State)
        } else {
            self.finalized.root()
        };
        assert_eq!(self.chain.current_state_root(), expected_state_root);
        assert_eq!(self.chain.custody_balance(), self.custody);
        assert_eq!(self.chain.claimable_balance(), self.claimable);
        self.custody
            .checked_add(self.claimable)
            .expect("active and claimable custody fit the accounting domain");
        assert_eq!(self.chain.pending_deposits(), self.deposit_batch());
        assert_eq!(self.chain.pending_withdrawals(), self.withdrawal_batch());
        assert_eq!(self.chain.hard_fault(), self.hard_fault.as_ref());
        assert_eq!(self.chain.admission_fence_epoch(), self.fence);
        assert_eq!(self.chain.invalid_from(), self.invalid_from);
        assert_eq!(self.chain.hard_fault_is_settled(), self.settled);
        assert!(
            self.finalized
                .leaves()
                .iter()
                .all(|leaf| leaf.state.active && leaf.state.balance > 0)
        );

        let expected_batches = self
            .slots
            .iter()
            .map(|slot| PendingBatch {
                header: slot.header,
                roots: slot.close.roots,
                certificate: slot.certificate.clone(),
                closing_liability: slot.closing.liability(),
                status: slot.status.clone(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            self.chain.pending_batches().cloned().collect::<Vec<_>>(),
            expected_batches
        );

        let mut roots = vec![expected_state_root];
        roots.extend(self.slots.iter().map(|slot| slot.closing.root()));
        assert_eq!(self.chain.withdrawal_safety_roots(), roots);

        let mut opening_root = self.finalized.root();
        let mut opening_liability = self.finalized.liability();
        for (offset, slot) in self.slots.iter().enumerate() {
            assert_eq!(slot.opening.root(), slot.close.roots.opening);
            assert_eq!(slot.close.header, slot.header);
            assert_eq!(
                slot.context.payment().epoch(),
                self.expected_epoch + offset as u64
            );
            assert_eq!(slot.close.roots.opening, opening_root);
            assert_eq!(slot.context.opening_liability(), opening_liability);
            assert_eq!(slot.close.roots.closing, slot.closing.root());
            assert_eq!(
                slot.close
                    .rows
                    .last()
                    .map_or(0, |row| row.prefix.withdrawal),
                release_total(&slot.withdrawal_releases)
            );
            assert_eq!(
                slot.close.rows.last().map_or(0, |row| row.prefix.payout),
                payout_total(&slot.external_payouts)
            );
            opening_root = slot.closing.root();
            opening_liability = slot.closing.liability();
        }

        if self.hard_fault_settlement.is_some() {
            assert!(self.staged_deposit_deadlines.is_empty());
        } else {
            assert!(
                self.staged_deposits
                    .keys()
                    .eq(self.staged_deposit_deadlines.keys())
            );
        }
        let unfinalized_deposits = self.unfinalized_deposit_total();
        assert_eq!(
            self.remaining_state_liability()
                .checked_add(unfinalized_deposits)
                .expect("bounded custody equation cannot overflow"),
            self.custody
        );

        if let Some(settlement) = &self.hard_fault_settlement {
            assert_eq!(Some(&settlement.reason), self.hard_fault.as_ref());
            assert_eq!(Some(settlement.admission_fence_epoch), self.fence);
            assert_eq!(settlement.invalid_from, self.invalid_from);
            assert_eq!(settlement.frozen_state_root, self.finalized.root());
            assert_eq!(settlement.state_liability, self.finalized.liability());
            assert!(unfinalized_deposits <= settlement.unfinalized_deposit_total);
            assert_eq!(
                settlement
                    .state_liability
                    .checked_add(settlement.unfinalized_deposit_total)
                    .expect("the frozen settlement fits active custody"),
                settlement.custody_balance
            );
            assert!(self.slots.is_empty());
            assert!(self.registered.is_none());
            assert!(self.staged_withdrawals.is_empty());
        } else {
            assert!(self.claimed_hard_fault_accounts.is_empty());
        }
        assert!(self.claimed_hard_fault_accounts.iter().all(|account| {
            self.finalized
                .leaves()
                .iter()
                .any(|leaf| &leaf.account == account)
        }));

        for account in &self.accounts {
            let public = account.public_key();
            let expected_deadline = self
                .hard_fault_settlement
                .is_none()
                .then(|| {
                    self.outstanding
                        .get(&public)
                        .map(|request| request.body().deadline())
                })
                .flatten();
            assert_eq!(
                self.chain.pending_withdrawal_deadline(&public),
                expected_deadline
            );
        }
        for (account, request) in &self.staged_withdrawals {
            assert_eq!(self.outstanding.get(account), Some(request));
            assert_eq!(request.account(), account);
            let tail = self
                .tail_cache()
                .leaves()
                .iter()
                .find(|leaf| &leaf.account == account)
                .expect("staged withdrawal account remains live")
                .state;
            assert!(tail.active);
            if let WithdrawalAction::Amount(amount) = request.body().action() {
                assert!(amount.get() <= tail.balance);
            }
        }
        if self.settled {
            assert_eq!(self.custody, 0);
            assert!(self.slots.is_empty());
            assert!(self.staged_deposits.is_empty());
            assert!(self.staged_deposit_deadlines.is_empty());
            assert!(self.staged_withdrawals.is_empty());
            assert!(self.outstanding.is_empty());
            assert!(self.hard_fault_settlement.is_some());
        }
    }

    fn advance(&mut self, tick: u8) -> u64 {
        self.now = self.now.saturating_add(u64::from(tick % 3));
        self.now
    }

    fn advance_to(&mut self, target: u64) -> u64 {
        self.now = self.now.max(target);
        self.now
    }

    fn next_epoch(&self) -> u64 {
        self.slots.back().map_or(self.expected_epoch, |slot| {
            slot.context.payment().epoch() + 1
        })
    }

    fn enter_fault(&mut self, reason: HardFaultReason<VerifyingKey, Digest>) {
        if self.hard_fault.is_none() {
            self.fence = Some(self.next_epoch());
            self.hard_fault = Some(reason);
            self.registered = None;
        }
    }

    fn predict_observation(&self, now: u64) -> TimeObservation {
        let fault = if self.hard_fault.is_none() {
            self.earliest_fault()
                .filter(|(deadline, _)| now >= *deadline)
                .map(|(_, reason)| ObservedFault {
                    reason,
                    fence: self.next_epoch(),
                })
        } else {
            None
        };
        TimeObservation { fault }
    }

    fn apply_observation(&mut self, now: u64, observation: &TimeObservation) {
        if let Some(observed) = &observation.fault {
            self.enter_fault(observed.reason.clone());
            assert_eq!(self.fence, Some(observed.fence));
        }
        self.withdrawal_replays
            .retain(|_, deadline| *deadline > now);
    }

    fn operates_after(&self, observation: &TimeObservation) -> bool {
        self.hard_fault.is_none() && observation.fault.is_none()
    }

    fn earliest_outstanding(&self) -> Option<(u64, VerifyingKey)> {
        self.outstanding
            .iter()
            .map(|(account, request)| (request.body().deadline(), account.clone()))
            .min()
    }

    fn earliest_fault(&self) -> Option<(u64, HardFaultReason<VerifyingKey, Digest>)> {
        let deposit = self
            .staged_deposit_deadlines
            .iter()
            .map(|(account, deadline)| (*deadline, account.clone()))
            .min();
        let withdrawal = self.earliest_outstanding();
        match (deposit, withdrawal) {
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
                    account,
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
        }
    }

    fn batch_epoch(&self, batch: BatchId<Digest>) -> Option<u64> {
        self.slots
            .iter()
            .find(|slot| slot.batch_id() == batch)
            .map(|slot| slot.context.payment().epoch())
    }

    fn digest(&self, label: &[u8], step: u64) -> Digest {
        let seed = self.seed.to_be_bytes();
        let step = step.to_be_bytes();
        Sha256::hash(&[label, &seed, &step])
    }

    fn external_account(&self) -> VerifyingKey {
        SigningKey::from_seed(self.seed.wrapping_add(10_000)).public_key()
    }

    fn deposit_batch(&self) -> TestDeposits {
        if self.hard_fault_settlement.is_some() {
            return DepositBatch::empty();
        }
        DepositBatch::new(
            self.staged_deposits
                .iter()
                .filter_map(|(account, amount)| {
                    let deferred = self.staged_withdrawals.get(account).is_some_and(|request| {
                        matches!(
                            request.body().action(),
                            WithdrawalAction::Amount(withdrawal) if withdrawal.get() == *amount
                        )
                    });
                    (!deferred).then(|| {
                        DepositRecord::new(account.clone(), *amount)
                            .expect("model deposits remain positive")
                    })
                })
                .collect(),
        )
        .expect("model deposits remain canonical")
    }

    fn unfinalized_deposit_total(&self) -> u64 {
        let staged = self
            .staged_deposits
            .values()
            .try_fold(0_u64, |total, amount| total.checked_add(*amount))
            .expect("bounded staged deposits cannot overflow the model");
        if self.hard_fault_settlement.is_some() {
            return staged;
        }
        self.slots
            .iter()
            .try_fold(staged, |total, slot| {
                total.checked_add(slot.deposits.total())
            })
            .expect("bounded admitted deposits cannot overflow the model")
    }

    fn remaining_state_liability(&self) -> u64 {
        if self.hard_fault_settlement.is_none() {
            return self.finalized.liability();
        }
        self.finalized
            .leaves()
            .iter()
            .filter(|leaf| !self.claimed_hard_fault_accounts.contains(&leaf.account))
            .try_fold(0_u64, |total, leaf| total.checked_add(leaf.state.balance))
            .expect("authenticated state liability fits active custody")
    }

    fn finish_hard_fault_if_drained(&mut self) {
        if self.hard_fault_settlement.is_some()
            && self.staged_deposits.is_empty()
            && self.remaining_state_liability() == 0
        {
            self.settled = true;
        }
    }

    fn withdrawal_batch(&self) -> TestWithdrawals {
        WithdrawalBatch::new(self.staged_withdrawals.values().cloned().collect())
            .expect("model withdrawals remain canonical")
    }

    fn tail_cache(&self) -> &TestCache {
        self.slots
            .back()
            .map_or(&self.finalized, |slot| &slot.closing)
    }

    fn make_context(
        &self,
        epoch: u64,
        cache: &TestCache,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> TestContext {
        EpochContext::new::<Sha256>(
            self.deployment,
            epoch,
            self.operator.public_key(),
            deposits,
            withdrawals,
            cache.liability(),
            admission_deadline,
            challenge_deadline,
            CloseLimits::protocol_maximum(),
            Assignment::new(self.committee_digest, 0).unwrap(),
        )
        .and_then(|epoch| epoch.bind::<Sha256>(cache, deposits, withdrawals))
        .expect("sanitized close context must be valid")
    }

    fn make_prepared(&self) -> Prepared {
        let cache = self.tail_cache();
        let deposits = self.deposit_batch();
        let withdrawals = self.withdrawal_batch();
        let admission_deadline = self.now.saturating_add(2);
        let challenge_deadline = admission_deadline.saturating_add(2);
        let context = self.make_context(
            self.next_epoch(),
            cache,
            &deposits,
            &withdrawals,
            admission_deadline,
            challenge_deadline,
        );
        let (close, closing) = boundary_close(cache, &context, &deposits, &withdrawals);
        self.finish_prepared(cache, context, deposits, withdrawals, close, closing)
    }

    fn make_payout_prepared(&self, payer_selector: u8, raw_amount: u8) -> Option<Prepared> {
        if !self.staged_deposits.is_empty() || self.staged_withdrawals.len() > 1 {
            return None;
        }
        let close_request = self.staged_withdrawals.values().next();
        if close_request
            .is_some_and(|request| !matches!(request.body().action(), WithdrawalAction::Close))
        {
            return None;
        }
        let cache = self.tail_cache();
        let leaf = match close_request {
            Some(request) => cache
                .leaves()
                .iter()
                .find(|leaf| &leaf.account == request.account())?,
            None => {
                let candidates = cache
                    .leaves()
                    .iter()
                    .filter(|leaf| leaf.state.balance > 1)
                    .collect::<Vec<_>>();
                candidates
                    .get(usize::from(payer_selector) % candidates.len().max(1))
                    .copied()?
            }
        };
        let payer = self
            .accounts
            .iter()
            .find(|key| key.public_key() == leaf.account)?;
        let recipient = self.external_account();
        if cache
            .leaves()
            .binary_search_by(|candidate| candidate.account.cmp(&recipient))
            .is_ok()
        {
            return None;
        }

        let deposits = DepositBatch::empty();
        let withdrawals = self.withdrawal_batch();
        let admission_deadline = self.now.saturating_add(2);
        let challenge_deadline = admission_deadline.saturating_add(2);
        let context = self.make_context(
            self.next_epoch(),
            cache,
            &deposits,
            &withdrawals,
            admission_deadline,
            challenge_deadline,
        );
        let maximum = if close_request.is_some() {
            leaf.state.balance
        } else {
            leaf.state.balance.checked_sub(1)?
        };
        let amount = u64::from(raw_amount).wrapping_rem(maximum) + 1;
        let shard = u64::from(payer_selector % 4);
        let payment = linked_payment(
            &context,
            &self.operator,
            payer,
            &recipient,
            amount,
            leaf.state.cumulative_debit,
            shard,
        );
        let payer_shards = ShardSet::empty(context.payment().epoch(), leaf.account.clone());
        let recipient_shards = ShardSet::new(
            context.payment().epoch(),
            recipient.clone(),
            vec![ShardHead::new(shard, payment.clone())],
        )
        .expect("one external receipt is a canonical shard set");
        let mut payer_closing = leaf.state;
        payer_closing.cumulative_debit = payment.send().body().cumulative_debit();
        if close_request.is_some() {
            payer_closing.balance = 0;
            payer_closing.active = false;
        } else {
            payer_closing.balance -= amount;
        }
        let recipient_closing = AccountState {
            cumulative_credit: amount,
            receipt_count: 1,
            ..AccountState::default()
        };
        let mut pairs = vec![
            (
                AccountRow {
                    account: leaf.account.clone(),
                    opening: leaf.state,
                    closing: payer_closing,
                    outgoing: Some(payment),
                    credit_root: payer_shards
                        .root::<Sha256>()
                        .expect("empty payer shard set commits"),
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient,
                    opening: AccountState::default(),
                    closing: recipient_closing,
                    outgoing: None,
                    credit_root: recipient_shards
                        .root::<Sha256>()
                        .expect("external recipient shard set commits"),
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        let mut prefix = Prefix::default();
        for (row, shards) in &mut pairs {
            let (debit, credit, _) = row
                .checked_deltas()
                .expect("constructed payout counters are monotonic");
            let closes_payer = close_request.is_some() && row.account == leaf.account;
            let withdrawal = if closes_payer {
                row.opening
                    .balance
                    .checked_sub(debit)
                    .expect("constructed close payment is affordable")
            } else {
                0
            };
            prefix = prefix
                .checked_extend(Prefix {
                    debit,
                    credit,
                    withdrawal,
                    payout: if row.opening.active { 0 } else { credit },
                    withdrawals: u64::from(closes_payer),
                    shards: shards.heads().len() as u64,
                    ..Prefix::default()
                })
                .expect("bounded payout prefixes cannot overflow");
            row.prefix = prefix;
        }
        let (rows, shard_sets) = pairs.into_iter().unzip();
        let close =
            build_close::<Sha256, _, _>(cache, &context, &deposits, &withdrawals, rows, shard_sets)
                .expect("sanitized external payout close must build");
        let closing = closing_cache(cache, &close);
        Some(self.finish_prepared(cache, context, deposits, withdrawals, close, closing))
    }

    fn finish_prepared(
        &self,
        opening: &TestCache,
        context: TestContext,
        deposits: TestDeposits,
        withdrawals: TestWithdrawals,
        close: TestClose,
        closing: TestCache,
    ) -> Prepared {
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close)
            .expect("sanitized close must validate before deriving settlement outputs");
        let withdrawal_releases = withdrawals
            .requests()
            .iter()
            .map(|request| {
                let claim = assemble_withdrawal_claim::<Sha256, _, _>(
                    &close,
                    &withdrawals,
                    request.account(),
                    &Sequential,
                )
                .expect("validated withdrawal has a canonical claim");
                assert_eq!(claim.request(), request);
                let amount = claim
                    .verify::<Sha256>(
                        context.deployment(),
                        context.withdrawal_root(),
                        &close.roots.change,
                    )
                    .expect("validated withdrawal claim verifies");
                let row = close
                    .rows
                    .iter()
                    .find(|row| &row.account == request.account())
                    .expect("validated withdrawal has an authenticated row");
                match request.body().action() {
                    WithdrawalAction::Amount(expected) => assert_eq!(amount, expected.get()),
                    WithdrawalAction::Close => {
                        let (debit, credit, _) = row
                            .checked_deltas()
                            .expect("validated close counters are monotonic");
                        let available = u128::from(row.opening.balance)
                            + u128::from(deposits.amount_for(&row.account))
                            + u128::from(credit);
                        let expected = u64::try_from(
                            available
                                .checked_sub(u128::from(debit))
                                .expect("validated close debit is affordable"),
                        )
                        .expect("validated close tail fits in u64");
                        assert_eq!(amount, expected);
                        assert!(!row.closing.active);
                        assert_eq!(row.closing.balance, 0);
                    }
                }
                WithdrawalRelease {
                    request: request.clone(),
                    amount,
                }
            })
            .collect::<Vec<_>>();
        let terminal = close
            .rows
            .last()
            .map_or(Prefix::default(), |row| row.prefix);
        assert_eq!(
            terminal.withdrawals,
            u64::try_from(withdrawals.len()).expect("bounded withdrawal count fits in u64")
        );
        assert!(terminal.withdrawal >= withdrawals.total());
        assert_eq!(terminal.withdrawal, release_total(&withdrawal_releases));
        let terminal_proof = assemble_terminal_proof::<Sha256, _, _>(
            &context,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .expect("sanitized close has a canonical terminal proof");
        let totals = terminal_proof
            .verify::<Sha256, VerifyingKey>(
                &context,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
            )
            .expect("sanitized terminal proof verifies");
        let external_payouts = expected_external_payouts(&close, &deposits, &withdrawals);
        assert_eq!(totals.withdrawal, release_total(&withdrawal_releases));
        assert_eq!(totals.payout, payout_total(&external_payouts));
        Prepared {
            opening: opening.clone(),
            context,
            deposits,
            withdrawals,
            withdrawal_releases,
            external_payouts,
            terminal_proof,
            close,
            closing,
        }
    }

    fn certificate(&self, prepared: &Prepared) -> Certificate {
        validate_close::<Sha256, _, _>(
            &prepared.context,
            &prepared.deposits,
            &prepared.withdrawals,
            &prepared.close,
        )
        .expect("sanitized close must validate");
        let slices = assemble_slices::<Sha256, _, _>(
            &prepared.opening,
            &prepared.context,
            &prepared.deposits,
            &prepared.withdrawals,
            &prepared.close,
            &Sequential,
        )
        .expect("sanitized close slices must build");
        let assigned = assigned_slice_indices::<Sha256, _>(
            self.validator.committee(),
            prepared.context.assignment(),
            self.validator.me().expect("validator can sign"),
        )
        .expect("committee-bound assignment must derive")
        .into_iter()
        .map(|index| slices[usize::from(index)].clone())
        .collect::<Vec<_>>();
        let (vote, retained) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &self.validator,
            &prepared.context,
            &prepared.deposits,
            &prepared.withdrawals,
            &prepared.close.header,
            &prepared.close.roots,
            assigned,
            &mut test_rng(),
            &Sequential,
        )
        .expect("complete validated assignment must sign");
        assert!(
            retained
                .slices()
                .iter()
                .all(|slice| retained.serve(slice.index).is_some())
        );
        self.validator
            .assemble_exact([vote])
            .expect("one-validator exact quorum must assemble")
    }

    fn deposit(
        &mut self,
        step: u64,
        tick: u8,
        account_selector: u8,
        raw_amount: u8,
        mutation: u8,
    ) -> ActionOutcome {
        let now = self.advance(tick);
        let mut account =
            self.accounts[usize::from(account_selector) % self.accounts.len()].public_key();
        let mut amount = u64::from(raw_amount % 5) + 1;
        let mut id = self.digest(b"deposit", step);
        match mutation % 6 {
            0 => {}
            1 => amount = 0,
            2 => {
                if let Some(fresh) =
                    self.accounts
                        .iter()
                        .map(SigningKey::public_key)
                        .find(|candidate| {
                            self.tail_cache()
                                .leaves()
                                .binary_search_by(|leaf| leaf.account.cmp(candidate))
                                .is_err()
                        })
                {
                    account = fresh;
                } else {
                    amount = 0;
                }
            }
            3 => {
                if let Some(consumed) = self.consumed_deposit_ids.iter().next().copied() {
                    id = consumed;
                } else {
                    amount = 0;
                }
            }
            4 => {
                if let Some(withdrawing) = self.staged_withdrawals.keys().next() {
                    account = withdrawing.clone();
                } else {
                    amount = 0;
                }
            }
            _ => amount = u64::MAX,
        }

        let observation = self.predict_observation(now);
        let aggregate = self
            .staged_deposits
            .get(&account)
            .copied()
            .unwrap_or(0)
            .checked_add(amount);
        let deadline = now.checked_add(DEPOSIT_INCLUSION_TIMEOUT);
        let custody = self.custody.checked_add(amount);
        let deferred = aggregate.is_some_and(|aggregate| {
            self.staged_withdrawals
                .get(&account)
                .is_some_and(|request| {
                    matches!(
                        request.body().action(),
                        WithdrawalAction::Amount(withdrawal) if withdrawal.get() == aggregate
                    )
                })
        });
        let epoch_available = self
            .next_epoch()
            .checked_add(if deferred { 4 } else { 3 })
            .is_some();
        let expected = if self.operates_after(&observation)
            && self.registered.is_none()
            && epoch_available
            && amount != 0
            && !self.consumed_deposit_ids.contains(&id)
            && self.consumed_deposit_ids.len() < MAX_DEPOSIT_IDS
            && aggregate.is_some()
            && deadline.is_some()
            && custody.is_some()
            && custody
                .and_then(|custody| self.claimable.checked_add(custody))
                .is_some()
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.record_deposit(now, id, account.clone(), amount);
        assert_eq!(OutcomeClass::of(&result), expected);
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            let deadline = deadline.expect("the oracle checked deposit deadline arithmetic");
            self.staged_deposit_deadlines
                .entry(account.clone())
                .and_modify(|current| *current = (*current).min(deadline))
                .or_insert(deadline);
            self.staged_deposits.insert(
                account,
                aggregate.expect("the oracle checked accepted deposit aggregation"),
            );
            self.custody = self
                .custody
                .checked_add(amount)
                .expect("accepted bounded deposit custody");
            assert!(self.consumed_deposit_ids.insert(id));
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    #[allow(clippy::too_many_arguments)]
    fn withdrawal(
        &mut self,
        tick: u8,
        account_selector: u8,
        raw_amount: u8,
        destination_seed: u64,
        destination_len: u8,
        wants_close: bool,
        mutation: u8,
    ) -> ActionOutcome {
        let now = self.advance(tick);
        let variant = mutation % 11;
        let candidate = self.withdrawal_candidate(account_selector);
        let (key, minimum_balance) = candidate.unwrap_or_else(|| {
            (
                self.accounts[usize::from(account_selector) % self.accounts.len()].clone(),
                1,
            )
        });
        let mut closes_account = wants_close;
        let mut amount = u64::from(raw_amount).wrapping_rem(minimum_balance) + 1;
        let len = usize::from(destination_len) % MAX_DESTINATION_BYTES + 1;
        let mut destination = Bytes::from(vec![destination_seed as u8; len]);
        let mut deployment = self.deployment;
        let mut root = self.finalized.root().digest;
        let mut deadline = now.saturating_add(MINIMUM_WITHDRAWAL_NOTICE + 8);
        let mut eligible = true;
        let mut replay = None;
        match variant {
            0 => {}
            1 => deadline = now,
            2 => {
                if let Some(too_late) = now.checked_add(MAXIMUM_WITHDRAWAL_NOTICE + 1) {
                    deadline = too_late;
                } else {
                    destination = Bytes::from(vec![0; MAX_DESTINATION_BYTES + 1]);
                }
            }
            3 => destination = Bytes::from(vec![0; MAX_DESTINATION_BYTES + 1]),
            4 => deployment = self.digest(b"wrong-deployment", destination_seed),
            5 => root = self.digest(b"wrong-root", destination_seed),
            6 => eligible = false,
            7 => {
                if let Some(excessive) = minimum_balance.checked_add(1) {
                    amount = excessive;
                    closes_account = false;
                } else {
                    destination = Bytes::from(vec![0; MAX_DESTINATION_BYTES + 1]);
                }
            }
            8 => {
                replay = self
                    .authorization_history
                    .iter()
                    .rev()
                    .find(|request| {
                        self.withdrawal_replays
                            .get(&request.id::<Sha256>())
                            .is_some_and(|deadline| *deadline > now)
                    })
                    .cloned();
                if replay.is_none() {
                    deadline = now;
                }
            }
            9 => {}
            _ => {
                if let Some(depositing) = self.staged_deposits.keys().next() {
                    let depositing_account = depositing.clone();
                    if let Some(depositing_key) = self
                        .accounts
                        .iter()
                        .find(|key| key.public_key() == depositing_account)
                    {
                        let request = SignedWithdrawal::sign(
                            deployment,
                            root,
                            destination.clone(),
                            WithdrawalAction::Amount(NonZeroU64::MIN),
                            deadline,
                            depositing_key,
                        );
                        replay = Some(request);
                    }
                } else {
                    deadline = now;
                }
            }
        }
        let request = replay.unwrap_or_else(|| {
            let action = if closes_account {
                WithdrawalAction::Close
            } else {
                WithdrawalAction::Amount(
                    NonZeroU64::new(amount).expect("sanitized withdrawal amount is positive"),
                )
            };
            SignedWithdrawal::sign(deployment, root, destination, action, deadline, &key)
        });
        let account = request.account().clone();
        let mut openings = self.safety_openings(&account).unwrap_or_default();
        if variant == 9 && !openings.is_empty() {
            openings.pop();
        }

        let observation = self.predict_observation(now);
        let expected =
            if self.withdrawal_would_succeed(now, &observation, &request, &openings, eligible) {
                OutcomeClass::Success
            } else {
                OutcomeClass::Error
            };
        let result = self
            .chain
            .queue_withdrawal(now, request.clone(), &openings, |_| eligible);
        assert_eq!(OutcomeClass::of(&result), expected);
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            let request_id = request.id::<Sha256>();
            assert!(!self.withdrawal_replays.contains_key(&request_id));
            assert!(
                self.staged_withdrawals
                    .insert(account.clone(), request.clone())
                    .is_none()
            );
            assert!(self.outstanding.insert(account, request.clone()).is_none());
            self.withdrawal_replays
                .insert(request_id, request.body().deadline());
            self.authorization_history.push(request);
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    fn withdrawal_candidate(&self, selector: u8) -> Option<(SigningKey, u64)> {
        (0..self.accounts.len()).find_map(|offset| {
            let index = (usize::from(selector) + offset) % self.accounts.len();
            let key = &self.accounts[index];
            let account = key.public_key();
            if self.outstanding.contains_key(&account) {
                return None;
            }
            let states = std::iter::once(&self.finalized)
                .chain(self.slots.iter().map(|slot| &slot.closing))
                .map(|cache| {
                    cache
                        .leaves()
                        .iter()
                        .find(|leaf| leaf.account == account)
                        .map(|leaf| leaf.state)
                })
                .collect::<Option<Vec<_>>>()?;
            if states
                .iter()
                .any(|state| !state.active || state.balance == 0)
            {
                return None;
            }
            let minimum = states.iter().map(|state| state.balance).min()?;
            Some((key.clone(), minimum))
        })
    }

    fn safety_openings(
        &self,
        account: &VerifyingKey,
    ) -> Option<Vec<StateOpening<VerifyingKey, Digest>>> {
        std::iter::once(&self.finalized)
            .chain(self.slots.iter().map(|slot| &slot.closing))
            .map(|cache| cache.opening(account).ok())
            .collect()
    }

    fn withdrawal_would_succeed(
        &self,
        now: u64,
        observation: &TimeObservation,
        request: &SignedWithdrawal<VerifyingKey, Digest>,
        openings: &[StateOpening<VerifyingKey, Digest>],
        destination_is_eligible: bool,
    ) -> bool {
        if !self.operates_after(observation) || self.registered.is_some() {
            return false;
        }
        let body = request.body();
        let request_id = request.id::<Sha256>();
        let deferred = self
            .staged_deposits
            .get(request.account())
            .is_some_and(|deposit| {
                matches!(
                    body.action(),
                    WithdrawalAction::Amount(withdrawal) if withdrawal.get() == *deposit
                )
            });
        let epoch_offset = if deferred {
            4
        } else {
            match body.action() {
                WithdrawalAction::Amount(_) => 2,
                WithdrawalAction::Close => 1,
            }
        };
        if self.next_epoch().checked_add(epoch_offset).is_none() {
            return false;
        }
        let Some(minimum_deadline) = now.checked_add(MINIMUM_WITHDRAWAL_NOTICE) else {
            return false;
        };
        if body.destination().len() > MAX_DESTINATION_BYTES
            || self
                .withdrawal_replays
                .get(&request_id)
                .is_some_and(|deadline| *deadline > now)
            || body.deployment() != &self.deployment
            || body.state_root() != &self.finalized.root().digest
            || !destination_is_eligible
            || body.deadline() < minimum_deadline
            || body.deadline() > now.saturating_add(MAXIMUM_WITHDRAWAL_NOTICE)
            || self.outstanding.contains_key(request.account())
        {
            return false;
        }

        let Some(expected_openings) = self.safety_openings(request.account()) else {
            return false;
        };
        if expected_openings != openings {
            return false;
        }
        expected_openings.iter().all(|opening| {
            opening.leaf.state.active
                && match body.action() {
                    WithdrawalAction::Amount(amount) => amount.get() <= opening.leaf.state.balance,
                    WithdrawalAction::Close => true,
                }
        })
    }

    fn register(&mut self, tick: u8, mutated: bool) -> ActionOutcome {
        let prepared = self.make_prepared();
        self.register_prepared(tick, mutated, prepared)
    }

    fn register_payout(&mut self, tick: u8, payer: u8, amount: u8, mutated: bool) -> ActionOutcome {
        let (prepared, unavailable) = self.make_payout_prepared(payer, amount).map_or_else(
            || (self.make_prepared(), true),
            |prepared| (prepared, false),
        );
        self.register_prepared(tick, mutated || unavailable, prepared)
    }

    fn register_prepared(&mut self, tick: u8, mutated: bool, prepared: Prepared) -> ActionOutcome {
        let now = self.advance(tick);
        let context = if mutated {
            self.make_context(
                prepared.context.payment().epoch() + 1,
                self.tail_cache(),
                &prepared.deposits,
                &prepared.withdrawals,
                prepared.context.admission_deadline(),
                prepared.context.challenge_deadline(),
            )
        } else {
            prepared.context.clone()
        };
        let observation = self.predict_observation(now);
        let expected = if self.operates_after(&observation)
            && self.registered.is_none()
            && self.slots.len() < MAX_PENDING_EPOCHS
            && now <= context.admission_deadline()
            && context == prepared.context
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.register(
            now,
            context,
            prepared.deposits.clone(),
            prepared.withdrawals.clone(),
        );
        assert_eq!(OutcomeClass::of(&result), expected);
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            assert!(self.registered.is_none());
            self.registered = Some(prepared);
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    fn admit(&mut self, tick: u8, mutated: bool) -> ActionOutcome {
        let now = self.advance(tick);
        let prepared = self
            .registered
            .clone()
            .unwrap_or_else(|| self.make_prepared());
        let terminal_proof = prepared.terminal_proof.clone();
        let certificate = self.certificate(&prepared);
        let retained_certificate = certificate.clone();
        let mut header = prepared.close.header;
        let mut roots = prepared.close.roots;
        if mutated {
            roots.closing.digest = self.digest(b"admit-root-mutation", now);
            header = commonware_clearing::bajillion::transition::Header::new::<Sha256, _>(
                prepared.context.payment(),
                &roots,
            );
        }
        let observation = self.predict_observation(now);
        let expected = if self.operates_after(&observation)
            && self.slots.len() < MAX_PENDING_EPOCHS
            && self.registered.as_ref().is_some_and(|registered| {
                now <= registered.context.admission_deadline()
                    && header == registered.close.header
                    && roots == registered.close.roots
            }) {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self
            .chain
            .admit(now, header, roots, terminal_proof, certificate);
        assert_eq!(OutcomeClass::of(&result), expected);
        if expected == OutcomeClass::Success {
            let batch_id = result
                .as_ref()
                .expect("the oracle predicted successful admission");
            assert_eq!(*batch_id, prepared.close.header.batch_id::<Sha256>());
        }
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            let registered = self
                .registered
                .take()
                .expect("admission requires the exact registered epoch");
            for record in registered.deposits.records() {
                assert_eq!(
                    self.staged_deposits.remove(record.account()),
                    Some(record.amount())
                );
                assert!(
                    self.staged_deposit_deadlines
                        .remove(record.account())
                        .is_some()
                );
            }
            self.slots.push_back(Slot {
                opening: registered.opening,
                close: registered.close.clone(),
                context: registered.context,
                deposits: registered.deposits,
                withdrawal_releases: registered.withdrawal_releases,
                external_payouts: registered.external_payouts,
                header: registered.close.header,
                certificate: retained_certificate,
                closing: registered.closing,
                status: BatchStatus::Pending,
            });
            self.staged_withdrawals.clear();
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    fn finalize(&mut self, tick: u8, early: bool) -> ActionOutcome {
        let now = if let Some(front) = self.slots.front() {
            let target = if early {
                front.context.challenge_deadline()
            } else {
                front.context.challenge_deadline().saturating_add(1)
            };
            self.advance_to(target)
        } else {
            self.advance(tick)
        };
        let observation = self.predict_observation(now);
        let reserve = self.slots.front().map(|front| {
            release_total(&front.withdrawal_releases)
                .checked_add(payout_total(&front.external_payouts))
                .expect("authenticated reserve fits custody")
        });
        let expected = if !self.settled
            && self.slots.front().is_some_and(|front| {
                matches!(front.status, BatchStatus::Pending)
                    && now > front.context.challenge_deadline()
                    && front.context.payment().epoch() == self.expected_epoch
            }) {
            if reserve
                .and_then(|reserve| self.claimable.checked_add(reserve))
                .is_some()
            {
                OutcomeClass::Success
            } else {
                OutcomeClass::Error
            }
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.finalize(now);
        assert_eq!(OutcomeClass::of(&result), expected);
        if expected == OutcomeClass::Success {
            let finalized = result
                .as_ref()
                .expect("the oracle predicted successful finalization");
            let slot = self
                .slots
                .front()
                .expect("the oracle required a front slot");
            assert_eq!(finalized.batch_id, slot.batch_id());
            assert_eq!(finalized.epoch, self.expected_epoch);
            assert_eq!(finalized.closing_state_root, slot.closing.root());
            assert_eq!(
                finalized.withdrawal_total,
                release_total(&slot.withdrawal_releases)
            );
            assert_eq!(finalized.payout_total, payout_total(&slot.external_payouts));
            assert_eq!(
                finalized.custody_balance,
                self.custody
                    .checked_sub(release_total(&slot.withdrawal_releases))
                    .and_then(|custody| {
                        custody.checked_sub(payout_total(&slot.external_payouts))
                    })
                    .expect("the model holds admitted withdrawal and payout custody")
            );
        }
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            let slot = self
                .slots
                .pop_front()
                .expect("successful finalization requires a front slot");
            assert!(matches!(slot.status, BatchStatus::Pending));
            assert!(now > slot.context.challenge_deadline());
            self.custody = self
                .custody
                .checked_sub(release_total(&slot.withdrawal_releases))
                .and_then(|custody| custody.checked_sub(payout_total(&slot.external_payouts)))
                .expect("admitted withdrawals and payouts are held in custody");
            self.claimable = self
                .claimable
                .checked_add(release_total(&slot.withdrawal_releases))
                .and_then(|claimable| claimable.checked_add(payout_total(&slot.external_payouts)))
                .expect("finalization preserves the combined custody domain");
            for release in &slot.withdrawal_releases {
                assert_eq!(
                    self.outstanding.remove(release.request.account()),
                    Some(release.request.clone())
                );
            }
            self.finalized = slot.closing;
            self.expected_epoch += 1;
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    fn expire_unadmitted(&mut self, tick: u8, inclusive_boundary: bool) -> ActionOutcome {
        let now = if let Some(prepared) = &self.registered {
            let target = if inclusive_boundary {
                prepared.context.admission_deadline()
            } else {
                prepared.context.admission_deadline().saturating_add(1)
            };
            self.advance_to(target)
        } else {
            self.advance(tick)
        };
        let observation = self.predict_observation(now);
        let expected = if self.operates_after(&observation)
            && self
                .registered
                .as_ref()
                .is_some_and(|prepared| now > prepared.context.admission_deadline())
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.expire_unadmitted(now);
        assert_eq!(OutcomeClass::of(&result), expected);
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            self.registered
                .take()
                .expect("successful expiry requires a registration");
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    fn explicit_timeout(&mut self, tick: u8, before_deadline: bool) -> ActionOutcome {
        let now = if let Some((deadline, _)) = self.earliest_fault() {
            let target = if before_deadline {
                deadline.saturating_sub(1)
            } else {
                deadline
            };
            self.advance_to(target)
        } else {
            self.advance(tick)
        };
        let expected_reason = if self.hard_fault.is_none() {
            self.earliest_fault()
                .filter(|(deadline, _)| now >= *deadline)
        } else {
            None
        };
        let expected = if expected_reason.is_some() {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.fault_expired(now);
        assert_eq!(OutcomeClass::of(&result), expected);
        if expected == OutcomeClass::Success {
            let reason = result
                .as_ref()
                .expect("the oracle predicted an explicit timeout");
            let (_, expected_reason) =
                expected_reason.expect("timeout requires an expired intake obligation");
            assert_eq!(reason, &expected_reason);
            self.enter_fault(expected_reason);
        }
        ActionOutcome::new(expected, None)
    }

    fn implicit_timeout(&mut self, step: u64, tick: u8, before_deadline: bool) -> ActionOutcome {
        let now = if let Some((deadline, _)) = self.earliest_fault() {
            let target = if before_deadline {
                deadline.saturating_sub(1)
            } else {
                deadline
            };
            self.advance_to(target)
        } else {
            self.advance(tick)
        };
        let id = self.digest(b"implicit-timeout", step);
        let account = self.accounts[0].public_key();
        let observation = self.predict_observation(now);
        let result = self.chain.record_deposit(now, id, account, 0);
        assert_eq!(OutcomeClass::of(&result), OutcomeClass::Error);
        self.apply_observation(now, &observation);
        ActionOutcome::new(OutcomeClass::Error, Some(&observation))
    }

    fn challenge_evidence(
        &self,
        family: u8,
        context: &TestContext,
        batch: BatchId<Digest>,
        opening: &TestCache,
        close: &TestClose,
    ) -> (TestChallenge, ChallengeKind) {
        let account = &self.accounts[usize::from(family) % self.accounts.len()];
        let recipient = account.public_key();
        let previous_debit = close
            .rows
            .iter()
            .find(|row| row.account == recipient)
            .map_or_else(
                || {
                    opening
                        .leaves()
                        .iter()
                        .find(|leaf| leaf.account == recipient)
                        .map_or(0, |leaf| leaf.state.cumulative_debit)
                },
                |row| row.closing.cumulative_debit,
            );
        let shard = u64::from(family);
        match family % 4 {
            0 => (
                Challenge::LatestAcknowledgedSend {
                    batch,
                    payment: Box::new(linked_payment(
                        context,
                        &self.operator,
                        account,
                        &recipient,
                        1,
                        previous_debit,
                        shard,
                    )),
                    payer: Box::new(account_lookup(opening, close, &recipient)),
                },
                ChallengeKind::LatestAcknowledgedSend,
            ),
            1 => {
                let position = close
                    .rows
                    .binary_search_by(|row| row.account.cmp(&recipient));
                let shard_lookup = match position {
                    Ok(position) => close.shard_sets[position]
                        .lookup::<Sha256>(shard)
                        .expect("canonical shard set has a bounded lookup"),
                    Err(_) => ShardSet::empty(context.payment().epoch(), recipient.clone())
                        .lookup::<Sha256>(shard)
                        .expect("empty shard set has a canonical absence proof"),
                };
                (
                    Challenge::HigherShardTip {
                        batch,
                        payment: Box::new(linked_payment(
                            context,
                            &self.operator,
                            account,
                            &recipient,
                            1,
                            previous_debit,
                            shard,
                        )),
                        recipient: Box::new(account_lookup(opening, close, &recipient)),
                        shard: Box::new(shard_lookup),
                    },
                    ChallengeKind::HigherShardTip,
                )
            }
            2 => (
                Challenge::InconsistentReceiptRange {
                    batch,
                    upper: Box::new(endpoint_payment(
                        context,
                        &self.operator,
                        account,
                        &recipient,
                        1,
                        previous_debit,
                        shard,
                        0,
                        0,
                    )),
                    lower: RangeLower::ShardStart,
                },
                ChallengeKind::InconsistentReceiptRange,
            ),
            _ => (
                Challenge::receipt_fork(
                    batch,
                    linked_payment(
                        context,
                        &self.operator,
                        account,
                        &recipient,
                        1,
                        previous_debit,
                        shard,
                    ),
                    linked_payment(
                        context,
                        &self.operator,
                        account,
                        &recipient,
                        2,
                        previous_debit,
                        shard,
                    ),
                ),
                ChallengeKind::ReceiptFork,
            ),
        }
    }

    fn challenge(
        &mut self,
        step: u64,
        tick: u8,
        slot_selector: u8,
        encoded: bool,
        mutation: u8,
    ) -> ActionOutcome {
        let now = self.advance(tick);
        let selected = if self.slots.is_empty() {
            None
        } else {
            self.slots
                .get(usize::from(slot_selector) % self.slots.len())
                .map(|slot| {
                    (
                        slot.context.clone(),
                        slot.batch_id(),
                        slot.opening.clone(),
                        slot.close.clone(),
                    )
                })
        };
        let (context, batch, opening, close) = selected.unwrap_or_else(|| {
            let prepared = self.make_prepared();
            (
                prepared.context,
                prepared.close.header.batch_id::<Sha256>(),
                prepared.opening,
                prepared.close,
            )
        });
        let family = mutation % 4;
        let variant = (mutation / 4) % 4;
        let submitted_batch = if variant == 1 || (!encoded && variant != 0) {
            BatchId::new(self.digest(b"unknown-batch", step))
        } else {
            batch
        };
        let (challenge, kind) =
            self.challenge_evidence(family, &context, submitted_batch, &opening, &close);
        let canonical = challenge.encode().to_vec();
        let mut bytes = canonical.clone();
        let maximum = if encoded && variant == 2 {
            canonical
                .len()
                .checked_sub(1)
                .expect("a challenge encoding is nonempty")
        } else {
            canonical.len()
        };
        if encoded && variant == 3 {
            bytes.clear();
        }
        let payload_is_valid =
            variant == 0 && (!encoded || (bytes == canonical && maximum >= canonical.len()));
        let observation = self.predict_observation(now);
        let expected_kind = self
            .slots
            .iter()
            .find(|slot| slot.batch_id() == submitted_batch)
            .filter(|slot| {
                !self.settled
                    && payload_is_valid
                    && slot.context == context
                    && matches!(slot.status, BatchStatus::Pending)
                    && now <= slot.context.challenge_deadline()
            })
            .map(|_| kind);
        let result = if encoded {
            self.chain.challenge_encoded(now, &bytes, maximum)
        } else {
            self.chain.challenge(now, &challenge)
        };
        match (&expected_kind, &result) {
            (Some(expected), Ok(Verdict::Proven(actual))) => assert_eq!(actual, expected),
            (None, Err(_)) => {}
            (Some(_), Ok(Verdict::NoContradiction)) => {
                panic!("canonical challenge evidence must be proven")
            }
            (expected, actual) => panic!(
                "challenge outcome disagreed with the oracle: expected {expected:?}, got {actual:?}"
            ),
        }
        self.apply_observation(now, &observation);
        let class = if let Some(kind) = expected_kind {
            self.apply_proven(submitted_batch, kind);
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        ActionOutcome::new(class, Some(&observation))
    }

    fn apply_proven(&mut self, batch: BatchId<Digest>, kind: ChallengeKind) {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.batch_id() == batch)
            .expect("proven challenge targets an admitted batch");
        assert!(matches!(self.slots[index].status, BatchStatus::Pending));
        self.slots[index].status = BatchStatus::Challenged(kind);
        for descendant in self.slots.iter_mut().skip(index + 1) {
            descendant.status = BatchStatus::Invalidated(batch);
        }
        self.invalid_from = Some(batch);
        self.enter_fault(HardFaultReason::ProvenChallenge {
            batch_id: batch,
            kind,
        });
    }

    fn claim_pending_deposit(&mut self, tick: u8, account_selector: u8) -> ActionOutcome {
        let now = self.advance(tick);
        let observation = self.predict_observation(now);
        let terminal_started = self.hard_fault_settlement.is_some();
        let account =
            self.accounts[usize::from(account_selector) % self.accounts.len()].public_key();
        let amount = self.staged_deposits.get(&account).copied();
        let expected = if (self.hard_fault.is_some() || observation.fault.is_some())
            && !self.settled
            && amount.is_some()
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.claim_pending_deposit(now, &account);
        assert_eq!(OutcomeClass::of(&result), expected);
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            let amount = amount.expect("the oracle required a queued deposit");
            let refund = result.expect("the oracle predicted a deposit refund");
            assert_eq!(refund.account, account);
            assert_eq!(refund.amount, amount);
            assert_eq!(self.staged_deposits.remove(&refund.account), Some(amount));
            if terminal_started {
                assert!(!self.staged_deposit_deadlines.contains_key(&refund.account));
            } else {
                assert!(
                    self.staged_deposit_deadlines
                        .remove(&refund.account)
                        .is_some()
                );
            }
            self.custody = self
                .custody
                .checked_sub(amount)
                .expect("queued deposits are held in custody");
            self.finish_hard_fault_if_drained();
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    fn begin_hard_fault_settlement(&mut self) -> ActionOutcome {
        let replay = self.hard_fault_settlement.clone();
        let expected = if self.hard_fault.is_some()
            && !self.settled
            && !self
                .slots
                .front()
                .is_some_and(|slot| matches!(slot.status, BatchStatus::Pending))
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let before = self.snapshot();
        let unfinalized_deposit_total = self.unfinalized_deposit_total();
        let result = self.chain.begin_hard_fault_settlement();
        assert_eq!(OutcomeClass::of(&result), expected);
        if expected == OutcomeClass::Success {
            let settlement = result
                .as_ref()
                .expect("the oracle predicted a frozen settlement boundary");
            assert_eq!(settlement.reason, self.hard_fault.clone().unwrap());
            assert_eq!(settlement.admission_fence_epoch, self.fence.unwrap());
            assert_eq!(settlement.invalid_from, self.invalid_from);
            assert_eq!(settlement.frozen_state_root, self.finalized.root());
            assert_eq!(settlement.state_liability, self.finalized.liability());
            assert_eq!(
                settlement.unfinalized_deposit_total,
                unfinalized_deposit_total
            );
            assert_eq!(settlement.custody_balance, self.custody);

            if let Some(replay) = replay {
                assert_eq!(settlement, &replay);
                assert_eq!(before, self.snapshot());
            } else {
                for slot in &self.slots {
                    for record in slot.deposits.records() {
                        let aggregate = self
                            .staged_deposits
                            .get(record.account())
                            .copied()
                            .unwrap_or(0)
                            .checked_add(record.amount())
                            .expect("bounded terminal deposits cannot overflow");
                        self.staged_deposits
                            .insert(record.account().clone(), aggregate);
                    }
                }
                self.slots.clear();
                self.registered = None;
                self.staged_deposit_deadlines.clear();
                self.staged_withdrawals.clear();
                self.withdrawal_replays.clear();
                self.hard_fault_settlement = Some(settlement.clone());
                assert_eq!(self.unfinalized_deposit_total(), unfinalized_deposit_total);
                self.finish_hard_fault_if_drained();
            }
        }
        ActionOutcome::new(expected, None)
    }

    fn claim_hard_fault(&mut self, account_selector: u8, mutation: u8) -> ActionOutcome {
        let (opening, selected) = self.hard_fault_opening(account_selector, mutation);
        let canonical = mutation % 4 == 0;
        let expected = if self.hard_fault.is_some()
            && self.hard_fault_settlement.is_some()
            && !self.settled
            && canonical
            && selected
                .as_ref()
                .is_some_and(|leaf| !self.claimed_hard_fault_accounts.contains(&leaf.account))
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.claim_hard_fault(&opening);
        assert_eq!(OutcomeClass::of(&result), expected);
        if expected == OutcomeClass::Success {
            let leaf = selected.expect("a canonical terminal claim selects one live leaf");
            let request = self.outstanding.get(&leaf.account).cloned();
            let withdrawal_amount =
                request
                    .as_ref()
                    .map_or(0, |request| match request.body().action() {
                        WithdrawalAction::Amount(amount) => amount.get(),
                        WithdrawalAction::Close => leaf.state.balance,
                    });
            let expected_withdrawal = request.clone().map(|request| WithdrawalRelease {
                request,
                amount: withdrawal_amount,
            });
            let release = result.expect("the oracle predicted a terminal state release");
            assert_eq!(release.account, leaf.account);
            assert_eq!(release.withdrawal, expected_withdrawal);
            assert_eq!(release.residual, leaf.state.balance - withdrawal_amount);
            assert_eq!(release.released_custody, leaf.state.balance);

            assert!(
                self.claimed_hard_fault_accounts
                    .insert(leaf.account.clone())
            );
            if let Some(request) = request {
                assert_eq!(self.outstanding.remove(&leaf.account), Some(request));
            }
            self.custody = self
                .custody
                .checked_sub(leaf.state.balance)
                .expect("authenticated state claims are held in active custody");
            self.finish_hard_fault_if_drained();
        }
        ActionOutcome::new(expected, None)
    }

    fn hard_fault_opening(
        &self,
        account_selector: u8,
        mutation: u8,
    ) -> (
        StateOpening<VerifyingKey, Digest>,
        Option<StateLeaf<VerifyingKey>>,
    ) {
        let selected = (!self.finalized.is_empty()).then(|| {
            self.finalized.leaves()[usize::from(account_selector) % self.finalized.len()].clone()
        });
        let mut opening = if let Some(leaf) = &selected {
            self.finalized
                .opening(&leaf.account)
                .expect("a selected finalized leaf has an opening")
        } else {
            let fallback = wrong_cache(&self.finalized);
            fallback
                .opening(&fallback.leaves()[0].account)
                .expect("the fallback cache has one live leaf")
        };

        match mutation % 4 {
            0 => {}
            1 => {
                opening.leaf.state.balance = if opening.leaf.state.balance == u64::MAX {
                    u64::MAX - 1
                } else {
                    opening.leaf.state.balance + 1
                };
            }
            2 => opening.leaf.state.active = false,
            _ => {
                let malformed = wrong_cache(&self.finalized);
                let account = selected.as_ref().map_or_else(
                    || malformed.leaves()[0].account.clone(),
                    |leaf| leaf.account.clone(),
                );
                opening = malformed
                    .opening(&account)
                    .expect("a root-mutated cache retains the selected account");
            }
        }
        (opening, selected)
    }
}

fn release_total(releases: &[WithdrawalRelease<VerifyingKey, Digest>]) -> u64 {
    releases
        .iter()
        .try_fold(0_u64, |total, release| total.checked_add(release.amount))
        .expect("authenticated withdrawal releases fit custody")
}

fn expected_external_payouts(
    close: &TestClose,
    deposits: &TestDeposits,
    withdrawals: &TestWithdrawals,
) -> Vec<ExternalPayout<VerifyingKey>> {
    close
        .rows
        .iter()
        .filter_map(|row| {
            if row.opening != AccountState::default()
                || row.closing.active
                || row.closing.balance != 0
                || row.outgoing.is_some()
                || deposits.amount_for(&row.account) != 0
                || withdrawals.request_for(&row.account).is_some()
            {
                return None;
            }

            let (debit, credit, receipts) = row
                .checked_deltas()
                .expect("validated payout row counters are monotonic");
            assert_eq!(debit, 0);
            assert!(credit > 0);
            assert!(receipts > 0);
            assert!(row.credit_root.len > 0);
            assert_eq!(row.credit_root.total_credit, credit);
            assert_eq!(row.credit_root.total_receipts, receipts);
            Some(ExternalPayout {
                recipient: row.account.clone(),
                amount: credit,
            })
        })
        .collect()
}

fn payout_total(payouts: &[ExternalPayout<VerifyingKey>]) -> u64 {
    payouts
        .iter()
        .try_fold(0_u64, |total, payout| total.checked_add(payout.amount))
        .expect("authenticated external payouts fit custody")
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
            WithdrawalAction::Close => opening
                .balance
                .checked_add(deposit)
                .expect("bounded closing balance"),
        });
        let mut closing = opening;
        closing.balance = opening
            .balance
            .checked_add(deposit)
            .and_then(|balance| balance.checked_sub(applied))
            .expect("sanitized boundary remains affordable");
        closing.active = closing.balance > 0;
        let shards = ShardSet::empty(context.payment().epoch(), account.clone());
        prefix = prefix
            .checked_extend(Prefix {
                deposit,
                withdrawal: applied,
                withdrawals: u64::from(withdrawal.is_some()),
                ..Prefix::default()
            })
            .expect("bounded close totals cannot overflow");
        rows.push(AccountRow {
            account,
            opening,
            closing,
            outgoing: None,
            credit_root: shards.root::<Sha256>().expect("empty shard set commits"),
            prefix,
        });
        shard_sets.push(shards);
    }
    let close =
        build_close::<Sha256, _, _>(cache, context, deposits, withdrawals, rows, shard_sets)
            .expect("sanitized boundary close must build");
    let closing = closing_cache(cache, &close);
    (close, closing)
}

fn closing_cache(cache: &TestCache, close: &TestClose) -> TestCache {
    let changed = close
        .rows
        .iter()
        .map(|row| row.account.clone())
        .collect::<BTreeSet<_>>();
    let mut leaves = cache
        .leaves()
        .iter()
        .filter(|leaf| !changed.contains(&leaf.account))
        .cloned()
        .collect::<Vec<_>>();
    leaves.extend(
        close
            .rows
            .iter()
            .filter(|row| row.closing.active)
            .map(|row| StateLeaf {
                account: row.account.clone(),
                state: row.closing,
            }),
    );
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    let closing = StateCache::new::<Sha256>(leaves).expect("closing live state remains canonical");
    assert_eq!(closing.root(), close.roots.closing);
    closing
}

fn account_lookup(
    opening: &TestCache,
    close: &TestClose,
    account: &VerifyingKey,
) -> AccountLookup<VerifyingKey, Digest> {
    let count = u32::try_from(close.rows.len()).expect("fuzz close rows are bounded");
    let mut builder = commitment::Builder::<Sha256>::new(VectorKind::Change, count)
        .expect("bounded change vector");
    for row in &close.rows {
        builder
            .add_encoded(row.encode().as_ref())
            .expect("row encoding is length-framable");
    }
    let tree = builder
        .build(&Sequential)
        .expect("complete change vector builds");
    assert_eq!(tree.root(), close.roots.change);
    match close.rows.binary_search_by(|row| row.account.cmp(account)) {
        Ok(position) => AccountLookup::Present(Box::new(RowOpening {
            row: close.rows[position].clone(),
            proof: tree
                .opening(position as u32)
                .expect("present row position is in range"),
        })),
        Err(insertion) => {
            let row_opening = |position: usize| {
                Box::new(RowOpening {
                    row: close.rows[position].clone(),
                    proof: tree
                        .opening(position as u32)
                        .expect("neighbor row position is in range"),
                })
            };
            let state: StateLookup<VerifyingKey, Digest> = opening
                .lookup(account)
                .expect("bounded state lookup must construct");
            AccountLookup::Absent {
                state: Box::new(state),
                predecessor: insertion.checked_sub(1).map(row_opening),
                successor: (insertion < close.rows.len()).then(|| row_opening(insertion)),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn linked_payment(
    context: &TestContext,
    operator: &SigningKey,
    payer: &SigningKey,
    recipient: &VerifyingKey,
    amount: u64,
    previous_debit: u64,
    shard: u64,
) -> Payment<VerifyingKey, Digest> {
    let send = SignedSend::sign_next(
        context.payment(),
        payer,
        recipient.clone(),
        amount,
        previous_debit,
    )
    .expect("positive bounded send signs");
    let receipt =
        SignedReceipt::issue_next::<Sha256, _>(context.payment(), &send, shard, 0, 0, operator)
            .expect("positive bounded receipt issues");
    Payment::new::<Sha256>(context.payment(), send, receipt)
        .expect("honestly linked payment verifies")
}

#[allow(clippy::too_many_arguments)]
fn endpoint_payment(
    context: &TestContext,
    operator: &SigningKey,
    payer: &SigningKey,
    recipient: &VerifyingKey,
    amount: u64,
    previous_debit: u64,
    shard: u64,
    credit: u64,
    index: u64,
) -> Payment<VerifyingKey, Digest> {
    let send = SignedSend::sign_next(
        context.payment(),
        payer,
        recipient.clone(),
        amount,
        previous_debit,
    )
    .expect("positive bounded send signs");
    let receipt = SignedReceipt::sign_body_by_authority(
        ReceiptBody::from_raw_unchecked(
            *context.payment().anchor(),
            context.payment().epoch(),
            recipient.clone(),
            shard,
            amount,
            send.tx_id::<Sha256>(),
            credit,
            index,
        ),
        operator,
    );
    Payment::new::<Sha256>(context.payment(), send, receipt)
        .expect("authority-signed endpoint remains linked")
}

fn wrong_cache(cache: &TestCache) -> TestCache {
    let mut leaves = cache.leaves().to_vec();
    if let Some(leaf) = leaves.first_mut() {
        leaf.state.balance = if leaf.state.balance == u64::MAX {
            u64::MAX - 1
        } else {
            leaf.state.balance + 1
        };
    } else {
        leaves.push(StateLeaf {
            account: SigningKey::from_seed(u64::MAX).public_key(),
            state: AccountState {
                balance: 1,
                active: true,
                ..AccountState::default()
            },
        });
    }
    let mutated = StateCache::new::<Sha256>(leaves)
        .expect("a guaranteed-distinct survivor remains structurally valid");
    assert_ne!(mutated.root(), cache.root());
    mutated
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let Ok(mut input) = FuzzInput::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };
    input.actions.truncate(MAX_ACTIONS);
    Harness::new(&input).run(&input.actions);
});
