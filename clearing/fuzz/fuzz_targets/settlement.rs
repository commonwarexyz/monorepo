#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{
        Committee, assigned_slice_indices,
        curve25519::{Certificate, Scheme as AdmissionScheme},
        seal,
    },
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalBatch, WithdrawalId},
    challenge::{
        AccountLookup, Challenge, ChallengeKind, RangeLower, RowOpening, StateOpening, Verdict,
    },
    commitment::{self, VectorKind, VectorRoot},
    credit::ShardSet,
    payment::{Payment, ReceiptBody, SignedReceipt, SignedSend},
    settlement::{
        BatchStatus, FaultPayout, HardFaultReason, PendingBatch, SettlementChain, SettlementConfig,
        WithdrawalRelease,
    },
    state::{AccountRow, AccountState, Prefix, StateLeaf},
    transition::{
        Assignment, BatchId, Close, CloseContext, CloseLimits, StateCache, assemble_slices,
        build_close, validate_close,
    },
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    curve25519::{BatchVerifier as PaymentBatchVerifier, SigningKey, VerifyingKey},
    sha256::Digest,
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
        full_close: bool,
        mutation: u8,
    },
    Register {
        tick: u8,
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
    SettleHardFault {
        mutated_survivor: bool,
    },
    Reconfigure {
        tick: u8,
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
    header: commonware_clearing::bajillion::transition::Header<VerifyingKey, Digest>,
    certificate: Certificate,
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
    registry: Vec<VerifyingKey>,
    custody: u64,
    deposits: TestDeposits,
    withdrawals: TestWithdrawals,
    safety_roots: Vec<VectorRoot<Digest>>,
    batches: Vec<PendingBatch<VerifyingKey, Digest>>,
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
    validator: AdmissionScheme<VerifyingKey>,
    committee: Committee<VerifyingKey>,
    committee_digest: Digest,
    accounts: Vec<SigningKey>,
    now: u64,
    finalized: TestCache,
    expected_epoch: u64,
    slots: VecDeque<Slot>,
    registered: Option<Prepared>,
    staged_deposits: BTreeMap<VerifyingKey, u64>,
    staged_withdrawals: BTreeMap<VerifyingKey, WithdrawalRelease<VerifyingKey, Digest>>,
    outstanding: BTreeMap<VerifyingKey, WithdrawalRelease<VerifyingKey, Digest>>,
    consumed_deposit_ids: BTreeSet<Digest>,
    withdrawal_replays: BTreeMap<WithdrawalId<Digest>, u64>,
    authorization_history: Vec<SignedWithdrawal<VerifyingKey, Digest>>,
    custody: u64,
    hard_fault: Option<HardFaultReason<VerifyingKey, Digest>>,
    fence: Option<u64>,
    invalid_from: Option<BatchId<Digest>>,
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
        let validator_key = SigningKey::from_seed(input.seed ^ 0x5a5a_5a5a_5a5a_5a5a);
        let committee = Committee::new(vec![validator_key.public_key()])
            .expect("one validator is an exact 3f+1 committee");
        let committee_digest = committee.commitment::<Sha256>();
        let validator = AdmissionScheme::signer(committee.clone(), validator_key)
            .expect("deterministic validator belongs to its committee");
        let config = SettlementConfig::new(
            NonZeroUsize::new(MAX_PENDING_EPOCHS).unwrap(),
            NonZeroU64::new(MINIMUM_WITHDRAWAL_NOTICE).unwrap(),
            NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).unwrap(),
            NonZeroUsize::new(MAX_ACCOUNTS).unwrap(),
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
            committee,
            committee_digest,
            accounts,
            now: 0,
            finalized,
            expected_epoch: 0,
            slots: VecDeque::new(),
            registered: None,
            staged_deposits: BTreeMap::new(),
            staged_withdrawals: BTreeMap::new(),
            outstanding: BTreeMap::new(),
            consumed_deposit_ids: BTreeSet::new(),
            withdrawal_replays: BTreeMap::new(),
            authorization_history: Vec::new(),
            custody,
            hard_fault: None,
            fence: None,
            invalid_from: None,
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
                full_close,
                mutation,
            } => self.withdrawal(
                *tick,
                *account,
                *amount,
                *destination,
                *destination_len,
                *full_close,
                *mutation,
            ),
            Action::Register { tick, mutated } => self.register(*tick, *mutated),
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
            Action::SettleHardFault { mutated_survivor } => {
                self.settle_hard_fault(*mutated_survivor)
            }
            Action::Reconfigure {
                tick,
                account,
                mutation,
            } => self.reconfigure(*tick, *account, *mutation),
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
            registry: self.chain.current_registry().to_vec(),
            custody: self.chain.custody_balance(),
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
        assert_eq!(self.chain.current_state_root(), self.finalized.root());
        assert_eq!(self.chain.custody_balance(), self.custody);
        assert_eq!(self.chain.pending_deposits(), self.deposit_batch());
        assert_eq!(self.chain.pending_withdrawals(), self.withdrawal_batch());
        assert_eq!(self.chain.hard_fault(), self.hard_fault.as_ref());
        assert_eq!(self.chain.admission_fence_epoch(), self.fence);
        assert_eq!(self.chain.invalid_from(), self.invalid_from);
        assert_eq!(self.chain.hard_fault_is_settled(), self.settled);

        let registry = self
            .finalized
            .leaves()
            .iter()
            .map(|leaf| leaf.account.clone())
            .collect::<Vec<_>>();
        assert_eq!(self.chain.current_registry(), registry);

        let expected_batches = self
            .slots
            .iter()
            .map(|slot| PendingBatch {
                header: slot.header.clone(),
                certificate: slot.certificate.clone(),
                status: slot.status.clone(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            self.chain.pending_batches().cloned().collect::<Vec<_>>(),
            expected_batches
        );

        let mut roots = vec![self.finalized.root()];
        roots.extend(self.slots.iter().map(|slot| slot.closing.root()));
        assert_eq!(self.chain.withdrawal_safety_roots(), roots);

        let mut opening_root = self.finalized.root();
        let mut opening_liability = self.finalized.liability();
        for (offset, slot) in self.slots.iter().enumerate() {
            assert_eq!(slot.opening.root(), slot.header.opening_root);
            assert_eq!(slot.close.header, slot.header);
            assert_eq!(
                slot.context.payment().epoch(),
                self.expected_epoch + offset as u64
            );
            assert_eq!(slot.header.context, *slot.context.payment());
            assert_eq!(slot.header.opening_root, opening_root);
            assert_eq!(slot.header.opening_liability, opening_liability);
            assert_eq!(slot.header.closing_root, slot.closing.root());
            assert_eq!(slot.header.closing_liability, slot.closing.liability());
            assert_eq!(
                slot.header.totals.withdrawal,
                release_total(&slot.withdrawal_releases)
            );
            opening_root = slot.closing.root();
            opening_liability = slot.closing.liability();
        }

        let staged_deposit_total = self
            .staged_deposits
            .values()
            .try_fold(0_u64, |total, amount| total.checked_add(*amount))
            .expect("bounded staged deposits cannot overflow the model");
        let unfinalized_deposits = self
            .slots
            .iter()
            .try_fold(staged_deposit_total, |total, slot| {
                total.checked_add(slot.deposits.total())
            })
            .expect("bounded deposits cannot overflow the model");
        assert_eq!(
            self.finalized
                .liability()
                .checked_add(unfinalized_deposits)
                .expect("bounded custody equation cannot overflow"),
            self.custody
        );

        for account in &self.accounts {
            let public = account.public_key();
            assert_eq!(
                self.chain.pending_withdrawal_deadline(&public),
                self.outstanding
                    .get(&public)
                    .map(|release| release.request.body().deadline())
            );
        }
        for (account, release) in &self.staged_withdrawals {
            assert_eq!(self.outstanding.get(account), Some(release));
            let tail_balance = self
                .tail_cache()
                .leaves()
                .iter()
                .find(|leaf| &leaf.account == account)
                .expect("staged withdrawal account remains registered")
                .state
                .balance;
            let expected_amount = if release.request.body().full_close() {
                tail_balance
                    .checked_add(self.staged_deposits.get(account).copied().unwrap_or(0))
                    .expect("bounded staged full-close amount")
            } else {
                release.request.body().amount()
            };
            assert_eq!(release.amount, expected_amount);
        }
        if self.settled {
            assert_eq!(self.custody, 0);
            assert!(self.slots.is_empty());
            assert!(self.staged_deposits.is_empty());
            assert!(self.staged_withdrawals.is_empty());
            assert!(self.outstanding.is_empty());
            assert!(
                self.finalized
                    .leaves()
                    .iter()
                    .all(|leaf| !leaf.state.active && leaf.state.balance == 0)
            );
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
            self.earliest_outstanding()
                .filter(|(deadline, _)| now >= *deadline)
                .map(|(deadline, account)| ObservedFault {
                    reason: HardFaultReason::ExpiredWithdrawal {
                        account,
                        expired_at: deadline,
                    },
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
            .map(|(account, release)| (release.request.body().deadline(), account.clone()))
            .min()
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

    fn unknown_account(&self) -> VerifyingKey {
        SigningKey::from_seed(self.seed.wrapping_add(10_000)).public_key()
    }

    fn deposit_batch(&self) -> TestDeposits {
        DepositBatch::new(
            self.staged_deposits
                .iter()
                .filter_map(|(account, amount)| {
                    let deferred = self.staged_withdrawals.get(account).is_some_and(|release| {
                        !release.request.body().full_close()
                            && release.request.body().amount() == *amount
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

    fn withdrawal_batch(&self) -> TestWithdrawals {
        WithdrawalBatch::new(
            self.staged_withdrawals
                .values()
                .map(|release| release.request.clone())
                .collect(),
        )
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
        CloseContext::new::<Sha256>(
            self.deployment,
            epoch,
            self.operator.public_key(),
            cache,
            deposits,
            withdrawals,
            admission_deadline,
            challenge_deadline,
            CloseLimits::protocol_maximum(),
            Assignment::new(self.committee_digest, 0).unwrap(),
        )
        .expect("sanitized close context must be valid")
    }

    fn make_prepared(&self) -> Prepared {
        let cache = self.tail_cache();
        let deposits = self.deposit_batch();
        let withdrawals = self.withdrawal_batch();
        let withdrawal_releases = self
            .staged_withdrawals
            .values()
            .cloned()
            .collect::<Vec<_>>();
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
        assert_eq!(
            close.header.totals.withdrawal,
            release_total(&withdrawal_releases)
        );
        Prepared {
            opening: cache.clone(),
            context,
            deposits,
            withdrawals,
            withdrawal_releases,
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
            self.tail_cache(),
            &prepared.context,
            &prepared.deposits,
            &prepared.withdrawals,
            &prepared.close,
            &Sequential,
        )
        .expect("sanitized close slices must build");
        let assigned = assigned_slice_indices::<Sha256, _>(
            &self.committee,
            prepared.context.assignment(),
            self.validator.me().expect("validator can sign"),
        )
        .expect("committee-bound assignment must derive")
        .into_iter()
        .map(|index| slices[usize::from(index)].clone())
        .collect::<Vec<_>>();
        let (vote, retained) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &self.validator,
            &self.committee,
            &prepared.context,
            &prepared.deposits,
            &prepared.withdrawals,
            &prepared.close.header,
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
            .assemble_exact([vote], &Sequential)
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
            2 => account = self.unknown_account(),
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
        let expected = if self.operates_after(&observation)
            && self.registered.is_none()
            && amount != 0
            && self
                .finalized
                .leaves()
                .iter()
                .any(|leaf| leaf.account == account)
            && !self.consumed_deposit_ids.contains(&id)
            && self.consumed_deposit_ids.len() < MAX_DEPOSIT_IDS
            && aggregate.is_some()
            && self
                .staged_withdrawals
                .get(&account)
                .filter(|release| release.request.body().full_close())
                .is_none_or(|release| release.amount.checked_add(amount).is_some())
            && self.custody.checked_add(amount).is_some()
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.record_deposit(now, id, account.clone(), amount);
        assert_eq!(OutcomeClass::of(&result), expected);
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            if let Some(release) = self.staged_withdrawals.get_mut(&account)
                && release.request.body().full_close()
            {
                release.amount = release
                    .amount
                    .checked_add(amount)
                    .expect("the oracle checked full-close release aggregation");
                self.outstanding.insert(account.clone(), release.clone());
            }
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
        wants_full_close: bool,
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
        let mut full_close = wants_full_close;
        let mut amount = if full_close {
            minimum_balance.checked_add(1).map_or_else(
                || u64::from(raw_amount),
                |range| u64::from(raw_amount).wrapping_rem(range),
            )
        } else {
            u64::from(raw_amount).wrapping_rem(minimum_balance) + 1
        };
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
                    full_close = false;
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
                        full_close = false;
                        amount = 1;
                        let request = SignedWithdrawal::sign(
                            deployment,
                            root,
                            destination.clone(),
                            amount,
                            full_close,
                            deadline,
                            depositing_key,
                        )
                        .expect("positive withdrawal must sign");
                        replay = Some(request);
                    }
                } else {
                    deadline = now;
                }
            }
        }
        let request = replay.unwrap_or_else(|| {
            SignedWithdrawal::sign(
                deployment,
                root,
                destination,
                amount,
                full_close,
                deadline,
                &key,
            )
            .expect("sanitized withdrawal must sign")
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
        let clean_amount = if request.body().full_close() {
            openings.last().and_then(|opening| {
                opening
                    .leaf
                    .state
                    .balance
                    .checked_add(self.staged_deposits.get(&account).copied().unwrap_or(0))
            })
        } else {
            Some(request.body().amount())
        };
        let result = self
            .chain
            .queue_withdrawal(now, request.clone(), &openings, |_| eligible);
        assert_eq!(OutcomeClass::of(&result), expected);
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            let request_id = request.id::<Sha256>();
            let release = WithdrawalRelease {
                request: request.clone(),
                amount: clean_amount
                    .expect("successful withdrawal authenticates the tail safety opening"),
            };
            assert!(!self.withdrawal_replays.contains_key(&request_id));
            assert!(
                self.staged_withdrawals
                    .insert(account.clone(), release.clone())
                    .is_none()
            );
            assert!(self.outstanding.insert(account, release).is_none());
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
        expected_openings
            .iter()
            .all(|opening| opening.leaf.state.active && body.amount() <= opening.leaf.state.balance)
    }

    fn register(&mut self, tick: u8, mutated: bool) -> ActionOutcome {
        let now = self.advance(tick);
        let prepared = self.make_prepared();
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
        let certificate = self.certificate(&prepared);
        let retained_certificate = certificate.clone();
        let mut header = prepared.close.header.clone();
        let terminal = terminal_opening(&prepared.close);
        if mutated {
            header.closing_liability ^= 1;
        }
        let observation = self.predict_observation(now);
        let expected = if self.operates_after(&observation)
            && self.slots.len() < MAX_PENDING_EPOCHS
            && self.registered.as_ref().is_some_and(|registered| {
                now <= registered.context.admission_deadline() && header == registered.close.header
            }) {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let mut rng = test_rng();
        let result = self.chain.admit(
            now,
            header,
            certificate,
            terminal.as_ref(),
            &mut rng,
            &Sequential,
        );
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
            }
            self.slots.push_back(Slot {
                opening: registered.opening,
                close: registered.close.clone(),
                context: registered.context,
                deposits: registered.deposits,
                withdrawal_releases: registered.withdrawal_releases,
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
        let expected = if !self.settled
            && self.slots.front().is_some_and(|front| {
                matches!(front.status, BatchStatus::Pending)
                    && now > front.context.challenge_deadline()
                    && front.context.payment().epoch() == self.expected_epoch
            }) {
            OutcomeClass::Success
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
            assert_eq!(finalized.released_withdrawals, slot.withdrawal_releases);
            assert_eq!(
                finalized.custody_balance,
                self.custody
                    .checked_sub(release_total(&slot.withdrawal_releases))
                    .expect("the model holds admitted withdrawal custody")
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
                .expect("admitted withdrawals are held in custody");
            for release in &slot.withdrawal_releases {
                assert_eq!(
                    self.outstanding.remove(release.request.account()),
                    Some(release.clone())
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
        let now = if let Some((deadline, _)) = self.earliest_outstanding() {
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
            self.earliest_outstanding()
                .filter(|(deadline, _)| now >= *deadline)
        } else {
            None
        };
        let expected = if expected_reason.is_some() {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.fault_expired_withdrawal(now);
        assert_eq!(OutcomeClass::of(&result), expected);
        if expected == OutcomeClass::Success {
            let reason = result
                .as_ref()
                .expect("the oracle predicted an explicit timeout");
            let (deadline, account) =
                expected_reason.expect("timeout requires an expired withdrawal");
            let expected_reason = HardFaultReason::ExpiredWithdrawal {
                account,
                expired_at: deadline,
            };
            assert_eq!(reason, &expected_reason);
            self.enter_fault(expected_reason);
        }
        ActionOutcome::new(expected, None)
    }

    fn implicit_timeout(&mut self, step: u64, tick: u8, before_deadline: bool) -> ActionOutcome {
        let now = if let Some((deadline, _)) = self.earliest_outstanding() {
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
        let account = self.finalized.leaves()[0].account.clone();
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
        let leaf = &opening.leaves()[usize::from(family) % opening.len()];
        let account = self
            .accounts
            .iter()
            .find(|key| key.public_key() == leaf.account)
            .expect("every registered fuzz account retains its signing key");
        let recipient = account.public_key();
        let previous_debit = leaf.state.cumulative_debit;
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

    fn settle_hard_fault(&mut self, mutated_survivor: bool) -> ActionOutcome {
        let survivor = if mutated_survivor {
            wrong_cache(&self.finalized)
        } else {
            self.finalized.clone()
        };
        let expected = if self.hard_fault.is_some()
            && !self.settled
            && !self
                .slots
                .front()
                .is_some_and(|slot| matches!(slot.status, BatchStatus::Pending))
            && Self::same_cache(&survivor, &self.finalized)
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let expected_terminal = (expected == OutcomeClass::Success).then(|| self.terminal_state());
        let custody = self.custody;
        let result = self.chain.settle_hard_fault(&survivor);
        assert_eq!(OutcomeClass::of(&result), expected);
        if expected == OutcomeClass::Success {
            let settlement = result
                .as_ref()
                .expect("the oracle predicted terminal settlement");
            assert_eq!(settlement.reason, self.hard_fault.clone().unwrap());
            assert_eq!(settlement.admission_fence_epoch, self.fence.unwrap());
            assert_eq!(settlement.invalid_from, self.invalid_from);
            assert_eq!(settlement.released_custody, custody);
            self.assert_payouts(&settlement.payouts, settlement.released_custody);
            let terminal = expected_terminal
                .as_ref()
                .expect("successful settlement has a reference terminal state");
            assert!(
                Self::same_cache(&settlement.terminal_state, terminal),
                "terminal settlement state disagreed with the reference transition"
            );
        }
        if expected == OutcomeClass::Success {
            self.finalized =
                expected_terminal.expect("successful settlement has a reference terminal state");
            self.custody = 0;
            self.slots.clear();
            self.registered = None;
            self.staged_deposits.clear();
            self.staged_withdrawals.clear();
            self.outstanding.clear();
            self.withdrawal_replays.clear();
            self.settled = true;
        }
        ActionOutcome::new(expected, None)
    }

    fn same_cache(left: &TestCache, right: &TestCache) -> bool {
        left.root() == right.root()
            && left.liability() == right.liability()
            && left.leaves() == right.leaves()
    }

    fn terminal_state(&self) -> TestCache {
        let mut leaves = self.finalized.leaves().to_vec();
        for leaf in &mut leaves {
            leaf.state.balance = 0;
            leaf.state.active = false;
        }
        StateCache::new::<Sha256>(leaves).expect("terminal reference state remains canonical")
    }

    fn assert_payouts(&self, payouts: &[FaultPayout<VerifyingKey, Digest>], released: u64) {
        let mut deposits = self.staged_deposits.clone();
        for slot in &self.slots {
            for record in slot.deposits.records() {
                let aggregate = deposits
                    .get(record.account())
                    .copied()
                    .unwrap_or(0)
                    .checked_add(record.amount())
                    .expect("bounded terminal deposits");
                deposits.insert(record.account().clone(), aggregate);
            }
        }

        let mut expected = Vec::new();
        let mut total = 0_u64;
        for leaf in self.finalized.leaves() {
            let withdrawal = self.outstanding.get(&leaf.account);
            let withdrawal_amount = withdrawal.map_or(0, |release| {
                if release.request.body().full_close() {
                    leaf.state.balance
                } else {
                    release.request.body().amount()
                }
            });
            if let Some(release) = withdrawal {
                assert!(leaf.state.active);
                assert!(release.request.body().amount() <= leaf.state.balance);
                expected.push(FaultPayout::QueuedWithdrawal(WithdrawalRelease {
                    request: release.request.clone(),
                    amount: withdrawal_amount,
                }));
            }
            let residual = leaf
                .state
                .balance
                .checked_sub(withdrawal_amount)
                .and_then(|balance| {
                    balance.checked_add(deposits.remove(&leaf.account).unwrap_or(0))
                })
                .expect("authenticated survivor pays every request");
            if residual > 0 {
                expected.push(FaultPayout::ResidualSettlement {
                    account: leaf.account.clone(),
                    amount: residual,
                });
            }
            total = total
                .checked_add(withdrawal_amount)
                .and_then(|value| value.checked_add(residual))
                .expect("bounded payout sum");
        }
        assert!(deposits.is_empty());
        assert_eq!(payouts, expected);
        assert_eq!(total, released);
    }

    fn reconfigure(&mut self, tick: u8, account_selector: u8, mutation: u8) -> ActionOutcome {
        let now = self.advance(tick);
        let variant = mutation % 4;
        let mut survivor = self.finalized.clone();
        let mut next = self
            .finalized
            .leaves()
            .iter()
            .map(|leaf| leaf.account.clone())
            .collect::<Vec<_>>();
        match variant {
            0 => {
                for offset in 0..self.accounts.len() {
                    let key = &self.accounts
                        [(usize::from(account_selector) + offset) % self.accounts.len()];
                    let account = key.public_key();
                    if !next.contains(&account) {
                        next.push(account);
                        break;
                    }
                }
            }
            1 => next.push(next[0].clone()),
            2 => {
                if let Some(active) = self
                    .finalized
                    .leaves()
                    .iter()
                    .find(|leaf| leaf.state.active)
                {
                    next.retain(|account| account != &active.account);
                } else {
                    next.push(next[0].clone());
                }
            }
            _ => survivor = wrong_cache(&self.finalized),
        }
        let observation = self.predict_observation(now);
        let expected_state = self.reconfiguration_state(&observation, &survivor, &next);
        let expected = if expected_state.is_some() {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.reconfigure(now, &survivor, next);
        assert_eq!(OutcomeClass::of(&result), expected);
        if let Some(expected_state) = &expected_state {
            let actual = result
                .as_ref()
                .expect("the oracle predicted successful reconfiguration");
            assert!(
                Self::same_cache(actual, expected_state),
                "reconfigured state disagreed with the reference transition"
            );
        }
        self.apply_observation(now, &observation);
        if let Some(expected_state) = expected_state {
            self.finalized = expected_state;
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    fn reconfiguration_state(
        &self,
        observation: &TimeObservation,
        survivor: &TestCache,
        next_accounts: &[VerifyingKey],
    ) -> Option<TestCache> {
        if !self.operates_after(observation)
            || self.registered.is_some()
            || !self.slots.is_empty()
            || !self.staged_deposits.is_empty()
            || !self.staged_withdrawals.is_empty()
            || !self.outstanding.is_empty()
            || !Self::same_cache(survivor, &self.finalized)
            || self.finalized.liability() != self.custody
            || next_accounts.len() > MAX_ACCOUNTS
        {
            return None;
        }

        let mut next_accounts = next_accounts.to_vec();
        next_accounts.sort_unstable();
        if next_accounts.windows(2).any(|pair| pair[0] == pair[1])
            || self.finalized.leaves().iter().any(|leaf| {
                leaf.state.active && next_accounts.binary_search(&leaf.account).is_err()
            })
        {
            return None;
        }
        let current = self
            .finalized
            .leaves()
            .iter()
            .map(|leaf| (leaf.account.clone(), leaf.state))
            .collect::<BTreeMap<_, _>>();
        let leaves = next_accounts
            .into_iter()
            .map(|account| StateLeaf {
                state: current.get(&account).copied().unwrap_or_default(),
                account,
            })
            .collect();
        let next = StateCache::new::<Sha256>(leaves).ok()?;
        (next.liability() == self.custody).then_some(next)
    }
}

fn release_total(releases: &[WithdrawalRelease<VerifyingKey, Digest>]) -> u64 {
    releases
        .iter()
        .try_fold(0_u64, |total, release| total.checked_add(release.amount))
        .expect("authenticated withdrawal releases fit custody")
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
            .expect("sealed boundary account is registered")
            .state;
        let deposit = deposits.amount_for(&account);
        let withdrawal = withdrawals.request_for(&account);
        let full_close = withdrawal.is_some_and(|request| request.body().full_close());
        let applied = withdrawal.map_or(0, |request| {
            if full_close {
                opening
                    .balance
                    .checked_add(deposit)
                    .expect("bounded closing balance")
            } else {
                request.body().amount()
            }
        });
        let mut closing = opening;
        closing.balance = opening
            .balance
            .checked_add(deposit)
            .and_then(|balance| balance.checked_sub(applied))
            .expect("sanitized boundary remains affordable");
        closing.active = (opening.active || deposit != 0) && !full_close;
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
    let mut leaves = cache.leaves().to_vec();
    for row in &close.rows {
        let leaf = leaves
            .iter_mut()
            .find(|leaf| leaf.account == row.account)
            .expect("changed row belongs to state");
        leaf.state = row.closing;
    }
    let closing = StateCache::new::<Sha256>(leaves).expect("closing state remains canonical");
    assert_eq!(closing.root(), close.header.closing_root);
    (close, closing)
}

fn terminal_opening(close: &TestClose) -> Option<RowOpening<VerifyingKey, Digest>> {
    let count = u32::try_from(close.rows.len()).expect("close row count is bounded");
    if count == 0 {
        return None;
    }
    let mut builder = commitment::Builder::<Sha256>::new(VectorKind::Change, count)
        .expect("bounded change vector");
    for row in &close.rows {
        builder
            .add_encoded(row.encode().as_ref())
            .expect("row encoding is length-framable");
    }
    let tree = builder.build().expect("complete change vector builds");
    let position = count - 1;
    Some(RowOpening {
        row: close.rows[position as usize].clone(),
        proof: tree
            .opening(position)
            .expect("terminal position is in range"),
    })
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
    let tree = builder.build().expect("complete change vector builds");
    assert_eq!(tree.root(), close.header.change_root);
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
            AccountLookup::Absent {
                state: Box::new(
                    opening
                        .opening(account)
                        .expect("challenge account belongs to opening state"),
                ),
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
    let leaf = leaves.first_mut().expect("fuzz registry is nonempty");
    if leaf.state.active {
        leaf.state.balance ^= 1;
    } else {
        leaf.state.active = true;
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
