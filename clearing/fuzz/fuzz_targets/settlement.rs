#![no_main]

mod support;

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, bls12381, seal},
    boundary::{
        DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch,
        WithdrawalId,
    },
    challenge::{AckWitness, Challenge, ChallengeKind, EntryWitness, Verdict},
    custody::Epoch,
    logs::{LogHead, Opening as LogOpening, PayoutOperation},
    payment::{SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck, VectorSendBody},
    qmdb::{StateHead, StateOpening, StateRoot, account_key},
    settlement::{
        BatchStatus, Bounds, ClaimError, EpochDeadlinePolicy, Genesis, HardFaultReason,
        HardFaultSettlement, PendingBatch, SettlementChain, SettlementConfig, UnclaimedInterval,
    },
    state::SettlementOutput,
    transition::{
        BatchId, Close, CloseContext, CloseLimits, OperatorKey, OperatorSignature, OperatorVariant,
        PreparedClose, Terminal, WithdrawalClaim, WithdrawalOutput, prepare_close_with_strategy,
    },
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::{Decode, Encode, RangeCfg};
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::{compute_public, sign_message},
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::test_rng;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
};
use support::TestState;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_ACCOUNTS: usize = 4;
const MAX_ACTIONS: usize = 24;
const MAX_DESTINATION_BYTES: usize = 16;
const MAX_EPOCH_ADMISSION_DELAY: u64 = 6;
const CHALLENGE_DURATION: u64 = 2;
const DEPOSIT_INCLUSION_TIMEOUT: u64 = 6;
const MINIMUM_WITHDRAWAL_NOTICE: u64 = 2;
const MAXIMUM_WITHDRAWAL_NOTICE: u64 = 1_000;
const MAX_DEPOSIT_IDS: usize = 4;
const MAX_RETAINED_CLAIM_BATCHES: usize = MAX_ACTIONS;

#[derive(Clone, Debug)]
struct BalanceEntry {
    account: VerifyingKey,
    balance: u64,
}

// The four-account model is independent of QMDB's mutation and proof implementation.
#[derive(Clone, Debug)]
struct TestCache {
    head: StateHead<Digest>,
    leaves: Vec<BalanceEntry>,
}
impl TestCache {
    fn root(&self) -> StateRoot<Digest> {
        self.head.root()
    }
    fn liability(&self) -> u64 {
        self.leaves.iter().map(|entry| entry.balance).sum()
    }
    fn leaves(&self) -> &[BalanceEntry] {
        &self.leaves
    }
    fn len(&self) -> usize {
        self.leaves.len()
    }
    fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
    fn balance(&self, account: &VerifyingKey) -> u64 {
        self.leaves
            .iter()
            .find(|entry| &entry.account == account)
            .map_or(0, |entry| entry.balance)
    }
}
type TestChain = SettlementChain<Sha256, VerifyingKey>;
type TestChallenge = Challenge<VerifyingKey, Digest>;
type TestClose = Close<VerifyingKey, Digest>;
type TestContext = CloseContext<VerifyingKey, Digest>;
type TestDeposits = DepositBatch<VerifyingKey>;
type TestWithdrawals = WithdrawalBatch<VerifyingKey, Digest>;
type TestWithdrawalClaim = WithdrawalClaim<Digest>;
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
    Restart,
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
    RegisterCredit {
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
    FaultUnadmitted {
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
    ClaimWithdrawal {
        batch: u8,
        claim: u8,
        mutation: u8,
    },
    BeginHardFaultSettlement,
    ClaimHardFault {
        account: u8,
        mutation: u8,
    },
}

#[derive(Clone)]
struct Prepared {
    predecessor: TestCache,
    context: TestContext,
    deposits: TestDeposits,
    withdrawals: TestWithdrawals,
    withdrawal_outputs: Vec<WithdrawalOutput>,
    close: TestClose,
    successor: TestCache,
}

#[derive(Clone)]
struct Slot {
    predecessor: TestCache,
    close: TestClose,
    context: TestContext,
    deposits: TestDeposits,
    withdrawals: TestWithdrawals,
    withdrawal_claims: Vec<TestWithdrawalClaim>,
    withdrawal_outputs: Vec<WithdrawalOutput>,
    header: commonware_clearing::bajillion::transition::Header<Digest>,
    certificate: bls12381::Certificate,
    successor: TestCache,
    status: BatchStatus<Digest>,
}

#[derive(Clone)]
struct ModeledWithdrawalClaim {
    claim: TestWithdrawalClaim,
}

// Ghost issuance and payment records provide an independent oracle for the interval ledger.
#[derive(Clone)]
struct FinalizedClaimBatch {
    batch_id: BatchId<Digest>,
    withdrawal_root: LogHead<Digest>,
    withdrawals: Vec<ModeledWithdrawalClaim>,
    claimed_withdrawals: BTreeSet<u64>,
    withdrawal_remaining: u64,
}

impl FinalizedClaimBatch {
    fn is_live(&self) -> bool {
        self.claimed_withdrawals.len() < self.withdrawals.len()
    }
}

impl Slot {
    fn batch_id(&self) -> BatchId<Digest> {
        self.header.batch_id::<Sha256>()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    claims: BTreeMap<u64, u64>,
    state_root: StateRoot<Digest>,
    custody: u64,
    claimable: u64,
    deposits: TestDeposits,
    withdrawals: TestWithdrawals,
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
    runtime: deterministic::Context,
    state: Option<TestState>,
    replica: TestCache,
    foreign_opening: StateOpening<VerifyingKey, Digest>,
    seed: u64,
    chain: TestChain,
    claims: BTreeMap<u64, u64>,
    deployment: Digest,
    operator: SigningKey,
    operator_ack: Private,
    operator_bls: OperatorKey,
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
    finalized_claim_batches: Vec<FinalizedClaimBatch>,
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
    async fn new(input: &FuzzInput, runtime: deterministic::Context) -> Self {
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
            .map(|(index, account)| BalanceEntry {
                account: account.public_key(),
                balance: u64::from(input.balances[index] % 8) + 1,
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|a, b| a.account.cmp(&b.account));
        let state = support::new_state(
            runtime.child("replica"),
            "settlement",
            leaves
                .iter()
                .map(|entry| (entry.account.clone(), entry.balance))
                .collect(),
        )
        .await;
        let finalized = TestCache {
            head: *state.state().head(),
            leaves,
        };
        let mut foreign_seed = input.seed.wrapping_add(0x200);
        let foreign = loop {
            let candidate = SigningKey::from_seed(foreign_seed).public_key();
            if accounts
                .iter()
                .all(|account| account.public_key() != candidate)
            {
                break candidate;
            }
            foreign_seed = foreign_seed.wrapping_add(1);
        };
        let foreign_state = support::new_state(
            runtime.child("replica"),
            "foreign",
            vec![(foreign.clone(), 1)],
        )
        .await;
        let foreign_opening = foreign_state.state().opening(foreign).await.unwrap();
        let seed = input.seed.to_be_bytes();
        let deployment = Sha256::hash(&[b"settlement-stateful-fuzz", &seed]);
        let operator = SigningKey::from_seed(input.seed ^ 0xa5a5_a5a5_a5a5_a5a5);
        let operator_ack = Private::new(Scalar::from((input.seed ^ 0x0f0f_0f0f_0f0f_0f0f).max(1)));
        let operator_bls = compute_public::<OperatorVariant>(&operator_ack);
        let validator_bls = Private::new(Scalar::from((input.seed ^ 0x1357_9bdf_2468_ace0).max(1)));
        let committee = Committee::new(vec![compute_public::<MinSig>(&validator_bls)])
            .expect("one validator is an exact 3f+1 committee");
        let committee_digest = committee.commitment::<Sha256>();
        let validator = bls12381::Scheme::signer(committee.clone(), validator_bls)
            .expect("deterministic validator belongs to its committee");
        let config = SettlementConfig::new(
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
            &Genesis::new(
                finalized.root(),
                finalized.head.operations(),
                &finalized
                    .leaves
                    .iter()
                    .map(|entry| {
                        (
                            account_key(&entry.account).unwrap(),
                            NonZeroU64::new(entry.balance).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            0,
            config,
        )
        .expect("bounded settlement fixture must construct");
        let custody = finalized.liability();
        Self {
            runtime,
            state: Some(state),
            replica: finalized.clone(),
            foreign_opening,
            seed: input.seed,
            chain,
            claims: BTreeMap::new(),
            deployment,
            operator,
            operator_ack,
            operator_bls,
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
            finalized_claim_batches: Vec::new(),
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

    async fn run(mut self, actions: &[Action]) {
        self.assert_invariants();
        for (step, action) in actions.iter().take(MAX_ACTIONS).enumerate() {
            self.apply(step as u64, action).await;
        }
    }

    async fn restart(&mut self) {
        let before = self.snapshot();
        let encoded = self.chain.encode();
        self.chain = TestChain::decode_cfg(
            encoded.clone(),
            &Bounds {
                committee: 4,
                items: MAX_ACTIONS * MAX_ACCOUNTS,
                destination: MAX_DESTINATION_BYTES,
            },
        )
        .unwrap();
        assert_eq!(self.chain.encode(), encoded);
        let encoded = self.claims.encode();
        self.claims = BTreeMap::decode_cfg(
            encoded.clone(),
            &((..=MAX_ACTIONS * MAX_ACCOUNTS).into(), ((), ())),
        )
        .unwrap();
        assert_eq!(self.claims.encode(), encoded);
        let state = self.state.take().unwrap().sync().await.unwrap();
        let head = *state.state().head();
        drop(state);
        let state = support::open_state(self.runtime.child("replica"), "settlement")
            .await
            .unwrap();
        assert_eq!(*state.state().head(), head);
        self.state = Some(state);
        for account in &self.accounts {
            assert_eq!(
                self.state
                    .as_ref()
                    .unwrap()
                    .state()
                    .get(&account_key(&account.public_key()).unwrap())
                    .await
                    .unwrap()
                    .map(NonZeroU64::get)
                    .unwrap_or(0),
                self.replica.balance(&account.public_key())
            );
        }
        assert_eq!(self.snapshot(), before);
        self.assert_invariants();
    }

    async fn apply(&mut self, step: u64, action: &Action) {
        let before = self.snapshot();
        let before_fault = self.hard_fault.clone();
        let before_fence = self.fence;
        let before_invalid = self.invalid_from;
        let before_invalid_epoch = before_invalid.and_then(|batch| self.batch_epoch(batch));
        let before_deposits = self.consumed_deposit_ids.clone();
        let was_settled = self.settled;

        let outcome = match action {
            Action::Restart => {
                self.restart().await;
                ActionOutcome::new(OutcomeClass::Success, None)
            }
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
            } => {
                self.withdrawal(
                    *tick,
                    *account,
                    *amount,
                    *destination,
                    *destination_len,
                    *closes_account,
                    *mutation,
                )
                .await
            }
            Action::Register { tick, mutated } => self.register(*tick, *mutated).await,
            Action::RegisterCredit {
                tick,
                payer,
                amount,
                mutated,
            } => self.register_credit(*tick, *payer, *amount, *mutated).await,
            Action::Admit { tick, mutated } => self.admit(*tick, *mutated).await,
            Action::Finalize { tick, early } => self.finalize(*tick, *early),
            Action::FaultUnadmitted {
                tick,
                inclusive_boundary,
            } => self.fault_unadmitted(*tick, *inclusive_boundary),
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
            } => {
                self.challenge(step, *tick, *slot, *encoded, *mutation)
                    .await
            }
            Action::ClaimPendingDeposit { tick, account } => {
                self.claim_pending_deposit(*tick, *account)
            }
            Action::ClaimWithdrawal {
                batch,
                claim,
                mutation,
            } => self.claim_withdrawal(*batch, *claim, *mutation).await,
            Action::BeginHardFaultSettlement => self.begin_hard_fault_settlement(),
            Action::ClaimHardFault { account, mutation } => {
                self.claim_hard_fault(*account, *mutation).await
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
        if was_settled && !matches!(action, Action::ClaimWithdrawal { .. }) {
            assert_eq!(before, after, "terminal settlement is permanent");
        }
        self.assert_invariants();
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            claims: self.claims.clone(),
            state_root: self.chain.current_state_root(),
            custody: self.chain.custody_balance(),
            claimable: self.chain.claimable_balance(),
            deposits: self.chain.pending_deposits(),
            withdrawals: self.chain.pending_withdrawals(),
            batches: self.chain.pending_batches().cloned().collect(),
            deadlines: self
                .accounts
                .iter()
                .map(|account| {
                    self.chain
                        .unfinalized_withdrawal_deadline(&account.public_key())
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
        assert_eq!(self.chain.pending_epoch_count(), self.slots.len());
        let expected_state_root = self.finalized.root();
        assert_eq!(self.chain.current_state_root(), expected_state_root);
        assert_eq!(self.chain.custody_balance(), self.custody);
        assert_eq!(self.chain.claimable_balance(), self.claimable);
        assert!(self.finalized_claim_batches.len() <= MAX_RETAINED_CLAIM_BATCHES);
        let mut finalized_batch_ids = BTreeSet::new();
        let modeled_claimable = self
            .finalized_claim_batches
            .iter()
            .try_fold(0_u64, |total, batch| {
                assert!(finalized_batch_ids.insert(batch.batch_id));

                let withdrawal_positions = batch
                    .withdrawals
                    .iter()
                    .map(|entry| entry.claim.position())
                    .collect::<BTreeSet<_>>();
                assert_eq!(withdrawal_positions.len(), batch.withdrawals.len());
                assert!(batch.claimed_withdrawals.is_subset(&withdrawal_positions));
                let withdrawal_remaining = batch
                    .withdrawals
                    .iter()
                    .filter(|entry| !batch.claimed_withdrawals.contains(&entry.claim.position()))
                    .try_fold(0_u64, |remaining, entry| {
                        remaining.checked_add(entry.claim.output().amount())
                    })
                    .expect("modeled withdrawal reserve fits in u64");
                assert_eq!(batch.withdrawal_remaining, withdrawal_remaining);
                total.checked_add(batch.withdrawal_remaining)
            })
            .expect("modeled finalized reserves fit in u64");
        assert_eq!(modeled_claimable, self.claimable);
        let actual = self
            .claims
            .iter()
            .flat_map(|(&start, &end)| start..end)
            .collect::<Vec<_>>();
        let mut expected = self
            .finalized_claim_batches
            .iter()
            .flat_map(|batch| {
                batch
                    .withdrawals
                    .iter()
                    .filter(|entry| !batch.claimed_withdrawals.contains(&entry.claim.position()))
                    .map(|entry| entry.claim.position())
            })
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert_eq!(actual, expected);
        assert!(self.claims.len() <= expected.len());
        self.custody
            .checked_add(self.claimable)
            .expect("active and claimable custody fit the accounting domain");
        assert_eq!(self.chain.pending_deposits(), self.deposit_batch());
        assert_eq!(self.chain.pending_withdrawals(), self.withdrawal_batch());
        assert_eq!(self.chain.hard_fault(), self.hard_fault.as_ref());
        assert_eq!(self.chain.admission_fence_epoch(), self.fence);
        assert_eq!(self.chain.invalid_from(), self.invalid_from);
        assert_eq!(self.chain.hard_fault_is_settled(), self.settled);
        assert!(self.finalized.leaves().iter().all(|leaf| leaf.balance > 0));

        let expected_batches = self
            .slots
            .iter()
            .map(|slot| PendingBatch {
                header: slot.header,
                roots: slot.close.roots,
                withdrawal_total: slot.close.withdrawal_total,
                certificate: slot.certificate.clone(),
                successor_liability: slot.successor.liability(),
                status: slot.status.clone(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            self.chain.pending_batches().cloned().collect::<Vec<_>>(),
            expected_batches
        );

        let mut predecessor_root = self.finalized.root();
        let mut predecessor_liability = self.finalized.liability();
        for (offset, slot) in self.slots.iter().enumerate() {
            assert_eq!(slot.predecessor.root(), *slot.context.predecessor_root());
            assert_eq!(slot.close.header, slot.header);
            assert_eq!(
                slot.context.payment().epoch(),
                self.expected_epoch + offset as u64
            );
            assert_eq!(*slot.context.predecessor_root(), predecessor_root);
            assert_eq!(slot.context.predecessor_liability(), predecessor_liability);
            assert_eq!(slot.close.roots.successor, slot.successor.root());
            assert_eq!(
                slot.close.withdrawal_total,
                output_total(&slot.withdrawal_outputs)
            );
            predecessor_root = slot.successor.root();
            predecessor_liability = slot.successor.liability();
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
                self.chain.unfinalized_withdrawal_deadline(&public),
                expected_deadline
            );
        }
        for (account, request) in &self.staged_withdrawals {
            assert_eq!(self.outstanding.get(account), Some(request));
            assert_eq!(request.account(), account);
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
        };
        let registration = self.registered.as_ref().map(|registered| {
            let deadline = registered.context.admission_deadline();
            (
                deadline
                    .checked_add(1)
                    .expect("a registered epoch reserves a post-deadline timestamp"),
                HardFaultReason::ExpiredRegistration {
                    anchor: *registered.context.payment().anchor(),
                    epoch: registered.context.payment().epoch(),
                    expired_at: deadline,
                },
            )
        });

        match (intake, registration) {
            (Some(intake), Some(registration)) if registration.0 <= intake.0 => Some(registration),
            (Some(intake), _) => Some(intake),
            (None, registration) => registration,
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
                .map(|(account, amount)| {
                    DepositRecord::new(account.clone(), *amount)
                        .expect("model deposits remain positive")
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
            .try_fold(0_u64, |total, leaf| total.checked_add(leaf.balance))
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
            .map_or(&self.finalized, |slot| &slot.successor)
    }

    // A fresh fixture deadline clears both now and the pipeline tail, so a
    // registration can satisfy the strict admission monotonicity rule while
    // the oracle still predicts rejections for stale or distant deadlines.
    fn fixture_admission_deadline(&self) -> u64 {
        let tail = self
            .slots
            .back()
            .map_or(0, |slot| slot.context.admission_deadline());
        self.now.saturating_add(2).max(tail.saturating_add(1))
    }

    async fn make_context(
        &self,
        epoch: u64,
        cache: &TestCache,
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> TestContext {
        assert_eq!(cache.root(), self.state.as_ref().unwrap().state().root());
        support::close_context(
            self.deployment,
            epoch,
            self.operator.public_key(),
            self.state.as_ref().unwrap(),
            cache.liability(),
            deposits,
            withdrawals,
            admission_deadline,
            challenge_deadline,
            CloseLimits::new(4, 5, 4, 4, 16, u64::MAX, u64::MAX, u64::MAX),
            self.committee_digest,
            self.chain.registration_floors(),
        )
    }

    async fn make_prepared(&self) -> Prepared {
        let cache = &self.replica;
        let deposits = self.deposit_batch();
        let withdrawals = self.withdrawal_batch();
        let admission = self.fixture_admission_deadline();
        let context = self
            .make_context(
                self.next_epoch(),
                cache,
                &deposits,
                &withdrawals,
                admission,
                admission.saturating_add(CHALLENGE_DURATION),
            )
            .await;
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            self.state.as_ref().unwrap(),
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            &Sequential,
        )
        .await
        .unwrap();
        self.finish_prepared(cache, context, deposits, withdrawals, prepared)
            .await
    }

    async fn make_credit_prepared(&self, payer_selector: u8, raw_amount: u8) -> Option<Prepared> {
        if !self.staged_deposits.is_empty() || self.staged_withdrawals.len() > 1 {
            return None;
        }
        let close_request = self.staged_withdrawals.values().next();
        if close_request
            .is_some_and(|request| !matches!(request.body().action(), WithdrawalAction::Close))
        {
            return None;
        }
        let cache = &self.replica;
        let leaf = match close_request {
            Some(request) => cache
                .leaves()
                .iter()
                .find(|leaf| &leaf.account == request.account())?,
            None => {
                let candidates = cache
                    .leaves()
                    .iter()
                    .filter(|leaf| leaf.balance > 1)
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
        let recipient_key = self
            .accounts
            .iter()
            .find(|candidate| cache.balance(&candidate.public_key()) == 0)?;
        let recipient = recipient_key.public_key();

        let deposits = DepositBatch::empty();
        let withdrawals = self.withdrawal_batch();
        let admission_deadline = self.fixture_admission_deadline();
        let challenge_deadline = admission_deadline.saturating_add(CHALLENGE_DURATION);
        let context = self
            .make_context(
                self.next_epoch(),
                cache,
                &deposits,
                &withdrawals,
                admission_deadline,
                challenge_deadline,
            )
            .await;
        let maximum = if close_request.is_some() {
            leaf.balance
        } else {
            leaf.balance.checked_sub(1)?
        };
        let amount = u64::from(raw_amount).wrapping_rem(maximum) + 1;
        let epoch = context.payment().epoch();
        let out_vector = OutVector::new(
            epoch,
            leaf.account.clone(),
            vec![OutEntry {
                recipient: recipient.clone(),
                cumulative: amount,
                count: 1,
            }],
        )
        .expect("one positive virtual credit is canonical");
        let body = VectorSendBody::new(
            context.payment(),
            leaf.account.clone(),
            1,
            amount,
            out_vector
                .root::<Sha256, Digest>()
                .expect("bounded credit vector commits"),
        );
        let operator_signature = bls_ack(&self.operator_ack, &body);
        let outgoing = SendAuthorization::sign(body.clone(), payer);
        let terminal = Terminal {
            authorization: outgoing,
            vector: out_vector,
            operator_signature,
        };

        // Receiving does not make an absent-at-boundary key eligible to originate payments in the
        // same epoch. A predecessor balance or sealed deposit remains the payer authority.
        let recipient_vector = OutVector::new(
            epoch,
            recipient.clone(),
            vec![OutEntry {
                recipient: leaf.account.clone(),
                cumulative: 1,
                count: 1,
            }],
        )
        .expect("one positive negative-control entry is canonical");
        let recipient_body = VectorSendBody::new(
            context.payment(),
            recipient.clone(),
            1,
            1,
            recipient_vector
                .root::<Sha256, Digest>()
                .expect("bounded negative-control vector commits"),
        );
        let mut ineligible = vec![
            terminal.clone(),
            Terminal {
                authorization: SendAuthorization::sign(recipient_body.clone(), recipient_key),
                vector: recipient_vector,
                operator_signature: bls_ack(&self.operator_ack, &recipient_body),
            },
        ];
        ineligible.sort_unstable_by(|left, right| {
            left.authorization
                .body()
                .payer()
                .cmp(right.authorization.body().payer())
        });
        assert!(
            prepare_close_with_strategy::<Sha256, _, _, _, _>(
                self.state.as_ref().unwrap(),
                &context,
                &deposits,
                &withdrawals,
                ineligible,
                &Sequential,
            )
            .await
            .is_err(),
            "an absent recipient cannot spend its same-epoch credit"
        );

        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            self.state.as_ref().unwrap(),
            &context,
            &deposits,
            &withdrawals,
            vec![terminal],
            &Sequential,
        )
        .await
        .unwrap();
        Some(
            self.finish_prepared(cache, context, deposits, withdrawals, prepared)
                .await,
        )
    }

    async fn finish_prepared(
        &self,
        predecessor: &TestCache,
        context: TestContext,
        deposits: TestDeposits,
        withdrawals: TestWithdrawals,
        prepared: PreparedClose<VerifyingKey, Digest>,
    ) -> Prepared {
        let close = prepared.close().clone();
        let withdrawal_outputs = close.withdrawal_outputs().to_vec();
        withdrawals
            .requests()
            .iter()
            .zip(&withdrawal_outputs)
            .for_each(|(request, output)| {
                assert_eq!(output.destination(), request.body().destination());
                let row = close
                    .rows
                    .iter()
                    .find(|row| &row.account == request.account())
                    .expect("validated withdrawal has an authenticated row");
                let debit = close
                    .out_vectors
                    .iter()
                    .find(|vector| vector.payer() == &row.account)
                    .map_or(0, |vector| vector.totals().unwrap().0);
                let credit: u64 = close
                    .out_vectors
                    .iter()
                    .flat_map(|vector| vector.entries())
                    .filter(|entry| entry.recipient == row.account)
                    .map(|entry| entry.cumulative)
                    .sum();
                let available = u128::from(predecessor.balance(&row.account))
                    + u128::from(deposits.amount_for(&row.account))
                    + u128::from(credit);
                let tail = available
                    .checked_sub(u128::from(debit))
                    .expect("validated close debit is affordable");
                match request.body().action() {
                    WithdrawalAction::Amount(expected) => {
                        let expected = if u128::from(expected.get()) <= tail {
                            expected.get()
                        } else {
                            0
                        };
                        assert_eq!(output.amount(), expected);
                    }
                    WithdrawalAction::Close => {
                        let expected =
                            u64::try_from(tail).expect("validated close tail fits in u64");
                        assert_eq!(output.amount(), expected);
                        assert_eq!(row.successor, 0);
                    }
                }
            });
        assert_eq!(withdrawal_outputs.len(), withdrawals.len());
        assert_eq!(close.withdrawal_total, output_total(&withdrawal_outputs));
        for entry in close.out_vectors.iter().flat_map(|vector| vector.entries()) {
            if predecessor.balance(&entry.recipient) == 0
                && deposits.amount_for(&entry.recipient) == 0
            {
                assert!(withdrawals.request_for(&entry.recipient).is_none());
                let row = close
                    .rows
                    .iter()
                    .find(|row| row.account == entry.recipient)
                    .expect("a first virtual credit has an authenticated row");
                assert_eq!(row.output, SettlementOutput::None);
                assert!(row.successor >= entry.cumulative);
            }
        }
        let successor = successor_snapshot(
            predecessor,
            &deposits,
            &withdrawals,
            &close,
            *prepared.state().head(),
        );
        Prepared {
            predecessor: predecessor.clone(),
            context,
            deposits,
            withdrawals,
            withdrawal_outputs,
            close,
            successor,
        }
    }

    async fn certificate(
        &self,
        prepared: &Prepared,
    ) -> (Certificate, PreparedClose<VerifyingKey, Digest>) {
        let before = *self.state.as_ref().unwrap().state().head();
        let (vote, candidate) = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
            &self.validator,
            self.state.as_ref().unwrap(),
            &prepared.context,
            &self.operator_bls,
            &prepared.deposits,
            &prepared.withdrawals,
            prepared.close.encoded().clone(),
            &mut test_rng(),
            &Sequential,
        )
        .await
        .unwrap();
        assert_eq!(*self.state.as_ref().unwrap().state().head(), before);
        assert_eq!(candidate.close().header, prepared.close.header);
        (self.validator.assemble_exact([vote]).unwrap(), candidate)
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
        let epoch_available = self.next_epoch().checked_add(3).is_some();
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
    async fn withdrawal(
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
        let mut request = replay.unwrap_or_else(|| {
            let action = if closes_account {
                WithdrawalAction::Close
            } else {
                WithdrawalAction::Amount(
                    NonZeroU64::new(amount).expect("sanitized withdrawal amount is positive"),
                )
            };
            SignedWithdrawal::sign(deployment, root, destination, action, deadline, &key)
        });
        if variant == 10 && !(mutation / 11).is_multiple_of(2) {
            let body = request.body().clone();
            let wrong_authority = self
                .accounts
                .iter()
                .find(|candidate| candidate.public_key() != *request.account())
                .expect("the fixture has a distinct signing authority");
            let (_, _, signature) =
                SignedWithdrawal::sign_body_by_authority(body.clone(), wrong_authority)
                    .into_parts();
            request =
                SignedWithdrawal::from_raw_unchecked(request.account().clone(), body, signature);
        }
        let account = request.account().clone();
        let opening = self.withdrawal_opening(&account, variant, mutation).await;

        let observation = self.predict_observation(now);
        let expected =
            if self.withdrawal_would_succeed(now, &observation, &request, &opening, eligible) {
                OutcomeClass::Success
            } else {
                OutcomeClass::Error
            };
        let result = self
            .chain
            .queue_withdrawal(now, request.clone(), &opening, |_| eligible);
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
            let balance = self.finalized.balance(&account);
            (balance != 0).then(|| (key.clone(), balance))
        })
    }

    async fn withdrawal_opening(
        &self,
        account: &VerifyingKey,
        variant: u8,
        mutation: u8,
    ) -> StateOpening<VerifyingKey, Digest> {
        let state = self.state.as_ref().unwrap();
        let before = *state.state().head();
        let canonical = state
            .state()
            .opening_at(
                self.finalized.root(),
                self.finalized.head.operations(),
                account.clone(),
            )
            .await
            .ok();
        let opening = if variant != 9 {
            canonical
                .clone()
                .unwrap_or_else(|| self.foreign_opening.clone())
        } else if (mutation / 11).is_multiple_of(2) {
            let wrong_account = self
                .finalized
                .leaves()
                .iter()
                .find(|entry| &entry.account != account);
            match wrong_account {
                Some(entry) => state
                    .state()
                    .opening_at(
                        self.finalized.root(),
                        self.finalized.head.operations(),
                        entry.account.clone(),
                    )
                    .await
                    .unwrap(),
                None => self.foreign_opening.clone(),
            }
        } else {
            match self.slots.back().filter(|slot| {
                slot.successor.root() != self.finalized.root()
                    && slot.successor.balance(account) != 0
            }) {
                Some(slot) => state
                    .state()
                    .opening_at(
                        slot.successor.root(),
                        slot.successor.head.operations(),
                        account.clone(),
                    )
                    .await
                    .unwrap(),
                None => self.foreign_opening.clone(),
            }
        };
        if variant != 9 && canonical.is_some() {
            assert!(opening.verify::<Sha256>(&self.finalized.root()).is_ok());
        }
        assert_eq!(*state.state().head(), before);
        opening
    }

    fn withdrawal_would_succeed(
        &self,
        now: u64,
        observation: &TimeObservation,
        request: &SignedWithdrawal<VerifyingKey, Digest>,
        opening: &StateOpening<VerifyingKey, Digest>,
        destination_is_eligible: bool,
    ) -> bool {
        if !self.operates_after(observation) {
            return false;
        }
        let body = request.body();
        let request_id = request.id::<Sha256>();
        let epoch_offset = match body.action() {
            WithdrawalAction::Amount(_) => 2,
            WithdrawalAction::Close => 1,
        };
        if self
            .next_epoch()
            .checked_add(epoch_offset + u64::from(self.registered.is_some()))
            .is_none()
        {
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
            || request.verify_signature().is_err()
            || !destination_is_eligible
            || body.deadline() < minimum_deadline
            || body.deadline() > now.saturating_add(MAXIMUM_WITHDRAWAL_NOTICE)
            || self.outstanding.contains_key(request.account())
        {
            return false;
        }

        let balance = self.finalized.balance(request.account());
        balance > 0
            && opening.account == *request.account()
            && opening.balance.get() == balance
            && opening.verify::<Sha256>(&self.finalized.root()).is_ok()
            && match body.action() {
                WithdrawalAction::Amount(amount) => amount.get() <= balance,
                WithdrawalAction::Close => true,
            }
    }

    async fn register(&mut self, tick: u8, mutated: bool) -> ActionOutcome {
        let prepared = self.make_prepared().await;
        self.register_prepared(tick, mutated, prepared).await
    }

    async fn register_credit(
        &mut self,
        tick: u8,
        payer: u8,
        amount: u8,
        mutated: bool,
    ) -> ActionOutcome {
        let (prepared, unavailable) = match self.make_credit_prepared(payer, amount).await {
            Some(prepared) => (prepared, false),
            None => (self.make_prepared().await, true),
        };
        self.register_prepared(tick, mutated || unavailable, prepared)
            .await
    }

    async fn register_prepared(
        &mut self,
        tick: u8,
        mutated: bool,
        prepared: Prepared,
    ) -> ActionOutcome {
        let now = self.advance(tick);
        let context = if mutated {
            self.make_context(
                prepared.context.payment().epoch() + 1,
                &self.replica,
                &prepared.deposits,
                &prepared.withdrawals,
                prepared.context.admission_deadline(),
                prepared.context.challenge_deadline(),
            )
            .await
        } else {
            prepared.context.clone()
        };
        let observation = self.predict_observation(now);

        // Mirror validate_epoch_deadlines: a strictly later admission deadline
        // than the pipeline tail, a bounded admission delay from the tail (or
        // from now when the pipeline is empty), and an exact challenge
        // duration (the config sets minimum and maximum equal).
        let tail_deadline = self
            .slots
            .back()
            .map(|slot| slot.context.admission_deadline());
        let deadline_base = tail_deadline.unwrap_or(now);
        let deadlines_valid = (tail_deadline.is_none()
            || context.admission_deadline() > deadline_base)
            && context.admission_deadline()
                <= deadline_base.saturating_add(MAX_EPOCH_ADMISSION_DELAY)
            && context
                .challenge_deadline()
                .checked_sub(context.admission_deadline())
                == Some(CHALLENGE_DURATION);
        let expected = if self.operates_after(&observation)
            && self.registered.is_none()
            && now <= context.admission_deadline()
            && deadlines_valid
            && context == prepared.context
        {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result =
            self.chain
                .register_close(now, context, prepared.withdrawals.clone(), &[], |_| true);
        assert_eq!(OutcomeClass::of(&result), expected);
        self.apply_observation(now, &observation);
        if expected == OutcomeClass::Success {
            assert!(self.registered.is_none());
            self.registered = Some(prepared);
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    async fn admit(&mut self, tick: u8, mutated: bool) -> ActionOutcome {
        let now = self.advance(tick);
        let prepared = match self.registered.clone() {
            Some(prepared) => prepared,
            None => self.make_prepared().await,
        };
        let (certificate, candidate) = self.certificate(&prepared).await;
        let retained_certificate = certificate.clone();
        let mut header = prepared.close.header;
        let mut roots = prepared.close.roots;
        if mutated {
            roots.successor.digest = self.digest(b"admit-root-mutation", now);
            header = commonware_clearing::bajillion::transition::Header::new::<Sha256, _>(
                &prepared.context,
                &roots,
                prepared.close.withdrawal_total,
            );
        }
        let observation = self.predict_observation(now);
        let expected = if self.operates_after(&observation)
            && self.registered.as_ref().is_some_and(|registered| {
                now <= registered.context.admission_deadline()
                    && header == registered.close.header
                    && roots == registered.close.roots
            }) {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let result = self.chain.admit(
            now,
            header,
            roots,
            prepared.close.withdrawal_total,
            certificate,
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
            let (state, validated) = candidate.apply(self.state.take().unwrap()).await.unwrap();
            assert_eq!(validated.header, prepared.close.header);
            let registered = self
                .registered
                .take()
                .expect("admission requires the exact registered epoch");
            let payout_start = registered.context.predecessor_logs().payouts.operations;
            let mut withdrawal_claims = Vec::with_capacity(registered.withdrawal_outputs.len());
            for (offset, expected_output) in registered.withdrawal_outputs.iter().enumerate() {
                let position = payout_start
                    .checked_add(u64::try_from(offset).expect("bounded output count fits in u64"))
                    .expect("bounded payout position cannot overflow");
                let (opening, operations) = state
                    .logs()
                    .payout_opening(
                        &validated.roots.withdrawal_outputs,
                        position,
                        NonZeroU64::MIN,
                    )
                    .await
                    .expect("an applied withdrawal output has a native opening");
                let [PayoutOperation::Append(output)] = operations.as_slice() else {
                    panic!("a withdrawal position contains exactly one output append");
                };
                assert_eq!(output, expected_output);
                let claim = WithdrawalClaim::new(output.clone(), opening);
                assert_eq!(
                    &claim
                        .verify::<Sha256>(&validated.roots.withdrawal_outputs)
                        .expect("native withdrawal claim verifies"),
                    expected_output
                );
                withdrawal_claims.push(claim);
            }
            self.state = Some(state.sync().await.unwrap());
            self.replica = prepared.successor.clone();
            assert_eq!(
                *self.state.as_ref().unwrap().state().head(),
                self.replica.head
            );
            for account in &self.accounts {
                assert_eq!(
                    self.state
                        .as_ref()
                        .unwrap()
                        .state()
                        .get(&account_key(&account.public_key()).unwrap())
                        .await
                        .unwrap()
                        .map(NonZeroU64::get)
                        .unwrap_or(0),
                    self.replica.balance(&account.public_key())
                );
            }
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
            for request in registered.withdrawals.requests() {
                assert_eq!(
                    self.staged_withdrawals.remove(request.account()),
                    Some(request.clone())
                );
            }
            self.slots.push_back(Slot {
                predecessor: registered.predecessor,
                close: registered.close.clone(),
                context: registered.context,
                deposits: registered.deposits,
                withdrawals: registered.withdrawals,
                withdrawal_claims,
                withdrawal_outputs: registered.withdrawal_outputs,
                header: registered.close.header,
                certificate: retained_certificate,
                successor: registered.successor,
                status: BatchStatus::Pending,
            });
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
        let reserve = self
            .slots
            .front()
            .map(|front| output_total(&front.withdrawal_outputs));
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
        let result = self.chain.finalize(now).map(|(batch, claims)| {
            if let Some(interval) = claims {
                assert!(self.claims.insert(interval.start, interval.end).is_none());
            }
            batch
        });
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
            assert_eq!(finalized.successor_root, slot.successor.root());
            assert_eq!(
                finalized.withdrawal_total,
                output_total(&slot.withdrawal_outputs)
            );
            assert_eq!(
                finalized.custody_balance,
                self.custody
                    .checked_sub(output_total(&slot.withdrawal_outputs))
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
            assert_eq!(slot.withdrawal_claims.len(), slot.withdrawal_outputs.len());
            let withdrawal_remaining = output_total(&slot.withdrawal_outputs);
            if !slot.withdrawal_claims.is_empty() {
                let batch_id = slot.batch_id();
                assert!(
                    self.finalized_claim_batches
                        .iter()
                        .all(|batch| batch.batch_id != batch_id)
                );
                self.finalized_claim_batches.push(FinalizedClaimBatch {
                    batch_id,
                    withdrawal_root: slot.close.roots.withdrawal_outputs,
                    withdrawals: slot
                        .withdrawal_claims
                        .iter()
                        .cloned()
                        .zip(slot.withdrawal_outputs.iter().cloned())
                        .map(|(claim, output)| {
                            assert_eq!(claim.output(), &output);
                            ModeledWithdrawalClaim { claim }
                        })
                        .collect(),
                    claimed_withdrawals: BTreeSet::new(),
                    withdrawal_remaining,
                });
            }
            self.custody = self
                .custody
                .checked_sub(withdrawal_remaining)
                .expect("admitted withdrawals are held in custody");
            self.claimable = self
                .claimable
                .checked_add(withdrawal_remaining)
                .expect("finalization preserves the combined custody domain");
            for request in slot.withdrawals.requests() {
                assert_eq!(
                    self.outstanding.remove(request.account()),
                    Some(request.clone())
                );
            }
            self.finalized = slot.successor;
            self.expected_epoch += 1;
        }
        ActionOutcome::new(expected, Some(&observation))
    }

    fn fault_unadmitted(&mut self, tick: u8, inclusive_boundary: bool) -> ActionOutcome {
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
                .expect("the oracle predicted an expired obligation");
            let (_, expected_reason) =
                expected_reason.expect("successful expiry requires an expired obligation");
            assert_eq!(reason, &expected_reason);
            self.enter_fault(expected_reason);
        }
        ActionOutcome::new(expected, None)
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

    /// Builds guaranteed-proven evidence of one challenge kind against a validated close.
    async fn challenge_evidence(
        &self,
        family: u8,
        context: &TestContext,
        close: &TestClose,
    ) -> (TestChallenge, ChallengeKind) {
        let key = &self.accounts[usize::from(family) % self.accounts.len()];
        let payer = key.public_key();
        let row = close
            .rows
            .binary_search_by(|candidate| candidate.account.cmp(&payer))
            .ok();
        let terminal_debit = row
            .and_then(|position| close.rows[position].outgoing.as_ref())
            .map_or(0, |send| send.body().cumulative_debit());
        let seq = row
            .and_then(|position| close.rows[position].outgoing.as_ref())
            .map_or(0, |send| send.body().seq());

        // A retained vector strictly above the committed terminal entry for (payer, external).
        let recipient = self.external_account();
        let committed = row.map(|position| &close.out_vectors[position]);
        let mut entries = committed.map_or_else(Vec::new, |vector| vector.entries().to_vec());
        match entries.binary_search_by(|entry| entry.recipient.cmp(&recipient)) {
            Ok(position) => {
                entries[position].cumulative = entries[position]
                    .cumulative
                    .checked_add(1)
                    .expect("bounded fixture edge cannot overflow");
                entries[position].count = entries[position]
                    .count
                    .checked_add(1)
                    .expect("bounded fixture edge cannot overflow");
            }
            Err(position) => entries.insert(
                position,
                OutEntry {
                    recipient: recipient.clone(),
                    cumulative: 1,
                    count: 1,
                },
            ),
        }
        let retained = OutVector::new(context.payment().epoch(), payer.clone(), entries)
            .expect("bounded retained vector is canonical");
        let retained_root = retained
            .root::<Sha256, Digest>()
            .expect("bounded retained vector commits");
        let ack = |seq: u64, debit: u64| {
            VectorAck::sign_by_authorities(
                VectorSendBody::new(context.payment(), payer.clone(), seq, debit, retained_root),
                key,
                &self.operator,
            )
        };
        let above = terminal_debit
            .checked_add(1)
            .expect("bounded fixture debit cannot overflow");
        match family % 3 {
            0 => {
                let range = close
                    .roots
                    .activity_range(context)
                    .expect("validated close has an exact activity range");
                let logs = self.state.as_ref().unwrap().logs();
                let epoch = Epoch::at(logs, context.payment().epoch(), range)
                    .await
                    .expect("an admitted close has retained native activity");
                (
                    Challenge::HigherAckDebit {
                        ack: Box::new(AckWitness::from_ack(&ack(seq + 1, above))),
                        payer: Box::new(
                            epoch
                                .account_lookup(logs, &payer)
                                .await
                                .expect("validated close has canonical payer evidence"),
                        ),
                    },
                    ChallengeKind::HigherAckDebit,
                )
            }
            1 => {
                let OutTipLookup::Present {
                    cumulative,
                    count,
                    opening,
                } = retained
                    .lookup::<Sha256, Digest>(&recipient)
                    .expect("retained entry has a lookup")
                else {
                    panic!("retained vector carries the disputed entry");
                };
                let range = close
                    .roots
                    .activity_range(context)
                    .expect("validated close has an exact activity range");
                let logs = self.state.as_ref().unwrap().logs();
                let epoch = Epoch::at(logs, context.payment().epoch(), range)
                    .await
                    .expect("an admitted close has retained native activity");
                (
                    Challenge::HigherAckEntry {
                        entry: Box::new(EntryWitness {
                            ack: AckWitness::from_ack(&ack(seq + 1, above)),
                            recipient: recipient.clone(),
                            cumulative,
                            count,
                            opening,
                        }),
                        sender: Box::new(
                            epoch
                                .higher_entry_lookup(logs, &payer, &recipient)
                                .await
                                .expect("validated close has canonical composed sender evidence"),
                        ),
                    },
                    ChallengeKind::HigherAckEntry,
                )
            }
            _ => (
                Challenge::AckFork {
                    left: Box::new(AckWitness::from_ack(&ack(seq + 1, above))),
                    right: Box::new(AckWitness::from_ack(&ack(
                        seq + 1,
                        above
                            .checked_add(1)
                            .expect("bounded fixture debit cannot overflow"),
                    ))),
                },
                ChallengeKind::AckFork,
            ),
        }
    }

    async fn challenge(
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
                .map(|slot| (slot.context.clone(), slot.batch_id(), slot.close.clone()))
        };
        let (context, batch, close, admitted) = if let Some((context, batch, close)) = selected {
            (context, batch, close, true)
        } else {
            let prepared = self.make_prepared().await;
            (
                prepared.context,
                prepared.close.header.batch_id::<Sha256>(),
                prepared.close,
                false,
            )
        };
        // The unknown-batch action has no applied native interval to serve. AckFork preserves the
        // negative challenge path without advancing the replica solely to manufacture evidence.
        let family = if admitted { mutation % 3 } else { 2 };
        let variant = (mutation / 4) % 4;
        let submitted_batch = if variant == 1 || (!encoded && variant != 0) {
            BatchId::new(self.digest(b"unknown-batch", step))
        } else {
            batch
        };
        let (challenge, kind) = self.challenge_evidence(family, &context, &close).await;
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
            self.chain
                .challenge_encoded(now, submitted_batch, &bytes, maximum)
        } else {
            self.chain.challenge(now, submitted_batch, &challenge)
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

    fn select_withdrawal_claim(
        &self,
        batch_selector: u8,
        claim_selector: u8,
        live_only: bool,
    ) -> Option<(usize, usize)> {
        let batches = self
            .finalized_claim_batches
            .iter()
            .enumerate()
            .filter_map(|(index, batch)| {
                (!batch.withdrawals.is_empty() && (!live_only || batch.is_live())).then_some(index)
            })
            .collect::<Vec<_>>();
        let batch_index = *batches.get(usize::from(batch_selector) % batches.len().max(1))?;
        let claims = self.finalized_claim_batches[batch_index].withdrawals.len();
        Some((batch_index, usize::from(claim_selector) % claims))
    }

    fn select_unconsumed_withdrawal_claim(
        &self,
        batch_selector: u8,
        claim_selector: u8,
    ) -> Option<(usize, usize)> {
        let batches =
            self.finalized_claim_batches
                .iter()
                .enumerate()
                .filter_map(|(index, batch)| {
                    (batch.is_live()
                        && batch.withdrawals.iter().any(|entry| {
                            !batch.claimed_withdrawals.contains(&entry.claim.position())
                        }))
                    .then_some(index)
                })
                .collect::<Vec<_>>();
        let batch_index = *batches.get(usize::from(batch_selector) % batches.len().max(1))?;
        let batch = &self.finalized_claim_batches[batch_index];
        let claims = batch
            .withdrawals
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                (!batch.claimed_withdrawals.contains(&entry.claim.position())).then_some(index)
            })
            .collect::<Vec<_>>();
        Some((
            batch_index,
            claims[usize::from(claim_selector) % claims.len()],
        ))
    }

    async fn claim_withdrawal(
        &mut self,
        batch_selector: u8,
        claim_selector: u8,
        mutation: u8,
    ) -> ActionOutcome {
        let mutation = mutation % 5;
        let selected = if mutation == 0 {
            self.select_unconsumed_withdrawal_claim(batch_selector, claim_selector)
        } else {
            self.select_withdrawal_claim(batch_selector, claim_selector, false)
        };
        let mut claim = selected.map_or_else(synthetic_withdrawal_claim, |(batch, index)| {
            self.finalized_claim_batches[batch].withdrawals[index]
                .claim
                .clone()
        });
        let finalized = self.chain.finalized_payouts();
        let accepted = selected.and_then(|(batch_index, claim_index)| {
            let batch = &self.finalized_claim_batches[batch_index];
            let entry = &batch.withdrawals[claim_index];
            (!batch.claimed_withdrawals.contains(&entry.claim.position())
                && mutation < 3
                && (mutation != 2 || batch.withdrawal_root == finalized))
                .then(|| {
                    (
                        batch_index,
                        entry.claim.position(),
                        entry.claim.output().clone(),
                    )
                })
        });
        if mutation != 2 && selected.is_some() {
            let (opening, _) = self
                .state
                .as_ref()
                .unwrap()
                .logs()
                .payout_opening(&finalized, claim.position(), NonZeroU64::MIN)
                .await
                .unwrap();
            claim = WithdrawalClaim::new(claim.output().clone(), opening);
        }
        if mutation == 3 {
            claim = malformed_withdrawal_claim(&claim);
        } else if mutation == 4 {
            let (output, mut opening) = <(WithdrawalOutput, LogOpening<Digest>)>::decode_cfg(
                claim.encode(),
                &(RangeCfg::new(..=usize::MAX), ()),
            )
            .unwrap();
            opening.proof = Default::default();
            claim = WithdrawalClaim::new(output, opening);
        }
        let expected = if accepted.is_some() {
            OutcomeClass::Success
        } else {
            OutcomeClass::Error
        };
        let interval = self
            .claims
            .range(..=claim.position())
            .next_back()
            .filter(|(_, end)| claim.position() < **end)
            .map(|(&start, &end)| UnclaimedInterval { start, end });
        let result = interval
            .ok_or(ClaimError::Unavailable)
            .and_then(|interval| {
                let effect = self.chain.claim_withdrawal(&interval, &claim)?;
                self.claims.remove(&interval.start);
                for fragment in effect.fragments.into_iter().flatten() {
                    self.claims.insert(fragment.start, fragment.end);
                }
                Ok(effect.output)
            });
        assert_eq!(OutcomeClass::of(&result), expected);
        if let Some((batch_index, position, expected_output)) = accepted {
            let output = result.expect("the oracle selected an unconsumed withdrawal output");
            assert_eq!(output, expected_output);
            let batch = &mut self.finalized_claim_batches[batch_index];
            assert!(batch.claimed_withdrawals.insert(position));
            batch.withdrawal_remaining = batch
                .withdrawal_remaining
                .checked_sub(output.amount())
                .unwrap();
            self.claimable = self.claimable.checked_sub(output.amount()).unwrap();
        }
        ActionOutcome::new(expected, None)
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

            if let Some(replay) = replay {
                assert_eq!(settlement, &replay);
                assert_eq!(before, self.snapshot());
            } else {
                // The frozen boundary replays verbatim, so the live custody
                // and deposit totals only match when it is first frozen.
                // Later claims drain the live values below the snapshot.
                assert_eq!(
                    settlement.unfinalized_deposit_total,
                    unfinalized_deposit_total
                );
                assert_eq!(settlement.custody_balance, self.custody);
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

    async fn claim_hard_fault(&mut self, account_selector: u8, mutation: u8) -> ActionOutcome {
        let (opening, selected) = self.hard_fault_opening(account_selector, mutation).await;
        let canonical = mutation.is_multiple_of(4);
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

            // Coverage is all-or-nothing at the frozen root: an amount the
            // frozen balance cannot cover releases zero and the whole balance
            // stays residual.
            let withdrawal_amount =
                request
                    .as_ref()
                    .map_or(0, |request| match request.body().action() {
                        WithdrawalAction::Amount(amount) if amount.get() <= leaf.balance => {
                            amount.get()
                        }
                        WithdrawalAction::Amount(_) => 0,
                        WithdrawalAction::Close => leaf.balance,
                    });
            let release = result.expect("the oracle predicted a terminal state release");
            assert_eq!(release.account, leaf.account);
            match (&release.withdrawal, &request) {
                (Some(output), Some(request)) => {
                    assert_eq!(output.destination(), request.body().destination());
                    assert_eq!(output.amount(), withdrawal_amount);
                }
                (None, None) => {}
                _ => panic!("hard-fault withdrawal output must match the queued request"),
            }
            assert_eq!(release.residual, leaf.balance - withdrawal_amount);
            assert_eq!(release.released_custody, leaf.balance);

            assert!(
                self.claimed_hard_fault_accounts
                    .insert(leaf.account.clone())
            );
            if let Some(request) = request {
                assert_eq!(self.outstanding.remove(&leaf.account), Some(request));
            }
            self.custody = self
                .custody
                .checked_sub(leaf.balance)
                .expect("authenticated state claims are held in active custody");
            self.finish_hard_fault_if_drained();
        }
        ActionOutcome::new(expected, None)
    }

    async fn hard_fault_opening(
        &mut self,
        account_selector: u8,
        mutation: u8,
    ) -> (StateOpening<VerifyingKey, Digest>, Option<BalanceEntry>) {
        let selected = (!self.finalized.is_empty()).then(|| {
            self.finalized.leaves()[usize::from(account_selector) % self.finalized.len()].clone()
        });
        let mut opening = if let Some(entry) = &selected {
            self.state
                .as_ref()
                .unwrap()
                .state()
                .opening_at(
                    self.finalized.root(),
                    self.finalized.head.operations(),
                    entry.account.clone(),
                )
                .await
                .unwrap()
        } else {
            self.foreign_opening.clone()
        };
        match mutation % 4 {
            0 => {}
            1 => opening.balance = NonZeroU64::new(opening.balance.get() + 1).unwrap(),
            2 => opening.account = self.external_account(),
            _ => {
                let account = opening.account.clone();
                opening = self.foreign_opening.clone();
                opening.account = account;
            }
        }
        (opening, selected)
    }
}

fn synthetic_withdrawal_claim() -> TestWithdrawalClaim {
    let output = WithdrawalOutput::decode_cfg(
        (Bytes::from_static(b"synthetic"), 1_u64).encode(),
        &(..=MAX_DESTINATION_BYTES).into(),
    )
    .expect("a bounded synthetic withdrawal output decodes");
    WithdrawalClaim::new(
        output,
        LogOpening {
            start: 0,
            proof: Default::default(),
        },
    )
}

fn malformed_withdrawal_claim(claim: &TestWithdrawalClaim) -> TestWithdrawalClaim {
    let destination = claim.output().destination();
    assert!(!destination.is_empty());
    let encoded_destination = destination.encode();
    let payload_offset = encoded_destination
        .len()
        .checked_sub(destination.len())
        .expect("a destination encoding contains its payload");
    let mut encoded = claim.encode().to_vec();
    encoded[payload_offset] ^= 1;
    let malformed = TestWithdrawalClaim::decode_cfg(encoded, &(..=MAX_DESTINATION_BYTES).into())
        .expect("mutating a destination byte preserves claim structure");
    assert_eq!(malformed.position(), claim.position());
    assert_ne!(malformed.output(), claim.output());
    malformed
}

fn output_total(outputs: &[WithdrawalOutput]) -> u64 {
    outputs
        .iter()
        .try_fold(0_u64, |total, release| total.checked_add(release.amount()))
        .expect("authenticated withdrawal outputs fit custody")
}

fn bls_ack(private: &Private, body: &VectorSendBody<VerifyingKey, Digest>) -> OperatorSignature {
    sign_message::<OperatorVariant>(
        private,
        VECTOR_ACK_AGGREGATE_NAMESPACE,
        body.encode().as_ref(),
    )
}

// Derive balances from input vectors and boundaries, then compare every public activity row.
fn successor_snapshot(
    predecessor: &TestCache,
    deposits: &TestDeposits,
    withdrawals: &TestWithdrawals,
    close: &TestClose,
    head: StateHead<Digest>,
) -> TestCache {
    let mut expected = predecessor
        .leaves
        .iter()
        .map(|entry| (entry.account.clone(), entry.balance))
        .collect::<BTreeMap<_, _>>();
    for record in deposits.records() {
        *expected.entry(record.account().clone()).or_default() += record.amount();
    }
    let mut credits = BTreeMap::<VerifyingKey, u64>::new();
    for vector in &close.out_vectors {
        let debit = vector
            .entries()
            .iter()
            .map(|entry| entry.cumulative)
            .sum::<u64>();
        if debit != 0 {
            *expected.get_mut(vector.payer()).unwrap() -= debit;
        }
        for entry in vector.entries() {
            *credits.entry(entry.recipient.clone()).or_default() += entry.cumulative;
        }
    }
    for (account, credit) in credits {
        *expected.entry(account).or_default() += credit;
    }
    for request in withdrawals.requests() {
        let balance = expected.entry(request.account().clone()).or_default();
        match request.body().action() {
            WithdrawalAction::Amount(amount) if amount.get() <= *balance => {
                *balance -= amount.get();
            }
            WithdrawalAction::Amount(_) => {}
            WithdrawalAction::Close => *balance = 0,
        }
    }
    for row in &close.rows {
        assert_eq!(row.predecessor, predecessor.balance(&row.account));
        assert_eq!(
            row.successor,
            expected.get(&row.account).copied().unwrap_or(0)
        );
    }
    let leaves = expected
        .into_iter()
        .filter(|(_, balance)| *balance > 0)
        .map(|(account, balance)| BalanceEntry { account, balance })
        .collect::<Vec<_>>();
    assert!(leaves.len() <= MAX_ACCOUNTS);
    let snapshot = TestCache { head, leaves };
    assert_eq!(snapshot.root(), close.roots.successor);
    assert_eq!(
        snapshot.liability(),
        predecessor.liability() + deposits.total() - close.withdrawal_total
    );
    assert_eq!(snapshot.len() as u64, head.live_accounts());
    snapshot
}

// A causal trace reaches finalized-root intake and account replay after a restart on every probe.
async fn lifecycle_probe(mut input: FuzzInput, runtime: deterministic::Context) {
    input.account_count = 1;
    input.balances = [7; MAX_ACCOUNTS];
    let mut harness = Harness::new(&input, runtime).await;
    let actions = [
        Action::RegisterCredit {
            tick: 0,
            payer: 0,
            amount: 1,
            mutated: false,
        },
        Action::Admit {
            tick: 0,
            mutated: false,
        },
        Action::Withdrawal {
            tick: 0,
            account: 0,
            amount: 0,
            destination: input.seed,
            destination_len: 3,
            closes_account: false,
            mutation: 9,
        },
        Action::Withdrawal {
            tick: 0,
            account: 0,
            amount: 0,
            destination: input.seed,
            destination_len: 3,
            closes_account: false,
            mutation: 0,
        },
        Action::Register {
            tick: 0,
            mutated: false,
        },
        Action::Admit {
            tick: 0,
            mutated: false,
        },
        Action::Restart,
        Action::Finalize {
            tick: 0,
            early: false,
        },
        Action::Withdrawal {
            tick: 0,
            account: 1,
            amount: 0,
            destination: input.seed,
            destination_len: 3,
            closes_account: false,
            mutation: 0,
        },
        Action::Challenge {
            tick: 0,
            slot: 0,
            encoded: true,
            mutation: 0,
        },
        Action::BeginHardFaultSettlement,
        Action::ClaimHardFault {
            account: 0,
            mutation: 0,
        },
        Action::Restart,
        Action::ClaimHardFault {
            account: 0,
            mutation: 0,
        },
        Action::ClaimHardFault {
            account: 1,
            mutation: 0,
        },
        Action::ClaimHardFault {
            account: 2,
            mutation: 0,
        },
        Action::ClaimWithdrawal {
            batch: 0,
            claim: 0,
            mutation: 0,
        },
        Action::ClaimWithdrawal {
            batch: 0,
            claim: 0,
            mutation: 0,
        },
    ];
    for (step, action) in actions.iter().enumerate() {
        harness.apply(step as u64, action).await;
        match step {
            1 => assert_eq!(harness.slots.len(), 1),
            2 => assert!(harness.outstanding.is_empty()),
            3 => assert_eq!(harness.outstanding.len(), 1),
            5 => assert_eq!(harness.slots.len(), 2),
            7 => assert_eq!(harness.slots.len(), 1),
            8 => assert_eq!(harness.outstanding.len(), 2),
            9 => assert!(harness.hard_fault.is_some()),
            11 | 13 => assert_eq!(harness.claimed_hard_fault_accounts.len(), 1),
            14 => assert_eq!(harness.claimed_hard_fault_accounts.len(), 2),
            15 => {
                assert_eq!(harness.claimed_hard_fault_accounts.len(), 3);
                assert!(harness.settled);
            }
            16 | 17 => assert_eq!(harness.claimable, 0),
            _ => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    let Ok(mut input) = FuzzInput::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };
    input.actions.truncate(MAX_ACTIONS);
    deterministic::Runner::seeded(input.seed).start(|runtime| async move {
        if mode % 2 == 0 {
            lifecycle_probe(input, runtime).await;
        } else {
            Harness::new(&input, runtime)
                .await
                .run(&input.actions)
                .await;
        }
    });
});
