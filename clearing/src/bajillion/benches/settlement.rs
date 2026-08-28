use super::fixtures::strategy;
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, bls12381},
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::StateOpening,
    credit::ShardSet,
    settlement::{EpochDeadlinePolicy, SettlementChain, SettlementConfig},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        Assignment, Close, CloseContext, CloseLimits, EpochContext, Header, RootBundle, StateCache,
        TerminalProof, prepare_close_with_strategy,
    },
};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::compute_public,
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{SigningKey, StrictVerifyingKey as VerifyingKey};
use criterion::{BatchSize, Criterion, criterion_group};
use std::{
    hint::black_box,
    num::{NonZeroU64, NonZeroUsize},
};

const LIVE_ACCOUNTS: usize = 1_024;
const OPENING_BALANCE: u64 = 1_000;
const ADMISSION_DEADLINE: u64 = 10;
const CHALLENGE_DEADLINE: u64 = 20;
const FINALIZE_AT: u64 = CHALLENGE_DEADLINE + 1;
const WITHDRAWAL_DEADLINE: u64 = 100;
const MAXIMUM_WITHDRAWAL_NOTICE: u64 = 1_000;
const FAULT_DEADLINE: u64 = 2;
const OPERATOR_SEED: u64 = 1;
const ACCOUNT_SEED_START: u64 = 10_000;
const VALIDATOR_SEED_START: u64 = 1_000_000;
const ADMISSION_VALIDATORS: usize = 100;
const ADMISSION_QUORUM: usize = 67;

const QUEUE_DEPTHS: &[usize] = &[0, 1, 4, 16];
const FINALIZE_WITHDRAWALS: &[usize] = &[0, 1, 16, 256];

#[cfg(not(full_bench))]
const HARD_FAULT_PROFILES: &[(usize, usize)] = &[(16, 1), (1_024, 1), (1_024, 64), (16_384, 256)];
#[cfg(full_bench)]
const HARD_FAULT_PROFILES: &[(usize, usize)] = &[
    (16, 1),
    (1_024, 1),
    (1_024, 64),
    (16_384, 256),
    (1_000_000, 1_024),
];

type TestCache = StateCache<VerifyingKey, Digest>;
type TestChain = SettlementChain<Sha256, VerifyingKey>;
type TestClose = Close<VerifyingKey, Digest>;
type TestContext = CloseContext<VerifyingKey, Digest>;
type TestHeader = Header<Digest>;
type TestTerminalProof = TerminalProof<Digest>;
type TestWithdrawals = WithdrawalBatch<VerifyingKey, Digest>;

struct Account {
    private: SigningKey,
    public: VerifyingKey,
}

struct Validators {
    committee: Committee,
    signers: Vec<bls12381::Scheme>,
}

impl Validators {
    fn new(count: usize) -> Self {
        let mut keys = (0..count)
            .map(|index| {
                let index = u64::try_from(index).expect("validator index fits in u64");
                let signing = Private::new(Scalar::from(VALIDATOR_SEED_START + index + 1));
                (compute_public::<MinSig>(&signing), signing)
            })
            .collect::<Vec<_>>();
        keys.sort_unstable_by_key(|validator| validator.0);
        let committee = Committee::new(keys.iter().map(|(public, _)| *public).collect::<Vec<_>>())
            .expect("benchmark committee is canonical");
        let signers = keys
            .into_iter()
            .take(committee.quorum())
            .map(|(_, signing)| {
                bls12381::Scheme::signer(committee.clone(), signing)
                    .expect("benchmark validator belongs to the committee")
            })
            .collect();
        Self { committee, signers }
    }

    fn certificate(&self, header: &TestHeader) -> bls12381::Certificate {
        let attestations = self
            .signers
            .iter()
            .map(|signer| signer.sign(header).expect("benchmark validator can sign"))
            .collect::<Vec<_>>();
        self.signers[0]
            .assemble_exact(attestations)
            .expect("benchmark certificate has an exact quorum")
    }
}

#[derive(Clone)]
struct AdmissionFixture {
    context: TestContext,
    withdrawals: TestWithdrawals,
    header: TestHeader,
    roots: RootBundle<Digest>,
    terminal_proof: TestTerminalProof,
    certificate: bls12381::Certificate,
}

struct QueueInput {
    chain: TestChain,
    request: SignedWithdrawal<VerifyingKey, Digest>,
}

struct AdmitInput {
    chain: TestChain,
    header: TestHeader,
    roots: RootBundle<Digest>,
    terminal_proof: TestTerminalProof,
    certificate: bls12381::Certificate,
}

struct ChainSource {
    cache: TestCache,
    validators: Validators,
}

struct WithdrawalSource {
    request: SignedWithdrawal<VerifyingKey, Digest>,
    opening: StateOpening<VerifyingKey, Digest>,
}

struct QueueSource {
    chain: ChainSource,
    admissions: Vec<AdmissionFixture>,
    request: SignedWithdrawal<VerifyingKey, Digest>,
    openings: Vec<StateOpening<VerifyingKey, Digest>>,
}

struct CloseSource {
    chain: ChainSource,
    withdrawals: Vec<WithdrawalSource>,
    admission: AdmissionFixture,
}

struct HardFaultSource {
    chain: ChainSource,
    withdrawals: Vec<WithdrawalSource>,
}

const fn nonzero_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("benchmark bound is positive")
}

fn settlement_config(max_pending_epochs: usize, live_accounts: usize) -> SettlementConfig {
    SettlementConfig::new(
        nonzero_usize(max_pending_epochs.max(2)),
        EpochDeadlinePolicy::new(
            NonZeroU64::new(ADMISSION_DEADLINE).expect("benchmark admission delay is positive"),
            NonZeroU64::new(CHALLENGE_DEADLINE - ADMISSION_DEADLINE)
                .expect("benchmark challenge duration is positive"),
            NonZeroU64::new(CHALLENGE_DEADLINE - ADMISSION_DEADLINE)
                .expect("benchmark challenge duration is positive"),
        ),
        NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).expect("benchmark deposit timeout is positive"),
        NonZeroU64::new(1).expect("benchmark notice is positive"),
        NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).expect("benchmark maximum notice is positive"),
        64,
        nonzero_usize(live_accounts),
    )
}

fn deployment() -> Digest {
    Sha256::hash(&[b"clearing-settlement-benchmark"])
}

fn state_fixture(live_accounts: usize) -> (TestCache, Vec<Account>) {
    let mut accounts = (0..live_accounts)
        .map(|index| {
            let index = u64::try_from(index).expect("account index fits in u64");
            let private = SigningKey::from_seed(ACCOUNT_SEED_START + index);
            Account {
                public: private.public_key(),
                private,
            }
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|left, right| left.public.cmp(&right.public));
    let leaves = accounts
        .iter()
        .map(|account| StateLeaf {
            account: account.public.clone(),
            state: AccountState {
                balance: OPENING_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect();
    let cache = StateCache::new::<Sha256>(leaves).expect("benchmark state is canonical");
    (cache, accounts)
}

fn chain(cache: &TestCache, validators: &Validators, max_pending_epochs: usize) -> TestChain {
    SettlementChain::new(
        deployment(),
        SigningKey::from_seed(OPERATOR_SEED).public_key(),
        validators.committee.clone(),
        cache,
        0,
        settlement_config(max_pending_epochs, cache.len()),
    )
    .expect("benchmark settlement chain is valid")
}

impl ChainSource {
    fn new(live_accounts: usize, validator_count: usize) -> (Self, Vec<Account>) {
        let (cache, accounts) = state_fixture(live_accounts);
        (
            Self {
                cache,
                validators: Validators::new(validator_count),
            },
            accounts,
        )
    }

    fn fresh_chain(&self, max_pending_epochs: usize) -> TestChain {
        chain(&self.cache, &self.validators, max_pending_epochs)
    }
}

fn context(
    cache: &TestCache,
    validators: &Validators,
    epoch: u64,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &TestWithdrawals,
) -> TestContext {
    // Sequential registrations must present strictly increasing admission
    // deadlines, so each epoch's deadlines advance from the base constants
    // while keeping the exact configured challenge duration.
    let admission_deadline = ADMISSION_DEADLINE + epoch;
    let challenge_deadline = admission_deadline + (CHALLENGE_DEADLINE - ADMISSION_DEADLINE);
    EpochContext::new::<Sha256>(
        deployment(),
        epoch,
        SigningKey::from_seed(OPERATOR_SEED).public_key(),
        deposits,
        withdrawals,
        cache.liability(),
        admission_deadline,
        challenge_deadline,
        CloseLimits::protocol_maximum(),
        Assignment::new(validators.committee.commitment::<Sha256>(), 0)
            .expect("benchmark assignment is valid"),
    )
    .and_then(|epoch| epoch.bind::<Sha256>(cache, deposits, withdrawals))
    .expect("benchmark close context is valid")
}

fn withdrawal_close(
    cache: &TestCache,
    context: &TestContext,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &TestWithdrawals,
) -> (TestClose, TestTerminalProof) {
    let mut prefix = Prefix::default();
    let mut rows = Vec::with_capacity(withdrawals.len());
    let mut shard_sets = Vec::with_capacity(withdrawals.len());
    for request in withdrawals.requests() {
        let account = request.account().clone();
        let predecessor = cache
            .leaves()
            .iter()
            .find(|leaf| leaf.account == account)
            .expect("benchmark withdrawal account is registered")
            .state;
        let (applied, closes_account) = match request.body().action() {
            WithdrawalAction::Amount(amount) => (amount.get(), false),
            WithdrawalAction::Close => (predecessor.balance, true),
        };
        let mut successor = predecessor;
        successor.balance = successor
            .balance
            .checked_sub(applied)
            .expect("benchmark withdrawal is affordable");
        successor.active = predecessor.active && !closes_account;
        let shards = ShardSet::empty(context.payment().epoch(), account.clone());
        prefix = prefix
            .checked_extend(Prefix {
                withdrawal: applied,
                withdrawal_count: 1,
                ..Prefix::default()
            })
            .expect("benchmark totals are representable");
        rows.push(AccountRow {
            account,
            predecessor,
            successor,
            outgoing: None,
            output: SettlementOutput::Withdrawal(applied),
            prefix,
        });
        shard_sets.push(shards);
    }
    let prepared = prepare_close_with_strategy::<Sha256, _, _>(
        cache,
        context,
        deposits,
        withdrawals,
        rows,
        shard_sets,
        strategy(),
    )
    .expect("benchmark close is valid");
    prepared
        .validate::<Sha256>(context, deposits, withdrawals)
        .expect("benchmark close is valid");
    let terminal_proof = prepared
        .terminal_proof()
        .expect("benchmark terminal proof is valid");
    (prepared.into_close(), terminal_proof)
}

fn admission_fixture(
    cache: &TestCache,
    validators: &Validators,
    epoch: u64,
    withdrawals: TestWithdrawals,
) -> AdmissionFixture {
    let deposits = DepositBatch::empty();
    let context = context(cache, validators, epoch, &deposits, &withdrawals);
    let (close, terminal_proof) = withdrawal_close(cache, &context, &deposits, &withdrawals);
    let certificate = validators.certificate(&close.header);
    AdmissionFixture {
        context,
        withdrawals,
        header: close.header,
        roots: close.roots,
        terminal_proof,
        certificate,
    }
}

fn admit_fixture(chain: &mut TestChain, admission: AdmissionFixture) {
    let AdmissionFixture {
        context,
        withdrawals,
        header,
        roots,
        terminal_proof,
        certificate,
    } = admission;
    chain
        .register_close(0, context, withdrawals, &[], |_| true)
        .expect("benchmark close can be registered");
    chain
        .admit(0, header, roots, terminal_proof, certificate)
        .expect("benchmark close can be admitted");
}

fn signed_withdrawal(
    cache: &TestCache,
    account: &Account,
    deadline: u64,
) -> SignedWithdrawal<VerifyingKey, Digest> {
    SignedWithdrawal::sign(
        deployment(),
        cache.root().digest,
        Bytes::from_static(b"benchmark-destination"),
        WithdrawalAction::Amount(NonZeroU64::MIN),
        deadline,
        &account.private,
    )
}

fn withdrawal_sources(
    cache: &TestCache,
    accounts: &[Account],
    count: usize,
    deadline: u64,
) -> Vec<WithdrawalSource> {
    accounts
        .iter()
        .take(count)
        .map(|account| WithdrawalSource {
            request: signed_withdrawal(cache, account, deadline),
            opening: cache
                .opening(&account.public)
                .expect("benchmark account can be opened"),
        })
        .collect()
}

fn queue_withdrawals(chain: &mut TestChain, withdrawals: &[WithdrawalSource]) {
    for withdrawal in withdrawals {
        chain
            .queue_withdrawal(
                0,
                withdrawal.request.clone(),
                std::slice::from_ref(&withdrawal.opening),
                |_| true,
            )
            .expect("benchmark withdrawal can be queued");
    }
}

fn queue_source(depth: usize) -> QueueSource {
    let (chain, accounts) = ChainSource::new(LIVE_ACCOUNTS, 1);
    let admissions = (0..depth)
        .map(|epoch| {
            let epoch = u64::try_from(epoch).expect("benchmark epoch fits in u64");
            admission_fixture(
                &chain.cache,
                &chain.validators,
                epoch,
                WithdrawalBatch::empty(),
            )
        })
        .collect();
    let opening = chain
        .cache
        .opening(&accounts[0].public)
        .expect("benchmark account can be opened");
    let request = signed_withdrawal(&chain.cache, &accounts[0], WITHDRAWAL_DEADLINE);
    QueueSource {
        chain,
        admissions,
        request,
        openings: vec![opening; depth + 1],
    }
}

fn queue_input(source: &QueueSource) -> QueueInput {
    let mut chain = source.chain.fresh_chain(source.admissions.len());
    for admission in source.admissions.iter().cloned() {
        admit_fixture(&mut chain, admission);
    }
    QueueInput {
        chain,
        request: source.request.clone(),
    }
}

fn close_source(withdrawal_count: usize, validator_count: usize) -> CloseSource {
    let (chain, accounts) = ChainSource::new(LIVE_ACCOUNTS, validator_count);
    let withdrawals = withdrawal_sources(
        &chain.cache,
        &accounts,
        withdrawal_count,
        WITHDRAWAL_DEADLINE,
    );
    let mut seed_chain = chain.fresh_chain(1);
    queue_withdrawals(&mut seed_chain, &withdrawals);
    let admission = admission_fixture(
        &chain.cache,
        &chain.validators,
        0,
        seed_chain.pending_withdrawals(),
    );
    CloseSource {
        chain,
        withdrawals,
        admission,
    }
}

fn admit_input(source: &CloseSource) -> AdmitInput {
    let mut chain = source.chain.fresh_chain(1);
    queue_withdrawals(&mut chain, &source.withdrawals);
    let AdmissionFixture {
        context,
        withdrawals,
        header,
        roots,
        terminal_proof,
        certificate,
    } = source.admission.clone();
    chain
        .register_close(0, context, withdrawals, &[], |_| true)
        .expect("benchmark close can be registered");
    AdmitInput {
        chain,
        header,
        roots,
        terminal_proof,
        certificate,
    }
}

fn finalize_input(source: &CloseSource) -> TestChain {
    let mut chain = source.chain.fresh_chain(1);
    queue_withdrawals(&mut chain, &source.withdrawals);
    admit_fixture(&mut chain, source.admission.clone());
    chain
}

fn hard_fault_source(live_accounts: usize, claims: usize) -> HardFaultSource {
    assert!(claims > 0 && claims <= live_accounts);
    let (chain, accounts) = ChainSource::new(live_accounts, 1);
    let withdrawals = withdrawal_sources(&chain.cache, &accounts, claims, FAULT_DEADLINE);
    HardFaultSource { chain, withdrawals }
}

fn hard_fault_input(source: &HardFaultSource) -> TestChain {
    let mut chain = source.chain.fresh_chain(1);
    queue_withdrawals(&mut chain, &source.withdrawals);
    chain
        .fault_expired(FAULT_DEADLINE)
        .expect("benchmark withdrawal deadline creates a hard fault");
    chain
}

fn bench_queue_withdrawal(c: &mut Criterion) {
    for &depth in QUEUE_DEPTHS {
        let source = queue_source(depth);
        c.bench_function(
            &format!(
                "{}/op=queue depth={depth} live_accounts={LIVE_ACCOUNTS}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || queue_input(&source),
                    |mut input| {
                        input
                            .chain
                            .queue_withdrawal(
                                black_box(0),
                                input.request,
                                black_box(&source.openings),
                                |_| true,
                            )
                            .expect("benchmark withdrawal can be queued");
                        black_box(&input.chain);
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

fn bench_admit(c: &mut Criterion) {
    let source = close_source(1, ADMISSION_VALIDATORS);
    c.bench_function(
        &format!(
            "{}/op=admit live_accounts={LIVE_ACCOUNTS} n={ADMISSION_VALIDATORS} q={ADMISSION_QUORUM} withdrawals=1",
            module_path!()
        ),
        |b| {
            b.iter_batched(
                || admit_input(&source),
                |mut input| {
                    black_box(
                        input
                            .chain
                            .admit(
                                black_box(0),
                                input.header,
                                input.roots,
                                input.terminal_proof,
                                input.certificate,
                            )
                            .expect("benchmark close can be admitted"),
                    )
                },
                BatchSize::LargeInput,
            );
        },
    );
}

fn bench_finalize(c: &mut Criterion) {
    for &withdrawals in FINALIZE_WITHDRAWALS {
        let source = close_source(withdrawals, 1);
        c.bench_function(
            &format!(
                "{}/op=finalize live_accounts={LIVE_ACCOUNTS} withdrawals={withdrawals}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || finalize_input(&source),
                    |mut chain| {
                        black_box(
                            chain
                                .finalize(black_box(FINALIZE_AT))
                                .expect("benchmark close can be finalized"),
                        )
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

fn bench_hard_fault(c: &mut Criterion) {
    for &(live_accounts, claims) in HARD_FAULT_PROFILES {
        let source = hard_fault_source(live_accounts, claims);
        c.bench_function(
            &format!(
                "{}/op=begin-hard-fault live_accounts={live_accounts} withdrawals={claims}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || hard_fault_input(&source),
                    |mut chain| {
                        black_box(
                            chain
                                .begin_hard_fault_settlement()
                                .expect("benchmark hard-fault claims can begin"),
                        )
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_queue_withdrawal,
        bench_admit,
        bench_finalize,
        bench_hard_fault,
}
