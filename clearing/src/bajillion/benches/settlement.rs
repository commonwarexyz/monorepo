use super::fixtures::strategy;
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, bls12381},
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::StateOpening,
    credit::ShardSet,
    settlement::{SettlementChain, SettlementConfig},
    state::{AccountRow, AccountState, Prefix, StateLeaf},
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

struct AdmissionFixture {
    context: TestContext,
    deposits: DepositBatch<VerifyingKey>,
    withdrawals: TestWithdrawals,
    header: TestHeader,
    roots: RootBundle<Digest>,
    terminal_proof: TestTerminalProof,
    certificate: bls12381::Certificate,
}

struct QueueInput {
    chain: TestChain,
    request: SignedWithdrawal<VerifyingKey, Digest>,
    openings: Vec<StateOpening<VerifyingKey, Digest>>,
}

struct AdmitInput {
    chain: TestChain,
    header: TestHeader,
    roots: RootBundle<Digest>,
    terminal_proof: TestTerminalProof,
    certificate: bls12381::Certificate,
}

const fn nonzero_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("benchmark bound is positive")
}

fn settlement_config(max_pending_epochs: usize, live_accounts: usize) -> SettlementConfig {
    SettlementConfig::new(
        nonzero_usize(max_pending_epochs.max(1)),
        NonZeroU64::new(1).expect("benchmark notice is positive"),
        NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).expect("benchmark maximum notice is positive"),
        nonzero_usize(live_accounts),
        64,
        nonzero_usize(live_accounts),
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

fn context(
    cache: &TestCache,
    validators: &Validators,
    epoch: u64,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &TestWithdrawals,
) -> TestContext {
    EpochContext::new::<Sha256>(
        deployment(),
        epoch,
        SigningKey::from_seed(OPERATOR_SEED).public_key(),
        deposits,
        withdrawals,
        cache.liability(),
        ADMISSION_DEADLINE,
        CHALLENGE_DEADLINE,
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
        let opening = cache
            .leaves()
            .iter()
            .find(|leaf| leaf.account == account)
            .expect("benchmark withdrawal account is registered")
            .state;
        let (applied, closes_account) = match request.body().action() {
            WithdrawalAction::Amount(amount) => (amount.get(), false),
            WithdrawalAction::Close => (opening.balance, true),
        };
        let mut closing = opening;
        closing.balance = closing
            .balance
            .checked_sub(applied)
            .expect("benchmark withdrawal is affordable");
        closing.active = opening.active && !closes_account;
        let shards = ShardSet::empty(context.payment().epoch(), account.clone());
        prefix = prefix
            .checked_extend(Prefix {
                withdrawal: applied,
                withdrawals: 1,
                ..Prefix::default()
            })
            .expect("benchmark totals are representable");
        rows.push(AccountRow {
            account,
            opening,
            closing,
            outgoing: None,
            credit_root: shards
                .root::<Sha256>()
                .expect("benchmark credit root is valid"),
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
        deposits,
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
        deposits,
        withdrawals,
        header,
        roots,
        terminal_proof,
        certificate,
    } = admission;
    chain
        .register(0, context, deposits, withdrawals)
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

fn queue_input(depth: usize) -> QueueInput {
    let (cache, accounts) = state_fixture(LIVE_ACCOUNTS);
    let validators = Validators::new(1);
    let mut chain = chain(&cache, &validators, depth);
    for epoch in 0..depth {
        let epoch = u64::try_from(epoch).expect("benchmark epoch fits in u64");
        admit_fixture(
            &mut chain,
            admission_fixture(&cache, &validators, epoch, WithdrawalBatch::empty()),
        );
    }
    let opening = cache
        .opening(&accounts[0].public)
        .expect("benchmark account can be opened");
    QueueInput {
        chain,
        request: signed_withdrawal(&cache, &accounts[0], WITHDRAWAL_DEADLINE),
        openings: vec![opening; depth + 1],
    }
}

fn admit_input() -> AdmitInput {
    let (cache, accounts) = state_fixture(LIVE_ACCOUNTS);
    let validators = Validators::new(ADMISSION_VALIDATORS);
    let mut chain = chain(&cache, &validators, 1);
    let request = signed_withdrawal(&cache, &accounts[0], WITHDRAWAL_DEADLINE);
    chain
        .queue_withdrawal(
            0,
            request,
            &[cache
                .opening(&accounts[0].public)
                .expect("benchmark account can be opened")],
            |_| true,
        )
        .expect("benchmark withdrawal can be queued");
    let admission = admission_fixture(&cache, &validators, 0, chain.pending_withdrawals());
    chain
        .register(
            0,
            admission.context,
            admission.deposits,
            admission.withdrawals,
        )
        .expect("benchmark close can be registered");
    AdmitInput {
        chain,
        header: admission.header,
        roots: admission.roots,
        terminal_proof: admission.terminal_proof,
        certificate: admission.certificate,
    }
}

fn finalize_input(withdrawals: usize) -> TestChain {
    let (cache, accounts) = state_fixture(LIVE_ACCOUNTS);
    let validators = Validators::new(1);
    let mut chain = chain(&cache, &validators, 1);
    for account in accounts.iter().take(withdrawals) {
        let request = signed_withdrawal(&cache, account, WITHDRAWAL_DEADLINE);
        chain
            .queue_withdrawal(
                0,
                request,
                &[cache
                    .opening(&account.public)
                    .expect("benchmark account can be opened")],
                |_| true,
            )
            .expect("benchmark withdrawal can be queued");
    }
    let admission = admission_fixture(&cache, &validators, 0, chain.pending_withdrawals());
    admit_fixture(&mut chain, admission);
    chain
}

fn hard_fault_input(live_accounts: usize, claims: usize) -> (TestChain, TestCache) {
    assert!(claims > 0 && claims <= live_accounts);
    let (cache, accounts) = state_fixture(live_accounts);
    let validators = Validators::new(1);
    let mut chain = chain(&cache, &validators, 1);
    for account in accounts.iter().take(claims) {
        let request = signed_withdrawal(&cache, account, FAULT_DEADLINE);
        chain
            .queue_withdrawal(
                0,
                request,
                &[cache
                    .opening(&account.public)
                    .expect("benchmark account can be opened")],
                |_| true,
            )
            .expect("benchmark withdrawal can be queued");
    }
    chain
        .fault_expired_withdrawal(FAULT_DEADLINE)
        .expect("benchmark withdrawal deadline creates a hard fault");
    (chain, cache)
}

fn bench_queue_withdrawal(c: &mut Criterion) {
    for &depth in QUEUE_DEPTHS {
        c.bench_function(
            &format!(
                "{}/op=queue depth={depth} live_accounts={LIVE_ACCOUNTS}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || queue_input(depth),
                    |mut input| {
                        input
                            .chain
                            .queue_withdrawal(
                                black_box(0),
                                input.request,
                                black_box(&input.openings),
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
    c.bench_function(
        &format!(
            "{}/op=admit live_accounts={LIVE_ACCOUNTS} n={ADMISSION_VALIDATORS} q={ADMISSION_QUORUM} withdrawals=1",
            module_path!()
        ),
        |b| {
            b.iter_batched(
                admit_input,
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
        c.bench_function(
            &format!(
                "{}/op=finalize live_accounts={LIVE_ACCOUNTS} withdrawals={withdrawals}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || finalize_input(withdrawals),
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
        c.bench_function(
            &format!(
                "{}/op=unwind live_accounts={live_accounts} claims={claims}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || hard_fault_input(live_accounts, claims),
                    |(mut chain, cache)| {
                        black_box(
                            chain
                                .settle_hard_fault(black_box(&cache))
                                .expect("benchmark hard fault can be settled"),
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
