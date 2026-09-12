use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, bls12381},
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    posted,
    qmdb::{self, State, StateHead, StateOpening, account_key},
    settlement::{EpochDeadlinePolicy, SettlementChain, SettlementConfig},
    transition::{
        CloseAmounts, CloseContext, CloseLimits, EpochContext, Header, OperatorKey, RootBundle,
        prepare_close_with_strategy, validate_close_with_strategy,
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
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, deterministic, utils::buffer::paged::CacheRef};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, TestRng, time::SYSTEM_TIME_PRECISION};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
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
const OPERATOR_BLS_SEED: u64 = 777;
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

type TestState = State<deterministic::Context, Sha256>;
type TestChain = SettlementChain<Sha256, VerifyingKey>;
type TestContext = CloseContext<VerifyingKey, Digest>;
type TestHeader = Header<Digest>;
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
    amounts: CloseAmounts,
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
    amounts: CloseAmounts,
    certificate: bls12381::Certificate,
}

struct ChainSource {
    head: StateHead<Digest>,
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

// The benchmark closes carry no payments, so this key countersigns nothing and only threads
// through close validation.
fn operator_bls() -> OperatorKey {
    compute_public::<MinSig>(&Private::new(Scalar::from(OPERATOR_BLS_SEED)))
}

fn state_config(context: &deterministic::Context) -> qmdb::Config<Sequential> {
    let cache = CacheRef::from_pooler(context, NZU16!(4096), NZUsize!(64));
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: "settlement-merkle".into(),
            metadata_partition: "settlement-merkle-meta".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: JournalConfig {
            partition: "settlement-operations".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(4096),
            page_cache: cache,
        },
        grafted_metadata_partition: "settlement-grafts".into(),
        translator: EightCap,
        init_cache_size: Some(NZUsize!(64)),
        init_buffer: NZUsize!(4096),
        init_concurrency: (),
    }
}

async fn state_fixture(
    runtime: deterministic::Context,
    live_accounts: usize,
) -> (TestState, Vec<Account>) {
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
    let genesis = accounts
        .iter()
        .map(|account| {
            (
                account_key(&account.public).expect("benchmark account key is canonical"),
                NonZeroU64::new(OPENING_BALANCE),
            )
        })
        .collect();
    let config = state_config(&runtime);
    let state = TestState::open(runtime, config)
        .await
        .expect("open native state");
    assert!(state.is_bootstrap());
    let genesis = state
        .prepare(state.head(), genesis)
        .await
        .expect("prepare canonical genesis");
    let state = state.apply(genesis).await.expect("apply canonical genesis");
    (state, accounts)
}

impl ChainSource {
    async fn new(
        runtime: deterministic::Context,
        live_accounts: usize,
        validator_count: usize,
    ) -> (Self, TestState, Vec<Account>) {
        let (state, accounts) = state_fixture(runtime, live_accounts).await;
        (
            Self {
                head: *state.head(),
                validators: Validators::new(validator_count),
            },
            state,
            accounts,
        )
    }

    fn fresh_chain(&self, max_pending_epochs: usize) -> TestChain {
        SettlementChain::new(
            deployment(),
            SigningKey::from_seed(OPERATOR_SEED).public_key(),
            self.validators.committee.clone(),
            &(&self.head).into(),
            0,
            settlement_config(
                max_pending_epochs,
                usize::try_from(self.head.live_accounts())
                    .expect("benchmark account count fits in usize"),
            ),
        )
        .expect("benchmark settlement chain is valid")
    }
}

#[commonware_macros::boxed]
async fn admission_fixture(
    state: TestState,
    validators: &Validators,
    epoch: u64,
    withdrawals: TestWithdrawals,
) -> (TestState, AdmissionFixture) {
    let deposits = DepositBatch::empty();

    // Sequential registrations require strictly increasing admission deadlines.
    let admission_deadline = ADMISSION_DEADLINE + epoch;
    let context = EpochContext::new::<Sha256>(
        deployment(),
        epoch,
        SigningKey::from_seed(OPERATOR_SEED).public_key(),
        &deposits,
        &withdrawals,
        state.liability(),
        admission_deadline,
        admission_deadline + (CHALLENGE_DEADLINE - ADMISSION_DEADLINE),
        CloseLimits::protocol_maximum(),
        validators.committee.commitment::<Sha256>(),
    )
    .expect("benchmark epoch is valid")
    .bind::<Sha256, _, _>(&state, &deposits, &withdrawals)
    .await
    .expect("benchmark close context is valid");
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &context,
        &deposits,
        &withdrawals,
        Vec::new(),
        &Sequential,
    )
    .await
    .expect("benchmark close is valid");
    let dealing =
        posted::decode(prepared.encoded().clone(), &context).expect("benchmark dealing decodes");
    let validated = validate_close_with_strategy::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
        &state,
        &context,
        &operator_bls(),
        &deposits,
        &withdrawals,
        dealing,
        &mut TestRng::new(0),
        &Sequential,
    )
    .await
    .expect("benchmark complete dealing validates");
    assert_eq!(prepared.close().header, validated.close().header);
    drop(prepared);
    let (state, close) = validated
        .apply(state)
        .await
        .expect("benchmark close applies");
    assert_eq!(state.root(), close.roots.successor);
    let certificate = validators.certificate(&close.header);
    (
        state,
        AdmissionFixture {
            context,
            withdrawals,
            header: close.header,
            roots: close.roots,
            amounts: close.amounts,
            certificate,
        },
    )
}

fn admit_fixture(chain: &mut TestChain, admission: AdmissionFixture) {
    let AdmissionFixture {
        context,
        withdrawals,
        header,
        roots,
        amounts,
        certificate,
    } = admission;
    chain
        .register_close(0, context, withdrawals, &[], |_| true)
        .expect("benchmark close can be registered");
    chain
        .admit(0, header, roots, amounts, certificate)
        .expect("benchmark close can be admitted");
}

fn signed_withdrawal(
    state: &TestState,
    account: &Account,
    deadline: u64,
) -> SignedWithdrawal<VerifyingKey, Digest> {
    SignedWithdrawal::sign(
        deployment(),
        state.root().digest,
        Bytes::from_static(b"benchmark-destination"),
        WithdrawalAction::Amount(NonZeroU64::MIN),
        deadline,
        &account.private,
    )
}

async fn withdrawal_sources(
    state: &TestState,
    accounts: &[Account],
    count: usize,
    deadline: u64,
) -> Vec<WithdrawalSource> {
    let mut withdrawals = Vec::with_capacity(count);
    for account in accounts.iter().take(count) {
        let opening = state
            .opening(account.public.clone())
            .await
            .expect("benchmark account can be opened");
        assert_eq!(
            opening.verify::<Sha256>(&state.root()).unwrap().get(),
            OPENING_BALANCE
        );
        withdrawals.push(WithdrawalSource {
            request: signed_withdrawal(state, account, deadline),
            opening,
        });
    }
    withdrawals
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

#[commonware_macros::boxed]
async fn queue_source(runtime: deterministic::Context, depth: usize) -> QueueSource {
    let (chain, mut state, accounts) = ChainSource::new(runtime, LIVE_ACCOUNTS, 1).await;
    let request = signed_withdrawal(&state, &accounts[0], WITHDRAWAL_DEADLINE);
    let mut openings = vec![state.opening(accounts[0].public.clone()).await.unwrap()];
    let mut admissions = Vec::with_capacity(depth);
    for epoch in 0..depth {
        let (next, admission) = admission_fixture(
            state,
            &chain.validators,
            u64::try_from(epoch).unwrap(),
            WithdrawalBatch::empty(),
        )
        .await;
        state = next;
        openings.push(state.opening(accounts[0].public.clone()).await.unwrap());
        admissions.push(admission);
    }
    let source = QueueSource {
        chain,
        admissions,
        request,
        openings,
    };
    let input = queue_input(&source);
    let roots = input.chain.withdrawal_safety_roots();
    assert_eq!(roots.len(), source.openings.len());
    for (root, opening) in roots.iter().zip(&source.openings) {
        assert_eq!(
            opening.verify::<Sha256>(root).unwrap().get(),
            OPENING_BALANCE
        );
    }
    source
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

async fn close_source(
    runtime: deterministic::Context,
    withdrawal_count: usize,
    validator_count: usize,
) -> CloseSource {
    let (chain, state, accounts) = ChainSource::new(runtime, LIVE_ACCOUNTS, validator_count).await;
    let withdrawals =
        withdrawal_sources(&state, &accounts, withdrawal_count, WITHDRAWAL_DEADLINE).await;
    let mut seed_chain = chain.fresh_chain(1);
    queue_withdrawals(&mut seed_chain, &withdrawals);
    let (_, admission) = admission_fixture(
        state,
        &chain.validators,
        0,
        seed_chain.pending_withdrawals(),
    )
    .await;
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
        amounts,
        certificate,
    } = source.admission.clone();
    chain
        .register_close(0, context, withdrawals, &[], |_| true)
        .expect("benchmark close can be registered");
    AdmitInput {
        chain,
        header,
        roots,
        amounts,
        certificate,
    }
}

fn finalize_input(source: &CloseSource) -> TestChain {
    let mut chain = source.chain.fresh_chain(1);
    queue_withdrawals(&mut chain, &source.withdrawals);
    admit_fixture(&mut chain, source.admission.clone());
    chain
}

async fn hard_fault_source(
    runtime: deterministic::Context,
    live_accounts: usize,
    claims: usize,
) -> HardFaultSource {
    assert!(claims > 0 && claims <= live_accounts);
    let (chain, state, accounts) = ChainSource::new(runtime, live_accounts, 1).await;
    let withdrawals = withdrawal_sources(&state, &accounts, claims, FAULT_DEADLINE).await;
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

// Runtime startup, QMDB construction, proof generation, and per-iteration chain preparation
// are excluded. Only the operation between Instant::now and elapsed contributes to Criterion.
fn bench_queue_withdrawal(c: &mut Criterion) {
    for &depth in QUEUE_DEPTHS {
        c.bench_function(
            &format!(
                "{}/op=queue depth={depth} live_accounts={LIVE_ACCOUNTS}",
                module_path!()
            ),
            |b| {
                b.iter_custom(|iterations| {
                    deterministic::Runner::new(
                        deterministic::Config::default().with_cycle(SYSTEM_TIME_PRECISION),
                    )
                    .start(|runtime| async move {
                        let source = queue_source(runtime, depth).await;
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iterations {
                            let mut input = queue_input(&source);
                            let start = Instant::now();
                            input
                                .chain
                                .queue_withdrawal(
                                    black_box(0),
                                    input.request,
                                    black_box(&source.openings),
                                    |_| true,
                                )
                                .expect("benchmark withdrawal can be queued");
                            elapsed += start.elapsed();
                            black_box(input.chain);
                        }
                        elapsed
                    })
                })
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
            b.iter_custom(|iterations| {
                deterministic::Runner::new(deterministic::Config::default().with_cycle(SYSTEM_TIME_PRECISION)).start(|runtime| async move {
                    let source = close_source(runtime, 1, ADMISSION_VALIDATORS).await;
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let mut input = admit_input(&source);
                        let start = Instant::now();
                        let batch = input.chain.admit(
                            black_box(0), input.header, input.roots, input.amounts, input.certificate,
                        ).expect("benchmark close can be admitted");
                        elapsed += start.elapsed();
                        black_box(batch);
                        black_box(input.chain);
                    }
                    elapsed
                })
            })
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
                b.iter_custom(|iterations| {
                    deterministic::Runner::new(
                        deterministic::Config::default().with_cycle(SYSTEM_TIME_PRECISION),
                    )
                    .start(|runtime| async move {
                        let source = close_source(runtime, withdrawals, 1).await;
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iterations {
                            let mut chain = finalize_input(&source);
                            let start = Instant::now();
                            let finalized = chain
                                .finalize(black_box(FINALIZE_AT))
                                .expect("benchmark close can be finalized");
                            elapsed += start.elapsed();
                            black_box(finalized);
                            black_box(chain);
                        }
                        elapsed
                    })
                })
            },
        );
    }
}

fn bench_hard_fault(c: &mut Criterion) {
    for &(live_accounts, claims) in HARD_FAULT_PROFILES {
        c.bench_function(
            &format!(
                "{}/op=begin-hard-fault live_accounts={live_accounts} withdrawals={claims}",
                module_path!()
            ),
            |b| {
                b.iter_custom(|iterations| {
                    deterministic::Runner::new(
                        deterministic::Config::default().with_cycle(SYSTEM_TIME_PRECISION),
                    )
                    .start(|runtime| async move {
                        let source = hard_fault_source(runtime, live_accounts, claims).await;
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iterations {
                            let mut chain = hard_fault_input(&source);
                            let start = Instant::now();
                            let settlement = chain
                                .begin_hard_fault_settlement()
                                .expect("benchmark hard-fault claims can begin");
                            elapsed += start.elapsed();
                            black_box(settlement);

                            // Exercise independent recovery with the retained frozen-root Current proofs.
                            for withdrawal in &source.withdrawals {
                                black_box(
                                    chain
                                        .claim_hard_fault(&withdrawal.opening)
                                        .expect("benchmark account can recover"),
                                );
                            }
                            black_box(chain);
                        }
                        elapsed
                    })
                })
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_queue_withdrawal, bench_admit, bench_finalize, bench_hard_fault,
}
