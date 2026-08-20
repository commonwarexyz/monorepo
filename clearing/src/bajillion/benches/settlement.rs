use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, HeaderSubject, curve25519},
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalBatch},
    challenge::{RowOpening, StateOpening},
    commitment::{self, VectorKind},
    credit::ShardSet,
    settlement::{SettlementChain, SettlementConfig},
    state::{AccountRow, AccountState, Prefix, StateLeaf},
    transition::{Assignment, Close, CloseContext, CloseLimits, Header, StateCache, build_close},
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    certificate::Scheme as _,
    curve25519::{SigningKey, VerifyingKey},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, test_rng};
use criterion::{BatchSize, Criterion, criterion_group};
use std::{
    hint::black_box,
    num::{NonZeroU64, NonZeroUsize},
};

const REGISTRY: usize = 1_024;
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
type TestHeader = Header<VerifyingKey, Digest>;
type TestWithdrawals = WithdrawalBatch<VerifyingKey, Digest>;

struct Account {
    private: SigningKey,
    public: VerifyingKey,
}

struct Validators {
    committee: Committee<VerifyingKey>,
    signers: Vec<curve25519::Scheme<VerifyingKey>>,
}

impl Validators {
    fn new(count: usize) -> Self {
        let mut keys = (0..count)
            .map(|index| {
                let index = u64::try_from(index).expect("validator index fits in u64");
                let private = SigningKey::from_seed(VALIDATOR_SEED_START + index);
                (private.public_key(), private)
            })
            .collect::<Vec<_>>();
        keys.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let committee = Committee::new(
            keys.iter()
                .map(|(public, _)| public.clone())
                .collect::<Vec<_>>(),
        )
        .expect("benchmark committee is canonical");
        let signers = keys
            .into_iter()
            .take(committee.quorum())
            .map(|(_, private)| {
                curve25519::Scheme::signer(committee.clone(), private)
                    .expect("benchmark validator belongs to the committee")
            })
            .collect();
        Self { committee, signers }
    }

    fn certificate(&self, header: &TestHeader) -> curve25519::Certificate {
        let attestations = self
            .signers
            .iter()
            .map(|signer| {
                signer
                    .sign(HeaderSubject::from_header(header))
                    .expect("benchmark validator can sign")
            })
            .collect::<Vec<_>>();
        self.signers[0]
            .assemble_exact(attestations, &Sequential)
            .expect("benchmark certificate has an exact quorum")
    }
}

struct PreparedClose {
    context: TestContext,
    deposits: DepositBatch<VerifyingKey>,
    withdrawals: TestWithdrawals,
    header: TestHeader,
    certificate: curve25519::Certificate,
    terminal: Option<RowOpening<VerifyingKey, Digest>>,
}

struct QueueInput {
    chain: TestChain,
    request: SignedWithdrawal<VerifyingKey, Digest>,
    openings: Vec<StateOpening<VerifyingKey, Digest>>,
}

struct AdmitInput {
    chain: TestChain,
    header: TestHeader,
    certificate: curve25519::Certificate,
    terminal: Option<RowOpening<VerifyingKey, Digest>>,
    rng: TestRng,
}

const fn nonzero_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("benchmark bound is positive")
}

fn settlement_config(max_pending_epochs: usize, registry: usize) -> SettlementConfig {
    SettlementConfig::new(
        nonzero_usize(max_pending_epochs.max(1)),
        NonZeroU64::new(1).expect("benchmark notice is positive"),
        NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).expect("benchmark maximum notice is positive"),
        nonzero_usize(registry),
        64,
        nonzero_usize(registry),
    )
}

fn deployment() -> Digest {
    Sha256::hash(&[b"clearing-settlement-benchmark"])
}

fn registry(registry: usize) -> (TestCache, Vec<Account>) {
    let mut accounts = (0..registry)
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
    CloseContext::new::<Sha256>(
        deployment(),
        epoch,
        SigningKey::from_seed(OPERATOR_SEED).public_key(),
        cache,
        deposits,
        withdrawals,
        ADMISSION_DEADLINE,
        CHALLENGE_DEADLINE,
        CloseLimits::protocol_maximum(),
        Assignment::new(validators.committee.commitment::<Sha256>(), 0)
            .expect("benchmark assignment is valid"),
    )
    .expect("benchmark close context is valid")
}

fn withdrawal_close(
    cache: &TestCache,
    context: &TestContext,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &TestWithdrawals,
) -> TestClose {
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
        let applied = if request.body().full_close() {
            opening.balance
        } else {
            request.body().amount()
        };
        let mut closing = opening;
        closing.balance = closing
            .balance
            .checked_sub(applied)
            .expect("benchmark withdrawal is affordable");
        closing.active = opening.active && !request.body().full_close();
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
    build_close::<Sha256, _, _>(cache, context, deposits, withdrawals, rows, shard_sets)
        .expect("benchmark close is valid")
}

fn terminal_opening(close: &TestClose) -> Option<RowOpening<VerifyingKey, Digest>> {
    let count = u32::try_from(close.rows.len()).expect("benchmark row count fits in u32");
    if count == 0 {
        return None;
    }
    let mut builder = commitment::Builder::<Sha256>::new(VectorKind::Change, count)
        .expect("benchmark change tree is valid");
    for row in &close.rows {
        builder
            .add_encoded(row.encode().as_ref())
            .expect("benchmark row count matches the tree");
    }
    let tree = builder.build().expect("benchmark change tree is complete");
    let position = count - 1;
    Some(RowOpening {
        row: close.rows[position as usize].clone(),
        proof: tree
            .opening(position)
            .expect("benchmark terminal row can be opened"),
    })
}

fn prepared_close(
    cache: &TestCache,
    validators: &Validators,
    epoch: u64,
    withdrawals: TestWithdrawals,
) -> PreparedClose {
    let deposits = DepositBatch::empty();
    let context = context(cache, validators, epoch, &deposits, &withdrawals);
    let close = withdrawal_close(cache, &context, &deposits, &withdrawals);
    let certificate = validators.certificate(&close.header);
    let terminal = terminal_opening(&close);
    PreparedClose {
        context,
        deposits,
        withdrawals,
        header: close.header,
        certificate,
        terminal,
    }
}

fn admit_prepared(chain: &mut TestChain, prepared: PreparedClose) {
    let PreparedClose {
        context,
        deposits,
        withdrawals,
        header,
        certificate,
        terminal,
    } = prepared;
    chain
        .register(0, context, deposits, withdrawals)
        .expect("benchmark close can be registered");
    chain
        .admit(
            0,
            header,
            certificate,
            terminal.as_ref(),
            &mut test_rng(),
            &Sequential,
        )
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
        1,
        false,
        deadline,
        &account.private,
    )
    .expect("benchmark withdrawal is valid")
}

fn queue_input(depth: usize) -> QueueInput {
    let (cache, accounts) = registry(REGISTRY);
    let validators = Validators::new(1);
    let mut chain = chain(&cache, &validators, depth);
    for epoch in 0..depth {
        let epoch = u64::try_from(epoch).expect("benchmark epoch fits in u64");
        admit_prepared(
            &mut chain,
            prepared_close(&cache, &validators, epoch, WithdrawalBatch::empty()),
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
    let (cache, accounts) = registry(REGISTRY);
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
    let prepared = prepared_close(&cache, &validators, 0, chain.pending_withdrawals());
    chain
        .register(0, prepared.context, prepared.deposits, prepared.withdrawals)
        .expect("benchmark close can be registered");
    AdmitInput {
        chain,
        header: prepared.header,
        certificate: prepared.certificate,
        terminal: prepared.terminal,
        rng: test_rng(),
    }
}

fn finalize_input(withdrawals: usize) -> TestChain {
    let (cache, accounts) = registry(REGISTRY);
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
    let prepared = prepared_close(&cache, &validators, 0, chain.pending_withdrawals());
    admit_prepared(&mut chain, prepared);
    chain
}

fn hard_fault_input(registry_size: usize, claims: usize) -> (TestChain, TestCache) {
    assert!(claims > 0 && claims <= registry_size);
    let (cache, accounts) = registry(registry_size);
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
                "{}/op=queue depth={depth} registry={REGISTRY}",
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
            "{}/op=admit registry={REGISTRY} n={ADMISSION_VALIDATORS} q={ADMISSION_QUORUM} withdrawals=1",
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
                                input.certificate,
                                black_box(input.terminal.as_ref()),
                                &mut input.rng,
                                &Sequential,
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
                "{}/op=finalize registry={REGISTRY} withdrawals={withdrawals}",
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
    for &(registry, claims) in HARD_FAULT_PROFILES {
        c.bench_function(
            &format!(
                "{}/op=unwind registry={registry} claims={claims}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || hard_fault_input(registry, claims),
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
