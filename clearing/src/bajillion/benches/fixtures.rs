use commonware_clearing::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    challenge::{AccountLookup, Challenge, ChallengeKind, Verdict, adjudicate},
    credit::{ShardHead, ShardLookup, ShardSet},
    payment::{Payment, PaymentContext, SignedReceipt, SignedSend},
    state::{AccountRow, AccountState, Prefix, StateLeaf},
    transition::{
        Assignment, Close, CloseContext, CloseLimits, Header, PreparedClose, RootBundle,
        StateCache, prepare_close_with_strategy,
    },
};
use commonware_cryptography::{Hasher, Sha256, Signer as _, sha256::Digest};
use commonware_cryptography_curve25519::signing::{SigningKey, StrictVerifyingKey as VerifyingKey};
use commonware_parallel::Rayon;
use std::{num::NonZeroUsize, ops::Deref, sync::OnceLock};

pub(crate) const WORKERS: usize = 8;
pub(crate) const PROFILE_ENV: &str = "COMMONWARE_CLEARING_PROFILE";

pub(crate) fn strategy() -> &'static Rayon {
    static STRATEGY: OnceLock<Rayon> = OnceLock::new();
    STRATEGY.get_or_init(|| {
        Rayon::new(NonZeroUsize::new(WORKERS).expect("worker count is nonzero"))
            .expect("benchmark worker pool must initialize")
    })
}

#[derive(Clone, Copy)]
pub(crate) struct ActiveProfile {
    pub(crate) live_accounts: usize,
    pub(crate) changed_accounts: usize,
    pub(crate) credited_accounts: usize,
    pub(crate) receive_shards_per_credited: usize,
}

impl ActiveProfile {
    const fn new(
        live_accounts: usize,
        changed_accounts: usize,
        credited_accounts: usize,
        receive_shards_per_credited: usize,
    ) -> Self {
        Self {
            live_accounts,
            changed_accounts,
            credited_accounts,
            receive_shards_per_credited,
        }
    }

    pub(crate) const fn terminal_shards(self) -> usize {
        self.credited_accounts
            .checked_mul(self.receive_shards_per_credited)
            .expect("benchmark terminal shard count fits in usize")
    }

    const fn credited_state_position(self, credited: usize) -> usize {
        credited
            .checked_mul(self.live_accounts)
            .expect("benchmark credited-account state spacing fits in usize")
            / self.credited_accounts
    }

    fn changed_positions(self) -> Vec<usize> {
        (0..self.changed_accounts)
            .map(|changed| {
                changed
                    .checked_mul(self.live_accounts)
                    .expect("benchmark changed-account spacing fits in usize")
                    / self.changed_accounts
            })
            .collect()
    }

    fn credited_accounts(self, changed_positions: &[usize]) -> Vec<usize> {
        (0..self.credited_accounts)
            .map(|credited| {
                changed_positions
                    .binary_search(&self.credited_state_position(credited))
                    .expect("every benchmark recipient is a changed account")
            })
            .collect()
    }
}

#[cfg(not(full_bench))]
pub(crate) const ACTIVE_PROFILES: &[ActiveProfile] = &[
    ActiveProfile::new(128, 128, 64, 1),
    ActiveProfile::new(256, 256, 64, 1),
    ActiveProfile::new(512, 512, 64, 1),
    ActiveProfile::new(1_024, 1_024, 64, 1),
];

#[cfg(full_bench)]
pub(crate) const ACTIVE_PROFILES: &[ActiveProfile] = &[
    ActiveProfile::new(1_024, 1_024, 512, 1),
    ActiveProfile::new(10_000, 10_000, 512, 1),
    ActiveProfile::new(100_000, 100_000, 512, 1),
    ActiveProfile::new(1_000_000, 1_000_000, 512, 1),
];

fn profile_key(profile: ActiveProfile) -> String {
    format!(
        "N={},A={},B={},h={}",
        profile.live_accounts,
        profile.changed_accounts,
        profile.credited_accounts,
        profile.receive_shards_per_credited,
    )
}

pub(crate) fn selected_active_profiles() -> Vec<(usize, ActiveProfile)> {
    #[cfg(full_bench)]
    assert_eq!(
        ACTIVE_PROFILES.len(),
        4,
        "the retained blog matrix has exactly four profiles"
    );
    let Ok(selector) = std::env::var(PROFILE_ENV) else {
        return ACTIVE_PROFILES.iter().copied().enumerate().collect();
    };
    let selected = selector
        .parse::<usize>()
        .ok()
        .filter(|index| *index < ACTIVE_PROFILES.len())
        .or_else(|| {
            ACTIVE_PROFILES
                .iter()
                .position(|profile| profile_key(*profile) == selector)
        })
        .unwrap_or_else(|| {
            panic!(
                "{PROFILE_ENV}={selector:?} is invalid; use a zero-based profile index or N=...,A=...,B=...,h=..."
            )
        });
    vec![(selected, ACTIVE_PROFILES[selected])]
}

#[cfg(not(full_bench))]
pub(crate) const STATE_CACHE_SIZES: &[usize] = &[1_024, 16_384];
#[cfg(full_bench)]
pub(crate) const STATE_CACHE_SIZES: &[usize] = &[1_024, 16_384, 1_000_000];

const ACCOUNT_SEED_START: u64 = 10_000;
const OPERATOR_SEED: u64 = 1;
const EPOCH: u64 = 7;
const OPENING_BALANCE: u64 = 1_000_000;
const ADMISSION_DEADLINE: u64 = 98;
const CHALLENGE_DEADLINE: u64 = 99;

pub(crate) type TestPayment = Payment<VerifyingKey, Digest>;
pub(crate) type TestStateCache = StateCache<VerifyingKey, Digest>;

struct Account {
    public: VerifyingKey,
    private: SigningKey,
}

#[derive(Clone, Copy)]
struct Edge {
    payer: usize,
    recipient: usize,
    shard: u64,
}

type EndpointSet = (
    Vec<Option<TestPayment>>,
    Vec<Vec<ShardHead<VerifyingKey, Digest>>>,
);

pub(crate) struct CloseFixture {
    pub(crate) cache: TestStateCache,
    pub(crate) context: CloseContext<VerifyingKey, Digest>,
    pub(crate) deposits: DepositBatch<VerifyingKey>,
    pub(crate) withdrawals: WithdrawalBatch<VerifyingKey, Digest>,
    pub(crate) prepared: PreparedClose<VerifyingKey, Digest>,
}

impl Deref for CloseFixture {
    type Target = Close<VerifyingKey, Digest>;

    fn deref(&self) -> &Self::Target {
        self.prepared.close()
    }
}

pub(crate) struct PaymentFixture {
    pub(crate) context: PaymentContext<VerifyingKey, Digest>,
    pub(crate) payment: TestPayment,
}

pub(crate) struct ChallengeFixture {
    pub(crate) context: CloseContext<VerifyingKey, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) challenge: Challenge<VerifyingKey, Digest>,
}

fn opening_state() -> AccountState {
    AccountState {
        balance: OPENING_BALANCE,
        active: true,
        ..AccountState::default()
    }
}

fn accounts(live_accounts: usize) -> Vec<Account> {
    let mut accounts = (0..live_accounts)
        .map(|index| {
            let index = u64::try_from(index).expect("benchmark account index fits in u64");
            let private = SigningKey::from_seed(ACCOUNT_SEED_START + index);
            Account {
                public: private.public_key(),
                private,
            }
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|left, right| left.public.cmp(&right.public));
    accounts
}

fn leaves(accounts: &[Account]) -> Vec<StateLeaf<VerifyingKey>> {
    accounts
        .iter()
        .map(|account| StateLeaf {
            account: account.public.clone(),
            state: opening_state(),
        })
        .collect()
}

pub(crate) fn state_leaves(live_accounts: usize) -> Vec<StateLeaf<VerifyingKey>> {
    leaves(&accounts(live_accounts))
}

fn payment_context(operator: &SigningKey) -> PaymentContext<VerifyingKey, Digest> {
    PaymentContext::new(
        Sha256::hash(&[b"clearing-benchmark-anchor"]),
        EPOCH,
        operator.public_key(),
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_payment(
    context: &PaymentContext<VerifyingKey, Digest>,
    operator: &SigningKey,
    payer: &SigningKey,
    recipient: &SigningKey,
    shard: u64,
    previous_debit: u64,
    previous_credit: u64,
    previous_index: u64,
) -> TestPayment {
    let send = SignedSend::sign_next(context, payer, recipient.public_key(), 1, previous_debit)
        .expect("benchmark send is valid");
    let receipt = SignedReceipt::issue_next::<Sha256, _>(
        context,
        &send,
        shard,
        previous_credit,
        previous_index,
        operator,
    )
    .expect("benchmark receipt is valid");
    Payment::new::<Sha256>(context, send, receipt).expect("benchmark payment is valid")
}

fn assemble_close_fixture<F>(
    live_accounts: usize,
    changed_positions: &[usize],
    assignment: Assignment<Digest>,
    endpoints: F,
) -> (CloseFixture, Vec<Account>)
where
    F: FnOnce(&PaymentContext<VerifyingKey, Digest>, &SigningKey, &[&Account]) -> EndpointSet,
{
    let changed = changed_positions.len();
    assert!(changed > 0 && changed <= live_accounts);
    assert!(changed_positions[0] < live_accounts);
    assert!(
        changed_positions
            .windows(2)
            .all(|positions| positions[0] < positions[1] && positions[1] < live_accounts)
    );
    let accounts = accounts(live_accounts);
    let cache = StateCache::new::<Sha256>(leaves(&accounts)).expect("benchmark state is canonical");
    let changed_accounts = changed_positions
        .iter()
        .map(|position| &accounts[*position])
        .collect::<Vec<_>>();
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = CloseContext::new::<Sha256>(
        Sha256::hash(&[b"clearing-benchmark-deployment"]),
        EPOCH,
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        ADMISSION_DEADLINE,
        CHALLENGE_DEADLINE,
        CloseLimits::protocol_maximum(),
        assignment,
    )
    .expect("benchmark close context is valid");
    let payment_context = context.payment().clone();

    let (mut outgoing, incoming) = endpoints(&payment_context, &operator, &changed_accounts);
    assert_eq!(outgoing.len(), changed);
    assert_eq!(incoming.len(), changed);

    let mut rows = Vec::with_capacity(changed);
    let mut shard_sets = Vec::with_capacity(changed);
    for (index, (account, mut heads)) in changed_accounts.into_iter().zip(incoming).enumerate() {
        heads.sort_unstable_by_key(|head| head.shard);
        let sent = outgoing[index]
            .as_ref()
            .map_or(0, |payment| payment.send().body().cumulative_debit());
        let shards = if heads.is_empty() {
            ShardSet::empty(payment_context.epoch(), account.public.clone())
        } else {
            ShardSet::new(payment_context.epoch(), account.public.clone(), heads)
                .expect("benchmark shards are canonical")
        };
        let credit_root = shards
            .root::<Sha256>()
            .expect("benchmark credit root is valid");
        let received = credit_root.total_credit;
        let receipts = credit_root.total_receipts;
        assert_ne!(sent + received, 0, "every disclosed account must change");
        let opening = opening_state();
        let closing = AccountState {
            balance: opening
                .balance
                .checked_sub(sent)
                .and_then(|balance| balance.checked_add(received))
                .expect("benchmark balance is valid"),
            cumulative_debit: sent,
            cumulative_credit: received,
            receipt_count: receipts,
            active: true,
        };
        rows.push(AccountRow {
            account: account.public.clone(),
            opening,
            closing,
            outgoing: outgoing[index].take(),
            credit_root,
            prefix: Prefix::default(),
        });
        shard_sets.push(shards);
    }

    let mut prefix = Prefix::default();
    for (row, shards) in rows.iter_mut().zip(&shard_sets) {
        let (debit, credit, _) = row.checked_deltas().expect("benchmark counters advance");
        prefix = prefix
            .checked_extend(Prefix {
                debit,
                credit,
                shards: u64::try_from(shards.heads().len())
                    .expect("benchmark shard count fits in u64"),
                ..Prefix::default()
            })
            .expect("benchmark prefix is valid");
        row.prefix = prefix;
    }

    let prepared = prepare_close_with_strategy::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        rows,
        shard_sets,
        strategy(),
    )
    .expect("benchmark close is valid");
    prepared
        .validate::<Sha256>(&context, &deposits, &withdrawals)
        .expect("benchmark close is valid");
    (
        CloseFixture {
            cache,
            context,
            deposits,
            withdrawals,
            prepared,
        },
        accounts,
    )
}

fn make_close_fixture(
    live_accounts: usize,
    changed: usize,
    edges: &[Edge],
    assignment: Assignment<Digest>,
) -> (CloseFixture, Vec<Account>) {
    let changed_positions = (0..changed).collect::<Vec<_>>();
    assemble_close_fixture(
        live_accounts,
        &changed_positions,
        assignment,
        |context, operator, accounts| {
            let mut outgoing = (0..changed).map(|_| None).collect::<Vec<_>>();
            let mut incoming = (0..changed).map(|_| Vec::new()).collect::<Vec<_>>();
            for edge in edges {
                assert!(edge.payer < changed && edge.recipient < changed);
                assert!(outgoing[edge.payer].is_none());
                assert!(
                    !incoming[edge.recipient]
                        .iter()
                        .any(|head: &ShardHead<VerifyingKey, Digest>| head.shard == edge.shard)
                );
                let payment = signed_payment(
                    context,
                    operator,
                    &accounts[edge.payer].private,
                    &accounts[edge.recipient].private,
                    edge.shard,
                    0,
                    0,
                    0,
                );
                outgoing[edge.payer] = Some(payment.clone());
                incoming[edge.recipient].push(ShardHead::new(edge.shard, payment));
            }
            (outgoing, incoming)
        },
    )
}

pub(crate) fn active_close_fixture(profile: ActiveProfile) -> CloseFixture {
    let assignment = Assignment::new(Sha256::hash(&[b"clearing-benchmark-committee"]), 8)
        .expect("benchmark assignment is valid");
    active_close_fixture_with_assignment(profile, assignment)
}

pub(crate) fn active_close_fixture_with_assignment(
    profile: ActiveProfile,
    assignment: Assignment<Digest>,
) -> CloseFixture {
    active_close_fixture_parts(profile, assignment).0
}

fn active_close_fixture_parts(
    profile: ActiveProfile,
    assignment: Assignment<Digest>,
) -> (CloseFixture, Vec<Account>) {
    let ActiveProfile {
        live_accounts,
        changed_accounts,
        credited_accounts,
        receive_shards_per_credited,
    } = profile;
    assert!(changed_accounts > 0 && changed_accounts <= live_accounts);
    assert!(credited_accounts > 0 && credited_accounts <= changed_accounts);
    assert!(receive_shards_per_credited > 0);
    let terminal_shards = profile.terminal_shards();
    let payment_count = changed_accounts.max(terminal_shards);
    let changed_positions = profile.changed_positions();
    let credited_rows = profile.credited_accounts(&changed_positions);
    assert!((0..credited_accounts).all(|credited| {
        changed_positions[credited_rows[credited]] == profile.credited_state_position(credited)
    }));

    let (fixture, accounts) = assemble_close_fixture(
        live_accounts,
        &changed_positions,
        assignment,
        |context, operator, accounts| {
            let mut outgoing = (0..changed_accounts).map(|_| None).collect::<Vec<_>>();
            let mut heads = (0..terminal_shards).map(|_| None).collect::<Vec<_>>();
            for index in 0..payment_count {
                let payer = index % changed_accounts;
                let shard_slot = index % terminal_shards;
                let credited = shard_slot / receive_shards_per_credited;
                let recipient = credited_rows[credited];
                let shard = shard_slot % receive_shards_per_credited;
                let payment = signed_payment(
                    context,
                    operator,
                    &accounts[payer].private,
                    &accounts[recipient].private,
                    u64::try_from(shard).expect("benchmark shard fits in u64"),
                    u64::try_from(index / changed_accounts)
                        .expect("benchmark payer sequence fits in u64"),
                    u64::try_from(index / terminal_shards)
                        .expect("benchmark shard credit fits in u64"),
                    u64::try_from(index / terminal_shards)
                        .expect("benchmark receipt index fits in u64"),
                );
                let payer_terminal = index + changed_accounts >= payment_count;
                let shard_terminal = index + terminal_shards >= payment_count;
                match (payer_terminal, shard_terminal) {
                    (true, true) => {
                        outgoing[payer] = Some(payment.clone());
                        heads[shard_slot] = Some(payment);
                    }
                    (true, false) => outgoing[payer] = Some(payment),
                    (false, true) => heads[shard_slot] = Some(payment),
                    (false, false) => unreachable!("one endpoint dimension spans every payment"),
                }
            }

            assert!(outgoing.iter().all(Option::is_some));
            assert!(heads.iter().all(Option::is_some));
            let mut incoming = (0..changed_accounts)
                .map(|_| Vec::new())
                .collect::<Vec<_>>();
            for (shard_slot, payment) in heads.into_iter().enumerate() {
                let credited = shard_slot / receive_shards_per_credited;
                let recipient = credited_rows[credited];
                let shard = shard_slot % receive_shards_per_credited;
                incoming[recipient].push(ShardHead::new(
                    u64::try_from(shard).expect("benchmark shard fits in u64"),
                    payment.expect("every benchmark shard has a terminal head"),
                ));
            }
            (outgoing, incoming)
        },
    );

    assert_eq!(fixture.rows.len(), changed_accounts);
    assert!(fixture.rows.iter().all(|row| row.outgoing.is_some()));
    assert_eq!(
        fixture
            .shard_sets
            .iter()
            .filter(|shards| !shards.heads().is_empty())
            .count(),
        credited_accounts
    );
    assert_eq!(
        fixture
            .shard_sets
            .iter()
            .map(|shards| shards.heads().len())
            .sum::<usize>(),
        terminal_shards
    );
    assert!((0..credited_accounts).all(|credited| {
        fixture.shard_sets[credited_rows[credited]].heads().len() == receive_shards_per_credited
    }));
    (fixture, accounts)
}

pub(crate) fn payment_fixture() -> PaymentFixture {
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let payer = SigningKey::from_seed(2);
    let recipient = SigningKey::from_seed(3);
    let context = payment_context(&operator);
    let payment = signed_payment(&context, &operator, &payer, &recipient, 4, 0, 0, 0);
    PaymentFixture { context, payment }
}

pub(crate) fn active_chain_fixture(
    profile: ActiveProfile,
    assignment: Assignment<Digest>,
) -> (CloseFixture, Challenge<VerifyingKey, Digest>) {
    let (fixture, accounts) = active_close_fixture_parts(profile, assignment);
    let row_position = fixture
        .shard_sets
        .iter()
        .position(|shards| shards.heads().iter().any(|head| head.shard == 0))
        .expect("the active profile credits shard zero");
    assert_eq!(row_position, 0);
    let public_tip = fixture.shard_sets[row_position]
        .heads()
        .iter()
        .find(|head| head.shard == 0)
        .expect("the active profile has a shard-zero tip")
        .payment
        .clone();
    let recipient_position = accounts
        .binary_search_by(|account| account.public.cmp(&fixture.rows[row_position].account))
        .expect("the challenged recipient is registered");
    assert_eq!(recipient_position, 0);
    let public_receipt = public_tip.receipt().body();
    let previous_debit = fixture.rows[row_position].closing.cumulative_debit;
    let previous_credit = public_receipt.cumulative_shard_credit();
    let previous_index = public_receipt.index();
    let expected_debit = previous_debit
        .checked_add(1)
        .expect("benchmark payer debit advances");
    let expected_credit = previous_credit
        .checked_add(1)
        .expect("benchmark shard credit advances");
    let expected_index = previous_index
        .checked_add(1)
        .expect("benchmark shard index advances");
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let retained = signed_payment(
        fixture.context.payment(),
        &operator,
        &accounts[recipient_position].private,
        &accounts[recipient_position].private,
        0,
        previous_debit,
        previous_credit,
        previous_index,
    );
    retained
        .verify_linked::<Sha256>(fixture.context.payment())
        .expect("benchmark retained payment is linked");
    assert_eq!(retained.recipient(), &fixture.rows[row_position].account);
    assert_eq!(retained.send().body().cumulative_debit(), expected_debit);
    assert_eq!(retained.receipt().body().shard(), 0);
    assert_eq!(
        retained.receipt().body().cumulative_shard_credit(),
        expected_credit
    );
    assert_eq!(retained.receipt().body().index(), expected_index);

    let recipient = fixture
        .prepared
        .row_opening(u32::try_from(row_position).expect("benchmark row position fits in u32"))
        .expect("benchmark recipient row can be opened");
    assert_eq!(recipient.proof.position, 0);
    assert_eq!(
        recipient.proof.proof.leaf_count,
        u32::try_from(fixture.rows.len()).expect("benchmark row count fits in u32")
    );
    let recipient = AccountLookup::Present(Box::new(recipient));
    assert_eq!(
        fixture.shard_sets[row_position]
            .root::<Sha256>()
            .expect("benchmark shard set has a valid root"),
        fixture.rows[row_position].credit_root
    );
    let shard = fixture.shard_sets[row_position]
        .lookup::<Sha256>(0)
        .expect("benchmark shard has a valid opening");
    let ShardLookup::Present { opening } = &shard else {
        unreachable!("benchmark shard zero is present")
    };
    assert_eq!(opening.proof.position, 0);
    assert_eq!(
        opening.proof.proof.leaf_count,
        u32::try_from(profile.receive_shards_per_credited)
            .expect("benchmark shard count fits in u32")
    );
    let challenge = Challenge::HigherShardTip {
        batch: fixture.prepared.close().header.batch_id::<Sha256>(),
        payment: Box::new(retained),
        recipient: Box::new(recipient),
        shard: Box::new(shard),
    };
    assert_eq!(
        adjudicate::<Sha256, _>(
            &fixture.context,
            &fixture.prepared.close().header,
            &fixture.prepared.close().roots,
            fixture.context.challenge_deadline(),
            &challenge,
        )
        .expect("benchmark challenge is well formed"),
        Verdict::Proven(ChallengeKind::HigherShardTip)
    );
    (fixture, challenge)
}

pub(crate) fn challenge_fixture(
    live_accounts: usize,
    change_rows: usize,
    receive_shards: usize,
) -> ChallengeFixture {
    assert!(receive_shards > 0 && receive_shards < change_rows);
    assert_eq!((change_rows - receive_shards - 1) % 2, 0);
    let mut edges = (0..receive_shards)
        .map(|shard| Edge {
            payer: shard + 1,
            recipient: 0,
            shard: u64::try_from(shard).expect("benchmark shard fits in u64"),
        })
        .collect::<Vec<_>>();
    let mut account = receive_shards + 1;
    while account < change_rows {
        edges.push(Edge {
            payer: account,
            recipient: account + 1,
            shard: 0,
        });
        account += 2;
    }

    let assignment = Assignment::new(Sha256::hash(&[b"clearing-benchmark-committee"]), 8)
        .expect("benchmark assignment is valid");
    let (fixture, accounts) = make_close_fixture(live_accounts, change_rows, &edges, assignment);
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let retained = signed_payment(
        fixture.context.payment(),
        &operator,
        &accounts[1].private,
        &accounts[0].private,
        0,
        1,
        1,
        1,
    );
    let row_position = fixture
        .rows
        .binary_search_by(|row| row.account.cmp(&accounts[0].public))
        .expect("challenged recipient has a changed row");
    let recipient = AccountLookup::Present(Box::new(
        fixture
            .prepared
            .row_opening(u32::try_from(row_position).expect("benchmark row position fits in u32"))
            .expect("benchmark row opening is valid"),
    ));
    let shard = fixture.shard_sets[row_position]
        .lookup::<Sha256>(0)
        .expect("challenged shard has a valid opening");
    let expected_batch = fixture.prepared.close().header.batch_id::<Sha256>();
    let challenge = Challenge::HigherShardTip {
        batch: expected_batch,
        payment: Box::new(retained),
        recipient: Box::new(recipient),
        shard: Box::new(shard),
    };
    let context = fixture.context.clone();
    let header = fixture.prepared.close().header;
    let roots = fixture.prepared.close().roots;
    assert_eq!(
        adjudicate::<Sha256, _>(
            &context,
            &header,
            &roots,
            context.challenge_deadline(),
            &challenge,
        )
        .expect("benchmark challenge is well formed"),
        Verdict::Proven(ChallengeKind::HigherShardTip)
    );
    ChallengeFixture {
        context,
        header,
        roots,
        challenge,
    }
}
