use commonware_clearing::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    challenge::{
        AckWitness, Challenge, ChallengeKind, EntryWitness, Verdict, account_lookup, adjudicate,
        higher_entry_lookup,
    },
    payment::{SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck, VectorSendBody},
    qmdb::{self, State, account_key},
    transition::{
        ChallengeIndex, CloseContext, CloseLimits, EpochContext, Header, OperatorKey,
        OperatorVariant, PreparedClose, RootBundle, Terminal, prepare_close_with_strategy,
        validate_close_with_strategy,
    },
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private as BlsPrivate, Scalar},
        ops::{compute_public, sign_message},
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::{Rayon, Strategy};
use commonware_runtime::{BufferPooler, deterministic, utils::buffer::paged::CacheRef};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, TestRng};
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    sync::OnceLock,
};

pub(crate) const WORKERS: usize = 16;
pub(crate) const PROFILE_ENV: &str = "COMMONWARE_CLEARING_PROFILE";
pub(crate) const EPOCH: u64 = 7;
pub(crate) const OPENING_BALANCE: u64 = 1_000_000;
const OPERATOR_SEED: u64 = 1;
const ACCOUNT_SEED_START: u64 = 10_000;
pub(crate) type BenchState = State<deterministic::Context, Sha256, Rayon>;
type BenchTerminal = Terminal<VerifyingKey, Digest>;
type BenchAck = VectorAck<VerifyingKey, Digest>;

// Real Rayon workers complete outside the deterministic executor. The benchmark requires
// runtime/external and uses the smallest supported delay between executor polls.
pub(crate) fn runner() -> deterministic::Runner {
    deterministic::Runner::new(
        deterministic::Config::default().with_cycle(commonware_utils::time::SYSTEM_TIME_PRECISION),
    )
}

pub(crate) fn strategy() -> &'static Rayon {
    static STRATEGY: OnceLock<Rayon> = OnceLock::new();
    STRATEGY.get_or_init(|| Rayon::new(NonZeroUsize::new(WORKERS).unwrap()).expect("worker pool"))
}

#[derive(Clone, Copy)]
pub(crate) struct ActiveProfile {
    pub(crate) live_accounts: usize,
    pub(crate) senders: usize,
    pub(crate) credited_accounts: usize,
    pub(crate) out_degree: usize,
}

impl ActiveProfile {
    pub(crate) const fn edges(self) -> usize {
        self.senders * self.out_degree
    }
}

/// Dense and sparse activity over a fixed512-account recipient pool.
#[cfg(full_bench)]
pub(crate) const ACTIVE_PROFILES: &[ActiveProfile] = &[
    ActiveProfile {
        live_accounts: 1024,
        senders: 1024,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 10000,
        senders: 10000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 100000,
        senders: 100000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1000000,
        senders: 1000000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1000000,
        senders: 1024,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1000000,
        senders: 10000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1000000,
        senders: 100000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1024,
        senders: 1024,
        credited_accounts: 512,
        out_degree: 8,
    },
    ActiveProfile {
        live_accounts: 10000,
        senders: 10000,
        credited_accounts: 512,
        out_degree: 8,
    },
    ActiveProfile {
        live_accounts: 100000,
        senders: 100000,
        credited_accounts: 512,
        out_degree: 8,
    },
    ActiveProfile {
        live_accounts: 1000000,
        senders: 1000000,
        credited_accounts: 512,
        out_degree: 8,
    },
    ActiveProfile {
        live_accounts: 1000000,
        senders: 1024,
        credited_accounts: 512,
        out_degree: 8,
    },
    ActiveProfile {
        live_accounts: 1000000,
        senders: 10000,
        credited_accounts: 512,
        out_degree: 8,
    },
    ActiveProfile {
        live_accounts: 1000000,
        senders: 100000,
        credited_accounts: 512,
        out_degree: 8,
    },
];
#[cfg(not(full_bench))]
pub(crate) const ACTIVE_PROFILES: &[ActiveProfile] = &[
    ActiveProfile {
        live_accounts: 1024,
        senders: 1024,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1024,
        senders: 128,
        credited_accounts: 512,
        out_degree: 8,
    },
    ActiveProfile {
        live_accounts: 512,
        senders: 512,
        credited_accounts: 512,
        out_degree: 1,
    },
];

pub(crate) fn profile_key(profile: ActiveProfile) -> String {
    format!(
        "N={} A={} B={} K={}",
        profile.live_accounts, profile.senders, profile.credited_accounts, profile.out_degree,
    )
}

pub(crate) fn selected_active_profiles() -> Vec<(usize, ActiveProfile)> {
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
                "{PROFILE_ENV}={selector:?} is invalid; use a zero-based profile index or N=... A=... B=... K=..."
            )
        });
    vec![(selected, ACTIVE_PROFILES[selected])]
}

pub(crate) fn state_config(context: &impl BufferPooler, prefix: &str) -> qmdb::Config<Rayon> {
    let page_cache = CacheRef::from_pooler(context, NZU16!(4092), NZUsize!(1024));
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-merkle"),
            metadata_partition: format!("{prefix}-metadata"),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(65536),
            strategy: strategy().clone(),
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-operations"),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(65536),
            page_cache,
        },
        grafted_metadata_partition: format!("{prefix}-grafted"),
        translator: EightCap,
        init_cache_size: Some(NZUsize!(65536)),
        init_buffer: NZUsize!(65536),
        init_concurrency: (),
    }
}

pub(crate) fn accounts(live: usize) -> Vec<(VerifyingKey, SigningKey)> {
    let mut accounts = (0..live)
        .map(|i| {
            let key = SigningKey::from_seed(ACCOUNT_SEED_START + i as u64);
            (key.public_key(), key)
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    accounts
}

pub(crate) async fn new_state(
    runtime: deterministic::Context,
    accounts: &[(VerifyingKey, SigningKey)],
) -> BenchState {
    let genesis = accounts
        .iter()
        .map(|(key, _)| {
            (
                account_key(key).expect("account key"),
                NonZeroU64::new(OPENING_BALANCE),
            )
        })
        .collect();
    let config = state_config(&runtime, "benchmark");
    let state = State::open(runtime, config)
        .await
        .expect("open native state");
    assert!(state.is_bootstrap());
    let genesis = state
        .prepare(state.head(), genesis)
        .await
        .expect("prepare canonical genesis");
    state.apply(genesis).await.expect("apply canonical genesis")
}

pub(crate) async fn epoch_context(
    state: &BenchState,
    epoch: u64,
    committee: Digest,
    operator: &SigningKey,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, Digest>,
) -> CloseContext<VerifyingKey, Digest> {
    EpochContext::new::<Sha256>(
        Sha256::hash(&[b"clearing-benchmark-deployment"]),
        epoch,
        operator.public_key(),
        deposits,
        withdrawals,
        state.liability(),
        98,
        99,
        CloseLimits::protocol_maximum(),
        committee,
    )
    .expect("epoch context")
    .bind::<Sha256, _, _>(state, deposits, withdrawals)
    .await
    .expect("bound context")
}

pub(crate) fn terminal_material(
    profile: ActiveProfile,
    accounts: &[(VerifyingKey, SigningKey)],
    context: &CloseContext<VerifyingKey, Digest>,
    operator: &SigningKey,
) -> (Vec<BenchTerminal>, Vec<BenchAck>) {
    let materials = strategy().map_collect_vec(
        accounts[..profile.senders].iter().enumerate(),
        |(index, account)| {
            let entries = (0..profile.out_degree)
                .map(|offset| OutEntry {
                    recipient: accounts[(index + offset) % profile.credited_accounts]
                        .0
                        .clone(),
                    cumulative: 1,
                    count: 1,
                })
                .collect();
            terminal_for_entries(account, context, operator, 0, entries)
        },
    );
    materials.into_iter().unzip()
}

pub(crate) fn terminal_for_entries(
    account: &(VerifyingKey, SigningKey),
    context: &CloseContext<VerifyingKey, Digest>,
    operator: &SigningKey,
    seq: u64,
    mut entries: Vec<OutEntry<VerifyingKey>>,
) -> (BenchTerminal, BenchAck) {
    entries.sort_unstable_by(|a, b| a.recipient.cmp(&b.recipient));
    let debit = entries
        .iter()
        .try_fold(0u64, |total, entry| total.checked_add(entry.cumulative))
        .expect("fixture debit fits");
    let vector = OutVector::new(context.payment().epoch(), account.0.clone(), entries)
        .expect("canonical vector");
    let body = VectorSendBody::new(
        context.payment(),
        account.0.clone(),
        seq,
        debit,
        vector.root::<Sha256, Digest>().expect("vector root"),
    );
    let ack = VectorAck::sign_by_authorities(body, &account.1, operator);
    let terminal = Terminal {
        authorization: SendAuthorization::from_raw_unchecked(
            ack.body().clone(),
            ack.payer_signature().clone(),
        ),
        vector,
        operator_signature: sign_message::<OperatorVariant>(
            &BlsPrivate::new(Scalar::from(OPERATOR_SEED)),
            VECTOR_ACK_AGGREGATE_NAMESPACE,
            ack.body().encode().as_ref(),
        ),
    };
    (terminal, ack)
}

pub(crate) struct CloseFixture {
    pub(crate) state: BenchState,
    pub(crate) context: CloseContext<VerifyingKey, Digest>,
    pub(crate) deposits: DepositBatch<VerifyingKey>,
    pub(crate) withdrawals: WithdrawalBatch<VerifyingKey, Digest>,
    pub(crate) prepared: PreparedClose<VerifyingKey, Digest, Rayon>,
    pub(crate) accounts: Vec<(VerifyingKey, SigningKey)>,
    pub(crate) operator: SigningKey,
    pub(crate) operator_bls: OperatorKey,
    pub(crate) terminals: Vec<BenchTerminal>,
    pub(crate) acks: Vec<BenchAck>,
    pub(crate) profile: ActiveProfile,
}

pub(crate) async fn active_close_fixture(
    runtime: deterministic::Context,
    profile: ActiveProfile,
) -> CloseFixture {
    let committee = super::admission_fixtures::Validators::new()
        .committee()
        .commitment::<Sha256>();
    active_close_fixture_with_committee(runtime, profile, committee).await
}

#[commonware_macros::boxed]
pub(crate) async fn active_close_fixture_with_committee(
    runtime: deterministic::Context,
    profile: ActiveProfile,
    committee: Digest,
) -> CloseFixture {
    assert!(
        profile.senders <= profile.live_accounts
            && profile.credited_accounts > 0
            && profile.credited_accounts <= profile.live_accounts
            && profile.out_degree > 0
            && profile.out_degree <= profile.credited_accounts
    );
    let accounts = accounts(profile.live_accounts);
    let state = new_state(runtime, &accounts).await;
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let operator_bls =
        compute_public::<OperatorVariant>(&BlsPrivate::new(Scalar::from(OPERATOR_SEED)));
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = epoch_context(&state, EPOCH, committee, &operator, &deposits, &withdrawals).await;
    let (terminals, acks) = terminal_material(profile, &accounts, &context, &operator);
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &context,
        &deposits,
        &withdrawals,
        terminals.clone(),
        strategy(),
    )
    .await
    .expect("prepare fixture");
    let decoded =
        commonware_clearing::bajillion::posted::decode(prepared.encoded().clone(), &context)
            .expect("fixture decodes");
    let validated = validate_close_with_strategy::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
        &state,
        &context,
        &operator_bls,
        &deposits,
        &withdrawals,
        decoded,
        &mut TestRng::new(0),
        strategy(),
    )
    .await
    .expect("fixture validates");
    assert_eq!(prepared.close().header, validated.close().header);
    let mut deltas = BTreeMap::<usize, (u64, u64)>::new();
    for sender in 0..profile.senders {
        deltas.entry(sender).or_default().0 += profile.out_degree as u64;
        for offset in 0..profile.out_degree {
            deltas
                .entry((sender + offset) % profile.credited_accounts)
                .or_default()
                .1 += 1;
        }
    }
    assert_eq!(prepared.close().rows.len(), deltas.len());
    let mut writes = 0;
    for row in &prepared.close().rows {
        let index = accounts
            .binary_search_by(|(key, _)| key.cmp(&row.account))
            .expect("registered activity account");
        let (debit, credit) = deltas[&index];
        assert_eq!(row.predecessor, OPENING_BALANCE);
        assert_eq!(row.successor, OPENING_BALANCE - debit + credit);
        writes += usize::from(debit != credit);
    }
    assert_eq!(prepared.state().mutations().len(), writes);

    CloseFixture {
        state,
        context,
        deposits,
        withdrawals,
        prepared,
        accounts,
        operator,
        operator_bls,
        terminals,
        acks,
        profile,
    }
}

/// Short benchmark label for one challenge kind.
pub(crate) const fn kind_label(kind: ChallengeKind) -> &'static str {
    match kind {
        ChallengeKind::HigherAckDebit => "debit",
        ChallengeKind::HigherAckEntry => "entry",
        ChallengeKind::AckFork => "fork",
    }
}

fn assert_proven(
    context: &CloseContext<VerifyingKey, Digest>,
    header: &Header<Digest>,
    roots: &RootBundle<Digest>,
    amounts: &commonware_clearing::bajillion::transition::CloseAmounts,
    challenge: &Challenge<VerifyingKey, Digest>,
    kind: ChallengeKind,
) {
    assert_eq!(
        adjudicate::<Sha256, _, _>(context, header, roots, amounts, challenge)
            .expect("benchmark challenge is well formed"),
        Verdict::Proven(kind)
    );
}

/// Signs one proven challenge per kind in [`ChallengeKind`] order against the fixture close.
///
/// The bench holds the operator and payer signers, so it can produce exactly the acknowledged
/// evidence a cheating operator would have issued beyond the committed close. Each challenge is
/// asserted to adjudicate to its proven kind.
pub(crate) fn proven_challenges(
    fixture: &CloseFixture,
) -> [(ChallengeKind, Challenge<VerifyingKey, Digest>); 3] {
    let close = fixture.prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&fixture.context, close)
        .expect("benchmark challenge index is valid");

    let payer_position = 3_usize;
    let payer_public = close.rows[payer_position].account.clone();
    let payer_private = fixture
        .accounts
        .iter()
        .find(|(public, _)| *public == payer_public)
        .map(|(_, private)| private.clone())
        .expect("the challenged payer is registered");

    // A retained successor vector one unit past the committed terminal on its first edge. Its
    // acknowledgment contradicts both the public terminal debit and the public terminal entry.
    let committed = &close.out_vectors[payer_position];
    let mut entries = committed.entries().to_vec();
    entries[0].cumulative += 1;
    entries[0].count += 1;
    let retained_recipient = entries[0].recipient.clone();
    let retained =
        OutVector::new(EPOCH, payer_public.clone(), entries).expect("vector is canonical");
    let retained_root = retained
        .root::<Sha256, Digest>()
        .expect("vector root is valid");
    let retained_body = VectorSendBody::new(
        fixture.context.payment(),
        payer_public.clone(),
        1,
        close.rows[payer_position]
            .outgoing
            .as_ref()
            .expect("payer authorization")
            .body()
            .cumulative_debit()
            + 1,
        retained_root,
    );
    let retained_ack =
        VectorAck::sign_by_authorities(retained_body, &payer_private, &fixture.operator);
    let OutTipLookup::Present {
        cumulative,
        count,
        opening,
    } = retained
        .lookup::<Sha256, Digest>(&retained_recipient)
        .expect("retained lookup is aligned")
    else {
        panic!("retained entry is present");
    };
    let debit = Challenge::HigherAckDebit {
        ack: Box::new(AckWitness::from_ack(&retained_ack)),
        payer: Box::new(
            account_lookup::<Sha256, _, _>(&index, &payer_public)
                .expect("benchmark payer lookup is aligned"),
        ),
    };
    let entry = Challenge::HigherAckEntry {
        entry: Box::new(EntryWitness {
            ack: AckWitness::from_ack(&retained_ack),
            recipient: retained_recipient.clone(),
            cumulative,
            count,
            opening,
        }),
        sender: Box::new(
            higher_entry_lookup::<Sha256, _, _>(
                &index,
                &payer_public,
                Some(committed),
                &retained_recipient,
            )
            .expect("benchmark sender lookup is aligned"),
        ),
    };

    // Two countersigned bodies at one payer sequence number.
    let fork = Challenge::AckFork {
        left: Box::new(AckWitness::from_ack(&fixture.acks[payer_position])),
        right: Box::new(AckWitness::from_ack(&{
            let body = VectorSendBody::new(
                fixture.context.payment(),
                payer_public,
                0,
                close.rows[payer_position]
                    .outgoing
                    .as_ref()
                    .expect("payer authorization")
                    .body()
                    .cumulative_debit()
                    + 5,
                retained_root,
            );
            VectorAck::sign_by_authorities(body, &payer_private, &fixture.operator)
        })),
    };

    let challenges = [
        (ChallengeKind::HigherAckDebit, debit),
        (ChallengeKind::HigherAckEntry, entry),
        (ChallengeKind::AckFork, fork),
    ];
    for (kind, challenge) in &challenges {
        assert_proven(
            &fixture.context,
            &close.header,
            &close.roots,
            &close.amounts,
            challenge,
            *kind,
        );
    }
    challenges
}
