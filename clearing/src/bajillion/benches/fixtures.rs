use commonware_clearing::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    challenge::{
        AckWitness, Challenge, ChallengeKind, EntryWitness, Verdict, account_lookup, adjudicate,
        higher_entry_lookup,
    },
    payment::{SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck, VectorSendBody},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        Assignment, ChallengeIndex, CloseContext, CloseLimits, EpochContext, Header, OperatorKey,
        OperatorSignature, OperatorVariant, PreparedClose, RootBundle, StateCache,
        prepare_close_with_strategy,
    },
    vector::{OutEntry, OutTipLookup, OutVector, TransposeEntry},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private as BlsPrivate, Scalar},
        ops::{compute_public, sign_message},
    },
    lthash::LtHash,
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::{Rayon, Strategy};
use commonware_utils::TestRng;
use std::{num::NonZeroUsize, sync::OnceLock};

pub(crate) const WORKERS: usize = 16;
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
    pub(crate) senders: usize,
    pub(crate) credited_accounts: usize,
    pub(crate) out_degree: usize,
}

impl ActiveProfile {
    pub(crate) const fn edges(self) -> usize {
        self.senders * self.out_degree
    }
}

/// The blog's measured matrix: every account sends one entry, the same 512 accounts
/// receive, and the live-account count sweeps 1,024 to one million.
#[cfg(full_bench)]
pub(crate) const ACTIVE_PROFILES: &[ActiveProfile] = &[
    ActiveProfile {
        live_accounts: 1_024,
        senders: 1_024,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 10_000,
        senders: 10_000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 100_000,
        senders: 100_000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1_000_000,
        senders: 1_000_000,
        credited_accounts: 512,
        out_degree: 1,
    },
    // The active sweep: the account set stays at one million while the movers shrink,
    // which the sender-vector close's posted and dealt figures scale with.
    ActiveProfile {
        live_accounts: 1_000_000,
        senders: 100_000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1_000_000,
        senders: 10_000,
        credited_accounts: 512,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1_000_000,
        senders: 1_024,
        credited_accounts: 512,
        out_degree: 1,
    },
];

#[cfg(not(full_bench))]
pub(crate) const ACTIVE_PROFILES: &[ActiveProfile] = &[
    ActiveProfile {
        live_accounts: 10_000,
        senders: 10_000,
        credited_accounts: 500,
        out_degree: 1,
    },
    // Partial participation: most of the account set stays unchanged.
    ActiveProfile {
        live_accounts: 10_000,
        senders: 1_000,
        credited_accounts: 500,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 100_000,
        senders: 100_000,
        credited_accounts: 500,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 100_000,
        senders: 100_000,
        credited_accounts: 500,
        out_degree: 10,
    },
    // Worst cases: every account pays one hot account, and all pairs at N=1024.
    ActiveProfile {
        live_accounts: 100_000,
        senders: 100_000,
        credited_accounts: 1,
        out_degree: 1,
    },
    ActiveProfile {
        live_accounts: 1_024,
        senders: 1_024,
        credited_accounts: 1_024,
        out_degree: 1_023,
    },
];

pub(crate) fn profile_key(profile: ActiveProfile) -> String {
    format!(
        "N={},A={},B={},K={}",
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
                "{PROFILE_ENV}={selector:?} is invalid; use a zero-based profile index or N=...,B=...,K=..."
            )
        });
    vec![(selected, ACTIVE_PROFILES[selected])]
}

#[cfg(not(full_bench))]
pub(crate) const STATE_CACHE_SIZES: &[usize] = &[1_024, 16_384];
#[cfg(full_bench)]
pub(crate) const STATE_CACHE_SIZES: &[usize] = &[1_024, 16_384, 1_000_000];

const EPOCH: u64 = 7;
const OPENING_BALANCE: u64 = 1_000_000;
const OPERATOR_SEED: u64 = 1;
const ACCOUNT_SEED_START: u64 = 10_000;
const ADMISSION_DEADLINE: u64 = 98;
const CHALLENGE_DEADLINE: u64 = 99;

pub(crate) type TestStateCache = StateCache<VerifyingKey, Digest>;

fn accounts(live_accounts: usize) -> Vec<(VerifyingKey, SigningKey)> {
    let mut accounts = (0..live_accounts)
        .map(|index| {
            let index = u64::try_from(index).expect("benchmark account index fits in u64");
            let private = SigningKey::from_seed(ACCOUNT_SEED_START + index);
            (private.public_key(), private)
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    accounts
}

pub(crate) fn state_leaves(live_accounts: usize) -> Vec<StateLeaf<VerifyingKey>> {
    accounts(live_accounts)
        .into_iter()
        .map(|(public, _)| StateLeaf {
            account: public,
            state: AccountState {
                balance: OPENING_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect()
}

pub(crate) struct CloseFixture {
    pub(crate) cache: TestStateCache,
    pub(crate) operator_bls: OperatorKey,
    pub(crate) context: CloseContext<VerifyingKey, Digest>,
    pub(crate) deposits: DepositBatch<VerifyingKey>,
    pub(crate) withdrawals: WithdrawalBatch<VerifyingKey, Digest>,
    pub(crate) prepared: PreparedClose<VerifyingKey, Digest>,
    pub(crate) rows: Vec<AccountRow<VerifyingKey, Digest>>,
    pub(crate) out_vectors: Vec<OutVector<VerifyingKey>>,
    pub(crate) out_partials: Vec<LtHash>,
    pub(crate) operator_signatures: Vec<Option<OperatorSignature>>,
    pub(crate) acks: Vec<VectorAck<VerifyingKey, Digest>>,
    pub(crate) transpose: Vec<TransposeEntry<VerifyingKey>>,
    pub(crate) accounts: Vec<(VerifyingKey, SigningKey)>,
    pub(crate) operator: SigningKey,
}

pub(crate) fn active_close_fixture(profile: ActiveProfile) -> CloseFixture {
    let assignment = Assignment::new(Sha256::hash(&[b"clearing-benchmark-committee"]), 8)
        .expect("benchmark assignment is valid");
    active_close_fixture_with_assignment(profile, assignment)
}

/// Builds a close where the first `senders` accounts each send one unit to `out_degree`
/// recipients drawn round-robin from the first `credited_accounts` accounts. Accounts that
/// neither send nor receive stay unchanged, so the changed-row count follows the movers
/// rather than the account set.
pub(crate) fn active_close_fixture_with_assignment(
    profile: ActiveProfile,
    assignment: Assignment<Digest>,
) -> CloseFixture {
    let ActiveProfile {
        live_accounts,
        senders,
        credited_accounts,
        out_degree,
    } = profile;
    assert!(
        senders <= live_accounts
            && credited_accounts <= live_accounts
            && out_degree <= credited_accounts
    );
    let accounts = accounts(live_accounts);
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let operator_bls_private = BlsPrivate::new(Scalar::from(OPERATOR_SEED));
    let operator_bls = compute_public::<OperatorVariant>(&operator_bls_private);

    let leaves = accounts
        .iter()
        .map(|(public, _)| StateLeaf {
            account: public.clone(),
            state: AccountState {
                balance: OPENING_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect::<Vec<_>>();
    let cache =
        StateCache::new_with_strategy::<Sha256>(leaves, strategy()).expect("state is canonical");
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = EpochContext::new::<Sha256>(
        Sha256::hash(&[b"clearing-benchmark-deployment"]),
        EPOCH,
        operator.public_key(),
        &deposits,
        &withdrawals,
        cache.liability(),
        ADMISSION_DEADLINE,
        CHALLENGE_DEADLINE,
        CloseLimits::protocol_maximum(),
        assignment,
    )
    .and_then(|epoch| epoch.bind::<Sha256>(&cache, &deposits, &withdrawals))
    .expect("close context is valid");

    // Edge (i -> (i + j) % credited) for each sender i, one unit each. Vector roots and
    // both signatures are produced per payer through the worker pool.
    let payment_context = context.payment().clone();
    let per_payer = strategy().map_collect_vec(
        accounts[..senders].iter().enumerate(),
        |(index, (public, private))| {
            let mut entries = (0..out_degree)
                .map(|j| OutEntry {
                    recipient: accounts[(index + j) % credited_accounts].0.clone(),
                    cumulative: 1,
                    count: 1,
                })
                .collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
            let vector =
                OutVector::new(EPOCH, public.clone(), entries).expect("vector is canonical");
            let send_root = vector
                .root::<Sha256, Digest>()
                .expect("vector root is valid");
            let body = VectorSendBody::new(
                &payment_context,
                public.clone(),
                0,
                out_degree as u64,
                send_root,
            );
            let ack = VectorAck::sign_by_authorities(body, private, &operator);
            let aggregable = sign_message::<OperatorVariant>(
                &operator_bls_private,
                VECTOR_ACK_AGGREGATE_NAMESPACE,
                ack.body().encode().as_ref(),
            );
            (vector, ack, aggregable)
        },
    );

    let mut incoming = vec![Vec::new(); live_accounts];
    for (index, (public, _)) in accounts[..senders].iter().enumerate() {
        for j in 0..out_degree {
            let recipient = (index + j) % credited_accounts;
            incoming[recipient].push(TransposeEntry {
                recipient: accounts[recipient].0.clone(),
                payer: public.clone(),
                cumulative: 1,
                count: 1,
            });
        }
    }

    let mut sender_material = per_payer.into_iter().map(Some).collect::<Vec<_>>();

    let mut transpose = Vec::new();
    let mut rows = Vec::with_capacity(senders.max(credited_accounts));
    let mut out_vectors = Vec::with_capacity(senders.max(credited_accounts));
    let mut acks = Vec::with_capacity(senders);
    let mut operator_signatures = Vec::with_capacity(senders.max(credited_accounts));
    let mut prefix = Prefix::default();
    for (index, (public, _)) in accounts.iter().enumerate() {
        let sends = index < senders;
        let mut group = std::mem::take(&mut incoming[index]);
        if !sends && group.is_empty() {
            // Neither sent nor received: the account stays an unchanged live leaf.
            continue;
        }
        group.sort_unstable_by(|left, right| left.payer.cmp(&right.payer));
        let credit = group.iter().map(|entry| entry.cumulative).sum::<u64>();
        let receipts = group.iter().map(|entry| entry.count).sum::<u64>();
        let debit = if sends { out_degree as u64 } else { 0 };
        let predecessor = AccountState {
            balance: OPENING_BALANCE,
            active: true,
            ..AccountState::default()
        };
        let successor = AccountState {
            balance: OPENING_BALANCE - debit + credit,
            cumulative_debit: debit,
            cumulative_credit: credit,
            receipt_count: receipts,
            active: true,
        };
        prefix = prefix
            .checked_extend(Prefix {
                debit,
                credit,
                out_count: debit,
                in_count: group.len() as u64,
                ..Prefix::default()
            })
            .expect("prefix is valid");
        let (vector, outgoing, aggregable) = if sends {
            let (vector, ack, aggregable) = sender_material[index]
                .take()
                .expect("each sender's material is consumed once");
            let outgoing = SendAuthorization::from_raw_unchecked(
                ack.body().clone(),
                ack.payer_signature().clone(),
            );
            acks.push(ack);
            (vector, Some(outgoing), Some(aggregable))
        } else {
            (OutVector::empty(EPOCH, public.clone()), None, None)
        };
        rows.push(AccountRow {
            account: public.clone(),
            predecessor,
            successor,
            outgoing,
            output: SettlementOutput::None,
            prefix,
        });
        out_vectors.push(vector);
        operator_signatures.push(aggregable);
        transpose.extend(group);
    }

    // Senders maintain these partials incrementally at acceptance time, so fixture
    // construction stands in for the sender fleet here.
    let out_partials = out_vectors
        .iter()
        .map(OutVector::accumulator)
        .collect::<Vec<_>>();
    let prepared = prepare_close_with_strategy::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        rows.clone(),
        out_vectors.clone(),
        &out_partials,
        &operator_signatures,
        transpose.clone(),
        strategy(),
    )
    .expect("close prepares");
    prepared
        .validate::<Sha256, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &mut TestRng::new(0),
            strategy(),
        )
        .expect("close validates");
    CloseFixture {
        cache,
        operator_bls,
        context,
        deposits,
        withdrawals,
        prepared,
        rows,
        out_vectors,
        out_partials,
        operator_signatures,
        acks,
        transpose,
        accounts,
        operator,
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
    challenge: &Challenge<VerifyingKey, Digest>,
    kind: ChallengeKind,
) {
    assert_eq!(
        adjudicate::<Sha256, _, _>(context, header, roots, challenge)
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
        close.rows[payer_position].successor.cumulative_debit + 1,
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
            account_lookup::<Sha256, _, _>(&index, &fixture.cache, &payer_public)
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
                close.rows[payer_position].successor.cumulative_debit + 5,
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
            challenge,
            *kind,
        );
    }
    challenges
}
