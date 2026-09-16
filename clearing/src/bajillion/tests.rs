use crate::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{
        AccountLookup, AckWitness, Challenge, ChallengeError, ChallengeKind, EntryWitness, Verdict,
        adjudicate,
    },
    custody::Epoch,
    logs::{self, ActivityInput, Floors, Heads, Logs},
    payment::{
        AckError, EntryReceipt, SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck,
        VectorSendBody,
    },
    posted,
    qmdb::{self, Mutations, State, StateHead, StateLookup, StateOpening, StateRoot, account_key},
    replica::{PreparedReplica, Replica},
    transition::{
        Close, CloseContext, CloseLimits, EpochContext, PreparedClose, Terminal,
        TransitionError as CloseError, WithdrawalClaim, WithdrawalOutput,
        prepare_close_with_strategy, validate_close_with_strategy,
    },
    vector::{OutEntry, OutVector},
};
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private as BlsPrivate, Scalar},
        ops::{compute_public, sign_message},
    },
    sha256::Digest as ShaDigest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as AckBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner as _, Supervisor as _, deterministic, utils::buffer::paged::CacheRef,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, TestRng};
use core::num::NonZeroU64;

mod boundaries;
mod challenges;
mod flat_logs;
mod native_custody;
mod ordering;
mod rotation;
mod state;
mod virtual_balances;
mod wire;

const EPOCH: u64 = 7;
const OPENING_BALANCE: u64 = 1_000_000;
const OPERATOR_SEED: u64 = 1;
const ACCOUNT_SEED_START: u64 = 10_000;

pub(crate) type TestState = Replica<deterministic::Context, Sha256, VerifyingKey>;

pub(crate) fn config(context: &impl BufferPooler, prefix: &str) -> qmdb::Config<Sequential> {
    let page_cache = CacheRef::from_pooler(context, NZU16!(4092), NZUsize!(16));
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-merkle"),
            metadata_partition: format!("{prefix}-merkle-meta"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-operations"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            page_cache,
        },
        grafted_metadata_partition: format!("{prefix}-grafted"),
        translator: EightCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(4096),
        init_concurrency: (),
    }
}

pub(crate) fn logs_config(context: &impl BufferPooler, prefix: &str) -> logs::Config<Sequential> {
    let activity = config(context, &format!("{prefix}-activity"));
    let payouts = config(context, &format!("{prefix}-payouts"));
    logs::Config {
        activity: commonware_storage::qmdb::keyless::Config {
            merkle: activity.merkle_config,
            log: commonware_storage::journal::contiguous::variable::Config {
                partition: activity.journal_config.partition,
                items_per_section: commonware_utils::NZU64!(4096),
                compression: None,
                codec_config: (),
                page_cache: activity.journal_config.page_cache,
                write_buffer: commonware_utils::NZUsize!(4096),
                replay_buffer: commonware_utils::NZUsize!(4096),
            },
        },
        payouts: commonware_storage::qmdb::keyless::Config {
            merkle: payouts.merkle_config,
            log: commonware_storage::journal::contiguous::variable::Config {
                partition: payouts.journal_config.partition,
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: commonware_codec::RangeCfg::new(0..=1024),
                page_cache: payouts.journal_config.page_cache,
                write_buffer: NZUsize!(4096),
                replay_buffer: NZUsize!(4096),
            },
        },
    }
}

pub(crate) async fn open_state(
    context: deterministic::Context,
    prefix: &str,
) -> Result<TestState, crate::bajillion::replica::Error> {
    let cfg = crate::bajillion::replica::Config {
        state: config(&context, prefix),
        logs: logs_config(&context, prefix),
    };
    Replica::open(context, cfg).await
}

pub(crate) async fn new_state(
    context: deterministic::Context,
    prefix: &str,
    balances: Vec<(VerifyingKey, u64)>,
) -> TestState {
    let mut genesis = balances
        .into_iter()
        .map(|(key, balance)| {
            (
                account_key(&key).unwrap(),
                NonZeroU64::new(balance).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    genesis.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let config = config(&context, prefix);
    let log_config = logs_config(&context, prefix);
    let state = State::init(context.child("state"), config, genesis)
        .await
        .unwrap();
    let logs = Logs::open(context.child("logs"), log_config).await.unwrap();
    Replica::from_parts(state, logs)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Accepted {
    pub head: StateHead<ShaDigest>,
    pub mutations: Mutations,
    pub logs: Heads<ShaDigest>,
    pub activity: ActivityInput<VerifyingKey, ShaDigest>,
    pub outputs: Vec<WithdrawalOutput>,
}

impl Accepted {
    pub(crate) const fn genesis(state: &TestState, mutations: Mutations) -> Self {
        Self {
            head: *state.state().head(),
            mutations,
            logs: *state.logs().head(),
            activity: ActivityInput::new(vec![], vec![]),
            outputs: vec![],
        }
    }

    pub(crate) fn prepared(prepared: &PreparedClose<VerifyingKey, ShaDigest>) -> Self {
        Self {
            head: *prepared.state().head(),
            mutations: prepared.state().mutations().to_vec(),
            logs: *prepared.replica().logs().head(),
            activity: prepared.close().activity_input::<Sha256>(),
            outputs: prepared.close().withdrawal_outputs().to_vec(),
        }
    }
}

// Accepted records authenticate all three native heads; only missing records supply replay values.
#[commonware_macros::boxed]
pub(crate) async fn replay_state(
    context: deterministic::Context,
    prefix: &str,
    accepted: &[Accepted],
) -> Result<TestState, crate::bajillion::replica::Error> {
    let mut replica = open_state(context, prefix).await?;
    let start = if replica.state().is_bootstrap() {
        0
    } else {
        accepted
            .iter()
            .position(|record| {
                record.head == *replica.state().head() && record.logs == *replica.logs().head()
            })
            .ok_or(qmdb::Error::Predecessor)?
            + 1
    };
    for (index, record) in accepted.iter().enumerate().skip(start) {
        let prepared = replica
            .state()
            .prepare(replica.state().head(), record.mutations.clone())
            .await?;
        if prepared.head() != &record.head {
            return Err(qmdb::Error::Predecessor.into());
        }
        if index == 0 {
            if record.logs != *replica.logs().head()
                || !record.activity.rows().is_empty()
                || !record.activity.entries().is_empty()
                || !record.outputs.is_empty()
            {
                return Err(qmdb::Error::Predecessor.into());
            }
            let (state, logs) = replica.into_parts();
            replica = Replica::from_parts(state.apply(prepared).await?, logs);
        } else {
            let logs = replica
                .logs()
                .prepare(
                    replica.logs().head(),
                    record.activity.clone(),
                    record.outputs.clone(),
                    Floors {
                        activity: record.logs.activity.floor,
                        payouts: record.logs.payouts.floor,
                    },
                )
                .await?;
            if logs.head() != &record.logs {
                return Err(qmdb::Error::Predecessor.into());
            }
            replica = replica.apply(PreparedReplica::new(prepared, logs)).await?;
        }
    }
    Ok(replica)
}

pub(crate) struct NativeIndex {
    replica: TestState,
    epoch: Epoch<ShaDigest>,
}

impl NativeIndex {
    pub(crate) async fn replay(
        context: deterministic::Context,
        prefix: &str,
        genesis: &Accepted,
        close_context: &CloseContext<VerifyingKey, ShaDigest>,
        prepared: &PreparedClose<VerifyingKey, ShaDigest>,
    ) -> Self {
        let range = prepared
            .close()
            .roots
            .activity_range(close_context)
            .unwrap();
        let replica = replay_state(
            context,
            prefix,
            &[genesis.clone(), Accepted::prepared(prepared)],
        )
        .await
        .unwrap();
        let epoch = Epoch::at(replica.logs(), close_context.payment().epoch(), range)
            .await
            .unwrap();
        Self { replica, epoch }
    }

    pub(crate) async fn account_lookup(
        &self,
        account: &VerifyingKey,
    ) -> AccountLookup<VerifyingKey, ShaDigest> {
        self.epoch
            .account_lookup(self.replica.logs(), account)
            .await
            .unwrap()
    }

    pub(crate) async fn higher_entry_lookup(
        &self,
        payer: &VerifyingKey,
        recipient: &VerifyingKey,
    ) -> crate::bajillion::challenge::HigherEntryLookup<VerifyingKey, ShaDigest> {
        self.epoch
            .higher_entry_lookup(self.replica.logs(), payer, recipient)
            .await
            .unwrap()
    }
}

struct Fixture {
    state: TestState,
    genesis: Accepted,
    context: CloseContext<VerifyingKey, ShaDigest>,
    deposits: DepositBatch<VerifyingKey>,
    withdrawals: WithdrawalBatch<VerifyingKey, ShaDigest>,
    prepared: PreparedClose<VerifyingKey, ShaDigest>,
    accounts: Vec<(VerifyingKey, SigningKey)>,
    acks: Vec<VectorAck<VerifyingKey, ShaDigest>>,
    terminals: Vec<Terminal<VerifyingKey, ShaDigest>>,
    operator: SigningKey,
    operator_bls_private: BlsPrivate,
    operator_bls: crate::bajillion::transition::OperatorKey,
}

fn bls_ack(
    private: &BlsPrivate,
    body: &VectorSendBody<VerifyingKey, ShaDigest>,
) -> crate::bajillion::transition::OperatorSignature {
    sign_message::<crate::bajillion::transition::OperatorVariant>(
        private,
        VECTOR_ACK_AGGREGATE_NAMESPACE,
        body.encode().as_ref(),
    )
}

// Every sender pays one unit to each selected recipient. The expected balances below are
// computed independently of the production transition's activity and mutation derivation.
#[commonware_macros::boxed]
async fn fixture(
    runtime: deterministic::Context,
    live: usize,
    senders: usize,
    credited: usize,
    out_degree: usize,
) -> Fixture {
    assert!(senders <= live && credited <= live && out_degree <= credited);
    let mut accounts = (0..live)
        .map(|index| {
            let private = SigningKey::from_seed(ACCOUNT_SEED_START + index as u64);
            (private.public_key(), private)
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let state = new_state(
        runtime,
        "fixture",
        accounts
            .iter()
            .map(|(key, _)| (key.clone(), OPENING_BALANCE))
            .collect(),
    )
    .await;
    let genesis = Accepted::genesis(
        &state,
        accounts
            .iter()
            .map(|(key, _)| (account_key(key).unwrap(), NonZeroU64::new(OPENING_BALANCE)))
            .collect(),
    );
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let operator_bls_private = BlsPrivate::new(Scalar::from(OPERATOR_SEED));
    let operator_bls =
        compute_public::<crate::bajillion::transition::OperatorVariant>(&operator_bls_private);
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = EpochContext::new::<Sha256>(
        Sha256::hash(&[b"close-test-deployment"]),
        EPOCH,
        operator.public_key(),
        &deposits,
        &withdrawals,
        live as u64 * OPENING_BALANCE,
        98,
        99,
        CloseLimits::protocol_maximum(),
        Sha256::hash(&[b"close-test-committee"]),
    )
    .unwrap()
    .bind::<Sha256, _, _>(
        &state,
        &deposits,
        &withdrawals,
        Floors {
            activity: 0,
            payouts: 0,
        },
    )
    .unwrap();
    let mut acks = Vec::new();
    let mut terminals = Vec::new();
    for (index, (public, private)) in accounts.iter().take(senders).enumerate() {
        let mut entries = (0..out_degree)
            .map(|offset| OutEntry {
                recipient: accounts[(index + offset) % credited].0.clone(),
                cumulative: 1,
                count: 1,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| a.recipient.cmp(&b.recipient));
        let vector = OutVector::new(EPOCH, public.clone(), entries).unwrap();
        let body = VectorSendBody::new(
            context.payment(),
            public.clone(),
            0,
            out_degree as u64,
            vector.root::<Sha256, ShaDigest>().unwrap(),
        );
        let ack = VectorAck::sign_by_authorities(body, private, &operator);
        terminals.push(Terminal {
            authorization: SendAuthorization::from_raw_unchecked(
                ack.body().clone(),
                ack.payer_signature().clone(),
            ),
            vector,
            operator_signature: bls_ack(&operator_bls_private, ack.body()),
        });
        acks.push(ack);
    }
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &context,
        &deposits,
        &withdrawals,
        terminals.clone(),
        &Sequential,
    )
    .await
    .unwrap();
    Fixture {
        state,
        genesis,
        context,
        deposits,
        withdrawals,
        prepared,
        accounts,
        acks,
        terminals,
        operator,
        operator_bls_private,
        operator_bls,
    }
}

async fn validate(
    fixture: &Fixture,
    wire: Bytes,
) -> Result<PreparedClose<VerifyingKey, ShaDigest>, CloseError> {
    let dealing = posted::decode::<VerifyingKey, ShaDigest>(wire, &fixture.context)?;
    validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
        &fixture.state,
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        dealing,
        &mut TestRng::new(5),
        &Sequential,
    )
    .await
}

#[test]
fn full_dealing_derives_balances_and_preserves_idle_accounts() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 24, 12, 8, 2).await;
        let prepared = validate(&fixture, fixture.prepared.encoded().clone())
            .await
            .unwrap();
        assert_eq!(prepared.close().header, fixture.prepared.close().header);
        assert_eq!(prepared.close().roots, fixture.prepared.close().roots);
        assert_eq!(prepared.encoded(), fixture.prepared.encoded());
        assert_eq!(prepared.close().rows.len(), 12);
        let mut expected = vec![OPENING_BALANCE; 24];
        for sender in 0..12 {
            expected[sender] -= 2;
            for offset in 0..2 {
                expected[(sender + offset) % 8] += 1;
            }
        }
        let (state, close) = Box::pin(prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        assert_eq!(state.state().root(), close.roots.successor);
        for ((public, _), balance) in fixture.accounts.iter().zip(expected) {
            assert_eq!(
                state
                    .state()
                    .get(&account_key(public).unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .get(),
                balance
            );
        }
        assert_eq!(state.state().live_accounts(), 24);
    });
}

#[test]
fn zero_net_activity_and_empty_epochs_append_canonical_batches() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("fixture"), 8, 8, 8, 2).await;
        assert_eq!(fixture.prepared.close().rows.len(), 8);
        assert!(fixture.prepared.state().mutations().is_empty());
        let before = fixture.state.state().root();
        let before_operations = fixture.state.state().head().operations();
        let prepared = validate(&fixture, fixture.prepared.encoded().clone())
            .await
            .unwrap();
        let (state, close) = Box::pin(prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        assert_ne!(state.state().root(), before);
        assert!(state.state().head().operations() > before_operations);
        let after_operations = state.state().head().operations();
        let range = close.roots.activity_range(&fixture.context).unwrap();
        let epoch = Epoch::at(state.logs(), EPOCH, range).await.unwrap();
        for ((account, _), ack) in fixture.accounts.iter().zip(&fixture.acks) {
            assert_eq!(
                state
                    .state()
                    .get(&account_key(account).unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .get(),
                OPENING_BALANCE
            );
            let payer = epoch.account_lookup(state.logs(), account).await.unwrap();
            assert!(matches!(payer, AccountLookup::Present(_)));
            assert_eq!(
                adjudicate::<Sha256, _, _>(
                    &fixture.context,
                    &close.header,
                    &close.roots,
                    close.withdrawal_total,
                    &Challenge::HigherAckDebit {
                        ack: Box::new(AckWitness::from_ack(ack)),
                        payer: Box::new(payer)
                    }
                )
                .unwrap(),
                Verdict::NoContradiction
            );
        }
        let context = EpochContext::new::<Sha256>(
            Sha256::hash(&[b"close-test-deployment"]),
            EPOCH + 1,
            fixture.operator.public_key(),
            &fixture.deposits,
            &fixture.withdrawals,
            fixture.context.predecessor_liability() - close.withdrawal_total,
            100,
            101,
            CloseLimits::protocol_maximum(),
            *fixture.context.committee(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(
            &state,
            &fixture.deposits,
            &fixture.withdrawals,
            Floors {
                activity: 0,
                payouts: 0,
            },
        )
        .unwrap();
        let empty = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &fixture.deposits,
            &fixture.withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        assert!(empty.close().rows.is_empty());
        assert!(empty.state().mutations().is_empty());
        let previous = state.state().root();
        let (state, _) = Box::pin(empty.apply::<_, Sha256>(state)).await.unwrap();
        assert_ne!(state.state().root(), previous);
        assert!(state.state().head().operations() > after_operations);
    });
}

#[test]
fn complete_wire_rejects_tampering_truncation_and_trailing_bytes_without_mutation() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let wire = fixture.prepared.encoded();
        let before = *fixture.state.state().head();
        for length in 0..wire.len() {
            assert!(
                posted::decode::<VerifyingKey, ShaDigest>(wire.slice(..length), &fixture.context)
                    .is_err(),
                "truncated length {length}"
            );
        }
        for position in [0, wire.len() / 2, wire.len() - 1] {
            let mut tampered = wire.to_vec();
            tampered[position] ^= 1;
            assert!(
                validate(&fixture, tampered.into()).await.is_err(),
                "tampered byte {position}"
            );
        }
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert!(
            posted::decode::<VerifyingKey, ShaDigest>(trailing.into(), &fixture.context).is_err()
        );
        assert_eq!(*fixture.state.state().head(), before);
        validate(&fixture, wire.clone()).await.unwrap();
    });
}

#[test]
fn forged_payer_and_operator_acceptance_are_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let before = *fixture.state.state().head();
        for forge_payer in [false, true] {
            let mut terminals = fixture.terminals.clone();
            if forge_payer {
                let wrong = SigningKey::from_seed(999);
                terminals[0].authorization =
                    SendAuthorization::sign(terminals[0].authorization.body().clone(), &wrong);
            } else {
                terminals[0].operator_signature = bls_ack(
                    &BlsPrivate::new(Scalar::from(999_u64)),
                    terminals[0].authorization.body(),
                );
            }
            let forged = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &fixture.state,
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                terminals,
                &Sequential,
            )
            .await
            .unwrap();
            assert!(validate(&fixture, forged.encoded().clone()).await.is_err());
            assert_eq!(*fixture.state.state().head(), before);
        }
    });
}

#[test]
fn stale_and_divergent_predecessors_cannot_validate_the_same_dealing() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("fixture"), 8, 8, 4, 1).await;
        let same = new_state(
            runtime.child("independent"),
            "independent",
            fixture
                .accounts
                .iter()
                .map(|(key, _)| (key.clone(), OPENING_BALANCE))
                .collect(),
        )
        .await;
        assert_eq!(same.state().root(), fixture.state.state().root());
        let dealing = posted::decode(fixture.prepared.encoded().clone(), &fixture.context).unwrap();
        let valid = validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
            &same,
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            dealing,
            &mut TestRng::new(6),
            &Sequential,
        )
        .await
        .unwrap();
        assert_eq!(valid.close().roots, fixture.prepared.close().roots);
        let (advanced, _) = Box::pin(valid.apply::<_, Sha256>(same)).await.unwrap();
        let divergent = new_state(
            runtime,
            "divergent",
            fixture
                .accounts
                .iter()
                .map(|(key, _)| (key.clone(), OPENING_BALANCE - 1))
                .collect(),
        )
        .await;
        for state in [&advanced, &divergent] {
            let before = *state.state().head();
            let dealing =
                posted::decode(fixture.prepared.encoded().clone(), &fixture.context).unwrap();
            assert!(
                validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                    state,
                    &fixture.context,
                    &fixture.operator_bls,
                    &fixture.deposits,
                    &fixture.withdrawals,
                    dealing,
                    &mut TestRng::new(7),
                    &Sequential
                )
                .await
                .is_err()
            );
            assert_eq!(*state.state().head(), before);
        }
    });
}

#[cfg(feature = "arbitrary")]
mod conformance {
    use super::*;
    use commonware_conformance::Conformance;

    struct FullDealing;

    impl Conformance for FullDealing {
        async fn commit(seed: u64) -> Vec<u8> {
            deterministic::Runner::seeded(seed).start(|context| async move {
                let live = 4 + seed as usize % 9;
                let senders = seed as usize % (live + 1);
                let credited = live.min(4);
                let degree = 1 + seed as usize % credited;
                let fixture = fixture(context, live, senders, credited, degree).await;
                let validated = validate(&fixture, fixture.prepared.encoded().clone())
                    .await
                    .unwrap();
                assert_eq!(validated.close().roots, fixture.prepared.close().roots);
                fixture.prepared.encoded().to_vec()
            })
        }
    }

    commonware_conformance::conformance_tests! {
        FullDealing => 64,
    }
}
